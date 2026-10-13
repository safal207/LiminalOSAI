"""Durable host fence joining agent lifecycle STOP and endpoint effect STOP.

A stopped process does not settle an unresolved remote effect. Every terminal
aggregate is rebuilt from fresh independently signed controller responses and
the supervisor's positive owned-workload census. Recovery closes admission
before consulting either remote service; it never resumes an unfinished run.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from pathlib import Path
from typing import Any

from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .external_agent_protocol import AGENT_FIXTURE_SHA256, AGENT_PROFILE, validate_agent_action, verify_agent_receipt
from .external_authority import validate_authority_pin
from .external_authority_service import HTTPExternalAuthorityClient
from .external_command_protocol import validate_supervisor_pin
from .external_network_protocol import validate_endpoint_pin, validate_network_action

RUN_SCHEMA = "liminal-owned-agent-run-v1"
_RUN_FIELDS = {"schema", "run_id", "command", "effect", "supervisor_pin", "endpoint_pin", "effect_actions",
               "effect_action_digests", "source_digest", "spec_digest"}
_TABLES = {"agent_coordinator_meta", "agent_coordinator_run", "agent_coordinator_events"}
MAX_EVENTS = 256


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _reason(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, ControlError) else type(exc).__name__


def validate_run_binding(value: Any) -> dict:
    value = _copy(value)
    if type(value) is not dict or set(value) != _RUN_FIELDS or value["schema"] != RUN_SCHEMA:
        raise ControlError("AGENT_RUN_BINDING_INVALID")
    validate_id(value["run_id"], "run_id")
    for branch in ("command", "effect"):
        part = value[branch]
        if type(part) is not dict or set(part) != {"root_id", "execution_id", "epoch", "authority_pin"}:
            raise ControlError("AGENT_RUN_LINEAGE_INVALID")
        validate_id(part["root_id"], "root_id")
        validate_id(part["execution_id"], "execution_id")
        if type(part["epoch"]) is not int or not 1 <= part["epoch"] < 2**63:
            raise ControlError("AGENT_RUN_EPOCH_INVALID")
        validate_authority_pin(part["authority_pin"])
    if value["command"]["root_id"] == value["effect"]["root_id"]:
        raise ControlError("AGENT_RUN_ROOTS_MUST_DIFFER")
    validate_supervisor_pin(value["supervisor_pin"])
    validate_endpoint_pin(value["endpoint_pin"])
    keys = [value[k]["authority_pin"]["public_key"] for k in ("command", "effect")]
    keys += [value["supervisor_pin"]["public_key"], value["endpoint_pin"]["public_key"]]
    if len(set(keys)) != len(keys):
        raise ControlError("AGENT_RUN_SIGNERS_MUST_DIFFER")
    spec = value["spec_digest"]
    if type(spec) is not str or len(spec) != 64 or any(c not in "0123456789abcdef" for c in spec):
        raise ControlError("AGENT_RUN_SPEC_DIGEST_INVALID")
    if value["source_digest"] != AGENT_FIXTURE_SHA256:
        raise ControlError("AGENT_RUN_SOURCE_DIGEST_INVALID")
    actions = value["effect_actions"]
    if type(actions) is not list or not 1 <= len(actions) <= 4:
        raise ControlError("AGENT_RUN_EFFECT_ACTIONS_INVALID")
    seen_actions, seen_attempts = set(), set()
    for action in actions:
        action = validate_network_action(action)
        if any(type(action[field]) is not type(value["effect"][field]) or action[field] != value["effect"][field]
               for field in ("root_id", "execution_id", "epoch")):
            raise ControlError("AGENT_RUN_EFFECT_LINEAGE_MISMATCH")
        if action["action_id"] in seen_actions or action["attempt_id"] in seen_attempts:
            raise ControlError("AGENT_RUN_EFFECT_ACTIONS_DUPLICATE")
        seen_actions.add(action["action_id"])
        seen_attempts.add(action["attempt_id"])
    if value["effect_action_digests"] != [digest(action) for action in actions]:
        raise ControlError("AGENT_RUN_EFFECT_DIGESTS_INVALID")
    return value


def agent_policy_digest(run_binding: dict, branch: str) -> str:
    """Public cross-controller policy binding, verified by each signed root."""
    if branch not in ("command", "effect"):
        raise ControlError("AGENT_POLICY_BRANCH_INVALID")
    binding = validate_run_binding(run_binding)
    return digest({"schema": "liminal-owned-agent-policy-v1", "run_binding_digest": digest(binding), "branch": branch})


class ExternalAgentCoordinator:
    def __init__(self, db_path: str | Path, *, run_binding: dict, supervisor: Any,
                 command_admin_client: HTTPExternalAuthorityClient,
                 effect_admin_client: HTTPExternalAuthorityClient, effect_gateway: Any, bridge: Any,
                 create: bool = True, watcher_interval: float = 0.1, start_watcher: bool = True):
        self.db_path = Path(db_path).absolute()
        self.run_binding = validate_run_binding(run_binding)
        self.supervisor, self.bridge, self.effect_gateway = supervisor, bridge, effect_gateway
        self.command_admin_client, self.effect_admin_client = command_admin_client, effect_admin_client
        if type(watcher_interval) not in (int, float) or not math.isfinite(watcher_interval) or not 0.01 <= watcher_interval <= 5:
            raise ControlError("AGENT_WATCHER_INTERVAL_INVALID")
        self.watcher_interval = float(watcher_interval)
        self._operation_lock = threading.RLock()
        self._event_lock = threading.RLock()
        self._watcher_stop = threading.Event()
        self._watcher_ready = threading.Event()
        self._watcher_health_lock = threading.RLock()
        self._watcher_last_completed: float | None = None
        self._watcher: threading.Thread | None = None
        self._closed = False
        self._command_id: str | None = None
        if any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("AGENT_COORDINATOR_DATABASE_UNSAFE")
        configuration = self._configuration()
        created = not self.db_path.exists()
        if created:
            if not create:
                raise ControlError("AGENT_COORDINATOR_STATE_MISSING")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self.db_path.open("xb"):
                pass
            self.db_path.chmod(0o600)
            with connect(self.db_path, create=False) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE agent_coordinator_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE agent_coordinator_run(singleton INTEGER PRIMARY KEY CHECK(singleton=1),state_json TEXT NOT NULL);
                    CREATE TABLE agent_coordinator_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_json TEXT NOT NULL);
                """)
                db.execute("INSERT INTO agent_coordinator_meta VALUES ('configuration',?)", (configuration,))
                db.execute("INSERT INTO agent_coordinator_run VALUES (1,?)", (canonical_bytes({
                    "state": "ACTIVE", "reason": None, "command_id": None, "aggregate": None,
                    "watcher_failed": False, "closed_at": None}).decode(),))
        with self._connection():
            pass
        self._command_id = self._state()["command_id"]
        if not created:
            # Recovery never treats an unfinished ACTIVE row as permission to
            # launch. The durable fence precedes callbacks and all remote I/O.
            self._close_local("HOST_RECOVERY")
        if start_watcher:
            self.start_watcher()

    def _configuration(self) -> str:
        binding = validate_run_binding(self.run_binding)
        clients = (self.command_admin_client, self.effect_admin_client)
        for branch, client in zip(("command", "effect"), clients):
            if (not isinstance(client, HTTPExternalAuthorityClient) or client.role != "admin"
                    or canonical_bytes(client.pin()) != canonical_bytes(binding[branch]["authority_pin"])):
                raise ControlError("AGENT_COORDINATOR_AUTHORITY_BINDING_MISMATCH")
        if canonical_bytes(self.supervisor.pin()) != canonical_bytes(binding["supervisor_pin"]):
            raise ControlError("AGENT_COORDINATOR_SUPERVISOR_BINDING_MISMATCH")
        if (canonical_bytes(self.effect_gateway.external_controller.pin()) != canonical_bytes(binding["effect"]["authority_pin"])
                or canonical_bytes(self.effect_gateway.endpoint_client.pin()) != canonical_bytes(binding["endpoint_pin"])):
            raise ControlError("AGENT_COORDINATOR_GATEWAY_BINDING_MISMATCH")
        if (self.supervisor.bridge is not self.bridge
                or getattr(self.bridge.executor, "__self__", None) is not self.effect_gateway
                or canonical_bytes(self.bridge.configuration().get("effect_gateway_configuration")) !=
                canonical_bytes(json.loads(self.effect_gateway._configuration()))):
            raise ControlError("AGENT_COORDINATOR_EXECUTOR_BINDING_MISMATCH")
        bridge_binding = self.bridge.configuration().get("run_binding")
        expected = {"run_id": binding["run_id"], **{k: binding["effect"][k] for k in ("root_id", "execution_id", "epoch")}}
        if (canonical_bytes(bridge_binding) != canonical_bytes(expected)
                or canonical_bytes(self.bridge.configuration().get("actions")) != canonical_bytes(binding["effect_actions"])):
            raise ControlError("AGENT_COORDINATOR_BRIDGE_BINDING_MISMATCH")
        return canonical_bytes({"schema": "liminal-agent-coordinator-store-v1", "profile": AGENT_PROFILE,
            "run_binding": binding, "run_binding_digest": digest(binding),
            "bridge_configuration_digest": digest(self.bridge.configuration()),
            "effect_gateway_configuration": json.loads(self.effect_gateway._configuration()),
            "command_authority_url": clients[0].url, "effect_authority_url": clients[1].url,
            "command_admin_key_digest": hashlib.sha256(clients[0].request_key).hexdigest(),
            "effect_admin_key_digest": hashlib.sha256(clients[1].request_key).hexdigest()}).decode()

    def _connection(self):
        if self._closed or not self.db_path.is_file() or any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("AGENT_COORDINATOR_STATE_MISSING")
        db = connect(self.db_path, create=False)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM agent_coordinator_meta")}
            if tables != _TABLES or meta != {"configuration": self._configuration()}:
                raise ControlError("AGENT_COORDINATOR_CONFIGURATION_IMMUTABLE")
            return db
        except BaseException:
            db.close()
            raise

    def _state(self) -> dict:
        with self._connection() as db:
            row = db.execute("SELECT state_json FROM agent_coordinator_run WHERE singleton=1").fetchone()
        if row is None:
            raise ControlError("AGENT_COORDINATOR_STATE_CORRUPT")
        return json.loads(row[0])

    def _update(self, **changes) -> dict:
        with self._event_lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            state = json.loads(db.execute("SELECT state_json FROM agent_coordinator_run WHERE singleton=1").fetchone()[0])
            state.update(changes)
            db.execute("UPDATE agent_coordinator_run SET state_json=? WHERE singleton=1", (canonical_bytes(state).decode(),))
        return state

    def _event(self, kind: str, **details) -> None:
        with self._event_lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM agent_coordinator_events").fetchone()[0] >= MAX_EVENTS:
                return  # No evidence capacity event can reopen admission.
            db.execute("INSERT INTO agent_coordinator_events(event_json) VALUES (?)", (canonical_bytes({
                "kind": kind, "observed_at": time.time(), **details}).decode(),))

    def fence_state(self) -> dict:
        """Nonblocking-with-respect-to-cleanup durable admission observation."""
        try:
            state = self._state()
            return {"closed": state["state"] != "ACTIVE" or state["watcher_failed"] is True,
                    "state": state["state"], "reason": state["reason"]}
        except Exception as exc:
            return {"closed": True, "state": "UNKNOWN", "reason": _reason(exc)}

    def _close_local(self, reason: str) -> None:
        validate_id(reason, "reason")
        def durable_close():
            state = self._state()
            if state["state"] == "ACTIVE":
                self._update(state="CLOSING", reason=reason, closed_at=time.time())
                self._event("DURABLE_ADMISSION_CLOSED", reason=reason)
        # The bridge shares this very short admission lock with proposal
        # registration. Persisting closure and publishing the local fence are
        # one ordered boundary; it never holds a Docker or network callback.
        self.bridge.close_admission(reason, durable_close)

    def close_admission(self, reason: str) -> dict:
        """Persist local closure without waiting for Docker or remote callbacks.

        This is an admission fence, not a STOPPED or no-effect certificate.
        The watcher performs the separate containment/reconciliation work.
        """
        self._close_local(reason)
        return self.fence_state()

    def _fresh_states(self) -> tuple[dict, dict, list[dict]]:
        states, evidence = [], []
        for branch, client in (("command", self.command_admin_client), ("effect", self.effect_admin_client)):
            result = client.status(self.run_binding[branch]["root_id"])
            if (result.get("root_id") != self.run_binding[branch]["root_id"]
                    or type(result.get("epoch")) is not int or result["epoch"] < self.run_binding[branch]["epoch"]
                    or result.get("state") not in ("ACTIVE", "STOPPING", "STOPPED")
                    or result.get("policy_digest") != agent_policy_digest(self.run_binding, branch)):
                raise ControlError("AGENT_COORDINATOR_STATE_BINDING_MISMATCH")
            states.append(result)
            evidence.append({"branch": branch, "pair": client.evidence[-1]})
        return states[0], states[1], evidence

    def launch(self, action: Any) -> dict:
        action = validate_agent_action(action)
        with self._operation_lock:
            if self.fence_state()["closed"]:
                return {"status": "DENIED", "reason": "AGENT_RUN_CLOSED", "action_id": action["action_id"], "execution_authorized": False}
            binding = self.run_binding["command"]
            if (any(type(action[k]) is not type(binding[k]) or action[k] != binding[k]
                    for k in ("root_id", "execution_id", "epoch"))
                    or digest(action["arguments"]["spec"]) != self.run_binding["spec_digest"]):
                raise ControlError("AGENT_COORDINATOR_LAUNCH_BINDING_MISMATCH")
            try:
                command, effect, _ = self._fresh_states()
                if command["admission_closed"] or effect["admission_closed"]:
                    self.stop("EXTERNAL_ADMISSION_CLOSED")
                    return {"status": "DENIED", "reason": "AGENT_EXTERNAL_ADMISSION_CLOSED", "action_id": action["action_id"], "execution_authorized": False}
            except Exception as exc:
                self._close_local("AUTHORITY_UNAVAILABLE")
                self._event("LAUNCH_HEALTH_FAILURE", reason=_reason(exc))
                self.stop("AUTHORITY_UNAVAILABLE")
                return {"status": "UNKNOWN", "reason": _reason(exc), "action_id": action["action_id"], "execution_authorized": False}
            command_id = action["arguments"]["spec"]["command_id"]
            if self._command_id not in (None, command_id):
                raise ControlError("AGENT_COORDINATOR_COMMAND_IMMUTABLE")
            self._update(command_id=command_id)
            self._command_id = command_id
            return self.supervisor.execute(action)

    def stop(self, reason: str = "HOST_STOP") -> dict:
        # Persist and fence first, before waiting for any operation lock. A
        # blocked endpoint callback never needs this lock to finish or query
        # fence_state, which reads its own independent SQLite snapshot.
        try:
            self._close_local(reason)
        except Exception as exc:
            return self._emergency_contain("DURABLE_COORDINATOR_UNAVAILABLE", exc)
        with self._operation_lock:
            failures = []
            for branch, client in (("command", self.command_admin_client), ("effect", self.effect_admin_client)):
                try:
                    result = client.stop(self.run_binding[branch]["root_id"])
                    self._event("EXTERNAL_STOP", branch=branch, result=result, pair=client.evidence[-1])
                except Exception as exc:
                    failures.append({"branch": branch, "reason": _reason(exc)})
            return self._reconcile_closed(failures)

    def _emergency_contain(self, reason: str, error: BaseException) -> dict:
        """Independent best efforts when coordinator journaling is unavailable.

        A failed coordinator store cannot prevent external STOP or cleanup of
        the already identified owned workload. It also cannot produce a new
        durable proof or a STOPPED aggregate, even if cleanup happens to work.
        """
        failures = [{"branch": "coordinator_store", "reason": _reason(error)}]
        try:
            self.bridge.fence(reason)
        except BaseException as exc:
            failures.append({"branch": "bridge_fence", "reason": _reason(exc)})
        for branch, client in (("command", self.command_admin_client), ("effect", self.effect_admin_client)):
            try:
                client.stop(self.run_binding[branch]["root_id"])
            except BaseException as exc:
                failures.append({"branch": branch, "reason": _reason(exc)})
        cleanup = None
        if self._command_id is not None:
            try:
                cleanup = self.supervisor.cleanup(self._command_id)
            except BaseException as exc:
                failures.append({"branch": "owned_cleanup", "reason": _reason(exc)})
        return {"schema": "liminal-agent-stop-aggregate-v1", "run_id": self.run_binding["run_id"],
            "run_binding_digest": digest(self.run_binding), "status": "UNKNOWN", "admission_closed": True,
            "reason": reason, "cleanup": cleanup, "failures": failures, "authority_observations": [],
            "coordinator_durable_state": "UNAVAILABLE", "execution_authorized": False, "model_calls": 0}

    def _reconcile_closed(self, failures: list[dict] | None = None) -> dict:
        failures = list(failures or [])
        cleanup = {"status": "QUIESCENT", "process_quiescent": True, "stages": [], "execution_authorized": False}
        if self._command_id is not None:
            try:
                cleanup = self.supervisor.cleanup(self._command_id)
            except Exception as exc:
                cleanup = {"status": "UNKNOWN", "process_quiescent": False, "reason": _reason(exc), "stages": []}
        effects = []
        bridge_busy = self.bridge.inventory().get("outstanding_effect_calls") != 0
        for action in self.run_binding["effect_actions"]:
            if bridge_busy:
                # NetworkGateway.execute holds its local transaction/lock for
                # the full endpoint call. Querying that lock here would turn
                # STOP into a wait for the very callback it is containing.
                effects.append({"status": "UNKNOWN", "action_id": action["action_id"],
                                "reason": "AGENT_EFFECT_CALLBACK_INFLIGHT", "execution_authorized": False})
                continue
            try:
                effects.append(self.effect_gateway.reconcile(action["action_id"]))
            except Exception as exc:
                effects.append({"status": "UNKNOWN", "action_id": action["action_id"], "reason": _reason(exc)})
        try:
            command, effect, proofs = self._fresh_states()
        except Exception as exc:
            command, effect, proofs = None, None, []
            failures.append({"branch": "fresh_observation", "reason": _reason(exc)})
        try:
            inventory = self.supervisor.inventory()
            stages = [state for state in inventory["grants"] if state["reservation_id"] is not None]
            def terminal_matches(state):
                action, receipt = state["action"], state["receipt"]
                return (state["callback_phase"] == "FINISHED" and state["settlement_status"] == "SETTLED"
                    and verify_agent_receipt(receipt, self.run_binding["supervisor_pin"])
                    and receipt["reservation_id"] == state["reservation_id"]
                    and receipt["action_digest"] == digest(action)
                    and receipt["authorization_digest"] == digest(state["authorization"])
                    and receipt["stage"] == action["arguments"]["stage"]
                    and all(type(receipt[k]) is type(action[k]) and receipt[k] == action[k]
                            for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                    and digest(action["arguments"]["spec"]) == self.run_binding["spec_digest"]
                    and all(type(action[k]) is type(self.run_binding["command"][k])
                            and action[k] == self.run_binding["command"][k]
                            for k in ("root_id", "execution_id", "epoch")))
            lifecycle_verified = all(terminal_matches(state) for state in stages)
            callbacks_finished = all(state["callback_phase"] != "INFLIGHT" for state in inventory["grants"])
            bridge = inventory["bridge"]
            bridge_finished = bridge.get("outstanding_effect_calls") == 0 and (
                not inventory["attach_processes"] or bridge.get("callback_finished") is True)
            cli_reaped = all(entry["reaped"] is True for entry in inventory["attach_processes"])
            if command is not None:
                lifecycle_verified = lifecycle_verified and len(stages) == command["issued_count"]
        except Exception as exc:
            lifecycle_verified = callbacks_finished = bridge_finished = cli_reaped = False
            failures.append({"branch": "supervisor_observation", "reason": _reason(exc)})
        known = command is not None and effect is not None
        local_quiescent = cleanup.get("process_quiescent") is True and callbacks_finished and bridge_finished and cli_reaped
        if not known or self._state()["watcher_failed"]:
            status = "UNKNOWN"
        elif command["admission_closed"] is not True or effect["admission_closed"] is not True:
            status = "UNKNOWN"
        elif command["pending_count"] > 0 or effect["pending_count"] > 0:
            # Confirmed closed admission and a still-owned reservation are a
            # positive STOP_PENDING fact even if local process observation is
            # unavailable. It never implies zero survivors or zero effects.
            status = "STOP_PENDING"
        elif command["state"] != "STOPPED" or effect["state"] != "STOPPED":
            status = "STOP_PENDING"
        elif not local_quiescent or not lifecycle_verified:
            status = "UNKNOWN"
        else:
            status = "STOPPED"
        aggregate = {"schema": "liminal-agent-stop-aggregate-v1", "run_id": self.run_binding["run_id"],
            "run_binding_digest": digest(self.run_binding), "status": status, "admission_closed": True,
            "command_state": command, "effect_state": effect, "authority_observations": proofs,
            "cleanup": cleanup, "effects": effects, "process_quiescent": cleanup.get("process_quiescent") is True,
            "process_quiescence": "CONFIRMED" if cleanup.get("process_quiescent") is True else "UNKNOWN",
            "callbacks_finished": callbacks_finished, "bridge_callbacks_finished": bridge_finished,
            "attach_cli_reaped": cli_reaped, "lifecycle_receipts_verified": lifecycle_verified,
            "failures": failures, "observed_at": time.time(), "execution_authorized": False,
            "business_effects": "ENDPOINT_RECEIPTS_ONLY", "model_calls": 0}
        self._update(state="STOPPED" if status == "STOPPED" else "CLOSING", aggregate=aggregate)
        return aggregate

    def reconcile(self) -> dict:
        with self._operation_lock:
            if self.fence_state()["closed"]:
                return self.stop("HOST_RECONCILIATION")
            try:
                command, effect, proofs = self._fresh_states()
                bridge = self.bridge.inventory()
                if bridge.get("fenced") is True:
                    return self.stop("BRIDGE_FENCED")
                if command["admission_closed"] or effect["admission_closed"]:
                    return self.stop("EXTERNAL_ADMISSION_CLOSED")
                return {"status": "ACTIVE", "run_id": self.run_binding["run_id"], "admission_closed": False,
                        "authority_observations": proofs, "execution_authorized": False}
            except Exception as exc:
                self._event("HEALTH_FAILURE", reason=_reason(exc))
                return self.stop("AUTHORITY_UNAVAILABLE")

    def status(self) -> dict:
        return self.reconcile()

    def _watch(self) -> None:
        try:
            while not self._watcher_stop.is_set():
                self.reconcile()
                with self._watcher_health_lock:
                    self._watcher_last_completed = time.monotonic()
                    self._watcher_ready.set()
                if self._watcher_stop.wait(self.watcher_interval):
                    break
        except BaseException as exc:
            try:
                self._update(watcher_failed=True)
            except BaseException:
                pass
            try:
                self._close_local("WATCHER_FAILURE")
                self._event("WATCHER_FAILURE", reason=_reason(exc))
            except BaseException:
                pass
            self._emergency_contain("WATCHER_FAILURE", exc)
        finally:
            self._watcher_ready.clear()

    def watcher_health(self, *, max_age_seconds: float = 2.0) -> dict:
        """Observe a completed host watcher cycle, never an execution grant.

        Thread presence alone is insufficient: an alive but blocked watcher
        loses freshness. Recovery has no inherited readiness or heartbeat.
        This is an in-process monitor; host-process crash survival is not
        established by this observation.
        """
        if (type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds)
                or not 0.05 <= max_age_seconds <= 5.0):
            raise ControlError("AGENT_WATCHER_HEALTH_WINDOW_INVALID")
        with self._watcher_health_lock:
            last = self._watcher_last_completed
            now = time.monotonic()
            age = None if last is None else now - last
            alive = bool(self._watcher and self._watcher.is_alive())
            stopping = self._closed or self._watcher_stop.is_set()
            ready = self._watcher_ready.is_set() and alive and not stopping
            fresh = bool(ready and age is not None and math.isfinite(age)
                         and 0 <= age < max_age_seconds)
            return {"ready": ready, "alive": alive, "fresh": fresh,
                    "last_completed": last, "age_seconds": age,
                    "interval_seconds": self.watcher_interval, "stopping": stopping,
                    "execution_authorized": False}

    def wait_watcher_ready(self, *, timeout: float = 5.0) -> bool:
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 5):
            raise ControlError("AGENT_WATCHER_READY_TIMEOUT_INVALID")
        return self._watcher_ready.wait(timeout) and self.watcher_health()["fresh"]

    def start_watcher(self) -> None:
        if self._watcher is not None:
            raise ControlError("AGENT_WATCHER_ALREADY_STARTED")
        self._watcher = threading.Thread(target=self._watch, name="liminal-agent-host-watcher", daemon=True)
        self._watcher.start()

    def inventory(self) -> dict:
        with self._connection() as db:
            db.execute("BEGIN")
            state = json.loads(db.execute("SELECT state_json FROM agent_coordinator_run WHERE singleton=1").fetchone()[0])
            events = [json.loads(row[0]) for row in db.execute("SELECT event_json FROM agent_coordinator_events ORDER BY sequence")]
        return {"profile": AGENT_PROFILE, "run_binding": _copy(self.run_binding), "run_binding_digest": digest(self.run_binding),
                "state": state, "events": events, "watcher_alive": bool(self._watcher and self._watcher.is_alive()),
                "execution_authorized": False}

    def close(self) -> None:
        if self._closed:
            return
        self.stop("HOST_CLOSE")
        self._watcher_stop.set()
        if self._watcher is not None and threading.current_thread() is not self._watcher:
            self._watcher.join(35)
            if self._watcher.is_alive():
                raise ControlError("AGENT_WATCHER_STILL_RUNNING")
        self._closed = True
