"""Trusted, durable supervisor for one fixed owned Docker command at a time.

Worker proposals carry neither Docker authority nor grants. Fresh external
one-shot admission precedes each CREATE and START. Only positive owned-object
observations plus finished host callbacks can produce a signed quiescence
receipt; an absent object or a callback deadline alone cannot release a permit.
The supervisor database, lease, key and Docker daemon are trust assumptions.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from adapters.docker.liminal_docker_executor import build_docker_argv
from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .external_authority_service import HTTPExternalAuthorityClient
from .external_command_protocol import (
    COMMAND_FIXTURE_SHA256, COMMAND_PROFILE, COMMAND_RECEIPT_DOMAIN, COMMAND_RECEIPT_SCHEMA, command_plan,
    validate_command_action, validate_command_authorization, verify_command_receipt,
)
from .observer_auth import _crypto
from .runtime import BoundedHostCall, DockerController, RuntimeBoundaryError
from .supervisor_registry import SupervisorRegistry, ownership_labels

MAX_GRANTS = 1024
MAX_EVIDENCE = 8192
MAX_OBSERVATIONS = 128
_TABLES = {"command_supervisor_meta", "command_supervisor_grants", "command_supervisor_commands",
           "command_supervisor_evidence"}
_ID = re.compile(r"[0-9a-f]{64}\Z")
_DOCKER_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z")


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _error(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, (ControlError, RuntimeBoundaryError)) and re.fullmatch(
        r"[A-Z0-9_]{1,120}", str(exc)) else type(exc).__name__


def _positive_started_at(value: Any) -> bool:
    """Validate Docker's RFC3339 start observation, including nanoseconds.

    A nonempty string is not proof. Parsing checks calendar/time/offset ranges;
    Python may truncate fractional precision only after syntax admits 1..9
    digits. Docker's year-one unstarted sentinel never witnesses a launch.
    """
    if type(value) is not str or not _DOCKER_TIMESTAMP.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.year > 1
    except ValueError:
        return False


class ExternalCommandSupervisor:
    # Defaults retain the frozen command-v1 contract. A separate owned-agent
    # profile may override these protected host-side hooks; workers cannot
    # select a validator, profile, receipt domain or launch implementation.
    def _validate_action(self, action: Any) -> dict:
        return validate_command_action(action)

    def _validate_authorization(self, action: Any, authorization: Any) -> dict:
        return validate_command_authorization(action, authorization, self.supervisor_id)

    def _plan(self, spec: Any):
        return command_plan(spec)

    def _profile_name(self) -> str:
        return COMMAND_PROFILE

    def _store_schema(self) -> str:
        return "liminal-command-supervisor-store-v1"

    def _configuration_extra(self) -> dict:
        return {}

    def _verify_receipt(self, receipt: Any) -> bool:
        return verify_command_receipt(receipt, self.pin())

    def _receipt_schema(self) -> str:
        return COMMAND_RECEIPT_SCHEMA

    def _receipt_domain(self) -> bytes:
        return COMMAND_RECEIPT_DOMAIN

    def _start_dispatch(self, action: dict, command: dict):
        return self.controller.command(["start", "--attach", action["arguments"]["container_id"]], timeout=30)

    def __init__(self, db_path: str | Path, registry_path: str | Path, *, supervisor_id: str,
                 key_id: str, private_key: bytes, authority_client: HTTPExternalAuthorityClient,
                 controller: DockerController | None = None, create: bool = True) -> None:
        validate_id(supervisor_id, "supervisor_id")
        validate_id(key_id, "key_id")
        if type(private_key) is not bytes or len(private_key) != 32:
            raise ControlError("COMMAND_SUPERVISOR_PRIVATE_KEY_INVALID")
        private, _ = _crypto()
        self.supervisor_id, self.key_id, self._private_bytes = supervisor_id, key_id, private_key
        self._signer = private.from_private_bytes(private_key)
        self.authority_client = authority_client
        self.controller = controller if controller is not None else DockerController()
        self.db_path = Path(db_path).absolute()
        self.registry_path = Path(registry_path).absolute()
        self._lock = threading.RLock()
        self._calls: dict[str, BoundedHostCall] = {}
        self._closed = False
        # Trusted harness fault hooks. They are not part of the worker API.
        self.before_dispatch_hook = None
        self.after_dispatch_hook = None
        self.drop_begin_response = False
        self.drop_finish_response = False
        for path in (self.db_path, self.registry_path):
            if any(item.is_symlink() for item in (path, *path.parents)):
                raise ControlError("COMMAND_SUPERVISOR_DATABASE_UNSAFE")
        if not self.registry_path.exists() and not create:
            raise ControlError("COMMAND_SUPERVISOR_REGISTRY_MISSING")
        self.registry = SupervisorRegistry(self.registry_path)
        self._lease = self.registry.lease()
        self._lease.__enter__()
        try:
            configuration = self._configuration()
            if not self.db_path.exists():
                if not create:
                    raise ControlError("COMMAND_SUPERVISOR_STATE_MISSING")
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                with self.db_path.open("xb"):
                    pass
                self.db_path.chmod(0o600)
                with connect(self.db_path, create=False) as db:
                    db.execute("PRAGMA journal_mode=WAL")
                    db.executescript("""
                        CREATE TABLE command_supervisor_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                        CREATE TABLE command_supervisor_grants(
                            action_id TEXT PRIMARY KEY,attempt_id TEXT UNIQUE NOT NULL,state_json TEXT NOT NULL);
                        CREATE TABLE command_supervisor_commands(command_id TEXT PRIMARY KEY,state_json TEXT NOT NULL);
                        CREATE TABLE command_supervisor_evidence(
                            sequence INTEGER PRIMARY KEY AUTOINCREMENT,packet_json TEXT NOT NULL);
                    """)
                    db.execute("INSERT INTO command_supervisor_meta VALUES ('configuration',?)", (configuration,))
            with self._connection():
                pass
            for command in self._commands():
                if command["registry_record"] is not None:
                    self.controller.bind_ownership(command["registry_record"])
                    if command["container_id"] is not None:
                        self.controller.bind_container_id(command["registry_record"]["session_id"], command["container_id"])
        except BaseException:
            self._lease.__exit__(None, None, None)
            self._closed = True
            raise

    def pin(self) -> dict[str, str]:
        return {"supervisor_id": self.supervisor_id, "key_id": self.key_id,
                "public_key": self._signer.public_key().public_bytes_raw().hex()}

    def _configuration(self) -> str:
        client = self.authority_client
        if not isinstance(client, HTTPExternalAuthorityClient) or client.role != "receiver":
            raise ControlError("COMMAND_SUPERVISOR_AUTHORITY_CONFIGURATION_INVALID")
        if self.pin()["public_key"] == client.pin()["public_key"]:
            raise ControlError("COMMAND_SUPERVISOR_AUTHORITY_KEY_MUST_DIFFER")
        if client.request_key == self._private_bytes:
            raise ControlError("COMMAND_SUPERVISOR_REQUEST_KEY_MUST_DIFFER")
        if (self.registry.path != self.registry_path.resolve()
                or self.registry.lock_path != self.registry_path.resolve().with_name(self.registry_path.name + ".lock")
                or not self.registry_path.is_file()
                or any(path.is_symlink() for path in (self.registry_path, *self.registry_path.parents))):
            raise ControlError("COMMAND_SUPERVISOR_REGISTRY_MISSING")
        with self.registry._connect() as registry_db:
            registry_meta = {row["key"]: row["value"] for row in registry_db.execute("SELECT * FROM supervisor_meta")}
        if registry_meta != {"registry_id": self.registry.registry_id}:
            raise ControlError("COMMAND_SUPERVISOR_REGISTRY_IDENTITY_CHANGED")
        configuration = {"schema": self._store_schema(), "profile": self._profile_name(),
            "supervisor_pin": self.pin(), "authority_pin": client.pin(), "authority_url": client.url,
            "authority_role": client.role, "authority_request_key_digest": hashlib.sha256(client.request_key).hexdigest(),
            "registry_path": str(self.registry_path), "registry_id": self.registry.registry_id,
            "docker_binary": self.controller.docker_binary}
        extra = self._configuration_extra()
        if type(extra) is not dict or set(extra) & set(configuration):
            raise ControlError("COMMAND_SUPERVISOR_CONFIGURATION_EXTRA_INVALID")
        configuration.update(extra)
        return canonical_bytes(configuration).decode()

    def _connection(self):
        if self._closed or not self.db_path.is_file() or any(item.is_symlink() for item in (self.db_path, *self.db_path.parents)):
            raise ControlError("COMMAND_SUPERVISOR_STATE_MISSING")
        db = connect(self.db_path, create=False)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM command_supervisor_meta")}
            if tables != _TABLES or meta != {"configuration": self._configuration()}:
                raise ControlError("COMMAND_SUPERVISOR_CONFIGURATION_IMMUTABLE")
            return db
        except BaseException:
            db.close()
            raise

    def _grants(self) -> list[dict]:
        with self._connection() as db:
            rows = db.execute("SELECT state_json FROM command_supervisor_grants ORDER BY action_id").fetchall()
        return [json.loads(row[0]) for row in rows]

    def _grant(self, action_id: str) -> dict | None:
        validate_id(action_id, "action_id")
        with self._connection() as db:
            row = db.execute("SELECT state_json FROM command_supervisor_grants WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            return None
        state = json.loads(row[0])
        action = self._validate_action(state["action"])
        grant = self._validate_authorization(action, state["authorization"])
        if (action["action_id"] != action_id or state["action_digest"] != digest(action)
                or state["authorization_digest"] != digest(grant)):
            raise ControlError("COMMAND_SUPERVISOR_GRANT_CORRUPT")
        return state

    def _save_grant(self, state: dict) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE command_supervisor_grants SET state_json=? WHERE action_id=?",
                (canonical_bytes(state).decode(), state["action"]["action_id"]))

    def _commands(self) -> list[dict]:
        with self._connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT state_json FROM command_supervisor_commands ORDER BY command_id")]

    def _command(self, command_id: str) -> dict | None:
        validate_id(command_id, "command_id")
        with self._connection() as db:
            row = db.execute("SELECT state_json FROM command_supervisor_commands WHERE command_id=?", (command_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def _save_command(self, command: dict) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO command_supervisor_commands VALUES (?,?) ON CONFLICT(command_id) DO UPDATE SET state_json=excluded.state_json",
                (command["command_id"], canonical_bytes(command).decode()))

    def authorize(self, action: Any, grant: Any) -> dict:
        """Trusted admin operation; workers can only submit an exact proposal."""
        with self._lock:
            action = self._validate_action(action)
            grant = self._validate_authorization(action, grant)
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                rows = db.execute("SELECT state_json FROM command_supervisor_grants WHERE action_id=? OR attempt_id=?",
                    (action["action_id"], action["attempt_id"])).fetchall()
                if rows:
                    existing = json.loads(rows[0][0])
                    if (len(rows) != 1 or canonical_bytes(existing["action"]) != canonical_bytes(action)
                            or canonical_bytes(existing["authorization"]) != canonical_bytes(grant)):
                        raise ControlError("COMMAND_SUPERVISOR_GRANT_IMMUTABLE")
                else:
                    if db.execute("SELECT COUNT(*) FROM command_supervisor_grants").fetchone()[0] >= MAX_GRANTS:
                        raise ControlError("COMMAND_SUPERVISOR_GRANT_CAPACITY")
                    state = {"action": action, "authorization": grant, "action_digest": digest(action),
                        "authorization_digest": digest(grant), "reservation_id": None, "begin_evidence": None,
                        "callback_phase": "NOT_DISPATCHED", "callback_result": None, "receipt": None,
                        "settlement_status": None, "status": "AUTHORIZED"}
                    db.execute("INSERT INTO command_supervisor_grants VALUES (?,?,?)",
                        (action["action_id"], action["attempt_id"], canonical_bytes(state).decode()))
            return {"status": "AUTHORIZED", "action_id": action["action_id"], "action_digest": digest(action),
                "authorization_digest": digest(grant), "execution_authorized": False}

    def _call(self, operation: str, *args) -> dict:
        with self._connection():
            pass
        prior = self.authority_client.evidence[-1] if self.authority_client.evidence else None
        try:
            result = getattr(self.authority_client, operation)(*args)
        finally:
            evidence = self.authority_client.evidence[-1] if self.authority_client.evidence else None
            if evidence is not None and evidence != prior:
                with self._connection() as db:
                    db.execute("BEGIN IMMEDIATE")
                    if db.execute("SELECT COUNT(*) FROM command_supervisor_evidence").fetchone()[0] >= MAX_EVIDENCE:
                        raise ControlError("COMMAND_SUPERVISOR_EVIDENCE_CAPACITY")
                    db.execute("INSERT INTO command_supervisor_evidence(packet_json) VALUES (?)", (canonical_bytes(evidence).decode(),))
        if operation == "begin" and self.drop_begin_response:
            self.drop_begin_response = False
            raise ControlError("COMMAND_TEST_BEGIN_RESPONSE_LOST")
        if operation == "finish" and self.drop_finish_response:
            self.drop_finish_response = False
            raise ControlError("COMMAND_TEST_FINISH_RESPONSE_LOST")
        return result

    def _bind(self, result: dict, action: dict) -> str:
        if (result.get("action_digest") != digest(action) or result.get("receiver_id") != self.supervisor_id
                or any(type(result.get(field)) is not type(action[field]) or result.get(field) != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("COMMAND_SUPERVISOR_AUTHORITY_BINDING_MISMATCH")
        return validate_id(result.get("reservation_id"), "reservation_id")

    def _stages(self, command_id: str) -> list[dict]:
        return sorted([state for state in self._grants() if state["action"]["arguments"]["spec"]["command_id"] == command_id
                       and state["reservation_id"] is not None],
                      key=lambda state: (state["action"]["arguments"]["stage"] != "CREATE", state["action"]["action_id"]))

    def _callbacks(self, command_id: str) -> list[dict]:
        return [{"action_id": state["action"]["action_id"], "stage": state["action"]["arguments"]["stage"],
                 "phase": state["callback_phase"], "result": state["callback_result"]} for state in self._stages(command_id)]

    def _result(self, state: dict | None, status: str, reason: str, action_id: str) -> dict:
        receipt = None if state is None else state["receipt"]
        return {"status": status, "reason": reason, "action_id": action_id,
            "reservation_id": None if state is None else state["reservation_id"],
            "callback_phase": None if state is None else state["callback_phase"],
            "process_quiescent": receipt is not None, "receipt": receipt,
            "settlement_status": None if state is None else state["settlement_status"],
            "business_effects": "NOT_ESTABLISHED", "execution_authorized": False}

    def _ready(self, action: dict) -> None:
        args = action["arguments"]
        self._verify_workspace(args["spec"])
        command = self._command(args["spec"]["command_id"])
        if args["stage"] == "CREATE":
            if command is not None or self.registry.unfinished():
                raise ControlError("COMMAND_SUPERVISOR_RECOVERY_REQUIRED")
            plan = self._plan(args["spec"])
            self.controller.image_id(plan.image_id)
            return
        if (command is None or command["closing"] or command["cleanup_complete"] or not command["create_confirmed"]
                or canonical_bytes(command["spec"]) != canonical_bytes(args["spec"])
                or command["container_id"] != args["container_id"]
                or command["root_id"] != action["root_id"] or command["execution_id"] != action["execution_id"]):
            raise ControlError("COMMAND_SUPERVISOR_PARENT_BINDING_MISMATCH")
        stages = self._stages(command["command_id"])
        creates = [s for s in stages if s["action"]["arguments"]["stage"] == "CREATE"]
        if (len(creates) != 1 or creates[0]["reservation_id"] != args["parent_reservation_id"]
                or creates[0]["callback_phase"] != "FINISHED"
                or any(s["action"]["arguments"]["stage"] == "START" for s in stages)):
            raise ControlError("COMMAND_SUPERVISOR_PARENT_NOT_READY")
        self.controller.verify_configuration(command["registry_record"]["session_id"], self._plan(command["spec"]))
        self._verify_fixed_configuration(command)

    def execute(self, proposed: Any) -> dict:
        """Fresh external admission and at most one durable host callback."""
        with self._lock:
            action = self._validate_action(proposed)
            state = self._grant(action["action_id"])
            if state is None or canonical_bytes(state["action"]) != canonical_bytes(action):
                return self._result(state, "DENIED", "COMMAND_EXACT_HOST_GRANT_REQUIRED", action["action_id"])
            # Readiness only precedes a first operation. Repeated proposals still
            # query fresh BEGIN and must never become a new callback.
            if state["reservation_id"] is None:
                try:
                    self._ready(action)
                except Exception as exc:
                    return self._result(state, "DENIED", _error(exc), action["action_id"])
            try:
                permit = self._call("begin", action, state["authorization"])
                if permit.get("status") == "DENIED":
                    return self._result(state, "DENIED", permit.get("reason", "COMMAND_ADMISSION_DENIED"), action["action_id"])
                reservation = self._bind(permit, action)
                if permit.get("status") != "PERMITTED":
                    if permit.get("status") == "CONSUMED" and permit.get("receipt") is not None:
                        return self._accept_terminal(state, permit)
                    return self._result(state, "UNKNOWN", "COMMAND_PERMIT_ALREADY_CONSUMED", action["action_id"])
                if state["reservation_id"] is not None or state["callback_phase"] != "NOT_DISPATCHED":
                    raise ControlError("COMMAND_SUPERVISOR_STATE_DIVERGENCE")
                state.update(reservation_id=reservation, begin_evidence=self.authority_client.evidence[-1],
                             callback_phase="INFLIGHT", status="UNKNOWN")
                self._save_grant(state)
                self._prepare(action)
                self._calls[action["action_id"]] = BoundedHostCall(
                    lambda: self._dispatch(action), name="liminal-command-" + action["arguments"]["stage"].lower())
                return self._result(state, "UNKNOWN", "COMMAND_CALLBACK_INFLIGHT", action["action_id"])
            except Exception as exc:
                return self._result(self._grant(action["action_id"]), "UNKNOWN", _error(exc), action["action_id"])

    def _prepare(self, action: dict) -> None:
        args = action["arguments"]
        if args["stage"] != "CREATE":
            return
        spec = args["spec"]
        session_id = "liminal-control-" + uuid.uuid4().hex
        plan = self._plan(spec)
        record = self.registry.register(session_id=session_id, root_id=action["root_id"], action_id=action["action_id"],
            image_id=plan.image_id, plan_sha256=plan.plan_sha256,
            backend_identity_sha256=digest({"backend": "docker", "image_id": plan.image_id}),
            receiver_id=self.supervisor_id, broker_context_sha256=digest({"profile": self._profile_name(), "spec": spec}))
        image_observation = self.controller.command(["image", "inspect", plan.image_id], timeout=3)
        try:
            images = json.loads(image_observation.stdout)
            if image_observation.returncode or len(images) != 1 or images[0].get("Id") != plan.image_id:
                raise ValueError
            image_environment_digest = digest(images[0].get("Config", {}).get("Env"))
        except (ValueError, TypeError, KeyError) as exc:
            raise ControlError("COMMAND_IMAGE_ENVIRONMENT_UNAVAILABLE") from exc
        command = {"command_id": spec["command_id"], "root_id": action["root_id"], "execution_id": action["execution_id"],
            "image_id": plan.image_id, "plan_sha256": plan.plan_sha256, "spec": spec, "registry_record": record,
            "container_id": None, "create_confirmed": False, "cleanup_complete": False,
            "closing": False, "image_environment_digest": image_environment_digest,
            "start_observed": False, "observations": [], "registry_completion": None}
        self._save_command(command)
        self.controller.bind_ownership(record)
        # This durable uncertainty marker precedes the first daemon request.
        self.registry.mark_create_pending(record)

    def _create_argv(self, command: dict) -> list[str]:
        plan = self._plan(command["spec"])
        argv = build_docker_argv(plan, docker_binary=self.controller.docker_binary,
                                container_name=command["registry_record"]["session_id"], entrypoint="python3")
        argv[1:3] = ["create", "--interactive"]
        index = argv.index(plan.image_id)
        extra = []
        for key, value in ownership_labels(command["registry_record"]).items():
            extra += ["--label", f"{key}={value}"]
        argv[index:index] = extra
        return argv[1:]

    def _dispatch(self, action: dict) -> None:
        stage = action["arguments"]["stage"]
        result = None
        failure = None
        try:
            if self.before_dispatch_hook is not None:
                self.before_dispatch_hook(stage, _copy(action))
            self._verify_workspace(action["arguments"]["spec"])
            command = self._command(action["arguments"]["spec"]["command_id"])
            if command is None:
                raise ControlError("COMMAND_SUPERVISOR_COMMAND_MISSING")
            if stage == "CREATE":
                result = self.controller.command(self._create_argv(command), timeout=30)
            else:
                result = self._start_dispatch(action, command)
            if self.after_dispatch_hook is not None:
                self.after_dispatch_hook(stage, _copy(action), result)
        except BaseException as exc:
            failure = _error(exc)
        # The journal is written by the callback itself after it has actually
        # returned from Docker and every trusted delivery hook.
        callback = {"finished_at": time.time(), "returned": result is not None,
                    "returncode": None if result is None else result.returncode,
                    "error": failure,
                    "stdout_sha256": None if result is None else hashlib.sha256(result.stdout).hexdigest(),
                    "stdout_bytes": None if result is None else len(result.stdout),
                    "stdout_hex": None if result is None else result.stdout[:8192].hex(),
                    "stderr_sha256": None if result is None else hashlib.sha256(result.stderr).hexdigest(),
                    "stderr_bytes": None if result is None else len(result.stderr)}
        state = self._grant(action["action_id"])
        if state is None or state["callback_phase"] != "INFLIGHT":
            raise ControlError("COMMAND_SUPERVISOR_CALLBACK_JOURNAL_CORRUPT")
        state.update(callback_phase="FINISHED", callback_result=callback)
        self._save_grant(state)

    def _append(self, command: dict, kind: str, value: Any, *, callbacks_digest: str | None = None) -> dict:
        if len(command["observations"]) >= MAX_OBSERVATIONS:
            raise ControlError("COMMAND_SUPERVISOR_OBSERVATION_CAPACITY")
        observation = {"kind": kind, "observed_at": time.time(), "container_id": command["container_id"],
                       "value": _copy(value), "callbacks_digest": callbacks_digest}
        command["observations"].append(observation)
        self._save_command(command)
        return observation

    @staticmethod
    def _bounded_inspect(item: dict) -> dict:
        # Fixed daemon fields suffice for public ownership/config/state checks;
        # environment contents and arbitrary Docker metadata are not published.
        config, host = item.get("Config", {}), item.get("HostConfig", {})
        config_fields = ("Labels", "User", "Entrypoint", "Cmd", "WorkingDir")
        host_fields = ("NetworkMode", "LogConfig", "ReadonlyRootfs", "Privileged", "PidMode", "IpcMode",
                       "CapDrop", "CapAdd", "SecurityOpt", "PidsLimit", "Memory", "NanoCpus", "Tmpfs")
        return {"Id": item.get("Id"), "Image": item.get("Image"),
            "Config": {**{key: config.get(key) for key in config_fields}, "EnvDigest": digest(config.get("Env"))},
            "HostConfig": {key: host.get(key) for key in host_fields},
            "Mounts": [{"Source": mount.get("Source"), "Destination": mount.get("Destination"), "RW": mount.get("RW")}
                       for mount in item.get("Mounts", [])],
            "State": {key: item.get("State", {}).get(key) for key in ("Running", "Paused", "Pid", "StartedAt", "FinishedAt", "ExitCode")}}

    def _verify_fixed_configuration(self, command: dict) -> dict:
        item = self.controller._inspect(command["registry_record"]["session_id"])
        if item is None:
            raise ControlError("COMMAND_CREATED_OBJECT_UNAVAILABLE")
        config = item.get("Config", {})
        if (config.get("Entrypoint") != ["python3"] or config.get("Cmd") != command["spec"]["argv"]
                or config.get("WorkingDir") != "/workspace"
                or digest(config.get("Env")) != command["image_environment_digest"]):
            raise ControlError("COMMAND_FIXED_CONFIGURATION_MISMATCH")
        return item

    @staticmethod
    def _verify_workspace(spec: dict) -> None:
        workspace = Path(spec["host_workspace"])
        fixture = workspace / "external_command_fixture.py"
        if (not workspace.is_dir() or not fixture.is_file()
                or any(path.is_symlink() for path in (workspace, *workspace.parents, fixture))
                or {path.name for path in workspace.iterdir()} != {fixture.name}
                or fixture.stat().st_mode & 0o222
                or hashlib.sha256(fixture.read_bytes()).hexdigest() != COMMAND_FIXTURE_SHA256):
            raise ControlError("COMMAND_FIXED_WORKSPACE_MISMATCH")

    def _observe(self, command_id: str) -> dict:
        command = self._command(command_id)
        if command is None:
            raise ControlError("COMMAND_SUPERVISOR_COMMAND_MISSING")
        stages = self._stages(command_id)
        creates = [state for state in stages if state["action"]["arguments"]["stage"] == "CREATE"]
        if len(creates) != 1 or creates[0]["callback_phase"] != "FINISHED":
            return command
        if not command["create_confirmed"]:
            item = self.controller._inspect(command["registry_record"]["session_id"])
            if item is None:
                return command
            container_id = item.get("Id")
            if type(container_id) is not str or not _ID.fullmatch(container_id):
                raise ControlError("COMMAND_IMMUTABLE_CONTAINER_ID_INVALID")
            self.controller.bind_container_id(command["registry_record"]["session_id"], container_id)
            self.controller.verify_configuration(command["registry_record"]["session_id"], self._plan(command["spec"]))
            self._verify_fixed_configuration(command)
            self.registry.confirm_created(command["registry_record"], container_id)
            command.update(container_id=container_id, create_confirmed=True)
            self._append(command, "positive_create", self._bounded_inspect(item))
        if not command["cleanup_complete"]:
            item = self.controller._inspect(command["registry_record"]["session_id"])
            if item is not None:
                state = item.get("State", {})
                started = state.get("StartedAt")
                start_proof = state.get("Running") is True or _positive_started_at(started)
                if start_proof and not command["start_observed"]:
                    command["start_observed"] = True
                    self._append(command, "positive_start", self._bounded_inspect(item))
        return command

    def _accept_terminal(self, state: dict, result: dict) -> dict:
        action, receipt = state["action"], result.get("receipt")
        reservation = self._bind(result, action)
        if (not self._verify_receipt(receipt) or receipt["reservation_id"] != reservation
                or receipt["action_digest"] != digest(action)
                or receipt["authorization_digest"] != digest(state["authorization"])):
            raise ControlError("COMMAND_SUPERVISOR_TERMINAL_BINDING_MISMATCH")
        if state["receipt"] is None or canonical_bytes(state["receipt"]) != canonical_bytes(receipt):
            raise ControlError("COMMAND_SUPERVISOR_EXTERNAL_TERMINAL_UNKNOWN")
        state.update(settlement_status="SETTLED", status="QUIESCENT")
        self._save_grant(state)
        return self._result(state, "QUIESCENT", "COMMAND_QUIESCENCE_SETTLED", action["action_id"])

    def _settle(self, state: dict) -> dict:
        try:
            terminal = self._call("finish", state["reservation_id"], state["receipt"])
            if terminal.get("status") != "SETTLED" or terminal.get("outcome") != "COMMITTED":
                raise ControlError("COMMAND_SUPERVISOR_SETTLEMENT_MISMATCH")
            return self._accept_terminal(state, terminal)
        except Exception as exc:
            state.update(status="UNKNOWN", settlement_status="UNKNOWN")
            self._save_grant(state)
            return self._result(state, "UNKNOWN", _error(exc), state["action"]["action_id"])

    def reconcile(self, action_id: str) -> dict:
        """Observe owned state and retry evidence settlement, never dispatch."""
        with self._lock:
            state = self._grant(action_id)
            if state is None:
                return self._result(None, "UNKNOWN", "COMMAND_NOT_OBSERVED", action_id)
            try:
                observed = self._call("query", action_id)
                if observed.get("status") == "CONSUMED" and observed.get("receipt") is not None:
                    return self._accept_terminal(state, observed)
                if observed.get("reservation_id") is not None:
                    reservation = self._bind(observed, state["action"])
                    if state["reservation_id"] is None:
                        # Observation recovers consumption identity only. It
                        # never upgrades a delivered-lost permit into dispatch.
                        state.update(reservation_id=reservation, status="UNKNOWN")
                        self._save_grant(state)
                command_id = state["action"]["arguments"]["spec"]["command_id"]
                if self._command(command_id) is not None:
                    self._observe(command_id)
                if state["receipt"] is not None:
                    return self._settle(state)
                return self._result(state, "UNKNOWN", "COMMAND_TERMINAL_PROOF_UNAVAILABLE", action_id)
            except Exception as exc:
                return self._result(state, "UNKNOWN", _error(exc), action_id)

    def _complete_registry(self, command: dict) -> dict:
        """Recover the two durable stores' completion window without a launch.

        A closed row is accepted only for the same immutable registration,
        pinned container and completed callback journal. Its prior observation
        census must be an actual prefix of this command's durable census.
        This is a bookkeeping recovery; current quiescence is checked first.
        """
        record = command["registry_record"]
        callbacks_digest = digest(self._callbacks(command["command_id"]))
        with self.registry._connect() as db:
            row = db.execute("SELECT * FROM workloads WHERE session_id=?", (record["session_id"],)).fetchone()
        if row is None or canonical_bytes(json.loads(row["record_json"])) != canonical_bytes(record):
            raise ControlError("COMMAND_REGISTRY_COMPLETION_BINDING_MISMATCH")
        if row["status"] != "CLOSED":
            self.registry.complete(record, {"verified": True, "zero_survivors": True,
                "container_id": command["container_id"], "callbacks_digest": callbacks_digest,
                "observations_digest": digest(command["observations"])})
            with self.registry._connect() as db:
                row = db.execute("SELECT * FROM workloads WHERE session_id=?", (record["session_id"],)).fetchone()
        completion = json.loads(row["completion_json"])
        evidence = completion.get("evidence", {})
        if (row["status"] != "CLOSED" or row["launch_phase"] != "CREATED"
                or row["container_id"] != command["container_id"]
                or evidence.get("verified") is not True or evidence.get("zero_survivors") is not True
                or evidence.get("container_id") != command["container_id"]
                or evidence.get("callbacks_digest") != callbacks_digest
                or not any(digest(command["observations"][:size]) == evidence.get("observations_digest")
                           for size in range(1, len(command["observations"]) + 1))):
            raise ControlError("COMMAND_REGISTRY_COMPLETION_BINDING_MISMATCH")
        return completion

    def cleanup(self, command_id: str) -> dict:
        """Trusted local cleanup continues even when authority is unavailable."""
        with self._lock:
            command = self._command(command_id)
            if command is None:
                return {"status": "UNKNOWN", "reason": "COMMAND_NOT_OBSERVED", "command_id": command_id,
                        "process_quiescent": False, "stages": [], "execution_authorized": False}
            # Permanent host admission fence precedes any cleanup observation.
            # execute holds this same lock from BEGIN through durable callback
            # journal, so an old final census can never race a later START.
            if not command["closing"]:
                command["closing"] = True
                self._save_command(command)
            failure = None
            try:
                command = self._observe(command_id)
                if command["create_confirmed"] and not command["cleanup_complete"]:
                    session = command["registry_record"]["session_id"]
                    item = self.controller._inspect(session)
                    if item is not None:
                        if item.get("State", {}).get("Running") is True:
                            # Capture real descendant lineage before termination.
                            try:
                                self.controller.inspect_session(session)
                                self._append(command, "process_tree", self.controller.process_evidence[session])
                            except Exception:
                                pass
                            if item.get("State", {}).get("Paused") is True:
                                self.controller.command(["unpause", command["container_id"]], timeout=3)
                            self.controller.command(["kill", command["container_id"]], timeout=3)
                        # Waiting is bounded; a still-running callback continues
                        # to own the permit even if the container is stopped.
                        for state in self._stages(command_id):
                            call = self._calls.get(state["action"]["action_id"])
                            if call is not None:
                                call.done.wait(0.25)
                        callbacks = self._callbacks(command_id)
                        if (any(entry["phase"] != "FINISHED" for entry in callbacks)
                                or any(self._calls.get(entry["action_id"]) is not None
                                       and self._calls[entry["action_id"]].thread.is_alive() for entry in callbacks)):
                            raise ControlError("COMMAND_CALLBACKS_UNRESOLVED")
                        item = self.controller._inspect(session)
                        if (item is None or item.get("State", {}).get("Running") is not False
                                or item.get("State", {}).get("Paused") is not False
                                or type(item.get("State", {}).get("Pid")) is not int or item["State"]["Pid"] != 0):
                            raise ControlError("COMMAND_OWNED_OBJECT_NOT_POSITIVELY_STOPPED")
                        self.controller.verify_configuration(session, self._plan(command["spec"]))
                        self._verify_fixed_configuration(command)
                        if any(entry["stage"] == "START" for entry in callbacks) and not command["start_observed"]:
                            started = item.get("State", {}).get("StartedAt")
                            if _positive_started_at(started):
                                command["start_observed"] = True
                                self._append(command, "positive_start", self._bounded_inspect(item))
                            else:
                                raise ControlError("COMMAND_START_OUTCOME_UNRESOLVED")
                        self._append(command, "stopped_inspect", self._bounded_inspect(item), callbacks_digest=digest(callbacks))
                        removed = self.controller.command(["rm", command["container_id"]], timeout=3)
                        if removed.returncode or self.controller._inspect(session) is not None:
                            raise ControlError("COMMAND_REMOVAL_UNVERIFIED")
                        self._append(command, "removed_absence", {"exists": False, "lookup_id": command["container_id"]},
                                     callbacks_digest=digest(callbacks))
                    else:
                        callbacks = self._callbacks(command_id)
                        prior = [o for o in command["observations"] if o["kind"] == "stopped_inspect"
                                 and o["callbacks_digest"] == digest(callbacks)]
                        if (not prior or any(c["phase"] != "FINISHED" for c in callbacks)
                                or any(self._calls.get(entry["action_id"]) is not None
                                       and self._calls[entry["action_id"]].thread.is_alive() for entry in callbacks)):
                            raise ControlError("COMMAND_ABSENCE_IS_NOT_QUIESCENCE")
                        self._append(command, "removed_absence", {"exists": False, "lookup_id": command["container_id"]},
                                     callbacks_digest=digest(callbacks))
                    command["registry_completion"] = self._complete_registry(command)
                    command["cleanup_complete"] = True
                    self._save_command(command)
                if not command["cleanup_complete"]:
                    raise ControlError("COMMAND_CREATE_OUTCOME_UNCONFIRMED")
                stages = self._stages(command_id)
                callbacks = self._callbacks(command_id)
                if (not callbacks or any(entry["phase"] != "FINISHED" for entry in callbacks)
                        or any(self._calls.get(entry["action_id"]) is not None
                               and self._calls[entry["action_id"]].thread.is_alive() for entry in callbacks)):
                    raise ControlError("COMMAND_CALLBACKS_UNRESOLVED")
                observation_digest = digest({"observations": command["observations"], "callbacks": callbacks})
                admitted = any(state["action"]["arguments"]["stage"] == "START" for state in stages)
                if admitted and not command["start_observed"]:
                    raise ControlError("COMMAND_START_OUTCOME_UNRESOLVED")
                existing = [state["receipt"] for state in stages if state["receipt"] is not None]
                observed_at = existing[0]["observed_at"] if existing else time.time()
                for state in stages:
                    if state["receipt"] is None:
                        action = state["action"]
                        body = {"schema": self._receipt_schema(), **{k: v for k, v in self.pin().items() if k != "public_key"},
                            "reservation_id": state["reservation_id"],
                            **{field: action[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
                            "action_digest": digest(action), "authorization_digest": digest(state["authorization"]),
                            "stage": action["arguments"]["stage"], "command_id": command_id,
                            "image_id": command["image_id"], "container_id": command["container_id"],
                            "plan_sha256": command["plan_sha256"], "ownership_digest": digest(command["registry_record"]),
                            "create_confirmed": True, "callbacks_finished": True, "process_quiescent": True,
                            "start_admitted": admitted, "start_outcome": "STARTED" if admitted else "NOT_STARTED",
                            "business_effects": "NOT_ESTABLISHED", "observation_digest": observation_digest,
                            "observed_at": observed_at, "status": "QUIESCENT"}
                        receipt = {**body, "signature": self._signer.sign(self._receipt_domain() + canonical_bytes(body)).hex()}
                        if not self._verify_receipt(receipt):
                            raise ControlError("COMMAND_SUPERVISOR_RECEIPT_CONTRACT_MISMATCH")
                        state.update(receipt=receipt, settlement_status="UNKNOWN", status="QUIESCENT_PROOF")
                        self._save_grant(state)  # proof durable before FINISH
            except Exception as exc:
                failure = _error(exc)
            results = [self._settle(state) for state in self._stages(command_id) if state["receipt"] is not None]
            current = self._command(command_id)
            return {"status": "QUIESCENT" if failure is None and current["cleanup_complete"] else "UNKNOWN",
                "reason": failure or "COMMAND_OWNED_WORKLOAD_QUIESCENT", "command_id": command_id,
                "process_quiescent": bool(current["cleanup_complete"]), "stages": results, "execution_authorized": False}

    def inventory(self) -> dict:
        with self._lock:
            # Callback completion is intentionally written outside this host
            # lock. One SQLite read transaction fixes a common snapshot before
            # projecting top-level grants, command stages and callback census.
            # Separate reads could otherwise mix INFLIGHT with FINISHED for the
            # same action and produce internally inconsistent public evidence.
            with self._connection() as db:
                db.execute("BEGIN")
                grants = [json.loads(row[0]) for row in db.execute(
                    "SELECT state_json FROM command_supervisor_grants ORDER BY action_id")]
                commands = [json.loads(row[0]) for row in db.execute(
                    "SELECT state_json FROM command_supervisor_commands ORDER BY command_id")]
                evidence = [json.loads(row[0]) for row in db.execute(
                    "SELECT packet_json FROM command_supervisor_evidence ORDER BY sequence")]
            for command in commands:
                command["stages"] = sorted([state for state in grants
                    if state["action"]["arguments"]["spec"]["command_id"] == command["command_id"]
                    and state["reservation_id"] is not None],
                    key=lambda state: (state["action"]["arguments"]["stage"] != "CREATE", state["action"]["action_id"]))
                command["callbacks_finished"] = bool(command["stages"]) and all(
                    state["callback_phase"] == "FINISHED" for state in command["stages"])
                command["callback_journal"] = [{"action_id": state["action"]["action_id"],
                    "stage": state["action"]["arguments"]["stage"], "phase": state["callback_phase"],
                    "result": state["callback_result"]} for state in command["stages"]]
                command["observation_digest"] = digest({"observations": command["observations"],
                                                         "callbacks": command["callback_journal"]})
            return {"profile": self._profile_name(), "supervisor_pin": self.pin(), "authority_pin": self.authority_client.pin(),
                "commands": commands, "grants": grants, "authority_evidence": evidence,
                "unfinished_registry": self.registry.unfinished(), "execution_authorized": False}

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if any(call.thread.is_alive() for call in self._calls.values()):
                raise ControlError("COMMAND_HOST_CALLBACK_STILL_RUNNING")
            self._lease.__exit__(None, None, None)
            self._closed = True
