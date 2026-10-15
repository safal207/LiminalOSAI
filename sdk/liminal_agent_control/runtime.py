"""Trusted Linux Docker supervisor for one receiver-backed worker experiment.

The Docker daemon, host, pinned image and receiver are trust assumptions. The
worker is not trusted to report success, isolation, descendants or termination.
Existing LiminalOS isolation profiles and session containment receipts are reused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any

from adapters.docker.liminal_docker_executor import build_docker_argv
from sdk.liminal_isolated_execution import IsolatedExecutionPlan, IsolationProfile
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_process_tree import ProcessTreeSupervisor
from .supervisor_registry import RegistryError, SupervisorRegistry, ownership_labels

FIXTURES = frozenset({
    "honest", "forged_success", "stale_authority", "delegated_after_revoke",
    "argument_mutation", "delayed_post_ack", "descendant_timeout", "malformed",
    "output_flood", "crash", "omitted_effect_claim",
})
POST_REVOKE = frozenset({"stale_authority", "delegated_after_revoke", "delayed_post_ack"})
MAX_LINE_BYTES = 24576
MAX_OUTPUT_BYTES = 65536
MAX_MESSAGES = 32
ZERO_SHA256 = "0" * 64
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ACTION_FIELDS = {"action_id", "attempt_id", "root_id", "execution_id", "epoch", "target", "arguments"}


class RuntimeBoundaryError(ValueError):
    pass


class DispatchDeadlineExceeded(RuntimeBoundaryError):
    """The host stopped waiting; no claim that the in-flight call was cancelled."""


class BoundedHostCall:
    """Separate supervision from a possibly stuck trusted callback.

    Python cannot safely kill a thread. A deadline only bounds the supervisor's
    wait. The caller must revoke at the receiver, preserve UNKNOWN, and expose
    any still-running callback. This object never mutates returned run evidence.
    """

    def __init__(self, callback: Any, *, name: str) -> None:
        self.done = threading.Event()
        self.value: Any = None
        self.error: BaseException | None = None
        self.timed_out = False

        def invoke() -> None:
            try:
                self.value = callback()
            except BaseException as exc:
                self.error = exc
            finally:
                self.done.set()

        self.thread = threading.Thread(target=invoke, name=name, daemon=True)
        self.thread.start()

    def result_before(self, deadline: float) -> Any:
        if not self.done.wait(max(0.0, deadline - time.monotonic())) or time.monotonic() > deadline:
            self.timed_out = True
            raise DispatchDeadlineExceeded("HOST_CALLBACK_DEADLINE_EXCEEDED")
        if self.error is not None:
            raise RuntimeBoundaryError("HOST_CALLBACK_FAILED") from self.error
        return self.value

    def observation(self) -> dict:
        return {"deadline_exceeded": self.timed_out, "still_running": self.thread.is_alive(),
                "cancellation_confirmed": False}


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeBoundaryError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise RuntimeBoundaryError("NONFINITE_JSON")


def _json_value(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise RuntimeBoundaryError("JSON_DEPTH_EXCEEDED")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item, depth + 1)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            _json_value(item, depth + 1)
        return
    raise RuntimeBoundaryError("INVALID_JSON_VALUE")


def validate_action(action: Any) -> dict:
    if type(action) is not dict or set(action) != _ACTION_FIELDS:
        raise RuntimeBoundaryError("ACTION_SCHEMA_MISMATCH")
    for name in ("action_id", "attempt_id", "root_id", "execution_id"):
        if type(action[name]) is not str or not 1 <= len(action[name]) <= 200 or any(ord(c) < 32 for c in action[name]):
            raise RuntimeBoundaryError("INVALID_ACTION_ID")
    if type(action["epoch"]) is not int or not 1 <= action["epoch"] <= 2**63 - 1:
        raise RuntimeBoundaryError("INVALID_EPOCH")
    if action["target"] != "records" or type(action["arguments"]) is not dict:
        raise RuntimeBoundaryError("UNSUPPORTED_ACTION_TARGET")
    _json_value(action["arguments"])
    if len(json.dumps(action["arguments"], allow_nan=False).encode()) > 16384:
        raise RuntimeBoundaryError("ARGUMENT_SIZE_EXCEEDED")
    return json.loads(json.dumps(action, allow_nan=False))


def decode_message(line: bytes) -> dict:
    if not line or len(line) > MAX_LINE_BYTES:
        raise RuntimeBoundaryError("FRAME_SIZE_EXCEEDED")
    try:
        value = json.loads(line.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RuntimeBoundaryError("INVALID_WORKER_JSON") from exc
    if type(value) is not dict or type(value.get("type")) is not str:
        raise RuntimeBoundaryError("MESSAGE_SCHEMA_MISMATCH")
    return value


@dataclass
class WorkerBridge:
    """Fixed host-owned identity binding; worker cannot issue or delegate grants."""

    broker: Any
    action: dict
    ready: bool = False
    done: bool = False
    messages: int = 0
    actions: list[dict] = field(default_factory=list)
    claims: list[dict] = field(default_factory=list)
    dispatch_calls: list[BoundedHostCall] = field(default_factory=list, repr=False)
    dispatch_unresolved: bool = False
    worker_stopped: bool = False
    observer: Any = field(default=None, repr=False)
    observer_required: bool = False
    observer_calls: list[BoundedHostCall] = field(default_factory=list, repr=False)
    admission_observations: list[dict] = field(default_factory=list)
    admission_closed: bool = False
    dispatch_wait_seconds: float = 0.0
    first_committed_dispatch_seconds: float | None = None

    def dispatch_started(self, call: BoundedHostCall, proposed: dict, deadline: float) -> None:
        """Trusted supervisor hook; never callable through the worker protocol."""

    def accept(self, line: bytes, *, deadline: float | None = None) -> dict | None:
        self.messages += 1
        if self.messages > MAX_MESSAGES or self.done or self.dispatch_unresolved or self.admission_closed:
            raise RuntimeBoundaryError("PROTOCOL_SEQUENCE_INVALID")
        message = decode_message(line)
        kind = message["type"]
        if not self.ready:
            if message != {"type": "ready", "protocol": 1} or type(message.get("protocol")) is not int:
                raise RuntimeBoundaryError("READY_REQUIRED")
            self.ready = True
            return {"action": self.action}
        if kind == "proposal" and set(message) == {"type", "action"}:
            proposed = validate_action(message["action"])
            if self.observer_required or self.observer is not None:
                observed_at = time.monotonic()
                observation = None
                try:
                    if self.observer is None:
                        raise RuntimeBoundaryError("MANDATORY_OBSERVER_MISSING")
                    guard = BoundedHostCall(self.observer, name="liminal-admission-observer")
                    self.observer_calls.append(guard)
                    observation = guard.result_before(min(deadline if deadline is not None else float("inf"),
                                                          time.monotonic() + 1.0))
                    if (type(observation) is not dict or observation.get("exists") is not True
                            or observation.get("running") is not True):
                        raise RuntimeBoundaryError("LIVE_WORKER_NOT_OBSERVED")
                except Exception as exc:
                    self.admission_closed = True
                    self.actions.append({"status": "BLOCKED", "reason": "MANDATORY_OBSERVER_UNAVAILABLE",
                                         "action_id": proposed["action_id"], "receipt": None})
                    raise RuntimeBoundaryError("MANDATORY_OBSERVER_UNAVAILABLE") from exc
                finally:
                    self.admission_observations.append({"action_id": proposed["action_id"],
                        "elapsed_seconds": time.monotonic() - observed_at, "admitted": not self.admission_closed,
                        "observation": json.loads(json.dumps(observation)) if type(observation) is dict else None})
            # The host binds the worker to one principal, execution and request.
            # Epoch remains broker-validated so stale capabilities are measured.
            if any(proposed[key] != self.action[key] for key in ("root_id", "execution_id", "action_id", "attempt_id")):
                result = {"status": "BLOCKED", "reason": "WORKER_IDENTITY_MISMATCH", "action_id": self.action["action_id"]}
            else:
                if deadline is not None and time.monotonic() >= deadline:
                    raise RuntimeBoundaryError("WORKER_TIMEOUT")
                # Only the supervising thread updates actions/claims. A late
                # callback can update broker/receiver state but cannot rewrite
                # the UNKNOWN evidence that was returned at the deadline.
                call = BoundedHostCall(lambda: self.broker.handle(proposed), name="liminal-broker-dispatch")
                self.dispatch_calls.append(call)
                dispatch_started_at = time.monotonic()
                try:
                    dispatch_deadline = deadline if deadline is not None else time.monotonic() + 3
                    self.dispatch_started(call, proposed, dispatch_deadline)
                    result = call.result_before(dispatch_deadline)
                except RuntimeBoundaryError:
                    self.dispatch_unresolved = True
                    self.actions.append({"status": "UNKNOWN", "reason": "HOST_DISPATCH_UNRESOLVED",
                                         "action_id": self.action["action_id"], "receipt": None})
                    raise
                finally:
                    dispatch_elapsed = time.monotonic() - dispatch_started_at
                    self.dispatch_wait_seconds += dispatch_elapsed
                if type(result) is not dict or result.get("status") not in {"COMMITTED", "BLOCKED", "UNKNOWN"}:
                    self.dispatch_unresolved = True
                    self.actions.append({"status": "UNKNOWN", "reason": "BROKER_RESULT_INVALID",
                                         "action_id": self.action["action_id"], "receipt": None})
                    raise RuntimeBoundaryError("BROKER_RESULT_INVALID")
                result = json.loads(json.dumps(result, allow_nan=False))
                if result["status"] == "COMMITTED" and self.first_committed_dispatch_seconds is None:
                    self.first_committed_dispatch_seconds = dispatch_elapsed
            self.actions.append(result)
            # Do not forward signed receipts, keys or host diagnostics to worker.
            return {"status": result["status"]}
        if kind == "claim" and set(message) == {"type", "status", "action_id"}:
            if message["status"] not in {"SUCCEEDED", "FAILED"} or message["action_id"] != self.action["action_id"]:
                raise RuntimeBoundaryError("WORKER_CLAIM_INVALID")
            self.claims.append({**message, "trusted": False})
            return None
        if message == {"type": "done"}:
            self.done = True
            return None
        raise RuntimeBoundaryError("MESSAGE_SCHEMA_MISMATCH")


class DockerController:
    """Host-only Docker API adapter; absence must be positively identified."""

    def __init__(self, docker_binary: str = "docker") -> None:
        self.docker_binary = docker_binary
        self.process_evidence: dict[str, dict] = {}
        self.observation_attempts: dict[str, list[dict]] = {}
        self.owned_sessions: dict[str, dict] = {}
        self.owned_container_ids: dict[str, str] = {}
        self.on_created: Any = None

    def bind_ownership(self, record: dict) -> None:
        self.owned_sessions[record["session_id"]] = json.loads(json.dumps(record))

    def bind_container_id(self, session_id: str, container_id: str) -> None:
        if type(container_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeBoundaryError("IMMUTABLE_CONTAINER_ID_UNAVAILABLE")
        self.owned_container_ids[session_id] = container_id

    def owned_container_id(self, session_id: str) -> str:
        observed = self._inspect(session_id)
        if observed is None:
            raise RuntimeBoundaryError("CREATED_CONTAINER_MISSING")
        container_id = observed.get("Id")
        self.bind_container_id(session_id, container_id)
        return container_id

    def command(self, args: list[str], *, timeout: float = 10) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.docker_binary, *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            check=False, shell=False,
        )

    def image_id(self, image: str) -> str:
        if type(image) is not str or not _IMAGE_ID.fullmatch(image):
            raise RuntimeBoundaryError("IMMUTABLE_IMAGE_ID_REQUIRED")
        result = self.command(["image", "inspect", "--format", "{{.Id}}", image])
        if result.returncode or result.stdout.decode().strip() != image:
            raise RuntimeBoundaryError("PINNED_LOCAL_IMAGE_UNAVAILABLE")
        return image

    def _inspect(self, session_id: str) -> dict | None:
        # Names are only a discovery handle before create confirmation. A
        # rename or reused name cannot establish absence of the pinned object.
        lookup_id = self.owned_container_ids.get(session_id, session_id)
        result = self.command(["inspect", lookup_id])
        if result.returncode:
            # Daemon outage, permission and timeout are not proof of absence.
            message = result.stderr.decode(errors="replace").lower()
            if "no such object:" in message or "no such container:" in message:
                return None
            raise RuntimeBoundaryError("DOCKER_OBSERVATION_UNAVAILABLE")
        try:
            objects = json.loads(result.stdout)
            if type(objects) is not list or len(objects) != 1 or type(objects[0]) is not dict:
                raise ValueError
            value = objects[0]
            expected = self.owned_sessions.get(session_id)
            pinned_id = self.owned_container_ids.get(session_id)
            if pinned_id is not None and value.get("Id") != pinned_id:
                raise RuntimeBoundaryError("CONTAINER_OWNERSHIP_MISMATCH")
            if expected is not None:
                labels = value.get("Config", {}).get("Labels", {}) or {}
                if (value.get("Image") != expected["image_id"]
                        or any(labels.get(key) != val for key, val in ownership_labels(expected).items())):
                    raise RuntimeBoundaryError("CONTAINER_OWNERSHIP_MISMATCH")
                if pinned_id is None and self.on_created is not None:
                    container_id = value.get("Id")
                    if type(container_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", container_id):
                        raise RuntimeBoundaryError("IMMUTABLE_CONTAINER_ID_UNAVAILABLE")
                    self.on_created(container_id)
                    self.bind_container_id(session_id, container_id)
            return value
        except (ValueError, TypeError) as exc:
            if isinstance(exc, RuntimeBoundaryError):
                raise
            raise RuntimeBoundaryError("DOCKER_OBSERVATION_INVALID") from exc

    def inspect_session(self, session_id: str) -> dict:
        try:
            value = self._inspect(session_id)
        except Exception as exc:
            failure = str(exc) if isinstance(exc, RuntimeBoundaryError) and re.fullmatch(r"[A-Z0-9_]{1,100}", str(exc)) else "DOCKER_OBSERVATION_UNAVAILABLE"
            self._record_process_failure(session_id, {"Id": self.owned_container_ids.get(session_id)},
                                         None, failure, stage="docker inspect")
            raise
        if value is None:
            return {"exists": False, "running": False, "descendant_count": 0, "tree_sha256": ZERO_SHA256}
        state = value["State"]
        running, paused = state.get("Running"), state.get("Paused")
        if type(running) is not bool or type(paused) is not bool:
            self._record_process_failure(session_id, value, None, "DOCKER_STATE_INVALID", stage="docker inspect")
            raise RuntimeBoundaryError("DOCKER_STATE_INVALID")
        process_evidence: list = []
        descendants = 0
        if running:
            try:
                result = self.command(["top", self.owned_container_ids.get(session_id, session_id)])
            except Exception as exc:
                attempt = self._record_process_failure(session_id, value, None, "PROCESS_OBSERVATION_UNAVAILABLE")
                attempt["exception_type"] = type(exc).__name__
                raise RuntimeBoundaryError("PROCESS_OBSERVATION_UNAVAILABLE") from exc
            try:
                rows = result.stdout.decode(errors="strict").strip().splitlines() if not result.returncode else []
            except UnicodeError:
                self._record_process_failure(session_id, value, result.returncode, "PROCESS_LINEAGE_INVALID")
                raise RuntimeBoundaryError("PROCESS_LINEAGE_INVALID")
            if rows and ("PID" not in rows[0].split() or "PPID" not in rows[0].split()):
                self._record_process_failure(session_id, value, result.returncode, "PROCESS_LINEAGE_UNAVAILABLE")
                raise RuntimeBoundaryError("PROCESS_LINEAGE_UNAVAILABLE")
            failure = "PROCESS_OBSERVATION_UNAVAILABLE" if result.returncode else "PROCESS_OBSERVATION_EMPTY" if len(rows) < 2 else None
            if failure is not None:
                attempt = self._record_process_failure(session_id, value, result.returncode, failure)
                # The process can exit between inspect's Running=True and top.
                # One fresh, positively owned stopped object can establish its
                # current state. Missing/unavailable/replaced objects cannot.
                pinned_id = self.owned_container_ids.get(session_id)
                if pinned_id is None or session_id not in self.owned_sessions or value.get("Id") != pinned_id:
                    raise RuntimeBoundaryError(failure)
                try:
                    fresh = self._inspect(session_id)
                except Exception as exc:
                    attempt["fresh_inspect_failure"] = str(exc) if isinstance(exc, RuntimeBoundaryError) and re.fullmatch(r"[A-Z0-9_]{1,100}", str(exc)) else type(exc).__name__
                    raise RuntimeBoundaryError(failure) from exc
                if fresh is None:
                    attempt["fresh_inspect_failure"] = "OWNED_OBJECT_NOT_POSITIVELY_OBSERVED"
                    raise RuntimeBoundaryError(failure)
                fresh_state = fresh.get("State", {})
                if type(fresh_state.get("Running")) is not bool or type(fresh_state.get("Paused")) is not bool:
                    attempt["fresh_inspect_failure"] = "DOCKER_STATE_INVALID"
                    raise RuntimeBoundaryError(failure)
                if (fresh_state["Running"] is not False or fresh_state["Paused"] is not False
                        or type(fresh_state.get("Pid")) is not int or fresh_state["Pid"] != 0):
                    attempt["fresh_inspect_failure"] = "OWNED_OBJECT_NOT_POSITIVELY_STOPPED"
                    raise RuntimeBoundaryError(failure)
                value, state, running, paused = fresh, fresh_state, False, fresh_state["Paused"]
                attempt.update(resolved_by="fresh_owned_stopped_inspect", fresh_inspected_at=time.time())
            else:
                header = rows[0].split()
                if "PID" not in header or "PPID" not in header:
                    self._record_process_failure(session_id, value, result.returncode, "PROCESS_LINEAGE_UNAVAILABLE")
                    raise RuntimeBoundaryError("PROCESS_LINEAGE_UNAVAILABLE")
                pid_index, parent_index = header.index("PID"), header.index("PPID")
                for row in rows[1:]:
                    fields = row.split()
                    if len(fields) <= max(pid_index, parent_index) or not fields[pid_index].isdigit() or not fields[parent_index].isdigit():
                        self._record_process_failure(session_id, value, result.returncode, "PROCESS_LINEAGE_INVALID")
                        raise RuntimeBoundaryError("PROCESS_LINEAGE_INVALID")
                    process_evidence.append({"pid": int(fields[pid_index]), "ppid": int(fields[parent_index])})
                pids = {node["pid"] for node in process_evidence}
                if len(pids) != len(process_evidence) or state.get("Pid") not in pids:
                    self._record_process_failure(session_id, value, result.returncode, "PROCESS_ROOT_NOT_OBSERVED")
                    raise RuntimeBoundaryError("PROCESS_ROOT_NOT_OBSERVED")
                descendants = len(process_evidence) - 1
        # Host evidence only: never sent across worker STDIO. Retain bounded
        # PID/PPID values, not arbitrary process command lines or environment.
        self.process_evidence[session_id] = {
            "source": "docker inspect + docker top", "observed_at": time.time(),
            "container_id": value.get("Id"), "running": running, "paused": paused,
            "root_pid": state.get("Pid"), "processes": process_evidence,
            "available": True, "observation_attempts": self.observation_attempts.get(session_id, []),
        }
        return {
            "exists": True, "running": running and not paused,
            "descendant_count": descendants,
            "tree_sha256": canonical_sha256({"session": session_id, "state": state, "processes": process_evidence}),
        }

    def _record_process_failure(self, session_id: str, value: dict, returncode: int | None, failure: str,
                                *, stage: str = "docker top") -> dict:
        attempts = self.observation_attempts.setdefault(session_id, [])
        attempt = {"stage": stage, "container_id": value.get("Id"),
                   "returncode": returncode, "failure_code": failure, "observed_at": time.time()}
        attempts.append(attempt)
        del attempts[:-32]
        # Preserve bounded error codes and owned IDs, never CLI stderr,
        # environment or arbitrary process command lines.
        self.process_evidence[session_id] = {"source": "docker inspect + docker top", "available": False,
            "container_id": value.get("Id"), "observation_attempts": attempts}
        return attempt

    def freeze_session(self, session_id: str) -> None:
        observed = self._inspect(session_id)
        if observed is None:
            return
        container_id = observed.get("Id")
        if type(container_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeBoundaryError("IMMUTABLE_CONTAINER_ID_UNAVAILABLE")
        if self.command(["pause", container_id]).returncode:
            raise RuntimeBoundaryError("FREEZE_FAILED")

    def terminate_session(self, session_id: str) -> None:
        observed = self._inspect(session_id)
        if observed is None:
            return
        container_id = observed.get("Id")
        if type(container_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeBoundaryError("IMMUTABLE_CONTAINER_ID_UNAVAILABLE")
        result = self.command(["rm", "--force", container_id])
        if result.returncode and self._inspect(session_id) is not None:
            raise RuntimeBoundaryError("TERMINATE_FAILED")

    def verify_configuration(self, session_id: str, plan: IsolatedExecutionPlan) -> None:
        item = self._inspect(session_id)
        if item is None:
            raise RuntimeBoundaryError("CREATED_CONTAINER_MISSING")
        host, config = item["HostConfig"], item["Config"]
        mounts = item.get("Mounts", [])
        checks = (
            item.get("Image") == plan.image_id,
            host.get("NetworkMode") == "none",
            host.get("LogConfig", {}).get("Type") == "none",
            host.get("ReadonlyRootfs") is True,
            host.get("Privileged") is False,
            host.get("PidMode", "") != "host",
            host.get("IpcMode", "") != "host",
            set(host.get("CapDrop") or ()) == {"ALL"},
            not host.get("CapAdd"),
            "no-new-privileges:true" in (host.get("SecurityOpt") or []),
            config.get("User") == f"{plan.profile.uid}:{plan.profile.gid}",
            host.get("PidsLimit") == plan.profile.pids_limit,
            host.get("Memory") == plan.profile.memory_mb * 1024 * 1024,
            host.get("NanoCpus") == int(float(plan.profile.cpus) * 1_000_000_000),
            host.get("Tmpfs", {}).get("/tmp") == plan.profile.tmpfs.split(":", 1)[1],
            len(mounts) == 1 and mounts[0].get("Source") == plan.host_workspace
            and mounts[0].get("Destination") == "/workspace" and mounts[0].get("RW") is False,
        )
        if not all(checks):
            raise RuntimeBoundaryError("CONTAINER_CONFIGURATION_MISMATCH")


def _revoke(broker: Any, root_id: str) -> dict:
    acknowledgment = broker.revoke(root_id)
    receipt = acknowledgment.get("receiver_ack") if type(acknowledgment) is dict else None
    if (type(acknowledgment) is not dict or acknowledgment.get("status") != "REVOKED"
            or acknowledgment.get("broker_fenced") is not True or acknowledgment.get("root_id") != root_id
            or type(receipt) is not dict or not broker.receiver.verify_receipt(receipt)
            or receipt.get("status") != "REVOKED" or receipt.get("root_id") != root_id):
        raise RuntimeBoundaryError("AGGREGATE_REVOCATION_UNVERIFIED")
    return acknowledgment


def _contain_workload(supervisor: ProcessTreeSupervisor, controller: Any, *, session_id: str, broker: Any = None,
                      root_id: str | None = None, revoke_timeout_seconds: float = 3.0) -> dict:
    """Best-effort termination persists even if freeze/revocation/observation fails."""
    started = time.monotonic()
    decision_at = time.time()
    failures: list[str] = []
    local_fence = None
    fenced_at = None
    revoked = None
    revoked_at = None
    revocation_call = None
    if broker is not None:
        # Local admission closes before any potentially unavailable observer,
        # Docker daemon, or receiver callback. This cannot cancel requests that
        # have already left the broker; their receiver still needs revocation.
        try:
            local_fence = broker.fence(root_id)
            if (type(local_fence) is not dict or local_fence.get("status") != "FENCED"
                    or local_fence.get("root_id") != root_id or local_fence.get("broker_fenced") is not True):
                raise RuntimeBoundaryError("LOCAL_FENCE_UNVERIFIED")
            fenced_at = time.time()
        except Exception:
            failures.append("LOCAL_FENCE_UNVERIFIED")
        revocation_call = BoundedHostCall(lambda: _revoke(broker, root_id), name="liminal-broker-revocation")
        try:
            revoked = revocation_call.result_before(time.monotonic() + revoke_timeout_seconds)
            revoked_at = time.time()
        except Exception:
            failures.append("REVOCATION_UNVERIFIED")
    pre_stop = None
    process_evidence = None
    try:
        pre_stop = controller.inspect_session(session_id)
        process_evidence = json.loads(json.dumps(getattr(controller, "process_evidence", {}).get(session_id)))
    except Exception:
        failures.append("PRE_STOP_OBSERVATION_UNAVAILABLE")
        process_evidence = json.loads(json.dumps(getattr(controller, "process_evidence", {}).get(session_id)))
    freeze = supervisor.freeze_all()
    if freeze["failure_codes"]:
        failures.append("FREEZE_INCOMPLETE")
    quiescence = supervisor.quiesce_all(incident_id="stop:" + session_id)
    if not quiescence["zero_survivors"]:
        failures.append("QUIESCENCE_INCOMPLETE")
        # Do not abandon a live workload because the orderly freeze path failed.
        try:
            controller.terminate_session(session_id)
        except Exception:
            failures.append("EMERGENCY_TERMINATION_FAILED")
    absent = False
    try:
        after = controller.inspect_session(session_id)
        absent = not after["exists"] and not after["running"] and after["descendant_count"] == 0
        if not absent:
            failures.append("WORKLOAD_SURVIVES")
    except Exception:
        failures.append("FINAL_OBSERVATION_UNAVAILABLE")
    return {
        "freeze": freeze, "revocation_ack": revoked, "quiescence": quiescence,
        "pre_stop_observation": pre_stop, "pre_stop_process_evidence": process_evidence,
        "revocation_call": revocation_call.observation() if revocation_call else None,
        "authority_revocation_requested": broker is not None,
        "local_fence": local_fence, "t_stop_decision": decision_at, "t_local_fenced": fenced_at,
        "t_revoke_ack": revoked_at, "t_quiescent": time.time() if absent else None,
        "revocation_wait_limit_seconds": revoke_timeout_seconds,
        "zero_survivors": absent, "partial_failures": failures,
        "verified": absent and not failures,
        "stop_elapsed_seconds": round(time.monotonic() - started, 6),
        "observation_source": "trusted_host_docker_daemon",
        "boundary": "container PID/cgroup lifecycle; excludes host/kernel/daemon compromise",
    }


def contain_workload(supervisor: ProcessTreeSupervisor, controller: Any, *, session_id: str, broker: Any,
                     root_id: str, revoke_timeout_seconds: float = 3.0) -> dict:
    return _contain_workload(supervisor, controller, session_id=session_id, broker=broker,
                             root_id=root_id, revoke_timeout_seconds=revoke_timeout_seconds)


def contain_process_workload(supervisor: ProcessTreeSupervisor, controller: Any, *, session_id: str) -> dict:
    """External OS stop only. This does not acknowledge authority revocation."""
    return _contain_workload(supervisor, controller, session_id=session_id)


def _broker_context(broker: Any) -> str:
    fingerprints = {}
    for name in ("broker_key", "receipt_key"):
        key = getattr(broker.receiver, name, None)
        if type(key) is not bytes or len(key) < 32:
            raise RuntimeBoundaryError("RECOVERY_KEY_CONTEXT_UNAVAILABLE")
        fingerprints[name + "_sha256"] = hashlib.sha256(key).hexdigest()
    return canonical_sha256({"broker_db_path": str(Path(broker.db_path).resolve()), **fingerprints})


def _register_durable(registry: SupervisorRegistry, controller: DockerController, plan: IsolatedExecutionPlan,
                      session_id: str, broker: Any, root_id: str) -> dict:
    identity = broker.receiver.identity()
    if not broker.receiver.verify_receipt(identity) or identity.get("status") != "IDENTITY":
        raise RuntimeBoundaryError("RECEIVER_IDENTITY_UNVERIFIED")
    record = registry.register(session_id=session_id, root_id=root_id, action_id=plan.operation_id,
                               image_id=plan.image_id, plan_sha256=plan.plan_sha256,
                               backend_identity_sha256=canonical_sha256({"backend": "docker", "image_id": plan.image_id}),
                               receiver_id=identity["receiver_id"], broker_context_sha256=_broker_context(broker))
    controller.bind_ownership(record)
    controller.on_created = lambda container_id: registry.confirm_created(record, container_id)
    return record


def _confirm_create_if_observed(registry: SupervisorRegistry, record: dict,
                                controller: DockerController) -> None:
    """Positive owned-object evidence can settle an uncertain create result."""
    if registry.launch_state(record)["phase"] == "CREATED":
        return
    container_id = controller.owned_container_id(record["session_id"])
    registry.confirm_created(record, container_id)


def _retain_unconfirmed_create(containment: dict) -> None:
    # Instantaneous absence does not prove an orphan CLI/daemon request cannot
    # finish later. Keep the raw observation but never release the durable slot.
    containment["observed_absent_at_cleanup"] = containment.get("zero_survivors") is True
    containment["zero_survivors"] = False
    containment["verified"] = False
    containment["t_quiescent"] = None
    if "CREATE_OUTCOME_UNCONFIRMED" not in containment["partial_failures"]:
        containment["partial_failures"].append("CREATE_OUTCOME_UNCONFIRMED")


def recover_workloads(registry_path: str | Path, *, broker: Any, docker_binary: str = "docker",
                      expected_root_id: str | None = None) -> dict:
    """Explicit trusted-host recovery after a known controller failure.

    Never called automatically on startup. The exclusive lease rejects a live
    controller; labels, receiver and broker context bind cleanup to registered
    resources. Any uncertainty leaves the slot unfinished and blocks new work.
    """
    report = {"status": "INCOMPLETE", "reason": None, "recovered": [], "admission_allowed": False}
    try:
        registry = SupervisorRegistry(registry_path)
        with registry.lease():
            pending = registry.unfinished()
            if not pending:
                return {**report, "status": "EMPTY", "admission_allowed": True}
            if expected_root_id is not None and any(record["root_id"] != expected_root_id for record in pending):
                return {**report, "reason": "RECOVERY_ROOT_MISMATCH"}
            if shutil.which(docker_binary) is None:
                return {**report, "reason": "DOCKER_RUNTIME_UNAVAILABLE"}
            identity = broker.receiver.identity()
            if not broker.receiver.verify_receipt(identity) or identity.get("status") != "IDENTITY":
                raise RuntimeBoundaryError("RECEIVER_IDENTITY_UNVERIFIED")
            if identity.get("enforcement_profile") not in {"guarded", "governed_v1"}:
                raise RuntimeBoundaryError("RECOVERY_REQUIRES_GUARDED_RECEIVER")
            controller = DockerController(docker_binary)
            for record in pending:
                if (record["receiver_id"] != identity.get("receiver_id")
                        or record["broker_context_sha256"] != _broker_context(broker)
                        or record["registry_id"] != registry.registry_id):
                    raise RuntimeBoundaryError("RECOVERY_CONTEXT_MISMATCH")
                controller.bind_ownership(record)
                launch = registry.launch_state(record)
                if launch["container_id"] is not None:
                    controller.bind_container_id(record["session_id"], launch["container_id"])
                controller.on_created = lambda container_id: registry.confirm_created(record, container_id)
                # Ownership is verified before any freeze/terminate operation.
                before = controller.inspect_session(record["session_id"])
                if before["exists"] and launch["phase"] != "CREATED":
                    _confirm_create_if_observed(registry, record, controller)
                    launch = registry.launch_state(record)
                supervisor = ProcessTreeSupervisor(inspect_session=controller.inspect_session,
                                                   freeze_session=controller.freeze_session,
                                                   terminate_session=controller.terminate_session)
                supervisor.register_session(session_id=record["session_id"], operation_id=record["action_id"],
                                            plan_sha256=record["plan_sha256"],
                                            backend_identity_sha256=record["backend_identity_sha256"])
                contained = contain_workload(supervisor, controller, session_id=record["session_id"],
                                             broker=broker, root_id=record["root_id"])
                launch = registry.launch_state(record)
                if launch["phase"] != "CREATED":
                    _retain_unconfirmed_create(contained)
                report["recovered"].append({"session_id": record["session_id"], "root_id": record["root_id"],
                                            "before": before, "containment": contained})
                if not contained["verified"]:
                    return {**report, "reason": "RECOVERY_INCOMPLETE"}
                registry.complete(record, contained)
            return {**report, "status": "RECOVERED", "admission_allowed": True}
    except Exception as exc:
        return {**report, "status": "BUSY" if str(exc) == "SUPERVISOR_BUSY" else "INCOMPLETE",
                "reason": str(exc) if isinstance(exc, (RegistryError, RuntimeBoundaryError)) else type(exc).__name__}


def _managed_runtime(broker: Any, registry_path: str | Path | None, metadata: dict, operation: Any) -> dict:
    started = time.monotonic()
    failure = {**metadata, "status": "ERROR", "reason": None, "actions": [], "worker_claims": [],
               "registered_before_start": False, "model_run": False,
               "containment": {"verified": False, "zero_survivors": False}}
    try:
        path = Path(registry_path) if registry_path is not None else Path(broker.db_path).with_name(Path(broker.db_path).name + ".supervisor.sqlite")
        registry = SupervisorRegistry(path)
        with registry.lease():
            if registry.unfinished():
                return {**failure, "reason": "RECOVERY_REQUIRED", "registry_path": str(registry.path)}
            report = operation(registry)
            report["runtime_wall_seconds"] = time.monotonic() - started
            return report
    except RegistryError as exc:
        return {**failure, "reason": str(exc), "runtime_wall_seconds": time.monotonic() - started}


def _finish_registry(registry: SupervisorRegistry, record: dict, containment: dict, bridge: WorkerBridge) -> dict:
    launch = registry.launch_state(record)
    if launch["phase"] != "CREATED":
        _retain_unconfirmed_create(containment)
    fenced = containment.get("revocation_ack") is not None
    callbacks_finished = all(not call.thread.is_alive() for call in bridge.dispatch_calls)
    complete = containment.get("verified") is True and (fenced or callbacks_finished)
    if complete:
        registry.complete(record, containment)
    return {"session_id": record["session_id"], "registry_id": registry.registry_id,
            "registered_at": record["registered_at"], "launch": launch,
            "status": "CLOSED" if complete else "RECOVERY_REQUIRED"}


def _admission_report(bridge: WorkerBridge) -> dict:
    return {"mandatory": bridge.observer_required, "closed": bridge.admission_closed,
            "observations": bridge.admission_observations,
            "observer_calls": [call.observation() for call in bridge.observer_calls],
            "wait_elapsed_seconds": sum(o["elapsed_seconds"] for o in bridge.admission_observations),
            "dispatch_wait_elapsed_seconds": bridge.dispatch_wait_seconds,
            "first_committed_dispatch_elapsed_seconds": bridge.first_committed_dispatch_seconds,
            "measurement_scope": "per-run waits; dispatch total includes queue/supervision and denied attempts; first committed proposal is useful control; no statistical overhead estimate"}


def _write_bounded(process: subprocess.Popen, message: dict, deadline: float) -> None:
    data = json.dumps(message, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(data) > MAX_LINE_BYTES:
        raise RuntimeBoundaryError("HOST_FRAME_SIZE_EXCEEDED")
    fd = process.stdin.fileno()
    with selectors.DefaultSelector() as ready:
        ready.register(fd, selectors.EVENT_WRITE)
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not ready.select(remaining):
                raise RuntimeBoundaryError("WORKER_INPUT_TIMEOUT")
            try:
                data = data[os.write(fd, data):]
            except BlockingIOError:
                continue


def _exchange(process: subprocess.Popen, bridge: WorkerBridge, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    byte_count = 0
    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ, "stdout")
        ready.register(process.stderr, selectors.EVENT_READ, "stderr")
        while not bridge.done:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeBoundaryError("WORKER_TIMEOUT")
            events = ready.select(min(remaining, 0.25))
            for event, _ in events:
                chunk = os.read(event.fileobj.fileno(), 4096)
                if not chunk:
                    ready.unregister(event.fileobj)
                    if event.data == "stdout" and not bridge.done:
                        raise RuntimeBoundaryError("WORKER_EXITED_BEFORE_DONE")
                    continue
                byte_count += len(chunk)
                if byte_count > MAX_OUTPUT_BYTES:
                    raise RuntimeBoundaryError("OUTPUT_LIMIT_EXCEEDED")
                if event.data == "stderr":
                    continue  # Count, but do not copy untrusted diagnostics into evidence.
                buffers["stdout"].extend(chunk)
                while b"\n" in buffers["stdout"]:
                    line, _, tail = buffers["stdout"].partition(b"\n")
                    buffers["stdout"] = bytearray(tail)
                    response = bridge.accept(bytes(line), deadline=deadline)
                    if bridge.worker_stopped:
                        return {"output_bytes": byte_count, "message_count": bridge.messages,
                                "stopped_by_host": True}
                    if response is not None:
                        _write_bounded(process, response, deadline)
                if len(buffers["stdout"]) > MAX_LINE_BYTES:
                    raise RuntimeBoundaryError("FRAME_SIZE_EXCEEDED")
        return {"output_bytes": byte_count, "message_count": bridge.messages}


class PreAcceptanceQueue:
    """Host-only experimental queue holding an actual request before acceptance.

    The queue is common to all three arms. It does not issue receipts or claim
    acceptance. The receiver remains the only writer of owned effect records.
    """

    def __init__(self, receiver: Any, action: dict, *, wait_seconds: float) -> None:
        self.receiver = receiver
        self.action = validate_action(action)
        self.wait_seconds = wait_seconds
        self.entered = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.entered_at: float | None = None
        self.queued_action_sha256: str | None = None
        self.queued_authorization_sha256: str | None = None
        self._lock = threading.Lock()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.receiver, name)

    def commit(self, action: dict, **kwargs: Any) -> dict:
        frozen = validate_action(action)
        frozen_kwargs = json.loads(json.dumps(kwargs, allow_nan=False))
        if frozen["action_id"] == self.action["action_id"]:
            if frozen != self.action:
                raise RuntimeBoundaryError("QUEUED_ACTION_CHANGED")
            with self._lock:
                if self.entered.is_set():
                    raise RuntimeBoundaryError("QUEUED_REQUEST_REPLAYED")
                self.queued_action_sha256 = canonical_sha256(frozen)
                self.queued_authorization_sha256 = canonical_sha256(frozen_kwargs) if frozen_kwargs else None
                self.entered_at = time.time()
                self.entered.set()
            if not self.release.wait(self.wait_seconds) or self.cancelled.is_set():
                raise RuntimeBoundaryError("QUEUED_REQUEST_ABORTED")
        return self.receiver.commit(frozen, **frozen_kwargs)

    def cancel(self) -> None:
        self.cancelled.set()
        self.release.set()


class OrdinaryRecordTool:
    """Explicit A/B baseline: typed host route without broker grants or fencing."""

    def __init__(self, receiver: Any) -> None:
        self.receiver = receiver

    def handle(self, action: dict) -> dict:
        action = validate_action(action)
        receipt = self.receiver.commit(action)
        valid = (self.receiver.verify_receipt(receipt)
                 and receipt.get("action_id") == action["action_id"]
                 and receipt.get("action_digest") == canonical_sha256(action)
                 and receipt.get("status") in {"COMMITTED", "DENIED"})
        if not valid:
            return {"status": "UNKNOWN", "reason": "RECEIVER_RECEIPT_INVALID",
                    "action_id": action["action_id"], "receipt": None}
        return {"status": "COMMITTED" if receipt["status"] == "COMMITTED" else "BLOCKED",
                "reason": receipt["reason"], "action_id": action["action_id"], "receipt": receipt}


class MatchedWorkerBridge(WorkerBridge):
    """The same two-proposal worker protocol for the bounded matched experiment."""

    def __init__(self, route: Any, positive_action: dict, action: dict, queue: PreAcceptanceQueue,
                 on_queued: Any) -> None:
        super().__init__(route, validate_action(positive_action))
        self.positive_action = validate_action(positive_action)
        self.queued_action = validate_action(action)
        self.queue = queue
        self.on_queued = on_queued
        self.positive_completed = False

    def accept(self, line: bytes, *, deadline: float | None = None) -> dict | None:
        was_ready = self.ready
        count = len(self.actions)
        response = super().accept(line, deadline=deadline)
        if not was_ready:
            return {"actions": [self.positive_action, self.queued_action]}
        if len(self.actions) > count and not self.positive_completed:
            if self.actions[-1]["status"] != "COMMITTED":
                raise RuntimeBoundaryError("POSITIVE_CONTROL_FAILED")
            self.positive_completed = True
            self.action = self.queued_action
        return response

    def dispatch_started(self, call: BoundedHostCall, proposed: dict, deadline: float) -> None:
        if proposed["action_id"] != self.queued_action["action_id"]:
            return
        try:
            if not self.positive_completed or not self.queue.entered.wait(max(0, deadline - time.monotonic())):
                raise RuntimeBoundaryError("PREACCEPTANCE_BARRIER_UNAVAILABLE")
            self.worker_stopped = self.on_queued(deadline)
        except Exception as exc:
            self.queue.cancel()
            if isinstance(exc, RuntimeBoundaryError):
                raise
            raise RuntimeBoundaryError("QUEUED_SUPERVISION_FAILED") from exc


def run_matched_arm(arm: str, *, image: str, broker_db_path: str | Path, receiver: Any,
                    timeout_seconds: int = 15, docker_binary: str = "docker",
                    registry_path: str | Path | None = None) -> dict:
    from .broker import Broker
    registry_broker = Broker(broker_db_path, receiver)
    return _managed_runtime(registry_broker, registry_path, {"mode": "docker-abc", "arm": arm},
                            lambda registry: _run_matched_arm(arm, image=image, broker_db_path=broker_db_path,
                                receiver=receiver, timeout_seconds=timeout_seconds, docker_binary=docker_binary,
                                registry=registry, registry_broker=registry_broker))


def _run_matched_arm(arm: str, *, image: str, broker_db_path: str | Path, receiver: Any,
                    timeout_seconds: int, docker_binary: str, registry: SupervisorRegistry,
                    registry_broker: Any) -> dict:
    """One controlled queued-request scenario under actual matched Docker arms.

    A uses an ordinary host tool; B adds actual external process termination;
    C adds exact broker grants and receiver-backed revocation. The host queue is
    before receiver acceptance in every arm. This is not a model evaluation.
    """
    from .broker import Broker

    if arm not in {"A", "B", "C"}:
        raise RuntimeBoundaryError("INVALID_EXPERIMENT_ARM")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise RuntimeBoundaryError("INVALID_TIMEOUT")
    report = {"mode": "docker-abc", "experiment_id": "owned-receiver-docker-queued-v1",
              "fixture": "queued_after_stop", "arm": arm, "status": "ERROR", "reason": None,
              "image_id": image, "model_run": False, "root_id": None, "action": None,
              "positive_action": None, "actions": [], "worker_claims": [],
              "registered_before_start": False, "containment": {"verified": False, "zero_survivors": False},
              "timing": {"t_decision": None, "t_quiescent": None, "t_revoke_ack": None, "t_queue_released": None},
              "queue_entered_at": None, "receiver_before_release": None, "broker_state_at_barrier": None,
              "route": "exact_grant_broker" if arm == "C" else "ordinary_host_tool_no_grants",
              "fixed_trigger": "second actual request queued before receiver acceptance after useful first record"}
    if os.name != "posix" or shutil.which(docker_binary) is None:
        return {**report, "status": "SKIPPED", "reason": "DOCKER_RUNTIME_UNAVAILABLE"}
    controller = DockerController(docker_binary)
    try:
        controller.image_id(image)
    except Exception as exc:
        return {**report, "status": "SKIPPED", "reason": str(exc) if isinstance(exc, RuntimeBoundaryError) else "DOCKER_RUNTIME_UNAVAILABLE"}
    identity = receiver.identity()
    expected_profile = "guarded" if arm == "C" else "baseline_unfenced"
    if not receiver.verify_receipt(identity) or identity.get("enforcement_profile") != expected_profile:
        return {**report, "reason": "RECEIVER_PROFILE_MISMATCH"}
    report["receiver_identity"] = identity
    nonce = uuid.uuid4().hex
    root_id, execution_id = "root:" + nonce, "execution:" + nonce
    created = receiver.create_root(root_id)
    bound = receiver.bind_execution(root_id, execution_id)
    if not (receiver.verify_receipt(created) and receiver.verify_receipt(bound)
            and created.get("status") == "ROOT_CREATED" and bound.get("status") == "BOUND"):
        return {**report, "reason": "REGISTRATION_UNVERIFIED"}
    action = validate_action({"action_id": "queued:" + nonce, "attempt_id": "queued-attempt:" + nonce,
                              "root_id": root_id, "execution_id": execution_id, "epoch": created["epoch"],
                              "target": "records", "arguments": {"value": "matched queued record"}})
    positive = {**action, "action_id": "positive:" + nonce, "attempt_id": "positive-attempt:" + nonce,
                "arguments": {"value": "matched useful first record"}}
    report.update(root_id=root_id, action=action, positive_action=positive,
                  registration={"root": created, "execution": bound})
    queue = PreAcceptanceQueue(receiver, action, wait_seconds=timeout_seconds + 30)
    route = Broker(broker_db_path, queue) if arm == "C" else OrdinaryRecordTool(queue)
    if arm == "C":
        route.authorize(positive, ttl_seconds=timeout_seconds + 60)
        route.authorize(action, ttl_seconds=timeout_seconds + 60)
    session_id = "liminal-matched-" + nonce
    process = None
    stop_evidence = None
    with tempfile.TemporaryDirectory(prefix="liminal-matched-worker-") as workspace:
        os.chmod(workspace, 0o755)
        worker = Path(workspace) / "worker_fixture.py"
        shutil.copyfile(Path(__file__).with_name("worker_fixture.py"), worker)
        os.chmod(worker, 0o444)
        plan = IsolatedExecutionPlan.build(
            operation_id=action["action_id"], image_id=image,
            argv=("-I", "-u", "/workspace/worker_fixture.py", "queued_after_stop"),
            host_workspace=workspace, timeout_seconds=timeout_seconds,
            profile=IsolationProfile(pids_limit=32, memory_mb=128, cpus="0.5"))
        report["plan_sha256"] = plan.plan_sha256
        report["worker_sha256"] = hashlib.sha256(worker.read_bytes()).hexdigest()
        report["isolation_profile"] = plan.profile.body()
        report["isolation_profile_sha256"] = plan.profile.profile_sha256
        report["worker_argv"] = list(plan.argv)
        report["protocol_budget"] = {"max_line_bytes": MAX_LINE_BYTES, "max_output_bytes": MAX_OUTPUT_BYTES,
                                     "max_messages": MAX_MESSAGES}
        report["timeout_seconds"] = timeout_seconds
        supervisor = ProcessTreeSupervisor(inspect_session=controller.inspect_session,
                                           freeze_session=controller.freeze_session,
                                           terminate_session=controller.terminate_session)
        supervisor.register_session(session_id=session_id, operation_id=action["action_id"],
                                    plan_sha256=plan.plan_sha256,
                                    backend_identity_sha256=canonical_sha256({"backend": "docker", "image_id": image}))
        record = _register_durable(registry, controller, plan, session_id, registry_broker, root_id)
        report["registered_before_start"] = True

        def on_queued(deadline: float) -> bool:
            nonlocal stop_evidence
            report["queue_entered_at"] = queue.entered_at
            report["queued_action_sha256"] = queue.queued_action_sha256
            report["queued_authorization_sha256"] = queue.queued_authorization_sha256
            report["timing"]["t_decision"] = time.time()
            observation = BoundedHostCall(lambda: receiver.query(action["action_id"]), name="liminal-queue-observation")
            before = observation.result_before(deadline)
            report["receiver_before_release"] = before
            if not (receiver.verify_receipt(before) and before.get("action_id") == action["action_id"]
                    and before.get("status") == "UNKNOWN" and before.get("reason") == "NOT_OBSERVED"):
                raise RuntimeBoundaryError("QUEUE_ALREADY_ACCEPTED_OR_UNVERIFIED")
            report["worker_at_trigger"] = controller.inspect_session(session_id)
            report["worker_processes_at_trigger"] = json.loads(json.dumps(controller.process_evidence.get(session_id)))
            if not report["worker_at_trigger"]["exists"] or not report["worker_at_trigger"]["running"]:
                raise RuntimeBoundaryError("LIVE_WORKER_NOT_OBSERVED_AT_TRIGGER")
            if arm == "C":
                report["broker_state_at_barrier"] = route.state(action["action_id"])
                if report["broker_state_at_barrier"].get("status") != "UNKNOWN":
                    raise RuntimeBoundaryError("BROKER_RESERVATION_UNVERIFIED")
                stop_evidence = contain_workload(supervisor, controller, session_id=session_id,
                                                broker=route, root_id=root_id,
                                                revoke_timeout_seconds=max(0.0, min(3.0, deadline - time.monotonic())))
            elif arm == "B":
                stop_evidence = contain_process_workload(supervisor, controller, session_id=session_id)
            if stop_evidence is not None:
                report["stop_evidence"] = stop_evidence
                report["timing"]["t_quiescent"] = stop_evidence["t_quiescent"]
                report["timing"]["t_revoke_ack"] = stop_evidence["t_revoke_ack"]
                if not stop_evidence["verified"]:
                    raise RuntimeBoundaryError("EXPERIMENT_STOP_UNVERIFIED")
            if time.monotonic() >= deadline:
                raise RuntimeBoundaryError("EXPERIMENT_DEADLINE_EXCEEDED")
            report["timing"]["t_queue_released"] = time.time()
            queue.release.set()
            return arm in {"B", "C"}

        bridge = MatchedWorkerBridge(route, positive, action, queue, on_queued)
        bridge.observer_required = True
        bridge.observer = lambda: controller.inspect_session(session_id)
        try:
            argv = build_docker_argv(plan, docker_binary=docker_binary, container_name=session_id)
            argv[1:3] = ["create", "--interactive"]
            image_index = argv.index(image)
            argv[image_index:image_index] = ["--entrypoint", "python3", "--log-driver", "none"]
            for key, value in ownership_labels(record).items():
                image_index = argv.index(image)
                argv[image_index:image_index] = ["--label", f"{key}={value}"]
            registry.mark_create_pending(record)
            if controller.command(argv[1:]).returncode:
                raise RuntimeBoundaryError("CONTAINER_CREATE_FAILED")
            _confirm_create_if_observed(registry, record, controller)
            controller.verify_configuration(session_id, plan)
            process = subprocess.Popen([docker_binary, "start", "--attach", "--interactive", controller.owned_container_ids[session_id]],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       shell=False, bufsize=0)
            report["protocol"] = _exchange(process, bridge, timeout_seconds)
            if len(bridge.actions) != 2 or report["timing"]["t_queue_released"] is None:
                raise RuntimeBoundaryError("MATCHED_PROTOCOL_INCOMPLETE")
            statuses = [result["status"] for result in bridge.actions]
            report["status"] = "UNKNOWN" if "UNKNOWN" in statuses else "BLOCKED" if "BLOCKED" in statuses else "COMPLETED"
        except Exception as exc:
            report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
            report["reason"] = str(exc) if isinstance(exc, RuntimeBoundaryError) else type(exc).__name__
        finally:
            try:
                _confirm_create_if_observed(registry, record, controller)
            except Exception:
                pass  # Unconfirmed creation stays durable and blocks admission.
            # Aborts an unreleased queue; it does not cancel a request already
            # handed to the receiver. A late callback stays externally scored.
            if not queue.release.is_set():
                queue.cancel()
            if stop_evidence is not None and stop_evidence["verified"]:
                report["containment"] = stop_evidence
            elif arm == "C":
                report["containment"] = contain_workload(supervisor, controller, session_id=session_id,
                                                        broker=route, root_id=root_id)
            else:
                report["containment"] = contain_process_workload(supervisor, controller, session_id=session_id)
            report["cleanup_after_queue_release"] = arm == "A" and report["timing"]["t_queue_released"] is not None
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
                attach_killed = False
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    attach_killed = True
                    process.kill()
                    process.wait(timeout=2)
                report["worker_attach_exit"] = {"returncode": process.returncode,
                                                "attach_cli_killed_by_host": attach_killed,
                                                "worker_stopped_before_reply": bridge.worker_stopped}
            for call in bridge.dispatch_calls:
                call.thread.join(timeout=0.05)
            report["actions"] = json.loads(json.dumps(bridge.actions))
            report["worker_claims"] = json.loads(json.dumps(bridge.claims))
            report["host_dispatch"] = {"calls": [call.observation() for call in bridge.dispatch_calls],
                                       "outcome_unresolved": bridge.dispatch_unresolved, "automatic_retry": False,
                                       "collection_complete": all(not call.thread.is_alive() for call in bridge.dispatch_calls),
                                       "boundary": "host threads are not killed; receiver reconciliation required for UNKNOWN"}
            report["effect_outcome"] = "UNKNOWN" if bridge.dispatch_unresolved else "RECEIVER_SCORING_REQUIRED"
            if not report["containment"]["verified"]:
                report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
                report["reason"] = "CONTAINMENT_PARTIAL_FAILURE"
            report["admission_guard"] = _admission_report(bridge)
            report["supervisor_registry"] = _finish_registry(registry, record, report["containment"], bridge)
            if not report["containment"]["verified"]:
                report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
                report["reason"] = "CONTAINMENT_PARTIAL_FAILURE"
    return report


def run_fixture(fixture: str, *, broker: Any, image: str, timeout_seconds: int = 10, action: dict | None = None,
                docker_binary: str = "docker", registry_path: str | Path | None = None,
                fault_scenario: str | None = None) -> dict:
    if fault_scenario is not None:
        from .runtime_faults import validate_fault_scenario
        validate_fault_scenario(fault_scenario, fixture)
    return _managed_runtime(broker, registry_path, {"mode": "docker", "fixture": fixture},
                            lambda registry: _run_fixture(fixture, broker=broker, image=image,
                                timeout_seconds=timeout_seconds, action=action, docker_binary=docker_binary,
                                registry=registry, fault_scenario=fault_scenario))


def _run_fixture(fixture: str, *, broker: Any, image: str, timeout_seconds: int, action: dict | None,
                 docker_binary: str, registry: SupervisorRegistry, fault_scenario: str | None = None) -> dict:
    """Run a known harmless fixture under actual Docker; never simulate Docker PASS.

    With ``action=None``, trusted host setup creates/binds/authorizes one action.
    With an explicit action, the caller must have created, bound and authorized it
    (including the parent/child registration for delegated_after_revoke).
    ``status`` describes runtime/broker outcome, not independent receiver scoring.
    """
    if fixture not in FIXTURES:
        raise RuntimeBoundaryError("UNKNOWN_FIXTURE")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise RuntimeBoundaryError("INVALID_TIMEOUT")
    report = {"fixture": fixture, "mode": "docker", "status": "ERROR", "reason": None,
              "actions": [], "worker_claims": [], "containment": {"verified": False, "zero_survivors": False},
              "image_id": image, "registered_before_start": False, "model_run": False}
    if os.name != "posix" or shutil.which(docker_binary) is None:
        return {**report, "status": "SKIPPED", "reason": "DOCKER_RUNTIME_UNAVAILABLE"}
    controller = DockerController(docker_binary)
    try:
        controller.image_id(image)
    except Exception as exc:
        return {**report, "status": "SKIPPED", "reason": str(exc) if isinstance(exc, RuntimeBoundaryError) else "DOCKER_RUNTIME_UNAVAILABLE"}
    identity = uuid.uuid4().hex
    session_id = "liminal-control-" + identity
    if action is None:
        root_id, execution_id = "root:" + identity, "execution:" + identity
        created = broker.receiver.create_root(root_id)
        broker.receiver.bind_execution(root_id, execution_id)
        if fixture == "delegated_after_revoke":
            parent_execution_id = execution_id
            execution_id = "child:" + identity
            broker.receiver.bind_execution(root_id, execution_id, parent_execution_id=parent_execution_id)
            report["registered_parent_execution_id"] = parent_execution_id
        action = {"action_id": "action:" + identity, "attempt_id": "attempt:" + identity,
                  "root_id": root_id, "execution_id": execution_id, "epoch": created["epoch"],
                  "target": "records", "arguments": {"value": "approved fixture record"}}
        broker.authorize(action)
    action = validate_action(action)
    report["action_id"], report["root_id"] = action["action_id"], action["root_id"]
    fault = None
    if fault_scenario is not None:
        from .runtime_faults import FaultExperiment
        fault = FaultExperiment(fault_scenario, broker, action, timeout_seconds=timeout_seconds)
        broker = fault.broker
    bridge = fault.make_bridge() if fault is not None else WorkerBridge(broker, action)
    process = None
    registered = False
    with tempfile.TemporaryDirectory(prefix="liminal-control-worker-") as workspace:
        os.chmod(workspace, 0o755)
        worker = Path(workspace) / "worker_fixture.py"
        shutil.copyfile(Path(__file__).with_name("worker_fixture.py"), worker)
        os.chmod(worker, 0o444)
        plan = IsolatedExecutionPlan.build(
            operation_id=action["action_id"], image_id=image,
            argv=("-I", "-u", "/workspace/worker_fixture.py", fixture),
            host_workspace=workspace, timeout_seconds=timeout_seconds,
            profile=IsolationProfile(pids_limit=32, memory_mb=128, cpus="0.5"),
        )
        report["plan_sha256"] = plan.plan_sha256
        supervisor = ProcessTreeSupervisor(inspect_session=controller.inspect_session,
                                           freeze_session=controller.freeze_session,
                                           terminate_session=controller.terminate_session)
        # Registration is complete before any create/start/worker instruction.
        supervisor.register_session(session_id=session_id, operation_id=action["action_id"],
                                    plan_sha256=plan.plan_sha256,
                                    backend_identity_sha256=canonical_sha256({"backend": "docker", "image_id": image}))
        record = _register_durable(registry, controller, plan, session_id, broker, action["root_id"])
        bridge.observer_required = True
        bridge.observer = lambda: controller.inspect_session(session_id)
        if fault is not None:
            fault.bind_runtime(bridge, controller, supervisor, session_id)
        registered = True
        report["registered_before_start"] = True
        try:
            argv = build_docker_argv(plan, docker_binary=docker_binary, container_name=session_id)
            argv[1:3] = ["create", "--interactive"]  # Retain stopped container for host observation.
            image_index = argv.index(image)
            argv[image_index:image_index] = ["--entrypoint", "python3", "--log-driver", "none"]
            for key, value in ownership_labels(record).items():
                image_index = argv.index(image)
                argv[image_index:image_index] = ["--label", f"{key}={value}"]
            registry.mark_create_pending(record)
            created = controller.command(argv[1:])
            if created.returncode:
                raise RuntimeBoundaryError("CONTAINER_CREATE_FAILED")
            _confirm_create_if_observed(registry, record, controller)
            controller.verify_configuration(session_id, plan)
            if fixture in POST_REVOKE:
                prior_revoke = BoundedHostCall(lambda: _revoke(broker, action["root_id"]), name="liminal-prior-revocation")
                try:
                    report["prior_revocation_ack"] = prior_revoke.result_before(time.monotonic() + 3)
                finally:
                    report["prior_revocation_call"] = prior_revoke.observation()
            process = subprocess.Popen([docker_binary, "start", "--attach", "--interactive", controller.owned_container_ids[session_id]],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       shell=False, bufsize=0)
            report["protocol"] = _exchange(process, bridge, timeout_seconds)
            statuses = [r["status"] for r in bridge.actions]
            report["status"] = "UNKNOWN" if "UNKNOWN" in statuses else "BLOCKED" if "BLOCKED" in statuses else "COMPLETED"
        except Exception as exc:
            report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
            report["reason"] = str(exc) if isinstance(exc, RuntimeBoundaryError) else type(exc).__name__
        finally:
            try:
                _confirm_create_if_observed(registry, record, controller)
            except Exception:
                pass  # Unconfirmed creation stays durable and blocks admission.
            if registered:
                if fault is not None and fault.stop_evidence is not None:
                    # Retain the barrier's original ACK/times. A later cleanup
                    # must not rewrite which stop preceded finalization.
                    report["containment"] = fault.stop_evidence
                    if not fault.stop_evidence["verified"]:
                        report["cleanup_containment"] = contain_workload(supervisor, controller,
                            session_id=session_id, broker=broker, root_id=action["root_id"])
                else:
                    report["containment"] = contain_workload(supervisor, controller, session_id=session_id,
                                                           broker=broker, root_id=action["root_id"])
            if fault is not None:
                fault.finish_calls(bridge)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            report["actions"] = bridge.actions
            report["worker_claims"] = bridge.claims
            report["host_dispatch"] = {
                "calls": [call.observation() for call in bridge.dispatch_calls],
                "outcome_unresolved": bridge.dispatch_unresolved,
                "automatic_retry": False,
                "collection_complete": all(not call.thread.is_alive() for call in bridge.dispatch_calls),
                "boundary": "deadline bounds supervisor wait; host threads are not killed; receiver reconciliation required",
            }
            report["effect_outcome"] = "UNKNOWN" if bridge.dispatch_unresolved else "RECEIVER_SCORING_REQUIRED"
            if not report["containment"]["verified"]:
                report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
                report["reason"] = "CONTAINMENT_PARTIAL_FAILURE"
            if fixture == "descendant_timeout":
                before_stop = report["containment"].get("pre_stop_observation") or {}
                observed_child = before_stop.get("descendant_count", 0) >= 1
                report["fixture_complete"] = observed_child
                report["fixture_verdict"] = "OBSERVED" if observed_child else "INCOMPLETE"
                if not observed_child:
                    report["status"] = "ERROR"
                    report["reason"] = "DESCENDANT_NOT_OBSERVED"
            report["admission_guard"] = _admission_report(bridge)
            report["supervisor_registry"] = _finish_registry(registry, record, report["containment"], bridge)
            if not report["containment"]["verified"]:
                report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
                report["reason"] = "CONTAINMENT_PARTIAL_FAILURE"
            if fault is not None:
                report["fault"] = fault.collect_report(bridge, report)
    return report
