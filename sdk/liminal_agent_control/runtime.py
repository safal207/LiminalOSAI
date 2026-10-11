"""Trusted Linux Docker supervisor for one receiver-backed worker experiment.

The Docker daemon, host, pinned image and receiver are trust assumptions. The
worker is not trusted to report success, isolation, descendants or termination.
Existing LiminalOS isolation profiles and session containment receipts are reused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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

FIXTURES = frozenset({
    "honest", "forged_success", "stale_authority", "delegated_after_revoke",
    "argument_mutation", "delayed_post_ack", "descendant_timeout", "malformed",
    "output_flood", "crash",
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

    def accept(self, line: bytes, *, deadline: float | None = None) -> dict | None:
        self.messages += 1
        if self.messages > MAX_MESSAGES or self.done or self.dispatch_unresolved:
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
                try:
                    result = call.result_before(deadline if deadline is not None else time.monotonic() + 3)
                except RuntimeBoundaryError:
                    self.dispatch_unresolved = True
                    self.actions.append({"status": "UNKNOWN", "reason": "HOST_DISPATCH_UNRESOLVED",
                                         "action_id": self.action["action_id"], "receipt": None})
                    raise
                if type(result) is not dict or result.get("status") not in {"COMMITTED", "BLOCKED", "UNKNOWN"}:
                    self.dispatch_unresolved = True
                    self.actions.append({"status": "UNKNOWN", "reason": "BROKER_RESULT_INVALID",
                                         "action_id": self.action["action_id"], "receipt": None})
                    raise RuntimeBoundaryError("BROKER_RESULT_INVALID")
                result = json.loads(json.dumps(result, allow_nan=False))
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
        result = self.command(["inspect", session_id])
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
            return objects[0]
        except (ValueError, TypeError) as exc:
            raise RuntimeBoundaryError("DOCKER_OBSERVATION_INVALID") from exc

    def inspect_session(self, session_id: str) -> dict:
        value = self._inspect(session_id)
        if value is None:
            return {"exists": False, "running": False, "descendant_count": 0, "tree_sha256": ZERO_SHA256}
        state = value["State"]
        running, paused = state.get("Running"), state.get("Paused")
        if type(running) is not bool or type(paused) is not bool:
            raise RuntimeBoundaryError("DOCKER_STATE_INVALID")
        process_evidence: list = []
        descendants = 0
        if running:
            result = self.command(["top", session_id])
            if result.returncode:
                raise RuntimeBoundaryError("PROCESS_OBSERVATION_UNAVAILABLE")
            rows = result.stdout.decode(errors="strict").strip().splitlines()
            if len(rows) < 2:
                raise RuntimeBoundaryError("PROCESS_OBSERVATION_EMPTY")
            header = rows[0].split()
            if "PID" not in header or "PPID" not in header:
                raise RuntimeBoundaryError("PROCESS_LINEAGE_UNAVAILABLE")
            pid_index, parent_index = header.index("PID"), header.index("PPID")
            for row in rows[1:]:
                fields = row.split()
                if len(fields) <= max(pid_index, parent_index) or not fields[pid_index].isdigit() or not fields[parent_index].isdigit():
                    raise RuntimeBoundaryError("PROCESS_LINEAGE_INVALID")
                process_evidence.append({"pid": int(fields[pid_index]), "ppid": int(fields[parent_index])})
            pids = {node["pid"] for node in process_evidence}
            if len(pids) != len(process_evidence) or state.get("Pid") not in pids:
                raise RuntimeBoundaryError("PROCESS_ROOT_NOT_OBSERVED")
            descendants = len(process_evidence) - 1
        # Host evidence only: never sent across worker STDIO. Retain bounded
        # PID/PPID values, not arbitrary process command lines or environment.
        self.process_evidence[session_id] = {
            "source": "docker inspect + docker top", "observed_at": time.time(),
            "container_id": value.get("Id"), "running": running, "paused": paused,
            "root_pid": state.get("Pid"), "processes": process_evidence,
        }
        return {
            "exists": True, "running": running and not paused,
            "descendant_count": descendants,
            "tree_sha256": canonical_sha256({"session": session_id, "state": state, "processes": process_evidence}),
        }

    def freeze_session(self, session_id: str) -> None:
        if self.command(["pause", session_id]).returncode:
            raise RuntimeBoundaryError("FREEZE_FAILED")

    def terminate_session(self, session_id: str) -> None:
        result = self.command(["rm", "--force", session_id])
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


def contain_workload(supervisor: ProcessTreeSupervisor, controller: Any, *, session_id: str, broker: Any, root_id: str,
                     revoke_timeout_seconds: float = 3.0) -> dict:
    """Best-effort termination persists even if freeze/revocation/observation fails."""
    started = time.monotonic()
    failures: list[str] = []
    pre_stop = None
    process_evidence = None
    try:
        pre_stop = controller.inspect_session(session_id)
        process_evidence = json.loads(json.dumps(getattr(controller, "process_evidence", {}).get(session_id)))
    except Exception:
        failures.append("PRE_STOP_OBSERVATION_UNAVAILABLE")
    freeze = supervisor.freeze_all()
    if freeze["failure_codes"]:
        failures.append("FREEZE_INCOMPLETE")
    revoked = None
    revocation_call = BoundedHostCall(lambda: _revoke(broker, root_id), name="liminal-broker-revocation")
    try:
        revoked = revocation_call.result_before(time.monotonic() + revoke_timeout_seconds)
    except Exception:
        failures.append("REVOCATION_UNVERIFIED")
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
        "revocation_call": revocation_call.observation(),
        "revocation_wait_limit_seconds": revoke_timeout_seconds,
        "zero_survivors": absent, "partial_failures": failures,
        "verified": absent and not failures,
        "stop_elapsed_seconds": round(time.monotonic() - started, 6),
        "observation_source": "trusted_host_docker_daemon",
        "boundary": "container PID/cgroup lifecycle; excludes host/kernel/daemon compromise",
    }


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
                    if response is not None:
                        _write_bounded(process, response, deadline)
                if len(buffers["stdout"]) > MAX_LINE_BYTES:
                    raise RuntimeBoundaryError("FRAME_SIZE_EXCEEDED")
        return {"output_bytes": byte_count, "message_count": bridge.messages}


def run_fixture(fixture: str, *, broker: Any, image: str, timeout_seconds: int = 10, action: dict | None = None, docker_binary: str = "docker") -> dict:
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
    bridge = WorkerBridge(broker, action)
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
        registered = True
        report["registered_before_start"] = True
        try:
            argv = build_docker_argv(plan, docker_binary=docker_binary, container_name=session_id)
            argv[1:3] = ["create", "--interactive"]  # Retain stopped container for host observation.
            image_index = argv.index(image)
            argv[image_index:image_index] = ["--entrypoint", "python3", "--log-driver", "none"]
            created = controller.command(argv[1:])
            if created.returncode:
                raise RuntimeBoundaryError("CONTAINER_CREATE_FAILED")
            controller.verify_configuration(session_id, plan)
            if fixture in POST_REVOKE:
                prior_revoke = BoundedHostCall(lambda: _revoke(broker, action["root_id"]), name="liminal-prior-revocation")
                try:
                    report["prior_revocation_ack"] = prior_revoke.result_before(time.monotonic() + 3)
                finally:
                    report["prior_revocation_call"] = prior_revoke.observation()
            process = subprocess.Popen([docker_binary, "start", "--attach", "--interactive", session_id],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       shell=False, bufsize=0)
            report["protocol"] = _exchange(process, bridge, timeout_seconds)
            statuses = [r["status"] for r in bridge.actions]
            report["status"] = "UNKNOWN" if "UNKNOWN" in statuses else "BLOCKED" if "BLOCKED" in statuses else "COMPLETED"
        except Exception as exc:
            report["status"] = "UNKNOWN" if bridge.dispatch_unresolved else "ERROR"
            report["reason"] = str(exc) if isinstance(exc, RuntimeBoundaryError) else type(exc).__name__
        finally:
            if registered:
                report["containment"] = contain_workload(supervisor, controller, session_id=session_id,
                                                       broker=broker, root_id=action["root_id"])
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
    return report
