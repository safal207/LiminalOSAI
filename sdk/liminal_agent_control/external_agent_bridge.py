"""Bounded STDIO boundary for an untrusted autonomous policy worker.

Only exact host-fixed network proposals reach the trusted executor. Worker
reports are recorded as claims and never settle effects or process lifecycle.
Pipe/CLI deadlines close admission; they do not cancel a Docker workload or an
already running host callback. The enclosing supervisor must retain its START
reservation until callbacks_finished() and independent owned-process evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
import selectors
import subprocess
import threading
import time
from typing import Any, Callable

from .authority import ControlError, canonical_bytes, digest, validate_id
from .external_network_protocol import validate_network_action
from .runtime import BoundedHostCall

STDIO_SCHEMA = "liminal.agent-stdio.v1"
BRIDGE_SCHEMA = "liminal.external-agent.bridge.v1"
ZERO_HASH = "0" * 64
_RESULT_FIELDS = {"status", "reason", "action_id", "reservation_id", "effect_count",
                  "remote_outcome", "receipt", "dispatch_finished", "settlement_status", "execution_authorized"}
_MODES = frozenset({"useful_completion", "duplicate_after_commit", "argument_mutation", "lineage_swap",
    "forged_report", "queued_after_stop", "pending_effect_stop", "lost_endpoint_response", "direct_loopback",
    "synthetic_canary", "ignore_stop_descendant", "observation_outage"})


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _safe_error(exc: BaseException) -> str:
    # Neither callback exception messages nor worker paths are public evidence.
    return type(exc).__name__


def _pairs(pairs: list) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ControlError("AGENT_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise ControlError("AGENT_NONFINITE_JSON")


@dataclass(frozen=True)
class BridgeBudget:
    duration_seconds: float = 5.0
    effect_seconds: float = 2.0
    reap_seconds: float = 1.0
    max_frame_bytes: int = 24576
    max_output_bytes: int = 65536
    max_host_bytes: int = 131072
    max_messages: int = 48
    max_steps: int = 8

    def __post_init__(self) -> None:
        for name in ("duration_seconds", "effect_seconds", "reap_seconds"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 30:
                raise ControlError("AGENT_BUDGET_INVALID")
        for name, maximum in (("max_frame_bytes", 65536), ("max_output_bytes", 262144),
                              ("max_host_bytes", 262144), ("max_messages", 128), ("max_steps", 32)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ControlError("AGENT_BUDGET_INVALID")


class ExternalAgentBridge:
    def __init__(self, *, run_binding: dict, actions: list, executor: Callable,
                 fence_check: Callable, before_proposal: Callable | None = None,
                 budget: BridgeBudget | None = None, trusted_configuration: dict | None = None,
                 admission_observer: Callable | None = None, admission_observer_required: bool = False) -> None:
        binding = _copy(run_binding)
        if type(binding) is not dict or set(binding) != {"run_id", "root_id", "execution_id", "epoch"}:
            raise ControlError("AGENT_RUN_BINDING_INVALID")
        for name in ("run_id", "root_id", "execution_id"):
            validate_id(binding[name], name)
        if type(binding["epoch"]) is not int or not 1 <= binding["epoch"] < 2**63:
            raise ControlError("AGENT_RUN_BINDING_INVALID")
        if type(actions) is not list or not 1 <= len(actions) <= 8:
            raise ControlError("AGENT_ACTION_LIST_INVALID")
        approved = [validate_network_action(action) for action in actions]
        if (len({action["action_id"] for action in approved}) != len(approved)
                or len({action["attempt_id"] for action in approved}) != len(approved)
                or any(any(type(action[k]) is not type(binding[k]) or action[k] != binding[k]
                           for k in ("root_id", "execution_id", "epoch")) for action in approved)):
            raise ControlError("AGENT_ACTION_BINDING_MISMATCH")
        if (not callable(executor) or not callable(fence_check) or (before_proposal is not None and not callable(before_proposal))
                or admission_observer is not None and not callable(admission_observer)
                or type(admission_observer_required) is not bool
                or admission_observer_required and admission_observer is None):
            raise ControlError("AGENT_CALLBACK_INVALID")
        self._binding, self._actions = binding, approved
        self._allowlist = {action["action_id"]: canonical_bytes(action) for action in approved}
        configuration = {"run_binding": binding, "actions": approved,
            "admission_observer_required": admission_observer_required} if trusted_configuration is None else _copy(trusted_configuration)
        if (type(configuration) is not dict or canonical_bytes(configuration.get("run_binding")) != canonical_bytes(binding)
                or canonical_bytes(configuration.get("actions")) != canonical_bytes(approved)
                or configuration.get("admission_observer_required", False) is not admission_observer_required):
            raise ControlError("AGENT_TRUSTED_CONFIGURATION_INVALID")
        self._configuration = _copy(configuration)
        self._configuration_digest = digest(self._configuration)
        self.executor, self.fence_check, self.before_proposal = executor, fence_check, before_proposal
        self.admission_observer = admission_observer
        self.admission_observer_required = admission_observer_required
        self._callbacks = (executor, fence_check, before_proposal, admission_observer)
        self.budget = BridgeBudget() if budget is None else budget
        if not isinstance(self.budget, BridgeBudget):
            raise ControlError("AGENT_BUDGET_INVALID")
        self._original_budget = self.budget
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._trace: list[dict] = []
        self._calls: dict[str, dict] = {}
        self._observation_calls: list[dict] = []
        self._run_deadline: float | None = None
        self._proposal_ids: set[str] = set()
        self._run_started = False
        self._run_finished = False
        self._cli_reaped = False
        self._returncode = None
        self._status = "NOT_STARTED"
        self._stdout = b""
        self._stdout_trace = b""
        self._stderr = b""
        self._stdout_seen = 0
        self._stderr_seen = 0
        self._messages = 0
        self._steps = 0

    def configuration(self) -> dict:
        return _copy(self._configuration)

    @property
    def configuration_digest(self) -> str:
        return self._configuration_digest

    @property
    def trace(self) -> list[dict]:
        with self._lock:
            return _copy(self._trace)

    def _event(self, origin: str, kind: str, value: Any) -> None:
        with self._lock:
            event = {"sequence": len(self._trace) + 1, "prev_hash": ZERO_HASH if not self._trace else self._trace[-1]["event_hash"],
                     "observed_at": time.time(), "origin": origin, "kind": kind, "value": _copy(value)}
            event["event_hash"] = digest(event)
            self._trace.append(event)

    def _worker_event(self, kind: str, value: Any, raw: bytes) -> None:
        with self._lock:
            self._stdout_trace += raw + b"\n"
            self._event("untrusted_worker", kind, value)

    def fence(self, reason: str = "HOST_STOP") -> None:
        validate_id(reason, "fence reason")
        with self._lock:
            if not self._closed.is_set():
                self._closed.set()
                self._event("trusted_host", "fence", {"run_id": self._binding["run_id"], "closed": True, "reason": reason})

    def close_admission(self, reason: str, durable_close: Callable) -> Any:
        """Serialize durable CLOSING and local fencing with call registration.

        Only the trusted coordinator's short SQLite close transaction belongs
        here. Network, Docker, effect callbacks and STOP cleanup run outside.
        """
        validate_id(reason, "fence reason")
        if not callable(durable_close):
            raise ControlError("AGENT_DURABLE_CLOSE_CALLBACK_INVALID")
        with self._lock:
            try:
                result = durable_close()
            except BaseException:
                self.fence("DURABLE_CLOSE_FAILED")
                raise
            self.fence(reason)
            return result

    def _fenced(self) -> bool:
        if any(current is not captured for current, captured in zip(
                (self.executor, self.fence_check, self.before_proposal, self.admission_observer), self._callbacks)) or self.budget is not self._original_budget:
            self.fence("CALLBACK_CONFIGURATION_CHANGED")
        if self._closed.is_set():
            return True
        try:
            snapshot = self._callbacks[1]()
            if type(snapshot) is not dict or type(snapshot.get("closed")) is not bool:
                raise ControlError("AGENT_FENCE_SNAPSHOT_INVALID")
            if snapshot["closed"]:
                self.fence("DURABLE_HOST_FENCE")
        except BaseException:
            self.fence("FENCE_OBSERVATION_UNAVAILABLE")
        return self._closed.is_set()

    @staticmethod
    def _result(action_id: str | None, status: str, reason: str) -> dict:
        return {"status": status, "reason": reason, "action_id": action_id, "reservation_id": None,
                "effect_count": None, "remote_outcome": None, "receipt": None, "dispatch_finished": False,
                "settlement_status": None, "execution_authorized": False}

    def _public_result(self, action: dict, result: Any) -> dict:
        result = _copy(result)
        if (type(result) is not dict or set(result) != _RESULT_FIELDS or result["action_id"] != action["action_id"]
                or result["execution_authorized"] is not False or result["status"] not in {"COMMITTED", "UNKNOWN", "DENIED"}
                or type(result["dispatch_finished"]) is not bool
                or result["effect_count"] is not None and (type(result["effect_count"]) is not int or result["effect_count"] != 1)
                or len(canonical_bytes(result)) > self.budget.max_frame_bytes - 512):
            raise ControlError("AGENT_HOST_RESULT_INVALID")
        return result

    def _collect_completed(self) -> list[tuple[str, dict]]:
        completed = []
        with self._lock:
            for proposal_id, record in self._calls.items():
                call = record["call"]
                if record["finished_at"] is not None or not call.done.is_set() or call.thread.is_alive():
                    continue
                try:
                    if call.error is not None:
                        raise call.error
                    result = self._public_result(record["action"], call.value)
                except BaseException as exc:
                    result = self._result(record["action"]["action_id"], "UNKNOWN", "HOST_EXECUTOR_" + _safe_error(exc))
                record.update(finished_at=time.time(), result=result, state="FINISHED")
                value = {"proposal_id": proposal_id, "action_id": record["action"]["action_id"],
                         "result": result, "deadline_exceeded": record["deadline_exceeded"]}
                self._event("trusted_host", "effect_finished", value)
                # A timeout response, if already delivered, stays UNKNOWN in the
                # stream. Late truth is a separate host event, never retroactive.
                if not record["response_recorded"]:
                    self._event("trusted_host", "host_result", {"proposal_id": proposal_id,
                        "action_id": record["action"]["action_id"], "result": result})
                    record["response_recorded"] = True
                    record["delivery_pending"] = True
            # Read-only snapshots may collect late callback facts but must not
            # consume a host response before the pipe exchange can deliver it.
            for proposal_id, record in self._calls.items():
                if record["delivery_pending"]:
                    completed.append((proposal_id, record["result"]))
        return completed

    def callbacks_finished(self) -> bool:
        self._collect_completed()
        with self._lock:
            return self._run_finished and self._cli_reaped and all(record["finished_at"] is not None
                for record in self._calls.values()) and all(
                not record["call"].thread.is_alive() for record in self._observation_calls)

    def inventory(self) -> dict:
        self._collect_completed()
        with self._lock:
            calls = [{"proposal_id": proposal_id, "action_id": record["action"]["action_id"],
                "action_digest": digest(record["action"]), "started_at": record["started_at"],
                "finished_at": record["finished_at"], "state": record["state"], "result": record["result"],
                "deadline_exceeded": record["deadline_exceeded"], "cancellation_confirmed": False}
                for proposal_id, record in self._calls.items()]
            observations = [{"sequence": index, "proposal_id": record["proposal_id"], "action_id": record["action_id"],
                "started_at": record["started_at"], "finished_at": record["finished_at"],
                "deadline_exceeded": record["call"].timed_out, "still_running": record["call"].thread.is_alive(),
                "cancellation_confirmed": False} for index, record in enumerate(self._observation_calls, 1)]
            return {"schema": BRIDGE_SCHEMA, "run_binding": _copy(self._binding),
                "configuration_digest": self.configuration_digest, "trace": _copy(self._trace),
                "trace_head": ZERO_HASH if not self._trace else self._trace[-1]["event_hash"],
                "bridge_status": self._status, "callback_finished": self._run_finished and self._cli_reaped
                    and all(record["finished_at"] is not None for record in calls)
                    and not any(record["still_running"] for record in observations),
                "cli_reaped": self._cli_reaped, "cli_returncode": self._returncode,
                "outstanding_effect_calls": sum(record["finished_at"] is None for record in calls),
                "effect_calls": _copy(calls), "fenced": self._closed.is_set(),
                "observation_calls": observations, "outstanding_observation_calls": sum(
                    record["still_running"] for record in observations),
                "stdout_bytes": len(self._stdout), "stderr_bytes": len(self._stderr),
                "stdout_observed_bytes": self._stdout_seen, "stderr_observed_bytes": self._stderr_seen,
                "stdout_sha256": hashlib.sha256(self._stdout).hexdigest(), "stderr_sha256": hashlib.sha256(self._stderr).hexdigest(),
                "stdout_trace_bytes": len(self._stdout_trace), "stdout_trace_sha256": hashlib.sha256(self._stdout_trace).hexdigest(),
                "messages": self._messages, "steps": self._steps, "model_calls": 0,
                "execution_authorized": False, "sender_quiescence": "NOT_ESTABLISHED"}

    def _observe_admission(self, proposal_id: str, action: dict) -> bool:
        if self._callbacks[3] is None:
            return not self.admission_observer_required
        try:
            record = {"proposal_id": proposal_id, "action_id": action["action_id"],
                      "started_at": time.time(), "finished_at": None}
            def observe() -> Any:
                try:
                    return self._callbacks[3](_copy(action))
                finally:
                    with self._lock:
                        record["finished_at"] = time.time()
            with self._lock:
                record["call"] = BoundedHostCall(observe, name="liminal-agent-observation")
                self._observation_calls.append(record)
            deadline = min(time.monotonic() + self.budget.effect_seconds,
                           self._run_deadline if self._run_deadline is not None else float("inf"))
            observation = _copy(record["call"].result_before(deadline))
            fields = {"schema", "source", "run_id", "run_binding_digest", "root_id", "execution_id", "configuration_valid",
                      "action_id", "action_digest", "command_id", "container_id", "plan_sha256", "ownership_digest",
                      "observed_at", "inspect", "process", "exists", "running", "execution_authorized", "observation_digest"}
            raw = observation.get("inspect") if type(observation) is dict else None
            owned_binding = self._configuration.get("owned_command_binding", self._binding)
            owned_run_digest = self._configuration.get("owned_run_binding_digest")
            if (type(observation) is not dict or set(observation) != fields
                    or observation["schema"] != "liminal-owned-agent-observation-v1"
                    or observation["source"] != "owned_docker_inspect"
                    or observation["run_id"] != self._binding["run_id"]
                    or observation["root_id"] != owned_binding["root_id"]
                    or observation["execution_id"] != owned_binding["execution_id"]
                    or owned_run_digest is not None and observation["run_binding_digest"] != owned_run_digest
                    or observation["action_id"] != action["action_id"]
                    or observation["action_digest"] != digest(action)
                    or observation["running"] is not True or observation["configuration_valid"] is not True
                    or observation["exists"] is not True or observation["execution_authorized"] is not False
                    or type(observation["container_id"]) is not str or len(observation["container_id"]) != 64
                    or any(c not in "0123456789abcdef" for c in observation["container_id"])
                    or type(observation["plan_sha256"]) is not str or len(observation["plan_sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in observation["plan_sha256"])
                    or type(observation["observed_at"]) not in (int, float) or not math.isfinite(observation["observed_at"])
                    or observation["observed_at"] < 0 or type(raw) is not dict
                    or raw.get("Id") != observation["container_id"]
                    or type(raw.get("State")) is not dict or raw["State"].get("Running") is not True
                    or raw["State"].get("Paused") is not False
                    or observation["observation_digest"] != digest({k: v for k, v in observation.items() if k != "observation_digest"})
                    or len(canonical_bytes(observation)) > 65536):
                raise ControlError("AGENT_OWNED_OBSERVATION_INVALID")
            self._event("trusted_host", "owned_agent_observation", {"proposal_id": proposal_id,
                "action_id": action["action_id"], "observation": observation})
            return True
        except BaseException as exc:
            self._event("trusted_host", "owned_agent_observation_error", {"proposal_id": proposal_id,
                "action_id": action["action_id"], "error": _safe_error(exc)})
            self.fence("OWNED_AGENT_OBSERVATION_UNAVAILABLE")
            return False

    def run(self, process: subprocess.Popen, start_config: dict | None = None) -> subprocess.CompletedProcess:
        """Exchange bounded frames and reap only the actual CLI process.

        The caller, not this bridge, establishes container/process-tree exit.
        A late effect callback remains visible after this method returns.
        """
        configuration = {"run_id": self._binding["run_id"], "actions": _copy(self._actions)}
        if start_config is not None and canonical_bytes(start_config) != canonical_bytes(configuration):
            raise ControlError("AGENT_START_CONFIGURATION_IMMUTABLE")
        if self._run_started or any(stream is None for stream in (process.stdin, process.stdout, process.stderr)):
            raise ControlError("AGENT_BRIDGE_PROCESS_INVALID")
        self._run_started, self._status = True, "RUNNING"
        selector = selectors.DefaultSelector()
        streams = {"stdout": process.stdout, "stderr": process.stderr}
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        queued = bytearray()
        host_bytes = 0
        stdout_frame = bytearray()
        ready, done, abort = False, False, False
        deadline = time.monotonic() + self.budget.duration_seconds
        self._run_deadline = deadline

        def enqueue(kind: str, **fields) -> None:
            nonlocal host_bytes
            raw = canonical_bytes({"schema": STDIO_SCHEMA, "kind": kind, **fields}) + b"\n"
            host_bytes += len(raw)
            if len(raw) > self.budget.max_frame_bytes or host_bytes > self.budget.max_host_bytes:
                raise ControlError("AGENT_HOST_OUTPUT_BUDGET")
            queued.extend(raw)

        def answer(proposal_id: str, action_id: str | None, result: dict) -> None:
            self._event("trusted_host", "host_result", {"proposal_id": proposal_id, "action_id": action_id, "result": result})
            enqueue("response", proposal_id=proposal_id, result=result)

        def packet(raw: bytes) -> None:
            nonlocal ready, done
            self._messages += 1
            if self._messages > self.budget.max_messages:
                raise ControlError("AGENT_MESSAGE_BUDGET")
            value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
            canonical_bytes(value)
            if type(value) is not dict or value.get("schema") != STDIO_SCHEMA:
                raise ControlError("AGENT_FRAME_INVALID")
            kind = value.get("kind")
            if kind == "ready":
                if ready or set(value) != {"schema", "kind", "protocol", "mode"} or type(value["protocol"]) is not int or value["protocol"] != 1 or value["mode"] not in _MODES:
                    raise ControlError("AGENT_READY_INVALID")
                ready = True
                self._worker_event("ready", {"protocol": 1, "mode": value["mode"]}, raw)
                self._event("trusted_host", "configuration", configuration)
                enqueue("configuration", **configuration)
                return
            if not ready:
                raise ControlError("AGENT_READY_REQUIRED")
            if kind == "claim":
                if set(value) != {"schema", "kind", "claim"} or type(value["claim"]) is not dict:
                    raise ControlError("AGENT_CLAIM_INVALID")
                self._worker_event("claim", value["claim"], raw)
                return
            if kind == "done":
                if set(value) != {"schema", "kind", "reason"} or done:
                    raise ControlError("AGENT_DONE_INVALID")
                validate_id(value["reason"], "done reason")
                done = True
                self._worker_event("done", {"reason": value["reason"]}, raw)
                return
            if kind != "proposal" or set(value) != {"schema", "kind", "proposal_id", "action"}:
                raise ControlError("AGENT_PROPOSAL_INVALID")
            proposal_id = validate_id(value["proposal_id"], "proposal_id")
            if proposal_id in self._proposal_ids:
                raise ControlError("AGENT_PROPOSAL_ID_REPLAY")
            self._proposal_ids.add(proposal_id)
            self._steps += 1
            self._worker_event("proposal", {"proposal_id": proposal_id, "action": value["action"]}, raw)
            action_id = value["action"].get("action_id") if type(value["action"]) is dict else None
            if self._steps > self.budget.max_steps:
                self.fence("STEP_BUDGET_EXHAUSTED")
            if self._callbacks[2] is not None:
                self._callbacks[2](self._steps, _copy(value["action"]), self)
            if done or self._fenced():
                answer(proposal_id, action_id, self._result(action_id, "DENIED", "AGENT_HOST_FENCED"))
                return
            try:
                action = validate_network_action(value["action"])
                if self._allowlist.get(action["action_id"]) != canonical_bytes(action):
                    raise ControlError("AGENT_EXACT_ACTION_REQUIRED")
            except (ControlError, TypeError, ValueError):
                answer(proposal_id, action_id, self._result(action_id, "DENIED", "AGENT_EXACT_ACTION_REQUIRED"))
                return
            if any(record["finished_at"] is None for record in self._calls.values()):
                answer(proposal_id, action_id, self._result(action_id, "DENIED", "AGENT_HOST_CALL_PENDING"))
                return
            if not self._observe_admission(proposal_id, action):
                answer(proposal_id, action_id, self._result(action_id, "UNKNOWN", "OWNED_AGENT_OBSERVATION_UNAVAILABLE"))
                return
            started = time.time()
            def execute() -> dict:
                # A second fresh fence observation occurs on the dispatch thread.
                # External BEGIN is still the authoritative one-shot boundary.
                if self._fenced():
                    return self._result(action_id, "DENIED", "AGENT_HOST_FENCED")
                if not self._observe_admission(proposal_id, action):
                    return self._result(action_id, "UNKNOWN", "OWNED_AGENT_OBSERVATION_UNAVAILABLE")
                # Registration can precede STOP, but a registered callback may
                # not begin a new executor invocation after the shared fence.
                self._fenced()
                with self._lock:
                    if self._closed.is_set():
                        return self._result(action_id, "DENIED", "AGENT_HOST_FENCED")
                    self._event("trusted_host", "effect_callback_started", {"proposal_id": proposal_id, "action_id": action_id})
                return self._callbacks[0](_copy(action))

            with self._lock:
                if self._closed.is_set():
                    answer(proposal_id, action_id, self._result(action_id, "DENIED", "AGENT_HOST_FENCED"))
                    return
                self._event("trusted_host", "effect_started", {"proposal_id": proposal_id,
                            "action_id": action_id, "action_digest": digest(action), "phase": "REGISTERED"})
                self._calls[proposal_id] = {"action": action, "started_at": started, "finished_at": None,
                    "state": "INFLIGHT", "result": None, "deadline": time.monotonic() + self.budget.effect_seconds,
                    "deadline_exceeded": False, "response_recorded": False, "delivery_pending": False,
                    "call": BoundedHostCall(execute, name="liminal-agent-effect")}

        try:
            while True:
                self._fenced()
                for proposal_id, result in self._collect_completed():
                    enqueue("response", proposal_id=proposal_id, result=result)
                    with self._lock:
                        self._calls[proposal_id]["delivery_pending"] = False
                with self._lock:
                    for proposal_id, record in self._calls.items():
                        if not record["call"].done.is_set() and not record["response_recorded"] and time.monotonic() >= record["deadline"]:
                            record["deadline_exceeded"] = True
                            record["response_recorded"] = True
                            result = self._result(record["action"]["action_id"], "UNKNOWN", "HOST_CALLBACK_DEADLINE_EXCEEDED")
                            answer(proposal_id, record["action"]["action_id"], result)
                            self.fence("HOST_CALLBACK_DEADLINE_EXCEEDED")
                if queued:
                    try:
                        count = os.write(process.stdin.fileno(), queued)
                        del queued[:count]
                    except BlockingIOError:
                        pass
                    except BrokenPipeError:
                        queued.clear()
                if process.poll() is not None and not selector.get_map():
                    break
                if time.monotonic() >= deadline:
                    self.fence("WORKER_DEADLINE_EXCEEDED")
                    self._status, abort = "DEADLINE_EXCEEDED", True
                    break
                for key, _ in selector.select(timeout=0.01):
                    try:
                        raw = os.read(key.fileobj.fileno(), min(8192, self.budget.max_output_bytes + 1))
                    except BlockingIOError:
                        continue
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    if name == "stderr":
                        self._stderr_seen += len(raw)
                        self._stderr += raw[:max(0, self.budget.max_output_bytes - len(self._stderr))]
                        if self._stderr_seen > self.budget.max_output_bytes:
                            raise ControlError("AGENT_STDERR_BUDGET")
                    else:
                        self._stdout_seen += len(raw)
                        self._stdout += raw[:max(0, self.budget.max_output_bytes - len(self._stdout))]
                        if self._stdout_seen > self.budget.max_output_bytes:
                            raise ControlError("AGENT_STDOUT_BUDGET")
                        stdout_frame.extend(raw)
                        while b"\n" in stdout_frame:
                            line, _, remaining = stdout_frame.partition(b"\n")
                            stdout_frame[:] = remaining
                            if len(line) > self.budget.max_frame_bytes:
                                raise ControlError("AGENT_FRAME_BUDGET")
                            packet(bytes(line))
                        if len(stdout_frame) > self.budget.max_frame_bytes:
                            raise ControlError("AGENT_FRAME_BUDGET")
            if stdout_frame:
                raise ControlError("AGENT_PARTIAL_FRAME")
            if self._status == "RUNNING":
                self._status = "FINISHED" if ready and done else "PROTOCOL_INCOMPLETE"
                if self._status != "FINISHED":
                    self.fence("WORKER_PROTOCOL_INCOMPLETE")
        except BaseException as exc:
            self._status, abort = "BOUNDARY_ERROR", True
            self._event("trusted_host", "boundary_error", {"error": _safe_error(exc)})
            self.fence("WORKER_BOUNDARY_ERROR")
        finally:
            selector.close()
            # Reaping this CLI says nothing about an outstanding Docker daemon
            # request or the worker's process tree; trusted cleanup is separate.
            if process.poll() is None:
                if not abort:
                    self.fence("CLI_EXIT_UNCONFIRMED")
                process.terminate()
                try:
                    process.wait(timeout=self.budget.reap_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
            try:
                process.wait(timeout=self.budget.reap_seconds)
                cli_reaped, cli_returncode = True, process.returncode
            except subprocess.TimeoutExpired:
                cli_reaped, cli_returncode = False, None
                self._status = "CLI_REAP_UNCONFIRMED"
                self.fence("CLI_REAP_UNCONFIRMED")
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
            with self._lock:
                self._cli_reaped, self._returncode = cli_reaped, cli_returncode
                self._run_finished = True
                self._collect_completed()
                self._event("trusted_host", "cli_exit", {"reaped": self._cli_reaped, "returncode": self._returncode,
                    "workload_quiescence": "NOT_ESTABLISHED"})
        return subprocess.CompletedProcess(process.args, self._returncode, self._stdout, self._stderr)
