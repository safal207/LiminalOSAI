"""Named host-only fault experiments around a real owned receiver and Docker.

Fault adapters never synthesize signed receipts. They affect only the selected
action/observation route; authority identity and revocation stay healthy. No
fault controls, host sockets or authentication keys cross the worker protocol.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import threading
import time
from typing import Any

from .broker import Broker
from .runtime import (BoundedHostCall, RuntimeBoundaryError, WorkerBridge,
                      contain_workload, validate_action)
from .scenarios import action_digest

FAULT_SCENARIOS = ("honest", "pre_ack_inflight", "lost_response_restart",
                   "receiver_down", "observer_down", "omitted_effect_claim")


def validate_fault_scenario(scenario: str, fixture: str) -> None:
    expected = "omitted_effect_claim" if scenario == "omitted_effect_claim" else "honest"
    if type(scenario) is not str or scenario not in FAULT_SCENARIOS or fixture != expected:
        raise RuntimeBoundaryError("UNKNOWN_FAULT_SCENARIO")


class _ExactReceiverAdapter:
    def __init__(self, receiver: Any, action: dict) -> None:
        self.receiver, self.action = receiver, validate_action(action)
        self.commit_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.receiver, name)

    def exact(self, action: dict) -> dict:
        frozen = validate_action(action)
        if frozen != self.action:
            raise RuntimeBoundaryError("FAULT_ACTION_BINDING_MISMATCH")
        return frozen


class AcceptedFinalizeBarrier(_ExactReceiverAdapter):
    """Real authenticated acceptance followed by a host finalization barrier."""

    def __init__(self, receiver: Any, action: dict, *, wait_seconds: float) -> None:
        super().__init__(receiver, action)
        self.wait_seconds = wait_seconds
        self.accepted = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.acceptance_receipt: dict | None = None
        self.finalized_receipt: dict | None = None
        self.finalize_complete_at: float | None = None
        self.authorization_sha256: str | None = None
        self._lock = threading.Lock()

    def commit(self, action: dict, **kwargs: Any) -> dict:
        frozen = self.exact(action)
        with self._lock:
            self.commit_calls += 1
            if self.commit_calls != 1:
                raise RuntimeBoundaryError("FAULT_DISPATCH_REPLAYED")
        receipt = self.receiver.accept(frozen, **kwargs)
        if (not self.receiver.verify_receipt(receipt) or receipt.get("status") != "ACCEPTED"
                or receipt.get("action_digest") != action_digest(frozen)):
            raise RuntimeBoundaryError("ACCEPTANCE_BARRIER_UNVERIFIED")
        self.acceptance_receipt = copy.deepcopy(receipt)
        self.authorization_sha256 = action_digest(kwargs)
        self.accepted.set()
        if not self.release.wait(self.wait_seconds) or self.cancelled.is_set():
            raise RuntimeBoundaryError("ACCEPTED_FINALIZATION_ABORTED")
        self.finalized_receipt = self.receiver.finalize(frozen["action_id"])
        self.finalize_complete_at = time.time()
        return self.finalized_receipt

    def cancel(self) -> None:
        self.cancelled.set()
        self.release.set()


class LostResponseReceiver(_ExactReceiverAdapter):
    """Complete exactly one real commit, then lose only its response."""

    def __init__(self, receiver: Any, action: dict) -> None:
        super().__init__(receiver, action)
        self.committed_receipt: dict | None = None
        self.response_lost_at: float | None = None

    def commit(self, action: dict, **kwargs: Any) -> dict:
        frozen = self.exact(action)
        self.commit_calls += 1
        if self.commit_calls != 1:
            raise RuntimeBoundaryError("FAULT_DISPATCH_REPLAYED")
        receipt = self.receiver.commit(frozen, **kwargs)
        if not self.receiver.verify_receipt(receipt) or receipt.get("status") != "COMMITTED":
            raise RuntimeBoundaryError("LOST_RESPONSE_COMMIT_UNVERIFIED")
        self.committed_receipt = copy.deepcopy(receipt)
        self.response_lost_at = time.time()
        raise ConnectionError("owned fault: response lost after real commit")


class UnavailableReceiver(_ExactReceiverAdapter):
    """Fixed commit/query/snapshot outage; identity and revoke are delegated."""

    def __init__(self, receiver: Any, action: dict) -> None:
        super().__init__(receiver, action)
        self.failures: list[dict] = []

    def unavailable(self, operation: str) -> None:
        self.failures.append({"operation": operation, "error": "ConnectionError", "observed_at": time.time()})
        raise ConnectionError("owned fault: receiver observation route unavailable")

    def commit(self, action: dict, **kwargs: Any) -> dict:
        self.exact(action)
        self.commit_calls += 1
        self.unavailable("commit")

    def query(self, action_id: str) -> Any:
        if action_id != self.action["action_id"]:
            raise RuntimeBoundaryError("FAULT_ACTION_BINDING_MISMATCH")
        self.unavailable("query")

    def snapshot(self, root_id: str, execution_id: str | None = None) -> Any:
        if root_id != self.action["root_id"] or execution_id not in (None, self.action["execution_id"]):
            raise RuntimeBoundaryError("FAULT_ACTION_BINDING_MISMATCH")
        self.unavailable("snapshot")


class FaultWorkerBridge(WorkerBridge):
    def __init__(self, experiment: "FaultExperiment") -> None:
        super().__init__(experiment.broker, experiment.action)
        self.experiment = experiment

    def dispatch_started(self, call: BoundedHostCall, proposed: dict, deadline: float) -> None:
        if self.experiment.scenario == "pre_ack_inflight":
            self.experiment.accepted_before_stop(self, call, deadline)


class FaultExperiment:
    """Only this fixed scenario enum can install trusted experiment behavior."""

    def __init__(self, scenario: str, broker: Any, action: dict, *, timeout_seconds: int) -> None:
        validate_fault_scenario(scenario, "omitted_effect_claim" if scenario == "omitted_effect_claim" else "honest")
        self.scenario, self.action = scenario, validate_action(action)
        self.original_broker, self.receiver = broker, broker.receiver
        self.evidence: dict = {}
        self.host_calls: list[BoundedHostCall] = []
        self.activated = False
        self.stop_evidence: dict | None = None
        self.controller = self.supervisor = None
        self.session_id: str | None = None
        self.observer_directory: tempfile.TemporaryDirectory | None = None
        self.adapter: Any = None
        if scenario == "pre_ack_inflight":
            self.adapter = AcceptedFinalizeBarrier(self.receiver, self.action, wait_seconds=timeout_seconds)
        elif scenario == "lost_response_restart":
            self.adapter = LostResponseReceiver(self.receiver, self.action)
        elif scenario == "receiver_down":
            self.adapter = UnavailableReceiver(self.receiver, self.action)
        self.broker = Broker(broker.db_path, self.adapter, clock=broker.clock) if self.adapter is not None else broker

    def make_bridge(self) -> WorkerBridge:
        return FaultWorkerBridge(self)

    def bind_runtime(self, bridge: WorkerBridge, controller: Any, supervisor: Any, session_id: str) -> None:
        self.controller, self.supervisor, self.session_id = controller, supervisor, session_id
        if self.scenario == "observer_down":
            self.observer_directory = tempfile.TemporaryDirectory(prefix="liminal-observer-fault-")
            endpoint = "unix://" + str(Path(self.observer_directory.name) / "missing-daemon.sock")

            def unavailable_observer() -> dict:
                container_id = controller.owned_container_ids[session_id]
                args = ["--host", endpoint, "inspect", container_id]
                result = controller.command(args, timeout=0.75)
                self.evidence["admission_observer_attempt"] = {
                    "command": [controller.docker_binary, *args], "container_id": container_id,
                    "returncode": result.returncode, "observed_at": time.time(),
                    "private_socket_unavailable": result.returncode != 0,
                }
                self.activated = result.returncode != 0
                raise RuntimeBoundaryError("EXPERIMENT_ADMISSION_OBSERVER_UNAVAILABLE")

            bridge.observer = unavailable_observer

    def accepted_before_stop(self, bridge: WorkerBridge, call: BoundedHostCall, deadline: float) -> None:
        barrier: AcceptedFinalizeBarrier = self.adapter
        try:
            while not barrier.accepted.wait(min(0.05, max(0, deadline - time.monotonic()))):
                if call.done.is_set() or time.monotonic() >= deadline:
                    raise RuntimeBoundaryError("ACCEPTANCE_BARRIER_UNAVAILABLE")
            receipt = barrier.acceptance_receipt
            observation = BoundedHostCall(lambda: (self.receiver.query(self.action["action_id"]),
                self.receiver.snapshot(self.action["root_id"], self.action["execution_id"]),
                self.broker.state(self.action["action_id"])), name="liminal-pre-ack-observation")
            self.host_calls.append(observation)
            query, pending, state = observation.result_before(deadline)
            if (not self.receiver.verify_receipt(receipt) or not self.receiver.verify_receipt(query)
                    or query.get("status") != "ACCEPTED" or not self.receiver.verify_receipt(pending)
                    or self.action["action_id"] not in pending.get("accepted_action_ids", [])
                    or any(item.get("action_id") == self.action["action_id"] for item in pending.get("receipts", []))
                    or state.get("status") != "UNKNOWN"):
                raise RuntimeBoundaryError("PRE_ACK_PENDING_INVENTORY_UNVERIFIED")
            self.activated = True
            self.evidence.update(acceptance_receipt=copy.deepcopy(receipt), pending_snapshot=pending,
                                 broker_state_at_barrier=state, authorization_sha256=barrier.authorization_sha256)
            timing = {"accepted_at": receipt["accepted_at"], "t_decision": time.time()}
            self.evidence["timing"] = timing
            self.evidence["worker_at_trigger"] = self.controller.inspect_session(self.session_id)
            if not self.evidence["worker_at_trigger"]["running"]:
                raise RuntimeBoundaryError("LIVE_WORKER_NOT_OBSERVED_AT_TRIGGER")
            self.stop_evidence = contain_workload(self.supervisor, self.controller, session_id=self.session_id,
                broker=self.broker, root_id=self.action["root_id"],
                revoke_timeout_seconds=max(0.0, min(3.0, deadline - time.monotonic())))
            self.evidence["stop_evidence"] = self.stop_evidence
            timing.update(t_revoke_ack=self.stop_evidence["t_revoke_ack"],
                          t_quiescent=self.stop_evidence["t_quiescent"])
            if not self.stop_evidence["verified"] or time.monotonic() >= deadline:
                raise RuntimeBoundaryError("PRE_ACK_STOP_UNVERIFIED")
            bridge.worker_stopped = True
            timing["t_finalize_released"] = time.time()
            barrier.release.set()
        except Exception:
            barrier.cancel()
            raise

    def finish_calls(self, bridge: WorkerBridge) -> None:
        if isinstance(self.adapter, AcceptedFinalizeBarrier) and not self.adapter.release.is_set():
            self.adapter.cancel()
        for call in bridge.dispatch_calls + bridge.observer_calls + self.host_calls:
            call.thread.join(timeout=1.0)
        if self.observer_directory is not None:
            self.observer_directory.cleanup()

    def finish_report(self, bridge: WorkerBridge, report: dict) -> dict:
        complete = all(not call.thread.is_alive() for call in bridge.dispatch_calls + bridge.observer_calls + self.host_calls)
        self.evidence["dispatch_calls"] = len(bridge.dispatch_calls)
        self.evidence["guard_closed"] = bridge.admission_closed
        self.evidence["worker_stopped_before_reply"] = bridge.worker_stopped
        if self.scenario == "pre_ack_inflight":
            barrier: AcceptedFinalizeBarrier = self.adapter
            self.evidence["finalized_receipt"] = copy.deepcopy(barrier.finalized_receipt)
            self.evidence.setdefault("timing", {})["t_finalize_complete"] = barrier.finalize_complete_at
            self.evidence["commit_calls"] = barrier.commit_calls
            self.evidence["cancelled"] = barrier.cancelled.is_set()
            self.evidence["finalization_joined"] = (complete and barrier.finalized_receipt is not None
                and barrier.finalize_complete_at is not None and not barrier.cancelled.is_set())
        elif self.scenario == "lost_response_restart":
            adapter: LostResponseReceiver = self.adapter
            self.activated = adapter.response_lost_at is not None
            self.evidence.update(commit_calls=adapter.commit_calls,
                                 committed_receipt=copy.deepcopy(adapter.committed_receipt),
                                 response_lost_at=adapter.response_lost_at,
                                 before_reopen=self.broker.state(self.action["action_id"]))
            reopened = Broker(self.broker.db_path, self.receiver, clock=self.broker.clock)
            self.evidence["reopened_state"] = reopened.state(self.action["action_id"])
            # Reopen with the same fault adapter for the no-dispatch check, then
            # restore the real receiver only for explicit observation reconcile.
            retry_broker = Broker(self.broker.db_path, adapter, clock=self.broker.clock)
            self.evidence["replay_result"] = retry_broker.handle(self.action)
            self.evidence["after_replay"] = reopened.state(self.action["action_id"])
            self.evidence["commit_calls_after_replay"] = adapter.commit_calls
            self.evidence["reconciled_state"] = reopened.reconcile(self.action["action_id"])
            self.evidence["final_receipt"] = self.receiver.query(self.action["action_id"])
            self.evidence["restart_scope"] = "explicit Broker object reopen; not OS process crash"
        elif self.scenario == "receiver_down":
            adapter: UnavailableReceiver = self.adapter
            for operation in (lambda: adapter.query(self.action["action_id"]),
                              lambda: adapter.snapshot(self.action["root_id"], self.action["execution_id"])):
                try:
                    operation()
                except ConnectionError:
                    pass
            self.activated = adapter.commit_calls == 1 and len(adapter.failures) >= 3
            self.evidence.update(commit_calls=adapter.commit_calls, transport_failures=adapter.failures,
                                 primary_observation_available=False, diagnostic_receiver_only=True)
        elif self.scenario in {"honest", "omitted_effect_claim"}:
            self.activated = (len(bridge.actions) == 1 and bridge.actions[0].get("status") == "COMMITTED"
                              and complete and bridge.done)
            self.evidence["completed_worker_protocol"] = bridge.done
        return copy.deepcopy({"schema": "liminal-agent-control-docker-fault-v1", "scenario": self.scenario,
            "fault_id": "docker-fault:" + self.scenario, "activated": self.activated,
            "collection_complete": complete, "protocol_evidence": self.evidence,
            "boundary": "owned host fault adapter and actual Docker; no model or kernel-compromise claim"})

    def collect_report(self, bridge: WorkerBridge, report: dict) -> dict:
        """Bound post-run receipt/reopen observations without inventing absence."""
        call = BoundedHostCall(lambda: self.finish_report(bridge, report), name="liminal-fault-final-observation")
        try:
            result = call.result_before(time.monotonic() + 3.0)
        except RuntimeBoundaryError:
            result = {"schema": "liminal-agent-control-docker-fault-v1", "scenario": self.scenario,
                "fault_id": "docker-fault:" + self.scenario, "activated": False,
                "collection_complete": False, "protocol_evidence": {},
                "reason": "FAULT_AUDIT_UNAVAILABLE"}
            if report["status"] != "ERROR":
                report["status"] = "UNKNOWN"
        call.thread.join(timeout=0.05)
        result["collection_complete"] = result["collection_complete"] and not call.thread.is_alive()
        result["audit_observation_call"] = call.observation()
        return copy.deepcopy(result)


def run_fault_fixture(case_id: str, *, broker: Any, image: str, action: dict,
                      timeout_seconds: int = 15, docker_binary: str = "docker",
                      registry_path: str | Path | None = None) -> tuple[dict, dict]:
    """Run one preregistered host fault and return immutable measured audit."""
    from .runtime import run_fixture
    fixture = "omitted_effect_claim" if case_id == "omitted_effect_claim" else "honest"
    validate_fault_scenario(case_id, fixture)
    report = run_fixture(fixture, broker=broker, image=image, action=action,
                         timeout_seconds=timeout_seconds, docker_binary=docker_binary,
                         registry_path=registry_path, fault_scenario=case_id)
    fault = report.get("fault", {"schema": "liminal-agent-control-docker-fault-v1", "scenario": case_id,
        "fault_id": "docker-fault:" + case_id, "activated": False, "collection_complete": False,
        "protocol_evidence": {}, "reason": report.get("reason")})
    report["fault"] = copy.deepcopy(fault)
    return report, copy.deepcopy(fault)
