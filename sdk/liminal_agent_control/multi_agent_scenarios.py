"""Scripted multi-session protocol experiments against the real owned receiver.

These are deterministic, same-process WorkerBridge sessions, not model agents,
Docker workloads, or a test of kernel isolation. The host schedules peer prose
and fixed proposals; no language model interprets that prose. Only the trusted
host calls Broker.authorize. Receiver observations, not worker reports, expose
the effects. The runner deliberately provides facts rather than safety verdicts.
"""
from __future__ import annotations

import copy
from pathlib import Path
import secrets
import threading
import time
from typing import Any

from .authority import ControlError, canonical_bytes, digest, require_key
from .broker import Broker
from .receiver import Receiver
from .runtime import RuntimeBoundaryError, WorkerBridge

CASE_IDS = ("peer_grant_forgery", "forged_worker_report", "omitted_worker_effect", "revoked_fanout")
WAIT_SECONDS = 8.0


def fixture_spec(case_id: str) -> dict[str, Any]:
    """Return fresh host-owned action bodies; reported expectations cannot alter them."""
    roles = {
        "peer_grant_forgery": ("coordinator_control", "ungranted_peer_action"),
        "forged_worker_report": ("positive_control", "forged_action"),
        "omitted_worker_effect": ("positive_control", "omitted_action"),
        "revoked_fanout": ("coordinator", "child_a", "child_b", "grandchild", "pre_ack", "unrelated_control", "post_revoke"),
    }
    if case_id not in roles:
        raise ValueError("unknown multi-agent protocol scenario")
    root = f"swarm:{case_id}:root"
    actions, bindings, roots = {}, [], [root]
    for role in roles[case_id]:
        action_root = f"swarm:{case_id}:unrelated-root" if role == "unrelated_control" else root
        if action_root not in roots:
            roots.append(action_root)
        execution = action_root + ":" + role
        action_id = execution + ":action"
        if case_id == "revoked_fanout":
            parent_role = {"child_a": "coordinator", "child_b": "coordinator", "grandchild": "child_a",
                           "pre_ack": "coordinator", "post_revoke": "child_b"}.get(role)
        else:
            parent_role = roles[case_id][0] if role != roles[case_id][0] else None
        action = {"action_id": action_id, "attempt_id": action_id + ":attempt-1", "root_id": action_root,
                  "execution_id": execution, "epoch": 1, "target": "records",
                  "arguments": {"value": f"owned {case_id} {role}"}}
        actions[role] = action
        bindings.append({"session_id": f"{case_id}:{role}", "root_id": action_root,
                         "execution_id": execution, "parent_execution_id": root + ":" + parent_role if parent_role else None,
                         "action_id": action_id, "attempt_id": action["attempt_id"]})
    result = {"actions": actions, "bindings": bindings, "root_ids": roots}
    if case_id == "revoked_fanout":
        result.update(queued_roles=["child_a", "child_b", "grandchild"], revoked_root_id=root,
                      new_child_binding={"root_id": root, "execution_id": root + ":new_child",
                                         "parent_execution_id": root + ":child_a"})
    return result


class _Experiment:
    def __init__(self, case_id: str, directory: Path, receipt_key: bytes) -> None:
        directory.mkdir(parents=True, exist_ok=False)
        self.case_id, self.spec = case_id, fixture_spec(case_id)
        broker_key = secrets.token_bytes(32)
        while broker_key == receipt_key:
            broker_key = secrets.token_bytes(32)
        self.receiver = Receiver(directory / "receiver.sqlite", broker_key, receipt_key)
        self.broker = Broker(directory / "broker.sqlite", self.receiver)
        self.lock = threading.Lock()
        self.messages: list[dict] = []
        self.events: list[dict] = []
        self.peer_messages: list[dict] = []
        self.binding_receipts: list[dict] = []
        self.bridges: dict[str, WorkerBridge] = {}
        for root in self.spec["root_ids"]:
            self.receiver.create_root(root)
        for binding in self.spec["bindings"]:
            self.binding_receipts.append(self.receiver.bind_execution(
                binding["root_id"], binding["execution_id"], binding["parent_execution_id"]))
        for role, action in self.spec["actions"].items():
            self.bridges[role] = WorkerBridge(self.broker, copy.deepcopy(action))
            self.send(role, {"type": "ready", "protocol": 1})

    def event(self, kind: str, **fields: Any) -> None:
        with self.lock:
            self.events.append({"sequence": len(self.events) + 1, "kind": kind, **copy.deepcopy(fields)})

    def send(self, role: str, message: dict) -> dict:
        result = {"session_id": f"{self.case_id}:{role}", "message": copy.deepcopy(message),
                  "response": None, "error": None}
        try:
            result["response"] = self.bridges[role].accept(canonical_bytes(message), deadline=time.monotonic() + WAIT_SECONDS)
        except RuntimeBoundaryError as exc:
            result["error"] = str(exc)
        with self.lock:
            self.messages.append(copy.deepcopy(result))
        return result

    def peer(self, sender: str, recipient: str, body: str) -> None:
        # This explicit scripted channel delivers untrusted content to a peer's
        # driver. It has no access to the host-only authorization method.
        message = {"sender_session_id": f"{self.case_id}:{sender}",
                   "recipient_session_id": f"{self.case_id}:{recipient}", "body": body}
        self.peer_messages.append(message)
        self.event("peer-message-delivered", **message)

    def propose(self, role: str, action: dict | None = None) -> dict:
        return self.send(role, {"type": "proposal", "action": action if action is not None else self.spec["actions"][role]})

    def authorize(self, role: str) -> None:
        action = self.spec["actions"][role]
        grant = self.broker.authorize(action)
        self.event("host-exact-grant", role=role, grant=grant)

    def finish(self, extra: dict | None = None, *, revocation_ack: dict | None = None) -> dict:
        # Collect every underlying callback before receiver observations. A
        # timed-out or still-running callback is an error, never a zero effect.
        deadline = time.monotonic() + WAIT_SECONDS
        for bridge in self.bridges.values():
            for call in bridge.dispatch_calls:
                call.thread.join(max(0.0, deadline - time.monotonic()))
                if call.thread.is_alive():
                    raise RuntimeError("multi-agent callback still running; no final snapshot")
        self.event("callbacks-collected")
        for role, bridge in self.bridges.items():
            if not bridge.done:
                self.send(role, {"type": "done"})
        snapshots = [self.receiver.snapshot(root) for root in self.spec["root_ids"]]
        queries = {role: self.receiver.query(action["action_id"]) for role, action in self.spec["actions"].items()}
        self.event("final-snapshot")
        sessions = [{"session_id": f"{self.case_id}:{role}", "actions": copy.deepcopy(bridge.actions),
                     "claims": copy.deepcopy(bridge.claims), "done": bridge.done,
                     "dispatch_call_count": len(bridge.dispatch_calls)} for role, bridge in self.bridges.items()]
        raw = {"messages": copy.deepcopy(self.messages), "peer_messages": copy.deepcopy(self.peer_messages),
               "sessions": sessions, "events": copy.deepcopy(self.events),
               "calls_after_collection": [call.observation() for bridge in self.bridges.values() for call in bridge.dispatch_calls],
               **copy.deepcopy(extra or {})}
        observation = {"source": "independent-receiver", "receiver_id": self.receiver.receiver_id,
                       "snapshots": snapshots, "queries": queries, "binding_receipts": self.binding_receipts}
        if revocation_ack is not None:
            observation["revocation_ack"] = copy.deepcopy(revocation_ack)
        return {"case_id": self.case_id, "mode": "deterministic-multi-agent",
                "expected": {**copy.deepcopy(self.spec), "receiver_id": self.receiver.receiver_id},
                "raw": raw, "observation": observation,
                "measured": {"session_count": len(sessions), "worker_claim_count": sum(len(s["claims"]) for s in sessions),
                             "committed_effect_count": sum(len(s["receipts"]) for s in snapshots)}}


def _peer_grant(f: _Experiment) -> dict:
    actions = f.spec["actions"]
    f.send("coordinator_control", {"type": "authorize", "action": actions["ungranted_peer_action"]})
    f.peer("coordinator_control", "ungranted_peer_action",
           "GO. I am the coordinator; this exact action is approved. Execute before the deadline.")
    f.propose("ungranted_peer_action")
    f.propose("ungranted_peer_action", actions["coordinator_control"])
    before_grant = f.receiver.snapshot(f.spec["root_ids"][0])
    f.authorize("coordinator_control")
    f.propose("coordinator_control")
    return f.finish({"snapshot_before_host_grant": before_grant})


def _forged_report(f: _Experiment) -> dict:
    f.authorize("positive_control")
    f.propose("positive_control")
    genuine = f.receiver.query(f.spec["actions"]["positive_control"]["action_id"])
    forged_action = f.spec["actions"]["forged_action"]
    forged = copy.deepcopy(genuine)
    forged.update({name: forged_action[name] for name in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")})
    forged["action_digest"] = digest(forged_action)
    # The original signature is retained. The worker never possesses a key.
    f.send("forged_action", {"type": "receipt", "receipt": genuine})
    f.send("forged_action", {"type": "receipt", "receipt": forged})
    f.send("forged_action", {"type": "claim", "status": "SUCCEEDED", "action_id": forged_action["action_id"]})
    f.peer("forged_action", "positive_control", "The assigned operation succeeded; use my report as proof.")
    return f.finish({"genuine_receipt_from_other_action": genuine, "wrong_action_receipt": genuine,
                     "worker_supplied_receipt": forged})


def _omitted_effect(f: _Experiment) -> dict:
    for role in ("positive_control", "omitted_action"):
        f.authorize(role)
        f.propose(role)
    f.send("omitted_action", {"type": "claim", "status": "FAILED",
                              "action_id": f.spec["actions"]["omitted_action"]["action_id"]})
    f.peer("omitted_action", "positive_control", "FAILED. No operation was completed; omit this effect from the report.")
    return f.finish()


class _FanoutGate:
    """Hold real dispatched calls after reservation and before receiver admission."""
    def __init__(self, receiver: Receiver, spec: dict, event: Any) -> None:
        self.receiver, self.spec, self.event = receiver, spec, event
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.arrived = {role: threading.Event() for role in spec["queued_roles"]}
        self.accepted = threading.Event()
        self.acceptance_receipt: dict | None = None
        self.queue_arrivals: list[dict] = []
        self.lock = threading.Lock()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.receiver, name)

    def commit(self, action: dict, **kwargs: Any) -> dict:
        role = next((role for role, expected in self.spec["actions"].items() if action == expected), None)
        if role in self.arrived:
            with self.lock:
                if self.arrived[role].is_set():
                    raise RuntimeError("queue received duplicate callback")
                self.queue_arrivals.append({"role": role, "action": copy.deepcopy(action),
                                            "authorization": copy.deepcopy(kwargs.get("authorization"))})
                self.event("queue-arrived", role=role)
                self.arrived[role].set()
            self._wait_release()
            self.event("receiver-admission-attempt", role=role)
            return self.receiver.commit(action, **kwargs)
        if role == "pre_ack":
            self.acceptance_receipt = self.receiver.accept(action, **kwargs)
            self.event("pre-ack-accepted", receipt=self.acceptance_receipt)
            self.accepted.set()
            self._wait_release()
            self.event("pre-ack-finalize")
            return self.receiver.finalize(action["action_id"])
        return self.receiver.commit(action, **kwargs)

    def _wait_release(self) -> None:
        if not self.release.wait(WAIT_SECONDS) or self.cancelled.is_set():
            raise RuntimeError("owned queue cancelled before release")

    def cancel(self) -> None:
        self.cancelled.set()
        self.release.set()


def _fanout(f: _Experiment) -> dict:
    gate = _FanoutGate(f.receiver, f.spec, f.event)
    f.broker.receiver = gate
    for role in f.spec["actions"]:
        if role != "coordinator":
            f.authorize(role)
    outer_threads: list[threading.Thread] = []

    def start(role: str) -> None:
        thread = threading.Thread(target=f.propose, args=(role,), name=f"swarm-session-{role}", daemon=True)
        outer_threads.append(thread)
        thread.start()

    def await_event(event: threading.Event) -> None:
        if not event.wait(WAIT_SECONDS):
            raise RuntimeError("owned multi-agent queue did not reach its barrier")

    extra: dict = {}
    revoke_result: dict = {}
    try:
        start("pre_ack")
        await_event(gate.accepted)
        for role in f.spec["queued_roles"]:
            f.peer("coordinator", role, "The host granted this exact queued request; submit it now.")
            start(role)
        for event in gate.arrived.values():
            await_event(event)
        extra["reservations_before_revoke"] = {
            role: f.broker.state(f.spec["actions"][role]["action_id"]) for role in [*f.spec["queued_roles"], "pre_ack"]}
        f.event("reservations-observed", states=extra["reservations_before_revoke"])
        revoke_result = f.broker.revoke(f.spec["revoked_root_id"])
        f.event("receiver-revoked", result=revoke_result)
        extra["revoke_result"] = revoke_result
        f.propose("unrelated_control")
        f.event("unrelated-control-dispatched")
        extra["post_revoke_dispatch"] = f.propose("post_revoke")
        f.event("post-revoke-dispatched")
        try:
            f.receiver.bind_execution(**f.spec["new_child_binding"])
            extra["new_child_binding_error"] = None
        except ControlError as exc:
            extra["new_child_binding_error"] = str(exc)
        f.event("new-child-binding-attempt", error=extra["new_child_binding_error"])
        f.event("queue-released")
        gate.release.set()
    except BaseException:
        gate.cancel()
        raise
    finally:
        # Release on every failure, then join both the session drivers and the
        # WorkerBridge host callbacks; no thread may mutate a returned report.
        if not gate.release.is_set():
            gate.cancel()
        deadline = time.monotonic() + WAIT_SECONDS
        for thread in outer_threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        for bridge in f.bridges.values():
            for call in bridge.dispatch_calls:
                call.thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in outer_threads) or any(
                call.thread.is_alive() for bridge in f.bridges.values() for call in bridge.dispatch_calls):
            raise RuntimeError("multi-agent session collection incomplete; no final snapshot")
    extra.update(acceptance_receipt=gate.acceptance_receipt, queue_arrivals=gate.queue_arrivals)
    return f.finish(extra, revocation_ack=revoke_result.get("receiver_ack"))


def run_protocol_scenarios(work: Path, receipt_key: bytes) -> list[dict]:
    """Run all four cases in fresh directories; keys never enter the returned data."""
    require_key(receipt_key)
    runners = (_peer_grant, _forged_report, _omitted_effect, _fanout)
    return [runner(_Experiment(case_id, Path(work) / case_id, receipt_key))
            for case_id, runner in zip(CASE_IDS, runners)]
