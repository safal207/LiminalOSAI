from __future__ import annotations

import hashlib
import threading
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_effect_commit import (
    AUTHORITY,
    CausalBoundEffectCommitBroker,
    CausalBoundEffectRuntimeMediator,
    CausalEffectCommitError,
    FencedTrajectoryRiskLedger,
    build_effect_trajectory_event,
    verify_authorization_receipt,
    verify_commit_receipt,
)
from sdk.liminal_causal_escalation import TrajectoryEvent
from sdk.liminal_effect_commit import EffectCommitBroker, RuntimeCommitFence, build_session_document
from sdk.liminal_epoch_bound_capability import EpochBoundCapabilityBroker, EpochBoundCapabilityContract
from sdk.liminal_objective_effect_commit import FencedObjectiveIntegrityGuard, ObjectiveBoundEffectCommitBroker
from sdk.liminal_objective_integrity import ObjectiveMethodPolicy
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeOperation

POLICY = "a" * 64
OBJECTIVE = "b" * 64
STATE0 = "1" * 64
HOST = "2" * 64
SESSION0 = "3" * 64
NOW = 2_200_000_000
ADAPTER_TOKEN = "trusted-causal-effect-adapter"
ADAPTER_SHA = hashlib.sha256(ADAPTER_TOKEN.encode("utf-8")).hexdigest()


class MutableClock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class FakeRuntimeProvider:
    def __init__(self):
        self.epoch = 0
        self.state = STATE0
        self.tainted = False

    def state_document(self):
        return {"epoch": self.epoch, "state_sha256": self.state, "tainted": self.tainted}


class FakeSessionProvider:
    def __init__(self):
        self.session = SESSION0
        self.active = True

    def session_document(self, operation_id):
        return build_session_document(
            operation_id=operation_id,
            session_sha256=self.session,
            host_binding_sha256=HOST,
            active=self.active,
        )


def method_policy():
    return ObjectiveMethodPolicy.build(
        objective_id="objective:causal-effect:test",
        objective_sha256=OBJECTIVE,
        method_policy_id="method-policy:causal-effect:v1",
        governance_policy_sha256=POLICY,
        allowed_runtime_kinds=("process.execute",),
    )


def process_operation(operation_id="op:causal-effect", *, at=NOW + 1, payload="4" * 64):
    return RuntimeOperation(
        operation_id=operation_id,
        subject_id="agent:test",
        policy_sha256=POLICY,
        kind="process.execute",
        scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        payload_sha256=payload,
        at_unix=at,
    )


def spawn_operation(operation_id="op:spawn-risk", *, at=NOW + 20):
    return RuntimeOperation(
        operation_id=operation_id,
        subject_id="agent:test",
        policy_sha256=POLICY,
        kind="process.spawn_child",
        scope={"executables": ["/usr/local/bin/worker"], "max_children": 1},
        payload_sha256="8" * 64,
        at_unix=at,
    )


def base_capability():
    return CapabilityContract.build(
        capability_id="cap:causal-effect:1",
        capability_type="process.execute",
        subject_id="agent:test",
        issuer_id="issuer:test",
        scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        max_uses=20,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )


def setup_stack(*, verifier=None):
    fence = RuntimeCommitFence()
    runtime = FakeRuntimeProvider()
    sessions = FakeSessionProvider()
    delegate = CapabilityBroker("broker:causal-effect:delegate")
    epoch = EpochBoundCapabilityBroker(
        runtime_provider=runtime,
        delegate=delegate,
        broker_id="broker:causal-effect:epoch",
    )
    bound = EpochBoundCapabilityContract.build(
        base_capability=base_capability().as_document(),
        runtime_epoch=runtime.epoch,
        runtime_state_sha256=runtime.state,
    )
    assert epoch.admit(bound.as_document(), at_unix=NOW)["decision"] == "ALLOW"
    clock = MutableClock()
    effect = EffectCommitBroker(
        runtime_provider=runtime,
        session_provider=sessions,
        capability_broker=epoch,
        host_binding_sha256=HOST,
        adapter_token_sha256=ADAPTER_SHA,
        commit_fence=fence,
        lease_ttl_seconds=5,
        clock=clock,
    )
    guard = FencedObjectiveIntegrityGuard(
        commit_fence=fence,
        policy=method_policy(),
    )
    objective = ObjectiveBoundEffectCommitBroker(
        guard=guard,
        delegate=effect,
        commit_fence=fence,
        clock=clock,
    )
    ledger = FencedTrajectoryRiskLedger(
        commit_fence=fence,
        verify_event=verifier or (lambda _: True),
    )
    causal = CausalBoundEffectCommitBroker(
        ledger=ledger,
        delegate=objective,
        commit_fence=fence,
        clock=clock,
    )
    return fence, runtime, sessions, delegate, epoch, effect, guard, objective, ledger, causal, clock


def authorize(epoch, op):
    return epoch.authorize(
        subject_id=op.subject_id,
        capability_type="process.execute",
        policy_sha256=op.policy_sha256,
        requested_scope=op.normalized_scope(),
        action={
            "operation_id": op.operation_id,
            "runtime_kind": op.kind,
            "scope_sha256": canonical_sha256(op.normalized_scope()),
            "payload_sha256": op.payload_sha256,
        },
        at_unix=op.at_unix,
    )


def proposal(ledger, op, cap, *, event_id=None):
    state = ledger.state_document()
    return build_effect_trajectory_event(
        operation=op,
        capability_decision=cap,
        sequence=state["event_count"] + 1,
        previous_event_sha256=state["trajectory_head_sha256"],
        event_id=event_id,
    )


def seed_event(*, event_id, sequence, previous, kind, at, capability_id=None):
    item = TrajectoryEvent.build(
        event_id=event_id,
        sequence=sequence,
        observed_at_unix=at,
        kind=kind,
        decision="ALLOW",
        subject_id="agent:test",
        capability_id=capability_id,
        privilege_level_before=0,
        privilege_level_after=0,
        metadata={"seed": event_id},
        previous_event_sha256=previous,
    )
    return item.body() | {"event_sha256": item.event_sha256}


class CausalBoundEffectCommitTests(unittest.TestCase):
    def test_authority_only_restricts_existing_controls(self):
        self.assertTrue(AUTHORITY["trajectory_head_binding"])
        self.assertTrue(AUTHORITY["projected_trajectory_gate"])
        self.assertTrue(AUTHORITY["shared_causal_effect_fence"])
        self.assertTrue(AUTHORITY["objective_bound_inner_effect_required"])
        self.assertTrue(AUTHORITY["trusted_event_verification_required"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["network_authority"])
        self.assertFalse(AUTHORITY["containment_execution"])
        self.assertFalse(AUTHORITY["kernel_enforcement"])

    def test_clean_commit_binds_projection_and_appends_exact_event(self):
        _, _, _, _, epoch, _, guard, objective, ledger, causal, _ = setup_stack()
        op = process_operation()
        gate = guard.evaluate_operation(op)
        cap = authorize(epoch, op)
        proposed = proposal(ledger, op, cap)
        lease_id, auth = causal.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=gate,
            proposed_event=proposed,
        )
        self.assertEqual(verify_authorization_receipt(auth), auth)
        self.assertEqual(auth["trajectory_decision"], "ALLOW")
        self.assertEqual(auth["projected_decision"], "ALLOW")
        called = []
        result = causal.consume_for_trusted_adapter(
            lease_id,
            adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"bounded": True}),
        )
        self.assertEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(called, [True])
        self.assertEqual(ledger.head_sha256, proposed["event_sha256"])
        self.assertEqual(ledger.event_count, 1)
        receipt = causal.commit_receipts()[-1]
        self.assertEqual(verify_commit_receipt(receipt), receipt)
        self.assertEqual(receipt["effect_outcome"], "SUCCEEDED")
        self.assertEqual(receipt["trajectory_head_after_sha256"], proposed["event_sha256"])
        self.assertNotEqual(receipt["objective_commit_receipt_sha256"], "0" * 64)
        self.assertEqual(len(objective.commit_receipts()), 1)

    def test_new_benign_event_after_issue_invalidates_old_lease(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        op = process_operation()
        cap = authorize(epoch, op)
        lease_id, _ = causal.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=guard.evaluate_operation(op),
            proposed_event=proposal(ledger, op, cap),
        )
        benign = seed_event(
            event_id="seed:repo-write",
            sequence=1,
            previous="0" * 64,
            kind="repository.write",
            at=NOW + 2,
        )
        accepted = ledger.append_verified_event(benign)
        self.assertEqual(accepted["trajectory_decision"], "ALLOW")
        called = []
        with self.assertRaisesRegex(CausalEffectCommitError, "stale_trajectory_head"):
            causal.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(True) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [])
        self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "NOT_EXECUTED")
        with self.assertRaisesRegex(CausalEffectCommitError, "causal_lease_replayed"):
            causal.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_projected_composition_blocks_effect_that_would_raise_risk(self):
        _, _, _, _, _, _, _, _, ledger, causal, _ = setup_stack()
        credential = seed_event(
            event_id="seed:credential",
            sequence=1,
            previous="0" * 64,
            kind="credential.access",
            at=NOW + 1,
            capability_id="cap:credential:seed",
        )
        ledger.append_verified_event(credential)
        self.assertEqual(ledger.state_document()["decision"], "ALLOW")

        op = spawn_operation()
        fake_cap = {
            "decision": "ALLOW",
            "capability_id": "cap:spawn:fake",
            "receipt_sha256": "9" * 64,
        }
        projected = build_effect_trajectory_event(
            operation=op,
            capability_decision=fake_cap,
            sequence=2,
            previous_event_sha256=ledger.head_sha256,
        )
        projection = ledger.project_verified_event(projected)
        self.assertEqual(projection["projected_decision"], "REVISE")
        with self.assertRaisesRegex(CausalEffectCommitError, "projected_trajectory_not_allow"):
            causal.issue_for_trusted_adapter(
                operation=op,
                capability_decision=fake_cap,
                objective_decision={"unused": True},
                proposed_event=projected,
            )

    def test_proposal_action_binding_tamper_is_rejected(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        op = process_operation()
        cap = authorize(epoch, op)
        proposed = proposal(ledger, op, cap)
        tampered = dict(proposed)
        tampered["metadata_sha256"] = "f" * 64
        tampered["event_sha256"] = canonical_sha256({k: v for k, v in tampered.items() if k != "event_sha256"})
        with self.assertRaisesRegex(CausalEffectCommitError, "proposal_action_binding_mismatch"):
            causal.issue_for_trusted_adapter(
                operation=op,
                capability_decision=cap,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=tampered,
            )

    def test_trusted_event_verifier_is_required_for_projection(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack(verifier=lambda _: False)
        op = process_operation()
        cap = authorize(epoch, op)
        with self.assertRaisesRegex(CausalEffectCommitError, "trusted_event_verification_failed"):
            causal.issue_for_trusted_adapter(
                operation=op,
                capability_decision=cap,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=proposal(ledger, op, cap),
            )

    def test_outer_replay_is_blocked_without_second_effect(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        op = process_operation()
        cap = authorize(epoch, op)
        lease_id, _ = causal.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=guard.evaluate_operation(op),
            proposed_event=proposal(ledger, op, cap),
        )
        called = []
        causal.consume_for_trusted_adapter(
            lease_id,
            adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
        )
        with self.assertRaisesRegex(CausalEffectCommitError, "causal_lease_replayed"):
            causal.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(False) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [True])

    def test_inner_callback_failure_burns_causal_lease_without_advancing_head(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        op = process_operation()
        cap = authorize(epoch, op)
        lease_id, _ = causal.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=guard.evaluate_operation(op),
            proposed_event=proposal(ledger, op, cap),
        )
        with self.assertRaisesRegex(CausalEffectCommitError, "objective_bound_effect_failed"):
            causal.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: (_ for _ in ()).throw(RuntimeError("sensitive host detail")),
            )
        self.assertEqual(ledger.event_count, 0)
        receipt = causal.commit_receipts()[-1]
        self.assertEqual(receipt["effect_outcome"], "FAILED")
        self.assertNotIn("sensitive host detail", repr(receipt))

    def test_shared_fence_prevents_trajectory_append_between_final_check_and_effect(self):
        fence, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        op = process_operation()
        cap = authorize(epoch, op)
        lease_id, _ = causal.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=guard.evaluate_operation(op),
            proposed_event=proposal(ledger, op, cap),
        )
        effect_entered = threading.Event()
        release_effect = threading.Event()
        append_done = threading.Event()
        errors = []

        def effect(_):
            effect_entered.set()
            if not release_effect.wait(2):
                raise RuntimeError("test release timeout")
            return ExecutionObservation.success({"head": ledger.head_sha256})

        def run_effect():
            try:
                causal.consume_for_trusted_adapter(
                    lease_id,
                    adapter_token=ADAPTER_TOKEN,
                    executor=effect,
                )
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        def append_after_fence():
            try:
                with fence.hold():
                    state = ledger.state_document()
                    event = seed_event(
                        event_id="seed:after-effect",
                        sequence=state["event_count"] + 1,
                        previous=state["trajectory_head_sha256"],
                        kind="repository.write",
                        at=NOW + 3,
                    )
                    ledger.append_verified_event(event)
                    append_done.set()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        effect_thread = threading.Thread(target=run_effect)
        append_thread = threading.Thread(target=append_after_fence)
        effect_thread.start()
        self.assertTrue(effect_entered.wait(1))
        append_thread.start()
        self.assertFalse(append_done.wait(0.05))
        release_effect.set()
        effect_thread.join(2)
        append_thread.join(2)
        self.assertEqual(errors, [])
        self.assertTrue(append_done.is_set())
        self.assertEqual(ledger.event_count, 2)
        self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "SUCCEEDED")


class CausalBoundRuntimeMediatorTests(unittest.TestCase):
    def test_clean_mediator_path_uses_projected_trajectory_and_commits_event(self):
        _, _, _, _, epoch, _, _, _, ledger, causal, _ = setup_stack()

        def factory(op, cap, causal_ledger):
            return proposal(causal_ledger, op, cap, event_id=f"proposal:{op.operation_id}")

        mediator = CausalBoundEffectRuntimeMediator(
            broker=epoch,
            causal_effect_broker=causal,
            adapter_token=ADAPTER_TOKEN,
            proposal_factory=factory,
        )
        called = []
        result = mediator.mediate(
            process_operation("op:causal-mediated"),
            lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
        )
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "SUCCEEDED")
        self.assertIn("causal_projection_allow", result["reason_codes"])
        self.assertEqual(called, [True])
        self.assertEqual(ledger.event_count, 1)


if __name__ == "__main__":
    unittest.main()
