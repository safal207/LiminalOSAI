from __future__ import annotations

import hashlib
import threading
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_effect_commit import EffectCommitBroker, RuntimeCommitFence, build_session_document
from sdk.liminal_epoch_bound_capability import EpochBoundCapabilityBroker, EpochBoundCapabilityContract
from sdk.liminal_objective_effect_commit import (
    AUTHORITY,
    FencedObjectiveIntegrityGuard,
    ObjectiveBoundEffectCommitBroker,
    ObjectiveBoundEffectRuntimeMediator,
    ObjectiveEffectCommitError,
    verify_authorization_receipt,
    verify_commit_receipt,
)
from sdk.liminal_objective_integrity import (
    ObjectiveIntegrityObservation,
    ObjectiveMethodPolicy,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeOperation

POLICY = "a" * 64
OBJECTIVE = "b" * 64
SOURCE_BINDING = "c" * 64
EVIDENCE = "d" * 64
STATE0 = "1" * 64
HOST = "2" * 64
SESSION0 = "3" * 64
NOW = 2_200_000_000
ADAPTER_TOKEN = "trusted-objective-effect-adapter"
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
        objective_id="objective:effect:test",
        objective_sha256=OBJECTIVE,
        method_policy_id="method-policy:objective-effect:v1",
        governance_policy_sha256=POLICY,
        allowed_runtime_kinds=("process.execute",),
    )


def operation(operation_id="op:objective-effect", *, at=NOW + 1, payload="4" * 64):
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


def base_capability():
    return CapabilityContract.build(
        capability_id="cap:objective-effect:1",
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
        max_uses=10,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )


def build_observation(guard, *, observation_id="obs:objective-effect:1", violation="hidden_answer_access", at=NOW + 3):
    return ObjectiveIntegrityObservation.build(
        observation_id=observation_id,
        objective_id=guard.policy.objective_id,
        method_policy_sha256=guard.policy.policy_sha256,
        source_id="detector:integrity",
        source_binding_sha256=SOURCE_BINDING,
        violation_code=violation,
        evidence_sha256=EVIDENCE,
        observed_at_unix=at,
        previous_observation_sha256=guard.observation_head_sha256,
    )


def setup_stack(*, clock=None):
    fence = RuntimeCommitFence()
    runtime = FakeRuntimeProvider()
    sessions = FakeSessionProvider()
    delegate = CapabilityBroker("broker:objective-effect:delegate")
    epoch = EpochBoundCapabilityBroker(
        runtime_provider=runtime,
        delegate=delegate,
        broker_id="broker:objective-effect:epoch",
    )
    base = base_capability()
    bound = EpochBoundCapabilityContract.build(
        base_capability=base.as_document(),
        runtime_epoch=runtime.epoch,
        runtime_state_sha256=runtime.state,
    )
    assert epoch.admit(bound.as_document(), at_unix=NOW)["decision"] == "ALLOW"
    trusted_clock = clock or MutableClock()
    inner = EffectCommitBroker(
        runtime_provider=runtime,
        session_provider=sessions,
        capability_broker=epoch,
        host_binding_sha256=HOST,
        adapter_token_sha256=ADAPTER_SHA,
        commit_fence=fence,
        lease_ttl_seconds=5,
        clock=trusted_clock,
    )
    guard = FencedObjectiveIntegrityGuard(
        commit_fence=fence,
        policy=method_policy(),
        trusted_source_bindings={"detector:integrity": SOURCE_BINDING},
        verify_observation=lambda doc: doc["source_binding_sha256"] == SOURCE_BINDING,
    )
    outer = ObjectiveBoundEffectCommitBroker(
        guard=guard,
        delegate=inner,
        commit_fence=fence,
        clock=trusted_clock,
    )
    return fence, runtime, sessions, delegate, epoch, inner, guard, outer, trusted_clock


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


class ObjectiveBoundEffectCommitTests(unittest.TestCase):
    def test_authority_only_composes_existing_controls(self):
        self.assertTrue(AUTHORITY["objective_head_binding"])
        self.assertTrue(AUTHORITY["objective_state_recheck"])
        self.assertTrue(AUTHORITY["shared_objective_runtime_fence"])
        self.assertTrue(AUTHORITY["inner_epoch_effect_lease_required"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["network_authority"])
        self.assertFalse(AUTHORITY["hidden_answer_access"])
        self.assertFalse(AUTHORITY["kernel_enforcement"])

    def test_clean_objective_and_runtime_world_commit_succeeds(self):
        _, _, _, _, epoch, inner, guard, outer, _ = setup_stack()
        op = operation()
        gate = guard.evaluate_operation(op)
        cap = authorize(epoch, op)
        lease_id, auth = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=cap,
            objective_decision=gate,
        )
        self.assertEqual(verify_authorization_receipt(auth), auth)
        self.assertEqual(auth["objective_decision"], "ALLOW")
        self.assertEqual(auth["objective_observation_head_sha256"], guard.observation_head_sha256)
        called = []
        result = outer.consume_for_trusted_adapter(
            lease_id,
            adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"bounded": True}),
        )
        self.assertEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(called, [True])
        receipt = outer.commit_receipts()[-1]
        self.assertEqual(verify_commit_receipt(receipt), receipt)
        self.assertEqual(receipt["effect_outcome"], "SUCCEEDED")
        self.assertNotEqual(receipt["inner_commit_receipt_sha256"], "0" * 64)
        self.assertEqual(len(inner.commit_receipts()), 1)

    def test_new_critical_observation_after_issue_invalidates_before_effect(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        gate = guard.evaluate_operation(op)
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=gate,
        )
        guard.ingest_observation(build_observation(guard).as_document())
        called = []
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "objective_decision_floor_changed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(True) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [])
        receipt = outer.commit_receipts()[-1]
        self.assertEqual(receipt["effect_outcome"], "NOT_EXECUTED")
        self.assertIn("objective_decision_floor_changed", receipt["reason_codes"])
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "outer_lease_replayed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_noncritical_observation_also_invalidates_allow_lease(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=guard.evaluate_operation(op),
        )
        guard.ingest_observation(
            build_observation(guard, violation="result_fabrication").as_document()
        )
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "objective_decision_floor_changed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(guard.state_document()["decision_floor"], "BLOCK")

    def test_objective_decision_must_exactly_match_operation_and_current_head(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        gate = guard.evaluate_operation(op)
        cap = authorize(epoch, op)
        wrong_op = operation("op:different")
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "objective_decision_action_mismatch"):
            outer.issue_for_trusted_adapter(
                operation=wrong_op,
                capability_decision=cap,
                objective_decision=gate,
            )

    def test_stale_objective_decision_is_rejected_at_issue(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        gate = guard.evaluate_operation(op)
        guard.ingest_observation(build_observation(guard).as_document())
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "objective_decision_not_allow|objective_state_not_allow|stale_objective_observation_head"):
            outer.issue_for_trusted_adapter(
                operation=op,
                capability_decision=authorize(epoch, op),
                objective_decision=gate,
            )

    def test_outer_replay_is_blocked_without_second_effect(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=guard.evaluate_operation(op),
        )
        called = []
        outer.consume_for_trusted_adapter(
            lease_id,
            adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
        )
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "outer_lease_replayed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(False) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [True])

    def test_containment_after_issue_invalidates_before_effect(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=guard.evaluate_operation(op),
        )
        guard.enter_containment(incident_receipt_sha256="5" * 64)
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "objective_containment_active"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_inner_callback_failure_burns_outer_lease_and_redacts_error(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=guard.evaluate_operation(op),
        )
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "inner_effect_commit_failed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: (_ for _ in ()).throw(RuntimeError("sensitive evaluator detail")),
            )
        receipt = outer.commit_receipts()[-1]
        self.assertEqual(receipt["effect_outcome"], "FAILED")
        self.assertNotIn("sensitive evaluator detail", repr(receipt))
        with self.assertRaisesRegex(ObjectiveEffectCommitError, "outer_lease_replayed"):
            outer.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_shared_fence_prevents_observation_between_final_check_and_effect(self):
        fence, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        op = operation()
        lease_id, _ = outer.issue_for_trusted_adapter(
            operation=op,
            capability_decision=authorize(epoch, op),
            objective_decision=guard.evaluate_operation(op),
        )
        effect_entered = threading.Event()
        release_effect = threading.Event()
        observation_done = threading.Event()
        errors = []

        def effect(_):
            effect_entered.set()
            if not release_effect.wait(2):
                raise RuntimeError("test release timeout")
            return ExecutionObservation.success({"head": guard.observation_head_sha256})

        def run_effect():
            try:
                outer.consume_for_trusted_adapter(
                    lease_id,
                    adapter_token=ADAPTER_TOKEN,
                    executor=effect,
                )
            except Exception as exc:  # pragma: no cover - diagnostic path
                errors.append(exc)

        obs = build_observation(guard, observation_id="obs:concurrent")

        def ingest():
            try:
                guard.ingest_observation(obs.as_document())
                observation_done.set()
            except Exception as exc:  # pragma: no cover - diagnostic path
                errors.append(exc)

        effect_thread = threading.Thread(target=run_effect)
        observation_thread = threading.Thread(target=ingest)
        effect_thread.start()
        self.assertTrue(effect_entered.wait(1))
        observation_thread.start()
        self.assertFalse(observation_done.wait(0.05))
        release_effect.set()
        effect_thread.join(2)
        observation_thread.join(2)
        self.assertEqual(errors, [])
        self.assertTrue(observation_done.is_set())
        self.assertEqual(outer.commit_receipts()[-1]["effect_outcome"], "SUCCEEDED")
        self.assertEqual(guard.state_document()["decision_floor"], "CONTAIN")
        self.assertIsInstance(fence, RuntimeCommitFence)


class ObjectiveBoundRuntimeMediatorTests(unittest.TestCase):
    def test_clean_mediator_path_executes_through_objective_bound_commit(self):
        _, _, _, _, epoch, _, guard, outer, _ = setup_stack()
        mediator = ObjectiveBoundEffectRuntimeMediator(
            broker=epoch,
            objective_effect_broker=outer,
            adapter_token=ADAPTER_TOKEN,
        )
        called = []
        result = mediator.mediate(
            operation("op:objective-mediated"),
            lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
        )
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "SUCCEEDED")
        self.assertIn("objective_bound_effect_lease_consumed", result["reason_codes"])
        self.assertEqual(called, [True])
        self.assertEqual(len(outer.commit_receipts()), 1)
        self.assertEqual(guard.state_document()["decision_floor"], "ALLOW")

    def test_existing_objective_violation_blocks_before_capability_consumption(self):
        _, _, _, delegate, epoch, _, guard, outer, _ = setup_stack()
        guard.ingest_observation(build_observation(guard).as_document())
        mediator = ObjectiveBoundEffectRuntimeMediator(
            broker=epoch,
            objective_effect_broker=outer,
            adapter_token=ADAPTER_TOKEN,
        )
        called = []
        result = mediator.mediate(
            operation("op:blocked-by-objective", at=NOW + 4),
            lambda _: called.append(True) or ExecutionObservation.success({"bad": True}),
        )
        self.assertEqual(result["admission_decision"], "BLOCK")
        self.assertEqual(result["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(called, [])
        cap = delegate.state_document()["capabilities"][0]
        self.assertEqual(cap["use_count"], 0)


if __name__ == "__main__":
    unittest.main()
