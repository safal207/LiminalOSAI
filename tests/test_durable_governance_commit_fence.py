from __future__ import annotations

import hashlib
import multiprocessing
import os
import tempfile
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_effect_commit import (
    CausalBoundEffectCommitBroker,
    FencedTrajectoryRiskLedger,
    build_effect_trajectory_event,
)
from sdk.liminal_durable_governance_fence import (
    AUTHORITY,
    DurableGovernanceCoordinator,
    DurableGovernanceEffectBroker,
    DurableGovernanceError,
    DurableGovernanceRuntimeMediator,
    GovernanceWorld,
    SQLiteGovernanceStore,
    default_world_provider,
    verify_authorization_receipt,
    verify_commit_receipt,
)
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
ADAPTER_TOKEN = "trusted-durable-effect-adapter"
ADAPTER_SHA = hashlib.sha256(ADAPTER_TOKEN.encode("utf-8")).hexdigest()
ROOT = "governance:test-root"


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
        objective_id="objective:durable-effect:test",
        objective_sha256=OBJECTIVE,
        method_policy_id="method-policy:durable-effect:v1",
        governance_policy_sha256=POLICY,
        allowed_runtime_kinds=("process.execute",),
    )


def operation(operation_id="op:durable-effect", *, at=NOW + 1, payload="4" * 64):
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
        capability_id="cap:durable-effect:1",
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


def setup_stack(db_path):
    fence = RuntimeCommitFence()
    runtime = FakeRuntimeProvider()
    sessions = FakeSessionProvider()
    delegate = CapabilityBroker("broker:durable-effect:delegate")
    epoch = EpochBoundCapabilityBroker(
        runtime_provider=runtime,
        delegate=delegate,
        broker_id="broker:durable-effect:epoch",
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
        verify_event=lambda _: True,
    )
    causal = CausalBoundEffectCommitBroker(
        ledger=ledger,
        delegate=objective,
        commit_fence=fence,
        clock=clock,
    )
    store = SQLiteGovernanceStore(db_path)
    provider = default_world_provider(
        objective_guard=guard,
        trajectory_ledger=ledger,
        runtime_provider=runtime,
    )
    durable = DurableGovernanceEffectBroker(
        store=store,
        root_id=ROOT,
        world_provider=provider,
        delegate=causal,
        commit_fence=fence,
        clock=clock,
    )
    durable.bootstrap()
    return fence, runtime, sessions, delegate, epoch, effect, guard, objective, ledger, causal, store, provider, durable, clock


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


def proposal(ledger, op, cap):
    state = ledger.state_document()
    return build_effect_trajectory_event(
        operation=op,
        capability_decision=cap,
        sequence=state["event_count"] + 1,
        previous_event_sha256=state["trajectory_head_sha256"],
        event_id=f"durable-proposal:{op.operation_id}",
    )


def synthetic_world(seed):
    return GovernanceWorld.build(
        objective_state_sha256=hashlib.sha256(f"objective:{seed}".encode()).hexdigest(),
        causal_state_sha256=hashlib.sha256(f"causal:{seed}".encode()).hexdigest(),
        runtime_context_sha256=hashlib.sha256(f"runtime:{seed}".encode()).hexdigest(),
    ).as_document()


def _child_reserve_and_die(db_path, root_id, generation, world_sha):
    try:
        store = SQLiteGovernanceStore(db_path)
        store.reserve_effect(
            root_id=root_id,
            expected_generation=generation,
            expected_world_sha256=world_sha,
            reservation_id="crashed-process-reservation",
            reservation_payload_sha256="7" * 64,
        )
        os._exit(0)
    except Exception:
        os._exit(73)


def _child_attempt_mutation(db_path, root_id, generation, world_sha, queue):
    try:
        store = SQLiteGovernanceStore(db_path)
        store.mutate_world(
            root_id=root_id,
            expected_generation=generation,
            expected_world_sha256=world_sha,
            new_world=synthetic_world("child-new"),
            transition_receipt_sha256="8" * 64,
        )
        queue.put("MUTATED")
    except Exception as exc:
        queue.put(type(exc).__name__ + ":" + str(exc))


class FailingFinalizeStore:
    def __init__(self, delegate):
        self.delegate = delegate

    def initialize(self, **kwargs):
        return self.delegate.initialize(**kwargs)

    def read_state(self, **kwargs):
        return self.delegate.read_state(**kwargs)

    def reserve_effect(self, **kwargs):
        return self.delegate.reserve_effect(**kwargs)

    def commit_effect(self, **kwargs):
        raise DurableGovernanceError("simulated_durable_finalize_failure")

    def mutate_world(self, **kwargs):
        return self.delegate.mutate_world(**kwargs)

    def reconcile_reservation(self, **kwargs):
        return self.delegate.reconcile_reservation(**kwargs)


class DurableGovernanceStoreTests(unittest.TestCase):
    def test_authority_boundary_is_restrictive(self):
        self.assertTrue(AUTHORITY["durable_generation_cas"])
        self.assertTrue(AUTHORITY["cross_process_effect_reservation"])
        self.assertTrue(AUTHORITY["explicit_reconciliation_required"])
        self.assertFalse(AUTHORITY["automatic_reservation_expiry"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["distributed_consensus"])
        self.assertFalse(AUTHORITY["kernel_enforcement"])

    def test_generation_cas_and_stale_world_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            store = SQLiteGovernanceStore(path)
            initial = synthetic_world("initial")
            state0 = store.initialize(root_id=ROOT, world=initial)
            state1 = store.mutate_world(
                root_id=ROOT,
                expected_generation=0,
                expected_world_sha256=state0["world_sha256"],
                new_world=synthetic_world("next"),
                transition_receipt_sha256="5" * 64,
            )
            self.assertEqual(state1["generation"], 1)
            with self.assertRaisesRegex(DurableGovernanceError, "stale_governance_generation"):
                store.mutate_world(
                    root_id=ROOT,
                    expected_generation=0,
                    expected_world_sha256=state0["world_sha256"],
                    new_world=synthetic_world("stale"),
                    transition_receipt_sha256="6" * 64,
                )

    def test_real_process_crash_leaves_durable_reservation_until_reconciliation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            store = SQLiteGovernanceStore(path)
            state0 = store.initialize(root_id=ROOT, world=synthetic_world("initial"))
            child = multiprocessing.Process(
                target=_child_reserve_and_die,
                args=(path, ROOT, state0["generation"], state0["world_sha256"]),
            )
            child.start()
            child.join(5)
            self.assertEqual(child.exitcode, 0)
            recovered = SQLiteGovernanceStore(path).read_state(root_id=ROOT)
            self.assertTrue(recovered["reservation_active"])
            self.assertEqual(recovered["generation"], 0)
            with self.assertRaisesRegex(DurableGovernanceError, "durable_reservation_active"):
                SQLiteGovernanceStore(path).reserve_effect(
                    root_id=ROOT,
                    expected_generation=0,
                    expected_world_sha256=recovered["world_sha256"],
                    reservation_id="second-reservation",
                    reservation_payload_sha256="9" * 64,
                )
            reconciled = SQLiteGovernanceStore(path).reconcile_reservation(
                root_id=ROOT,
                expected_generation=0,
                expected_world_sha256=recovered["world_sha256"],
                reservation_id="crashed-process-reservation",
                new_world=synthetic_world("reconciled"),
                reconciliation_receipt_sha256="a" * 64,
            )
            self.assertFalse(reconciled["reservation_active"])
            self.assertEqual(reconciled["generation"], 1)

    def test_second_process_cannot_mutate_world_while_reservation_is_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            store = SQLiteGovernanceStore(path)
            state = store.initialize(root_id=ROOT, world=synthetic_world("initial"))
            store.reserve_effect(
                root_id=ROOT,
                expected_generation=0,
                expected_world_sha256=state["world_sha256"],
                reservation_id="parent-reservation",
                reservation_payload_sha256="b" * 64,
            )
            queue = multiprocessing.Queue()
            child = multiprocessing.Process(
                target=_child_attempt_mutation,
                args=(path, ROOT, 0, state["world_sha256"], queue),
            )
            child.start()
            child.join(5)
            self.assertEqual(child.exitcode, 0)
            result = queue.get(timeout=2)
            self.assertIn("durable_reservation_active", result)
            final = SQLiteGovernanceStore(path).read_state(root_id=ROOT)
            self.assertEqual(final["generation"], 0)
            self.assertTrue(final["reservation_active"])


class DurableGovernanceEffectTests(unittest.TestCase):
    def test_clean_effect_advances_generation_and_publishes_post_effect_world(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            _, _, _, _, epoch, _, guard, _, ledger, causal, store, _, durable, _ = setup_stack(path)
            before = store.read_state(root_id=ROOT)
            op = operation()
            cap = authorize(epoch, op)
            lease_id, auth = durable.issue_for_trusted_adapter(
                operation=op,
                capability_decision=cap,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=proposal(ledger, op, cap),
            )
            self.assertEqual(verify_authorization_receipt(auth), auth)
            reserved = store.read_state(root_id=ROOT)
            self.assertTrue(reserved["reservation_active"])
            called = []
            result = durable.consume_for_trusted_adapter(
                lease_id,
                adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
            )
            self.assertEqual(result.outcome, "SUCCEEDED")
            self.assertEqual(called, [True])
            after = store.read_state(root_id=ROOT)
            self.assertEqual(after["generation"], before["generation"] + 1)
            self.assertFalse(after["reservation_active"])
            self.assertNotEqual(after["world_sha256"], before["world_sha256"])
            self.assertEqual(after["causal_state_sha256"], ledger.state_document()["state_sha256"])
            receipt = durable.commit_receipts()[-1]
            self.assertEqual(verify_commit_receipt(receipt), receipt)
            self.assertEqual(receipt["effect_outcome"], "SUCCEEDED")
            self.assertNotEqual(receipt["causal_commit_receipt_sha256"], "0" * 64)
            self.assertEqual(len(causal.commit_receipts()), 1)

    def test_inner_failure_keeps_reservation_stuck_and_redacts_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            _, _, _, _, epoch, _, guard, _, ledger, _, store, _, durable, _ = setup_stack(path)
            op = operation()
            cap = authorize(epoch, op)
            lease_id, _ = durable.issue_for_trusted_adapter(
                operation=op,
                capability_decision=cap,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=proposal(ledger, op, cap),
            )
            with self.assertRaisesRegex(DurableGovernanceError, "inner_effect_failed_reservation_stuck"):
                durable.consume_for_trusted_adapter(
                    lease_id,
                    adapter_token=ADAPTER_TOKEN,
                    executor=lambda _: (_ for _ in ()).throw(RuntimeError("secret host detail")),
                )
            state = store.read_state(root_id=ROOT)
            self.assertTrue(state["reservation_active"])
            self.assertEqual(state["generation"], 0)
            receipt = durable.commit_receipts()[-1]
            self.assertEqual(receipt["effect_outcome"], "EFFECT_FAILED_RESERVATION_STUCK")
            self.assertNotIn("secret host detail", repr(receipt))
            with self.assertRaisesRegex(DurableGovernanceError, "durable_lease_replayed"):
                durable.consume_for_trusted_adapter(
                    lease_id,
                    adapter_token=ADAPTER_TOKEN,
                    executor=lambda _: ExecutionObservation.success({"bad": True}),
                )

    def test_finalize_failure_after_effect_keeps_reservation_and_never_reports_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            fence, runtime, _, _, epoch, _, guard, _, ledger, causal, base_store, provider, _, clock = setup_stack(path)
            failing = FailingFinalizeStore(base_store)
            durable = DurableGovernanceEffectBroker(
                store=failing,
                root_id=ROOT,
                world_provider=provider,
                delegate=causal,
                commit_fence=fence,
                clock=clock,
            )
            op = operation("op:finalize-failure")
            cap = authorize(epoch, op)
            lease_id, _ = durable.issue_for_trusted_adapter(
                operation=op,
                capability_decision=cap,
                objective_decision=guard.evaluate_operation(op),
                proposed_event=proposal(ledger, op, cap),
            )
            called = []
            with self.assertRaisesRegex(DurableGovernanceError, "durable_finalize_failed_after_effect"):
                durable.consume_for_trusted_adapter(
                    lease_id,
                    adapter_token=ADAPTER_TOKEN,
                    executor=lambda _: called.append(True) or ExecutionObservation.success({"effect": "done"}),
                )
            self.assertEqual(called, [True])
            state = base_store.read_state(root_id=ROOT)
            self.assertTrue(state["reservation_active"])
            self.assertEqual(state["generation"], 0)
            receipt = durable.commit_receipts()[-1]
            self.assertEqual(receipt["effect_outcome"], "EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED")
            self.assertIn("durable_reservation_retained", receipt["reason_codes"])
            self.assertFalse(AUTHORITY["automatic_rollback"])
            self.assertEqual(runtime.epoch, 0)

    def test_coordinator_world_mutation_invalidates_preexisting_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            store = SQLiteGovernanceStore(path)
            state0 = store.initialize(root_id=ROOT, world=synthetic_world("zero"))
            coordinator = DurableGovernanceCoordinator(store=store, root_id=ROOT)
            state1 = coordinator.mutate_world(
                expected_generation=0,
                expected_world_sha256=state0["world_sha256"],
                new_world=synthetic_world("one"),
                transition_receipt_sha256="c" * 64,
            )
            self.assertEqual(state1["generation"], 1)
            with self.assertRaisesRegex(DurableGovernanceError, "stale_governance_generation"):
                coordinator.mutate_world(
                    expected_generation=0,
                    expected_world_sha256=state0["world_sha256"],
                    new_world=synthetic_world("two"),
                    transition_receipt_sha256="d" * 64,
                )


class DurableGovernanceMediatorTests(unittest.TestCase):
    def test_clean_mediator_path_commits_through_durable_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "governance.db")
            _, _, _, _, epoch, _, _, _, ledger, _, store, _, durable, _ = setup_stack(path)

            def factory(op, cap, causal_ledger):
                return build_effect_trajectory_event(
                    operation=op,
                    capability_decision=cap,
                    sequence=causal_ledger.event_count + 1,
                    previous_event_sha256=causal_ledger.head_sha256,
                    event_id=f"mediated:{op.operation_id}",
                )

            mediator = DurableGovernanceRuntimeMediator(
                broker=epoch,
                durable_effect_broker=durable,
                adapter_token=ADAPTER_TOKEN,
                proposal_factory=factory,
            )
            result = mediator.mediate(
                operation("op:durable-mediated"),
                lambda _: ExecutionObservation.success({"ok": True}),
            )
            self.assertEqual(result["admission_decision"], "ALLOW")
            self.assertEqual(result["execution_outcome"], "SUCCEEDED")
            self.assertIn("durable_governance_reservation_committed", result["reason_codes"])
            self.assertEqual(store.read_state(root_id=ROOT)["generation"], 1)
            self.assertEqual(ledger.event_count, 1)


if __name__ == "__main__":
    unittest.main()
