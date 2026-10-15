"""Regression tests for grant snapshots and bounded effect receipt reads."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_durable_governance_fence import DurableGovernanceError
from sdk.liminal_effect_commit import EffectCommitError
from sdk.liminal_multi_agent import MultiAgentError, MultiAgentGovernance
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation
from tests import test_capability_broker_phase1 as capability_fixture
from tests import test_durable_governance_commit_fence as durable_fixture
from tests import test_epoch_bound_effect_commit as effect_fixture
from tests.test_multi_agent_governance_v1_2 import cap

ZERO = "0" * 64


class CapabilitySnapshotTests(unittest.TestCase):
    def test_event_export_mutation_cannot_invalidate_recorded_events(self):
        broker = CapabilityBroker()
        broker.admit(capability_fixture.contract().as_document(), at_unix=105)
        capability_fixture.authorize(broker)
        expected = deepcopy(broker.events())
        exported = broker.events()
        exported[0]["authority"]["execution"] = True
        exported[0]["reason_codes"].append("forged_reason")
        self.assertEqual(broker.events(), expected)
        for event in broker.events():
            body = dict(event)
            self.assertEqual(body.pop("event_sha256"), canonical_sha256(body))

    def test_admission_receipt_cannot_widen_live_scope(self):
        broker = CapabilityBroker()
        receipt = broker.admit(capability_fixture.contract().as_document(), at_unix=105)
        receipt["requested_scope"]["paths"].append("ungranted/")
        decision = capability_fixture.authorize(broker, requested_scope={
            "repository": "safal207/LiminalOSAI",
            "refs": ["refs/heads/agent/test"],
            "paths": ["ungranted/"],
        })
        self.assertEqual(decision["decision"], "BLOCK")
        self.assertIn("scope_mismatch", decision["reason_codes"])

    def test_export_mutation_preserves_stored_receipt_hashes(self):
        broker = CapabilityBroker()
        broker.admit(capability_fixture.contract().as_document(), at_unix=105)
        capability_fixture.authorize(broker)
        original = broker.receipts()
        expected = deepcopy(original)
        broker.state_document()["authority"]["execution"] = True
        for receipt in original:
            receipt["requested_scope"]["paths"].append("ungranted/")
            receipt["reason_codes"].append("forged_reason")
            receipt["authority"]["execution"] = True
        self.assertEqual(broker.receipts(), expected)
        for receipt in broker.receipts():
            body = dict(receipt)
            self.assertEqual(body.pop("receipt_sha256"), canonical_sha256(body))


class DelegationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"domains": ["api.example.com"], "protocols": ["https"], "ports": [443]}
        self.governance = MultiAgentGovernance()
        self.root = cap("root", "agent:a", self.scope, uses=1)
        self.governance.admit_root(self.root, at_unix=20)

    def authorize(self, capability_id="root", subject="agent:a", *, at=30, scope=None):
        return self.governance.authorize(
            subject_id=subject, capability_id=capability_id,
            requested_scope=scope if scope is not None else self.scope, at_unix=at,
        )

    def test_duplicate_root_cannot_reset_exhausted_budget(self):
        self.assertEqual(self.authorize()["decision"], "ALLOW")
        with self.assertRaises(MultiAgentError):
            self.governance.admit_root(self.root, at_unix=31)
        self.assertEqual(self.authorize(at=32)["decision"], "BLOCK")

    def test_duplicate_root_cannot_reactivate_revoked_grant(self):
        self.governance.revoke_tree("root", at_unix=30)
        with self.assertRaises(MultiAgentError):
            self.governance.admit_root(self.root, at_unix=31)
        self.assertEqual(self.authorize(at=32)["decision"], "BLOCK")

    def test_duplicate_child_cannot_reset_budget_or_change_parent(self):
        child = cap("child", "agent:b", self.scope, parent="root", uses=1)
        self.governance.delegate(child, at_unix=20)
        self.assertEqual(self.authorize("child", "agent:b")["decision"], "ALLOW")
        with self.assertRaises(MultiAgentError):
            self.governance.delegate(child, at_unix=31)
        self.governance.admit_root(cap("other", "agent:c", self.scope, uses=1), at_unix=20)
        with self.assertRaises(MultiAgentError):
            self.governance.delegate({**child, "parent_capability_id": "other"}, at_unix=31)
        self.assertEqual(self.authorize("child", "agent:b", at=32)["decision"], "BLOCK")
        revoked = self.governance.revoke_tree("root", at_unix=33)
        self.assertEqual({item["capability_id"] for item in revoked}, {"root", "child"})

    def test_duplicate_child_cannot_reactivate_after_tree_revocation(self):
        child = cap("child", "agent:b", self.scope, parent="root", uses=1)
        self.governance.delegate(child, at_unix=20)
        self.governance.revoke_tree("child", at_unix=30)
        with self.assertRaises(MultiAgentError):
            self.governance.delegate(child, at_unix=31)
        self.assertEqual(self.authorize("child", "agent:b", at=32)["decision"], "BLOCK")

    def test_caller_scope_mutation_cannot_widen_root_or_child(self):
        child_scope = deepcopy(self.scope)
        self.governance.delegate(cap("child", "agent:b", child_scope, parent="root", uses=1), at_unix=20)
        self.scope["domains"].append("ungranted.example.com")
        child_scope["domains"].append("ungranted.example.com")
        request = {**self.scope, "domains": ["ungranted.example.com"]}
        self.assertEqual(self.authorize(scope=request)["decision"], "BLOCK")
        self.assertEqual(self.authorize("child", "agent:b", scope=request)["decision"], "BLOCK")

    def test_use_before_issuance_is_blocked_without_spending_budget(self):
        self.assertEqual(self.authorize(at=1)["decision"], "BLOCK")
        self.assertEqual(self.authorize(at=10)["decision"], "ALLOW")
        self.assertEqual(self.authorize(at=11)["decision"], "BLOCK")

    def test_child_validity_cannot_start_before_parent(self):
        child = cap("child", "agent:b", self.scope, parent="root", uses=1)
        with self.assertRaises(MultiAgentError):
            self.governance.delegate({**child, "issued_at_unix": 9}, at_unix=20)

    def test_malformed_grants_are_rejected_before_admission(self):
        cases = {
            "capability_id": [None, "", " root ", []],
            "subject_id": [None, "", 7],
            "capability_type": [None, "unknown", []],
            "scope": [{}, {"domains": []}, {"ports": [443, "bad"]}, {"unknown": "value"}],
            "issued_at_unix": [True, -1, 1.5, "10"],
            "expires_at_unix": [True, 10, "200"],
            "max_uses": [True, 0, -1, 1.5],
            "policy_sha256": ["invalid", "A" * 64, None],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    candidate = {**self.root, "capability_id": "candidate", key: value}
                    with self.assertRaises(MultiAgentError):
                        self.governance.admit_root(candidate, at_unix=20)

    def test_malformed_requested_scope_cannot_authorize_empty_action(self):
        for scope in ({}, {"domains": []}, {"ports": [True]}, {"unknown": "value"}):
            with self.subTest(scope=scope):
                self.assertEqual(self.authorize(scope=scope)["decision"], "BLOCK")
        self.assertEqual(self.authorize()["decision"], "ALLOW")

    def test_invalid_trusted_times_cannot_mutate_state(self):
        for invalid in (True, -1, "20", 20.5):
            with self.subTest(at_unix=invalid):
                with self.assertRaises(MultiAgentError):
                    self.authorize(at=invalid)
                with self.assertRaises(MultiAgentError):
                    self.governance.revoke_tree("root", at_unix=invalid)
                with self.assertRaises(MultiAgentError):
                    self.governance.delegate(cap("child", "agent:b", self.scope, parent="root", uses=1), at_unix=invalid)
        self.assertEqual(self.authorize()["decision"], "ALLOW")

    def test_sibling_budgets_remain_per_grant(self):
        for capability_id, subject in (("child:b", "agent:b"), ("child:c", "agent:c")):
            self.governance.delegate(cap(capability_id, subject, self.scope, parent="root", uses=1), at_unix=20)
        self.assertEqual(self.authorize()["decision"], "ALLOW")
        self.assertEqual(self.authorize("child:b", "agent:b")["decision"], "ALLOW")
        self.assertEqual(self.authorize("child:c", "agent:c")["decision"], "ALLOW")
        self.assertEqual(self.authorize("child:b", "agent:b")["decision"], "BLOCK")

    def test_concurrent_admissions_cannot_overwrite_consumed_grant(self):
        governance = MultiAgentGovernance()
        first_checked = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        second_done = threading.Event()
        results = []
        require_new_id = governance._require_new_id

        def pause_after_check(capability_id):
            require_new_id(capability_id)
            if threading.current_thread().name == "first-admission":
                first_checked.set()
                if not release_first.wait(2):
                    raise RuntimeError("test release timeout")

        def admit_and_consume(second=False):
            if second:
                second_started.set()
            try:
                governance.admit_root(self.root, at_unix=20)
                decision = governance.authorize(
                    subject_id="agent:a", capability_id="root",
                    requested_scope=self.scope, at_unix=30,
                )
                results.append(decision["decision"])
            except MultiAgentError:
                results.append("duplicate_rejected")
            finally:
                if second:
                    second_done.set()

        first = threading.Thread(target=admit_and_consume, name="first-admission")
        second = threading.Thread(target=admit_and_consume, args=(True,))
        with patch.object(governance, "_require_new_id", side_effect=pause_after_check):
            first.start()
            try:
                self.assertTrue(first_checked.wait(1))
                second.start()
                self.assertTrue(second_started.wait(1))
                self.assertFalse(second_done.wait(0.05))
            finally:
                release_first.set()
                first.join(2)
                if second.ident is not None:
                    second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertCountEqual(results, ["ALLOW", "duplicate_rejected"])
        self.assertEqual(governance.authorize(
            subject_id="agent:a", capability_id="root", requested_scope=self.scope, at_unix=31,
        )["decision"], "BLOCK")

    def test_concurrent_authorizations_cannot_double_spend_one_use(self):
        from sdk import liminal_multi_agent

        first_checked = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        second_done = threading.Event()
        results = []
        scope_contains = liminal_multi_agent._scope_contains

        def pause_after_scope(parent, child):
            result = scope_contains(parent, child)
            if threading.current_thread().name == "first-authorization":
                first_checked.set()
                if not release_first.wait(2):
                    raise RuntimeError("test release timeout")
            return result

        def authorize(second=False):
            if second:
                second_started.set()
            try:
                results.append(self.authorize()["decision"])
            finally:
                if second:
                    second_done.set()

        first = threading.Thread(target=authorize, name="first-authorization")
        second = threading.Thread(target=authorize, args=(True,))
        with patch.object(liminal_multi_agent, "_scope_contains", side_effect=pause_after_scope):
            first.start()
            try:
                self.assertTrue(first_checked.wait(1))
                second.start()
                self.assertTrue(second_started.wait(1))
                self.assertFalse(second_done.wait(0.05))
            finally:
                release_first.set()
                first.join(2)
                if second.ident is not None:
                    second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertCountEqual(results, ["ALLOW", "BLOCK"])


class EffectSnapshotTests(unittest.TestCase):
    def test_caller_cannot_change_operation_after_lease_issue(self):
        _, _, _, epoch, broker, _, _ = effect_fixture.setup_stack()
        operation = effect_fixture.operation()
        lease, authorization = broker.issue_for_trusted_adapter(
            operation=operation, capability_decision=effect_fixture.authorize(epoch, operation),
        )
        original_scope = operation.normalized_scope()
        operation.scope["executables"].append("/ungranted/synthetic-worker")
        seen = []

        def execute(actual):
            seen.append(actual.normalized_scope())
            operation.scope["executables"].append("/ungranted/during-callback")
            self.assertEqual(actual.normalized_scope(), original_scope)
            return ExecutionObservation.success({"synthetic": True})

        broker.consume_for_trusted_adapter(lease, adapter_token=effect_fixture.ADAPTER_TOKEN, executor=execute)
        self.assertEqual(seen, [original_scope])
        self.assertEqual(canonical_sha256(seen[0]), authorization["scope_sha256"])
        with self.assertRaisesRegex(EffectCommitError, "lease_replayed"):
            broker.consume_for_trusted_adapter(lease, adapter_token=effect_fixture.ADAPTER_TOKEN, executor=execute)

    def test_provider_callback_cannot_mutate_pending_operation_snapshot(self):
        runtime, _, _, epoch, broker, _, _ = effect_fixture.setup_stack()
        operation = effect_fixture.operation()
        capability = effect_fixture.authorize(epoch, operation)
        original_scope = operation.normalized_scope()
        state_document = runtime.state_document

        def mutate_caller_scope():
            if "/ungranted/provider-worker" not in operation.scope["executables"]:
                operation.scope["executables"].append("/ungranted/provider-worker")
            return state_document()

        with patch.object(runtime, "state_document", side_effect=mutate_caller_scope):
            lease, authorization = broker.issue_for_trusted_adapter(operation=operation, capability_decision=capability)
        seen = []
        broker.consume_for_trusted_adapter(
            lease, adapter_token=effect_fixture.ADAPTER_TOKEN,
            executor=lambda actual: seen.append(actual.normalized_scope()) or ExecutionObservation.success({"synthetic": True}),
        )
        self.assertEqual(seen, [original_scope])
        self.assertEqual(authorization["scope_sha256"], canonical_sha256(original_scope))


class EffectCursorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        stack = durable_fixture.setup_stack(os.path.join(temporary.name, "governance.sqlite"))
        _, _, _, _, self.epoch, self.effect, self.guard, self.objective, self.ledger, self.causal, self.store, _, self.durable, _ = stack
        self.brokers = (self.effect, self.objective, self.causal, self.durable)

    def issue(self, operation_id):
        operation = durable_fixture.operation(operation_id)
        capability = durable_fixture.authorize(self.epoch, operation)
        lease, _ = self.durable.issue_for_trusted_adapter(
            operation=operation,
            capability_decision=capability,
            objective_decision=self.guard.evaluate_operation(operation),
            proposed_event=durable_fixture.proposal(self.ledger, operation, capability),
        )
        return lease

    def test_stacked_effects_do_not_export_historical_receipts(self):
        for broker in self.brokers:
            self.assertEqual(broker.commit_cursor(), (0, ZERO))
        for index in range(3):
            lease = self.issue(f"op:cursor:{index}")
            with ExitStack() as patches:
                for broker in self.brokers:
                    patches.enter_context(patch.object(broker, "commit_receipts", side_effect=AssertionError("history export in control path")))
                self.durable.consume_for_trusted_adapter(
                    lease, adapter_token=durable_fixture.ADAPTER_TOKEN,
                    executor=lambda _: ExecutionObservation.success({"synthetic": True}),
                )
            for broker in self.brokers:
                receipts = broker.commit_receipts()
                self.assertEqual(len(receipts), index + 1)
                self.assertEqual(broker.commit_cursor(), (index + 1, receipts[-1]["receipt_sha256"]))
            self.assertEqual(self.objective.commit_receipts()[-1]["inner_commit_receipt_sha256"], self.effect.commit_cursor()[1])
            self.assertEqual(self.causal.commit_receipts()[-1]["objective_commit_receipt_sha256"], self.objective.commit_cursor()[1])
            self.assertEqual(self.durable.commit_receipts()[-1]["causal_commit_receipt_sha256"], self.causal.commit_cursor()[1])

    def test_missing_inner_commit_retains_durable_reservation(self):
        lease = self.issue("op:missing-inner-receipt")
        with patch.object(self.causal, "consume_for_trusted_adapter", return_value=ExecutionObservation.success({"synthetic": True})):
            with self.assertRaisesRegex(DurableGovernanceError, "inner_commit_receipt_missing_after_effect"):
                self.durable.consume_for_trusted_adapter(
                    lease, adapter_token=durable_fixture.ADAPTER_TOKEN,
                    executor=lambda _: self.fail("callback unexpectedly executed"),
                )
        self.assertTrue(self.store.read_state(root_id=durable_fixture.ROOT)["reservation_active"])
        receipt = self.durable.commit_receipts()[-1]
        self.assertEqual(receipt["causal_commit_receipt_sha256"], ZERO)
        self.assertEqual(receipt["effect_outcome"], "EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED")

    def test_public_authority_documents_cannot_rewrite_history(self):
        lease = self.issue("op:authority-export")
        self.durable.consume_for_trusted_adapter(
            lease, adapter_token=durable_fixture.ADAPTER_TOKEN,
            executor=lambda _: ExecutionObservation.success({"synthetic": True}),
        )
        for broker in self.brokers:
            expected = deepcopy((broker.authorization_receipts(), broker.commit_receipts(), broker.state_document()))
            broker.state_document()["authority"]["forged_export_flag"] = True
            broker.authorization_receipts()[0]["authority"]["forged_export_flag"] = True
            broker.commit_receipts()[0]["authority"]["forged_export_flag"] = True
            self.assertEqual((broker.authorization_receipts(), broker.commit_receipts(), broker.state_document()), expected)

    def test_failed_inner_admission_does_not_reuse_previous_receipt(self):
        first = self.issue("op:previous-success")
        self.durable.consume_for_trusted_adapter(
            first, adapter_token=durable_fixture.ADAPTER_TOKEN,
            executor=lambda _: ExecutionObservation.success({"synthetic": True}),
        )
        previous_cursor = self.effect.commit_cursor()
        lease = self.issue("op:adapter-denied")
        with self.assertRaisesRegex(DurableGovernanceError, "inner_effect_failed_reservation_stuck"):
            self.durable.consume_for_trusted_adapter(
                lease, adapter_token="invalid",
                executor=lambda _: self.fail("callback unexpectedly executed"),
            )
        self.assertEqual(self.effect.commit_cursor(), previous_cursor)
        self.assertEqual(previous_cursor[0], 1)
        self.assertEqual(self.objective.commit_receipts()[-1]["inner_commit_receipt_sha256"], ZERO)
        self.assertTrue(self.store.read_state(root_id=durable_fixture.ROOT)["reservation_active"])


if __name__ == "__main__":
    unittest.main()
