"""Possible effects must remain visible to real trajectory analysis and replay."""

import unittest
from pathlib import Path
import tempfile
from dataclasses import replace
from unittest.mock import patch

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_effect_commit import (
    CausalBoundEffectRuntimeMediator,
    CausalEffectCommitError,
    verify_commit_receipt as verify_causal_commit,
)
from sdk.liminal_causal_escalation import analyze_trajectory, replay
from sdk.liminal_durable_governance_fence import (
    DurableGovernanceRuntimeMediator,
    DurableGovernanceError,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import (
    ExecutionObservation,
    ExecutionOutcomeUnknown,
    RuntimeMediator,
    verify_receipt,
)
from tests.test_runtime_mediation_v1_3 import contract, op
from tests.test_causal_bound_effect_commit import (
    ADAPTER_TOKEN,
    authorize,
    process_operation,
    proposal,
    setup_stack,
)
from tests.test_durable_governance_commit_fence import (
    ADAPTER_TOKEN as DURABLE_ADAPTER_TOKEN,
    ROOT as DURABLE_ROOT,
    authorize as durable_authorize,
    operation as durable_operation,
    proposal as durable_proposal,
    setup_stack as setup_durable_stack,
)


CREDENTIAL_SCOPE = {"credential_ids": ["cred:db"], "purpose": "runtime_test"}
CHILD_SCOPE = {"executables": ["worker"], "max_children": 1}
CONFIG_SCOPE = {"setting_keys": ["feature.safe_mode"]}


class UnknownTrajectoryProjectionTests(unittest.TestCase):
    def setUp(self):
        self.broker = CapabilityBroker("broker:unknown-trajectory")
        self.mediator = RuntimeMediator(broker=self.broker)

    def admit(self, cid, kind, scope):
        self.broker.admit(contract(cid, kind, "agent:a", scope, uses=1), at_unix=20)

    @staticmethod
    def uncertain(_):
        raise ExecutionOutcomeUnknown("private executor details")

    def test_possible_credential_effect_contributes_to_following_child_risk(self):
        self.admit("cap:cred", "credential.access", CREDENTIAL_SCOPE)
        self.admit("cap:child", "process.spawn_child", CHILD_SCOPE)
        observed_effects = []

        def read_credential(_):
            observed_effects.append("credential_used")
            raise ExecutionOutcomeUnknown("private credential path")

        unknown = self.mediator.mediate(
            op("credential.access", CREDENTIAL_SCOPE, oid="op:cred", at=20),
            read_credential,
        )
        self.assertEqual(unknown["admission_decision"], "ALLOW")
        self.assertEqual(unknown["execution_outcome"], "UNKNOWN")
        self.assertIn("reconciliation_required", unknown["reason_codes"])
        self.assertEqual(verify_receipt(unknown), unknown)
        self.assertNotIn("private credential path", repr(unknown))

        self.mediator.mediate(
            op("process.spawn_child", CHILD_SCOPE, oid="op:child", at=21),
            lambda _: ExecutionObservation.success({"child_created": True}),
        )
        events = self.mediator.trajectory_events()
        self.assertEqual([event.decision for event in events], ["ALLOW", "ALLOW"])
        self.assertEqual(events[0].event_sha256, unknown["trajectory_event_sha256"])
        risk = analyze_trajectory(events)
        self.assertEqual(risk["matched_rules"], ["R-CRED-CHILD"])
        self.assertEqual(risk["risk_score"], 30)
        self.assertEqual(risk["decision"], "REVISE")
        self.assertEqual(risk["contributing_event_ids"], [event.event_id for event in events])
        self.assertEqual(replay([event.__dict__ for event in events]), risk)

        # The uncertainty projection does not refund the spent capability use.
        retry_calls = []
        retry = self.mediator.mediate(
            op("credential.access", CREDENTIAL_SCOPE, oid="op:retry", at=22),
            lambda _: retry_calls.append("entered"),
        )
        self.assertEqual(retry["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(retry["admission_decision"], "BLOCK")
        self.assertEqual(retry_calls, [])
        self.assertEqual(observed_effects, ["credential_used"])
        self.assertEqual(analyze_trajectory(self.mediator.trajectory_events())["risk_score"], 30)

    def test_unknown_privilege_transition_preserves_the_conservative_bound(self):
        for before, after, expected_after, expected_risk in (
            (1, 6, 6, 25),
            (6, 1, 6, 0),
            (3, 3, 3, 0),
        ):
            with self.subTest(before=before, after=after):
                broker = CapabilityBroker("broker:unknown-privilege")
                broker.admit(contract("cap:cfg", "runtime.configure", "agent:a", CONFIG_SCOPE,
                                      uses=1), at_unix=20)
                mediator = RuntimeMediator(broker=broker)
                receipt = mediator.mediate(
                    op("runtime.configure", CONFIG_SCOPE, before=before, after=after),
                    self.uncertain,
                )
                event = mediator.trajectory_events()[0]
                self.assertEqual(event.decision, "ALLOW")
                self.assertEqual(event.privilege_level_before, before)
                self.assertEqual(event.privilege_level_after, expected_after)
                self.assertEqual(analyze_trajectory((event,))["risk_score"], expected_risk)
                self.assertEqual(receipt["execution_outcome"], "UNKNOWN")
                self.assertEqual(event.metadata_sha256, canonical_sha256({
                    "operation_id": "op:1", "runtime_kind": "runtime.configure",
                    "payload_sha256": receipt["payload_sha256"],
                    "scope_sha256": receipt["scope_sha256"], "outcome": "UNKNOWN",
                    "containment_evidence_sha256": "0" * 64,
                }))

    def test_genuine_failed_executor_remains_excluded_from_effect_rules(self):
        self.admit("cap:cred", "credential.access", CREDENTIAL_SCOPE)
        self.admit("cap:child", "process.spawn_child", CHILD_SCOPE)

        def fail(_):
            raise RuntimeError("known executor failure")

        failed = self.mediator.mediate(
            op("credential.access", CREDENTIAL_SCOPE, before=0, after=5), fail,
        )
        self.mediator.mediate(
            op("process.spawn_child", CHILD_SCOPE, oid="op:child", at=21),
            lambda _: ExecutionObservation.success({"child_created": True}),
        )
        events = self.mediator.trajectory_events()
        self.assertEqual(failed["execution_outcome"], "FAILED")
        self.assertEqual(events[0].decision, "BLOCK")
        self.assertEqual(events[0].privilege_level_after, 0)
        self.assertEqual(analyze_trajectory(events)["matched_rules"], [])

    def test_denial_never_dispatches_or_projects_requested_escalation(self):
        calls = []
        denied = self.mediator.mediate(
            op("runtime.configure", CONFIG_SCOPE, before=2, after=9),
            lambda _: calls.append("entered"),
        )
        event = self.mediator.trajectory_events()[0]
        self.assertEqual(denied["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(event.decision, "BLOCK")
        self.assertEqual(event.privilege_level_after, 2)
        self.assertEqual(analyze_trajectory((event,))["risk_score"], 0)
        self.assertEqual(calls, [])

    def test_unknown_retains_explicit_containment_and_independent_admission(self):
        self.admit("cap:cred", "credential.access", CREDENTIAL_SCOPE)
        self.admit("cap:cfg", "runtime.configure", CONFIG_SCOPE)
        self.mediator.mediate(op("credential.access", CREDENTIAL_SCOPE), self.uncertain)
        completed = self.mediator.mediate(
            op("runtime.configure", CONFIG_SCOPE, oid="op:independent", at=21),
            lambda _: ExecutionObservation.success({"changed": True}),
        )
        self.assertEqual(completed["execution_outcome"], "SUCCEEDED")
        self.mediator.enter_containment(incident_receipt_sha256="c" * 64)
        self.admit("cap:child", "process.spawn_child", CHILD_SCOPE)
        calls = []
        contained = self.mediator.mediate(
            op("process.spawn_child", CHILD_SCOPE, oid="op:contained", at=22),
            lambda _: calls.append("entered"),
        )
        self.assertEqual(contained["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(contained["reason_codes"], ["containment_active"])
        self.assertEqual(calls, [])

    def test_successful_effect_append_failure_preserves_typed_error_and_spent_lease(self):
        _, _, _, _, epoch, _, guard, objective, ledger, causal, _ = setup_stack()
        operation = process_operation("op:evidence-failed")
        capability = authorize(epoch, operation)
        lease_id, _ = causal.issue_for_trusted_adapter(
            operation=operation, capability_decision=capability,
            objective_decision=guard.evaluate_operation(operation),
            proposed_event=proposal(ledger, operation, capability),
        )
        observed = ExecutionObservation.success({"effect_completed": True})
        calls = []

        def execute(_):
            calls.append("effect_completed")
            return observed

        with patch.object(ledger, "append_verified_event", side_effect=OSError("private ledger path")):
            with self.assertRaises(CausalEffectCommitError) as caught:
                causal.consume_for_trusted_adapter(
                    lease_id, adapter_token=ADAPTER_TOKEN, executor=execute,
                )
        self.assertIsInstance(caught.exception, ExecutionOutcomeUnknown)
        self.assertEqual(caught.exception.code, "trajectory_append_failed_after_effect")
        self.assertEqual(caught.exception.result_sha256, observed.result_sha256)
        self.assertEqual(objective.commit_receipts()[-1]["effect_outcome"], "SUCCEEDED")
        committed = causal.commit_receipts()[-1]
        self.assertEqual(committed["effect_outcome"], "EFFECT_SUCCEEDED_EVIDENCE_FAILED")
        self.assertEqual(committed["result_sha256"], observed.result_sha256)
        self.assertEqual(verify_causal_commit(committed), committed)
        self.assertNotIn("private ledger path", repr(committed))
        self.assertEqual(ledger.event_count, 0)
        with self.assertRaisesRegex(CausalEffectCommitError, "causal_lease_replayed"):
            causal.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN, executor=execute,
            )
        self.assertEqual(calls, ["effect_completed"])

    def test_causal_mediator_keeps_successful_effect_risk_when_append_fails(self):
        _, _, _, _, epoch, _, _, _, ledger, causal, _ = setup_stack()
        mediator = CausalBoundEffectRuntimeMediator(
            broker=epoch, causal_effect_broker=causal, adapter_token=ADAPTER_TOKEN,
            proposal_factory=lambda operation, capability, journal: proposal(journal, operation, capability),
        )
        operation = replace(process_operation("op:evidence-risk"), privilege_level_after=1)
        observed = ExecutionObservation.success({"effect_completed": True})
        calls = []

        def execute(_):
            calls.append("effect_completed")
            return observed

        with patch.object(ledger, "append_verified_event", side_effect=OSError("private ledger path")):
            result = mediator.mediate(operation, execute)
        self.assertEqual(result["execution_outcome"], "UNKNOWN")
        self.assertEqual(result["result_sha256"], observed.result_sha256)
        self.assertEqual(result["reason_codes"], [
            "effect_succeeded", "reconciliation_required", "trajectory_append_failed",
        ])
        self.assertEqual(verify_receipt(result), result)
        self.assertEqual(calls, ["effect_completed"])
        self.assertEqual(ledger.event_count, 0)
        self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "EFFECT_SUCCEEDED_EVIDENCE_FAILED")
        events = mediator.trajectory_events()
        self.assertEqual(events[0].decision, "ALLOW")
        risk = analyze_trajectory(events)
        self.assertEqual(risk["privilege_delta"], 1)
        self.assertEqual(risk["risk_score"], 5)
        self.assertEqual(replay([event.__dict__ for event in events]), risk)
        self.assertNotIn("private ledger path", repr(result))

    def test_unknown_survives_every_layer_diagnostic_cursor_and_receipt_failure(self):
        for layer, method in (
            ("effect", "_append_commit"),
            ("objective", "_latest_inner_commit"),
            ("objective", "_append_commit"),
            ("causal", "_latest_objective_commit"),
            ("causal", "_append_commit"),
            ("durable", "_latest_inner_commit"),
            ("durable", "_append_commit"),
        ):
            for interface in ("broker", "mediator"):
                with self.subTest(layer=layer, method=method, interface=interface), tempfile.TemporaryDirectory() as directory:
                    stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                    _, _, _, _, epoch, effect, guard, objective, ledger, causal, store, _, durable, _ = stack
                    target = {"effect": effect, "objective": objective, "causal": causal, "durable": durable}[layer]
                    operation = replace(durable_operation(), privilege_level_after=1)
                    marker = ExecutionOutcomeUnknown("private executor details")
                    calls = []

                    def execute(_):
                        calls.append("entered")
                        raise marker

                    if interface == "broker":
                        capability = durable_authorize(epoch, operation)
                        lease_id, _ = durable.issue_for_trusted_adapter(
                            operation=operation, capability_decision=capability,
                            objective_decision=guard.evaluate_operation(operation),
                            proposed_event=durable_proposal(ledger, operation, capability),
                        )
                        with patch.object(target, method, side_effect=OSError("private diagnostic token")):
                            with self.assertRaises(ExecutionOutcomeUnknown) as caught:
                                durable.consume_for_trusted_adapter(
                                    lease_id, adapter_token=DURABLE_ADAPTER_TOKEN, executor=execute,
                                )
                        self.assertIs(caught.exception, marker)
                        self.assertNotIn("private diagnostic token", repr(caught.exception.__cause__))
                        with self.assertRaisesRegex(DurableGovernanceError, "durable_lease_replayed"):
                            durable.consume_for_trusted_adapter(
                                lease_id, adapter_token=DURABLE_ADAPTER_TOKEN, executor=execute,
                            )
                    else:
                        mediator = DurableGovernanceRuntimeMediator(
                            broker=epoch, durable_effect_broker=durable,
                            adapter_token=DURABLE_ADAPTER_TOKEN,
                            proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                        )
                        with patch.object(target, method, side_effect=OSError("private diagnostic token")):
                            result = mediator.mediate(operation, execute)
                        self.assertEqual(result["execution_outcome"], "UNKNOWN")
                        self.assertEqual(mediator.trajectory_events()[0].decision, "ALLOW")
                        self.assertEqual(analyze_trajectory(mediator.trajectory_events())["risk_score"], 5)
                        self.assertNotIn("private diagnostic token", repr(result))
                    self.assertEqual(calls, ["entered"])
                    self.assertTrue(store.read_state(root_id=DURABLE_ROOT)["reservation_active"])
                    self.assertEqual(ledger.event_count, 0)
                    for broker in (effect, objective, causal):
                        self.assertEqual(broker.state_document()["consumed_count"], 1)

    def test_causal_known_success_survives_secondary_and_final_recording_failures(self):
        for append_fails, diagnostic in (
            (True, "_latest_objective_commit"), (True, "_append_commit"),
            (False, "_latest_objective_commit"), (False, "_append_commit"),
        ):
            with self.subTest(append_fails=append_fails, diagnostic=diagnostic):
                _, _, _, _, epoch, _, _, _, ledger, causal, _ = setup_stack()
                mediator = CausalBoundEffectRuntimeMediator(
                    broker=epoch, causal_effect_broker=causal, adapter_token=ADAPTER_TOKEN,
                    proposal_factory=lambda op, cap, journal: proposal(journal, op, cap),
                )
                operation = replace(process_operation(), privilege_level_after=1)
                observed = ExecutionObservation.success({"effect_completed": True})
                calls = []

                def execute(_):
                    calls.append("effect_completed")
                    return observed

                with patch.object(causal, diagnostic, side_effect=OSError("private diagnostic token")):
                    if append_fails:
                        with patch.object(ledger, "append_verified_event", side_effect=OSError("private ledger path")):
                            result = mediator.mediate(operation, execute)
                    else:
                        result = mediator.mediate(operation, execute)
                expected_code = "trajectory_append_failed" if append_fails else "causal_commit_receipt_failed"
                self.assertEqual(result["execution_outcome"], "UNKNOWN")
                self.assertEqual(result["result_sha256"], observed.result_sha256)
                self.assertEqual(result["reason_codes"], sorted([
                    "effect_succeeded", expected_code, "reconciliation_required",
                ]))
                self.assertEqual(calls, ["effect_completed"])
                self.assertEqual(ledger.event_count, 0 if append_fails else 1)
                self.assertEqual(causal.state_document()["consumed_count"], 1)
                self.assertEqual(mediator.trajectory_events()[0].decision, "ALLOW")
                self.assertEqual(analyze_trajectory(mediator.trajectory_events())["risk_score"], 5)
                self.assertNotIn("private diagnostic token", repr(result))

    def test_pre_dispatch_cursor_failure_remains_failed_without_possible_effect(self):
        for layer in ("effect", "objective", "causal"):
            with self.subTest(layer=layer), tempfile.TemporaryDirectory() as directory:
                stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                _, _, _, _, epoch, effect, _, objective, ledger, causal, _, _, durable, _ = stack
                target = {"effect": effect, "objective": objective, "causal": causal}[layer]
                mediator = DurableGovernanceRuntimeMediator(
                    broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                    proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                )
                calls = []
                with patch.object(target, "commit_cursor", side_effect=OSError("pre-dispatch cursor unavailable")):
                    result = mediator.mediate(
                        replace(durable_operation(), privilege_level_after=1),
                        lambda _: calls.append("entered"),
                    )
                self.assertEqual(result["execution_outcome"], "FAILED")
                self.assertEqual(mediator.trajectory_events()[0].decision, "BLOCK")
                self.assertEqual(mediator.trajectory_events()[0].privilege_level_after, 0)
                self.assertEqual(calls, [])

    def test_known_success_evidence_failure_keeps_outer_durable_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = setup_durable_stack(str(Path(directory) / "governance.db"))
            _, _, _, _, epoch, _, _, _, ledger, causal, store, _, durable, _ = stack
            mediator = DurableGovernanceRuntimeMediator(
                broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
            )
            observed = ExecutionObservation.success({"effect_completed": True})
            with patch.object(ledger, "append_verified_event", side_effect=OSError("private ledger path")):
                result = mediator.mediate(
                    replace(durable_operation(), privilege_level_after=1), lambda _: observed,
                )
            self.assertEqual(result["execution_outcome"], "UNKNOWN")
            self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "EFFECT_SUCCEEDED_EVIDENCE_FAILED")
            self.assertEqual(causal.commit_receipts()[-1]["result_sha256"], observed.result_sha256)
            self.assertEqual(durable.commit_receipts()[-1]["effect_outcome"], "EFFECT_UNKNOWN_RESERVATION_STUCK")
            self.assertTrue(store.read_state(root_id=DURABLE_ROOT)["reservation_active"])
            self.assertEqual(mediator.trajectory_events()[0].decision, "ALLOW")


if __name__ == "__main__":
    unittest.main()
