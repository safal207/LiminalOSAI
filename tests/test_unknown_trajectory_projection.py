"""Possible effects must remain visible to real trajectory analysis and replay."""

import unittest
from contextlib import ExitStack
from pathlib import Path
import tempfile
from dataclasses import replace
from unittest.mock import patch

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_effect_commit import (
    CausalBoundEffectCommitBroker,
    CausalBoundEffectRuntimeMediator,
    CausalEffectCommitError,
    CausalEffectEvidenceError,
    verify_commit_receipt as verify_causal_commit,
)
from sdk.liminal_causal_escalation import analyze_trajectory, replay
from sdk.liminal_durable_governance_fence import (
    DurableGovernanceRuntimeMediator,
    DurableGovernanceError,
    verify_commit_receipt as verify_durable_commit,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_effect_commit import ZERO_SHA256
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
    seed_event,
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

    def assert_uncertain_ledger(self, ledger):
        state = ledger.state_document()
        verified = replay(ledger.events())
        self.assertEqual(state["decision"], "BLOCK")
        self.assertTrue(state["effect_uncertain"])
        self.assertEqual(state["verified_trajectory_decision"], verified["decision"])
        self.assertEqual(state["graph_sha256"], verified["graph_sha256"])
        self.assertEqual(state["decision_receipt_sha256"], verified["receipt_sha256"])
        gate = state["uncertainty_gate"]
        self.assertEqual(gate["decision"], "BLOCK")
        self.assertEqual(gate["reason_codes"], ["effect_outcome_unreconciled"])
        self.assertEqual(gate["graph_sha256"], verified["graph_sha256"])
        self.assertEqual(gate["decision_receipt_sha256"], verified["receipt_sha256"])
        self.assertEqual(gate["trajectory_head_sha256"], ledger.head_sha256)
        self.assertEqual(gate["event_count"], ledger.event_count)
        self.assertEqual(state["uncertainty_gate_sha256"], canonical_sha256(gate))
        self.assertEqual(state["state_sha256"], canonical_sha256({
            key: value for key, value in state.items() if key != "state_sha256"
        }))
        return state

    def test_causal_uncertainty_blocks_all_shared_brokers_and_burns_preissued_lease(self):
        for diagnostics_fail in (False, True):
            with self.subTest(diagnostics_fail=diagnostics_fail):
                fence, _, _, _, epoch, effect, guard, objective, ledger, causal, clock = setup_stack()
                other = CausalBoundEffectCommitBroker(
                    ledger=ledger, delegate=objective, commit_fence=fence, clock=clock,
                )
                first = replace(process_operation("op:uncertain"), privilege_level_after=1)
                second = process_operation("op:preissued")
                leases = []
                for broker, operation in ((causal, first), (other, second)):
                    capability = authorize(epoch, operation)
                    lease, _ = broker.issue_for_trusted_adapter(
                        operation=operation, capability_decision=capability,
                        objective_decision=guard.evaluate_operation(operation),
                        proposed_event=proposal(ledger, operation, capability),
                    )
                    leases.append(lease)
                original_head = ledger.head_sha256
                calls = []
                marker = ExecutionOutcomeUnknown("private executor token")

                def execute(_):
                    calls.append("possible effect")
                    raise marker

                with ExitStack() as faults:
                    if diagnostics_fail:
                        for layer, method in (
                            (effect, "_append_commit"), (objective, "_latest_inner_commit"),
                            (causal, "_latest_objective_commit"), (causal, "_append_commit"),
                        ):
                            faults.enter_context(patch.object(layer, method, side_effect=OSError("private diagnostic token")))
                    with self.assertRaises(ExecutionOutcomeUnknown) as caught:
                        causal.consume_for_trusted_adapter(
                            leases[0], adapter_token=ADAPTER_TOKEN, executor=execute,
                        )
                self.assertIs(caught.exception, marker)
                blocked = self.assert_uncertain_ledger(ledger)
                self.assertEqual(ledger.head_sha256, original_head)
                self.assertEqual(ledger.events(), ())
                self.assertNotIn("private", repr(blocked))
                with self.assertRaisesRegex(CausalEffectCommitError, "trajectory_state_not_allow"):
                    other.consume_for_trusted_adapter(
                        leases[1], adapter_token=ADAPTER_TOKEN, executor=execute,
                    )
                self.assertEqual(other.state_document()["consumed_count"], 1)
                with self.assertRaisesRegex(CausalEffectCommitError, "causal_lease_replayed"):
                    other.consume_for_trusted_adapter(
                        leases[1], adapter_token=ADAPTER_TOKEN, executor=execute,
                    )
                for broker in (causal, other):
                    operation = process_operation("op:after-unknown")
                    capability = authorize(epoch, operation)
                    self.assertEqual(capability["decision"], "ALLOW")
                    projected = proposal(ledger, operation, capability)
                    with self.assertRaisesRegex(CausalEffectCommitError, "trajectory_state_not_allow"):
                        broker.issue_for_trusted_adapter(
                            operation=operation, capability_decision=capability,
                            objective_decision=guard.evaluate_operation(operation), proposed_event=projected,
                        )
                    with self.assertRaisesRegex(CausalEffectCommitError, "trajectory_effect_uncertain"):
                        ledger.project_verified_event(projected)
                self.assertEqual(calls, ["possible effect"])

                # Neither a host containment release nor new verified facts reconcile a lost outcome.
                causal.enter_containment(incident_receipt_sha256="6" * 64)
                causal.exit_containment(human_release_receipt_sha256="7" * 64)
                fact = seed_event(
                    event_id="fact:after-uncertainty", sequence=1, previous=original_head,
                    kind="repository.write", at=first.at_unix + 1,
                )
                appended = ledger.append_verified_event(fact)
                self.assertEqual(appended["trajectory_decision"], "BLOCK")
                self.assert_uncertain_ledger(ledger)
                self.assertEqual(ledger.event_count, 1)

    def test_causal_mediator_next_operation_cannot_dispatch_after_unknown(self):
        _, _, _, _, epoch, _, _, _, ledger, causal, _ = setup_stack()
        mediator = CausalBoundEffectRuntimeMediator(
            broker=epoch, causal_effect_broker=causal, adapter_token=ADAPTER_TOKEN,
            proposal_factory=lambda operation, capability, journal: proposal(journal, operation, capability),
        )
        first = mediator.mediate(
            replace(process_operation("op:first"), privilege_level_after=1), self.uncertain,
        )
        calls = []
        second = mediator.mediate(
            process_operation("op:next"),
            lambda _: calls.append("entered") or ExecutionObservation.success({"next": True}),
        )
        self.assertEqual(first["execution_outcome"], "UNKNOWN")
        self.assertEqual(second["execution_outcome"], "FAILED")
        self.assertEqual(calls, [])
        self.assertEqual([event.decision for event in mediator.trajectory_events()], ["ALLOW", "BLOCK"])
        self.assertEqual(ledger.event_count, 0)
        self.assert_uncertain_ledger(ledger)
        self.assertEqual(replay([event.__dict__ for event in mediator.trajectory_events()]), analyze_trajectory(mediator.trajectory_events()))

    def test_causal_normal_path_retains_published_wire_hashes(self):
        _, _, _, _, epoch, _, guard, _, ledger, causal, _ = setup_stack()
        self.assertEqual(ledger.state_document()["state_sha256"], "78998ab078ac314d039213735fdca6a412aeca6905fddccd33658f657616afbc")
        operation = process_operation("op:normal-golden")
        capability = authorize(epoch, operation)
        lease, authorization = causal.issue_for_trusted_adapter(
            operation=operation, capability_decision=capability,
            objective_decision=guard.evaluate_operation(operation),
            proposed_event=proposal(ledger, operation, capability),
        )
        causal.consume_for_trusted_adapter(
            lease, adapter_token=ADAPTER_TOKEN,
            executor=lambda _: ExecutionObservation.success({"normal": True}),
        )
        self.assertEqual(authorization["receipt_sha256"], "23eeef28174e1e0a41f16ccae0a644964c1fa6cf845d7dfbcb1ce20ac0bf5e18")
        self.assertEqual(causal.commit_receipts()[-1]["receipt_sha256"], "3667060a39f7042832f3ff2f9a2d64d6aeb70cf5b6acee2a3b15c4e667cf27a5")
        self.assertEqual(ledger.state_document()["state_sha256"], "15bd6ebd8c7fbdbb689889afb962a3b82321a51fdd29237a8fc05a49cb72fba8")
        self.assertNotIn("effect_uncertain", ledger.state_document())

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
        self.assert_uncertain_ledger(ledger)
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
                    self.assert_uncertain_ledger(ledger)
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
                self.assert_uncertain_ledger(ledger)
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
                self.assertEqual(ledger.state_document()["decision"], "ALLOW")
                self.assertNotIn("effect_uncertain", ledger.state_document())

    def test_known_success_evidence_failure_keeps_outer_durable_reservation(self):
        for boundary in ("append", "causal_receipt", "durable_cursor", "durable_receipt"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                _, _, _, _, epoch, _, _, _, ledger, causal, store, _, durable, _ = stack
                mediator = DurableGovernanceRuntimeMediator(
                    broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                    proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                )
                observed = ExecutionObservation.success({"effect_completed": True})
                calls = []
                with ExitStack() as faults:
                    if boundary == "causal_receipt":
                        faults.enter_context(patch.object(causal, "_append_commit", side_effect=OSError("private receipt path")))
                        evidence_code = "causal_commit_receipt_failed"
                    else:
                        faults.enter_context(patch.object(ledger, "append_verified_event", side_effect=OSError("private ledger path")))
                        evidence_code = "trajectory_append_failed"
                        if boundary in ("durable_cursor", "durable_receipt"):
                            method = "_latest_inner_commit" if boundary == "durable_cursor" else "_append_commit"
                            faults.enter_context(patch.object(durable, method, side_effect=OSError("private diagnostic path")))
                    result = mediator.mediate(
                        replace(durable_operation(), privilege_level_after=1),
                        lambda _: calls.append("effect completed") or observed,
                    )
                self.assertEqual(result["execution_outcome"], "UNKNOWN")
                self.assertEqual(result["result_sha256"], observed.result_sha256)
                self.assertEqual(result["reason_codes"], sorted([
                    "effect_succeeded", evidence_code, "durable_reservation_retained", "reconciliation_required",
                ]))
                self.assertEqual(verify_receipt(result), result)
                if boundary != "causal_receipt":
                    self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "EFFECT_SUCCEEDED_EVIDENCE_FAILED")
                    self.assertEqual(causal.commit_receipts()[-1]["result_sha256"], observed.result_sha256)
                if boundary in ("append", "causal_receipt"):
                    receipt = durable.commit_receipts()[-1]
                    self.assertEqual(receipt["effect_outcome"], "EFFECT_UNKNOWN_RESERVATION_STUCK")
                    self.assertEqual(receipt["result_sha256"], observed.result_sha256)
                    self.assertEqual(receipt["reason_codes"], sorted([
                        "effect_succeeded", evidence_code, "durable_reservation_retained", "reconciliation_required",
                    ]))
                    self.assertEqual(verify_durable_commit(receipt), receipt)
                self.assertTrue(store.read_state(root_id=DURABLE_ROOT)["reservation_active"])
                self.assertEqual(causal.state_document()["consumed_count"], 1)
                self.assertEqual(calls, ["effect completed"])
                self.assertEqual(mediator.trajectory_events()[0].decision, "ALLOW")
                self.assertEqual(replay([event.__dict__ for event in mediator.trajectory_events()]), analyze_trajectory(mediator.trajectory_events()))
                self.assert_uncertain_ledger(ledger)
                self.assertNotIn("private", repr(result))

    def test_direct_durable_evidence_error_retains_known_result_and_consumed_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = setup_durable_stack(str(Path(directory) / "governance.db"))
            _, _, _, _, epoch, _, guard, _, ledger, _, store, _, durable, _ = stack
            operation = durable_operation()
            capability = durable_authorize(epoch, operation)
            lease, _ = durable.issue_for_trusted_adapter(
                operation=operation, capability_decision=capability,
                objective_decision=guard.evaluate_operation(operation),
                proposed_event=durable_proposal(ledger, operation, capability),
            )
            observation = ExecutionObservation.success({"direct_effect": True})
            calls = []
            with patch.object(ledger, "append_verified_event", side_effect=OSError("private path")):
                with self.assertRaises(CausalEffectCommitError) as caught:
                    durable.consume_for_trusted_adapter(
                        lease, adapter_token=DURABLE_ADAPTER_TOKEN,
                        executor=lambda _: calls.append("entered") or observation,
                    )
            self.assertIsInstance(caught.exception, CausalEffectEvidenceError)
            self.assertIsInstance(caught.exception, ExecutionOutcomeUnknown)
            self.assertEqual(caught.exception.result_sha256, observation.result_sha256)
            receipt = durable.commit_receipts()[-1]
            self.assertEqual(receipt["result_sha256"], observation.result_sha256)
            self.assertIn(caught.exception.evidence_code, receipt["reason_codes"])
            self.assertEqual(verify_durable_commit(receipt), receipt)
            with self.assertRaisesRegex(DurableGovernanceError, "durable_lease_replayed"):
                durable.consume_for_trusted_adapter(
                    lease, adapter_token=DURABLE_ADAPTER_TOKEN, executor=lambda _: calls.append("reentered"),
                )
            self.assertEqual(calls, ["entered"])
            self.assertTrue(store.read_state(root_id=DURABLE_ROOT)["reservation_active"])

    def test_plain_durable_unknown_commit_explicitly_requires_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = setup_durable_stack(str(Path(directory) / "governance.db"))
            _, _, _, _, epoch, _, guard, _, ledger, _, store, _, durable, _ = stack
            operation = durable_operation()
            capability = durable_authorize(epoch, operation)
            lease, _ = durable.issue_for_trusted_adapter(
                operation=operation, capability_decision=capability,
                objective_decision=guard.evaluate_operation(operation),
                proposed_event=durable_proposal(ledger, operation, capability),
            )
            marker = ExecutionOutcomeUnknown("private executor details")

            def execute(_):
                raise marker

            with self.assertRaises(ExecutionOutcomeUnknown) as caught:
                durable.consume_for_trusted_adapter(lease, adapter_token=DURABLE_ADAPTER_TOKEN, executor=execute)
            self.assertIs(caught.exception, marker)
            receipt = durable.commit_receipts()[-1]
            self.assertEqual(receipt["effect_outcome"], "EFFECT_UNKNOWN_RESERVATION_STUCK")
            self.assertIn("effect_outcome_unknown", receipt["reason_codes"])
            self.assertIn("reconciliation_required", receipt["reason_codes"])
            self.assertEqual(receipt["result_sha256"], canonical_sha256({"error_type": "ExecutionOutcomeUnknown"}))
            self.assertEqual(verify_durable_commit(receipt), receipt)
            self.assertTrue(store.read_state(root_id=DURABLE_ROOT)["reservation_active"])
            self.assert_uncertain_ledger(ledger)

    def test_durable_post_success_faults_preserve_effect_and_actual_reservation_state(self):
        boundaries = {
            "missing_inner_receipt": "inner_commit_receipt_missing",
            "inner_cursor": "inner_commit_receipt_unavailable",
            "world": "durable_world_evidence_failed",
            "finalize": "durable_finalize_failed",
            "commit_ack_loss": "durable_finalize_failed",
            "commit_ack_loss_new_reservation": "durable_finalize_failed",
            "final_receipt": "durable_commit_receipt_failed",
            "final_receipt_new_reservation": "durable_commit_receipt_failed",
        }
        for boundary, evidence_code in boundaries.items():
            for interface in ("broker", "mediator"):
                with self.subTest(boundary=boundary, interface=interface), tempfile.TemporaryDirectory() as directory:
                    stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                    _, _, _, _, epoch, _, guard, _, ledger, causal, store, _, durable, _ = stack
                    operation = replace(durable_operation(), privilege_level_after=3)
                    observed = ExecutionObservation.success({"effect_completed": True})
                    calls = []
                    original_world = durable._local_world
                    original_commit = store.commit_effect

                    def world():
                        if calls:
                            raise OSError("private world path")
                        return original_world()

                    def commit(**kwargs):
                        if boundary != "finalize":
                            state = original_commit(**kwargs)
                            if boundary.endswith("new_reservation"):
                                store.reserve_effect(
                                    root_id=DURABLE_ROOT, expected_generation=state["generation"],
                                    expected_world_sha256=state["world_sha256"],
                                    reservation_id="peer:successor-reservation", reservation_payload_sha256="9" * 64,
                                )
                            if boundary == "final_receipt_new_reservation":
                                return state
                        raise OSError("private commit details")

                    def execute(_):
                        calls.append("effect completed")
                        return observed

                    with ExitStack() as faults:
                        if boundary == "missing_inner_receipt":
                            faults.enter_context(patch.object(durable, "_latest_inner_commit", return_value=ZERO_SHA256))
                        elif boundary == "inner_cursor":
                            faults.enter_context(patch.object(durable, "_latest_inner_commit", side_effect=OSError("private cursor details")))
                        elif boundary == "world":
                            faults.enter_context(patch.object(durable, "_local_world", side_effect=world))
                        elif boundary in ("finalize", "commit_ack_loss", "commit_ack_loss_new_reservation", "final_receipt_new_reservation"):
                            faults.enter_context(patch.object(store, "commit_effect", side_effect=commit))
                            if boundary == "final_receipt_new_reservation":
                                faults.enter_context(patch.object(durable, "_append_commit", side_effect=OSError("private receipt details")))
                        else:
                            faults.enter_context(patch.object(durable, "_append_commit", side_effect=OSError("private receipt details")))
                        if interface == "broker":
                            capability = durable_authorize(epoch, operation)
                            lease, _ = durable.issue_for_trusted_adapter(
                                operation=operation, capability_decision=capability,
                                objective_decision=guard.evaluate_operation(operation),
                                proposed_event=durable_proposal(ledger, operation, capability),
                            )
                            with self.assertRaises(DurableGovernanceError) as caught:
                                durable.consume_for_trusted_adapter(lease, adapter_token=DURABLE_ADAPTER_TOKEN, executor=execute)
                            self.assertIsInstance(caught.exception, ExecutionOutcomeUnknown)
                            from sdk.liminal_durable_governance_fence import DurableEffectEvidenceError
                            self.assertIsInstance(caught.exception, DurableEffectEvidenceError)
                            self.assertEqual(caught.exception.result_sha256, observed.result_sha256)
                            self.assertEqual(caught.exception.evidence_code, evidence_code)
                            self.assertEqual(caught.exception.durable_commit_confirmed, boundary.startswith("final_receipt"))
                            expected_status = "released" if boundary.startswith(("commit_ack_loss", "final_receipt")) else "retained"
                            self.assertEqual(caught.exception.reservation_status, expected_status)
                            self.assertNotIn("private", str(caught.exception))
                            with self.assertRaisesRegex(DurableGovernanceError, "durable_lease_replayed"):
                                durable.consume_for_trusted_adapter(lease, adapter_token=DURABLE_ADAPTER_TOKEN, executor=execute)
                        else:
                            mediator = DurableGovernanceRuntimeMediator(
                                broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                                proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                            )
                            result = mediator.mediate(operation, execute)
                            self.assertEqual(result["execution_outcome"], "UNKNOWN")
                            self.assertEqual(result["result_sha256"], observed.result_sha256)
                            self.assertIn(evidence_code, result["reason_codes"])
                            self.assertIn("effect_succeeded", result["reason_codes"])
                            self.assertIn("reconciliation_required", result["reason_codes"])
                            self.assertEqual(verify_receipt(result), result)
                            if boundary.startswith(("commit_ack_loss", "final_receipt")):
                                self.assertIn("durable_reservation_released", result["reason_codes"])
                                self.assertNotIn("durable_reservation_retained", result["reason_codes"])
                            event = mediator.trajectory_events()[0]
                            self.assertEqual((event.decision, event.privilege_level_after), ("ALLOW", 3))
                            self.assertEqual(analyze_trajectory(mediator.trajectory_events())["risk_score"], 15)
                            self.assertEqual(replay([event.__dict__]), analyze_trajectory(mediator.trajectory_events()))
                            self.assertNotIn("private", repr(result))
                    self.assertEqual(calls, ["effect completed"])
                    self.assertEqual(ledger.event_count, 1)
                    self.assertEqual(causal.commit_receipts()[-1]["effect_outcome"], "SUCCEEDED")
                    self.assert_uncertain_ledger(ledger)
                    state = store.read_state(root_id=DURABLE_ROOT)
                    finalized = boundary.startswith(("commit_ack_loss", "final_receipt"))
                    self.assertEqual(state["reservation_active"], not finalized or boundary.endswith("new_reservation"))
                    self.assertEqual(state["generation"], 1 if finalized else 0)
                    if boundary.endswith("new_reservation"):
                        # The old failure cannot claim or mutate the successor's reservation.
                        self.assertEqual(state["reservation_id_sha256"], canonical_sha256("peer:successor-reservation"))
                        self.assertEqual(state["reservation_payload_sha256"], "9" * 64)
                    if not boundary.startswith("final_receipt"):
                        receipt = durable.commit_receipts()[-1]
                        self.assertEqual(receipt["effect_outcome"], "EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED")
                        self.assertEqual(receipt["result_sha256"], observed.result_sha256)
                        self.assertIn(evidence_code, receipt["reason_codes"])
                        self.assertEqual(verify_durable_commit(receipt), receipt)
                    # A different mediator cannot bypass the durable failure through its shared causal ledger.
                    peer = CausalBoundEffectRuntimeMediator(
                        broker=epoch, causal_effect_broker=causal, adapter_token=DURABLE_ADAPTER_TOKEN,
                        proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                    )
                    followup = peer.mediate(durable_operation("op:peer-after-failure"), execute)
                    self.assertEqual(followup["execution_outcome"], "FAILED")
                    self.assertEqual(calls, ["effect completed"])
                    self.assertEqual(ledger.event_count, 1)

    def test_durable_finalize_marker_survives_diagnostic_read_and_append_cascades(self):
        for diagnostic in ("read", "append", "both"):
            for commit_before_error in (False, True):
                with self.subTest(diagnostic=diagnostic, committed=commit_before_error), tempfile.TemporaryDirectory() as directory:
                    stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                    _, _, _, _, epoch, _, _, _, ledger, _, store, _, durable, _ = stack
                    original_read = store.read_state
                    original_commit = store.commit_effect
                    dispatched = []

                    def read(**kwargs):
                        if dispatched:
                            raise OSError("private diagnostic read")
                        return original_read(**kwargs)

                    def commit(**kwargs):
                        if commit_before_error:
                            original_commit(**kwargs)
                        raise OSError("private primary failure")

                    observed = ExecutionObservation.success({"effect_completed": True})
                    mediator = DurableGovernanceRuntimeMediator(
                        broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                        proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                    )
                    with ExitStack() as faults:
                        faults.enter_context(patch.object(store, "commit_effect", side_effect=commit))
                        if diagnostic in ("read", "both"):
                            faults.enter_context(patch.object(store, "read_state", side_effect=read))
                        if diagnostic in ("append", "both"):
                            faults.enter_context(patch.object(durable, "_append_commit", side_effect=OSError("private diagnostic append")))
                        result = mediator.mediate(
                            replace(durable_operation(), privilege_level_after=3),
                            lambda _: dispatched.append("effect completed") or observed,
                        )
                    self.assertEqual(result["execution_outcome"], "UNKNOWN")
                    self.assertEqual(result["result_sha256"], observed.result_sha256)
                    self.assertIn("durable_finalize_failed", result["reason_codes"])
                    self.assertIn("reconciliation_required", result["reason_codes"])
                    if diagnostic in ("read", "both"):
                        self.assertIn("durable_reservation_unconfirmed", result["reason_codes"])
                        self.assertNotIn("durable_reservation_retained", result["reason_codes"])
                    self.assertNotIn("private", repr(result))
                    self.assertEqual(verify_receipt(result), result)
                    self.assertEqual(dispatched, ["effect completed"])
                    self.assertEqual(original_read(root_id=DURABLE_ROOT)["reservation_active"], not commit_before_error)
                    self.assert_uncertain_ledger(ledger)

    def test_durable_pre_dispatch_failures_keep_failed_without_effect_uncertainty(self):
        for boundary in ("read", "world", "cursor"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                _, _, _, _, epoch, _, _, _, ledger, causal, store, _, durable, _ = stack
                mediator = DurableGovernanceRuntimeMediator(
                    broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                    proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                )
                target, method = {
                    "read": (store, "read_state"), "world": (durable, "_local_world"),
                    "cursor": (causal, "commit_cursor"),
                }[boundary]
                calls = []
                with patch.object(target, method, side_effect=OSError("private pre-dispatch failure")):
                    result = mediator.mediate(
                        replace(durable_operation(), privilege_level_after=3),
                        lambda _: calls.append("entered"),
                    )
                self.assertEqual(result["execution_outcome"], "FAILED")
                self.assertEqual(calls, [])
                self.assertEqual(ledger.event_count, 0)
                self.assertNotIn("effect_uncertain", ledger.state_document())
                self.assertEqual(mediator.trajectory_events()[0].decision, "BLOCK")

    def test_durable_ordinary_success_and_failure_keep_published_hashes(self):
        goldens = {
            "success": ("d7deb1106aeddaea9b714de2346e3e1bb25719745cd24701dfc5117835b1c2d7", "f3561d1ebcb4be77ae301d5912e4e72abdc72deb40b0d3dbbc9f00538e3eb3fe"),
            "failure": ("c87122183ac5701c5e69a294744cb070286cd9b8aa69300c70b28f5d3cb358c8", "64226c3b9e0583665abb666925f641bb1558a21df453e2aacbd17477a909a17c"),
        }
        for case, (runtime_sha, durable_sha) in goldens.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                stack = setup_durable_stack(str(Path(directory) / "governance.db"))
                _, _, _, _, epoch, _, _, _, _, _, _, _, durable, _ = stack
                mediator = DurableGovernanceRuntimeMediator(
                    broker=epoch, durable_effect_broker=durable, adapter_token=DURABLE_ADAPTER_TOKEN,
                    proposal_factory=lambda op, cap, journal: durable_proposal(journal, op, cap),
                )

                def execute(_):
                    if case == "failure":
                        raise RuntimeError("private")
                    return ExecutionObservation.success({"normal": True})

                result = mediator.mediate(durable_operation("op:durable-golden"), execute)
                self.assertEqual(result["receipt_sha256"], runtime_sha)
                self.assertEqual(durable.commit_receipts()[-1]["receipt_sha256"], durable_sha)


if __name__ == "__main__":
    unittest.main()
