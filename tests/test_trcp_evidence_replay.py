"""TRCP v0.2 - Evidence adapter and independent replay tests.

Happy-path PASS plus adversarial mutation tests. Every mutation must
produce FAIL or a specific verifier check failure.

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.
"""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import (
    AuthorizationRecord,
    MockProvider,
    ScopeEnvelope,
    TRCPSimulator,
    run_default_scenario,
)
from sdk.liminal_trcp.evidence import (
    AUTHORIZATION_NODE,
    PRIMARY_RUN_NODE,
    build_evidence_bundle,
)
from sdk.liminal_trcp.replay import verify_evidence_bundle

ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = ROOT / "scripts" / "replay_trcp_evidence.py"


def _run_scenario_with_two_actions():
    authorization = AuthorizationRecord(
        authorization_id="auth:trcp-demo",
        subject_id="researcher:fixture",
        asset_id="fixture:repo",
        valid_from=900,
        valid_until=2000,
        allowed_activity_classes=("STATIC_ANALYSIS",),
    )
    scope = ScopeEnvelope(
        scope_id="scope:trcp-demo",
        authorization_id=authorization.authorization_id,
        allowed_targets=("fixture:repo",),
        allowed_actions=("ANALYZE_FIXTURE", "OPTIONAL_STEP"),
    )
    task = {
        "task_id": "task:2",
        "asset_id": "fixture:repo",
        "activity_class": "STATIC_ANALYSIS",
        "action": "ANALYZE_FIXTURE",
        "fixture": "synthetic-safe-fixture-v1",
    }
    primary = MockProvider("provider:A", "mock-model-a", "ACCESS_RESTRICTED")
    fallback = MockProvider(
        "provider:B",
        "mock-model-b",
        "COMPLETED",
        synthetic_finding={
            "finding_class": "SYNTHETIC_BOUNDARY_CHECK",
            "location_reference": "fixture://sample#L1",
            "summary": "Synthetic fixture matches expected marker",
            "severity_claim": "LOW",
            "confidence_claim": "FIXTURE",
        },
    )
    simulator = TRCPSimulator(authorization, scope)
    simulator.authorize()
    simulator.execute_primary(task, primary)
    simulator.record_failover(fallback)
    simulator.execute_fallback(task, fallback)
    simulator.verify(reproduced=True)
    simulator.confirm_finding()
    return simulator.report()


def _recalculate_bundle_hash(bundle):
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    bundle["bundle_sha256"] = canonical_sha256(body)


def _rebuild_trace_hashes(trace):
    previous = "0" * 64
    for i, event in enumerate(trace):
        event["sequence"] = i + 1
        event["previous_event_sha256"] = previous
        core = {k: v for k, v in event.items() if k != "event_sha256"}
        event["event_sha256"] = canonical_sha256(core)
        previous = event["event_sha256"]


class EvidenceAdapterHappyPathTests(unittest.TestCase):
    def test_bundle_is_deterministic(self):
        first = build_evidence_bundle(run_default_scenario())
        second = build_evidence_bundle(run_default_scenario())
        self.assertEqual(first, second)

    def test_bundle_has_correct_schema(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertEqual(bundle["schema"], "liminal-trcp-evidence-v0.2")

    def test_bundle_sha256_matches_canonical(self):
        bundle = build_evidence_bundle(run_default_scenario())
        body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
        self.assertEqual(bundle["bundle_sha256"], canonical_sha256(body))

    def test_bundle_contains_causal_lineage(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        self.assertGreater(len(lineage), 0)
        for edge in lineage:
            self.assertIn("edge_id", edge)
            self.assertIn("from", edge)
            self.assertIn("to", edge)
            self.assertIn("relation", edge)
            self.assertIn("evidence_ref", edge)


class DeepCopyIndependenceTests(unittest.TestCase):
    def test_bundle_mutate_does_not_affect_source_report(self):
        report = run_default_scenario()
        bundle = build_evidence_bundle(report)
        bundle["trace"][0]["payload"]["mutated"] = True
        self.assertNotIn("mutated", report["trace"][0]["payload"])

    def test_report_mutate_does_not_affect_bundle(self):
        report = run_default_scenario()
        bundle = build_evidence_bundle(report)
        original_auth_id = bundle["authorization"]["authorization_id"]
        report["authorization"]["authorization_id"] = "auth:mutated-after-bundle"
        self.assertEqual(bundle["authorization"]["authorization_id"], original_auth_id)

    def test_bundle_deep_copy_of_provider_runs(self):
        report = run_default_scenario()
        bundle = build_evidence_bundle(report)
        bundle["provider_runs"][0]["new_field"] = "injected"
        self.assertNotIn("new_field", report["provider_runs"][0])

    def test_bundle_deep_copy_of_finding(self):
        report = run_default_scenario()
        bundle = build_evidence_bundle(report)
        self.assertIsNotNone(bundle["finding"])
        bundle["finding"]["status"] = "TAMPERED"
        self.assertNotEqual(report["finding"]["status"], "TAMPERED")


class ReplayVerifierHappyPathTests(unittest.TestCase):
    def test_happy_path_pass(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["schema"], "liminal-trcp-replay-receipt-v0.2")

    def test_receipt_is_deterministic(self):
        bundle = build_evidence_bundle(run_default_scenario())
        first = verify_evidence_bundle(bundle)
        second = verify_evidence_bundle(bundle)
        self.assertEqual(first, second)

    def test_receipt_sha256_matches(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        body = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
        self.assertEqual(receipt["receipt_sha256"], canonical_sha256(body))

    def test_all_checks_pass(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        for check in receipt["checks"]:
            self.assertEqual(check["result"], "PASS", "check " + check["id"] + " failed")

    def test_fail_receipt_has_failure_detail(self):
        bundle = build_evidence_bundle(run_default_scenario())
        bundle["authorization"]["authorization_id"] = "auth:mutated"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn("failed_check", receipt)
        self.assertIn("failure_detail", receipt)


class StateTransitionChainTests(unittest.TestCase):
    def test_first_transition_must_start_from_new(self):
        bundle = build_evidence_bundle(run_default_scenario())
        trace = bundle["trace"]
        found = False
        for event in trace:
            if event["kind"] == "STATE_TRANSITION":
                event["payload"]["from"] = "AUTHORIZED"
                found = True
                break
        self.assertTrue(found, "expected at least one STATE_TRANSITION")
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "STATE_TRANSITION")

    def test_disconnected_state_chain_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        trace = bundle["trace"]
        transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        self.assertGreaterEqual(len(transitions), 2, "need at least 2 transitions")
        transitions[1]["payload"]["from"] = "NEW"
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "STATE_TRANSITION")

    def test_valid_hashes_illegal_chain_still_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        trace = bundle["trace"]
        transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        self.assertGreaterEqual(len(transitions), 2, "need at least 2 transitions")
        t0_from = transitions[0]["payload"]["from"]
        transitions[1]["payload"]["from"] = t0_from
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "STATE_TRANSITION")


class FallbackRunIdentityTests(unittest.TestCase):
    def test_primary_run_id_is_run1(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertIsNotNone(bundle["provider_runs"][0].get("run_id"))
        primary_run_id = bundle["provider_runs"][0]["run_id"]
        self.assertEqual(primary_run_id, "run:1")

    def test_fallback_run_is_not_misidentified(self):
        bundle = build_evidence_bundle(run_default_scenario())
        primary_run_id = bundle["provider_runs"][0]["run_id"]
        for run in bundle["provider_runs"][1:]:
            self.assertNotEqual(run["run_id"], primary_run_id)

    def test_causal_order_passes_with_correct_ids(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")
        causal_check = next(c for c in receipt["checks"] if c["id"] == "CAUSAL_ORDER")
        self.assertEqual(causal_check["result"], "PASS")

    def test_fallback_masked_as_run10_is_still_identified(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertGreaterEqual(len(bundle["provider_runs"]), 2)
        primary_run_id = bundle["provider_runs"][0]["run_id"]
        self.assertNotEqual("run:10", primary_run_id)
        bundle["provider_runs"][1]["run_id"] = "run:10"
        trace = bundle["trace"]
        for event in trace:
            if event["kind"] == "PROVIDER_RUN_RECORDED":
                payload = event["payload"]
                if payload.get("run_id") != primary_run_id:
                    payload["run_id"] = "run:10"
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")

    def test_fallback_with_missing_run_id_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertGreaterEqual(len(bundle["provider_runs"]), 2)
        primary_run_id = bundle["provider_runs"][0]["run_id"]
        bundle["provider_runs"][1].pop("run_id", None)
        trace = bundle["trace"]
        for event in trace:
            if event["kind"] == "PROVIDER_RUN_RECORDED":
                payload = event["payload"]
                if payload.get("run_id") != primary_run_id:
                    payload["run_id"] = ""
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "FAILOVER_DECISION_REQUIRED")

    def test_missing_primary_run_id_does_not_misidentify_fallback(self):
        bundle = build_evidence_bundle(run_default_scenario())
        primary_run_id = bundle["provider_runs"][0]["run_id"]
        bundle["provider_runs"][0].pop("run_id", None)
        trace = bundle["trace"]
        for event in trace:
            if event["kind"] == "PROVIDER_RUN_RECORDED":
                payload = event["payload"]
                if payload.get("run_id") == primary_run_id:
                    payload["run_id"] = ""
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")
        causal_check = next(c for c in receipt["checks"] if c["id"] == "CAUSAL_ORDER")
        self.assertEqual(causal_check["result"], "PASS")

    def test_early_fallback_run_before_decision_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        failover_run_id = bundle["provider_runs"][1].get("run_id")
        trace = bundle["trace"]
        decision_idx = next(
            i for i, e in enumerate(trace) if e["kind"] == "FAILOVER_DECISION_RECORDED"
        )
        decision_event = trace[decision_idx]
        early_run_event = {
            "kind": "PROVIDER_RUN_RECORDED",
            "observed_at_unix": decision_event["observed_at_unix"],
            "payload": {
                "run_id": failover_run_id,
                "scope_id": decision_event["payload"].get("scope_id"),
            },
        }
        trace.insert(decision_idx, early_run_event)
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        failover_check = next(
            c for c in receipt["checks"] if c["id"] == "FAILOVER_DECISION_REQUIRED"
        )
        self.assertEqual(failover_check["result"], "FAIL")

    def test_three_runs_middle_task_hash_mismatch_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertEqual(len(bundle["provider_runs"]), 2)
        middle_run = copy.deepcopy(bundle["provider_runs"][1])
        middle_run["run_id"] = "run:mismatch"
        middle_run["normalized_task_hash"] = "0" * 64
        bundle["provider_runs"].insert(1, middle_run)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "TASK_IDENTITY")

    def test_three_runs_all_matching_hashes_pass(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertEqual(len(bundle["provider_runs"]), 2)
        extra_run = copy.deepcopy(bundle["provider_runs"][1])
        extra_run["run_id"] = "run:extra"
        bundle["provider_runs"].append(extra_run)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")
        task_check = next(c for c in receipt["checks"] if c["id"] == "TASK_IDENTITY")
        self.assertEqual(task_check["result"], "PASS")


class ProhibitedActionSeparateScopeTests(unittest.TestCase):
    def test_initial_scope_overlap_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertIn("ANALYZE_FIXTURE", bundle["initial_scope"]["allowed_actions"])
        initial_prohibited = list(bundle["initial_scope"]["prohibited_actions"])
        bundle["initial_scope"]["prohibited_actions"] = [*initial_prohibited, "ANALYZE_FIXTURE"]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        prohibited_check = next(
            c for c in receipt["checks"] if c["id"] == "PROHIBITED_ACTION"
        )
        self.assertEqual(prohibited_check["result"], "FAIL")

    def test_effective_scope_overlap_fails(self):
        bundle = build_evidence_bundle(run_default_scenario())
        effective_prohibited = list(bundle["effective_scope"]["prohibited_actions"])
        self.assertNotIn("ANALYZE_FIXTURE", effective_prohibited)
        bundle["effective_scope"]["prohibited_actions"] = ["ANALYZE_FIXTURE", *effective_prohibited]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "PROHIBITED_ACTION")

    def test_legal_narrowing_passes(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertIn("ANALYZE_FIXTURE", bundle["effective_scope"]["allowed_actions"])
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")

    def test_narrowing_by_moving_to_prohibited_passes(self):
        scenario = _run_scenario_with_two_actions()
        bundle = build_evidence_bundle(scenario)
        self.assertGreaterEqual(len(bundle["initial_scope"]["allowed_actions"]), 2)
        initial_allowed = sorted(bundle["initial_scope"]["allowed_actions"])
        narrowed = initial_allowed[:1]
        removed = initial_allowed[1]
        bundle["effective_scope"]["allowed_actions"] = narrowed
        effective_prohibited = list(bundle["effective_scope"]["prohibited_actions"])
        bundle["effective_scope"]["prohibited_actions"] = [*effective_prohibited, removed]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")


class AdversarialMutationTests(unittest.TestCase):
    def _valid_bundle(self):
        return build_evidence_bundle(run_default_scenario())

    def test_01_change_authorization_id_fails(self):
        bundle = self._valid_bundle()
        bundle["authorization"]["authorization_id"] = "auth:mutated"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "AUTHORIZATION_CONTINUITY")

    def test_02_broaden_effective_scope_targets_fails(self):
        bundle = self._valid_bundle()
        self.assertIn("allowed_targets", bundle["effective_scope"])
        bundle["effective_scope"]["allowed_targets"] = [
            "fixture:repo",
            "fixture:other",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_03_add_prohibited_action_to_allowed_fails(self):
        bundle = self._valid_bundle()
        bundle["effective_scope"]["allowed_actions"] = [
            "ANALYZE_FIXTURE",
            "LIVE_EXPLOIT",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(receipt["failed_check"], {"SCOPE_MONOTONICITY", "PROHIBITED_ACTION"})

    def test_04_reorder_provider_transitions_fails(self):
        bundle = self._valid_bundle()
        trace = bundle["trace"]
        transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        self.assertGreaterEqual(len(transitions), 2, "need at least 2 transitions")
        transitions[0]["payload"]["to"], transitions[1]["payload"]["to"] = (
            transitions[1]["payload"]["to"],
            transitions[0]["payload"]["to"],
        )
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"STATE_TRANSITION", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_05_remove_failover_decision_fails(self):
        bundle = self._valid_bundle()
        self.assertIsNotNone(bundle["failover_decision"])
        bundle["failover_decision"] = None
        trace = bundle["trace"]
        bundle["trace"] = [
            e for e in trace if e["kind"] != "FAILOVER_DECISION_RECORDED"
        ]
        _rebuild_trace_hashes(bundle["trace"])
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"FAILOVER_DECISION_REQUIRED", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_06_change_fallback_task_hash_fails(self):
        bundle = self._valid_bundle()
        self.assertGreaterEqual(len(bundle["provider_runs"]), 2)
        bundle["provider_runs"][-1]["normalized_task_hash"] = "deadbeef" * 8
        run_body = {
            k: v for k, v in bundle["provider_runs"][-1].items()
            if k != "record_sha256"
        }
        bundle["provider_runs"][-1]["record_sha256"] = canonical_sha256(run_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "TASK_IDENTITY")

    def test_07_mutate_trace_event_without_rehash_fails(self):
        bundle = self._valid_bundle()
        trace = bundle["trace"]
        found = False
        for event in trace:
            if event["kind"] == "PROVIDER_RUN_RECORDED":
                event["payload"]["outcome"] = "COMPLETED"
                found = True
                break
        self.assertTrue(found, "expected PROVIDER_RUN_RECORDED event")
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"TRACE_HASH_CHAIN", "BUNDLE_INTEGRITY"},
        )

    def test_08_illegal_state_transition_with_valid_hashes_fails(self):
        bundle = self._valid_bundle()
        trace = bundle["trace"]
        transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        self.assertGreaterEqual(len(transitions), 3, "need at least 3 transitions")
        transitions[0]["payload"]["to"] = "VERIFYING"
        transitions[1]["payload"]["from"] = "VERIFYING"
        transitions[1]["payload"]["to"] = "ACTIVE"
        transitions[2]["payload"]["from"] = "ACTIVE"
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"STATE_TRANSITION", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_09_non_monotonic_timestamp_fails(self):
        bundle = self._valid_bundle()
        trace = bundle["trace"]
        self.assertGreaterEqual(len(trace), 3, "need at least 3 trace events")
        trace[2]["observed_at_unix"] = trace[0]["observed_at_unix"] - 100
        _rebuild_trace_hashes(trace)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"TEMPORAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_10_confirmed_without_reproduced_fails(self):
        bundle = self._valid_bundle()
        self.assertIsNotNone(bundle["finding"])
        self.assertIsNotNone(bundle["verification"])
        bundle["finding"]["status"] = "CONFIRMED"
        finding_body = {
            k: v for k, v in bundle["finding"].items()
            if k != "record_sha256"
        }
        bundle["finding"]["record_sha256"] = canonical_sha256(finding_body)
        bundle["verification"]["result"] = "NOT_REPRODUCED"
        ver_body = {
            k: v for k, v in bundle["verification"].items()
            if k != "record_sha256"
        }
        bundle["verification"]["record_sha256"] = canonical_sha256(ver_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "VERIFICATION_CLOSURE")

    def test_11_verification_status_mismatch_fails(self):
        bundle = self._valid_bundle()
        self.assertIsNotNone(bundle["verification"])
        self.assertIsNotNone(bundle["finding"])
        bundle["verification"]["finding_id"] = "finding:different-id"
        ver_body = {
            k: v for k, v in bundle["verification"].items()
            if k != "record_sha256"
        }
        bundle["verification"]["record_sha256"] = canonical_sha256(ver_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "VERIFICATION_CONSISTENCY")

    def test_12_tampered_bundle_hash_fails(self):
        bundle = self._valid_bundle()
        bundle["authorization"]["authority_source"] = "tampered"
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "BUNDLE_INTEGRITY")

    def test_13_broaden_effective_actions_fails(self):
        bundle = self._valid_bundle()
        bundle["effective_scope"]["allowed_actions"] = [
            "ANALYZE_FIXTURE",
            "ACTIVE_VALIDATE",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_14_change_initial_scope_authorization_fails(self):
        bundle = self._valid_bundle()
        bundle["initial_scope"]["authorization_id"] = "auth:different"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "AUTHORIZATION_CONTINUITY")

    def test_15_empty_trace_preserves_hash_fails_integrity(self):
        bundle = self._valid_bundle()
        original_hash = bundle["bundle_sha256"]
        bundle["trace"] = []
        bundle["bundle_sha256"] = original_hash
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "BUNDLE_INTEGRITY")

    def test_16_broaden_network_mode_fails(self):
        bundle = self._valid_bundle()
        bundle["effective_scope"]["network_mode"] = "EXTERNAL"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_17_extend_scope_expiry_fails(self):
        bundle = self._valid_bundle()
        bundle["effective_scope"]["expires_at"] = 9999
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_18_non_numeric_timestamp_fails(self):
        bundle = self._valid_bundle()
        bundle["trace"][2]["observed_at_unix"] = "not-a-number"
        _rebuild_trace_hashes(bundle["trace"])
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "TEMPORAL_ORDER")

    def test_19_non_numeric_expiry_fails(self):
        bundle = self._valid_bundle()
        bundle["effective_scope"]["expires_at"] = "not-a-number"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_20_empty_primary_task_hash_fails(self):
        bundle = self._valid_bundle()
        bundle["provider_runs"][0]["normalized_task_hash"] = ""
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "TASK_IDENTITY")


class ReplayIndependenceTests(unittest.TestCase):
    def test_replay_does_not_import_simulator(self):
        from sdk.liminal_trcp import replay
        replay_names = set(replay.__dict__)
        self.assertNotIn("TRCPSimulator", replay_names)
        self.assertNotIn("execute_primary", replay_names)
        self.assertNotIn("execute_fallback", replay_names)

    def test_replay_uses_only_bundle_data(self):
        bundle = build_evidence_bundle(run_default_scenario())
        bundle_copy = copy.deepcopy(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(bundle, bundle_copy)
        self.assertEqual(receipt["result"], "PASS")


class CausalLineageTests(unittest.TestCase):
    def test_lineage_is_deterministic(self):
        bundle1 = build_evidence_bundle(run_default_scenario())
        bundle2 = build_evidence_bundle(run_default_scenario())
        self.assertEqual(bundle1["causal_lineage"], bundle2["causal_lineage"])

    def test_lineage_contains_authorization_to_primary(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        first_edge = lineage[0]
        self.assertEqual(first_edge["from"], "AUTHORIZATION")
        self.assertEqual(first_edge["to"], "PRIMARY_RUN")

    def test_lineage_edge_ids_are_deterministic(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        for edge in lineage:
            self.assertTrue(edge["edge_id"].startswith("edge:"))

    def test_lineage_edges_refer_to_existing_nodes(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        existing_nodes = {AUTHORIZATION_NODE, PRIMARY_RUN_NODE}
        for edge in lineage:
            self.assertIn(edge["from"], existing_nodes,
                          "edge from=" + edge["from"] + " references non-existing node")
            existing_nodes.add(edge["to"])

    def test_lineage_contains_fallback_to_finding_edge(self):
        bundle = build_evidence_bundle(run_default_scenario())
        edges = {(e["from"], e["to"]) for e in bundle["causal_lineage"]}
        self.assertIn(("FALLBACK_RUN", "FINDING"), edges)

    def test_lineage_contains_verification_to_closed_edge(self):
        bundle = build_evidence_bundle(run_default_scenario())
        edges = {(e["from"], e["to"]) for e in bundle["causal_lineage"]}
        self.assertIn(("VERIFICATION", "CLOSED"), edges)

    def test_lineage_contains_failover_scope_edges(self):
        bundle = build_evidence_bundle(run_default_scenario())
        edges = {(e["from"], e["to"]) for e in bundle["causal_lineage"]}
        self.assertIn(("PROVIDER_FAILURE", "FAILOVER_DECISION"), edges)
        self.assertIn(("FAILOVER_DECISION", "EFFECTIVE_SCOPE"), edges)
        self.assertIn(("EFFECTIVE_SCOPE", "FALLBACK_RUN"), edges)


class StateTransitionParityTests(unittest.TestCase):
    def test_allowed_transitions_match_simulator(self):
        from sdk.liminal_trcp import _ALLOWED_TRANSITIONS
        from sdk.liminal_trcp.replay import ALLOWED_TRANSITIONS

        self.assertEqual(set(ALLOWED_TRANSITIONS), set(_ALLOWED_TRANSITIONS))
        for state, targets in _ALLOWED_TRANSITIONS.items():
            self.assertEqual(
                ALLOWED_TRANSITIONS[state],
                frozenset(targets),
                f"transition targets differ for {state}",
            )

    def test_terminal_states_match_simulator_dead_ends(self):
        from sdk.liminal_trcp import _ALLOWED_TRANSITIONS
        from sdk.liminal_trcp.replay import TERMINAL_STATES

        dead_ends = frozenset(
            state for state, targets in _ALLOWED_TRANSITIONS.items() if not targets
        )
        self.assertEqual(TERMINAL_STATES, dead_ends)


class DeterministicReceiptTests(unittest.TestCase):
    def test_same_bundle_same_receipt_hash(self):
        bundle = build_evidence_bundle(run_default_scenario())
        r1 = verify_evidence_bundle(bundle)
        r2 = verify_evidence_bundle(bundle)
        self.assertEqual(r1["receipt_sha256"], r2["receipt_sha256"])

    def test_pass_and_fail_receipts_differ(self):
        bundle_pass = build_evidence_bundle(run_default_scenario())
        r1 = verify_evidence_bundle(bundle_pass)
        self.assertEqual(r1["result"], "PASS")

        bundle_fail = copy.deepcopy(bundle_pass)
        bundle_fail["authorization"]["authorization_id"] = "auth:mutated"
        _recalculate_bundle_hash(bundle_fail)
        r2 = verify_evidence_bundle(bundle_fail)
        self.assertEqual(r2["result"], "FAIL")
        self.assertNotEqual(r1["receipt_sha256"], r2["receipt_sha256"])


class FailoverWithoutFindingTests(unittest.TestCase):
    def test_no_finding_verification_path(self):
        report = run_default_scenario()
        report_no_finding = copy.deepcopy(report)
        report_no_finding["finding"] = None
        report_no_finding["verification"] = None
        body = {k: v for k, v in report_no_finding.items() if k != "report_sha256"}
        report_no_finding["report_sha256"] = canonical_sha256(body)
        bundle = build_evidence_bundle(report_no_finding)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")


class CliExitCodeTests(unittest.TestCase):
    def _run_cli(self):
        return subprocess.run(
            [sys.executable, str(CLI_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=60,
            check=False,
        )

    def test_cli_exit_code_zero_on_pass(self):
        result = self._run_cli()
        self.assertEqual(result.returncode, 0, "stderr: " + result.stderr)

    def test_cli_output_is_valid_json(self):
        result = self._run_cli()
        self.assertEqual(result.returncode, 0, "stderr: " + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["result"], "PASS")


if __name__ == "__main__":
    unittest.main()
