"""Tests for the TRCP v0.3 local contract-state consumer fixture and adapter."""

from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import run_default_scenario
from sdk.liminal_trcp.consumer import (
    DOUBLE_RELEASE_PATH,
    ILLEGAL_PATH,
    VALID_PATH,
    EscrowFixture,
    IllegalTransition,
    contract_fixture,
    run_contract_consumer,
    workload_result,
)
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import verify_evidence_bundle


class WorkloadFixtureTests(unittest.TestCase):
    def test_valid_path_has_no_violations(self):
        result = workload_result(VALID_PATH)
        self.assertEqual(result["final_state"], "RELEASED")
        self.assertEqual(result["violations"], [])

    def test_illegal_path_violates_terminal_state_exclusivity(self):
        result = workload_result(ILLEGAL_PATH)
        self.assertEqual(result["final_state"], "RELEASED")
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["terminal-state-exclusivity"],
        )

    def test_double_release_violates_payout_conservation(self):
        result = workload_result(DOUBLE_RELEASE_PATH)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["payout-conservation"],
        )

    def test_unauthorized_actor_is_rejected(self):
        fixture = EscrowFixture()
        with self.assertRaises(IllegalTransition):
            fixture.fund("seller")

    def test_unauthorized_actor_is_classified_as_authorization(self):
        result = workload_result(("FUNDED",), actor="seller")
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["authorization"],
        )

    def test_release_before_funding_is_transition_validation(self):
        result = workload_result(("RELEASED",))
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["transition-validation"],
        )

    def test_steps_are_recorded_in_order(self):
        result = workload_result(VALID_PATH)
        self.assertEqual(
            [step["action"] for step in result["path"]],
            ["fund", "release_request", "release"],
        )

    def test_steps_preserve_true_pre_and_post_states(self):
        result = workload_result(VALID_PATH)
        states = [(step["pre_state"], step["post_state"]) for step in result["path"]]
        self.assertEqual(
            states,
            [
                ("CREATED", "FUNDED"),
                ("FUNDED", "RELEASE_REQUESTED"),
                ("RELEASE_REQUESTED", "RELEASED"),
            ],
        )


class ContractConsumerPipelineTests(unittest.TestCase):
    def test_valid_path_produces_clean_passing_receipt(self):
        outcome = run_contract_consumer(VALID_PATH)
        self.assertIsNone(outcome["report"]["finding"])
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertEqual(outcome["report"]["final_state"], "CLOSED")

    def test_illegal_path_finding_is_high_severity(self):
        outcome = run_contract_consumer(ILLEGAL_PATH)
        finding = outcome["report"]["finding"]
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity_claim"], "HIGH")
        self.assertEqual(finding["finding_class"], "CONTRACT_INVARIANT_VIOLATION")
        self.assertIn("terminal-state-exclusivity", finding["summary"])
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_double_release_finding_reports_payout_conservation(self):
        outcome = run_contract_consumer(DOUBLE_RELEASE_PATH)
        finding = outcome["report"]["finding"]
        self.assertIsNotNone(finding)
        self.assertIn("payout-conservation", finding["summary"])
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_verification_records_finding_status_after_second_execution(self):
        outcome = run_contract_consumer(ILLEGAL_PATH)
        verification = outcome["report"]["verification"]
        self.assertIsNotNone(verification)
        self.assertTrue(outcome["reproduction"]["matches_original"])
        self.assertEqual(
            outcome["workload_evidence"]["workload_sha256"],
            outcome["reproduction"]["workload_sha256"],
        )
        self.assertEqual(verification["result"], "REPRODUCED")
        self.assertEqual(
            verification["finding_id"],
            outcome["report"]["finding"]["finding_id"],
        )
        self.assertEqual(outcome["report"]["finding"]["status"], "CONFIRMED")

    def test_reproduction_mismatch_is_not_confirmed(self):
        original = workload_result(ILLEGAL_PATH)
        different = copy.deepcopy(original)
        different["final_state"] = "REFUNDED"

        with patch(
            "sdk.liminal_trcp.consumer.workload_result",
            side_effect=[original, different],
        ):
            outcome = run_contract_consumer(ILLEGAL_PATH)

        self.assertFalse(outcome["reproduction"]["matches_original"])
        self.assertEqual(outcome["report"]["verification"]["result"], "NOT_REPRODUCED")
        self.assertEqual(outcome["report"]["finding"]["status"], "NOT_REPRODUCED")
        self.assertEqual(outcome["report"]["final_state"], "CLOSED")
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_distinct_clean_workloads_bind_to_distinct_evidence(self):
        full = run_contract_consumer(VALID_PATH)
        partial = run_contract_consumer(("FUNDED",))

        self.assertIsNone(full["report"]["finding"])
        self.assertIsNone(partial["report"]["finding"])
        self.assertNotEqual(
            full["workload_evidence"]["workload_sha256"],
            partial["workload_evidence"]["workload_sha256"],
        )
        self.assertNotEqual(
            full["report"]["provider_runs"][0]["normalized_task_hash"],
            partial["report"]["provider_runs"][0]["normalized_task_hash"],
        )
        self.assertNotEqual(
            full["report"]["provider_runs"][0]["output_artifact_reference"],
            partial["report"]["provider_runs"][0]["output_artifact_reference"],
        )
        self.assertNotEqual(
            full["receipt"]["receipt_sha256"],
            partial["receipt"]["receipt_sha256"],
        )

    def test_run_is_deterministic(self):
        first = run_contract_consumer(ILLEGAL_PATH)
        second = run_contract_consumer(ILLEGAL_PATH)
        self.assertEqual(first["bundle"], second["bundle"])
        self.assertEqual(first["receipt"], second["receipt"])

    def test_replay_does_not_mutate_bundle(self):
        outcome = run_contract_consumer(DOUBLE_RELEASE_PATH)
        bundle_copy = copy.deepcopy(outcome["bundle"])
        verify_evidence_bundle(outcome["bundle"])
        self.assertEqual(outcome["bundle"], bundle_copy)

    def test_lineage_chains_fallback_to_finding_when_violation_exists(self):
        outcome = run_contract_consumer(ILLEGAL_PATH)
        edges = {(e["from"], e["to"]) for e in outcome["bundle"]["causal_lineage"]}
        self.assertIn(("FALLBACK_RUN", "FINDING"), edges)
        self.assertIn(("VERIFICATION", "CLOSED"), edges)

    def test_lineage_has_no_finding_edge_on_clean_path(self):
        outcome = run_contract_consumer(VALID_PATH)
        edges = {(e["from"], e["to"]) for e in outcome["bundle"]["causal_lineage"]}
        self.assertNotIn(("FALLBACK_RUN", "FINDING"), edges)


class ContractFixtureTests(unittest.TestCase):
    def test_contract_fixture_is_valid(self):
        fixture = contract_fixture()
        authorization = fixture["authorization"]
        authorization.validate(1000)
        fixture["scope"].validate(authorization, 1000)

    def test_task_asset_matches_authorization(self):
        fixture = contract_fixture()
        self.assertEqual(fixture["task"]["asset_id"], fixture["authorization"].asset_id)
        self.assertIn(
            fixture["task"]["asset_id"],
            fixture["scope"].allowed_targets,
        )

    def test_workload_digest_is_embedded_in_task_fixture_reference(self):
        digest = "a" * 64
        fixture = contract_fixture(digest)
        self.assertEqual(
            fixture["task"]["fixture"],
            f"escrow-causal-temporal-v0.1@sha256:{digest}",
        )


def _recalculate_bundle_hash(bundle):
    body = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    bundle["bundle_sha256"] = canonical_sha256(body)


class WorkloadEvidenceBindingTests(unittest.TestCase):
    def _valid_bundle(self):
        outcome = run_contract_consumer(VALID_PATH)
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        return outcome["bundle"]

    def test_bundle_contains_complete_consumer_evidence(self):
        bundle = self._valid_bundle()
        evidence = bundle["consumer_evidence"]
        self.assertEqual(evidence["schema"], "contract-workload-evidence-v0.1")
        self.assertEqual(evidence["requested_path"], list(VALID_PATH))
        self.assertEqual(evidence["actor"], "buyer")
        self.assertIsInstance(evidence["result"], dict)
        self.assertIn("violations", evidence["result"])
        self.assertIn("final_state", evidence["result"])
        self.assertIn("workload_sha256", evidence)
        self.assertIn("task", evidence)
        self.assertIn("task_fixture", evidence)

    def test_consumer_evidence_hash_matches_content(self):
        bundle = self._valid_bundle()
        evidence = bundle["consumer_evidence"]
        body = {
            "schema": evidence["schema"],
            "requested_path": evidence["requested_path"],
            "actor": evidence["actor"],
            "result": evidence["result"],
        }
        self.assertEqual(evidence["workload_sha256"], canonical_sha256(body))

    def test_clean_paths_produce_distinct_receipts(self):
        full = run_contract_consumer(VALID_PATH)
        partial = run_contract_consumer(("FUNDED",))
        self.assertIsNone(full["report"]["finding"])
        self.assertIsNone(partial["report"]["finding"])
        self.assertEqual(full["receipt"]["result"], "PASS")
        self.assertEqual(partial["receipt"]["result"], "PASS")
        self.assertNotEqual(
            full["workload_evidence"]["workload_sha256"],
            partial["workload_evidence"]["workload_sha256"],
        )
        self.assertNotEqual(
            full["bundle"]["bundle_sha256"],
            partial["bundle"]["bundle_sha256"],
        )
        self.assertNotEqual(
            full["receipt"]["receipt_sha256"],
            partial["receipt"]["receipt_sha256"],
        )

    def test_mutated_consumer_artifact_fails_binding(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["requested_path"] = ["CREATED"]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_mutated_final_state_fails_binding(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["result"]["final_state"] = "REFUNDED"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_rehashed_artifact_with_stale_task_reference_fails(self):
        bundle = self._valid_bundle()
        evidence = bundle["consumer_evidence"]
        evidence["result"]["violations"] = [{"invariant_id": "forged", "violated": True}]
        body = {
            "schema": evidence["schema"],
            "requested_path": evidence["requested_path"],
            "actor": evidence["actor"],
            "result": evidence["result"],
        }
        evidence["workload_sha256"] = canonical_sha256(body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_stale_provider_reference_fails_binding(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["task"]["task_id"] = "task:forged"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_legacy_bundle_workload_binding_is_skip(self):
        legacy_bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(legacy_bundle)
        self.assertEqual(receipt["result"], "PASS")
        binding = next(
            check for check in receipt["checks"]
            if check["id"] == "WORKLOAD_EVIDENCE_BINDING"
        )
        self.assertEqual(binding["result"], "SKIP")
        self.assertEqual(binding["detail"], "not applicable: no consumer workload declared")

    def test_contract_consumer_missing_consumer_evidence_fails(self):
        bundle = self._valid_bundle()
        del bundle["consumer_evidence"]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_consumer_evidence_without_provider_runs_fails(self):
        bundle = self._valid_bundle()
        bundle["provider_runs"] = []
        bundle["failover_decision"] = None
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_consumer_evidence_without_matching_provider_hash_fails(self):
        bundle = self._valid_bundle()
        for run in bundle["provider_runs"]:
            run["provider_metadata"]["workload_sha256"] = "1" * 64
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_valid_contract_consumer_binding_passes(self):
        bundle = self._valid_bundle()
        binding = next(
            check for check in verify_evidence_bundle(bundle)["checks"]
            if check["id"] == "WORKLOAD_EVIDENCE_BINDING"
        )
        self.assertEqual(binding["result"], "PASS")

    def test_unrecognized_consumer_evidence_schema_fails(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["schema"] = "contract-workload-evidence-v0.9"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_all_workload_violations_preserved(self):
        outcome = run_contract_consumer(ILLEGAL_PATH)
        evidence_violations = outcome["workload_evidence"]["result"]["violations"]
        finding_summary = outcome["report"]["finding"]["summary"]
        self.assertGreater(len(evidence_violations), 0)
        self.assertEqual(
            evidence_violations,
            outcome["workload"]["violations"],
        )
        self.assertIn(evidence_violations[0]["invariant_id"], finding_summary)


if __name__ == "__main__":
    unittest.main()
