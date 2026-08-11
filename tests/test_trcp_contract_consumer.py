"""Tests for the TRCP v0.3 local contract-state consumer fixture and adapter."""

from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
