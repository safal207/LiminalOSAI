"""Tests for the TRCP v0.3 local contract-state consumer fixture and adapter."""

from __future__ import annotations

import copy
import unittest

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

    def test_release_before_funding_is_rejected(self):
        result = workload_result(("RELEASED",))
        self.assertIn("authorization", [v["invariant_id"] for v in result["violations"]])

    def test_steps_are_recorded_in_order(self):
        result = workload_result(VALID_PATH)
        self.assertEqual(
            [step["action"] for step in result["path"]],
            ["fund", "release_request", "release"],
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

    def test_verification_records_finding_status(self):
        outcome = run_contract_consumer(ILLEGAL_PATH)
        verification = outcome["report"]["verification"]
        self.assertIsNotNone(verification)
        self.assertEqual(verification["result"], "REPRODUCED")
        self.assertEqual(
            verification["finding_id"],
            outcome["report"]["finding"]["finding_id"],
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


if __name__ == "__main__":
    unittest.main()
