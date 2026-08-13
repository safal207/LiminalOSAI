"""Contract tests for the client-neutral financial transition receipt example."""

from __future__ import annotations

import ast
import copy
import unittest
from pathlib import Path

from examples.trcp_agent_financial_transition_reference.self_check import (
    AgentFinancialTransitionAdapter,
    SYNTHETIC_BOUNDARY_OBSERVATION,
    classify_observation,
)
from sdk.liminal_trcp.sdk import run_external_workload, verify_binding

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "trcp_agent_financial_transition_reference" / "self_check.py"


class FinancialTransitionReceiptTests(unittest.TestCase):
    def test_boundary_observation_binds_and_classifies_pass(self):
        outcome = run_external_workload(
            AgentFinancialTransitionAdapter(),
            SYNTHETIC_BOUNDARY_OBSERVATION,
        )
        self.assertEqual(outcome.binding_receipt.result, "PASS")
        self.assertEqual(outcome.execution_replay.status, "NOT_RUN")
        self.assertEqual(outcome.normalized_workload["result"]["classification"], "PASS")
        self.assertEqual(
            outcome.normalized_workload["result"]["expected_outcome_class"],
            "REJECTED_OVER_PER_TRANSACTION_LIMIT",
        )
        self.assertTrue(outcome.normalized_workload["result"]["state_unchanged"])

    def test_repeated_runs_are_deterministic(self):
        first = run_external_workload(
            AgentFinancialTransitionAdapter(),
            SYNTHETIC_BOUNDARY_OBSERVATION,
        )
        second = run_external_workload(
            AgentFinancialTransitionAdapter(),
            copy.deepcopy(SYNTHETIC_BOUNDARY_OBSERVATION),
        )
        self.assertEqual(first.normalized_workload, second.normalized_workload)
        self.assertEqual(first.workload_sha256, second.workload_sha256)
        self.assertEqual(first.bundle_sha256, second.bundle_sha256)
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)

    def test_semantic_failure_does_not_turn_binding_into_execution_proof(self):
        bad_observation = copy.deepcopy(SYNTHETIC_BOUNDARY_OBSERVATION)
        bad_observation["observed_response"] = {
            "status": "EXECUTED",
            "reason_class": "NONE",
        }
        bad_observation["post_state"]["available_balance_minor"] = 3999
        bad_observation["post_state"]["spent_today_minor"] = 1001

        outcome = run_external_workload(
            AgentFinancialTransitionAdapter(),
            bad_observation,
        )
        self.assertEqual(outcome.binding_receipt.result, "PASS")
        self.assertEqual(outcome.normalized_workload["result"]["classification"], "FAIL")
        self.assertEqual(outcome.execution_replay.status, "NOT_RUN")

    def test_rejected_mutation_is_an_explicit_invariant_failure(self):
        mutated = copy.deepcopy(SYNTHETIC_BOUNDARY_OBSERVATION)
        mutated["post_state"]["spent_today_minor"] = 1001
        result = classify_observation(mutated)
        checks = {item["invariant_id"]: item["passed"] for item in result["invariants"]}
        self.assertFalse(checks["rejected-action-no-mutation"])
        self.assertEqual(result["classification"], "FAIL")

    def test_bound_observation_tamper_is_detected(self):
        outcome = run_external_workload(
            AgentFinancialTransitionAdapter(),
            SYNTHETIC_BOUNDARY_OBSERVATION,
        )
        tampered = copy.deepcopy(outcome.evidence_bundle)
        tampered["consumer_evidence"]["input"]["request"]["amount_minor"] = 1000
        receipt = verify_binding(tampered)
        self.assertEqual(receipt.result, "FAIL")
        self.assertNotEqual(receipt.receipt_sha256, outcome.receipt_sha256)

    def test_reference_uses_public_sdk_only_and_has_no_client_or_network_tokens(self):
        source = EXAMPLE.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(EXAMPLE))
        liminal_imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("sdk.liminal"):
                liminal_imports.append(node.module)
            elif isinstance(node, ast.Import):
                liminal_imports.extend(
                    alias.name for alias in node.names if alias.name.startswith("sdk.liminal")
                )
        self.assertEqual(liminal_imports, ["sdk.liminal_trcp.sdk"])
        lowered = source.lower()
        for token in (
            "valta",
            "wallet-guardian",
            "http://",
            "https://",
            "requests.",
            "urllib",
            "authorization:",
            "bearer ",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, lowered)


if __name__ == "__main__":
    unittest.main()
