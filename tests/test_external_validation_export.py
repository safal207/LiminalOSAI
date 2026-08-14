from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from export_external_validation_evidence import (  # noqa: E402
    build_export,
    validate_authority_boundary,
)
from validate_external_graph import load_graph, validate_graph  # noqa: E402

GRAPH_PATH = ROOT / "docs" / "external_validation_graph.v0.1.yaml"


class ExternalValidationExportTests(unittest.TestCase):
    def setUp(self):
        self.graph = load_graph(GRAPH_PATH)

    def test_canonical_export_is_explicitly_non_authorizing(self):
        exported = build_export(self.graph)
        boundary = exported["authority_boundary"]

        self.assertEqual(exported["schema_version"], "external-validation-evidence-export/v0.1")
        self.assertEqual(boundary["classification"], "EVIDENCE_ONLY")
        self.assertEqual(boundary["authorization_transfer"], "NONE")
        self.assertIs(boundary["execution_authorized"], False)
        self.assertIs(boundary["policy_mutation_authorized"], False)
        self.assertIs(boundary["capability_granted"], False)
        self.assertIs(boundary["durable_authority_granted"], False)
        self.assertIs(boundary["requires_separate_authorization_contract"], True)
        self.assertIs(exported["downstream"]["proofpath"]["may_infer_authority"], False)
        self.assertIs(
            exported["downstream"]["cml"]["may_influence_authorization_without_separate_contract"],
            False,
        )

    def test_ee_w_100_and_all_validated_still_grants_zero_authority(self):
        graph = copy.deepcopy(self.graph)
        for target in graph["review_targets"]:
            target["status"] = "VALIDATED"
            target["status_weight"] = 1.0
            target["next_high_value_state"] = "VALIDATED"
            target["technical_feedback_reference"] = f"technical:{target['id']}"
            target["reproduction_evidence"] = {
                "external_reference": f"reproduction:{target['id']}",
                "external_reproducer": "synthetic-independent-reviewer",
                "repository_commit_or_pr": target["repository_commit_or_pr"],
            }
            target["validation_evidence"] = {
                "external_reference": f"validation:{target['id']}",
                "reproduction_reference": f"reproduction:{target['id']}",
                "repository_commit_or_pr": target["repository_commit_or_pr"],
            }

        graph["score"]["weighted_sum"] = 7.0
        graph["score"]["score_percent"] = 100.0
        graph["score"]["interpretation"] = "Synthetic all-validated regression fixture."

        summary, errors = validate_graph(graph)
        self.assertEqual(errors, [])
        self.assertEqual(summary["score_percent"], 100.0)
        self.assertEqual(summary["validated_targets"], 7)

        exported = build_export(graph)
        self.assertEqual(exported["review_maturity"]["score_percent"], 100.0)
        self.assertEqual(exported["review_maturity"]["validated_targets"], 7)
        self.assertEqual(exported["authority_boundary"]["authorization_transfer"], "NONE")
        self.assertIs(exported["authority_boundary"]["execution_authorized"], False)
        self.assertIs(exported["authority_boundary"]["capability_granted"], False)
        self.assertIs(exported["authority_boundary"]["durable_authority_granted"], False)

    def test_authority_boundary_tampering_fails_closed(self):
        graph = copy.deepcopy(self.graph)
        graph["export_contract"]["execution_authorized"] = True

        errors = validate_authority_boundary(graph)
        self.assertTrue(any("execution_authorized" in error for error in errors))
        with self.assertRaisesRegex(ValueError, "execution_authorized"):
            build_export(graph)

    def test_downstream_authority_inference_tampering_fails_closed(self):
        graph = copy.deepcopy(self.graph)
        graph["proofpath_mapping"]["may_infer_authority"] = True
        graph["cml_mapping"]["may_influence_authorization_without_separate_contract"] = True

        errors = validate_authority_boundary(graph)
        self.assertTrue(any("proofpath_mapping.may_infer_authority" in error for error in errors))
        self.assertTrue(
            any(
                "cml_mapping.may_influence_authorization_without_separate_contract" in error
                for error in errors
            )
        )

    def test_export_is_deterministic(self):
        first = build_export(self.graph)
        second = build_export(self.graph)
        self.assertEqual(first, second)
        self.assertRegex(first["export_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
