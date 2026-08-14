import copy
import unittest
from pathlib import Path

from tools.validate_external_graph import load_graph, validate_graph


GRAPH_PATH = Path("docs/external_validation_graph.v0.1.yaml")


class ExternalValidationGraphTests(unittest.TestCase):
    def setUp(self):
        self.graph = load_graph(GRAPH_PATH)

    def test_canonical_graph_is_valid(self):
        summary, errors = validate_graph(self.graph)
        self.assertEqual([], errors)
        self.assertEqual(7, summary["target_count"])
        self.assertAlmostEqual(0.55, summary["weighted_sum"])
        self.assertAlmostEqual(7.86, summary["score_percent"])
        self.assertEqual(0, summary["reproduced_targets"])
        self.assertEqual(0, summary["validated_targets"])

    def test_stale_score_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["score"]["score_percent"] = 99.99
        _, errors = validate_graph(graph)
        self.assertTrue(any("score.score_percent is stale" in error for error in errors))

    def test_status_weight_tampering_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["review_targets"][0]["status_weight"] = 1.0
        _, errors = validate_graph(graph)
        self.assertTrue(any("status_weight" in error for error in errors))

    def test_validated_without_external_reproduction_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        target = graph["review_targets"][0]
        target["status"] = "VALIDATED"
        target["status_weight"] = 1.0
        graph["score"]["weighted_sum"] = 1.35
        graph["score"]["score_percent"] = 19.29

        _, errors = validate_graph(graph)
        self.assertTrue(any("technical_feedback_reference" in error for error in errors))
        self.assertTrue(any("reproduction_evidence" in error for error in errors))
        self.assertTrue(any("validation_evidence" in error for error in errors))

    def test_reproduced_requires_external_evidence_link(self):
        graph = copy.deepcopy(self.graph)
        target = graph["review_targets"][1]
        target["status"] = "REPRODUCED"
        target["status_weight"] = 0.75
        target["technical_feedback_reference"] = "reviewer response retained with attributable reference"
        target["reproduction_evidence"] = {
            "external_reference": "",
            "repository_commit_or_pr": "https://github.com/safal207/LiminalOSAI/pull/174",
        }
        graph["score"]["weighted_sum"] = 1.20
        graph["score"]["score_percent"] = 17.14

        _, errors = validate_graph(graph)
        self.assertTrue(any("reproduction_evidence.external_reference" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
