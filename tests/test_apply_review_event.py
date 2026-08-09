import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from apply_review_event import apply_event  # noqa: E402
from validate_external_graph import load_graph  # noqa: E402


GRAPH_PATH = ROOT / "docs" / "external_validation_graph.v0.1.yaml"
OPENAI_REPLAY = ROOT / "examples" / "review_events" / "openai_routed.v0.1.json"


def technical_feedback_event() -> dict:
    return {
        "schema_version": "review-event-envelope/v0.1",
        "event_id": "test-openai-technical-feedback-001",
        "event_type": "review.technical_feedback",
        "occurred_at": "2026-08-10T10:00:00Z",
        "claim_id": "PSAG-001",
        "subject": {
            "organization": "OpenAI",
            "target_id": "openai-preparedness",
        },
        "transition": {"from": "ROUTED", "to": "TECHNICAL_FEEDBACK"},
        "evidence": {
            "kind": "external_correspondence",
            "reference": "synthetic-test-reference-openai-feedback",
            "summary": (
                "Synthetic regression fixture representing substantive technical "
                "feedback about a bounded post-sandbox authority counterexample."
            ),
            "public": False,
        },
        "repository": {
            "repository": "safal207/LiminalOSAI",
            "pr": 174,
            "commit": None,
        },
        "provenance": {
            "recorded_by": "test-fixture",
            "source": "synthetic_regression_fixture",
        },
    }


class ApplyReviewEventTests(unittest.TestCase):
    def setUp(self):
        self.graph = load_graph(GRAPH_PATH)

    def test_valid_transition_recomputes_eew_without_mutating_input(self):
        original = copy.deepcopy(self.graph)
        candidate, result = apply_event(self.graph, technical_feedback_event())

        self.assertEqual(self.graph, original)
        self.assertEqual(result["action"], "apply")
        self.assertEqual(result["previous_status"], "ROUTED")
        self.assertEqual(result["new_status"], "TECHNICAL_FEEDBACK")
        self.assertEqual(result["score_percent"], 10.71)

        target = next(
            item
            for item in candidate["review_targets"]
            if item["id"] == "openai-preparedness"
        )
        self.assertEqual(target["status"], "TECHNICAL_FEEDBACK")
        self.assertEqual(target["status_weight"], 0.40)
        self.assertEqual(
            target["technical_feedback_reference"],
            "synthetic-test-reference-openai-feedback",
        )
        self.assertEqual(
            target["last_review_event"]["event_id"],
            "test-openai-technical-feedback-001",
        )

    def test_existing_openai_routed_event_replays_as_idempotent_noop(self):
        event = json.loads(OPENAI_REPLAY.read_text(encoding="utf-8"))
        candidate, result = apply_event(self.graph, event)
        self.assertEqual(candidate, self.graph)
        self.assertEqual(result["action"], "noop")
        self.assertEqual(result["reason"], "already_applied")
        self.assertEqual(result["score_percent"], 7.86)

    def test_stale_source_is_rejected(self):
        event = technical_feedback_event()
        event["transition"]["from"] = "SENT"
        with self.assertRaisesRegex(ValueError, "transition.from must equal"):
            apply_event(self.graph, event)

    def test_regression_is_rejected_by_envelope_or_state_guard(self):
        event = technical_feedback_event()
        event["event_type"] = "review.acknowledged"
        event["transition"] = {"from": "ROUTED", "to": "ACKNOWLEDGED"}
        with self.assertRaisesRegex(ValueError, "invalid review event|stale/regressive"):
            apply_event(self.graph, event)

    def test_disallowed_jump_is_rejected_even_with_strong_evidence_shape(self):
        event = {
            "schema_version": "review-event-envelope/v0.1",
            "event_id": "test-anthropic-reproduced-jump-001",
            "event_type": "review.reproduced",
            "occurred_at": "2026-08-10T11:00:00Z",
            "claim_id": "PSAG-001",
            "subject": {
                "organization": "Anthropic",
                "target_id": "anthropic-safeguards",
            },
            "transition": {"from": "ACKNOWLEDGED", "to": "REPRODUCED"},
            "evidence": {
                "kind": "external_reproduction",
                "reference": "synthetic-anthropic-reproduction",
                "summary": (
                    "Synthetic regression fixture with enough detail to satisfy "
                    "the stronger evidence shape while testing edge authorization."
                ),
                "public": False,
                "external_reproducer": "synthetic-reviewer",
                "reproduction_reference": "synthetic-reproduction-artifact",
            },
            "repository": {
                "repository": "safal207/LiminalOSAI",
                "pr": 174,
                "commit": None,
            },
            "provenance": {
                "recorded_by": "test-fixture",
                "source": "synthetic_regression_fixture",
            },
        }
        with self.assertRaisesRegex(ValueError, "transition is not allowed"):
            apply_event(self.graph, event)

    def test_same_state_with_unrelated_evidence_is_not_silently_accepted(self):
        event = json.loads(OPENAI_REPLAY.read_text(encoding="utf-8"))
        event["event_id"] = "different-routed-event"
        event["evidence"]["reference"] = "unrelated-evidence-reference"
        with self.assertRaisesRegex(ValueError, "same-state replay is not attributable"):
            apply_event(self.graph, event)


if __name__ == "__main__":
    unittest.main()
