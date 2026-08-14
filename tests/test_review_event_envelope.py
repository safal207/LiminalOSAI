import copy
import json
import unittest
from pathlib import Path

from tools.validate_review_event import validate_event


ROOT = Path(__file__).resolve().parents[1]
GRAPH = json.loads((ROOT / "docs/external_validation_graph.v0.1.yaml").read_text())
EXAMPLE = json.loads((ROOT / "examples/review_events/openai_routed.v0.1.json").read_text())


class ReviewEventEnvelopeTests(unittest.TestCase):
    def test_openai_routed_example_is_valid(self):
        self.assertEqual(validate_event(EXAMPLE, GRAPH), [])

    def test_event_type_must_match_transition_target(self):
        event = copy.deepcopy(EXAMPLE)
        event["event_type"] = "review.acknowledged"
        errors = validate_event(event, GRAPH)
        self.assertTrue(any("requires transition.to" in error for error in errors))

    def test_transition_must_move_forward(self):
        event = copy.deepcopy(EXAMPLE)
        event["transition"] = {"from": "ROUTED", "to": "ROUTED"}
        errors = validate_event(event, GRAPH)
        self.assertTrue(any("strictly stronger" in error for error in errors))

    def test_reproduced_requires_external_reproduction_fields(self):
        event = copy.deepcopy(EXAMPLE)
        event["event_type"] = "review.reproduced"
        event["transition"] = {"from": "TECHNICAL_FEEDBACK", "to": "REPRODUCED"}
        event["evidence"]["summary"] = (
            "An external reviewer independently reproduced the bounded failure trace "
            "against the linked benchmark artifact."
        )
        errors = validate_event(event, None)
        self.assertTrue(any("external_reproducer" in error for error in errors))
        self.assertTrue(any("reproduction_reference" in error for error in errors))

    def test_validated_requires_explicit_validation_reference(self):
        event = copy.deepcopy(EXAMPLE)
        event["event_type"] = "review.validated"
        event["transition"] = {"from": "REPRODUCED", "to": "VALIDATED"}
        event["evidence"].update(
            {
                "summary": (
                    "An external reviewer reproduced the bounded artifact and issued "
                    "an explicit evidence-backed validation statement."
                ),
                "external_reproducer": "Independent reviewer",
                "reproduction_reference": "https://example.org/reproduction",
            }
        )
        errors = validate_event(event, None)
        self.assertTrue(any("validation_reference" in error for error in errors))

    def test_event_cannot_outrun_canonical_graph(self):
        event = copy.deepcopy(EXAMPLE)
        event["event_type"] = "review.technical_feedback"
        event["transition"] = {"from": "ROUTED", "to": "TECHNICAL_FEEDBACK"}
        event["evidence"]["summary"] = (
            "A substantive external counterexample describes a stale-authority path "
            "that should be reproduced before the graph advances."
        )
        errors = validate_event(event, GRAPH)
        self.assertTrue(any("exceeds the evidence state" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
