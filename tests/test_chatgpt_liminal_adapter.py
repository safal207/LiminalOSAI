from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "chatgpt_liminal_adapter.py"
SPEC = importlib.util.spec_from_file_location("chatgpt_liminal_adapter", MODULE_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class ChatGPTLiminalAdapterTests(unittest.TestCase):
    def _base_packet(self) -> dict:
        return {
            "schema_version": "chatgpt-liminal-input-v0.1",
            "request": {
                "id": "request-1",
                "intent": "Give a grounded answer about the current repository state",
                "high_stakes": False,
                "requires_current_information": True,
            },
            "draft": {
                "response": "The repository main branch includes the response gate.",
                "no_signal": False,
                "intent_alignment": 0.95,
                "claims": [
                    {
                        "id": "claim-1",
                        "text": "The repository contains the response gate.",
                        "kind": "fact",
                        "confidence": 0.99,
                        "requires_current_information": True,
                        "evidence_refs": ["evidence-1"],
                    }
                ],
                "actions": [],
                "contradictions": [],
            },
            "evidence": [
                {
                    "id": "evidence-1",
                    "verified": True,
                    "freshness": "current",
                    "source_kind": "repository",
                    "locator": "tools/chatgpt_liminal_adapter.py@HEAD",
                }
            ],
        }

    def _build(self, packet: dict) -> tuple[dict, dict[str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "input.json"
            output_dir = root / "out"
            input_path.write_text(json.dumps(packet, sort_keys=True))
            result = adapter.build_packet(input_path, output_dir)
            files = {
                path.name: path.read_text()
                for path in sorted(output_dir.iterdir())
                if path.is_file()
            }
            return result, files

    def test_allow_requires_verified_current_evidence(self) -> None:
        result, files = self._build(self._base_packet())

        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["checks"]["intent_aligned"])
        self.assertTrue(result["checks"]["claim_evidence_complete"])
        self.assertTrue(result["checks"]["current_information_verified"])
        self.assertFalse(result["authority"]["delivery"])
        self.assertFalse(result["authority"]["execution"])
        self.assertFalse(result["authority"]["model_weight_update"])
        self.assertIn("chatgpt-liminal-advice.json", files)
        self.assertIn("chatgpt-liminal-next-step.json", files)
        self.assertIn("chatgpt-liminal-causal-graph.md", files)

    def test_verify_when_current_fact_has_only_stable_evidence(self) -> None:
        packet = self._base_packet()
        packet["evidence"][0]["freshness"] = "stable"

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "VERIFY")
        self.assertIn(
            "claim:claim-1:missing_verified_current_evidence",
            result["reasons"],
        )
        self.assertIn("claim-1", result["blocked_claims"])
        self.assertTrue(result["next_step"]["requires_external_verification"])

    def test_verify_when_fact_references_unknown_evidence(self) -> None:
        packet = self._base_packet()
        packet["draft"]["claims"][0]["evidence_refs"] = ["missing-source"]

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "VERIFY")
        self.assertEqual(result["missing_evidence"], ["missing-source"])
        self.assertIn(
            "claim:claim-1:unknown_evidence_references",
            result["reasons"],
        )

    def test_revise_on_low_alignment_and_unauthorized_action(self) -> None:
        packet = self._base_packet()
        packet["draft"]["intent_alignment"] = 0.4
        packet["draft"]["actions"] = [
            {
                "id": "action-1",
                "description": "Merge a pull request",
                "mode": "performed",
                "reversible": False,
                "user_authorized": False,
                "recovery_plan": None,
            }
        ]

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "REVISE")
        self.assertIn("intent_alignment_below_0.65", result["reasons"])
        self.assertIn(
            "action:action-1:performed_without_user_authorization",
            result["action_findings"],
        )
        self.assertIn(
            "action:action-1:irreversible_without_recovery_plan",
            result["action_findings"],
        )
        self.assertFalse(result["checks"]["action_boundary_respected"])

    def test_revise_overconfident_unsupported_reasoning(self) -> None:
        packet = self._base_packet()
        packet["request"]["requires_current_information"] = False
        packet["draft"]["claims"] = [
            {
                "id": "claim-reasoning",
                "text": "This architecture will certainly solve every future case.",
                "kind": "reasoning",
                "confidence": 0.99,
                "requires_current_information": False,
                "evidence_refs": [],
            }
        ]

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "REVISE")
        self.assertIn(
            "overconfident_unsupported_claim:claim-reasoning",
            result["reasons"],
        )

    def test_explicit_no_signal_does_not_manufacture_an_answer(self) -> None:
        packet = self._base_packet()
        packet["request"]["requires_current_information"] = False
        packet["draft"] = {
            "response": "",
            "no_signal": True,
            "intent_alignment": 1.0,
            "claims": [],
            "actions": [],
            "contradictions": [],
        }
        packet["evidence"] = []

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "NO_SIGNAL")
        self.assertEqual(
            result["reasons"], ["explicit_no_signal_without_claims_or_actions"]
        )
        self.assertEqual(result["next_step"]["name"], "return_explicit_no_signal")

    def test_no_signal_with_claims_is_rejected(self) -> None:
        packet = self._base_packet()
        packet["draft"]["no_signal"] = True

        result, _ = self._build(packet)

        self.assertEqual(result["decision"], "REVISE")
        self.assertIn(
            "no_signal_packet_contains_response_claims_or_actions",
            result["reasons"],
        )

    def test_output_is_deterministic_for_identical_input(self) -> None:
        first, first_files = self._build(self._base_packet())
        second, second_files = self._build(self._base_packet())

        self.assertEqual(first, second)
        self.assertEqual(first_files, second_files)

    def test_duplicate_evidence_ids_fail_closed(self) -> None:
        packet = self._base_packet()
        packet["evidence"].append(dict(packet["evidence"][0]))

        with self.assertRaisesRegex(ValueError, "duplicate evidence id"):
            adapter.evaluate_packet(packet, "test-sha")

    def test_unknown_schema_fails_closed(self) -> None:
        packet = self._base_packet()
        packet["schema_version"] = "future-schema"

        with self.assertRaisesRegex(ValueError, "schema_version"):
            adapter.evaluate_packet(packet, "test-sha")


if __name__ == "__main__":
    unittest.main()
