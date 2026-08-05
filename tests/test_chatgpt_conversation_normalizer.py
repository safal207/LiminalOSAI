from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NORMALIZER_PATH = ROOT / "tools" / "chatgpt_conversation_normalizer.py"
ADAPTER_PATH = ROOT / "tools" / "chatgpt_liminal_adapter.py"

NORMALIZER_SPEC = importlib.util.spec_from_file_location(
    "chatgpt_conversation_normalizer", NORMALIZER_PATH
)
assert NORMALIZER_SPEC and NORMALIZER_SPEC.loader
normalizer = importlib.util.module_from_spec(NORMALIZER_SPEC)
NORMALIZER_SPEC.loader.exec_module(normalizer)

ADAPTER_SPEC = importlib.util.spec_from_file_location(
    "chatgpt_liminal_adapter", ADAPTER_PATH
)
assert ADAPTER_SPEC and ADAPTER_SPEC.loader
adapter = importlib.util.module_from_spec(ADAPTER_SPEC)
ADAPTER_SPEC.loader.exec_module(adapter)


class ChatGPTConversationNormalizerTests(unittest.TestCase):
    def _base_bundle(self) -> dict:
        return {
            "schema_version": "chatgpt-conversation-bundle-v0.2",
            "request": {
                "id": "conversation-1",
                "text": "Report the current repository state with evidence",
                "high_stakes": False,
                "requires_current_information": True,
            },
            "draft": {
                "response": "The current main branch contains the Liminal Adapter.",
                "no_signal": False,
                "intent_alignment": 0.97,
                "claims": [
                    {
                        "id": "claim-1",
                        "text": "The current main branch contains the Liminal Adapter.",
                        "kind": "fact",
                        "confidence": 0.99,
                        "requires_current_information": True,
                        "evidence_handles": ["main-state"],
                    }
                ],
                "proposed_actions": [],
                "contradictions": [],
            },
            "sources": [
                {
                    "handle": "main-state",
                    "verified": True,
                    "freshness": "current",
                    "source_kind": "repository",
                    "locator": "refs/heads/main@HEAD",
                }
            ],
            "tool_events": [],
        }

    def _build(self, bundle: dict) -> tuple[dict, dict, dict[str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "conversation.json"
            output_dir = root / "normalized"
            input_path.write_text(json.dumps(bundle, sort_keys=True))
            packet, manifest = normalizer.build_packet(input_path, output_dir)
            outputs = {
                path.name: path.read_text()
                for path in output_dir.iterdir()
                if path.is_file()
            }
            return packet, manifest, outputs

    def test_source_handle_resolves_to_adapter_evidence(self) -> None:
        packet, manifest, _ = self._build(self._base_bundle())
        self.assertEqual(packet["draft"]["claims"][0]["evidence_refs"], ["source:main-state"])
        self.assertEqual(packet["evidence"][0]["id"], "source:main-state")
        self.assertEqual(manifest["unresolved_evidence_handles"], [])

    def test_successful_read_tool_event_can_supply_evidence(self) -> None:
        bundle = self._base_bundle()
        bundle["draft"]["claims"][0]["evidence_handles"] = ["fetch-main"]
        bundle["sources"] = []
        bundle["tool_events"] = [
            {
                "id": "fetch-main",
                "tool": "GitHub",
                "operation": "fetch branch main",
                "status": "success",
                "effect": "read",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": "api.github.com/repos/example/repo/branches/main",
                "reversible": True,
                "user_authorized": True,
                "recovery_plan": None,
            }
        ]
        packet, _, _ = self._build(bundle)
        self.assertEqual(packet["draft"]["claims"][0]["evidence_refs"], ["tool:fetch-main"])
        self.assertTrue(packet["evidence"][0]["verified"])
        self.assertEqual(packet["draft"]["actions"], [])

    def test_successful_write_becomes_performed_action(self) -> None:
        bundle = self._base_bundle()
        bundle["tool_events"] = [
            {
                "id": "merge-pr-96",
                "tool": "GitHub",
                "operation": "merge pull request 96",
                "status": "success",
                "effect": "write",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": "pull/96#merged",
                "reversible": False,
                "user_authorized": True,
                "recovery_plan": "Revert the merge commit",
            }
        ]
        packet, manifest, _ = self._build(bundle)
        action = packet["draft"]["actions"][0]
        self.assertEqual(action["mode"], "performed")
        self.assertEqual(action["id"], "merge-pr-96")
        self.assertEqual(action["recovery_plan"], "Revert the merge commit")
        self.assertEqual(manifest["counts"]["actions"], 1)

    def test_failed_write_is_not_reported_as_performed(self) -> None:
        bundle = self._base_bundle()
        bundle["tool_events"] = [
            {
                "id": "failed-write",
                "tool": "GitHub",
                "operation": "update file",
                "status": "failure",
                "effect": "write",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": "tool-event/failed-write",
                "reversible": True,
                "user_authorized": True,
                "recovery_plan": None,
            }
        ]
        packet, manifest, _ = self._build(bundle)
        self.assertEqual(packet["draft"]["actions"], [])
        self.assertEqual(manifest["ignored_write_events"], ["failed-write"])
        self.assertFalse(packet["evidence"][1]["verified"])

    def test_unknown_evidence_handle_remains_missing_for_adapter(self) -> None:
        bundle = self._base_bundle()
        bundle["draft"]["claims"][0]["evidence_handles"] = ["not-present"]
        packet, manifest, _ = self._build(bundle)
        self.assertEqual(packet["draft"]["claims"][0]["evidence_refs"], ["missing:not-present"])
        self.assertEqual(manifest["unresolved_evidence_handles"], ["not-present"])
        decision = adapter.evaluate_packet(packet, "normalized-sha")
        self.assertEqual(decision["decision"], "VERIFY")

    def test_proposed_action_is_preserved(self) -> None:
        bundle = self._base_bundle()
        bundle["draft"]["proposed_actions"] = [
            {
                "id": "proposal-1",
                "description": "Open a pull request",
                "reversible": True,
                "user_authorized": False,
                "recovery_plan": None,
            }
        ]
        packet, _, _ = self._build(bundle)
        self.assertEqual(packet["draft"]["actions"][0]["mode"], "proposed")

    def test_unauthorized_successful_write_causes_adapter_revise(self) -> None:
        bundle = self._base_bundle()
        bundle["tool_events"] = [
            {
                "id": "unauthorized-write",
                "tool": "GitHub",
                "operation": "merge pull request",
                "status": "success",
                "effect": "write",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": "pull/999#merged",
                "reversible": False,
                "user_authorized": False,
                "recovery_plan": None,
            }
        ]
        packet, _, _ = self._build(bundle)
        decision = adapter.evaluate_packet(packet, "normalized-sha")
        self.assertEqual(decision["decision"], "REVISE")
        self.assertFalse(decision["checks"]["action_boundary_respected"])

    def test_stale_current_evidence_causes_adapter_verify(self) -> None:
        bundle = self._base_bundle()
        bundle["sources"][0]["freshness"] = "stable"
        packet, _, _ = self._build(bundle)
        decision = adapter.evaluate_packet(packet, "normalized-sha")
        self.assertEqual(decision["decision"], "VERIFY")
        self.assertFalse(decision["checks"]["current_information_verified"])

    def test_clean_bundle_is_allowed_end_to_end(self) -> None:
        packet, _, _ = self._build(self._base_bundle())
        decision = adapter.evaluate_packet(packet, "normalized-sha")
        self.assertEqual(decision["decision"], "ALLOW")

    def test_explicit_no_signal_normalizes(self) -> None:
        bundle = self._base_bundle()
        bundle["request"]["requires_current_information"] = False
        bundle["draft"] = {
            "response": "",
            "no_signal": True,
            "intent_alignment": 1.0,
            "claims": [],
            "proposed_actions": [],
            "contradictions": [],
        }
        bundle["sources"] = []
        packet, _, _ = self._build(bundle)
        decision = adapter.evaluate_packet(packet, "normalized-sha")
        self.assertEqual(decision["decision"], "NO_SIGNAL")

    def test_output_is_deterministic(self) -> None:
        packet_a, manifest_a, outputs_a = self._build(self._base_bundle())
        packet_b, manifest_b, outputs_b = self._build(self._base_bundle())
        self.assertEqual(packet_a, packet_b)
        self.assertEqual(manifest_a, manifest_b)
        self.assertEqual(outputs_a, outputs_b)

    def test_duplicate_source_and_tool_handle_is_rejected(self) -> None:
        bundle = self._base_bundle()
        bundle["tool_events"] = [
            {
                "id": "main-state",
                "tool": "GitHub",
                "operation": "fetch main",
                "status": "success",
                "effect": "read",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": "main",
                "reversible": True,
                "user_authorized": True,
                "recovery_plan": None,
            }
        ]
        with self.assertRaisesRegex(ValueError, "globally unique"):
            normalizer.validate_bundle(bundle)

    def test_evidence_eligible_tool_requires_locator(self) -> None:
        bundle = self._base_bundle()
        bundle["tool_events"] = [
            {
                "id": "fetch-main",
                "tool": "GitHub",
                "operation": "fetch main",
                "status": "success",
                "effect": "read",
                "evidence_eligible": True,
                "freshness": "current",
                "locator": None,
                "reversible": True,
                "user_authorized": True,
                "recovery_plan": None,
            }
        ]
        with self.assertRaisesRegex(ValueError, "locator is required"):
            normalizer.validate_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
