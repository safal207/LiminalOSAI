from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = _load(
    "chatgpt_live_session_exporter",
    ROOT / "tools" / "chatgpt_live_session_exporter.py",
)
normalizer = _load(
    "chatgpt_conversation_normalizer",
    ROOT / "tools" / "chatgpt_conversation_normalizer.py",
)
adapter = _load(
    "chatgpt_liminal_adapter",
    ROOT / "tools" / "chatgpt_liminal_adapter.py",
)


class ChatGPTLiveSessionExporterTests(unittest.TestCase):
    def _base_packet(self) -> dict:
        return {
            "schema_version": "chatgpt-live-session-v0.3",
            "session": {
                "id": "live-session-001",
                "request_event_id": "user-1",
                "draft_event_id": "draft-1",
                "high_stakes": False,
                "requires_current_information": True,
                "capture_complete": True,
            },
            "events": [
                {
                    "id": "user-1",
                    "sequence": 1,
                    "type": "user_message",
                    "text": "Report the current repository state and the authorized merge.",
                },
                {
                    "id": "auth-1",
                    "sequence": 2,
                    "type": "user_authorization",
                    "text": "Go",
                    "authorized_event_ids": ["merge-pr-97", "proposal-1"],
                },
                {
                    "id": "source-main",
                    "sequence": 3,
                    "type": "source",
                    "handle": "main-state",
                    "verified": True,
                    "freshness": "current",
                    "source_kind": "repository",
                    "locator": "refs/heads/main@HEAD",
                },
                {
                    "id": "merge-pr-97",
                    "sequence": 4,
                    "type": "tool_event",
                    "tool": "GitHub",
                    "operation": "merge pull request 97",
                    "status": "success",
                    "effect": "write",
                    "evidence_eligible": True,
                    "freshness": "current",
                    "locator": "pull/97#merged",
                    "reversible": False,
                    "recovery_plan": "Revert the merge commit.",
                },
                {
                    "id": "draft-1",
                    "sequence": 5,
                    "type": "assistant_draft",
                    "response": "The repository contains the normalizer and PR 97 was merged with explicit authorization.",
                    "no_signal": False,
                    "intent_alignment": 0.98,
                },
                {
                    "id": "claim-main",
                    "sequence": 6,
                    "type": "claim",
                    "draft_event_id": "draft-1",
                    "text": "The current repository contains the conversation normalizer.",
                    "kind": "fact",
                    "confidence": 0.99,
                    "requires_current_information": True,
                    "evidence_event_ids": ["source-main"],
                },
                {
                    "id": "claim-merge",
                    "sequence": 7,
                    "type": "claim",
                    "draft_event_id": "draft-1",
                    "text": "Pull request 97 was merged successfully.",
                    "kind": "fact",
                    "confidence": 0.99,
                    "requires_current_information": True,
                    "evidence_event_ids": ["merge-pr-97"],
                },
                {
                    "id": "proposal-1",
                    "sequence": 8,
                    "type": "proposed_action",
                    "draft_event_id": "draft-1",
                    "description": "Run the exported bundle through the deterministic gate.",
                    "reversible": True,
                    "recovery_plan": None,
                },
            ],
        }

    def _pipeline(self, packet: dict) -> tuple[dict, dict, dict, dict]:
        bundle, export_manifest = exporter.export_session(packet, "a" * 64)
        adapter_input, normalization_manifest = normalizer.normalize_bundle(
            bundle, "b" * 64
        )
        advice = adapter.evaluate_packet(adapter_input, "c" * 64)
        return bundle, export_manifest, normalization_manifest, advice

    def test_exports_selected_request_draft_and_claims(self) -> None:
        bundle, manifest = exporter.export_session(self._base_packet(), "a" * 64)
        self.assertEqual(bundle["schema_version"], "chatgpt-conversation-bundle-v0.2")
        self.assertEqual(bundle["request"]["text"], self._base_packet()["events"][0]["text"])
        self.assertEqual(bundle["draft"]["claims"][0]["evidence_handles"], ["main-state"])
        self.assertEqual(bundle["draft"]["claims"][1]["evidence_handles"], ["merge-pr-97"])
        self.assertEqual(manifest["selected_event_ids"]["draft"], "draft-1")

    def test_explicit_prior_authorization_is_exported(self) -> None:
        bundle, _ = exporter.export_session(self._base_packet(), "a" * 64)
        self.assertTrue(bundle["tool_events"][0]["user_authorized"])
        self.assertTrue(bundle["draft"]["proposed_actions"][0]["user_authorized"])

    def test_missing_authorization_reaches_revise_for_performed_write(self) -> None:
        packet = self._base_packet()
        packet["events"] = [event for event in packet["events"] if event["id"] != "auth-1"]
        _, _, _, advice = self._pipeline(packet)
        self.assertEqual(advice["decision"], "REVISE")
        self.assertIn(
            "action:merge-pr-97:performed_without_user_authorization",
            advice["reasons"],
        )

    def test_late_authorization_is_rejected(self) -> None:
        packet = self._base_packet()
        next(event for event in packet["events"] if event["id"] == "auth-1")["sequence"] = 9
        with self.assertRaisesRegex(ValueError, "must precede"):
            exporter.validate_session(packet)

    def test_unknown_authorization_target_is_rejected(self) -> None:
        packet = self._base_packet()
        auth = next(event for event in packet["events"] if event["id"] == "auth-1")
        auth["authorized_event_ids"] = ["ghost-action"]
        with self.assertRaisesRegex(ValueError, "unknown event"):
            exporter.validate_session(packet)

    def test_incomplete_capture_fails_closed(self) -> None:
        packet = self._base_packet()
        packet["session"]["capture_complete"] = False
        with self.assertRaisesRegex(ValueError, "capture_complete"):
            exporter.validate_session(packet)

    def test_duplicate_event_id_is_rejected(self) -> None:
        packet = self._base_packet()
        duplicate = copy.deepcopy(packet["events"][0])
        duplicate["sequence"] = 99
        packet["events"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "event ids"):
            exporter.validate_session(packet)

    def test_duplicate_sequence_is_rejected(self) -> None:
        packet = self._base_packet()
        packet["events"][1]["sequence"] = packet["events"][0]["sequence"]
        with self.assertRaisesRegex(ValueError, "event sequences"):
            exporter.validate_session(packet)

    def test_request_and_draft_selection_are_typed(self) -> None:
        packet = self._base_packet()
        packet["session"]["request_event_id"] = "draft-1"
        with self.assertRaisesRegex(ValueError, "user_message"):
            exporter.validate_session(packet)

    def test_unknown_evidence_event_reaches_verify(self) -> None:
        packet = self._base_packet()
        claim = next(event for event in packet["events"] if event["id"] == "claim-main")
        claim["evidence_event_ids"] = ["ghost-source-event"]
        bundle, manifest, _, advice = self._pipeline(packet)
        self.assertEqual(
            bundle["draft"]["claims"][0]["evidence_handles"],
            ["unresolved:ghost-source-event"],
        )
        self.assertEqual(manifest["unresolved_evidence_event_ids"], ["ghost-source-event"])
        self.assertEqual(advice["decision"], "VERIFY")

    def test_non_evidence_tool_reference_reaches_verify(self) -> None:
        packet = self._base_packet()
        tool = next(event for event in packet["events"] if event["id"] == "merge-pr-97")
        tool["evidence_eligible"] = False
        tool["locator"] = None
        _, manifest, _, advice = self._pipeline(packet)
        self.assertIn("merge-pr-97", manifest["unresolved_evidence_event_ids"])
        self.assertEqual(advice["decision"], "VERIFY")

    def test_failed_write_is_not_reported_as_performed(self) -> None:
        packet = self._base_packet()
        tool = next(event for event in packet["events"] if event["id"] == "merge-pr-97")
        tool["status"] = "failure"
        bundle, _ = exporter.export_session(packet, "a" * 64)
        adapter_input, manifest = normalizer.normalize_bundle(bundle, "b" * 64)
        performed_ids = [item["id"] for item in adapter_input["draft"]["actions"]]
        self.assertNotIn("merge-pr-97", performed_ids)
        self.assertIn("merge-pr-97", manifest["ignored_write_events"])

    def test_clean_no_signal_reaches_no_signal(self) -> None:
        packet = self._base_packet()
        packet["events"] = [
            packet["events"][0],
            {
                "id": "draft-1",
                "sequence": 2,
                "type": "assistant_draft",
                "response": "",
                "no_signal": True,
                "intent_alignment": 1.0,
            },
        ]
        _, _, _, advice = self._pipeline(packet)
        self.assertEqual(advice["decision"], "NO_SIGNAL")

    def test_other_draft_bound_events_are_ignored_and_recorded(self) -> None:
        packet = self._base_packet()
        packet["events"].extend(
            [
                {
                    "id": "draft-old",
                    "sequence": 9,
                    "type": "assistant_draft",
                    "response": "Old draft.",
                    "no_signal": False,
                    "intent_alignment": 0.5,
                },
                {
                    "id": "claim-old",
                    "sequence": 10,
                    "type": "claim",
                    "draft_event_id": "draft-old",
                    "text": "Old claim.",
                    "kind": "reasoning",
                    "confidence": 0.5,
                    "requires_current_information": False,
                    "evidence_event_ids": [],
                },
            ]
        )
        bundle, manifest = exporter.export_session(packet, "a" * 64)
        self.assertNotIn("claim-old", [item["id"] for item in bundle["draft"]["claims"]])
        self.assertEqual(manifest["ignored_draft_bound_event_ids"], ["claim-old"])

    def test_source_handle_and_tool_id_collision_is_rejected(self) -> None:
        packet = self._base_packet()
        source = next(event for event in packet["events"] if event["id"] == "source-main")
        source["handle"] = "merge-pr-97"
        with self.assertRaisesRegex(ValueError, "globally unique"):
            exporter.validate_session(packet)

    def test_export_is_deterministic(self) -> None:
        first_bundle, first_manifest = exporter.export_session(self._base_packet(), "a" * 64)
        second_bundle, second_manifest = exporter.export_session(self._base_packet(), "a" * 64)
        self.assertEqual(first_bundle, second_bundle)
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(
            first_manifest["output_integrity"]["bundle_sha256"],
            second_manifest["output_integrity"]["bundle_sha256"],
        )

    def test_build_export_writes_three_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "session.json"
            output_dir = root / "out"
            input_path.write_text(json.dumps(self._base_packet()))
            manifest, paths = exporter.build_export(input_path, output_dir)
            self.assertEqual(manifest["schema_version"], "chatgpt-live-session-export-v0.3")
            self.assertEqual(set(paths), {"bundle", "manifest", "graph"})
            for path in paths.values():
                self.assertTrue(Path(path).exists())

    def test_wrong_schema_is_rejected(self) -> None:
        packet = self._base_packet()
        packet["schema_version"] = "wrong"
        with self.assertRaisesRegex(ValueError, "schema_version"):
            exporter.validate_session(packet)


if __name__ == "__main__":
    unittest.main()
