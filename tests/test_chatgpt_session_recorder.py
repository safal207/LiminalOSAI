from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_session_recorder import (  # noqa: E402
    AUTHORITY,
    JOURNAL_SCHEMA,
    RecorderError,
    SessionRecorder,
)


class SessionRecorderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.journal = self.root / "session.json"
        self.recorder = SessionRecorder.create(
            self.journal,
            session_id="session-1",
            high_stakes=False,
            requires_current_information=True,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _basic_recording(self, *, authorized: bool = True) -> None:
        self.recorder.record_user_message(event_id="user-1", text="Go")
        if authorized:
            self.recorder.record_authorization(
                event_id="auth-1", text="Go", authorized_event_ids=["write-1"]
            )
        self.recorder.record_source(
            event_id="source-1",
            handle="main-state",
            verified=True,
            freshness="current",
            source_kind="repository",
            locator="refs/heads/main@HEAD",
        )
        self.recorder.record_tool_event(
            event_id="write-1",
            tool="GitHub",
            operation="merge pull request 98",
            status="success",
            effect="write",
            evidence_eligible=True,
            freshness="current",
            locator="pull/98#merged",
            reversible=False,
            recovery_plan="Revert the merge commit",
        )
        self.recorder.record_assistant_draft(
            event_id="draft-1",
            response="The authorized merge completed and main contains v0.3.",
            no_signal=False,
            intent_alignment=0.99,
        )
        self.recorder.record_claim(
            event_id="claim-1",
            draft_event_id="draft-1",
            text="Main contains v0.3.",
            kind="fact",
            confidence=0.99,
            requires_current_information=True,
            evidence_event_ids=["source-1"],
        )
        self.recorder.record_claim(
            event_id="claim-2",
            draft_event_id="draft-1",
            text="The merge completed.",
            kind="fact",
            confidence=0.99,
            requires_current_information=True,
            evidence_event_ids=["write-1"],
        )

    def test_create_initializes_unsealed_empty_journal(self) -> None:
        journal = self.recorder.read()
        self.assertEqual(journal["schema_version"], JOURNAL_SCHEMA)
        self.assertFalse(journal["session"]["sealed"])
        self.assertEqual(journal["entries"], [])
        self.assertFalse(journal["authority"]["execution"])

    def test_append_assigns_contiguous_sequences(self) -> None:
        first = self.recorder.record_user_message(event_id="u1", text="Hello")
        second = self.recorder.record_assistant_draft(
            event_id="d1", response="Hi", no_signal=False, intent_alignment=1.0
        )
        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)

    def test_hash_chain_verifies(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Hello")
        verification = self.recorder.verify()
        self.assertEqual(verification["event_count"], 1)
        self.assertEqual(len(verification["head_sha256"]), 64)

    def test_tampered_event_is_rejected(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Hello")
        raw = json.loads(self.journal.read_text())
        raw["entries"][0]["event"]["text"] = "Tampered"
        self.journal.write_text(json.dumps(raw))
        with self.assertRaisesRegex(RecorderError, "entry hash mismatch"):
            self.recorder.read()

    def test_tampered_head_is_rejected(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Hello")
        raw = json.loads(self.journal.read_text())
        raw["head_sha256"] = "f" * 64
        self.journal.write_text(json.dumps(raw))
        with self.assertRaisesRegex(RecorderError, "head_sha256"):
            self.recorder.read()

    def test_unknown_event_fields_are_rejected(self) -> None:
        with self.assertRaisesRegex(RecorderError, "unsupported keys"):
            self.recorder.append_event(
                {"id": "u1", "type": "user_message", "text": "Hello", "secret": "x"}
            )

    def test_caller_cannot_supply_sequence(self) -> None:
        with self.assertRaisesRegex(RecorderError, "recorder-owned"):
            self.recorder.append_event(
                {"id": "u1", "sequence": 10, "type": "user_message", "text": "Hello"}
            )

    def test_duplicate_event_id_is_rejected(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Hello")
        with self.assertRaisesRegex(RecorderError, "duplicate event id"):
            self.recorder.record_user_message(event_id="u1", text="Again")

    def test_lock_conflict_is_rejected(self) -> None:
        lock = self.journal.with_name(self.journal.name + ".lock")
        lock.write_text("external")
        with self.assertRaisesRegex(RecorderError, "lock already exists"):
            self.recorder.record_user_message(event_id="u1", text="Hello")

    def test_unsealed_journal_cannot_export(self) -> None:
        with self.assertRaisesRegex(RecorderError, "must be sealed"):
            self.recorder.export_live_session(self.root / "live.json")

    def test_seal_requires_typed_selectors(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Hello")
        with self.assertRaisesRegex(RecorderError, "assistant_draft"):
            self.recorder.seal(request_event_id="u1", draft_event_id="u1")

    def test_late_authorization_is_rejected_at_seal(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Go")
        self.recorder.record_tool_event(
            event_id="write-1",
            tool="GitHub",
            operation="merge",
            status="success",
            effect="write",
            evidence_eligible=True,
            freshness="current",
            locator="pull/1#merged",
            reversible=False,
            recovery_plan="Revert",
        )
        self.recorder.record_authorization(
            event_id="auth-1", text="Go", authorized_event_ids=["write-1"]
        )
        self.recorder.record_assistant_draft(
            event_id="d1", response="Done", no_signal=False, intent_alignment=1.0
        )
        with self.assertRaisesRegex(RecorderError, "must occur before"):
            self.recorder.seal(request_event_id="u1", draft_event_id="d1")

    def test_unknown_authorization_target_is_rejected_at_seal(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Go")
        self.recorder.record_authorization(
            event_id="auth-1", text="Go", authorized_event_ids=["missing"]
        )
        self.recorder.record_assistant_draft(
            event_id="d1", response="Done", no_signal=False, intent_alignment=1.0
        )
        with self.assertRaisesRegex(RecorderError, "unknown event"):
            self.recorder.seal(request_event_id="u1", draft_event_id="d1")

    def test_non_authorizable_target_is_rejected(self) -> None:
        self.recorder.record_authorization(
            event_id="auth-1", text="Go", authorized_event_ids=["u1"]
        )
        self.recorder.record_user_message(event_id="u1", text="Go")
        self.recorder.record_assistant_draft(
            event_id="d1", response="Done", no_signal=False, intent_alignment=1.0
        )
        with self.assertRaisesRegex(RecorderError, "not authorizable"):
            self.recorder.seal(request_event_id="u1", draft_event_id="d1")

    def test_source_handle_tool_id_collision_is_rejected(self) -> None:
        self.recorder.record_user_message(event_id="u1", text="Go")
        self.recorder.record_source(
            event_id="s1",
            handle="tool-1",
            verified=True,
            freshness="current",
            source_kind="repository",
            locator="x",
        )
        self.recorder.record_tool_event(
            event_id="tool-1",
            tool="GitHub",
            operation="read",
            status="success",
            effect="read",
            evidence_eligible=True,
            freshness="current",
            locator="y",
            reversible=True,
            recovery_plan=None,
        )
        self.recorder.record_assistant_draft(
            event_id="d1", response="Done", no_signal=False, intent_alignment=1.0
        )
        with self.assertRaisesRegex(RecorderError, "globally unique"):
            self.recorder.seal(request_event_id="u1", draft_event_id="d1")

    def test_seal_blocks_future_appends_and_protects_selectors(self) -> None:
        self._basic_recording()
        session = self.recorder.seal(request_event_id="user-1", draft_event_id="draft-1")
        self.assertTrue(session["sealed"])
        verification = self.recorder.verify()
        self.assertEqual(len(verification["seal_sha256"]), 64)
        with self.assertRaisesRegex(RecorderError, "sealed"):
            self.recorder.record_user_message(event_id="late", text="Late")

    def test_export_matches_live_session_v03(self) -> None:
        self._basic_recording()
        self.recorder.seal(request_event_id="user-1", draft_event_id="draft-1")
        output = self.root / "live.json"
        live = self.recorder.export_live_session(output)
        self.assertEqual(live["schema_version"], "chatgpt-live-session-v0.3")
        self.assertTrue(live["session"]["capture_complete"])
        self.assertEqual(live["events"][0]["sequence"], 1)
        self.assertNotIn("entry_sha256", live["events"][0])
        self.assertEqual(json.loads(output.read_text()), live)

    def test_identical_inputs_produce_identical_journals(self) -> None:
        other_path = self.root / "other.json"
        other = SessionRecorder.create(
            other_path,
            session_id="session-1",
            high_stakes=False,
            requires_current_information=True,
        )
        for recorder in (self.recorder, other):
            recorder.record_user_message(event_id="u1", text="Hello")
            recorder.record_assistant_draft(
                event_id="d1", response="Hi", no_signal=False, intent_alignment=1.0
            )
            recorder.seal(request_event_id="u1", draft_event_id="d1")
        self.assertEqual(json.loads(self.journal.read_text()), json.loads(other_path.read_text()))

    def test_authority_is_fixed_no_authority(self) -> None:
        verification = self.recorder.verify()
        self.assertEqual(verification["authority"], AUTHORITY)
        self.assertFalse(verification["authority"]["hidden_message_access"])
        self.assertFalse(verification["authority"]["merge"])

    def test_cli_full_flow(self) -> None:
        cli_journal = self.root / "cli.json"
        cli_live = self.root / "cli-live.json"
        cli = ROOT / "tools" / "chatgpt_session_recorder.py"
        subprocess.run(
            [
                sys.executable,
                str(cli),
                "init",
                "--journal",
                str(cli_journal),
                "--session-id",
                "cli-session",
                "--no-high-stakes",
                "--requires-current-information",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        events = [
            {"id": "u1", "type": "user_message", "text": "Hello"},
            {
                "id": "d1",
                "type": "assistant_draft",
                "response": "Hi",
                "no_signal": False,
                "intent_alignment": 1.0,
            },
        ]
        for index, event in enumerate(events):
            path = self.root / f"event-{index}.json"
            path.write_text(json.dumps(event))
            subprocess.run(
                [sys.executable, str(cli), "append", "--journal", str(cli_journal), "--event", str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
        subprocess.run(
            [
                sys.executable,
                str(cli),
                "seal",
                "--journal",
                str(cli_journal),
                "--request-event-id",
                "u1",
                "--draft-event-id",
                "d1",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [sys.executable, str(cli), "export", "--journal", str(cli_journal), "--output", str(cli_live)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(cli_live.read_text())["schema_version"], "chatgpt-live-session-v0.3")

    def test_end_to_end_exporter_normalizer_adapter_allow(self) -> None:
        exporter = ROOT / "tools" / "chatgpt_live_session_exporter.py"
        normalizer = ROOT / "tools" / "chatgpt_conversation_normalizer.py"
        adapter = ROOT / "tools" / "chatgpt_liminal_adapter.py"
        if not all(path.exists() for path in (exporter, normalizer, adapter)):
            self.skipTest("full repository pipeline is not present in local fixture")

        self._basic_recording()
        self.recorder.seal(request_event_id="user-1", draft_event_id="draft-1")
        live = self.root / "live.json"
        self.recorder.export_live_session(live)
        exported = self.root / "exported"
        normalized = self.root / "normalized"
        advice = self.root / "advice"
        subprocess.run(
            [sys.executable, str(exporter), "--input", str(live), "--output-dir", str(exported)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(normalizer),
                "--input",
                str(exported / "chatgpt-conversation-bundle.json"),
                "--output-dir",
                str(normalized),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                sys.executable,
                str(adapter),
                "--input",
                str(normalized / "chatgpt-liminal-input.json"),
                "--output-dir",
                str(advice),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads((advice / "chatgpt-liminal-advice.json").read_text())
        self.assertEqual(result["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
