from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_host_adapter import (
    AUTHORITY,
    HostAdapterError,
    HostIntegrationAdapter,
    ToolCallSpec,
)


class HostAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.trace = self.root / "host-trace.json"
        self.journal = self.root / "session-journal.json"
        self.adapter = HostIntegrationAdapter.create(
            self.trace,
            recorder_path=self.journal,
            session_id="session-1",
            high_stakes=False,
            requires_current_information=True,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def spec(self, **overrides):
        data = dict(
            call_id="call-1",
            tool="ExampleTool",
            operation="read state",
            effect="read",
            evidence_eligible=True,
            freshness="current",
            reversible=True,
            recovery_plan=None,
        )
        data.update(overrides)
        return ToolCallSpec(**data)

    def authorize(self, call_id="call-1"):
        return self.adapter.record_authorization(
            event_id=f"auth-{call_id}", text="Go", authorized_event_ids=[call_id]
        )

    def test_create_initializes_trace_and_journal(self):
        result = self.adapter.verify(allow_pending=True)
        self.assertEqual(result["started_calls"], 0)
        self.assertEqual(result["completed_calls"], 0)
        self.assertFalse(result["authority"]["tool_execution_ownership"])

    def test_write_requires_explicit_prior_authorization(self):
        with self.assertRaisesRegex(HostAdapterError, "requires explicit prior authorization"):
            self.adapter.start_tool_call(self.spec(effect="write"))
        self.assertEqual(self.adapter.verify(allow_pending=True)["started_calls"], 0)

    def test_read_call_can_complete_without_authorization(self):
        with self.adapter.tool_call(self.spec()) as call:
            event = call.succeed(locator="fixture://read")
        self.assertEqual(event["status"], "success")
        self.assertEqual(self.adapter.verify()["completed_calls"], 1)

    def test_write_call_preserves_authorization_edge(self):
        self.authorize()
        with self.adapter.tool_call(self.spec(effect="write")) as call:
            call.succeed(locator="fixture://write")
        trace = json.loads(self.trace.read_text())
        start = trace["entries"][0]["record"]
        self.assertEqual(start["authorization_event_ids"], ["auth-call-1"])

    def test_only_one_call_may_be_pending(self):
        self.adapter.start_tool_call(self.spec())
        with self.assertRaisesRegex(HostAdapterError, "only one visible tool call"):
            self.adapter.start_tool_call(self.spec(call_id="call-2"))

    def test_visible_events_are_blocked_while_call_pending(self):
        self.adapter.start_tool_call(self.spec())
        with self.assertRaisesRegex(HostAdapterError, "pending tool calls block"):
            self.adapter.record_user_message(event_id="user-1", text="hello")

    def test_recorder_mutation_while_pending_blocks_completion(self):
        self.adapter.start_tool_call(self.spec())
        self.adapter.recorder.record_user_message(event_id="external", text="changed")
        with self.assertRaisesRegex(HostAdapterError, "recorder changed"):
            self.adapter.finish_tool_call("call-1", status="success", locator="fixture://read")

    def test_evidence_eligible_call_requires_locator(self):
        self.adapter.start_tool_call(self.spec())
        with self.assertRaisesRegex(HostAdapterError, "requires locator"):
            self.adapter.finish_tool_call("call-1", status="success", locator=None)

    def test_non_evidence_call_may_have_null_locator(self):
        with self.adapter.tool_call(self.spec(evidence_eligible=False)) as call:
            event = call.succeed(locator=None)
        self.assertIsNone(event["locator"])

    def test_context_manager_exception_records_failure(self):
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with self.adapter.tool_call(self.spec()) as _call:
                raise RuntimeError("boom")
        event = self.adapter.recorder.read()["entries"][-1]["event"]
        self.assertEqual(event["status"], "failure")
        self.assertTrue(event["locator"].startswith("exception:"))

    def test_context_manager_requires_explicit_outcome(self):
        with self.assertRaisesRegex(HostAdapterError, "without an explicit outcome"):
            with self.adapter.tool_call(self.spec()):
                pass
        self.assertEqual(self.adapter.verify(allow_pending=True)["pending_call_ids"], ["call-1"])

    def test_duplicate_call_id_is_rejected(self):
        with self.adapter.tool_call(self.spec()) as call:
            call.succeed(locator="fixture://one")
        with self.assertRaisesRegex(HostAdapterError, "already exists"):
            self.adapter.start_tool_call(self.spec())

    def test_finish_requires_pending_call(self):
        with self.assertRaisesRegex(HostAdapterError, "not pending"):
            self.adapter.finish_tool_call("missing", status="success", locator="fixture://x")

    def test_verify_rejects_pending_by_default(self):
        self.adapter.start_tool_call(self.spec())
        with self.assertRaisesRegex(HostAdapterError, "pending tool calls"):
            self.adapter.verify()

    def test_verify_can_report_pending(self):
        self.adapter.start_tool_call(self.spec())
        result = self.adapter.verify(allow_pending=True)
        self.assertEqual(result["pending_call_ids"], ["call-1"])

    def test_trace_content_tampering_fails_closed(self):
        with self.adapter.tool_call(self.spec()) as call:
            call.succeed(locator="fixture://read")
        trace = json.loads(self.trace.read_text())
        trace["entries"][0]["record"]["operation"] = "tampered"
        self.trace.write_text(json.dumps(trace))
        with self.assertRaisesRegex(HostAdapterError, "entry hash mismatch"):
            self.adapter.verify()

    def test_trace_head_tampering_fails_closed(self):
        data = json.loads(self.trace.read_text())
        data["head_sha256"] = "f" * 64
        self.trace.write_text(json.dumps(data))
        with self.assertRaisesRegex(HostAdapterError, "head_sha256 mismatch"):
            self.adapter.verify(allow_pending=True)

    def test_recovery_completes_crash_gap(self):
        self.adapter.start_tool_call(self.spec())
        self.adapter.recorder.record_tool_event(
            event_id="call-1",
            tool="ExampleTool",
            operation="read state",
            status="success",
            effect="read",
            evidence_eligible=True,
            freshness="current",
            locator="fixture://recovered",
            reversible=True,
            recovery_plan=None,
        )
        recovered = self.adapter.recover_tool_call("call-1")
        self.assertEqual(recovered["status"], "success")
        self.assertEqual(self.adapter.verify()["completed_calls"], 1)

    def test_recovery_rejects_non_latest_event(self):
        self.adapter.start_tool_call(self.spec())
        self.adapter.recorder.record_tool_event(
            event_id="call-1",
            tool="ExampleTool",
            operation="read state",
            status="success",
            effect="read",
            evidence_eligible=True,
            freshness="current",
            locator="fixture://recovered",
            reversible=True,
            recovery_plan=None,
        )
        self.adapter.recorder.record_user_message(event_id="later", text="later")
        with self.assertRaisesRegex(HostAdapterError, "latest recorder event"):
            self.adapter.recover_tool_call("call-1")

    def test_seal_is_blocked_by_pending_call(self):
        self.adapter.record_user_message(event_id="user-1", text="request")
        self.adapter.record_assistant_draft(
            event_id="draft-1", response="draft", no_signal=False, intent_alignment=1.0
        )
        self.adapter.start_tool_call(self.spec())
        with self.assertRaises(HostAdapterError):
            self.adapter.seal(request_event_id="user-1", draft_event_id="draft-1")

    def test_full_record_seal_export(self):
        self.adapter.record_user_message(event_id="user-1", text="Run safe tool")
        self.authorize()
        with self.adapter.tool_call(self.spec(effect="write")) as call:
            call.succeed(locator="fixture://write")
        self.adapter.record_assistant_draft(
            event_id="draft-1",
            response="The authorized tool completed.",
            no_signal=False,
            intent_alignment=1.0,
        )
        self.adapter.record_claim(
            event_id="claim-1",
            draft_event_id="draft-1",
            text="The authorized tool completed.",
            kind="fact",
            confidence=1.0,
            requires_current_information=True,
            evidence_event_ids=["call-1"],
        )
        self.adapter.seal(request_event_id="user-1", draft_event_id="draft-1")
        output = self.root / "live-session.json"
        live = self.adapter.export_live_session(output)
        self.assertEqual(live["schema_version"], "chatgpt-live-session-v0.3")
        self.assertTrue(output.exists())

    def test_invalid_spec_is_rejected(self):
        with self.assertRaises(HostAdapterError):
            self.adapter.start_tool_call(self.spec(effect="explode"))

    def test_authority_map_remains_no_authority(self):
        self.assertFalse(AUTHORITY["authorization_inference"])
        self.assertFalse(AUTHORITY["tool_result_fabrication"])
        self.assertFalse(AUTHORITY["merge"])
        self.assertFalse(AUTHORITY["model_weight_update"])

    def test_cli_round_trip(self):
        cli = Path(__file__).resolve().parents[1] / "tools" / "chatgpt_host_adapter.py"
        root = self.root / "cli"
        root.mkdir()
        trace = root / "trace.json"
        journal = root / "journal.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(cli),
                "init",
                "--trace",
                str(trace),
                "--journal",
                str(journal),
                "--session-id",
                "cli-session",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        verify = subprocess.run(
            [sys.executable, str(cli), "verify", "--trace", str(trace)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)


if __name__ == "__main__":
    unittest.main()
