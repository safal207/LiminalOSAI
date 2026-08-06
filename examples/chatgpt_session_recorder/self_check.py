#!/usr/bin/env python3
"""Build a deterministic v0.4 journal and export a v0.3 live session."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_session_recorder import SessionRecorder  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    journal = args.output_dir / "session-journal.json"
    live = args.output_dir / "chatgpt-live-session.json"

    recorder = SessionRecorder.create(
        journal,
        session_id="session-recorder-self-check-001",
        high_stakes=False,
        requires_current_information=False,
    )
    recorder.record_user_message(event_id="user-go", text="Go")
    recorder.record_authorization(
        event_id="auth-go",
        text="Go",
        authorized_event_ids=["merge-pr-98"],
    )
    recorder.record_source(
        event_id="source-main",
        handle="main-state",
        verified=True,
        freshness="stable",
        source_kind="repository",
        locator="commit/096ed16e2e53fd16161b9bb4f96c6230a4de657f",
    )
    recorder.record_tool_event(
        event_id="merge-pr-98",
        tool="GitHub",
        operation="merge pull request 98",
        status="success",
        effect="write",
        evidence_eligible=True,
        freshness="stable",
        locator="pull/98#merged",
        reversible=False,
        recovery_plan="Revert merge commit 096ed16e2e53fd16161b9bb4f96c6230a4de657f",
    )
    recorder.record_assistant_draft(
        event_id="draft-final",
        response=(
            "The repository contains the ChatGPT Live Session Exporter v0.3, "
            "introduced through the explicitly authorized merge of pull request 98."
        ),
        no_signal=False,
        intent_alignment=0.99,
    )
    recorder.record_claim(
        event_id="claim-main",
        draft_event_id="draft-final",
        text="Commit 096ed16 contains the ChatGPT Live Session Exporter v0.3.",
        kind="fact",
        confidence=0.99,
        requires_current_information=False,
        evidence_event_ids=["source-main"],
    )
    recorder.record_claim(
        event_id="claim-merge",
        draft_event_id="draft-final",
        text="Pull request 98 was merged through an explicit prior authorization edge.",
        kind="fact",
        confidence=0.99,
        requires_current_information=False,
        evidence_event_ids=["merge-pr-98"],
    )
    recorder.seal(request_event_id="user-go", draft_event_id="draft-final")
    recorder.export_live_session(live)
    print(json.dumps(recorder.verify(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
