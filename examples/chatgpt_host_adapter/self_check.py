#!/usr/bin/env python3
"""Repository self-check for Host Integration Adapter v0.5."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_host_adapter import HostIntegrationAdapter, ToolCallSpec


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    trace = out / "host-trace.json"
    journal = out / "session-journal.json"
    artifact = out / "authorized-artifact.txt"
    live_session = out / "live-session.json"

    adapter = HostIntegrationAdapter.create(
        trace,
        recorder_path=journal,
        session_id="host-adapter-self-check-001",
        high_stakes=False,
        requires_current_information=True,
    )
    adapter.record_user_message(
        event_id="user-request-1",
        text="Create one reversible local artifact and report the verified result",
    )
    adapter.record_authorization(
        event_id="authorization-1",
        text="Go",
        authorized_event_ids=["tool-write-1"],
    )

    spec = ToolCallSpec(
        call_id="tool-write-1",
        tool="LocalFileHost",
        operation="write authorized self-check artifact",
        effect="write",
        evidence_eligible=True,
        freshness="current",
        reversible=True,
        recovery_plan="Delete the generated authorized-artifact.txt file",
    )
    with adapter.tool_call(spec) as call:
        artifact.write_text("host adapter self-check\n", encoding="utf-8")
        call.succeed(locator=str(artifact))

    adapter.record_assistant_draft(
        event_id="draft-1",
        response="The explicitly authorized local artifact was created successfully.",
        no_signal=False,
        intent_alignment=1.0,
    )
    adapter.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The explicitly authorized local artifact was created successfully.",
        kind="fact",
        confidence=1.0,
        requires_current_information=True,
        evidence_event_ids=["tool-write-1"],
    )
    adapter.seal(
        request_event_id="user-request-1",
        draft_event_id="draft-1",
    )
    exported = adapter.export_live_session(live_session)
    verification = adapter.verify()
    print(
        json.dumps(
            {
                "verification": verification,
                "live_session": str(live_session),
                "event_count": len(exported["events"]),
                "artifact": str(artifact),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
