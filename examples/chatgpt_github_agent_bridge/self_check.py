#!/usr/bin/env python3
"""Deterministic v0.6 self-check using an explicit simulated host executor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import (  # noqa: E402
    GitHubAgentBridge,
    GitHubExecutorResult,
    GitHubOperation,
)

REPO = "safal207/LiminalOSAI"
RESULT_SHA = "b" * 40


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    bridge = GitHubAgentBridge.create(
        output / "github-bridge-config.json",
        host_trace_path=output / "host-trace.json",
        recorder_path=output / "session-journal.json",
        session_id="github-bridge-self-check",
        high_stakes=False,
        requires_current_information=True,
        allowed_repositories=[REPO],
    )
    bridge.record_user_message(
        event_id="user-1",
        text="Create the explicitly authorized review branch and report the result.",
    )
    operation = GitHubOperation(
        call_id="github-create-branch-1",
        action="create_branch",
        arguments={
            "repository_full_name": REPO,
            "branch_name": "agent/v06-self-check",
            "base_ref": "main",
        },
    )
    bridge.authorize_operation(
        event_id="auth-1",
        text="Authorize exactly github-create-branch-1",
        operation=operation,
    )

    def simulated_host_executor(action: str, arguments: dict):
        """CI fixture only: a real host would dispatch to its GitHub connector here."""
        assert action == "create_branch"
        assert arguments["branch_name"] == "agent/v06-self-check"
        return GitHubExecutorResult.success(
            locator=(
                "https://github.com/safal207/LiminalOSAI/tree/agent/v06-self-check"
                f"@{RESULT_SHA}"
            ),
            payload={
                "branch": "agent/v06-self-check",
                "sha": RESULT_SHA,
                "simulated": True,
            },
        )

    receipt = bridge.execute(operation, simulated_host_executor)
    bridge.record_assistant_draft(
        event_id="draft-1",
        response="The explicitly authorized review branch was created successfully.",
        no_signal=False,
        intent_alignment=0.99,
    )
    bridge.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The explicitly authorized review branch was created successfully.",
        kind="fact",
        confidence=0.99,
        requires_current_information=True,
        evidence_event_ids=[operation.call_id],
    )
    bridge.seal(request_event_id="user-1", draft_event_id="draft-1")
    bridge.export_live_session(output / "live-session.json")
    (output / "github-execution-receipt.json").write_text(
        json.dumps(receipt.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(bridge.verify(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
