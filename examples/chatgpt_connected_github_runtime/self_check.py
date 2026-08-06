#!/usr/bin/env python3
"""Deterministic v0.7 self-check with a connected namespace fixture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import GitHubAgentBridge, GitHubOperation
from sdk.liminal_github_runtime import (
    ConnectedGitHubRuntime,
    ConnectorNamespaceInvoker,
)

REPO = "safal207/LiminalOSAI"
RESULT_SHA = "c" * 40


class ConnectedGitHubFixture:
    """CI-only namespace shaped like the connected GitHub tool surface."""

    def __init__(self):
        self.invocations: list[dict] = []

    def create_branch(self, **arguments):
        self.invocations.append(dict(arguments))
        return {
            "result": {
                "branch": arguments["branch_name"],
                "sha": RESULT_SHA,
            },
            "error": None,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    GitHubAgentBridge.create(
        out / "github-bridge-config.json",
        host_trace_path=out / "host-trace.json",
        recorder_path=out / "session-journal.json",
        session_id="connected-github-runtime-self-check",
        high_stakes=False,
        requires_current_information=True,
        allowed_repositories=[REPO],
    )
    runtime = ConnectedGitHubRuntime.create(
        out / "connected-runtime-config.json",
        bridge_config_path=out / "github-bridge-config.json",
    )
    runtime.record_user_message(
        event_id="user-1",
        text="Create the explicitly authorized review branch and report the result.",
    )
    operation = GitHubOperation(
        call_id="github-create-branch-1",
        action="create_branch",
        arguments={
            "repository_full_name": REPO,
            "branch_name": "agent/v07-self-check",
            "base_ref": "main",
        },
    )
    runtime.authorize_operation(
        event_id="auth-1",
        text="Authorize exactly github-create-branch-1",
        operation=operation,
    )
    namespace = ConnectedGitHubFixture()
    receipt = runtime.execute(operation, ConnectorNamespaceInvoker(namespace))
    runtime.record_assistant_draft(
        event_id="draft-1",
        response="The explicitly authorized review branch was created successfully.",
        no_signal=False,
        intent_alignment=0.99,
    )
    runtime.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The explicitly authorized review branch was created successfully.",
        kind="fact",
        confidence=0.99,
        requires_current_information=True,
        evidence_event_ids=[operation.call_id],
    )
    runtime.seal(request_event_id="user-1", draft_event_id="draft-1")
    runtime.export_live_session(out / "live-session.json")
    (out / "connected-github-receipt.json").write_text(
        json.dumps(receipt.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "fixture-invocations.json").write_text(
        json.dumps(namespace.invocations, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(runtime.verify(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
