#!/usr/bin/env python3
"""Deterministic v0.8 transaction self-check with a simulated connector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import GitHubAgentBridge
from sdk.liminal_github_runtime import ConnectedGitHubRuntime
from sdk.liminal_github_transaction import (
    GitHubTransactionOrchestrator,
    checkpoint_reference,
)

REPO = "safal207/LiminalOSAI"
SHA_BRANCH = "a" * 40
SHA_HEAD = "b" * 40
SHA_MERGE = "c" * 40


class FixtureConnector:
    def __init__(self):
        self.calls = []

    def preflight(self, tool_name):
        allowed = {
            "create_branch",
            "create_file",
            "create_pull_request",
            "get_commit_combined_status",
            "merge_pull_request",
        }
        if tool_name not in allowed:
            raise RuntimeError(f"unsupported fixture tool: {tool_name}")

    def invoke(self, tool_name, arguments):
        self.calls.append(
            {"tool_name": tool_name, "arguments": json.loads(json.dumps(arguments))}
        )
        if tool_name == "create_branch":
            return {"branch": "agent/v08-self-check", "sha": SHA_BRANCH}
        if tool_name == "create_file":
            return {"commit_sha": SHA_HEAD}
        if tool_name == "create_pull_request":
            return {"number": 108, "url": f"https://github.com/{REPO}/pull/108"}
        if tool_name == "get_commit_combined_status":
            return {"state": "success", "statuses": []}
        if tool_name == "merge_pull_request":
            return {"merged": True, "sha": SHA_MERGE, "message": "merged"}
        raise RuntimeError(f"unexpected fixture tool: {tool_name}")


def steps():
    branch = checkpoint_reference("branch", "branch")
    head = checkpoint_reference("file", "commit_sha")
    pr_number = checkpoint_reference("pr", "number")
    return [
        {
            "step_id": "branch",
            "call_id": "v08-branch",
            "action": "create_branch",
            "arguments": {
                "repository_full_name": REPO,
                "branch_name": "agent/v08-self-check",
                "base_ref": "main",
            },
            "exports": {"branch": "branch"},
            "expect": {},
        },
        {
            "step_id": "file",
            "call_id": "v08-file",
            "action": "create_file",
            "arguments": {
                "repository_full_name": REPO,
                "path": "reports/v08-self-check.txt",
                "content": "safe fixture\n",
                "message": "test: add v0.8 fixture",
                "branch": branch,
            },
            "exports": {"commit_sha": "commit_sha"},
            "expect": {},
        },
        {
            "step_id": "pr",
            "call_id": "v08-pr",
            "action": "create_pull_request",
            "arguments": {
                "repository_full_name": REPO,
                "title": "v0.8 self-check",
                "head": branch,
                "base": "main",
                "body": "Deterministic fixture only",
                "draft": False,
            },
            "exports": {"number": "number"},
            "expect": {},
        },
        {
            "step_id": "ci",
            "call_id": "v08-ci",
            "action": "get_commit_combined_status",
            "arguments": {"repo_full_name": REPO, "commit_sha": head},
            "exports": {"state": "state"},
            "expect": {"state": "success"},
        },
        {
            "step_id": "merge",
            "call_id": "v08-merge",
            "action": "merge_pull_request",
            "arguments": {
                "repository_full_name": REPO,
                "pr_number": pr_number,
                "expected_head_sha": head,
                "merge_method": "merge",
            },
            "exports": {"merge_sha": "sha"},
            "expect": {"merged": True},
            "gate_step_ids": ["ci"],
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    GitHubAgentBridge.create(
        out / "bridge.json",
        host_trace_path=out / "host-trace.json",
        recorder_path=out / "session-journal.json",
        session_id="github-transaction-v08-self-check",
        high_stakes=False,
        requires_current_information=True,
        allowed_repositories=[REPO],
    )
    ConnectedGitHubRuntime.create(
        out / "runtime.json",
        bridge_config_path=out / "bridge.json",
        max_response_bytes=16384,
    )
    orchestrator = GitHubTransactionOrchestrator.create(
        out / "transaction-plan.json",
        out / "transaction-journal.json",
        runtime_config_path=out / "runtime.json",
        transaction_id="transaction-v08-self-check",
        repository_full_name=REPO,
        steps=steps(),
    )
    orchestrator.record_user_message(
        event_id="user-1",
        text="Execute the exact reviewed branch, file, PR, CI gate, and merge transaction.",
    )
    for index, step in enumerate(orchestrator.plan.steps):
        if step.effect == "write":
            orchestrator.authorize_step(
                step_id=step.step_id,
                event_id=f"authorization-{index}",
                text=f"Authorize exactly {step.call_id}",
            )

    connector = FixtureConnector()
    verification = orchestrator.run(connector)
    orchestrator.record_assistant_draft(
        event_id="draft-1",
        response="The authorized GitHub transaction completed after a successful CI gate.",
        no_signal=False,
        intent_alignment=0.99,
    )
    orchestrator.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The authorized GitHub transaction completed after a successful CI gate.",
        kind="fact",
        confidence=0.99,
        requires_current_information=True,
        evidence_event_ids=["v08-merge"],
    )
    orchestrator.seal(request_event_id="user-1", draft_event_id="draft-1")
    orchestrator.export_live_session(out / "live-session.json")
    recovery = orchestrator.recovery_report()
    (out / "connector-calls.json").write_text(
        json.dumps(connector.calls, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "transaction-verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "recovery-report.json").write_text(
        json.dumps(recovery, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": verification["journal"]["status"],
        "transaction_id": verification["transaction_id"],
        "step_count": verification["step_count"],
        "journal_head_sha256": verification["journal"]["head_sha256"],
        "connector_calls": len(connector.calls),
        "live_session": str(out / "live-session.json"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
