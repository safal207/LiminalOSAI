#!/usr/bin/env python3
"""Deterministic v0.9 governed transaction self-check."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import GitHubAgentBridge
from sdk.liminal_github_policy import GitHubTransactionPolicyEngine
from sdk.liminal_github_runtime import ConnectedGitHubRuntime
from sdk.liminal_github_transaction import GitHubTransactionOrchestrator, checkpoint_reference

REPO = "safal207/LiminalOSAI"
SHA_BRANCH = "a" * 40
SHA_HEAD = "b" * 40
SHA_MERGE = "c" * 40


class FixtureConnector:
    def __init__(self):
        self.calls = []

    def preflight(self, tool_name):
        if tool_name not in {
            "create_branch", "create_file", "create_pull_request",
            "get_commit_combined_status", "merge_pull_request",
        }:
            raise RuntimeError(f"unsupported fixture tool: {tool_name}")

    def invoke(self, tool_name, arguments):
        self.calls.append({"tool_name": tool_name, "arguments": json.loads(json.dumps(arguments))})
        if tool_name == "create_branch":
            return {"branch": "agent/v09-self-check", "sha": SHA_BRANCH}
        if tool_name == "create_file":
            return {"commit_sha": SHA_HEAD}
        if tool_name == "create_pull_request":
            return {"number": 109, "url": f"https://github.com/{REPO}/pull/109"}
        if tool_name == "get_commit_combined_status":
            return {"state": "success", "statuses": []}
        if tool_name == "merge_pull_request":
            return {"merged": True, "sha": SHA_MERGE, "message": "merged"}
        raise RuntimeError(tool_name)


def steps():
    branch = checkpoint_reference("branch", "branch")
    head = checkpoint_reference("file", "commit_sha")
    pr_number = checkpoint_reference("pr", "number")
    return [
        {
            "step_id": "branch", "call_id": "v09-branch", "action": "create_branch",
            "arguments": {
                "repository_full_name": REPO,
                "branch_name": "agent/v09-self-check", "base_ref": "main",
            },
            "exports": {"branch": "branch"}, "expect": {},
        },
        {
            "step_id": "file", "call_id": "v09-file", "action": "create_file",
            "arguments": {
                "repository_full_name": REPO,
                "path": "reports/v09-self-check.txt",
                "content": "safe governed fixture\n",
                "message": "test: add v0.9 fixture", "branch": branch,
            },
            "exports": {"commit_sha": "commit_sha"}, "expect": {},
        },
        {
            "step_id": "pr", "call_id": "v09-pr", "action": "create_pull_request",
            "arguments": {
                "repository_full_name": REPO, "title": "v0.9 self-check",
                "head": branch, "base": "main", "body": "Fixture", "draft": False,
            },
            "exports": {"number": "number"}, "expect": {},
        },
        {
            "step_id": "ci", "call_id": "v09-ci", "action": "get_commit_combined_status",
            "arguments": {"repo_full_name": REPO, "commit_sha": head},
            "exports": {"state": "state"}, "expect": {"state": "success"},
        },
        {
            "step_id": "merge", "call_id": "v09-merge", "action": "merge_pull_request",
            "arguments": {
                "repository_full_name": REPO, "pr_number": pr_number,
                "expected_head_sha": head, "merge_method": "merge",
            },
            "exports": {"merge_sha": "sha"}, "expect": {"merged": True},
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
        session_id="github-policy-v09-self-check",
        high_stakes=False,
        requires_current_information=True,
        allowed_repositories=[REPO],
    )
    ConnectedGitHubRuntime.create(
        out / "runtime.json",
        bridge_config_path=out / "bridge.json",
        max_response_bytes=16384,
    )
    GitHubTransactionOrchestrator.create(
        out / "transaction-plan.json",
        out / "transaction-journal.json",
        runtime_config_path=out / "runtime.json",
        transaction_id="transaction-v09-self-check",
        repository_full_name=REPO,
        steps=steps(),
    )
    engine = GitHubTransactionPolicyEngine.create(
        out / "policy.json",
        out / "policy-snapshot.json",
        out / "approval-ledger.json",
        transaction_plan_path=out / "transaction-plan.json",
        transaction_journal_path=out / "transaction-journal.json",
        policy_id="default-v09-self-check",
        allowed_repositories=[REPO],
    )
    engine.record_user_message(
        event_id="user-1",
        text="Execute the exact governed transaction after all required approvals.",
    )

    approval_count = 0
    for requirement in engine.snapshot.requirements:
        for role, count in requirement.required_role_counts.items():
            for index in range(count):
                approval_count += 1
                engine.record_approval(
                    approval_id=f"approval-{approval_count}",
                    principal_id=f"principal-{role}-{approval_count}-{index}",
                    role=role,
                    decision="approve",
                    requirement_id=requirement.requirement_id,
                    evidence_locator=f"urn:self-check:approval:{approval_count}",
                )
    for index, step in enumerate(engine.plan.steps):
        if step.effect == "write":
            engine.authorize_step(
                step_id=step.step_id,
                event_id=f"write-authorization-{index}",
                text=f"Authorize exactly {step.call_id}",
            )

    connector = FixtureConnector()
    verification = engine.run(connector)
    engine.record_assistant_draft(
        event_id="draft-1",
        response="The governed GitHub transaction completed after policy, approvals, and CI.",
        no_signal=False,
        intent_alignment=0.99,
    )
    engine.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The governed GitHub transaction completed after policy, approvals, and CI.",
        kind="fact",
        confidence=0.99,
        requires_current_information=True,
        evidence_event_ids=["v09-merge"],
    )
    engine.seal(request_event_id="user-1", draft_event_id="draft-1")
    engine.export_live_session(out / "live-session.json")
    evidence = engine.evidence_summary()
    (out / "connector-calls.json").write_text(
        json.dumps(connector.calls, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "policy-verification.json").write_text(
        json.dumps(engine.verify(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "policy-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "status": verification["journal"]["status"],
        "approval_count": approval_count,
        "approval_status": engine.verify()["approval"]["status"],
        "snapshot_sha256": engine.snapshot.snapshot_sha256,
        "engine_evidence_sha256": evidence["engine_evidence_sha256"],
        "connector_calls": len(connector.calls),
        "live_session": str(out / "live-session.json"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
