#!/usr/bin/env python3
"""Deterministic v1.0 signed governance capsule self-check."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import GitHubAgentBridge
from sdk.liminal_github_policy import GitHubTransactionPolicyEngine
from sdk.liminal_github_runtime import ConnectedGitHubRuntime
from sdk.liminal_github_transaction import GitHubTransactionOrchestrator, checkpoint_reference
from sdk.liminal_governance_capsule import (
    ALGORITHM,
    GovernanceCapsuleSession,
    GovernanceTrustStore,
    generate_ed25519_keypair,
    issue_capsule,
)

REPO = "safal207/LiminalOSAI"
AUDIENCE = "github-transaction-executor"
NOW = 1_800_000_000
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
            return {"branch": "agent/v10-self-check", "sha": SHA_BRANCH}
        if tool_name == "create_file":
            return {"commit_sha": SHA_HEAD}
        if tool_name == "create_pull_request":
            return {"number": 110, "url": f"https://github.com/{REPO}/pull/110"}
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
            "step_id": "branch", "call_id": "v10-branch", "action": "create_branch",
            "arguments": {
                "repository_full_name": REPO,
                "branch_name": "agent/v10-self-check", "base_ref": "main",
            },
            "exports": {"branch": "branch"}, "expect": {},
        },
        {
            "step_id": "file", "call_id": "v10-file", "action": "create_file",
            "arguments": {
                "repository_full_name": REPO,
                "path": "reports/v10-self-check.txt",
                "content": "signed governed fixture\n",
                "message": "test: add v1.0 fixture", "branch": branch,
            },
            "exports": {"commit_sha": "commit_sha"}, "expect": {},
        },
        {
            "step_id": "pr", "call_id": "v10-pr", "action": "create_pull_request",
            "arguments": {
                "repository_full_name": REPO, "title": "v1.0 self-check",
                "head": branch, "base": "main", "body": "Fixture", "draft": False,
            },
            "exports": {"number": "number"}, "expect": {},
        },
        {
            "step_id": "ci", "call_id": "v10-ci", "action": "get_commit_combined_status",
            "arguments": {"repo_full_name": REPO, "commit_sha": head},
            "exports": {"state": "state"}, "expect": {"state": "success"},
        },
        {
            "step_id": "merge", "call_id": "v10-merge", "action": "merge_pull_request",
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
        session_id="signed-governance-v10-self-check",
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
        transaction_id="transaction-v10-self-check",
        repository_full_name=REPO,
        steps=steps(),
    )
    engine = GitHubTransactionPolicyEngine.create(
        out / "policy.json",
        out / "policy-snapshot.json",
        out / "approval-ledger.json",
        transaction_plan_path=out / "transaction-plan.json",
        transaction_journal_path=out / "transaction-journal.json",
        policy_id="default-v10-self-check",
        allowed_repositories=[REPO],
    )
    engine.record_user_message(
        event_id="user-1",
        text="Execute the exact transaction only under the signed governance capsule.",
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

    private_key, public_key = generate_ed25519_keypair()
    with tempfile.TemporaryDirectory(prefix="liminal-v10-key-") as key_dir:
        private_path = Path(key_dir) / "issuer-private.pem"
        private_path.write_bytes(private_key)
        capsule = issue_capsule(
            engine,
            private_key_path=private_path,
            capsule_id="capsule-v10-self-check",
            issuer_id="issuer-v10-self-check",
            subject_id="user:alex",
            key_id="key-v10-self-check",
            audience=AUDIENCE,
            ttl_seconds=900,
            issued_at_unix=NOW,
            nonce="nonce-v10-self-check",
            output_path=out / "governance-capsule.json",
        )

    trust_store = GovernanceTrustStore.build(
        trust_store_id="trust-v10-self-check",
        max_ttl_seconds=900,
        max_clock_skew_seconds=0,
        keys=[{
            "issuer_id": "issuer-v10-self-check",
            "key_id": "key-v10-self-check",
            "algorithm": ALGORITHM,
            "public_key_pem": public_key.decode("utf-8"),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "valid_from_unix": NOW - 60,
            "valid_until_unix": NOW + 3600,
            "revoked_at_unix": None,
            "allowed_audiences": [AUDIENCE],
            "allowed_repositories": [REPO],
        }],
    )
    (out / "governance-trust-store.json").write_text(
        json.dumps(trust_store.as_document(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    session = GovernanceCapsuleSession(
        engine,
        capsule_path=out / "governance-capsule.json",
        trust_store_path=out / "governance-trust-store.json",
        expected_audience=AUDIENCE,
        clock=lambda: NOW,
    )
    issuance_verification = session.verify()
    for index, step in enumerate(engine.plan.steps):
        if step.effect == "write":
            session.authorize_step(
                step_id=step.step_id,
                event_id=f"write-authorization-{index}",
                text=f"Authorize exactly {step.call_id} under capsule {capsule.claims.capsule_id}",
            )

    connector = FixtureConnector()
    transaction = session.run(connector)
    post_run_verification = session.verify()
    session.record_assistant_draft(
        event_id="draft-1",
        response="The signed governed transaction completed after policy, approvals, signature, and CI.",
        no_signal=False,
        intent_alignment=0.99,
    )
    session.record_claim(
        event_id="claim-1",
        draft_event_id="draft-1",
        text="The signed governed transaction completed after policy, approvals, signature, and CI.",
        kind="fact",
        confidence=0.99,
        requires_current_information=True,
        evidence_event_ids=["v10-merge"],
    )
    session.seal(request_event_id="user-1", draft_event_id="draft-1")
    session.export_live_session(out / "live-session.json")

    (out / "connector-calls.json").write_text(
        json.dumps(connector.calls, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "capsule-verification-issued.json").write_text(
        json.dumps(issuance_verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "capsule-verification-post-run.json").write_text(
        json.dumps(post_run_verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "policy-verification.json").write_text(
        json.dumps(engine.verify(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "status": transaction["journal"]["status"],
        "approval_count": approval_count,
        "capsule_status": post_run_verification["status"],
        "capsule_sha256": post_run_verification["capsule_sha256"],
        "anchor_is_ancestor": post_run_verification["transaction_journal_anchor_is_ancestor"],
        "connector_calls": len(connector.calls),
        "private_key_persisted": False,
        "live_session": str(out / "live-session.json"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
