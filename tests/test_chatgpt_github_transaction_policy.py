from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_github_bridge import GitHubAgentBridge
from sdk.liminal_github_policy import (
    AUTHORITY,
    GitHubTransactionPolicyEngine,
    PolicyError,
    PolicySnapshot,
    TransactionPolicy,
    default_rule_documents,
)
from sdk.liminal_github_runtime import ConnectedGitHubRuntime
from sdk.liminal_github_transaction import GitHubTransactionOrchestrator, checkpoint_reference

REPO = "safal207/LiminalOSAI"
OTHER_REPO = "example/other"
SHA_BRANCH = "a" * 40
SHA_HEAD = "b" * 40
SHA_MERGE = "c" * 40


class FixtureConnector:
    def __init__(self):
        self.calls = []

    def preflight(self, tool_name):
        allowed = {
            "get_repo", "create_branch", "create_file", "create_pull_request",
            "get_commit_combined_status", "merge_pull_request",
        }
        if tool_name not in allowed:
            raise RuntimeError(f"unsupported fixture tool: {tool_name}")

    def invoke(self, tool_name, arguments):
        self.calls.append((tool_name, json.loads(json.dumps(arguments))))
        if tool_name == "get_repo":
            return {"name": "LiminalOSAI", "html_url": f"https://github.com/{REPO}"}
        if tool_name == "create_branch":
            return {"branch": "agent/v09-test", "sha": SHA_BRANCH}
        if tool_name == "create_file":
            return {"commit_sha": SHA_HEAD}
        if tool_name == "create_pull_request":
            return {"number": 109, "url": f"https://github.com/{REPO}/pull/109"}
        if tool_name == "get_commit_combined_status":
            return {"state": "success", "statuses": []}
        if tool_name == "merge_pull_request":
            return {"merged": True, "sha": SHA_MERGE, "message": "merged"}
        raise RuntimeError(tool_name)


def full_steps():
    branch = checkpoint_reference("branch", "branch")
    head = checkpoint_reference("file", "commit_sha")
    pr_number = checkpoint_reference("pr", "number")
    return [
        {
            "step_id": "branch", "call_id": "v09-branch", "action": "create_branch",
            "arguments": {
                "repository_full_name": REPO,
                "branch_name": "agent/v09-test", "base_ref": "main",
            },
            "exports": {"branch": "branch"}, "expect": {},
        },
        {
            "step_id": "file", "call_id": "v09-file", "action": "create_file",
            "arguments": {
                "repository_full_name": REPO,
                "path": "reports/v09-test.txt",
                "content": "reviewed secret-free fixture\n",
                "message": "test: add v0.9 fixture", "branch": branch,
            },
            "exports": {"commit_sha": "commit_sha"}, "expect": {},
        },
        {
            "step_id": "pr", "call_id": "v09-pr", "action": "create_pull_request",
            "arguments": {
                "repository_full_name": REPO,
                "title": "v0.9 fixture", "head": branch, "base": "main",
                "body": "Fixture", "draft": False,
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


def read_steps(count=1):
    return [
        {
            "step_id": f"read-{index}", "call_id": f"read-call-{index}",
            "action": "get_repo", "arguments": {"repository_full_name": REPO},
            "exports": {}, "expect": {},
        }
        for index in range(count)
    ]


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def create_orchestrator(self, steps=None):
        GitHubAgentBridge.create(
            self.root / "bridge.json",
            host_trace_path=self.root / "host-trace.json",
            recorder_path=self.root / "recorder.json",
            session_id="policy-test",
            high_stakes=False,
            requires_current_information=True,
            allowed_repositories=[REPO],
        )
        ConnectedGitHubRuntime.create(
            self.root / "runtime.json",
            bridge_config_path=self.root / "bridge.json",
            max_response_bytes=16384,
        )
        return GitHubTransactionOrchestrator.create(
            self.root / "plan.json",
            self.root / "transaction-journal.json",
            runtime_config_path=self.root / "runtime.json",
            transaction_id="transaction-v09-test",
            repository_full_name=REPO,
            steps=steps or full_steps(),
        )

    def create_engine(self, steps=None, **policy_kwargs):
        self.create_orchestrator(steps)
        return GitHubTransactionPolicyEngine.create(
            self.root / "policy.json",
            self.root / "snapshot.json",
            self.root / "approval-ledger.json",
            transaction_plan_path=self.root / "plan.json",
            transaction_journal_path=self.root / "transaction-journal.json",
            policy_id="policy-v09-test",
            allowed_repositories=policy_kwargs.pop("allowed_repositories", [REPO]),
            **policy_kwargs,
        )

    @staticmethod
    def rules_with(action, **updates):
        rules = default_rule_documents()
        for rule in rules:
            if rule["action"] == action:
                rule.update(updates)
                return rules
        raise AssertionError(action)

    def approve_all(self, engine):
        counter = 0
        for requirement in engine.snapshot.requirements:
            for role, count in requirement.required_role_counts.items():
                for role_index in range(count):
                    counter += 1
                    engine.record_approval(
                        approval_id=f"approval-{counter}",
                        principal_id=f"principal-{role}-{counter}-{role_index}",
                        role=role,
                        decision="approve",
                        requirement_id=requirement.requirement_id,
                        evidence_locator=f"urn:test:approval:{counter}",
                    )
        return counter

    def authorize_all_writes(self, engine):
        for index, step in enumerate(engine.plan.steps):
            if step.effect == "write":
                engine.authorize_step(
                    step_id=step.step_id,
                    event_id=f"write-auth-{index}",
                    text=f"Authorize exactly {step.call_id}",
                )

    def test_default_policy_covers_operation_catalog(self):
        policy = TransactionPolicy.build(policy_id="p", allowed_repositories=[REPO])
        self.assertEqual(set(policy.rule_map), {rule["action"] for rule in default_rule_documents()})
        self.assertFalse(policy.payload()["authority"]["identity_verification"])

    def test_policy_unknown_field_fails_closed(self):
        policy = TransactionPolicy.build(policy_id="p", allowed_repositories=[REPO]).as_document()
        policy["unexpected"] = True
        with self.assertRaisesRegex(PolicyError, "unsupported keys"):
            TransactionPolicy.from_document(policy)

    def test_duplicate_rule_rejected(self):
        rules = default_rule_documents()
        rules.append(dict(rules[0]))
        with self.assertRaisesRegex(PolicyError, "duplicate action"):
            TransactionPolicy.build(policy_id="p", allowed_repositories=[REPO], rules=rules)

    def test_policy_tampering_fails_closed(self):
        engine = self.create_engine(read_steps())
        raw = json.loads((self.root / "policy.json").read_text())
        raw["max_steps"] += 1
        (self.root / "policy.json").write_text(json.dumps(raw))
        with self.assertRaisesRegex(PolicyError, "policy_sha256 mismatch"):
            engine.verify()

    def test_snapshot_tampering_fails_closed(self):
        engine = self.create_engine(read_steps())
        raw = json.loads((self.root / "snapshot.json").read_text())
        raw["decision"] = "deny"
        (self.root / "snapshot.json").write_text(json.dumps(raw))
        with self.assertRaises(PolicyError):
            engine.verify()

    def test_plan_tampering_invalidates_snapshot(self):
        engine = self.create_engine(read_steps())
        raw = json.loads((self.root / "plan.json").read_text())
        raw["steps"][0]["call_id"] = "changed"
        (self.root / "plan.json").write_text(json.dumps(raw))
        with self.assertRaises(Exception):
            engine.verify()

    def test_repository_outside_policy_is_denied(self):
        engine = self.create_engine(read_steps(), allowed_repositories=[OTHER_REPO])
        result = engine.verify()
        self.assertEqual(result["decision"], "deny")
        self.assertIn(f"repository_not_allowed:{REPO}", result["denied_reasons"])

    def test_step_limit_denies_plan(self):
        engine = self.create_engine(full_steps(), max_steps=1)
        self.assertEqual(engine.verify()["decision"], "deny")

    def test_write_limit_denies_plan(self):
        engine = self.create_engine(full_steps(), max_write_steps=0)
        self.assertEqual(engine.verify()["decision"], "deny")

    def test_critical_limit_denies_plan(self):
        engine = self.create_engine(full_steps(), max_critical_steps=0)
        self.assertEqual(engine.verify()["decision"], "deny")

    def test_action_rule_can_deny_specific_action(self):
        engine = self.create_engine(full_steps(), rules=self.rules_with("create_file", allowed=False))
        self.assertIn("action_denied:file:create_file", engine.verify()["denied_reasons"])

    def test_occurrence_limit_is_enforced(self):
        engine = self.create_engine(read_steps(2), rules=self.rules_with("get_repo", max_occurrences=1))
        self.assertEqual(engine.verify()["decision"], "deny")

    def test_read_only_plan_needs_no_approval(self):
        engine = self.create_engine(read_steps())
        result = engine.verify()
        self.assertEqual(result["approval"]["status"], "ready")
        self.assertEqual(result["approval"]["pending_requirement_ids"], [])

    def test_full_plan_has_deterministic_requirements(self):
        engine = self.create_engine()
        ids = [item.requirement_id for item in engine.snapshot.requirements]
        self.assertEqual(ids, [
            "transaction:create_branch",
            "step:file:create_file",
            "step:pr:create_pull_request",
            "step:merge:merge_pull_request",
        ])

    def test_prepare_next_reports_pending_approvals(self):
        engine = self.create_engine()
        result = engine.prepare_next()
        self.assertEqual(result["approval_status"], "pending")
        self.assertEqual(result["next_step"]["step_id"], "branch")

    def test_wrong_role_is_rejected(self):
        engine = self.create_engine()
        requirement = engine.snapshot.requirement_map["step:file:create_file"]
        with self.assertRaisesRegex(PolicyError, "not permitted"):
            engine.record_approval(
                approval_id="a1", principal_id="p1", role="operator",
                decision="approve", requirement_id=requirement.requirement_id,
            )

    def test_unknown_requirement_is_rejected(self):
        engine = self.create_engine()
        with self.assertRaisesRegex(PolicyError, "unknown approval requirement"):
            engine.record_approval(
                approval_id="a1", principal_id="p1", role="reviewer",
                decision="approve", requirement_id="step:unknown:create_file",
            )

    def test_duplicate_approval_id_is_rejected(self):
        engine = self.create_engine()
        requirement = engine.snapshot.requirement_map["transaction:create_branch"]
        engine.record_approval(
            approval_id="a1", principal_id="p1", role="operator",
            decision="approve", requirement_id=requirement.requirement_id,
        )
        with self.assertRaisesRegex(PolicyError, "duplicate approval_id"):
            engine.record_approval(
                approval_id="a1", principal_id="p2", role="operator",
                decision="approve", requirement_id=requirement.requirement_id,
            )

    def test_same_principal_cannot_attest_same_requirement_twice(self):
        engine = self.create_engine()
        requirement = engine.snapshot.requirement_map["step:merge:merge_pull_request"]
        engine.record_approval(
            approval_id="a1", principal_id="same", role="reviewer",
            decision="approve", requirement_id=requirement.requirement_id,
        )
        with self.assertRaisesRegex(PolicyError, "already attested"):
            engine.record_approval(
                approval_id="a2", principal_id="same", role="release_manager",
                decision="approve", requirement_id=requirement.requirement_id,
            )

    def test_merge_requires_both_distinct_roles(self):
        engine = self.create_engine()
        merge = engine.snapshot.requirement_map["step:merge:merge_pull_request"]
        engine.record_approval(
            approval_id="a1", principal_id="reviewer-1", role="reviewer",
            decision="approve", requirement_id=merge.requirement_id,
        )
        status = engine.verify()["approval"]["requirements"][merge.requirement_id]
        self.assertFalse(status["satisfied"])
        engine.record_approval(
            approval_id="a2", principal_id="release-1", role="release_manager",
            decision="approve", requirement_id=merge.requirement_id,
        )
        status = engine.verify()["approval"]["requirements"][merge.requirement_id]
        self.assertTrue(status["satisfied"])

    def test_denial_vetoes_ready_approvals(self):
        engine = self.create_engine()
        self.approve_all(engine)
        requirement = engine.snapshot.requirement_map["step:file:create_file"]
        engine.record_approval(
            approval_id="deny-1", principal_id="veto-reviewer", role="reviewer",
            decision="deny", requirement_id=requirement.requirement_id,
        )
        self.assertEqual(engine.verify()["approval"]["status"], "denied")

    def test_authorize_step_blocked_until_all_approvals_ready(self):
        engine = self.create_engine()
        with self.assertRaisesRegex(PolicyError, "approval status is pending"):
            engine.authorize_step(step_id="branch", event_id="auth-1", text="Authorize v09-branch")

    def test_run_blocked_until_all_approvals_ready(self):
        engine = self.create_engine()
        connector = FixtureConnector()
        with self.assertRaisesRegex(PolicyError, "approval status is pending"):
            engine.run(connector)
        self.assertEqual(connector.calls, [])

    def test_policy_ready_does_not_replace_exact_step_authorization(self):
        engine = self.create_engine()
        self.approve_all(engine)
        connector = FixtureConnector()
        with self.assertRaisesRegex(Exception, "explicit prior authorization"):
            engine.run_next(connector)
        self.assertEqual(connector.calls, [])

    def test_full_governed_transaction_completes(self):
        engine = self.create_engine()
        self.assertEqual(self.approve_all(engine), 5)
        self.authorize_all_writes(engine)
        connector = FixtureConnector()
        result = engine.run(connector)
        self.assertEqual(result["journal"]["status"], "completed")
        self.assertEqual(len(connector.calls), 5)
        self.assertEqual(engine.verify()["approval"]["status"], "ready")

    def test_ledger_tampering_fails_closed(self):
        engine = self.create_engine()
        self.approve_all(engine)
        raw = json.loads((self.root / "approval-ledger.json").read_text())
        raw["entries"][0]["event"]["role"] = "release_manager"
        (self.root / "approval-ledger.json").write_text(json.dumps(raw))
        with self.assertRaises(PolicyError):
            engine.verify()

    def test_approval_ledger_excludes_file_content(self):
        engine = self.create_engine()
        self.approve_all(engine)
        self.assertNotIn("reviewed secret-free fixture", (self.root / "approval-ledger.json").read_text())

    def test_approval_targets_exact_snapshot(self):
        engine = self.create_engine()
        raw = json.loads((self.root / "snapshot.json").read_text())
        raw["snapshot_sha256"] = "0" * 64
        with self.assertRaises(PolicyError):
            PolicySnapshot.from_document(raw)

    def test_evidence_summary_binds_all_heads(self):
        engine = self.create_engine(read_steps())
        evidence = engine.evidence_summary()
        self.assertEqual(len(evidence["engine_evidence_sha256"]), 64)
        self.assertEqual(evidence["authority"], AUTHORITY)

    def test_identity_and_signature_verification_are_not_claimed(self):
        authority = self.create_engine(read_steps()).verify()["authority"]
        self.assertFalse(authority["identity_verification"])
        self.assertFalse(authority["signature_verification"])
        self.assertFalse(authority["automatic_step_authorization"])


if __name__ == "__main__":
    unittest.main()
