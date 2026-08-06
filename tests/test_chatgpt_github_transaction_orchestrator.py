from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_github_bridge import GitHubAgentBridge, GitHubOperation
from sdk.liminal_github_runtime import ConnectedGitHubRuntime
from sdk.liminal_github_transaction import (
    AUTHORITY,
    GitHubTransactionOrchestrator,
    MAX_STEPS,
    TransactionError,
    checkpoint_reference,
)


REPO = "safal207/LiminalOSAI"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class FakeInvoker:
    def __init__(self, responses=None, error: Exception | None = None):
        self.responses = dict(responses or {})
        self.error = error
        self.calls: list[tuple[str, dict]] = []
        self.last_response = None

    def preflight(self, tool_name):
        if tool_name not in self.responses and self.error is None:
            raise RuntimeError(f"missing fake response for {tool_name}")

    def invoke(self, tool_name, arguments):
        self.calls.append((tool_name, json.loads(json.dumps(arguments))))
        if self.error is not None:
            raise self.error
        value = self.responses[tool_name]
        if isinstance(value, list):
            if not value:
                raise RuntimeError(f"no fake responses left for {tool_name}")
            response = value.pop(0)
        else:
            response = value
        self.last_response = json.loads(json.dumps(response))
        return response


def full_steps(*, ci_state: str = "success"):
    branch_ref = checkpoint_reference("branch", "branch")
    commit_ref = checkpoint_reference("file", "commit_sha")
    pr_ref = checkpoint_reference("pr", "number")
    return [
        {
            "step_id": "branch",
            "call_id": "tx-branch",
            "action": "create_branch",
            "arguments": {
                "repository_full_name": REPO,
                "branch_name": "agent/transaction-v08",
                "base_ref": "main",
            },
            "exports": {"branch": "branch", "branch_sha": "sha"},
            "expect": {},
        },
        {
            "step_id": "file",
            "call_id": "tx-file",
            "action": "create_file",
            "arguments": {
                "repository_full_name": REPO,
                "path": "reports/transaction.txt",
                "content": "transaction-secret-fixture",
                "message": "test: add transaction fixture",
                "branch": branch_ref,
            },
            "exports": {"commit_sha": "commit_sha"},
            "expect": {},
        },
        {
            "step_id": "pr",
            "call_id": "tx-pr",
            "action": "create_pull_request",
            "arguments": {
                "repository_full_name": REPO,
                "title": "Transaction fixture",
                "head": branch_ref,
                "base": "main",
                "body": "Fixture only",
                "draft": False,
            },
            "exports": {"number": "number", "url": "url"},
            "expect": {},
        },
        {
            "step_id": "ci",
            "call_id": "tx-ci",
            "action": "get_commit_combined_status",
            "arguments": {
                "repo_full_name": REPO,
                "commit_sha": commit_ref,
            },
            "exports": {"state": "state"},
            "expect": {"state": ci_state},
        },
        {
            "step_id": "merge",
            "call_id": "tx-merge",
            "action": "merge_pull_request",
            "arguments": {
                "repository_full_name": REPO,
                "pr_number": pr_ref,
                "expected_head_sha": commit_ref,
                "merge_method": "merge",
            },
            "exports": {"merge_sha": "sha"},
            "expect": {"merged": True},
            "gate_step_ids": ["ci"],
        },
    ]


def full_responses(*, ci_state: str = "success", merged: bool = True):
    return {
        "create_branch": {"branch": "agent/transaction-v08", "sha": SHA_A},
        "create_file": {"commit_sha": SHA_B},
        "create_pull_request": {
            "number": 104,
            "url": f"https://github.com/{REPO}/pull/104",
        },
        "get_commit_combined_status": {"state": ci_state, "statuses": []},
        "merge_pull_request": {
            "merged": merged,
            "sha": SHA_C,
            "message": "merged" if merged else "not merged",
        },
    }


class GitHubTransactionOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        GitHubAgentBridge.create(
            self.root / "bridge.json",
            host_trace_path=self.root / "host-trace.json",
            recorder_path=self.root / "session-journal.json",
            session_id="transaction-test",
            high_stakes=False,
            requires_current_information=True,
            allowed_repositories=[REPO],
        )
        ConnectedGitHubRuntime.create(
            self.root / "runtime.json",
            bridge_config_path=self.root / "bridge.json",
            max_response_bytes=16384,
        )

    def tearDown(self):
        self.temp.cleanup()

    def create(self, steps=None, transaction_id="tx-1"):
        return GitHubTransactionOrchestrator.create(
            self.root / "plan.json",
            self.root / "transaction-journal.json",
            runtime_config_path=self.root / "runtime.json",
            transaction_id=transaction_id,
            repository_full_name=REPO,
            steps=steps or full_steps(),
        )

    @staticmethod
    def authorize_writes(orchestrator):
        for index, step in enumerate(orchestrator.plan.steps):
            if step.effect == "write":
                orchestrator.authorize_step(
                    step_id=step.step_id,
                    event_id=f"auth-{index}",
                    text=f"Authorize exactly {step.call_id}",
                )

    def test_create_reports_ready_transaction(self):
        orchestrator = self.create()
        result = orchestrator.verify()
        self.assertEqual(result["journal"]["status"], "ready")
        self.assertEqual(result["step_count"], 5)
        self.assertEqual(result["authority"], AUTHORITY)

    def test_prepare_next_does_not_require_authorization(self):
        orchestrator = self.create()
        prepared = orchestrator.prepare_next()["next_step"]
        self.assertEqual(prepared["step_id"], "branch")
        self.assertTrue(prepared["authorization_required"])
        self.assertEqual(prepared["authorization_event_ids"], [])

    def test_unauthorized_write_stops_before_journal_start_and_connector(self):
        orchestrator = self.create()
        connector = FakeInvoker(full_responses())
        with self.assertRaisesRegex(TransactionError, "explicit prior authorization"):
            orchestrator.run_next(connector)
        self.assertEqual(connector.calls, [])
        self.assertEqual(orchestrator.journal.summary()["starts"], {})

    def test_full_transaction_resolves_checkpoints_and_completes(self):
        orchestrator = self.create()
        self.authorize_writes(orchestrator)
        connector = FakeInvoker(full_responses())
        result = orchestrator.run(connector)
        self.assertEqual(result["journal"]["status"], "completed")
        self.assertEqual(
            [name for name, _ in connector.calls],
            ["create_branch", "create_file", "create_pull_request",
             "get_commit_combined_status", "merge_pull_request"],
        )
        self.assertEqual(connector.calls[1][1]["branch"], "agent/transaction-v08")
        self.assertEqual(connector.calls[3][1]["commit_sha"], SHA_B)
        self.assertEqual(connector.calls[4][1]["pr_number"], 104)
        self.assertEqual(connector.calls[4][1]["expected_head_sha"], SHA_B)

    def test_run_next_checkpoints_exactly_one_step(self):
        orchestrator = self.create()
        self.authorize_writes(orchestrator)
        connector = FakeInvoker(full_responses())
        result = orchestrator.run_next(connector)
        self.assertEqual(result["journal"]["successful_step_ids"], ["branch"])
        self.assertEqual(len(connector.calls), 1)

    def test_completed_transaction_is_idempotent(self):
        orchestrator = self.create()
        self.authorize_writes(orchestrator)
        connector = FakeInvoker(full_responses())
        orchestrator.run(connector)
        call_count = len(connector.calls)
        result = orchestrator.run(connector)
        self.assertEqual(result["journal"]["status"], "completed")
        self.assertEqual(len(connector.calls), call_count)

    def test_ci_expectation_mismatch_halts_before_merge(self):
        orchestrator = self.create()
        self.authorize_writes(orchestrator)
        connector = FakeInvoker(full_responses(ci_state="failure"))
        result = orchestrator.run(connector)
        self.assertEqual(result["journal"]["status"], "halted")
        self.assertEqual(result["journal"]["failed_step_ids"], ["ci"])
        self.assertNotIn("merge_pull_request", [name for name, _ in connector.calls])

    def test_merge_false_halts(self):
        orchestrator = self.create()
        self.authorize_writes(orchestrator)
        connector = FakeInvoker(full_responses(merged=False))
        result = orchestrator.run(connector)
        self.assertEqual(result["journal"]["status"], "halted")
        self.assertIn("merge", result["journal"]["failed_step_ids"])

    def test_connector_exception_is_checkpointed_and_halts(self):
        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        connector = FakeInvoker({"create_branch": {"branch": "unused"}}, error=RuntimeError("boom"))
        with self.assertRaisesRegex(RuntimeError, "boom"):
            orchestrator.run_next(connector)
        result = orchestrator.verify()
        self.assertEqual(result["journal"]["status"], "halted")
        self.assertEqual(result["journal"]["failed_step_ids"], ["branch"])

    def test_missing_connector_tool_fails_before_journal_start(self):
        class Missing:
            def preflight(self, tool_name):
                raise RuntimeError(f"missing {tool_name}")
            def invoke(self, tool_name, arguments):
                raise AssertionError("must not invoke")

        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        with self.assertRaisesRegex(RuntimeError, "missing create_branch"):
            orchestrator.run_next(Missing())
        self.assertEqual(orchestrator.journal.summary()["starts"], {})

    def test_non_scalar_export_halts_without_persisting_payload(self):
        steps = [{
            "step_id": "read", "call_id": "tx-read", "action": "get_repo",
            "arguments": {"repository_full_name": REPO},
            "exports": {"bad": "owner"}, "expect": {},
        }]
        orchestrator = self.create(steps)
        connector = FakeInvoker({"get_repo": {"owner": {"login": "safal207"}}})
        result = orchestrator.run(connector)
        self.assertEqual(result["journal"]["status"], "halted")
        self.assertNotIn('"login"', (self.root / "transaction-journal.json").read_text())

    def test_plan_tampering_fails_closed(self):
        orchestrator = self.create()
        raw = json.loads((self.root / "plan.json").read_text())
        raw["steps"][0]["arguments"]["branch_name"] = "agent/tampered"
        (self.root / "plan.json").write_text(json.dumps(raw))
        with self.assertRaisesRegex(TransactionError, "plan_sha256 mismatch"):
            orchestrator.verify()

    def test_journal_tampering_fails_closed(self):
        orchestrator = self.create()
        raw = json.loads((self.root / "transaction-journal.json").read_text())
        raw["entries"][0]["event"]["repository_full_name"] = "evil/repo"
        (self.root / "transaction-journal.json").write_text(json.dumps(raw))
        with self.assertRaisesRegex(TransactionError, "hash mismatch"):
            orchestrator.verify()

    def test_forward_checkpoint_reference_is_rejected(self):
        steps = full_steps()
        steps[1]["arguments"]["branch"] = checkpoint_reference("pr", "number")
        with self.assertRaisesRegex(TransactionError, "non-prior step"):
            self.create(steps)

    def test_unknown_checkpoint_export_is_rejected(self):
        steps = full_steps()
        steps[1]["arguments"]["branch"] = checkpoint_reference("branch", "missing")
        with self.assertRaisesRegex(TransactionError, "unknown export"):
            self.create(steps)

    def test_repository_must_be_literal_and_fixed(self):
        steps = full_steps()
        steps[1]["arguments"]["repository_full_name"] = checkpoint_reference("branch", "branch")
        with self.assertRaisesRegex(TransactionError, "must not be a checkpoint"):
            self.create(steps)

    def test_duplicate_call_ids_are_rejected(self):
        steps = full_steps()
        steps[1]["call_id"] = steps[0]["call_id"]
        with self.assertRaisesRegex(TransactionError, "duplicate call_id"):
            self.create(steps)

    def test_merge_requires_ci_gate(self):
        steps = full_steps()
        steps[-1]["gate_step_ids"] = []
        with self.assertRaisesRegex(TransactionError, "requires at least one"):
            self.create(steps)

    def test_merge_gate_must_check_same_head(self):
        steps = full_steps()
        steps[3]["arguments"]["commit_sha"] = checkpoint_reference("branch", "branch_sha")
        with self.assertRaisesRegex(TransactionError, "same checkpoint head"):
            self.create(steps)

    def test_step_limit_is_enforced(self):
        one = full_steps()[0]
        steps = []
        for index in range(MAX_STEPS + 1):
            step = json.loads(json.dumps(one))
            step["step_id"] = f"s{index}"
            step["call_id"] = f"c{index}"
            step["arguments"]["branch_name"] = f"agent/s{index}"
            steps.append(step)
        with self.assertRaisesRegex(TransactionError, "1..64"):
            self.create(steps)

    def test_raw_file_content_is_not_written_to_checkpoint_journal(self):
        orchestrator = self.create(full_steps()[:2])
        self.authorize_writes(orchestrator)
        connector = FakeInvoker({
            "create_branch": full_responses()["create_branch"],
            "create_file": full_responses()["create_file"],
        })
        orchestrator.run(connector)
        self.assertNotIn("transaction-secret-fixture", (self.root / "transaction-journal.json").read_text())

    def test_recovery_report_never_claims_automatic_rollback(self):
        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        orchestrator.run(FakeInvoker({"create_branch": full_responses()["create_branch"]}))
        report = orchestrator.recovery_report()
        self.assertTrue(report["manual_recovery_required"])
        self.assertFalse(report["automatic_rollback"])
        self.assertFalse(report["automatic_pending_write_replay"])

    def test_abort_blocks_future_execution(self):
        orchestrator = self.create()
        result = orchestrator.abort(reason="operator cancelled")
        self.assertEqual(result["journal"]["status"], "aborted")
        connector = FakeInvoker(full_responses())
        orchestrator.run(connector)
        self.assertEqual(connector.calls, [])

    def test_pending_step_blocks_replay(self):
        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        prepared = orchestrator.prepare_next()["next_step"]
        from sdk.liminal_github_transaction._contracts import canonical_sha256
        orchestrator.journal.append({
            "type": "step_started", "step_id": "branch", "call_id": "tx-branch",
            "action": "create_branch", "request_sha256": prepared["request_sha256"],
            "resolved_arguments_sha256": canonical_sha256(prepared["arguments"]),
        })
        connector = FakeInvoker({"create_branch": full_responses()["create_branch"]})
        with self.assertRaisesRegex(TransactionError, "reconciliation"):
            orchestrator.run_next(connector)
        self.assertEqual(connector.calls, [])

    def test_reconcile_pending_with_retained_receipt_and_response(self):
        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        prepared = orchestrator.prepare_next()["next_step"]
        from sdk.liminal_github_transaction._contracts import canonical_sha256
        orchestrator.journal.append({
            "type": "step_started", "step_id": "branch", "call_id": "tx-branch",
            "action": "create_branch", "request_sha256": prepared["request_sha256"],
            "resolved_arguments_sha256": canonical_sha256(prepared["arguments"]),
        })
        raw_response = full_responses()["create_branch"]
        receipt = orchestrator.runtime.execute(
            GitHubOperation(call_id="tx-branch", action="create_branch", arguments=prepared["arguments"]),
            FakeInvoker({"create_branch": raw_response}),
        )
        result = orchestrator.reconcile_pending(
            connected_receipt=receipt.as_dict(), raw_response=raw_response,
        )
        self.assertEqual(result["journal"]["status"], "completed")
        self.assertTrue(result["journal"]["finishes"]["branch"]["reconciled"])

    def test_reconcile_rejects_raw_response_hash_mismatch(self):
        orchestrator = self.create([full_steps()[0]])
        self.authorize_writes(orchestrator)
        prepared = orchestrator.prepare_next()["next_step"]
        from sdk.liminal_github_transaction._contracts import canonical_sha256
        orchestrator.journal.append({
            "type": "step_started", "step_id": "branch", "call_id": "tx-branch",
            "action": "create_branch", "request_sha256": prepared["request_sha256"],
            "resolved_arguments_sha256": canonical_sha256(prepared["arguments"]),
        })
        raw_response = full_responses()["create_branch"]
        receipt = orchestrator.runtime.execute(
            GitHubOperation(call_id="tx-branch", action="create_branch", arguments=prepared["arguments"]),
            FakeInvoker({"create_branch": raw_response}),
        )
        with self.assertRaisesRegex(TransactionError, "does not match"):
            orchestrator.reconcile_pending(
                connected_receipt=receipt.as_dict(),
                raw_response={"branch": "agent/other", "sha": SHA_A},
            )

    def test_full_visible_session_seals_and_exports(self):
        orchestrator = self.create()
        orchestrator.record_user_message(
            event_id="user-1", text="Execute the exact reviewed GitHub transaction."
        )
        self.authorize_writes(orchestrator)
        orchestrator.run(FakeInvoker(full_responses()))
        orchestrator.record_assistant_draft(
            event_id="draft-1",
            response="The authorized transaction completed and merged.",
            no_signal=False,
            intent_alignment=0.99,
        )
        orchestrator.record_claim(
            event_id="claim-1", draft_event_id="draft-1",
            text="The authorized transaction completed and merged.",
            kind="fact", confidence=0.99, requires_current_information=True,
            evidence_event_ids=["tx-merge"],
        )
        orchestrator.seal(request_event_id="user-1", draft_event_id="draft-1")
        result = orchestrator.export_live_session(self.root / "live-session.json")
        self.assertEqual(result["schema_version"], "chatgpt-live-session-v0.3")
        self.assertTrue((self.root / "live-session.json").exists())


if __name__ == "__main__":
    unittest.main()
