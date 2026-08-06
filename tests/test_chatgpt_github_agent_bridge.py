from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_github_bridge import (
    AUTHORITY,
    BRIDGE_SCHEMA,
    GitHubAgentBridge,
    GitHubBridgeError,
    GitHubExecutorResult,
    GitHubOperation,
)

REPO = "safal207/LiminalOSAI"
SHA_A = "a" * 40
SHA_B = "b" * 40


class GitHubAgentBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.config = root / "bridge-config.json"
        self.trace = root / "host-trace.json"
        self.journal = root / "session-journal.json"
        self.live = root / "live-session.json"
        self.bridge = GitHubAgentBridge.create(
            self.config,
            host_trace_path=self.trace,
            recorder_path=self.journal,
            session_id="session-v06",
            high_stakes=False,
            requires_current_information=True,
            allowed_repositories=[REPO],
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def op(self, call_id: str, action: str, arguments: dict) -> GitHubOperation:
        return GitHubOperation(call_id=call_id, action=action, arguments=arguments)

    def branch_op(self, call_id: str = "branch-1") -> GitHubOperation:
        return self.op(
            call_id,
            "create_branch",
            {
                "repository_full_name": REPO,
                "branch_name": "agent/v06-test",
                "base_ref": "main",
            },
        )

    def authorize(self, operation: GitHubOperation, event_id: str = "auth-1") -> None:
        self.bridge.authorize_operation(
            event_id=event_id,
            text="Explicitly authorize this exact GitHub call",
            operation=operation,
        )

    def test_unknown_action_fails_closed(self) -> None:
        with self.assertRaises(GitHubBridgeError):
            self.bridge.validate_operation(self.op("x", "launch_missiles", {"repository_full_name": REPO}))

    def test_repository_allowlist_is_exact(self) -> None:
        operation = self.op("x", "get_repo", {"repository_full_name": "other/repo"})
        with self.assertRaisesRegex(GitHubBridgeError, "allowlist"):
            self.bridge.validate_operation(operation)

    def test_unknown_argument_fails_closed(self) -> None:
        operation = self.op(
            "x",
            "get_repo",
            {"repository_full_name": REPO, "token": "secret"},
        )
        with self.assertRaisesRegex(GitHubBridgeError, "unsupported"):
            self.bridge.validate_operation(operation)

    def test_path_traversal_is_rejected(self) -> None:
        operation = self.op(
            "x",
            "fetch_file",
            {"repository_full_name": REPO, "path": "../secret"},
        )
        with self.assertRaisesRegex(GitHubBridgeError, "unsafe"):
            self.bridge.validate_operation(operation)

    def test_create_branch_requires_exactly_one_base_selector(self) -> None:
        neither = self.op(
            "x",
            "create_branch",
            {"repository_full_name": REPO, "branch_name": "agent/x"},
        )
        both = self.op(
            "y",
            "create_branch",
            {
                "repository_full_name": REPO,
                "branch_name": "agent/y",
                "sha": SHA_A,
                "base_ref": "main",
            },
        )
        for operation in (neither, both):
            with self.assertRaisesRegex(GitHubBridgeError, "exactly one"):
                self.bridge.validate_operation(operation)

    def test_direct_write_to_protected_branch_is_blocked(self) -> None:
        operation = self.op(
            "x",
            "create_file",
            {
                "repository_full_name": REPO,
                "path": "unsafe.txt",
                "content": "x",
                "message": "unsafe",
                "branch": "main",
            },
        )
        with self.assertRaisesRegex(GitHubBridgeError, "protected branch"):
            self.bridge.validate_operation(operation)

    def test_create_file_requires_explicit_branch(self) -> None:
        operation = self.op(
            "x",
            "create_file",
            {
                "repository_full_name": REPO,
                "path": "safe.txt",
                "content": "x",
                "message": "safe",
            },
        )
        with self.assertRaisesRegex(GitHubBridgeError, "missing keys"):
            self.bridge.validate_operation(operation)

    def test_force_ref_update_is_never_supported(self) -> None:
        operation = self.op(
            "x",
            "update_ref",
            {
                "repository_full_name": REPO,
                "branch_name": "agent/x",
                "sha": SHA_A,
                "force": True,
            },
        )
        with self.assertRaisesRegex(GitHubBridgeError, "force"):
            self.bridge.validate_operation(operation)

    def test_merge_requires_expected_head_sha(self) -> None:
        operation = self.op(
            "x",
            "merge_pull_request",
            {"repository_full_name": REPO, "pr_number": 100},
        )
        with self.assertRaisesRegex(GitHubBridgeError, "expected_head_sha"):
            self.bridge.validate_operation(operation)

    def test_merge_is_declared_non_reversible(self) -> None:
        operation = self.op(
            "merge-1",
            "merge_pull_request",
            {
                "repository_full_name": REPO,
                "pr_number": 100,
                "expected_head_sha": SHA_A,
            },
        )
        normalized = self.bridge.validate_operation(operation)
        self.assertFalse(normalized.reversible)
        self.assertIn("revert", normalized.recovery_plan.lower())

    def test_create_pull_request_to_main_is_allowed(self) -> None:
        operation = self.op(
            "pr-1",
            "create_pull_request",
            {
                "repository_full_name": REPO,
                "title": "v0.6",
                "head": "agent/v06",
                "base": "main",
                "draft": True,
            },
        )
        normalized = self.bridge.validate_operation(operation)
        self.assertEqual(normalized.arguments["base"], "main")

    def test_request_size_limit_is_enforced(self) -> None:
        root = Path(self.tmp.name)
        small = GitHubAgentBridge.create(
            root / "small-config.json",
            host_trace_path=root / "small-host.json",
            recorder_path=root / "small-journal.json",
            session_id="small",
            high_stakes=False,
            requires_current_information=False,
            allowed_repositories=[REPO],
            max_request_bytes=128,
        )
        operation = self.op(
            "x",
            "create_file",
            {
                "repository_full_name": REPO,
                "path": "a.txt",
                "content": "x" * 500,
                "message": "large",
                "branch": "agent/v06",
            },
        )
        with self.assertRaisesRegex(GitHubBridgeError, "max_request_bytes"):
            small.validate_operation(operation)

    def test_operation_summary_contains_digest_not_file_content(self) -> None:
        secret = "visible-but-redacted-from-summary"
        operation = self.op(
            "file-1",
            "create_file",
            {
                "repository_full_name": REPO,
                "path": "artifact.txt",
                "content": secret,
                "message": "create artifact",
                "branch": "agent/v06",
            },
        )
        normalized = self.bridge.validate_operation(operation)
        self.assertNotIn(secret, normalized.operation_summary)
        self.assertIn(normalized.request_sha256, normalized.operation_summary)

    def test_read_executes_without_authorization(self) -> None:
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        calls = []

        def executor(action, arguments):
            calls.append((action, arguments))
            return GitHubExecutorResult.success(
                locator="https://github.com/safal207/LiminalOSAI",
                payload={"default_branch": "main"},
            )

        receipt = self.bridge.execute(operation, executor)
        self.assertEqual(calls, [("get_repo", {"repository_full_name": REPO})])
        self.assertEqual(receipt.status, "success")
        self.assertEqual(receipt.schema_version, BRIDGE_SCHEMA)

    def test_unauthorized_write_stops_before_executor(self) -> None:
        called = False

        def executor(action, arguments):
            nonlocal called
            called = True
            return GitHubExecutorResult.success(locator="refs/heads/agent/v06-test", payload={})

        with self.assertRaisesRegex(GitHubBridgeError, "authorization"):
            self.bridge.execute(self.branch_op(), executor)
        self.assertFalse(called)

    def test_authorized_write_executes_and_returns_receipt(self) -> None:
        operation = self.branch_op()
        self.authorize(operation)

        def executor(action, arguments):
            self.assertEqual(action, "create_branch")
            self.assertEqual(arguments["branch_name"], "agent/v06-test")
            return GitHubExecutorResult.success(
                locator="refs/heads/agent/v06-test@" + SHA_A,
                payload={"branch": "agent/v06-test", "sha": SHA_A},
            )

        receipt = self.bridge.execute(operation, executor)
        self.assertEqual(receipt.call_id, "branch-1")
        self.assertEqual(receipt.recorder_event_id, "branch-1")
        self.assertEqual(receipt.authority, AUTHORITY)
        self.assertEqual(len(receipt.payload_sha256), 64)

    def test_authorization_targets_exact_call_id(self) -> None:
        operation = self.branch_op("branch-exact")
        event = self.bridge.authorize_operation(
            event_id="auth-exact", text="yes", operation=operation
        )
        self.assertEqual(event["authorized_event_ids"], ["branch-exact"])

    def test_executor_receives_a_copy_of_arguments(self) -> None:
        operation = self.op("read-copy", "get_repo", {"repository_full_name": REPO})
        original = operation.arguments.copy()

        def executor(action, arguments):
            arguments["repository_full_name"] = "mutated/repo"
            return GitHubExecutorResult.success(locator="repo:" + REPO, payload={})

        self.bridge.execute(operation, executor)
        self.assertEqual(operation.arguments, original)

    def test_failure_result_is_preserved(self) -> None:
        operation = self.op("read-fail", "get_repo", {"repository_full_name": REPO})
        receipt = self.bridge.execute(
            operation,
            lambda action, arguments: GitHubExecutorResult.failure(
                locator="github:error:403", payload={"message": "forbidden"}
            ),
        )
        self.assertEqual(receipt.status, "failure")
        journal = json.loads(self.journal.read_text())
        self.assertEqual(journal["entries"][-1]["event"]["status"], "failure")

    def test_cancelled_result_is_preserved(self) -> None:
        operation = self.op("read-cancel", "get_repo", {"repository_full_name": REPO})
        receipt = self.bridge.execute(
            operation,
            lambda action, arguments: GitHubExecutorResult.cancelled(
                locator="github:cancelled-by-host"
            ),
        )
        self.assertEqual(receipt.status, "cancelled")

    def test_executor_exception_is_recorded_and_reraised(self) -> None:
        operation = self.op("read-exception", "get_repo", {"repository_full_name": REPO})

        def executor(action, arguments):
            raise RuntimeError("boom")

        with self.assertRaisesRegex(RuntimeError, "boom"):
            self.bridge.execute(operation, executor)
        summary = self.bridge.verify()
        self.assertEqual(summary["host"]["completed_calls"], 1)
        journal = json.loads(self.journal.read_text())
        self.assertEqual(journal["entries"][-1]["event"]["status"], "failure")

    def test_executor_result_requires_exact_fields(self) -> None:
        operation = self.op("bad-result", "get_repo", {"repository_full_name": REPO})
        with self.assertRaisesRegex(GitHubBridgeError, "missing keys"):
            self.bridge.execute(
                operation,
                lambda action, arguments: {"status": "success", "locator": "repo:" + REPO},
            )

    def test_executor_result_requires_locator(self) -> None:
        operation = self.op("bad-locator", "get_repo", {"repository_full_name": REPO})
        with self.assertRaisesRegex(GitHubBridgeError, "locator"):
            self.bridge.execute(
                operation,
                lambda action, arguments: {
                    "status": "success",
                    "locator": "",
                    "payload": {},
                },
            )

    def test_config_tampering_fails_closed(self) -> None:
        raw = json.loads(self.config.read_text())
        raw["allowed_repositories"] = ["attacker/repo"]
        self.config.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(GitHubBridgeError, "config_sha256"):
            self.bridge.verify()

    def test_verify_reports_fixed_authority(self) -> None:
        summary = self.bridge.verify()
        self.assertEqual(summary["authority"], AUTHORITY)
        self.assertFalse(summary["authority"]["merge_authority"])
        self.assertFalse(summary["authority"]["github_execution_ownership"])

    def test_full_session_seals_and_exports(self) -> None:
        self.bridge.record_user_message(event_id="user-1", text="Create the reviewed branch")
        operation = self.branch_op("branch-final")
        self.authorize(operation, "auth-final")
        receipt = self.bridge.execute(
            operation,
            lambda action, arguments: GitHubExecutorResult.success(
                locator="refs/heads/agent/v06-test@" + SHA_B,
                payload={"branch": "agent/v06-test", "sha": SHA_B},
            ),
        )
        self.bridge.record_assistant_draft(
            event_id="draft-1",
            response="The authorized branch was created successfully.",
            no_signal=False,
            intent_alignment=0.99,
        )
        self.bridge.record_claim(
            event_id="claim-1",
            draft_event_id="draft-1",
            text="The authorized branch was created successfully.",
            kind="fact",
            confidence=0.99,
            requires_current_information=True,
            evidence_event_ids=[receipt.call_id],
        )
        self.bridge.seal(request_event_id="user-1", draft_event_id="draft-1")
        live = self.bridge.export_live_session(self.live)
        self.assertTrue(live["session"]["capture_complete"])
        self.assertEqual(live["schema_version"], "chatgpt-live-session-v0.3")


if __name__ == "__main__":
    unittest.main()
