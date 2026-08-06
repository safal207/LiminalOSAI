from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_github_bridge import GitHubAgentBridge, GitHubOperation
from sdk.liminal_github_runtime import (
    ACTION_BINDINGS,
    AUTHORITY,
    REGISTRY_SHA256,
    SUPPORTED_ACTIONS,
    ConnectedGitHubRuntime,
    ConnectorNamespaceInvoker,
    GitHubRuntimeError,
)


REPO = "safal207/LiminalOSAI"
SHA_A = "a" * 40
SHA_B = "b" * 40


class FakeInvoker:
    def __init__(self, response=None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.calls = []

    def invoke(self, tool_name, arguments):
        self.calls.append((tool_name, json.loads(json.dumps(arguments))))
        if self.error is not None:
            raise self.error
        return self.response


class ConnectedGitHubRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        GitHubAgentBridge.create(
            self.root / "bridge.json",
            host_trace_path=self.root / "trace.json",
            recorder_path=self.root / "journal.json",
            session_id="runtime-test",
            high_stakes=False,
            requires_current_information=True,
            allowed_repositories=[REPO],
        )
        self.runtime = ConnectedGitHubRuntime.create(
            self.root / "runtime.json",
            bridge_config_path=self.root / "bridge.json",
            max_response_bytes=4096,
        )

    def tearDown(self):
        self.temp.cleanup()

    def op(self, call_id, action, arguments):
        return GitHubOperation(call_id=call_id, action=action, arguments=arguments)

    def authorize(self, operation, event_id="auth-1"):
        self.runtime.authorize_operation(
            event_id=event_id,
            text=f"Authorize exactly {operation.call_id}",
            operation=operation,
        )

    def test_registry_is_fixed_and_one_to_one(self):
        self.assertEqual(tuple(ACTION_BINDINGS), SUPPORTED_ACTIONS)
        self.assertEqual(dict(ACTION_BINDINGS), {x: x for x in SUPPORTED_ACTIONS})
        self.assertEqual(len(REGISTRY_SHA256), 64)

    def test_runtime_verify_reports_fixed_contract(self):
        result = self.runtime.verify(allow_pending=True)
        self.assertEqual(result["connector_name"], "GitHub")
        self.assertEqual(tuple(result["supported_actions"]), SUPPORTED_ACTIONS)
        self.assertEqual(result["registry_sha256"], REGISTRY_SHA256)
        self.assertEqual(result["authority"], AUTHORITY)

    def test_runtime_config_tampering_fails_closed(self):
        path = self.root / "runtime.json"
        raw = json.loads(path.read_text())
        raw["max_response_bytes"] += 1
        path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(GitHubRuntimeError, "config_sha256 mismatch"):
            self.runtime.verify()

    def test_runtime_config_unknown_field_fails_closed(self):
        path = self.root / "runtime.json"
        raw = json.loads(path.read_text())
        raw["unexpected"] = True
        path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(GitHubRuntimeError, "unsupported keys"):
            self.runtime.verify()

    def test_plain_callable_is_not_a_connector(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        with self.assertRaisesRegex(GitHubRuntimeError, "must expose invoke"):
            self.runtime.execute(operation, lambda *_: {})
        self.assertEqual(self.runtime.bridge.host.verify(allow_pending=True)["started_calls"], 0)

    def test_namespace_missing_tool_fails_before_host_start(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = ConnectorNamespaceInvoker(object())
        with self.assertRaisesRegex(GitHubRuntimeError, "lacks callable tool"):
            self.runtime.execute(operation, connector)
        self.assertEqual(self.runtime.bridge.host.verify(allow_pending=True)["started_calls"], 0)

    def test_read_executes_without_authorization(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = FakeInvoker({"name": "LiminalOSAI", "html_url": f"https://github.com/{REPO}"})
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "success")
        self.assertEqual(connector.calls[0][0], "get_repo")
        self.assertEqual(receipt.locator, f"https://github.com/{REPO}")

    def test_connector_receives_exact_argument_copy(self):
        operation = self.op("read-1", "fetch_file", {
            "repository_full_name": REPO,
            "path": "README.md",
            "ref": "main",
        })

        class MutatingInvoker:
            def __init__(self):
                self.seen = None
            def invoke(self, tool_name, arguments):
                self.seen = arguments
                arguments["path"] = "MUTATED"
                return {"content": "ok", "display_url": f"https://github.com/{REPO}/blob/main/README.md"}

        connector = MutatingInvoker()
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "success")
        self.assertEqual(operation.arguments["path"], "README.md")
        self.assertEqual(connector.seen["path"], "MUTATED")

    def test_authorized_write_executes(self):
        operation = self.op("write-1", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/runtime-test",
            "base_ref": "main",
        })
        self.authorize(operation)
        connector = FakeInvoker({"result": {"branch": "agent/runtime-test", "sha": SHA_A}, "error": None})
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "success")
        self.assertEqual(receipt.connector_tool, "create_branch")
        self.assertEqual(len(receipt.raw_response_sha256), 64)
        self.assertEqual(len(receipt.bridge_receipt_sha256), 64)

    def test_unauthorized_write_stops_before_connector(self):
        operation = self.op("write-1", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/runtime-test",
            "base_ref": "main",
        })
        connector = FakeInvoker({"branch": "agent/runtime-test"})
        with self.assertRaisesRegex(GitHubRuntimeError, "requires explicit prior authorization"):
            self.runtime.execute(operation, connector)
        self.assertEqual(connector.calls, [])

    def test_authorization_targets_exact_call_id(self):
        allowed = self.op("write-1", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/one",
            "base_ref": "main",
        })
        denied = self.op("write-2", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/two",
            "base_ref": "main",
        })
        self.authorize(allowed)
        connector = FakeInvoker({"branch": "agent/two"})
        with self.assertRaisesRegex(GitHubRuntimeError, "requires explicit prior authorization"):
            self.runtime.execute(denied, connector)
        self.assertEqual(connector.calls, [])

    def test_connector_error_envelope_becomes_failure(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = FakeInvoker({"result": None, "error": {"code": "denied"}})
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "failure")
        event = self.runtime.bridge.host.recorder.read()["entries"][-1]["event"]
        self.assertEqual(event["status"], "failure")

    def test_merge_false_becomes_failure(self):
        operation = self.op("merge-1", "merge_pull_request", {
            "repository_full_name": REPO,
            "pr_number": 101,
            "expected_head_sha": SHA_A,
        })
        self.authorize(operation)
        connector = FakeInvoker({"sha": SHA_B, "merged": False, "message": "head changed"})
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "failure")

    def test_merge_true_requires_sha_and_succeeds(self):
        operation = self.op("merge-1", "merge_pull_request", {
            "repository_full_name": REPO,
            "pr_number": 101,
            "expected_head_sha": SHA_A,
        })
        self.authorize(operation)
        connector = FakeInvoker({"sha": SHA_B, "merged": True, "message": "merged"})
        receipt = self.runtime.execute(operation, connector)
        self.assertEqual(receipt.status, "success")
        self.assertIn(SHA_B, receipt.locator)

    def test_malformed_create_branch_response_records_failure_and_raises(self):
        operation = self.op("write-1", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/runtime-test",
            "base_ref": "main",
        })
        self.authorize(operation)
        connector = FakeInvoker({"unexpected": True})
        with self.assertRaisesRegex(GitHubRuntimeError, "connector_response.branch"):
            self.runtime.execute(operation, connector)
        summary = self.runtime.bridge.host.verify()
        self.assertEqual(summary["completed_calls"], 1)
        event = self.runtime.bridge.host.recorder.read()["entries"][-1]["event"]
        self.assertEqual(event["status"], "failure")

    def test_response_size_limit_is_enforced(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = FakeInvoker({"blob": "x" * 5000})
        with self.assertRaisesRegex(GitHubRuntimeError, "exceeds max_response_bytes"):
            self.runtime.execute(operation, connector)

    def test_non_json_response_is_rejected(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = FakeInvoker({"bad": {1, 2, 3}})
        with self.assertRaisesRegex(GitHubRuntimeError, "not canonical JSON"):
            self.runtime.execute(operation, connector)

    def test_create_file_requires_commit_sha(self):
        operation = self.op("write-1", "create_file", {
            "repository_full_name": REPO,
            "path": "docs/a.md",
            "content": "a",
            "message": "add a",
            "branch": "agent/runtime-test",
        })
        self.authorize(operation)
        with self.assertRaisesRegex(GitHubRuntimeError, "commit_sha"):
            self.runtime.execute(operation, FakeInvoker({"success": True}))

    def test_create_pull_request_accepts_positive_number(self):
        operation = self.op("pr-1", "create_pull_request", {
            "repository_full_name": REPO,
            "title": "Runtime test",
            "head": "agent/runtime-test",
            "base": "main",
        })
        self.authorize(operation)
        receipt = self.runtime.execute(operation, FakeInvoker({"number": 102, "state": "open"}))
        self.assertEqual(receipt.status, "success")
        self.assertIn("/pull/102", receipt.locator)

    def test_update_ref_accepts_explicit_success_ack(self):
        operation = self.op("ref-1", "update_ref", {
            "repository_full_name": REPO,
            "branch_name": "agent/runtime-test",
            "sha": SHA_A,
            "force": False,
        })
        self.authorize(operation)
        receipt = self.runtime.execute(operation, FakeInvoker({"success": True}))
        self.assertEqual(receipt.status, "success")

    def test_unknown_action_fails_before_connector(self):
        operation = self.op("bad-1", "delete_repository", {"repository_full_name": REPO})
        connector = FakeInvoker({})
        with self.assertRaisesRegex(Exception, "unsupported GitHub action"):
            self.runtime.execute(operation, connector)
        self.assertEqual(connector.calls, [])

    def test_raw_response_hash_is_deterministic(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        payload = {"name": "LiminalOSAI", "html_url": f"https://github.com/{REPO}"}
        receipt = self.runtime.execute(operation, FakeInvoker(payload))
        from sdk.liminal_github_runtime._contracts import canonical_sha256
        self.assertEqual(receipt.raw_response_sha256, canonical_sha256(payload))

    def test_namespace_invoker_dispatches_keyword_arguments(self):
        class Namespace:
            def __init__(self):
                self.args = None
            def get_repo(self, **kwargs):
                self.args = kwargs
                return {"html_url": f"https://github.com/{REPO}"}
        namespace = Namespace()
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        receipt = self.runtime.execute(operation, ConnectorNamespaceInvoker(namespace))
        self.assertEqual(receipt.status, "success")
        self.assertEqual(namespace.args, {"repository_full_name": REPO})

    def test_fallback_locator_is_deterministic(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        receipt = self.runtime.execute(operation, FakeInvoker({"name": "LiminalOSAI"}))
        self.assertTrue(receipt.locator.startswith("github://connector/get_repo/"))

    def test_full_session_seals_and_exports(self):
        self.runtime.record_user_message(event_id="user-1", text="Create the authorized branch")
        operation = self.op("write-1", "create_branch", {
            "repository_full_name": REPO,
            "branch_name": "agent/runtime-test",
            "base_ref": "main",
        })
        self.authorize(operation)
        receipt = self.runtime.execute(operation, FakeInvoker({"branch": "agent/runtime-test", "sha": SHA_A}))
        self.runtime.record_assistant_draft(
            event_id="draft-1",
            response="The authorized branch was created.",
            no_signal=False,
            intent_alignment=0.99,
        )
        self.runtime.record_claim(
            event_id="claim-1",
            draft_event_id="draft-1",
            text="The authorized branch was created.",
            kind="fact",
            confidence=0.99,
            requires_current_information=True,
            evidence_event_ids=[receipt.call_id],
        )
        self.runtime.seal(request_event_id="user-1", draft_event_id="draft-1")
        live = self.runtime.export_live_session(self.root / "live.json")
        self.assertTrue(live["session"]["capture_complete"])

    def test_authority_never_claims_execution_or_merge(self):
        self.assertFalse(AUTHORITY["github_execution_ownership"])
        self.assertFalse(AUTHORITY["arbitrary_tool_dispatch"])
        self.assertFalse(AUTHORITY["merge_authority"])
        self.assertFalse(AUTHORITY["credential_access"])

    def test_connector_exception_is_recorded_and_reraised(self):
        operation = self.op("read-1", "get_repo", {"repository_full_name": REPO})
        connector = FakeInvoker(error=RuntimeError("connector unavailable"))
        with self.assertRaisesRegex(RuntimeError, "connector unavailable"):
            self.runtime.execute(operation, connector)
        event = self.runtime.bridge.host.recorder.read()["entries"][-1]["event"]
        self.assertEqual(event["status"], "failure")
        self.assertIn("exception:", event["locator"])

    def test_protected_branch_policy_is_inherited(self):
        operation = self.op("write-1", "create_file", {
            "repository_full_name": REPO,
            "path": "docs/a.md",
            "content": "a",
            "message": "add a",
            "branch": "main",
        })
        connector = FakeInvoker({"commit_sha": SHA_A})
        with self.assertRaisesRegex(Exception, "protected branch"):
            self.runtime.execute(operation, connector)
        self.assertEqual(connector.calls, [])

    def test_merge_expected_head_policy_is_inherited(self):
        operation = self.op("merge-1", "merge_pull_request", {
            "repository_full_name": REPO,
            "pr_number": 101,
        })
        connector = FakeInvoker({"merged": True, "sha": SHA_A})
        with self.assertRaisesRegex(Exception, "missing keys"):
            self.runtime.execute(operation, connector)
        self.assertEqual(connector.calls, [])


if __name__ == "__main__":
    unittest.main()
