"""Counterexamples for an assurance model, not proof of runtime containment.

These checks never run Docker, invoke a model, or grant execution authority.
They challenge claimed routes and evidence using the current versioned model.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/containment_assurance_graph.v1.json"
TOOL = ROOT / "tools/validate_containment_graph.py"
SPEC = importlib.util.spec_from_file_location("containment_assurance_validator", TOOL)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ContainmentAssuranceGraphTests(unittest.TestCase):
    def setUp(self):
        self.graph = VALIDATOR.load_graph(MANIFEST)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def assert_rejected(self, graph):
        result = VALIDATOR.validate_graph(graph, ROOT)
        self.assertEqual(result["model_status"], "FAIL", result)
        self.assertTrue(result["errors"], result)
        self.assertIs(result["execution_authorized"], False, result)
        self.assertEqual(result["containment_status"], "NOT_ESTABLISHED", result)
        self.assertEqual(result["readiness"], "HOLD", result)

    def report_file(self, report):
        path = self.directory / "receiver-report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def current_identity(self, root=ROOT):
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout.splitlines()

    def clean_verifier_repository(self):
        # Actual verifier sources, isolated Git configuration, no Docker or hooks.
        root = self.directory / "verifier-repository"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        for name in ("verify_external_agent_receiver_evidence.py", "verify_external_agent_evidence.py",
                     "verify_external_stop_evidence.py"):
            (scripts / name).write_bytes((ROOT / "scripts" / name).read_bytes())
        (root / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
        hooks = self.directory / "empty-hooks"
        hooks.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], capture_output=True, check=True, timeout=10)
        subprocess.run(["git", "-C", str(root), "add", "--", "scripts", ".gitignore"],
                       capture_output=True, check=True, timeout=10)
        subprocess.run([
            "git", "-C", str(root), "-c", "core.hooksPath=" + str(hooks),
            "-c", "user.name=Assurance test fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgSign=false", "commit", "-q", "-m", "Pin actual independent verifier sources",
        ], capture_output=True, check=True, timeout=10)
        return root

    def test_consistent_model_still_holds_execution_and_unknown_containment(self):
        result = VALIDATOR.validate_graph(self.graph, ROOT)
        self.assertEqual(result["model_status"], "PASS", result)
        self.assertEqual(result["errors"], [], result)
        self.assertIs(result["execution_authorized"], False, result)
        self.assertEqual(result["containment_status"], "NOT_ESTABLISHED", result)
        self.assertEqual(result["readiness"], "HOLD", result)
        self.assertEqual(result["gaps"], self.graph["gaps"], result)
        self.assertEqual(result["gaps"]["g03_orientation"], "NOT_CONNECTED")

    def test_direct_proposal_to_effect_bypass_is_rejected(self):
        self.graph["edges"].append({"from": "proposal", "to": "synthetic_effect", "kind": "flow"})
        self.assert_rejected(self.graph)

    def test_each_mandatory_guard_cannot_be_skipped_by_an_alternate_route(self):
        route = ["proposal", "launch", "bridge", "authorization", "begin",
                 "dispatch_recheck", "receiver_fence", "synthetic_effect"]
        for index, guard in enumerate(route[1:-1], 1):
            with self.subTest(skipped_guard=guard):
                graph = deepcopy(self.graph)
                graph["edges"].append({"from": route[index - 1], "to": route[index + 1], "kind": "flow"})
                self.assert_rejected(graph)

    def test_present_guards_in_wrong_order_do_not_satisfy_the_route(self):
        removed = {("bridge", "authorization"), ("authorization", "begin"), ("begin", "dispatch_recheck")}
        self.graph["edges"] = [edge for edge in self.graph["edges"]
                               if (edge["from"], edge["to"]) not in removed or edge["kind"] != "flow"]
        self.graph["edges"].extend([
            {"from": "bridge", "to": "begin", "kind": "flow"},
            {"from": "begin", "to": "authorization", "kind": "flow"},
            {"from": "authorization", "to": "dispatch_recheck", "kind": "flow"},
        ])
        self.assert_rejected(self.graph)

    def test_disconnected_effect_or_weakened_requirement_is_not_a_safety_proof(self):
        graph = deepcopy(self.graph)
        graph["edges"] = [edge for edge in graph["edges"]
                          if not (edge["from"] == "receiver_fence" and edge["to"] == "synthetic_effect"
                                  and edge["kind"] == "flow")]
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["requirements"][0]["ordered_guards"].remove("authorization")
        graph["edges"].append({"from": "bridge", "to": "begin", "kind": "flow"})
        self.assert_rejected(graph)

    def test_named_guard_without_source_binding_is_rejected(self):
        next(node for node in self.graph["nodes"] if node["id"] == "authorization").pop("binding")
        self.assert_rejected(self.graph)

    def test_changed_source_digest_cannot_reuse_old_assurance(self):
        binding = next(item for item in self.graph["source_bindings"] if item["id"] == "receiver_store")
        binding["sha256"] = ("0" if binding["sha256"][0] != "0" else "1") + binding["sha256"][1:]
        self.assert_rejected(self.graph)

    def test_invented_basis_commit_or_mismatched_basis_tree_cannot_claim_valid_binding(self):
        graph = deepcopy(self.graph)
        graph["scope"]["basis_commit"] = "0" * 40
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["scope"]["basis_tree"] = "0" * 40
        self.assert_rejected(graph)

    def test_source_bindings_reject_missing_digest_and_unsafe_paths(self):
        for path in ("../outside.py", str(ROOT / "sdk/liminal_agent_control/external_agent_receiver.py"),
                     "sdk/../../outside.py"):
            with self.subTest(path=path):
                graph = deepcopy(self.graph)
                graph["source_bindings"][0]["path"] = path
                self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["source_bindings"][0].pop("sha256")
        self.assert_rejected(graph)

    def test_ideas_and_evidence_cannot_become_execution_routes(self):
        for origin in ("idea", "projection", "signed_observation", "runtime_report", "independent_verifier"):
            with self.subTest(origin=origin):
                graph = deepcopy(self.graph)
                graph["edges"].append({"from": origin, "to": "begin", "kind": "flow"})
                self.assert_rejected(graph)

    def test_circular_evidence_support_cannot_justify_itself(self):
        self.graph["edges"].append({"from": "launch", "to": "inventory", "kind": "supports"})
        self.assert_rejected(self.graph)

    def test_declared_evidence_and_stop_links_cannot_disappear_or_change_meaning(self):
        connections = [edge for edge in self.graph["edges"] if edge["kind"] != "flow"]
        self.assertEqual(len(connections), 12)
        graph = deepcopy(self.graph)
        graph["edges"] = [edge for edge in graph["edges"] if edge["kind"] == "flow"]
        with self.subTest(mutation="remove all evidence, description and STOP links"):
            self.assert_rejected(graph)
        for connection in connections:
            with self.subTest(connection=connection, mutation="remove link"):
                graph = deepcopy(self.graph)
                graph["edges"].remove(connection)
                self.assert_rejected(graph)
            with self.subTest(connection=connection, mutation="change meaning"):
                graph = deepcopy(self.graph)
                changed = next(edge for edge in graph["edges"] if edge == connection)
                changed["kind"] = "describes" if connection["kind"] == "supports" else "supports"
                self.assert_rejected(graph)

    def test_channel_inventory_cannot_omit_or_invent_a_route(self):
        graph = deepcopy(self.graph)
        graph["channels"].pop()
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["channels"].append({**graph["channels"][0], "id": "uninspected_hidden_mcp"})
        self.assert_rejected(graph)

    def test_channel_barrier_must_be_the_bound_control_not_a_claim(self):
        for barrier in ("missing_control", "idea", "runtime_report"):
            with self.subTest(barrier=barrier):
                graph = deepcopy(self.graph)
                graph["channels"][0]["barrier"] = barrier
                self.assert_rejected(graph)

    def test_required_trust_assumptions_cannot_disappear(self):
        for assumption in self.graph["scope"]["assumptions"]:
            with self.subTest(assumption=assumption):
                graph = deepcopy(self.graph)
                graph["scope"]["assumptions"].remove(assumption)
                self.assert_rejected(graph)

    def test_universal_escape_or_review_score_cannot_grant_authority(self):
        graph = deepcopy(self.graph)
        graph["scope"]["universal_escape_prevention"] = True
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["execution_authorized"] = True
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["review_score"] = {"percent": 100, "execution_authorized": True}
        self.assert_rejected(graph)

    def test_orientation_is_not_falsely_wired_into_g03(self):
        graph = deepcopy(self.graph)
        graph["gaps"]["g03_orientation"] = "CONNECTED"
        self.assert_rejected(graph)
        graph = deepcopy(self.graph)
        graph["edges"].append({"from": "orientation_admission", "to": "launch", "kind": "flow"})
        self.assert_rejected(graph)

    def test_unknown_cannot_refund_or_redispatch_consumed_reservations(self):
        for value in ("REFUND_RESERVATION", "RETRY_POST", "NO_EFFECT_ASSUMED"):
            with self.subTest(value=value):
                graph = deepcopy(self.graph)
                graph["temporal_contract"]["unknown"] = value
                self.assert_rejected(graph)

    def test_final_expiry_guard_cannot_be_claimed_when_only_begin_checks_expiry(self):
        self.graph["temporal_contract"]["expiry"] = "FINAL_COMMIT_EXPIRY_REQUIRED"
        self.assert_rejected(self.graph)

    def test_committed_result_cannot_be_revoked_after_stop(self):
        self.graph["temporal_contract"]["committed"] = "REVOKED_AFTER_STOP"
        self.assert_rejected(self.graph)

    def test_duplicate_json_keys_are_rejected_before_model_validation(self):
        path = self.directory / "duplicate-keys.json"
        path.write_text('{"execution_authorized": false, "execution_authorized": true}', encoding="utf-8")
        with self.assertRaises(ValueError):
            VALIDATOR.load_graph(path)

    def test_nonfinite_json_values_are_rejected_before_model_validation(self):
        path = self.directory / "nonfinite.json"
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                path.write_text('{"score": ' + value + '}', encoding="utf-8")
                with self.assertRaises(ValueError):
                    VALIDATOR.load_graph(path)

    def test_receiver_report_for_different_commit_tree_or_dirty_source_is_stale(self):
        root = self.clean_verifier_repository()
        commit, tree = self.current_identity(root)
        for source in ({"commit": "0" * 40, "tree": tree, "dirty": False},
                       {"commit": commit, "tree": "0" * 40, "dirty": False},
                       {"commit": commit, "tree": tree, "dirty": True}):
            with self.subTest(source=source):
                result = VALIDATOR.inspect_receiver_report(self.report_file({
                    "schema": "liminal-external-agent-receiver-runtime-v1", "source": source,
                    "passed": True, "status": "PASS",
                }), root)
                self.assertEqual(result["runtime_evidence"], "STALE", result)

    def test_matching_head_self_declared_pass_reaches_real_independent_verifier_and_fails(self):
        root = self.clean_verifier_repository()
        commit, tree = self.current_identity(root)
        fake = self.report_file({
            "schema": "liminal-external-agent-receiver-runtime-v1",
            "source": {"commit": commit, "tree": tree, "dirty": False},
            "source_files_sha256": {}, "passed": True,
            "checks": {"all_passed": True}, "status": "PASS",
        })
        actual_run = subprocess.run
        calls = []

        def capture_and_execute(arguments, *args, **kwargs):
            calls.append(arguments)
            return actual_run(arguments, *args, **kwargs)

        # Observe real subprocess execution; no verifier decision is substituted.
        with patch.object(subprocess, "run", side_effect=capture_and_execute):
            result = VALIDATOR.inspect_receiver_report(fake, root)
        self.assertEqual(result["runtime_evidence"], "FAIL", result)
        self.assertTrue(any(str(root / "scripts/verify_external_agent_receiver_evidence.py")
                            in [str(value) for value in arguments] for arguments in calls), calls)

    def test_dirty_checkout_cannot_reuse_a_report_claiming_clean_matching_identity(self):
        root = self.clean_verifier_repository()
        commit, tree = self.current_identity(root)
        report = self.report_file({
            "schema": "liminal-external-agent-receiver-runtime-v1",
            "source": {"commit": commit, "tree": tree, "dirty": False}, "passed": True,
        })
        # Untracked data changes the actual checkout state without moving HEAD.
        (root / "unreviewed-change.txt").write_text("not part of the captured source\n", encoding="utf-8")
        result = VALIDATOR.inspect_receiver_report(report, root)
        self.assertEqual(result["runtime_evidence"], "STALE", result)
        self.assertIs(result["execution_authorized"], False, result)

    def test_source_move_during_child_verification_invalidates_even_a_pass_shaped_reply(self):
        root = self.clean_verifier_repository()
        git = ["git", "-C", str(root), "-c", "core.hooksPath=" + str(self.directory / "empty-hooks"),
               "-c", "user.name=Assurance test fixture", "-c", "user.email=fixture@example.invalid",
               "-c", "commit.gpgSign=false"]
        verifier = root / "scripts/verify_external_agent_receiver_evidence.py"
        # This child is ONLY an identity-race fixture, not the G03 oracle. Its toy
        # PASS shape exercises the caller's source fence; it establishes no facts.
        verifier.write_text(
            "import hashlib, json, subprocess, sys\n"
            "from pathlib import Path\n"
            "root = Path(__file__).resolve().parents[1]\n"
            "(root / 'source-revision-marker.txt').write_text('moved during verification\\n')\n"
            "git = " + repr(git) + "\n"
            "subprocess.run(git + ['add', '--', 'source-revision-marker.txt'], check=True, capture_output=True)\n"
            "subprocess.run(git + ['commit', '-q', '-m', 'Move isolated race fixture'], check=True, capture_output=True)\n"
            "print(json.dumps({'schema':'liminal-external-agent-receiver-verification-v1',\n"
            " 'status':'PASS', 'execution_authorized':False,\n"
            " 'report_sha256':hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()}))\n",
            encoding="utf-8",
        )
        subprocess.run(git + ["add", "--", str(verifier.relative_to(root))],
                       capture_output=True, check=True, timeout=10)
        subprocess.run(git + ["commit", "-q", "-m", "Pin controlled identity race child"],
                       capture_output=True, check=True, timeout=10)
        commit, tree = self.current_identity(root)
        report = self.report_file({"source": {"commit": commit, "tree": tree, "dirty": False}})
        result = VALIDATOR.inspect_receiver_report(report, root)
        moved_commit, moved_tree = self.current_identity(root)
        self.assertNotEqual(moved_commit, commit)
        self.assertNotEqual(moved_tree, tree)
        self.assertEqual(result["runtime_evidence"], "STALE", result)
        self.assertIs(result["execution_authorized"], False, result)

    def test_cli_cannot_require_current_runtime_evidence_without_a_report(self):
        completed = subprocess.run(
            [sys.executable, str(TOOL), "--graph", str(MANIFEST), "--root", str(ROOT),
             "--require-current-report"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["model_status"], "PASS", result)
        self.assertEqual(result["runtime_evidence"], "NOT_RUN", result)
        self.assertIs(result["execution_authorized"], False, result)
        self.assertEqual(result["containment_status"], "NOT_ESTABLISHED", result)
        self.assertEqual(result["readiness"], "HOLD", result)


if __name__ == "__main__":
    unittest.main()
