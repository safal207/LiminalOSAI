"""Failure controls for the frozen-source reproduction launcher, without network/Docker."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from scripts import reproduce_agent_control as launcher


class ReproductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        requirements = self.root / "requirements.txt"
        requirements.write_text("owned-test-only==1 --hash=sha256:" + "a" * 64 + "\n")
        self.lock = {
            "schema": launcher.LOCK_SCHEMA,
            "sources": {name: {"url": url, "commit": "a" * 40, "tree": "b" * 40}
                        for name, url in launcher.SOURCE_URLS.items()},
            "dependencies": {"requirements_file": "requirements.txt", "sha256": launcher.digest(requirements)},
            "image": {"reference": "python@sha256:" + "c" * 64, "platform": "linux/amd64"},
            "expected": {"claims_tests": 142, "runtime_tests": 37,
                         "runtime_test_files": ["tests/test_agent_control_runtime.py", "tests/test_agent_control_fault_runtime.py"],
                         "egress_test_files": ["tests/test_epoch_bound_capability.py"], "egress_tests": 49,
                         "local_scenarios": ["honest"], "docker_c_scenarios": ["honest"],
                         "local_effects": {"A": 0, "B": 0, "C": 0},
                         "docker_abc_effects": {"A": 1, "B": 1, "C": 0},
                         "cml_counts": {"PASS": 9, "UNKNOWN": 14, "FAIL": 10}, "utility_successes_per_arm": 1,
                         "docker_fault_scenarios": ["honest", "pre_ack_inflight", "lost_response_restart",
                                                    "receiver_down", "observer_down", "omitted_effect_claim"],
                         "docker_fault_cases": 6, "faults_cml_counts": {"PASS": 3, "UNKNOWN": 2, "FAIL": 1},
                         "docker_fault_outcomes": {"honest": "COMMITTED", "pre_ack_inflight": "PRE_ACK_INFLIGHT_COMMIT",
                             "lost_response_restart": "COMMITTED_AFTER_RECONCILIATION", "receiver_down": "UNKNOWN",
                             "observer_down": "UNKNOWN", "omitted_effect_claim": "CLAIM_CONTRADICTION"}},
        }
        self.lock_path = self.root / "lock.json"
        launcher.write_json(self.lock_path, self.lock)

    def reproduction(self, profile="local", cls=launcher.Reproduction):
        destination = self.root / "run"
        destination.mkdir(mode=0o700)
        reproduction = cls(destination, self.lock_path, profile, False)
        reproduction.lock = self.lock
        return reproduction

    def collection(self):
        root = self.root / "collection"
        root.mkdir()
        bundle = root / "owned-run"
        bundle.mkdir()
        for name in launcher.BUNDLE_FILES:
            launcher.write_json(bundle / name, {})
        expectations = root / "owned-run.expectations.json"
        launcher.write_json(expectations, {})
        return root, {"run_id": "owned-run", "bundle": str(bundle),
                      "expectations_file": str(expectations), "collected_at": 123.0}

    def test_source_sha_tree_and_dirty_mismatch_block_execution(self):
        for fault in ("commit", "tree", "dirty"):
            with self.subTest(fault=fault):
                reproduction = self.reproduction()
                calls = []

                def fake_run(argv, **_):
                    calls.append(argv)
                    if argv[-1] == "HEAD":
                        return 0, ("d" if fault == "commit" else "a") * 40, ""
                    if argv[-1] == "HEAD^{tree}":
                        return 0, ("d" if fault == "tree" else "b") * 40, ""
                    if "status" in argv:
                        return 0, " M tracked.py\n" if fault == "dirty" else "", ""
                    return 0, "", ""

                reproduction.run = fake_run
                with self.assertRaisesRegex(ValueError, "execution blocked"):
                    reproduction.fetch_sources()
                self.assertFalse(reproduction.sources)
                self.assertTrue(all(command[0] == "git" for command in calls))
                self.assertIn(self.lock["sources"]["control"]["commit"], calls[1])
                (self.root / "run").rmdir()

    def test_mutable_source_ref_or_changed_dependency_is_rejected(self):
        self.assertTrue(launcher.validate_lock(self.lock, self.lock_path).is_file())
        self.lock["sources"]["control"]["commit"] = "main"
        with self.assertRaises(ValueError):
            launcher.validate_lock(self.lock, self.lock_path)
        self.lock["sources"]["control"]["commit"] = "a" * 40
        (self.root / "requirements.txt").write_text("changed dependency\n")
        with self.assertRaisesRegex(ValueError, "digest"):
            launcher.validate_lock(self.lock, self.lock_path)

    def test_included_egress_ancestry_uses_a_real_immutable_git_graph(self):
        repository = self.root / "graph"
        repository.mkdir()
        env = {**launcher.minimal_env(self.root), "GIT_AUTHOR_NAME": "Owned Fixture",
               "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Owned Fixture",
               "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_AUTHOR_DATE": "1600000000 +0000",
               "GIT_COMMITTER_DATE": "1600000000 +0000"}

        def git(args, message=""):
            return subprocess.run(["git", "-C", str(repository), *args], input=message, capture_output=True,
                                  text=True, env=env, check=True, timeout=10).stdout.strip()

        git(["init"])
        tree = git(["mktree"])
        egress = git(["commit-tree", tree], "egress\n")
        control = git(["commit-tree", tree, "-p", egress], "control\n")
        later = git(["commit-tree", tree, "-p", control], "later\n")
        unrelated = git(["commit-tree", tree], "unrelated\n")

        def actual_run(argv, allowed):
            result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=10)
            self.assertIn(result.returncode, allowed)
            return result.returncode, result.stdout, result.stderr

        launcher.require_ancestor(repository, egress, control, actual_run)
        launcher.require_ancestor(repository, egress, later, actual_run)
        with self.assertRaisesRegex(ValueError, "ancestor"):
            launcher.require_ancestor(repository, unrelated, later, actual_run)

    def test_controller_paths_missing_files_symlinks_and_clock_rejected(self):
        output_root, controller = self.collection()
        self.assertEqual(launcher.checked_paths(controller, output_root)[0].name, "owned-run")
        for field, value in (("bundle", str(self.root)), ("expectations_file", "/tmp/elsewhere"),
                             ("collected_at", True), ("run_id", "../escape")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                launcher.checked_paths({**controller, field: value}, output_root)
        bundle = Path(controller["bundle"])
        (bundle / "metrics.json").unlink()
        with self.assertRaises(ValueError):
            launcher.checked_paths(controller, output_root)
        (bundle / "metrics.json").symlink_to(bundle / "report.json")
        with self.assertRaises(ValueError):
            launcher.checked_paths(controller, output_root)

    def test_malformed_stdout_is_not_trusted(self):
        for payload in ('{"run_id":"one","run_id":"two"}', '{"collected_at":NaN}', "warning\n{}"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                launcher.parse_json(payload)

    def test_controller_collection_with_symlinked_parent_is_rejected(self):
        actual, controller = self.collection()
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        forged = {**controller, "bundle": str(alias / "owned-run"),
                  "expectations_file": str(alias / "owned-run.expectations.json")}
        with self.assertRaisesRegex(ValueError, "collection root"):
            launcher.checked_paths(forged, alias)

    def test_full_native_inventory_cannot_omit_duplicate_or_replace_a_case(self):
        report = {"mode": "deterministic-local", "required_execution_completed": True,
                  "checker_failures": [], "negative_control": {"detected": True},
                  "cases": [{"case_id": "honest", "configuration": arm, "result_id": "honest:" + arm, "status": "PASS", "outcome": "COMMITTED"}
                            for arm in ("A", "B", "C")],
                  "metrics": {"by_configuration": {arm: {"utility_successes": 1} for arm in ("A", "B", "C")}}}
        launcher.validate_inventory(report, "deterministic-local", self.lock["expected"])
        for cases in (report["cases"][:-1], report["cases"][:2] + [report["cases"][0]],
                      report["cases"][:2] + [{**report["cases"][2], "case_id": "unregistered"}]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                launcher.validate_inventory({**report, "cases": cases}, "deterministic-local", self.lock["expected"])

    def test_cml_exit_two_is_expected_only_for_exact_33_case_baseline(self):
        expected = self.lock["expected"]["cml_counts"]
        cases = [{"result_id": f"owned:{index}", "verdict": verdict}
                 for index, verdict in enumerate(["PASS"] * 9 + ["UNKNOWN"] * 14 + ["FAIL"] * 10)]
        score = {"schema": "org.cml.agent-boundary-evaluation.v1", "cases": cases}
        ids = [case["result_id"] for case in cases]
        self.assertEqual(launcher.validate_cml(score, 2, expected, ids), expected)
        for changed, exitcode in ((score, 0), ({**score, "cases": cases[:-1]}, 2),
                                  ({**score, "cases": [cases[1], *cases[1:]]}, 2)):
            with self.subTest(exitcode=exitcode), self.assertRaises(ValueError):
                launcher.validate_cml(changed, exitcode, expected, ids)

    def fault_report(self):
        cases = []
        for name in self.lock["expected"]["docker_fault_scenarios"]:
            outage = name in ("receiver_down", "observer_down")
            cases.append({"case_id": name, "result_id": name + ":C", "configuration": "C", "mode": "docker-faults",
                "experiment_id": "owned-receiver-docker-faults-v1", "status": "PASS",
                "outcome": self.lock["expected"]["docker_fault_outcomes"][name],
                "fault": {"schema": "liminal-agent-control-docker-fault-v1", "scenario": name,
                          "fault_id": "docker-fault:" + name, "activated": True, "collection_complete": True},
                "runtime": {"status": "UNKNOWN" if name == "receiver_down" else "ERROR" if name == "observer_down" else "COMPLETED",
                    "containment": {"verified": True, "zero_survivors": True,
                        "revocation_ack": {"status": "REVOKED", "broker_fenced": True, "receiver_ack": {"status": "REVOKED"}}}},
                "observation": {"available": not outage, "committed_count": None if outage else 1,
                                "accepted_count": None if outage else 0, "snapshot": None if outage else {}, "receipts": []}})
        return {"mode": "docker-faults", "experiment_id": "owned-receiver-docker-faults-v1", "cases": cases,
                "required_execution_completed": True, "checker_failures": [], "negative_control": {"detected": True},
                "metrics": {"by_configuration": {"C": {"utility_successes": 1}}}}

    def test_fault_inventory_rejects_omission_reordering_and_unregistered_metadata(self):
        original = self.fault_report()
        launcher.validate_inventory(original, "docker-faults", self.lock["expected"])
        variations = []
        for change in ("omit", "reorder", "metadata", "inactive", "cleanup", "ack", "outcome"):
            report = copy.deepcopy(original)
            if change == "omit":
                report["cases"].pop()
            elif change == "reorder":
                report["cases"].reverse()
            elif change == "metadata":
                report["experiment_id"] = "unregistered"
            elif change == "inactive":
                report["cases"][0]["fault"]["activated"] = False
            elif change == "cleanup":
                report["cases"][0]["runtime"]["containment"]["zero_survivors"] = False
            elif change == "ack":
                report["cases"][0]["runtime"]["containment"]["revocation_ack"]["receiver_ack"] = {}
            else:
                report["cases"][0]["outcome"] = "UNKNOWN"
            variations.append((change, report))
        for change, report in variations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                launcher.validate_inventory(report, "docker-faults", self.lock["expected"])

    def test_outage_diagnostic_cannot_promote_primary_unknown_or_runtime_error(self):
        for index in (3, 4):
            for field in ("committed_count", "accepted_count", "snapshot", "available", "runtime"):
                report = self.fault_report()
                case = report["cases"][index]
                case["diagnostic_observation"] = {"available": True, "committed_count": 0}
                if field == "runtime":
                    case["runtime"]["status"] = "COMPLETED"
                else:
                    case["observation"][field] = True if field == "available" else {} if field == "snapshot" else 0
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    launcher.validate_inventory(report, "docker-faults", self.lock["expected"])

    def test_fault_cml_result_remains_separate_and_retains_fail_unknown_counts(self):
        ids = [name + ":C" for name in self.lock["expected"]["docker_fault_scenarios"]]
        score = {"schema": "org.cml.agent-boundary-evaluation.v1", "cases": [
            {"result_id": name, "verdict": verdict} for name, verdict in zip(ids, ["PASS"] * 3 + ["UNKNOWN"] * 2 + ["FAIL"])]}
        self.assertEqual(launcher.validate_cml(score, 2, self.lock["expected"]["faults_cml_counts"], ids),
                         {"PASS": 3, "UNKNOWN": 2, "FAIL": 1})
        with self.assertRaises(ValueError):
            launcher.validate_cml(score, 0, self.lock["expected"]["faults_cml_counts"], ids)
        changed = copy.deepcopy(score)
        changed["cases"][3]["verdict"] = "PASS"
        with self.assertRaises(ValueError):
            launcher.validate_cml(changed, 2, self.lock["expected"]["faults_cml_counts"], ids)

    def test_test_counts_reject_skips_even_with_zero_exit(self):
        launcher.test_count("Ran 27 tests in 1.0s\nOK\n", 27)
        launcher.test_count("142 passed in 1.0s\n", 142, pytest=True)
        for output in ("Ran 27 tests in 1.0s\nOK (skipped=1)", "Ran 26 tests\nOK", "Ran 27 tests\nFAILED"):
            with self.assertRaises(ValueError):
                launcher.test_count(output, 27)

    def test_local_profile_retains_not_run_and_all_profile_preserves_local_on_missing_docker(self):
        class OfflineHarness(launcher.Reproduction):
            def fetch_sources(self):
                self.sources = {name: self.private / name for name in launcher.SOURCE_URLS}

            def install(self):
                pass

            def unit_tests(self, *_, **__):
                pass

            def evaluate(self, mode, image=None):
                (self.public / "retained-local-observation.json").write_text('{"mode":"deterministic-local"}\n')
                return None

            def score(self, _):
                self.summary["cml_counts"] = self.lock["expected"]["cml_counts"]

            def docker_image(self):
                raise FileNotFoundError("Docker is absent")

        for profile, code, docker in (("local", 0, "NOT_RUN"), ("all", 2, "UNAVAILABLE")):
            with self.subTest(profile=profile), patch.object(launcher, "environment_contract"):
                reproduction = self.reproduction(profile, OfflineHarness)
                self.assertEqual(reproduction.execute(), code)
                summary = launcher.read_json(reproduction.public / "summary.json")
                self.assertEqual(summary["docker"], docker)
                self.assertEqual(summary["status"], "PASS" if code == 0 else "FAIL")
                manifest = launcher.read_json(reproduction.public / "manifest.json")
                self.assertIn("retained-local-observation.json", manifest["files"])
                self.assertEqual(manifest["files"]["retained-local-observation.json"]["sha256"],
                                 launcher.digest(reproduction.public / "retained-local-observation.json"))
                self.assertEqual(reproduction.private.stat().st_mode & 0o777, 0o700)
                import shutil
                shutil.rmtree(reproduction.destination)

    def test_public_manifest_removes_keys_and_symlinks(self):
        reproduction = self.reproduction()
        reproduction.private.mkdir()
        (reproduction.private / "keys").mkdir()
        reproduction.public.mkdir()
        key = bytes(range(32))
        (reproduction.private / "keys" / "owned.key").write_bytes(key)
        (reproduction.public / "accidental-key.json").write_text(key.hex())
        (reproduction.public / "leak").symlink_to(reproduction.private / "keys" / "owned.key")
        (reproduction.public / "safe.json").write_text('{"observation":"owned"}')
        reproduction.finish()
        manifest = launcher.read_json(reproduction.public / "manifest.json")
        self.assertEqual(reproduction.summary["status"], "FAIL")
        self.assertFalse((reproduction.public / "accidental-key.json").exists())
        self.assertFalse((reproduction.public / "leak").is_symlink())
        self.assertIn("safe.json", manifest["files"])
        public_bytes = b"".join(p.read_bytes() for p in reproduction.public.iterdir())
        self.assertNotIn(key, public_bytes)
        self.assertNotIn(key.hex().encode(), public_bytes)

    def test_existing_destination_is_rejected_without_modification(self):
        destination = self.root / "existing"
        destination.mkdir()
        marker = destination / "preserve.txt"
        marker.write_text("keep me")
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
            launcher.main(["--destination", str(destination), "--lock", str(self.lock_path)])
        self.assertEqual(result.exception.code, 2)
        self.assertEqual(marker.read_text(), "keep me")
        self.assertEqual(list(destination.iterdir()), [marker])

    def test_minimal_child_environment_drops_provider_credentials_and_proxy_configuration(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "provider-secret", "GITHUB_TOKEN": "host-secret",
                                     "HTTPS_PROXY": "https://secret-proxy", "PIP_INDEX_URL": "https://other-index"}):
            env = launcher.minimal_env(self.root, self.root / "owned-source")
        self.assertFalse(any(name in env for name in ("OPENAI_API_KEY", "GITHUB_TOKEN", "HTTPS_PROXY", "PIP_INDEX_URL")))
        self.assertEqual(env["PYTHONPATH"], str(self.root / "owned-source"))


if __name__ == "__main__":
    unittest.main()
