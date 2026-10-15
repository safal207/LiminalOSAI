"""Rehashing an unsigned bundle cannot conceal evidence or label substitutions."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.reproduce_reinforcement_contract import reproduce, write_json
from scripts.verify_reinforcement_bundle import (
    CASE_IDS, MAX_EXTERNAL_BYTES, MAX_FILE_BYTES, POSITIVE_IDS,
    EvidenceError, verify_bundle,
)
from sdk.liminal_agent_control.external_stop_demo import run_demo
from sdk.liminal_agent_control.reinforcement import assess, seal_episode


class ReinforcementBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.shared.cleanup)
        cls.base = Path(cls.shared.name) / "original"
        cls.external_path = Path(cls.shared.name) / "external.json"
        # One actual bounded authority/receiver process run for all mutations.
        write_json(cls.external_path, run_demo())
        cls.summary = reproduce(cls.base, external_report=cls.external_path)
        cls.verified = verify_bundle(cls.base)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / "bundle"
        shutil.copytree(self.base, self.bundle)

    def load(self, name):
        return json.loads((self.bundle / name).read_bytes())

    def write(self, name, value):
        write_json(self.bundle / name, value)

    def rehash(self):
        manifest = self.load("manifest.json")
        for item in manifest["files"]:
            path = self.bundle / item["path"]
            raw = path.read_bytes()
            item.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.write("manifest.json", manifest)

    def rejected(self, reason=None, **kwargs):
        if reason is None:
            with self.assertRaises((EvidenceError, OSError, ValueError, KeyError, TypeError)):
                verify_bundle(self.bundle, **kwargs)
        else:
            with self.assertRaisesRegex(EvidenceError, reason):
                verify_bundle(self.bundle, **kwargs)

    def test_actual_bundle_replays_all_19_cases_with_six_non_authorizing_examples(self):
        result = verify_bundle(self.bundle)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cases_verified"], list(CASE_IDS))
        self.assertEqual(result["positive_examples_verified"], 6)
        self.assertEqual(result["source_files_verified"], 11)
        self.assertEqual(result["files_verified"], 8)
        self.assertIs(result["execution_authorized"], False)
        self.assertIs(result["model_training"], False)
        self.assertEqual(result["manifest_scope"], "bundle_consistency_only")
        external = result["external_verification"]
        self.assertEqual(external["pin_scope"], "report_fixture")
        self.assertEqual(external["checkpoint_verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertEqual(external["contractgraph_qa"]["status"], "NOT_RUN")
        for item in self.load("assessments.json"):
            self.assertEqual(item["assessment"]["learning_record"] is not None,
                             item["case_id"] in POSITIVE_IDS)

    def test_independently_supplied_exact_manifest_digest_is_checked(self):
        expected = hashlib.sha256((self.bundle / "manifest.json").read_bytes()).hexdigest()
        self.assertEqual(verify_bundle(self.bundle, expected_manifest_sha256=expected)["manifest_scope"],
                         "caller_supplied_digest")
        self.rejected("caller-supplied manifest", expected_manifest_sha256="0" * 64)

    def test_payload_bytes_cannot_change_without_manifest_update(self):
        with (self.bundle / "assessments.json").open("ab") as stream:
            stream.write(b" ")
        self.rejected("manifest byte/digest")

    def test_rehashed_assessment_status_and_learning_record_are_replayed(self):
        rows = self.load("assessments.json")
        row = next(item for item in rows if item["case_id"] == "unsafe_baseline")
        row["assessment"] = copy.deepcopy(rows[0]["assessment"])
        self.write("assessments.json", rows)
        self.rehash()
        self.rejected("assessments do not replay")

    def test_rehashed_sticky_hard_violation_cannot_be_removed(self):
        rows = self.load("assessments.json")
        row = next(item for item in rows if item["case_id"] == "retry_unknown")
        self.assertTrue(row["assessment"]["hard_violations"])
        row["assessment"]["hard_violations"] = []
        self.write("assessments.json", rows)
        self.rehash()
        self.rejected("assessments do not replay")

    def test_resealed_and_rehashed_episode_is_rebuilt_from_raw_evidence(self):
        episodes = self.load("episodes.json")
        raw = episodes["authority_unavailable"]["episode"]
        raw.pop("head_hash")
        raw.pop("episode_digest")
        for opportunity in raw["opportunities"]:
            for key in ("sequence", "parent_hash", "opportunity_hash"):
                opportunity.pop(key)
        raw["opportunities"][0].update(visible_outcome="DENIED", visible_effect_count=0)
        episodes["authority_unavailable"]["episode"] = seal_episode(raw)
        self.write("episodes.json", episodes)
        self.rehash()
        self.rejected("episodes do not replay")

    def test_rehashed_candidate_and_its_recomputed_assessment_cannot_replace_matrix(self):
        comparisons = self.load("candidates.json")
        item = next(item for item in comparisons if item["case_id"] == "false_zero")
        item["candidate"]["answers"][0]["effect_count"] = None
        self.write("candidates.json", comparisons)
        rows = self.load("assessments.json")
        contract, episodes = self.load("contract.json"), self.load("episodes.json")
        row = next(row for row in rows if row["case_id"] == item["case_id"])
        row["assessment"] = assess(contract, episodes[item["episode_id"]]["episode"], item["candidate"])
        self.write("assessments.json", rows)
        self.rehash()
        self.rejected("candidates differ")

    def test_source_digest_substitution_is_rejected_after_rehash(self):
        report = self.load("report.json")
        report["source_files_sha256"]["sdk/liminal_agent_control/reinforcement.py"] = "0" * 64
        self.write("report.json", report)
        self.rehash()
        self.rejected("source digest mismatch")

    def test_source_inventory_cannot_omit_or_add_a_path(self):
        for operation in ("omit", "add"):
            with self.subTest(operation=operation):
                report = self.load("report.json")
                if operation == "omit":
                    report["source_files_sha256"].pop("sdk/liminal_agent_control/reinforcement.py")
                else:
                    report["source_files_sha256"]["extra.py"] = "0" * 64
                self.write("report.json", report)
                self.rehash()
                self.rejected("source inventory missing/extra")

    def test_source_inventory_rejects_traversal_before_reading_it(self):
        report = self.load("report.json")
        old = report["source_files_sha256"].pop("sdk/liminal_agent_control/reinforcement.py")
        report["source_files_sha256"]["../../outside.py"] = old
        self.write("report.json", report)
        self.rehash()
        self.rejected("source inventory missing/extra")

    def test_expected_source_requires_clean_reported_identity(self):
        report = self.load("report.json")
        report["source"]["dirty"] = True
        self.write("report.json", report)
        self.rehash()
        self.rejected("expected clean source", expected_source_sha=report["source"]["commit"])

    def test_expected_source_checks_actual_checkout_dirt_despite_clean_report_claim(self):
        report = self.load("report.json")
        fixture_repo = Path(self.temp.name) / "repo"
        fixture_repo.mkdir()
        from scripts.verify_reinforcement_bundle import ROOT, EXPECTED_SOURCES
        for name in EXPECTED_SOURCES:
            destination = fixture_repo / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
        def git(*args):
            return subprocess.run(["git", "-C", str(fixture_repo), *args], check=True,
                                  capture_output=True, text=True, timeout=10).stdout.strip()
        git("init", "--quiet")
        git("add", ".")
        git("-c", "user.name=Reinforcement fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "--quiet", "-m", "Freeze bounded verifier source fixture")
        expected_sha, expected_tree = git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
        (fixture_repo / "untracked-change.txt").write_text("dirty independently of the claimed report")
        report["source"].update(commit=expected_sha, tree=expected_tree, dirty=False)
        self.write("report.json", report)
        self.rehash()
        self.rejected("expected source checkout is dirty", repo_root=fixture_repo, expected_source_sha=expected_sha)

    def test_scripted_stop_and_query_slots_do_not_expose_future_signed_observations(self):
        external = self.load("external-stop.json")
        episodes = self.load("episodes.json")
        case = external["outcomes"]["pending_duplicate"]
        stop_pairs = [pair for pair in case["authority_evidence"]
                      if pair["request"]["operation"] == "stop"
                      and pair["request"]["payload"].get("root_id") == case["action"]["root_id"]]
        self.assertTrue(stop_pairs)
        pending = episodes["pending_stop"]["episode"]["opportunities"][0]
        self.assertGreaterEqual(pending["observed_at"], stop_pairs[-1]["response"]["issued_at"])
        case = external["outcomes"]["terminal_restore"]
        query_pairs = [pair for pair in case["authority_evidence"]
                       if pair["request"]["operation"] == "query"
                       and pair["request"]["payload"].get("action_id") == case["action"]["action_id"]]
        self.assertTrue(query_pairs)
        delivered = episodes["uncertainty_then_receipt"]["episode"]["opportunities"][1]
        self.assertGreaterEqual(delivered["observed_at"], query_pairs[-1]["response"]["issued_at"])

    def test_rehashed_raw_external_tamper_is_checked_despite_cached_pass(self):
        external = self.load("external-stop.json")
        external["authority_evidence"][0]["response"]["signature"] = "0" * 128
        self.write("external-stop.json", external)
        report = self.load("report.json")
        report["external_report_sha256"] = hashlib.sha256((self.bundle / "external-stop.json").read_bytes()).hexdigest()
        self.write("report.json", report)
        self.assertEqual(self.load("external-verification.json")["status"], "PASS")
        self.rehash()
        self.rejected("signature invalid")

    def test_raw_external_bytes_digest_is_not_a_canonical_document_digest(self):
        with (self.bundle / "external-stop.json").open("ab") as stream:
            stream.write(b"\n")
        self.rehash()
        self.rejected("raw external report digest")

    def test_rehashed_authorization_or_training_flag_cannot_be_added(self):
        for field, value in (("execution_authorized", True), ("model_training", True),
                             ("execution_authorized", 0), ("model_training", 0)):
            with self.subTest(field=field, value=value):
                report = self.load("report.json")
                report[field] = value
                self.write("report.json", report)
                self.rehash()
                self.rejected("summary differs")

    def test_boolean_effect_count_cannot_be_hidden_by_python_equality(self):
        comparisons = self.load("candidates.json")
        comparisons[0]["candidate"]["answers"][0]["effect_count"] = True
        self.write("candidates.json", comparisons)
        self.rehash()
        self.rejected("candidates differ")

    def test_rehashed_positive_jsonl_cannot_duplicate_omit_or_reformat(self):
        original = (self.bundle / "positive-examples.jsonl").read_bytes()
        lines = original.splitlines(keepends=True)
        self.assertEqual(len(lines), 6)
        for raw in (original + lines[0], b"".join(lines[:-1]), original + b" "):
            with self.subTest(size=len(raw)):
                (self.bundle / "positive-examples.jsonl").write_bytes(raw)
                self.rehash()
                self.rejected("positive JSONL differs")

    def test_matrix_case_order_and_extra_candidates_are_rejected(self):
        rows = self.load("candidates.json")
        rows.reverse()
        rows.append(copy.deepcopy(rows[0]))
        self.write("candidates.json", rows)
        self.rehash()
        self.rejected("candidates differ")

    def test_cached_verification_cannot_upgrade_checkpoint_trust(self):
        cached = self.load("external-verification.json")
        cached["checkpoint_verification_status"] = "EXTERNAL_ANCHORED_VERIFIED"
        self.write("external-verification.json", cached)
        self.rehash()
        self.rejected("cached external verification core")

    def test_cached_oracle_pass_does_not_claim_a_fresh_oracle_run(self):
        cached = self.load("external-verification.json")
        cached["contractgraph_qa"] = {"status": "PASS", "execution_authorized": False, "results": []}
        self.write("external-verification.json", cached)
        self.rehash()
        result = verify_bundle(self.bundle)
        self.assertEqual(result["external_verification"]["contractgraph_qa"]["status"], "NOT_RUN")

    def test_manifest_duplicate_json_keys_are_rejected(self):
        path = self.bundle / "manifest.json"
        raw = path.read_text()
        path.write_text(raw.replace('"schema":', '"schema": "duplicate", "schema":', 1))
        self.rejected("duplicate JSON object key")

    def test_manifest_path_traversal_absolute_or_duplicate_inventory_is_rejected(self):
        original = self.load("manifest.json")
        for bad_path in ("../external-stop.json", str((self.bundle / "external-stop.json").resolve()),
                         original["files"][1]["path"]):
            with self.subTest(path=bad_path):
                manifest = copy.deepcopy(original)
                manifest["files"][0]["path"] = bad_path
                self.write("manifest.json", manifest)
                self.rejected("manifest paths")

    def test_manifest_boolean_byte_count_is_rejected(self):
        manifest = self.load("manifest.json")
        manifest["files"][0]["size_bytes"] = True
        self.write("manifest.json", manifest)
        self.rejected("invalid manifest size")

    def test_missing_extra_file_or_subdirectory_is_rejected(self):
        (self.bundle / "extra.txt").write_text("not in matrix")
        self.rejected("missing/extra files")
        (self.bundle / "extra.txt").unlink()
        (self.bundle / "extra").mkdir()
        self.rejected("missing/extra files")
        (self.bundle / "extra").rmdir()
        (self.bundle / "contract.json").unlink()
        self.rejected("missing/extra files")

    def test_symlink_payload_and_symlink_bundle_directory_are_rejected(self):
        path = self.bundle / "contract.json"
        outside = Path(self.temp.name) / "outside.json"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        self.rejected("non-regular/symlink")
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaisesRegex(EvidenceError, "bundle directory"):
            verify_bundle(alias)

    def test_oversized_external_or_small_payload_is_rejected_before_parsing(self):
        for name, maximum in (("external-stop.json", MAX_EXTERNAL_BYTES), ("episodes.json", MAX_FILE_BYTES)):
            with self.subTest(name=name):
                path = self.bundle / name
                original = path.read_bytes()
                with path.open("wb") as stream:
                    stream.truncate(maximum + 1)
                self.rejected("input file exceeds bound")
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
