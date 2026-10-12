"""Evidence authentication, inventory and replay pins for the composed fixture."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import sign_document
from sdk.liminal_agent_control.multi_agent import run_suite, verify_bundle, main

KEY = b"synthetic-multi-worker-evaluation-key" * 2


class MultiAgentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.result = run_suite(cls.root / "original", KEY)
        cls.bundle = Path(cls.result["bundle"])

    def copy_bundle(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        bundle = Path(temporary.name) / "evidence"
        bundle.mkdir()
        for path in self.bundle.iterdir():
            (bundle / path.name).write_bytes(path.read_bytes())
        return bundle

    def rewrite_report(self, bundle, mutate, *, authenticate=False):
        report = json.loads((bundle / "report.json").read_text())
        mutate(report)
        if authenticate:
            report = sign_document(report, KEY)
        (bundle / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        manifest = json.loads((bundle / "manifest.json").read_text())
        for name in manifest["files"]:
            raw = (bundle / name).read_bytes()
            manifest["files"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        (bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_real_complete_run_and_external_digest_verify(self):
        self.assertEqual(self.result["checks"]["status"], "PASS", self.result["checks"])
        verified = verify_bundle(self.bundle, KEY, expected_report_sha256=self.result["report_sha256"])
        self.assertTrue(verified["valid"], verified)
        self.assertTrue(verified["current_run_pinned"])

    def test_wrong_external_key_rejected(self):
        self.assertFalse(verify_bundle(self.bundle, b"different-synthetic-key" * 2)["valid"])

    def test_rehashed_report_mutation_does_not_create_authenticated_evidence(self):
        bundle = self.copy_bundle()
        self.rewrite_report(bundle, lambda r: r.update(created_at=r["created_at"] + 1))
        self.assertIn("collector authentication failed", verify_bundle(bundle, KEY)["errors"])

    def test_signed_case_removal_still_fails_semantic_inventory(self):
        bundle = self.copy_bundle()
        self.rewrite_report(bundle, lambda r: r["cases"].pop(), authenticate=True)
        self.assertFalse(verify_bundle(bundle, KEY)["valid"])

    def test_authenticated_scope_promotion_rejected(self):
        bundle = self.copy_bundle()
        self.rewrite_report(bundle, lambda r: r["execution"].update(live_model="PASS"), authenticate=True)
        self.assertIn("execution scope mismatch", verify_bundle(bundle, KEY)["errors"])

    def test_stale_authentic_report_does_not_match_external_run_pin(self):
        self.assertFalse(verify_bundle(self.bundle, KEY, expected_report_sha256="0" * 64)["valid"])

    def test_authenticated_missing_source_revision_is_not_reviewable(self):
        bundle = self.copy_bundle()
        self.rewrite_report(bundle, lambda r: r.pop("source"), authenticate=True)
        self.assertIn("invalid source revision identity", verify_bundle(bundle, KEY)["errors"])

    def test_extra_member_symlink_and_manifest_traversal_rejected(self):
        for mutation in ("extra", "symlink", "traversal"):
            with self.subTest(mutation=mutation):
                bundle = self.copy_bundle()
                if mutation == "extra":
                    (bundle / "ignored.json").write_text("{}")
                elif mutation == "symlink":
                    (bundle / "report.json").unlink()
                    (bundle / "report.json").symlink_to(self.bundle / "report.json")
                else:
                    manifest = json.loads((bundle / "manifest.json").read_text())
                    manifest["files"]["../report.json"] = manifest["files"].pop("report.json")
                    (bundle / "manifest.json").write_text(json.dumps(manifest))
                self.assertFalse(verify_bundle(bundle, KEY)["valid"])

    def test_new_runs_have_unique_directories_and_no_keys_or_databases(self):
        second = run_suite(self.root / "original", KEY)
        self.assertNotEqual(second["bundle"], self.result["bundle"])
        for path in Path(second["bundle"]).iterdir():
            self.assertEqual(path.suffix, ".json")
            self.assertNotIn(KEY, path.read_bytes())

    def test_key_inside_public_tree_rejected_before_key_creation(self):
        with tempfile.TemporaryDirectory() as name:
            key = Path(name) / "public.key"
            with patch("sys.stderr"):
                self.assertEqual(main(["run", "--output-root", name,
                                       "--receipt-key-file", str(key)]), 1)
            self.assertFalse(key.exists())


if __name__ == "__main__":
    unittest.main()
