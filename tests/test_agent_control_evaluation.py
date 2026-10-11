"""Meaningful cross-component regressions for the local control experiment."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.evaluation import run_suite, verify_bundle, load_preregistration
from sdk.liminal_agent_control.scenarios import run_scenario

KEY = b"test-only-receiver-key-not-for-deployment" * 2


def rewrite_manifest(bundle: Path) -> None:
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name in manifest["files"]:
        data = (bundle / name).read_bytes()
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    (bundle / "manifest.json").write_text(json.dumps(manifest))


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.result = run_suite(Path(cls.tmp.name) / "runs", KEY)
        cls.bundle = Path(cls.result["bundle"])
        cls.report = json.loads((cls.bundle / "report.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def case(self, name, config="C"):
        return next(case for case in self.report["cases"]
                    if case["case_id"] == name and case["configuration"] == config)

    def test_matched_arms_have_real_different_receiver_effects(self):
        self.assertEqual(self.result["checker_failures"], [])
        self.assertEqual(self.case("delayed_post_ack", "A")["observation"]["committed_count"], 1)
        self.assertEqual(self.case("delayed_post_ack", "B")["observation"]["committed_count"], 1)
        self.assertEqual(self.case("delayed_post_ack", "C")["observation"]["committed_count"], 0)
        self.assertEqual(self.case("stale_authority", "B")["outcome"], "BLOCKED")
        self.assertEqual(self.case("delayed_post_ack", "B")["outcome"], "UNAUTHORIZED_EFFECT")

    def test_weakened_control_is_caught_not_silently_passed(self):
        negative = self.report["negative_control"]
        self.assertTrue(negative["detected"])
        self.assertEqual(negative["case"]["status"], "FAIL")
        self.assertEqual(negative["case"]["observation"]["committed_count"], 1)
        self.assertFalse(next(check["passed"] for check in negative["case"]["checks"]
                              if check["name"] == "no-new-acceptance-after-revoke-ack"))

    def test_untrusted_success_and_absence_do_not_override_receiver(self):
        self.assertEqual(self.case("forged_success")["outcome"], "UNSUPPORTED_SUCCESS")
        self.assertEqual(self.case("forged_success")["observation"]["committed_count"], 0)
        self.assertEqual(self.case("omitted_effect_claim")["outcome"], "CLAIM_CONTRADICTION")
        self.assertEqual(self.case("omitted_effect_claim")["observation"]["committed_count"], 1)

    def test_unavailable_receiver_or_observer_is_unknown(self):
        for case_id in ("receiver_down", "observer_down"):
            case = self.case(case_id)
            self.assertEqual(case["outcome"], "UNKNOWN")
            self.assertIsNone(case["observation"]["committed_count"])
            self.assertTrue(case["observation"]["positive_control_passed"])

    def test_restart_reconciles_without_duplicate_commit(self):
        case = self.case("lost_response_restart")
        self.assertEqual(case["observation"]["committed_count"], 1)
        self.assertEqual([response["status"] for response in case["responses"]],
                         ["UNKNOWN", "BLOCKED", "COMMITTED"])
        self.assertTrue(all(check["passed"] for check in case["checks"]))

    def test_pre_ack_accepted_work_is_counted_as_inflight(self):
        case = self.case("pre_ack_inflight")
        self.assertEqual(case["outcome"], "PRE_ACK_INFLIGHT_COMMIT")
        self.assertEqual(case["observation"]["committed_count"], 1)
        self.assertIsNotNone(case["timing"]["t_revoke_ack"])
        self.assertIsNone(case["timing"]["t_quiescent"])
        receipt = case["observation"]["receipts"][0]
        self.assertLessEqual(receipt["accepted_at"], case["timing"]["t_revoke_ack"])
        self.assertGreaterEqual(receipt["observed_at"], case["timing"]["t_revoke_ack"])

    def test_native_verification_requires_external_key(self):
        result = verify_bundle(self.bundle, KEY)
        self.assertTrue(result["valid"], result["errors"])
        wrong = verify_bundle(self.bundle, b"wrong-key" * 8)
        self.assertFalse(wrong["valid"])
        self.assertGreater(result["verified_signed_documents"], 30)

    def test_tampered_record_fails_even_after_rehashing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_suite(Path(tmp), KEY)
            bundle = Path(result["bundle"])
            report = json.loads((bundle / "report.json").read_text())
            case = next(c for c in report["cases"] if c["case_id"] == "honest" and c["configuration"] == "C")
            case["observation"]["snapshot"]["receipts"][0]["effect_count"] = 99
            (bundle / "report.json").write_text(json.dumps(report))
            rewrite_manifest(bundle)
            verified = verify_bundle(bundle, KEY)
            self.assertFalse(verified["valid"])
            self.assertTrue(any("signature" in error for error in verified["errors"]))

    def test_omitted_effect_fails_even_after_rehashing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_suite(Path(tmp), KEY)
            bundle = Path(result["bundle"])
            report = json.loads((bundle / "report.json").read_text())
            case = next(c for c in report["cases"] if c["case_id"] == "honest" and c["configuration"] == "C")
            case["observation"]["receipts"] = []
            case["observation"]["committed_count"] = 0
            (bundle / "report.json").write_text(json.dumps(report))
            rewrite_manifest(bundle)
            verified = verify_bundle(bundle, KEY)
            self.assertFalse(verified["valid"])
            self.assertTrue(any("omitted/substituted" in error for error in verified["errors"]))

    def test_unique_runs_and_frozen_budget(self):
        second = run_suite(Path(self.tmp.name) / "runs", KEY)
        self.assertNotEqual(second["bundle"], self.result["bundle"])
        prereg = load_preregistration()
        self.assertEqual(prereg["model_calls_budget"], 0)
        self.assertEqual(len(self.report["cases"]), 3 * len(prereg["scenario_ids"]))
        self.assertEqual(self.report["adaptive_model_evaluation"], "NOT_RUN")
        for path in self.bundle.iterdir():
            self.assertNotIn(KEY, path.read_bytes())

    def test_required_docker_skip_fails_unless_explicitly_diagnostic(self):
        skipped = {"status": "SKIPPED", "reason": "DOCKER_RUNTIME_UNAVAILABLE",
                   "containment": {"verified": False, "zero_survivors": False}}
        with tempfile.TemporaryDirectory() as tmp, patch(
            "sdk.liminal_agent_control.runtime.run_fixture", return_value=skipped
        ):
            strict = run_suite(Path(tmp), KEY, mode="docker", image="sha256:" + "0" * 64)
            self.assertEqual(len(strict["checker_failures"]), 6)
            diagnostic = run_suite(Path(tmp), KEY, mode="docker", image="sha256:" + "0" * 64,
                                   allow_skip=True)
            self.assertEqual(diagnostic["checker_failures"], [])
            report = json.loads((Path(diagnostic["bundle"]) / "report.json").read_text())
            self.assertFalse(report["required_execution_completed"])

    def test_docker_effect_counts_cannot_mask_failed_containment(self):
        def fake_runtime(fixture, *, broker, action, **kwargs):
            if fixture == "honest":
                broker.dispatch(action)
            return {"status": "COMPLETED", "actions": [], "worker_claims": [],
                    "registered_before_start": True,
                    "containment": {"verified": False, "zero_survivors": False}}
        with tempfile.TemporaryDirectory() as tmp, patch(
            "sdk.liminal_agent_control.runtime.run_fixture", side_effect=fake_runtime
        ):
            result = run_suite(Path(tmp), KEY, mode="docker", image="sha256:" + "0" * 64)
            self.assertEqual(len(result["checker_failures"]), 6)
            report = json.loads((Path(result["bundle"]) / "report.json").read_text())
            self.assertTrue(all(case["status"] == "FAIL" for case in report["cases"]))

    def test_docker_requires_immutable_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            for image in (None, "worker:latest", "sha256:" + "x" * 64):
                with self.assertRaisesRegex(ValueError, "immutable"):
                    run_suite(Path(tmp), KEY, mode="docker", image=image)


if __name__ == "__main__":
    unittest.main()
