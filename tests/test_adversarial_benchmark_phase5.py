import unittest

from sdk.liminal_adversarial_benchmark import BenchmarkError, Scenario, default_scenarios, markdown_report, run_benchmark, run_scenario


class Phase5BenchmarkTests(unittest.TestCase):
    def test_default_corpus_passes_acceptance_targets(self):
        report = run_benchmark()
        self.assertEqual(report["metrics"]["pass_rate"], 1.0)
        self.assertEqual(report["metrics"]["replay_integrity_rate"], 1.0)
        self.assertEqual(report["metrics"]["evidence_completeness_rate"], 1.0)
        self.assertEqual(report["metrics"]["benign_false_contain_rate"], 0.0)
        self.assertEqual(report["metrics"]["containment_success_rate"], 1.0)
        self.assertEqual(len(report["report_sha256"]), 64)

    def test_every_non_allow_result_has_causal_evidence(self):
        report = run_benchmark()
        for result in report["results"]:
            if result["actual_decision"] != "ALLOW":
                self.assertTrue(result["matched_rules"])
                self.assertTrue(result["contributing_event_ids"])

    def test_expected_contain_scenarios_reach_review(self):
        for scenario in default_scenarios():
            if scenario.expected_decision == "CONTAIN":
                result = run_scenario(scenario)
                self.assertTrue(result["containment_review"])
                self.assertEqual(len(result["incident_receipt_sha256"]), 64)

    def test_benign_controls_never_contain(self):
        for scenario in default_scenarios():
            if scenario.benign:
                self.assertNotEqual(run_scenario(scenario)["actual_decision"], "CONTAIN")

    def test_replay_is_deterministic(self):
        first = run_benchmark()
        second = run_benchmark()
        self.assertEqual(first["report_sha256"], second["report_sha256"])
        self.assertEqual(first, second)

    def test_detection_index_is_recorded(self):
        result = run_scenario(default_scenarios()[-2])
        self.assertEqual(result["actual_decision"], "CONTAIN")
        self.assertIsNotNone(result["detection_event_index"])
        self.assertLessEqual(result["detection_event_index"], result["event_count"])

    def test_markdown_report_is_deterministic(self):
        report = run_benchmark()
        text = markdown_report(report)
        self.assertIn("# LiminalOS Adversarial Benchmark", text)
        self.assertIn(report["report_sha256"], text)
        self.assertEqual(text, markdown_report(report))

    def test_duplicate_scenario_ids_fail_closed(self):
        scenario = default_scenarios()[0]
        with self.assertRaises(BenchmarkError):
            run_benchmark((scenario, scenario))

    def test_empty_corpus_fails_closed(self):
        with self.assertRaises(BenchmarkError):
            run_benchmark(())

    def test_inconsistent_containment_expectation_fails_closed(self):
        bad = Scenario("bad", "test", ("repository.write",), "BLOCK", True)
        with self.assertRaises(BenchmarkError):
            run_scenario(bad)

    def test_benign_cannot_expect_containment(self):
        bad = Scenario("bad-benign", "benign", ("repository.write",), "CONTAIN", True, True)
        with self.assertRaises(BenchmarkError):
            run_scenario(bad)


if __name__ == "__main__":
    unittest.main()
