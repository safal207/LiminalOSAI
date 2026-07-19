from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "liminal_evidence_advisor.py"
SPEC = importlib.util.spec_from_file_location("liminal_evidence_advisor", MODULE_PATH)
assert SPEC and SPEC.loader
advisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(advisor)


class LiminalEvidenceAdvisorTests(unittest.TestCase):
    def _run(self, evidence: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_path = root / "result.json"
            runtime_path = root / "runtime.log"
            output_dir = root / "out"
            evidence_path.write_text(json.dumps(evidence))
            runtime_path.write_text("pipeline: awareness → introspect → harmony → gate\n")
            packet = advisor.build_packet(evidence_path, runtime_path, output_dir)
            self.assertTrue((output_dir / "liminalos-advice.json").is_file())
            self.assertTrue((output_dir / "liminalos-causal-graph.md").is_file())
            self.assertTrue((output_dir / "liminalos-next-experiment.json").is_file())
            return packet

    def test_no_defect_observed_is_advisory_only(self) -> None:
        packet = self._run(
            {
                "dns_baseline_addresses": ["1.1.1.1"],
                "dns_garden_addresses": ["1.1.1.1"],
                "garden_events": [
                    "RUN_CREATED",
                    "SEED_LOADED",
                    "NS_CREATED",
                    "MOUNT_DONE",
                    "CAPS_DROPPED",
                    "SECCOMP_ENABLED",
                    "PROCESS_START",
                    "PROCESS_EXIT",
                ],
                "probe_present": True,
                "safe_readonly_probe": True,
                "live_garden_probe_confirmed": True,
                "probe_summary": {"confirmed_defect": False},
            }
        )
        self.assertEqual(packet["classification"], "NO_DEFECT_OBSERVED")
        self.assertTrue(packet["evidence_ingested"])
        self.assertTrue(packet["liminal_runtime"]["pipeline_complete"])
        self.assertFalse(packet["authority"]["product_verdict_override"])
        self.assertFalse(packet["authority"]["merge"])
        self.assertEqual(packet["product_verdict_source"], "normalized_evidence_not_liminalos")

    def test_missing_probe_blocks_product_conclusion(self) -> None:
        packet = self._run(
            {
                "dns_baseline_addresses": ["1.1.1.1"],
                "dns_garden_addresses": [],
                "garden_events": ["RUN_CREATED", "SEED_LOADED"],
                "probe_present": False,
                "safe_readonly_probe": False,
                "live_garden_probe_confirmed": False,
                "probe_summary": None,
            }
        )
        self.assertEqual(packet["classification"], "RUNTIME_OR_EVIDENCE_GAP")
        self.assertIn("probe_result", packet["next_experiment"]["missing"])
        self.assertFalse(packet["authority"]["execution"])
        self.assertFalse(packet["authority"]["external_submission"])

    def test_positive_signal_still_requires_lotus(self) -> None:
        packet = self._run(
            {
                "dns_baseline_addresses": ["1.1.1.1"],
                "dns_garden_addresses": ["1.1.1.1"],
                "garden_events": [
                    "RUN_CREATED",
                    "SEED_LOADED",
                    "NS_CREATED",
                    "MOUNT_DONE",
                    "CAPS_DROPPED",
                    "SECCOMP_ENABLED",
                    "PROCESS_START",
                    "PROCESS_EXIT",
                ],
                "probe_present": True,
                "safe_readonly_probe": True,
                "live_garden_probe_confirmed": True,
                "probe_summary": {"confirmed_defect": True},
            }
        )
        self.assertEqual(packet["classification"], "PRODUCT_SIGNAL_REQUIRES_LOTUS_ADJUDICATION")
        self.assertFalse(packet["authority"]["approval"])
        self.assertFalse(packet["authority"]["product_verdict_override"])


if __name__ == "__main__":
    unittest.main()
