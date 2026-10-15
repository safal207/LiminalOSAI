"""Required real Docker probe for the separately selected observed G03 profile."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.external_agent_demo import FIXTURE
from sdk.liminal_agent_control.external_agent_orientation_demo import CASE_IDS, DESIGN, SCHEMA, run_demo
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256
from scripts.verify_external_agent_orientation_evidence import verify_report

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EFFECTS = {name: 2 if name == "verified_feedback_chain" else 0 for name in CASE_IDS}


class ExternalAgentOrientationRuntimeTests(unittest.TestCase):
    def test_preregistration_pins_separate_four_case_observed_profile(self):
        design = json.loads(DESIGN.read_text())
        self.assertEqual(design["experiment_id"], SCHEMA)
        self.assertEqual(design["scenario_ids"], list(CASE_IDS))
        self.assertEqual(CASE_IDS, ("verified_feedback_chain", "tampered_or_stale_context",
                                    "forged_observation", "stop_after_begin"))
        self.assertEqual((design["expected_container_count"], design["expected_channel_count"]), (4, 15))
        self.assertEqual(design["expected_endpoint_request_counts"], EXPECTED_EFFECTS)
        self.assertEqual(design["expected_endpoint_effect_counts"], EXPECTED_EFFECTS)
        self.assertEqual(design["expected_orientation_revisions"], EXPECTED_EFFECTS)
        self.assertEqual(design["expected_external_pending_counts"],
                         {name: int(name == "stop_after_begin") for name in CASE_IDS})
        self.assertEqual(design["expected_receiver_terminal_counts"], {"COMMITTED": 2, "NO_EFFECT": 0})
        self.assertEqual(design["fixture_sha256"], AGENT_FIXTURE_SHA256)
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), AGENT_FIXTURE_SHA256)
        self.assertEqual(design["model_calls_budget"], 0)
        self.assertIs(design["live_internet"], False)
        self.assertIn("universal escape prevention", design["non_claims"])
        self.assertIn("host", design["verified_feedback_chain"].lower())

    def test_actual_owned_docker_feedback_and_admission_boundaries(self):
        image = os.environ.get("LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE")
        if not image:
            if os.environ.get("LIMINAL_EXTERNAL_AGENT_ORIENTATION_REQUIRE_DOCKER") == "1":
                self.fail("required observed G03 runtime has no explicit immutable real Docker image ID")
            self.skipTest("NOT_RUN: observed G03 runtime requires explicit immutable real Docker image ID")
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        report = run_demo(image=image)
        destination = os.environ.get("LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        # Persist raw evidence even if an independent reconstruction rejects it.
        # Producer PASS and fixture claims alone cannot satisfy this test.
        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["preregistration"], json.loads(DESIGN.read_text()))
        self.assertEqual(set(report["outcomes"]), set(CASE_IDS))
        verify_report(report, repo_root=ROOT,
                      expected_source_sha=os.environ.get("EXPECTED_SOURCE_SHA"), expected_image=image)


if __name__ == "__main__":
    unittest.main()
