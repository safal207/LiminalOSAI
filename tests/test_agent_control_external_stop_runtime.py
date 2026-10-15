"""Actual receiver/controller processes; mocks cannot satisfy this experiment."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.external_authority_service import verify_authority_response
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain
from sdk.liminal_agent_control.external_stop_demo import CASE_IDS, run_demo


class ExternalStopRuntimeTests(unittest.TestCase):
    def test_external_stop_and_consumption_survive_real_local_database_restore(self):
        report = run_demo()
        destination = os.environ.get("LIMINAL_EXTERNAL_STOP_EVIDENCE")
        if destination:
            target = Path(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertTrue(report["passed"], {name: value for name, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), set(CASE_IDS))
        cases = report["outcomes"]
        self.assertEqual((cases["positive"]["accepted_count"], cases["positive"]["effect_count"]), (1, 1))
        self.assertEqual(cases["positive"]["external_query"]["receipt"], cases["positive"]["receipt"])
        for name in ("stop_restore", "terminal_restore", "pending_duplicate", "authority_restart", "split_api_denied"):
            with self.subTest(case=name):
                self.assertEqual((cases[name]["accepted_count"], cases[name]["effect_count"]), (0, 0))
                self.assertEqual(cases[name]["records"], [])
        self.assertEqual(cases["stop_restore"]["restored_local_state"]["state"], "ACTIVE")
        self.assertEqual(cases["stop_restore"]["external_state"]["state"], "STOPPED")
        self.assertEqual(cases["terminal_restore"]["external_query"]["receipt"], cases["terminal_restore"]["committed_receipt"])
        self.assertEqual(cases["terminal_restore"]["retry_receipt"]["status"], "UNKNOWN")
        self.assertEqual(cases["pending_duplicate"]["stop_response"]["status"], "STOP_PENDING")
        self.assertEqual(cases["pending_duplicate"]["stop_response"]["pending_count"], 1)
        self.assertEqual((cases["authority_outage"]["outage_accepted_count"], cases["authority_outage"]["outage_effect_count"]), (0, 0))
        self.assertEqual((cases["authority_outage"]["accepted_count"], cases["authority_outage"]["effect_count"]), (1, 1))
        self.assertEqual(cases["authority_outage"]["external_query"]["receipt"], cases["authority_outage"]["fresh_receipt"])
        self.assertEqual((cases["unsafe_local_restore"]["accepted_count"], cases["unsafe_local_restore"]["effect_count"]), (1, 1))

        pin = report["authority_public_pin"]
        nonces = set()
        for pair in report["authority_evidence"]:
            request, response = pair["request"], pair["response"]
            self.assertEqual(set(request), {"schema", "role", "operation", "nonce", "payload"})
            self.assertNotIn(request["nonce"], nonces)
            nonces.add(request["nonce"])
            self.assertEqual(verify_authority_response(request, response, pin), response["result"])
        verified = verify_checkpoint_chain(report["authority_checkpoints"], authority_id=pin["authority_id"],
            signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"],
            anchor=report["checkpoint_anchor"])
        self.assertFalse(verified["execution_authorized"])
        self.assertEqual(verified["tip"], report["checkpoint_verification"]["tip"])
        self.assertEqual(report["scope"]["independent_latest_anchor"], "NOT_ESTABLISHED")
        self.assertFalse(report["scope"]["private_keys_bundled"])
        self.assertFalse(report["scope"]["receiver_receipts_publicly_verifiable"])
        self.assertTrue(all(item["reaped"] for item in report["cleanup"]))
        self.assertEqual({item["pid"] for item in report["processes"]}, {item["pid"] for item in report["cleanup"]})
        self.assertIn("sdk/liminal_agent_control/external_authority.py", report["source_files_sha256"])
        self.assertIn("sdk/liminal_agent_control/external_authority_service.py", report["source_files_sha256"])
        self.assertIn("sdk/liminal_agent_control/external_stop_demo.py", report["source_files_sha256"])
        self.assertIn("tests/test_agent_control_external_stop_runtime.py", report["source_files_sha256"])
        self.assertIn("experiments/agent_control/preregistration_external_stop.json", report["source_files_sha256"])


if __name__ == "__main__":
    unittest.main()
