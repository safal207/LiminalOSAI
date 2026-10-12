"""Real authority/gateway/endpoint HTTP processes; mocks cannot satisfy this test."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.external_authority_service import verify_authority_response
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain
from sdk.liminal_agent_control.external_network_demo import CASE_IDS, run_demo
from sdk.liminal_agent_control.external_network_protocol import verify_endpoint_receipt


class ExternalNetworkRuntimeTests(unittest.TestCase):
    def test_owned_network_stop_survives_real_gateway_restore_and_unknown_outcomes(self):
        report = run_demo()
        destination = os.environ.get("LIMINAL_EXTERNAL_NETWORK_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertTrue(report["passed"], {name: value for name, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), set(CASE_IDS))
        expected_counts = {
            "network_positive": (1, 1), "network_binding_swap": (0, 0),
            "network_stop_before_dispatch": (0, 0), "network_pending_dispatch_stop": (1, 1),
            "network_lost_begin_response": (0, 0), "network_lost_transport_response": (1, 1),
            "network_lost_finish_response": (1, 1), "network_restore_consumed_state": (1, 1),
            "network_restore_stopped_state": (0, 0), "network_authority_restart_outage": (2, 2),
            "network_ambiguous_endpoint": (1, 1), "network_cross_profile_receipt": (0, 0)}
        for name, counts in expected_counts.items():
            with self.subTest(case=name):
                case = report["outcomes"][name]
                self.assertEqual((case["request_count_delta"], case["effect_count_delta"]), counts)
                self.assertEqual(case["endpoint_after"]["independent_sqlite_effect_count"], len(case["endpoint_after"]["effects"]))

        cases = report["outcomes"]
        for name in ("network_lost_begin_response", "network_ambiguous_endpoint", "network_cross_profile_receipt"):
            self.assertEqual(cases[name]["stop_response"]["status"], "STOP_PENDING")
            self.assertEqual(cases[name]["stop_response"]["pending_count"], 1)
        self.assertEqual(cases["network_pending_dispatch_stop"]["stop_response"]["status"], "STOP_PENDING")
        self.assertEqual(cases["network_pending_dispatch_stop"]["final_stop_state"]["state"], "STOPPED")
        self.assertEqual(cases["network_lost_transport_response"]["results"]["execute"]["status"], "UNKNOWN")
        self.assertIsNone(cases["network_lost_transport_response"]["results"]["execute"]["effect_count"])
        self.assertEqual(cases["network_lost_transport_response"]["results"]["reconcile"]["status"], "COMMITTED")
        self.assertEqual(cases["network_ambiguous_endpoint"]["results"]["reconcile"]["status"], "UNKNOWN")
        self.assertIsNone(cases["network_ambiguous_endpoint"]["results"]["reconcile"]["effect_count"])
        for name in ("network_restore_consumed_state", "network_restore_stopped_state"):
            self.assertTrue(cases[name]["restore"]["gateway_stopped_during_copy"])
            self.assertTrue(cases[name]["restore"]["authority_database_not_restored"])
            self.assertTrue(cases[name]["restore"]["endpoint_database_not_restored"])

        pin = report["authority_public_pin"]
        nonces = set()
        for pair in report["authority_evidence"]:
            request, response = pair["request"], pair["response"]
            self.assertEqual(set(request), {"schema", "role", "operation", "nonce", "payload"})
            self.assertNotIn(request["nonce"], nonces)
            nonces.add(request["nonce"])
            self.assertEqual(verify_authority_response(request, response, pin), response["result"])
        for receipt in report["endpoint_final_inventory"]["receipts"]:
            self.assertTrue(verify_endpoint_receipt(receipt, report["endpoint_public_pin"]))
        verified = verify_checkpoint_chain(report["authority_checkpoints"], authority_id=pin["authority_id"],
            signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"])
        self.assertEqual(verified["verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertFalse(verified["execution_authorized"])
        self.assertEqual(verified["tip"], report["checkpoint_verification"]["tip"])
        self.assertFalse(report["scope"]["private_keys_bundled"])
        self.assertEqual(report["scope"]["full_worker_socket_mediation"], "NOT_ESTABLISHED")
        self.assertEqual(report["scope"]["sender_quiescence"], "NOT_ESTABLISHED")
        self.assertTrue(all(item["reaped"] for item in report["cleanup"]))
        self.assertEqual({item["pid"] for item in report["processes"]}, {item["pid"] for item in report["cleanup"]})
        self.assertTrue({"external_authority", "gateway", "endpoint"}.issubset({item["role"] for item in report["processes"]}))
        for path in ("sdk/liminal_agent_control/external_network_protocol.py",
            "sdk/liminal_agent_control/external_network_authority.py",
            "sdk/liminal_agent_control/external_network_endpoint.py",
            "sdk/liminal_agent_control/external_network_gateway.py",
            "sdk/liminal_agent_control/external_network_demo.py",
            "tests/test_agent_control_external_network_runtime.py",
            "experiments/agent_control/preregistration_external_network.json"):
            self.assertIn(path, report["source_files_sha256"])


if __name__ == "__main__":
    unittest.main()
