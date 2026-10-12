"""Required real Docker lifecycle matrix; a missing backend is never simulated."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.external_authority_service import verify_authority_response
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain
from sdk.liminal_agent_control.external_command_demo import CASE_IDS, run_demo
from sdk.liminal_agent_control.external_command_protocol import verify_command_receipt


class ExternalCommandRuntimeTests(unittest.TestCase):
    def test_external_stop_accounts_actual_create_start_callbacks_and_owned_tree(self):
        image = os.environ.get("LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE")
        if not image:
            if os.environ.get("LIMINAL_EXTERNAL_COMMAND_REQUIRE_DOCKER") == "1":
                self.fail("required real Docker runtime has no explicit immutable image ID")
            self.skipTest("NOT_RUN: requires explicit immutable real Docker image ID")
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        report = run_demo(image=image)
        destination = os.environ.get("LIMINAL_EXTERNAL_COMMAND_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertTrue(report["passed"], {key: value for key, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), set(CASE_IDS))
        expected = {"command_positive": (1, 1), "command_binding_swap": (0, 0),
            "command_stop_before_create": (0, 0), "command_stop_between_create_start": (1, 0),
            "command_pending_launch_stop": (1, 0), "command_lost_launch_response": (1, 1),
            "command_restore_local_state": (1, 1), "command_descendant_cleanup": (1, 1),
            "command_observation_unavailable": (1, 1), "command_authority_restart_outage": (1, 1)}
        for name, counts in expected.items():
            with self.subTest(case=name):
                case = report["outcomes"][name]
                self.assertEqual((case["create_count_delta"], case["start_count_delta"]), counts)
                self.assertTrue(all(case["checks"].values()))
                self.assertEqual(case["external_state"]["pending_count"], 0)
        cases = report["outcomes"]
        self.assertEqual(cases["command_positive"]["positive_stdout"], "LIMINAL_COMMAND_POSITIVE\n")
        self.assertEqual(cases["command_pending_launch_stop"]["stop_response"]["status"], "STOP_PENDING")
        self.assertEqual(cases["command_pending_launch_stop"]["final_stop_state"]["state"], "STOPPED")
        loss = cases["command_lost_launch_response"]
        self.assertEqual(loss["results"]["execute_create"]["status"], "UNKNOWN")
        self.assertTrue(loss["dispatcher_crash"]["reaped"])
        self.assertNotEqual(loss["dispatcher_crash"]["pid"], loss["dispatcher_restarted_pid"])
        restored = cases["command_restore_local_state"]["restore"]
        for field in ("dispatcher_stopped_during_restore", "authority_database_not_restored",
                      "supervisor_database_not_restored", "registry_database_not_restored"):
            self.assertTrue(restored[field])
        self.assertFalse(restored["cache_after"]["rows"])
        descendants = cases["command_descendant_cleanup"]
        self.assertGreaterEqual(len(descendants["process_tree"]["processes"]), 2)
        self.assertTrue(descendants["process_tree_after_term"]["running"])
        self.assertTrue(descendants["unrelated_sentinel_after"]["running"])
        unknown = cases["command_observation_unavailable"]
        self.assertEqual(unknown["results"]["unavailable_cleanup"]["status"], "UNKNOWN")
        self.assertFalse(unknown["results"]["unavailable_cleanup"]["process_quiescent"])
        self.assertEqual(unknown["stop_response"]["status"], "STOP_PENDING")
        self.assertEqual(unknown["final_stop_state"]["state"], "STOPPED")
        nonces = set()
        for pair in report["authority_evidence"]:
            self.assertNotIn(pair["request"]["nonce"], nonces)
            nonces.add(pair["request"]["nonce"])
            self.assertEqual(verify_authority_response(pair["request"], pair["response"], report["authority_public_pin"]),
                pair["response"]["result"])
        final = report["supervisor_final_inventory"]
        self.assertFalse(final["unfinished_registry"])
        self.assertEqual(sum(row["operation"] == "create" for row in final["docker_calls"]), 8)
        self.assertEqual(sum(row["operation"] == "start" for row in final["docker_calls"]), 6)
        for grant in final["grants"]:
            if grant["reservation_id"] is not None:
                self.assertEqual(grant["callback_phase"], "FINISHED")
                self.assertTrue(verify_command_receipt(grant["receipt"], report["supervisor_public_pin"]))
                self.assertEqual(grant["receipt"]["business_effects"], "NOT_ESTABLISHED")
        pin = report["authority_public_pin"]
        verified = verify_checkpoint_chain(report["authority_checkpoints"], authority_id=pin["authority_id"],
            signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"])
        self.assertEqual(verified["verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertFalse(verified["execution_authorized"])
        self.assertEqual(verified["tip"], report["checkpoint_anchor"])
        self.assertEqual(report["scope"]["supervisor_registry_rollback"], "NOT_SUPPORTED")
        self.assertFalse(report["scope"]["private_keys_bundled"])
        self.assertTrue(all(row["reaped"] for row in report["cleanup"]))
        self.assertEqual({row["pid"] for row in report["processes"]}, {row["pid"] for row in report["cleanup"]})
        self.assertEqual({"external_authority", "owned_workload_supervisor", "proposal_dispatcher"},
            {row["role"] for row in report["processes"]})
        for path in ("sdk/liminal_agent_control/external_command_protocol.py",
            "sdk/liminal_agent_control/external_command_authority.py", "sdk/liminal_agent_control/external_command_supervisor.py",
            "sdk/liminal_agent_control/external_command_demo.py", "experiments/agent_control/external_command_fixture.py",
            "experiments/agent_control/preregistration_external_command.json", "tests/test_agent_control_external_command_runtime.py"):
            self.assertIn(path, report["source_files_sha256"])
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), report["source_files_sha256"][path])


if __name__ == "__main__":
    unittest.main()
