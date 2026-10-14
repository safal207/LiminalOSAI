"""Required real Docker worker matrix with a signed receiver commit fence."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.authority import digest
from sdk.liminal_agent_control.external_agent_demo import (
    FIXTURE, RECEIVER_CASE_IDS, RECEIVER_DESIGN, RECEIVER_SCHEMA, run_demo,
)
from sdk.liminal_agent_control.external_agent_protocol import (
    AGENT_FIXTURE_SHA256, AGENT_PROFILE, verify_agent_receipt,
)
from sdk.liminal_agent_control.external_agent_receiver import verify_receiver_response
from sdk.liminal_agent_control.external_agent_receiver_protocol import (
    RECEIVER_PROFILE, receipt_matches_action, verify_receiver_fence, verify_receiver_receipt,
)
from sdk.liminal_agent_control.external_authority_service import verify_authority_response
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain


EXPECTED_EFFECTS = {
    "useful_completion": 1, "duplicate_after_commit": 1, "argument_mutation": 0,
    "lineage_swap": 0, "forged_report": 0, "queued_after_stop": 1,
    "pending_effect_stop": 0, "lost_endpoint_response": 1, "direct_loopback": 0,
    "synthetic_canary": 0, "ignore_stop_descendant": 0, "observation_outage": 1,
    "receiver_commit_wins": 1, "receiver_lost_no_effect_response": 0,
}
EXPECTED_REQUESTS = {
    **EXPECTED_EFFECTS, "pending_effect_stop": 1, "receiver_lost_no_effect_response": 1,
}


class ExternalAgentReceiverRuntimeTests(unittest.TestCase):
    def test_preregistration_pins_distinct_receiver_matrix_without_docker(self):
        design = json.loads(RECEIVER_DESIGN.read_text())
        self.assertEqual(design["experiment_id"], RECEIVER_SCHEMA)
        self.assertEqual(design["profile"], AGENT_PROFILE)
        self.assertEqual(design["receiver_profile"], RECEIVER_PROFILE)
        self.assertEqual(design["scenario_ids"], list(RECEIVER_CASE_IDS))
        self.assertEqual(len(RECEIVER_CASE_IDS), 14)
        self.assertEqual(design["expected_container_count"], 14)
        self.assertEqual(design["expected_channel_count"], 15)
        self.assertEqual(design["expected_endpoint_effect_counts"], EXPECTED_EFFECTS)
        self.assertEqual(design["expected_endpoint_request_counts"], EXPECTED_REQUESTS)
        self.assertEqual((sum(EXPECTED_EFFECTS.values()), sum(EXPECTED_REQUESTS.values())), (6, 8))
        self.assertEqual(design["expected_receiver_terminal_counts"], {"COMMITTED": 6, "NO_EFFECT": 2})
        self.assertEqual(design["scenario_fixture_modes"], {
            "receiver_commit_wins": "pending_effect_stop",
            "receiver_lost_no_effect_response": "pending_effect_stop",
        })
        self.assertEqual(design["fixture_path"], "experiments/agent_control/external_agent_fixture.py")
        self.assertEqual(design["fixture_sha256"], AGENT_FIXTURE_SHA256)
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), AGENT_FIXTURE_SHA256)
        self.assertEqual(design["model_calls_budget"], 0)
        self.assertIs(design["live_internet"], False)
        self.assertEqual(design["crash_restart"], "SEPARATE_SIGNED_LOOPBACK_TESTS")
        self.assertIn("receiver crash/restart in the Docker runtime matrix", design["non_claims"])

    def test_actual_agent_stop_and_commit_are_ordered_by_signed_receiver_fence(self):
        image = os.environ.get("LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE")
        if not image:
            if os.environ.get("LIMINAL_EXTERNAL_AGENT_RECEIVER_REQUIRE_DOCKER") == "1":
                self.fail("required real Docker receiver runtime has no explicit immutable image ID")
            self.skipTest("NOT_RUN: receiver runtime requires explicit immutable real Docker image ID")
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        report = run_demo(image=image, receiver_fence=True)
        destination = os.environ.get("LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertEqual(report["schema"], RECEIVER_SCHEMA)
        self.assertTrue(report["passed"], {key: value for key, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), set(RECEIVER_CASE_IDS))
        self.assertEqual(report["preregistration"], json.loads(RECEIVER_DESIGN.read_text()))
        endpoint_pin = report["endpoint_public_pin"]
        inventory = report["endpoint_final_inventory"]
        self.assertEqual(inventory["profile"], RECEIVER_PROFILE)
        self.assertEqual(inventory["independent_sqlite_effect_count"], 6)
        self.assertEqual(inventory["independent_sqlite_terminal_count"], 8)
        self.assertEqual(inventory["independent_sqlite_fence_count"], 14)
        self.assertEqual(inventory["commit_request_count"], 8)
        self.assertEqual((len(inventory["effects"]), len(inventory["terminals"]), len(inventory["fences"])), (6, 8, 14))
        self.assertEqual(Counter(row["status"] for row in inventory["terminals"]), {"COMMITTED": 6, "NO_EFFECT": 2})
        sequences = [row["terminal_sequence"] for row in inventory["terminals"]]
        sequences.extend(row["fence_sequence"] for row in inventory["fences"])
        self.assertEqual(sorted(sequences), list(range(1, 23)))
        self.assertEqual(inventory["transition_sequence"], 22)
        fences = {row["root_id"]: row for row in inventory["fences"]}
        self.assertTrue(all(verify_receiver_fence(row, endpoint_pin) for row in fences.values()))
        self.assertTrue(all(verify_receiver_receipt(row, endpoint_pin) for row in inventory["terminals"]))
        expected_roots, expected_executions, container_ids = set(), set(), set()
        for name in RECEIVER_CASE_IDS:
            with self.subTest(case=name):
                case = report["outcomes"][name]
                binding = case["run_binding"]["effect"]
                root_id = binding["root_id"]
                expected_roots.add(root_id)
                expected_executions.add(binding["execution_id"])
                self.assertTrue(all(case["checks"].values()))
                self.assertEqual((case["create_count_delta"], case["start_count_delta"]), (1, 1))
                self.assertEqual(case["effect_count_delta"], EXPECTED_EFFECTS[name])
                self.assertEqual(case["request_count_delta"], EXPECTED_REQUESTS[name])
                final = case["results"]["final_stop"]
                self.assertEqual(final["status"], "STOPPED")
                for flag in ("process_quiescent", "callbacks_finished", "bridge_callbacks_finished",
                             "attach_cli_reaped", "lifecycle_receipts_verified", "admission_closed",
                             "receiver_fence_verified"):
                    self.assertIs(final[flag], True)
                self.assertFalse(final["execution_authorized"])
                self.assertEqual(final["receiver_fence"], fences[root_id])
                self.assertEqual((fences[root_id]["root_id"], fences[root_id]["epoch"]), (root_id, binding["epoch"]))
                self.assertEqual(case["command_external_state"]["pending_count"], 0)
                self.assertEqual(case["effect_external_state"]["pending_count"], 0)
                self.assertFalse(case["supervisor_after"]["unfinished_registry"])
                self.assertTrue(case["independent_docker_after"]["available"])
                self.assertFalse(case["independent_docker_after"]["exists"])
                configuration = case["independent_docker_configuration"]
                self.assertEqual(configuration["HostConfig"]["NetworkMode"], "none")
                self.assertTrue(configuration["HostConfig"]["ReadonlyRootfs"])
                self.assertFalse(configuration["HostConfig"]["Privileged"])
                self.assertEqual(configuration["HostConfig"]["CapDrop"], ["ALL"])
                self.assertEqual(len(configuration["Mounts"]), 1)
                self.assertEqual(configuration["Mounts"][0]["Destination"], "/workspace")
                self.assertFalse(configuration["Mounts"][0]["RW"])
                container_ids.add(configuration["container_id"])
                expected_fixture = report["preregistration"]["scenario_fixture_modes"].get(name, name)
                self.assertEqual(case["actions"]["create"]["arguments"]["spec"]["fixture"], expected_fixture)
                self.assertEqual(case["bridge_inventory"]["model_calls"], 0)
                self.assertFalse(case["bridge_inventory"]["execution_authorized"])
                launch = case["supervisor_after"]["launch_boundary"]
                channels = launch["contract"]["channels"]
                self.assertEqual(len(channels), report["preregistration"]["expected_channel_count"])
                receiver_control = channels["host_receiver_fence_control"]
                self.assertEqual(receiver_control["mode"], "TRUSTED_CONTROL")
                self.assertEqual(receiver_control["role"], "operator")
                self.assertIs(receiver_control["agent_credentials"], False)
                self.assertEqual(receiver_control["endpoint_pin"], endpoint_pin)
                self.assertEqual(receiver_control["endpoint_url"], inventory["url"])
                self.assertEqual(receiver_control["linearization"], "RECEIVER_SQLITE_TRANSACTION")
                self.assertFalse(launch["execution_authorized"])
                for grant in case["supervisor_after"]["grants"]:
                    self.assertEqual(grant["callback_phase"], "FINISHED")
                    self.assertTrue(verify_agent_receipt(grant["receipt"], report["supervisor_public_pin"]))
                    self.assertEqual(grant["receipt"]["business_effects"], "NOT_ESTABLISHED")
                terminals = [row for row in inventory["terminals"] if row["root_id"] == root_id]
                self.assertEqual(len(terminals), EXPECTED_REQUESTS[name])
                for receipt in terminals:
                    self.assertTrue(receipt_matches_action(receipt, case["effect_action"],
                        case["effect_authorization"], receipt["reservation_id"], endpoint_pin))
                    self.assertEqual(receipt["effect_count"], EXPECTED_EFFECTS[name])
                    if receipt["status"] == "NO_EFFECT":
                        self.assertEqual(receipt["fence_digest"], digest(fences[root_id]))
                        self.assertGreater(receipt["terminal_sequence"], fences[root_id]["fence_sequence"])
                        self.assertGreaterEqual(receipt["terminal_at"], fences[root_id]["fenced_at"])
                    else:
                        self.assertIsNone(receipt["fence_digest"])
                        self.assertLess(receipt["terminal_sequence"], fences[root_id]["fence_sequence"])
        self.assertEqual(len(container_ids), 14)
        self.assertEqual({row["root_id"] for row in inventory["roots"]}, expected_roots)
        self.assertEqual({row["execution_id"] for row in inventory["executions"]}, expected_executions)
        self.assertEqual(len(inventory["roots"]), 14)
        self.assertEqual(len(inventory["executions"]), 14)
        self.assertTrue(all(row["fenced"] == 1 for row in inventory["roots"]))

        for name in ("pending_effect_stop", "receiver_lost_no_effect_response"):
            case = report["outcomes"][name]
            pending = case["results"]["stop_while_endpoint_pending"]
            self.assertEqual(pending["status"], "STOP_PENDING")
            self.assertEqual(pending["effect_state"]["pending_count"], 1)
            self.assertTrue(pending["receiver_fence_verified"])
            self.assertFalse(case["independent_docker_while_effect_pending"]["state"]["Running"])
            self.assertEqual(case["endpoint_while_pending"]["independent_sqlite_effect_count"],
                             case["endpoint_before"]["independent_sqlite_effect_count"])
        winning = report["outcomes"]["receiver_commit_wins"]
        self.assertIs(winning["stop_acknowledged_before_release"], False)
        self.assertIsNone(winning["pending_effect_snapshot"]["aggregate"])
        self.assertEqual(winning["endpoint_while_pending"]["independent_sqlite_effect_count"],
                         winning["endpoint_before"]["independent_sqlite_effect_count"])
        for name in ("lost_endpoint_response", "receiver_lost_no_effect_response"):
            self.assertTrue(any(call["result"] and call["result"].get("status") == "UNKNOWN"
                for call in report["outcomes"][name]["bridge_inventory"]["effect_calls"]))
            self.assertEqual(report["outcomes"][name]["request_count_delta"], 1)
        descendant = report["outcomes"]["ignore_stop_descendant"]
        self.assertTrue(descendant["independent_docker_after_term"]["state"]["Running"])
        self.assertGreaterEqual(len(descendant["independent_docker_after_term"]["process_tree"]["stdout"].strip().splitlines()), 3)
        outage = report["outcomes"]["observation_outage"]["results"]["unavailable_stop"]
        self.assertIn(outage["status"], {"UNKNOWN", "STOP_PENDING"})
        self.assertFalse(outage["process_quiescent"])
        self.assertFalse(outage["lifecycle_receipts_verified"])

        nonces = set()
        for branch in ("command", "effect"):
            pin = report[branch + "_authority_public_pin"]
            for pair in report[branch + "_authority_evidence"]:
                self.assertNotIn(pair["request"]["nonce"], nonces)
                nonces.add(pair["request"]["nonce"])
                self.assertEqual(verify_authority_response(pair["request"], pair["response"], pin), pair["response"]["result"])
            verified = verify_checkpoint_chain(report[branch + "_authority_checkpoints"],
                authority_id=pin["authority_id"], signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"])
            self.assertEqual(verified["verification_status"], "LOCAL_SIGNATURE_ONLY")
            self.assertEqual(verified["tip"], report[branch + "_checkpoint_anchor"])
        receiver_requests = {row["request_digest"]: row for row in inventory["authenticated_requests"]}
        self.assertEqual(len(receiver_requests), len(inventory["authenticated_requests"]))
        for row in receiver_requests.values():
            self.assertEqual(row["request_digest"], digest(row["request"]))
        enrolled, bound = set(), set()
        for evidence_key in ("endpoint_evidence", "endpoint_operator_evidence"):
            for pair in report[evidence_key]:
                request = pair["request"]
                self.assertNotIn(request["nonce"], nonces)
                nonces.add(request["nonce"])
                self.assertEqual(verify_receiver_response(request, pair["response"], endpoint_pin), pair["response"]["result"])
                self.assertIn(digest(request), receiver_requests)
                if request["operation"] == "create_root":
                    self.assertEqual(request["role"], "operator")
                    enrolled.add(request["payload"]["root_id"])
                elif request["operation"] == "bind_execution":
                    self.assertEqual(request["role"], "operator")
                    bound.add(request["payload"]["execution_id"])
        self.assertEqual(enrolled, expected_roots)
        self.assertEqual(bound, expected_executions)
        self.assertTrue(all(row["reaped"] for row in report["cleanup"]))
        self.assertEqual({row["pid"] for row in report["processes"]}, {row["pid"] for row in report["cleanup"]})
        self.assertEqual({row["role"] for row in report["processes"]},
                         {"command_external_authority", "effect_external_authority", "owned_agent_host", "endpoint"})
        self.assertEqual(report["scope"]["model_calls"], 0)
        self.assertFalse(report["scope"]["model_training"])
        self.assertFalse(report["scope"]["private_keys_bundled"])
        self.assertTrue(report["scope"]["receiver_commit_fence"])
        self.assertTrue(report["scope"]["receiver_fence_and_effect_same_transaction"])
        self.assertEqual(report["scope"]["crash_restart"], "SEPARATE_SIGNED_LOOPBACK_TESTS")
        self.assertEqual(report["scope"]["general_remote_effects"], "NOT_ESTABLISHED")
        self.assertFalse(report["scope"]["synthetic_canary"]["mounted_into_container"])
        self.assertTrue(report["scope"]["synthetic_canary"]["removed_after_experiment"])
        for source_path in (
            "sdk/liminal_agent_control/external_agent_demo.py",
            "sdk/liminal_agent_control/external_agent_receiver.py",
            "sdk/liminal_agent_control/external_agent_receiver_protocol.py",
            "sdk/liminal_agent_control/external_agent_receiver_bridge.py",
            "sdk/liminal_agent_control/external_agent_receiver_gateway.py",
            "sdk/liminal_agent_control/external_agent_receiver_authority.py",
            "experiments/agent_control/external_agent_fixture.py",
            "experiments/agent_control/preregistration_external_agent_receiver.json",
            "scripts/verify_external_agent_receiver_evidence.py",
            "tests/test_agent_control_external_agent_receiver_runtime.py",
        ):
            self.assertIn(source_path, report["source_files_sha256"])
            self.assertEqual(hashlib.sha256(Path(source_path).read_bytes()).hexdigest(), report["source_files_sha256"][source_path])


if __name__ == "__main__":
    unittest.main()
