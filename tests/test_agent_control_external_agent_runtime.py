"""Required actual Docker agent experiment; absent Docker is never simulated."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from sdk.liminal_agent_control.authority import ControlError
from sdk.liminal_agent_control.external_agent_demo import CASE_IDS, _cleanup_owned_containers, _owned_synthetic_canary, run_demo
from sdk.liminal_agent_control.external_agent_protocol import verify_agent_receipt
from sdk.liminal_agent_control.external_authority_service import verify_authority_response
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain


class ExternalAgentRuntimeTests(unittest.TestCase):
    def test_failure_cleanup_tracks_incomplete_case_and_preserves_unrelated_object(self):
        owned_id, unrelated_id = "a" * 64, "b" * 64
        objects = {owned_id, unrelated_id}
        calls = []

        class FakeDocker:
            def command(self, argv):
                calls.append(argv)
                if argv[0] == "inspect":
                    found = argv[1] in objects
                    return subprocess.CompletedProcess(argv, 0 if found else 1, b"[]",
                        b"" if found else b"Error: No such object: " + argv[1].encode())
                if argv[:2] == ["rm", "--force"]:
                    objects.remove(argv[2])
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                raise AssertionError(argv)

        # The owned ID is captured as soon as CREATE is confirmed, before the
        # case obtains any final outcome. No outcome object is needed to clean.
        result = _cleanup_owned_containers(FakeDocker(), {owned_id})
        self.assertTrue(result[0]["positively_absent"])
        self.assertEqual(objects, {unrelated_id})
        self.assertTrue(all(unrelated_id not in argv for argv in calls))

    def test_daemon_outage_during_failure_cleanup_is_not_absence(self):
        class UnavailableDocker:
            def command(self, argv):
                return subprocess.CompletedProcess(argv, 1, b"", b"Cannot connect to Docker daemon")
        with self.assertRaisesRegex(ControlError, "CLEANUP_UNCONFIRMED"):
            _cleanup_owned_containers(UnavailableDocker(), {"a" * 64})

    def test_cleanup_timeout_does_not_skip_later_exact_owned_ids(self):
        first, second = "a" * 64, "b" * 64
        observed = []

        class PartlyUnavailableDocker:
            def command(self, argv):
                observed.append(argv[1])
                if argv[1] == first:
                    raise subprocess.TimeoutExpired(argv, 3)
                return subprocess.CompletedProcess(argv, 1, b"", b"Error: No such object: " + argv[1].encode())

        with self.assertRaisesRegex(ControlError, "CLEANUP_UNCONFIRMED"):
            _cleanup_owned_containers(PartlyUnavailableDocker(), {first, second})
        self.assertEqual(observed, [first, second])

    def test_setup_exception_removes_only_exclusively_created_synthetic_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned-canary"
            with self.assertRaisesRegex(RuntimeError, "setup failure"):
                with _owned_synthetic_canary(path):
                    self.assertTrue(path.exists())
                    raise RuntimeError("setup failure")
            self.assertFalse(path.exists())
            path.write_bytes(b"unrelated fixture")
            with self.assertRaisesRegex(ControlError, "PATH_OCCUPIED"):
                with _owned_synthetic_canary(path):
                    self.fail("unrelated file was accepted")
            self.assertEqual(path.read_bytes(), b"unrelated fixture")

    def test_actual_agent_process_has_only_stdio_and_external_stop_bounds_effects(self):
        image = os.environ.get("LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE")
        if not image:
            if os.environ.get("LIMINAL_EXTERNAL_AGENT_REQUIRE_DOCKER") == "1":
                self.fail("required real Docker runtime has no explicit immutable image ID")
            self.skipTest("NOT_RUN: requires explicit immutable real Docker image ID")
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        report = run_demo(image=image)
        destination = os.environ.get("LIMINAL_EXTERNAL_AGENT_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertTrue(report["passed"], {key: value for key, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), set(CASE_IDS))
        expected = report["preregistration"]["expected_endpoint_effect_counts"]
        self.assertEqual(sum(expected.values()), 6)
        for name in CASE_IDS:
            with self.subTest(case=name):
                case = report["outcomes"][name]
                self.assertTrue(all(case["checks"].values()))
                self.assertEqual((case["create_count_delta"], case["start_count_delta"]), (1, 1))
                self.assertEqual(case["effect_count_delta"], expected[name])
                self.assertEqual(case["request_count_delta"], expected[name])
                final = case["results"]["final_stop"]
                self.assertEqual(final["status"], "STOPPED")
                for flag in ("process_quiescent", "callbacks_finished", "bridge_callbacks_finished",
                             "attach_cli_reaped", "lifecycle_receipts_verified", "admission_closed"):
                    self.assertIs(final[flag], True)
                self.assertFalse(final["execution_authorized"])
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
                self.assertEqual(case["bridge_inventory"]["model_calls"], 0)
                self.assertFalse(case["bridge_inventory"]["execution_authorized"])
                for grant in case["supervisor_after"]["grants"]:
                    self.assertEqual(grant["callback_phase"], "FINISHED")
                    self.assertTrue(verify_agent_receipt(grant["receipt"], report["supervisor_public_pin"]))
                    self.assertEqual(grant["receipt"]["business_effects"], "NOT_ESTABLISHED")
        pending = report["outcomes"]["pending_effect_stop"]
        self.assertEqual(pending["results"]["stop_while_endpoint_pending"]["status"], "STOP_PENDING")
        self.assertEqual(pending["results"]["stop_while_endpoint_pending"]["effect_state"]["pending_count"], 1)
        self.assertFalse(pending["independent_docker_while_effect_pending"]["state"]["Running"])
        self.assertEqual(pending["endpoint_while_pending"]["independent_sqlite_effect_count"],
                         pending["endpoint_before"]["independent_sqlite_effect_count"])
        loss = report["outcomes"]["lost_endpoint_response"]
        self.assertTrue(any(call["result"] and call["result"]["status"] == "UNKNOWN"
                            for call in loss["bridge_inventory"]["effect_calls"]))
        self.assertEqual(loss["request_count_delta"], 1)
        descendant = report["outcomes"]["ignore_stop_descendant"]
        self.assertTrue(descendant["independent_docker_after_term"]["state"]["Running"])
        self.assertGreaterEqual(len(descendant["independent_docker_after_term"]["process_tree"]["stdout"].strip().splitlines()), 3)
        self.assertGreaterEqual(len(descendant["independent_docker_tree"]["process_tree"]["stdout"].strip().splitlines()), 3)
        outage = report["outcomes"]["observation_outage"]
        self.assertIn(outage["results"]["unavailable_stop"]["status"], {"UNKNOWN", "STOP_PENDING"})
        self.assertFalse(outage["results"]["unavailable_stop"]["process_quiescent"])
        self.assertFalse(outage["results"]["unavailable_stop"]["lifecycle_receipts_verified"])
        all_nonces = set()
        for branch in ("command", "effect"):
            pin = report[branch + "_authority_public_pin"]
            for pair in report[branch + "_authority_evidence"]:
                self.assertNotIn(pair["request"]["nonce"], all_nonces)
                all_nonces.add(pair["request"]["nonce"])
                self.assertEqual(verify_authority_response(pair["request"], pair["response"], pin), pair["response"]["result"])
            result = verify_checkpoint_chain(report[branch + "_authority_checkpoints"],
                authority_id=pin["authority_id"], signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"])
            self.assertEqual(result["verification_status"], "LOCAL_SIGNATURE_ONLY")
            self.assertEqual(result["tip"], report[branch + "_checkpoint_anchor"])
        self.assertEqual(report["endpoint_final_inventory"]["independent_sqlite_effect_count"], 6)
        self.assertEqual(report["endpoint_final_inventory"]["commit_request_count"], 6)
        self.assertTrue(all(row["reaped"] for row in report["cleanup"]))
        self.assertEqual({row["pid"] for row in report["processes"]}, {row["pid"] for row in report["cleanup"]})
        self.assertEqual({row["role"] for row in report["processes"]},
                         {"command_external_authority", "effect_external_authority", "owned_agent_host", "endpoint"})
        self.assertEqual(report["scope"]["model_calls"], 0)
        self.assertFalse(report["scope"]["model_training"])
        self.assertFalse(report["scope"]["private_keys_bundled"])
        self.assertFalse(report["scope"]["synthetic_canary"]["mounted_into_container"])
        self.assertTrue(report["scope"]["synthetic_canary"]["removed_after_experiment"])
        for path in ("sdk/liminal_agent_control/external_agent_demo.py",
            "sdk/liminal_agent_control/external_agent_bridge.py", "sdk/liminal_agent_control/external_agent_coordinator.py",
            "sdk/liminal_agent_control/external_agent_supervisor.py", "sdk/liminal_agent_control/external_agent_protocol.py",
            "experiments/agent_control/external_agent_fixture.py", "experiments/agent_control/preregistration_external_agent.json",
            "tests/test_agent_control_external_agent_runtime.py"):
            self.assertIn(path, report["source_files_sha256"])
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), report["source_files_sha256"][path])


if __name__ == "__main__":
    unittest.main()
