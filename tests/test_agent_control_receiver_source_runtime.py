"""Real-Docker receiver issuer/signature tests; mocks do not satisfy this suite."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import unittest

from sdk.liminal_agent_control.receiver_source_demo import NEGATIVE_CASES, run_demo


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


@unittest.skipUnless(os.environ.get("LIMINAL_OBSERVER_DOCKER_IMAGE"),
    "set pinned Docker image for real signed receiver-source observers")
class ReceiverSourceDockerTests(unittest.TestCase):
    def test_real_receiver_source_positive_and_collector_forgeries_have_bounded_effects(self):
        image = os.environ["LIMINAL_OBSERVER_DOCKER_IMAGE"]
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        report = run_demo(image)
        destination = os.environ.get("LIMINAL_RECEIVER_SOURCE_EVIDENCE")
        if destination:
            target = Path(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        self.assertTrue(report["passed"], {name: value for name, value in report["checks"].items() if not value})
        self.assertEqual(set(report["outcomes"]), {"positive", *NEGATIVE_CASES})
        self.assertEqual(report["outcomes"]["positive"]["record_count"], 1)
        self.assertEqual(report["outcomes"]["positive"]["candidate_effect_count"], 1)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        for name, case in report["outcomes"].items():
            with self.subTest(signature_case=name):
                enrollment = {item["observer_id"]: item for item in case["observer_enrollments"]}
                self.assertEqual(set(enrollment), {role + "-observer" for role in ("reality", "continuity", "projection")})
                self.assertEqual(len({item["public_key"] for item in enrollment.values()}), 3)
                for witness in [case["witness"], *case["other_witnesses"]]:
                    envelope = witness["envelope"]
                    self.assertIsNotNone(envelope)
                    request = witness["request"]
                    self.assertEqual(_canonical(envelope["request"]), _canonical(request))
                    self.assertEqual(envelope["evidence_digest"], hashlib.sha256(_canonical(witness["packet"])).hexdigest())
                    key = enrollment[request["observer_id"]]
                    self.assertEqual(key["key_id"], request["key_id"])
                    self.assertEqual(key["role"], request["role"])
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key"])).verify(
                        bytes.fromhex(envelope["signature"]), b"liminal-observer-attestation-v1\x00"
                        + _canonical({field: value for field, value in envelope.items() if field != "signature"}))
                command = case["container"]["command"]
                self.assertEqual(command.count("--source-issuer"), 1)
                self.assertEqual(json.loads(command[command.index("--source-issuer") + 1]), case["receiver_pin"])
                self.assertEqual(case["container"]["network_mode"], "none")
                mounts = [item for item in case["container"]["mounts"] if item["Type"] == "bind"]
                self.assertEqual({item["Destination"] for item in mounts}, {"/sdk", "/evidence"})
                self.assertEqual(len(mounts), 2)
                self.assertTrue(all(item["RW"] is False for item in mounts))
        for name in NEGATIVE_CASES:
            with self.subTest(case=name):
                case = report["outcomes"][name]
                self.assertEqual(case["result"]["status"], "DENIED", case)
                self.assertEqual(case["candidate_effect_count"], 0, case)
                self.assertEqual(case["candidate_record_count"], 0, case)
                self.assertEqual(case["record_count"], 1 if name == "tamper_existing_record" else 0)
                self.assertNotEqual(case["issuer_child_pid"], case["controller_pid"])
                self.assertTrue(case["container"]["receiver_public_pin_in_fixed_command"])
                self.assertTrue(case["container"]["only_public_evidence_and_sdk_mounted"])
        forged = report["outcomes"]["forged_host_verified"]["witness"]
        self.assertTrue(forged["packet"]["payload"]["receiver_snapshot_verified_by_host"])
        self.assertEqual(forged["binding"], {"status": "REJECTED", "reason": "RECEIVER_SOURCE_REQUIRED"})
        self.assertEqual(forged["envelope"]["verdict"], "UNKNOWN")
        self.assertEqual(report["outcomes"]["missing_signature"]["witness"]["binding"],
                         {"status": "REJECTED", "reason": "RECEIVER_SOURCE_MALFORMED"})
        self.assertEqual(report["outcomes"]["attacker_key"]["witness"]["binding"],
                         {"status": "REJECTED", "reason": "RECEIVER_SOURCE_SIGNATURE_INVALID"})
        self.assertEqual(report["outcomes"]["old_request_nonce"]["witness"]["binding"],
                         {"status": "REJECTED", "reason": "RECEIVER_SOURCE_BINDING_MISMATCH"})
        expiry = report["outcomes"]["expired_export"]
        self.assertEqual(expiry["witness"]["envelope"]["verdict"], "SUPPORT")
        self.assertTrue(expiry["challenge_still_valid_at_effect_attempt"])
        self.assertEqual(expiry["freshness_check"], {"status": "REJECTED", "reason": "RECEIVER_SOURCE_STALE"})
        self.assertTrue(all(item["removed"] is True for item in report["observer_cleanup"]))
        self.assertTrue(all(item["reaped"] is True for item in report["issuer_cleanup"]))
        self.assertIn("sdk/liminal_agent_control/receiver_source.py", report["source_files_sha256"])
        self.assertIn("tests/test_agent_control_receiver_source_runtime.py", report["source_files_sha256"])


if __name__ == "__main__":
    unittest.main()
