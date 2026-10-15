"""Public offline verification rejects altered real experiment evidence."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

from sdk.liminal_agent_control.external_stop_demo import run_demo

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("external_stop_independent_verifier",
    ROOT / "scripts/verify_external_stop_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ExternalStopEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One actual multiprocess capture is shared across tamper regressions.
        # No secret HMAC/signing keys are passed to the independent verifier.
        cls.report = run_demo()

    def verify(self, report=None, **arguments):
        return verifier.verify_report(self.report if report is None else report, repo_root=ROOT, **arguments)

    def reject(self, mutate, message=None):
        report = deepcopy(self.report)
        mutate(report)
        with self.assertRaises(verifier.EvidenceError) as caught:
            self.verify(report)
        if message:
            self.assertIn(message, str(caught.exception))

    def test_actual_public_evidence_passes_without_private_keys_or_authority(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["pin_scope"], "report_fixture")
        self.assertEqual(result["checkpoint_verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertEqual(result["cases_verified"], list(verifier.CASE_IDS))
        self.assertEqual(result["checkpoint_signatures_verified"], len(self.report["authority_checkpoints"]))
        self.assertEqual(result["authority_response_signatures_verified"], len(self.report["authority_evidence"]))

    def test_caller_owned_pin_and_latest_anchor_are_explicit(self):
        result = self.verify(expected_authority_pin=deepcopy(self.report["authority_public_pin"]),
            trusted_latest_anchor=deepcopy(self.report["checkpoint_anchor"]))
        self.assertEqual(result["pin_scope"], "caller_supplied")
        self.assertEqual(result["checkpoint_verification_status"], "EXTERNAL_ANCHORED_VERIFIED")
        changed = deepcopy(self.report["authority_public_pin"])
        changed["public_key"] = "0" * 64
        with self.assertRaisesRegex(verifier.EvidenceError, "caller-supplied authority pin"):
            self.verify(expected_authority_pin=changed)
        changed = deepcopy(self.report["checkpoint_anchor"])
        changed["sequence"] -= 1
        with self.assertRaisesRegex(verifier.EvidenceError, "caller-supplied latest anchor"):
            self.verify(trusted_latest_anchor=changed)

    def test_changed_response_signature_and_public_pin_are_rejected(self):
        self.reject(lambda report: report["authority_evidence"][0]["response"].update(signature="0" * 128), "signature invalid")
        self.reject(lambda report: report["authority_public_pin"].update(public_key="0" * 64), "signature invalid")

    def test_public_request_payload_and_nonce_are_exactly_bound(self):
        self.reject(lambda report: report["authority_evidence"][0]["request"]["payload"].update(root_id="changed-root"), "binding mismatch")
        self.reject(lambda report: report["authority_evidence"][0]["request"].update(nonce="0" * 64), "binding mismatch")

    def test_wire_hmac_credential_must_never_be_public(self):
        self.reject(lambda report: report["authority_evidence"][0]["request"].update(signature="a" * 64), "without HMAC")

    def test_duplicate_authenticated_request_is_not_extra_evidence(self):
        self.reject(lambda report: report["authority_evidence"].append(deepcopy(report["authority_evidence"][0])), "duplicate public request")

    def test_changed_checkpoint_signature_and_truncated_chain_fail(self):
        def change_signature(report):
            entry = report["authority_checkpoints"][0]
            entry["signature"] = "0" * 128
            entry["checkpoint_digest"] = verifier.sha({k: v for k, v in entry.items() if k != "checkpoint_digest"})
        self.reject(change_signature, "checkpoint signature invalid")
        self.reject(lambda report: report["authority_checkpoints"].pop(), "expected-tip anchor mismatch")
        self.reject(lambda report: report["checkpoint_anchor"].update(checkpoint_digest="0" * 64), "expected-tip anchor mismatch")

    def test_missing_case_and_claimed_success_do_not_pass(self):
        self.reject(lambda report: report["outcomes"].pop("unsafe_local_restore"), "missing/extra")
        self.reject(lambda report: report["checks"].update(all_cases_collected=False), "incomplete/failed")

    def test_actual_effect_and_acceptance_counts_are_checked(self):
        self.reject(lambda report: report["outcomes"]["positive"].update(effect_count=0), "effect inventory mismatch")
        self.reject(lambda report: report["outcomes"]["stop_restore"].update(accepted_count=1), "acceptance inventory mismatch")
        self.reject(lambda report: report["outcomes"]["authority_outage"].update(outage_accepted_count=True), "outage acceptance/effect")
        self.reject(lambda report: report["outcomes"]["positive"]["records"].clear(), "record inventory count")

    def test_unsigned_outcome_cannot_override_signed_state_or_terminal_receipt(self):
        self.reject(lambda report: report["outcomes"]["positive"]["external_state"].update(committed_count=0), "signed response")
        self.reject(lambda report: report["outcomes"]["positive"]["receipt"].update(effect_count=0), "signed external proof")
        self.reject(lambda report: report["outcomes"]["positive"]["receipt"].update(reason="invented reason"), "signed external proof")
        self.reject(lambda report: report["outcomes"]["stop_restore"]["receipt"].update(receiver_id="receiver:other"), "receiver differs")

    def test_unknown_is_not_a_definitive_zero_effect_receipt(self):
        self.reject(lambda report: report["outcomes"]["pending_duplicate"]["retry_receipt"].update(effect_count=0), "definitive effect count")
        self.reject(lambda report: report["outcomes"]["pending_duplicate"]["stop_response"].update(status="STOPPED"), "signed response")

    def test_source_inventory_and_source_commit_are_bound(self):
        self.reject(lambda report: report["source_files_sha256"].pop("sdk/liminal_agent_control/receiver.py"), "source digest inventory")
        self.reject(lambda report: report["source_files_sha256"].update({"sdk/liminal_agent_control/receiver.py": "0" * 64}), "source file digest mismatch")
        self.reject(lambda report: report["source_files_sha256"].update({"../outside.py": "0" * 64}), "unsafe source digest entry")
        with self.assertRaisesRegex(verifier.EvidenceError, "expected clean source commit mismatch"):
            self.verify(expected_source_sha="0" * 40)

    def test_omitted_cleanup_and_overstated_scope_fail(self):
        self.reject(lambda report: report["cleanup"].pop(), "not reaped")
        self.reject(lambda report: report["scope"].update(rust_liminaldb_runtime="PASS"), "scope overstates")
        self.reject(lambda report: report["scope"].update(private_keys_bundled=True), "scope overstates")
        self.reject(lambda report: report["outcomes"]["stop_restore"]["restore"].update(receiver_identity_preserved=False), "pinned receiver rollback")

    def test_derived_oracle_preserves_unresolved_permit_and_does_not_dispatch_denial(self):
        scenarios = self.verify()["contractgraph_qa"]["derived_scenarios"]
        pending = next(item for item in scenarios if item["scenarioId"].endswith(":pending_duplicate"))
        self.assertEqual([event["type"] for event in pending["events"]], ["authorize", "dispatch", "ambiguous"])
        for name in ("stop_restore", "authority_restart", "split_api_denied"):
            item = next(item for item in scenarios if item["scenarioId"].endswith(":" + name))
            self.assertEqual([event["type"] for event in item["events"]], ["stop"])

    def test_pinned_oracle_source_is_checked_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "contractgraph_qa").mkdir()
            (root / "contractgraph_qa/agent_trajectory.py").write_text("raise AssertionError('must not execute')")
            with self.assertRaisesRegex(verifier.EvidenceError, "differs from pinned commit"):
                verifier._run_oracle(root, [])

    def test_cli_pins_exact_report_bytes_and_rejects_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            raw = json.dumps(self.report, sort_keys=True).encode()
            path.write_bytes(raw)
            with redirect_stdout(io.StringIO()) as captured:
                code = verifier.main([str(path), "--expected-report-sha256", hashlib.sha256(raw).hexdigest()])
            self.assertEqual(code, 0, captured.getvalue())
            path.write_bytes(raw + b"\n")
            with redirect_stdout(io.StringIO()) as captured:
                code = verifier.main([str(path), "--expected-report-sha256", hashlib.sha256(raw).hexdigest()])
            self.assertEqual(code, 1)
            self.assertIn("report SHA-256 mismatch", captured.getvalue())
            path.write_text('{"schema":"first","schema":"second"}')
            with redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(verifier.main([str(path)]), 1)
            self.assertIn("duplicate JSON object key", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
