"""Tamper regressions against one real three-service network experiment."""
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

from sdk.liminal_agent_control.external_network_demo import run_demo

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("independent_network_verifier", ROOT / "scripts/verify_external_network_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ExternalNetworkEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_demo()

    def verify(self, report=None, **kwargs):
        return verifier.verify_report(self.report if report is None else report, repo_root=ROOT, **kwargs)

    def reject(self, mutate, text=None):
        report = deepcopy(self.report)
        mutate(report)
        with self.assertRaises(verifier.EvidenceError) as caught:
            self.verify(report)
        if text:
            self.assertIn(text, str(caught.exception))

    def test_real_artifact_passes_without_private_keys_or_new_permission(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cases_verified"], list(verifier.CASE_IDS))
        self.assertEqual(result["actual_endpoint_requests"], 8)
        self.assertEqual(result["actual_endpoint_effects"], 8)
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["checkpoint_verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertEqual(result["sender_quiescence"], "NOT_ESTABLISHED")
        self.assertEqual(result["authority_pin_scope"], "report_fixture")
        self.assertEqual(result["endpoint_pin_scope"], "report_fixture")

    def test_independently_supplied_pins_and_anchor_have_explicit_scope(self):
        result = self.verify(expected_authority_pin=self.report["authority_public_pin"],
            expected_endpoint_pin=self.report["endpoint_public_pin"], trusted_latest_anchor=self.report["checkpoint_anchor"])
        self.assertEqual(result["authority_pin_scope"], "caller_supplied")
        self.assertEqual(result["endpoint_pin_scope"], "caller_supplied")
        self.assertEqual(result["checkpoint_verification_status"], "EXTERNAL_ANCHORED_VERIFIED")
        for argument, field in (("expected_authority_pin", "authority_public_pin"), ("expected_endpoint_pin", "endpoint_public_pin")):
            pin = deepcopy(self.report[field])
            pin["public_key"] = "0" * 64
            with self.assertRaisesRegex(verifier.EvidenceError, "caller-supplied"):
                self.verify(**{argument: pin})
        anchor = deepcopy(self.report["checkpoint_anchor"])
        anchor["sequence"] -= 1
        with self.assertRaisesRegex(verifier.EvidenceError, "latest anchor mismatch"):
            self.verify(trusted_latest_anchor=anchor)

    def test_authority_signature_tamper_is_rejected(self):
        self.reject(lambda r: r["authority_evidence"][0]["response"].update(signature="0" * 128), "signature invalid")

    def test_authority_challenge_or_payload_tamper_is_rejected(self):
        self.reject(lambda r: r["authority_evidence"][0]["request"].update(nonce="0" * 64), "binding mismatch")
        self.reject(lambda r: r["authority_evidence"][0]["request"]["payload"].update(root_id="altered"), "binding mismatch")

    def test_authority_duplicate_is_not_extra_evidence(self):
        self.reject(lambda r: r["authority_evidence"].append(deepcopy(r["authority_evidence"][0])), "duplicate public")

    def test_endpoint_signature_tamper_is_rejected(self):
        self.reject(lambda r: r["endpoint_evidence"][0]["response"].update(signature="0" * 128), "signature invalid")

    def test_endpoint_exact_challenge_and_role_are_checked(self):
        self.reject(lambda r: r["endpoint_evidence"][0]["request"].update(nonce="0" * 64), "binding mismatch")
        self.reject(lambda r: r["endpoint_evidence"][0]["request"].update(role="admin"), "role invalid")

    def test_endpoint_duplicate_cannot_satisfy_a_fresh_query(self):
        self.reject(lambda r: r["endpoint_evidence"].append(deepcopy(r["endpoint_evidence"][0])), "duplicate endpoint")

    def test_live_hmac_and_private_keys_cannot_enter_public_packets(self):
        self.reject(lambda r: r["authority_evidence"][0]["request"].update(signature="a" * 64), "without HMAC")
        self.reject(lambda r: r["endpoint_evidence"][0]["request"].update(signature="a" * 64), "HMAC bundled")
        self.reject(lambda r: r.update(private_key="synthetic-private-material"), "private credential bundled")

    def test_endpoint_terminal_signature_is_checked_against_actual_inventory(self):
        self.reject(lambda r: r["endpoint_final_inventory"]["receipts"][0].update(signature="0" * 128), "receipt signature invalid")

    def test_receipt_action_body_authorization_and_reservation_are_bound(self):
        for field, changed in (("action_digest", "0" * 64), ("body_digest", "0" * 64),
            ("authorization_digest", "0" * 64), ("reservation_id", "reservation:changed")):
            self.reject(lambda r, f=field, v=changed: r["outcomes"]["network_positive"]["results"]["execute"]["receipt"].update({f: v}))

    def test_actual_sqlite_count_and_row_content_are_checked(self):
        self.reject(lambda r: r["endpoint_final_inventory"].update(independent_sqlite_effect_count=0), "inventory count mismatch")
        self.reject(lambda r: r["endpoint_final_inventory"]["effects"][0]["body"].update(synthetic_marker="changed"), "SQLite row differs")
        self.reject(lambda r: r["endpoint_final_inventory"]["independent_sqlite_action_ids"].clear(), "SQLite action inventory")

    def test_actual_request_counters_and_measured_deltas_are_checked(self):
        self.reject(lambda r: r["outcomes"]["network_positive"]["endpoint_after"].update(commit_request_count=0), "request counter mismatch")
        self.reject(lambda r: r["outcomes"]["network_positive"].update(request_count_delta=2), "reported delta")
        self.reject(lambda r: r["outcomes"]["network_positive"].update(effect_count_delta=True), "reported delta")

    def test_actual_inventory_permit_and_digest_are_checked(self):
        self.reject(lambda r: r["endpoint_final_inventory"]["requests"][0].update(permit_digest="0" * 64), "request/endpoint binding")
        self.reject(lambda r: r["endpoint_final_inventory"]["requests"][0]["permit_request"].update(nonce="0" * 64), "binding mismatch")

    def test_network_exact_request_cannot_change_to_an_arbitrary_api(self):
        self.reject(lambda r: r["outcomes"]["network_positive"]["action"]["arguments"].update(url="https://example.com/v1/record"), "owned endpoint URL")
        self.reject(lambda r: r["outcomes"]["network_positive"]["action"]["arguments"].update(headers={"X": "changed"}), "bounded network request")

    def test_operator_grant_cannot_change_identity_expiry_or_policy(self):
        self.reject(lambda r: r["outcomes"]["network_positive"]["authorization"].update(receiver_id="other:endpoint"), "grant binding")
        self.reject(lambda r: r["outcomes"]["network_positive"]["authorization"].update(expires_at=-1), "grant binding")
        self.reject(lambda r: r["outcomes"]["network_positive"]["authorization"].update(policy_version="not-a-digest"), "grant binding")

    def test_declared_success_cannot_replace_case_observations(self):
        self.reject(lambda r: r["outcomes"].pop("network_ambiguous_endpoint"), "missing/extra")
        self.reject(lambda r: r["checks"].update(all_cases_collected=False), "incomplete/failed")
        self.reject(lambda r: r["outcomes"]["network_binding_swap"]["results"].pop("headers"), "matrix incomplete")

    def test_unknown_does_not_become_zero_effect_or_terminal(self):
        self.reject(lambda r: r["outcomes"]["network_lost_transport_response"]["results"]["execute"].update(effect_count=0), "UNKNOWN asserted")
        self.reject(lambda r: r["outcomes"]["network_ambiguous_endpoint"]["results"]["reconcile"].update(status="COMMITTED"), "gateway outcome mismatch")
        self.reject(lambda r: r["outcomes"]["network_lost_begin_response"]["stop_response"].update(status="STOPPED"), "signed response")

    def test_gateway_result_cannot_change_action_or_create_execution_authority(self):
        self.reject(lambda r: r["outcomes"]["network_positive"]["results"]["execute"].update(action_id="different:action"), "identity/authority")
        self.reject(lambda r: r["outcomes"]["network_lost_begin_response"]["results"]["execute"].update(execution_authorized=True), "identity/authority")
        self.reject(lambda r: r["outcomes"]["network_binding_swap"]["results"]["body"]["result"].update(execution_authorized=True), "invented authority")

    def test_gateway_inventory_cannot_fabricate_terminal_status_without_receipt(self):
        self.reject(lambda r: r["outcomes"]["network_lost_begin_response"]["gateway_inventory"]["actions"][0].update(status="COMMITTED"), "status lacks actual receipt")

    def test_unknown_remote_commit_requires_an_authenticated_actual_receipt(self):
        self.reject(lambda r: r["outcomes"]["network_ambiguous_endpoint"]["results"]["reconcile"].update(remote_outcome="COMMITTED"), "UNKNOWN asserted")

    def test_lost_finish_preserves_remote_commit_and_unknown_settlement_separately(self):
        self.reject(lambda r: r["outcomes"]["network_lost_finish_response"]["results"]["execute"].update(settlement_status="SETTLED"), "conflated")
        self.reject(lambda r: r["outcomes"]["network_lost_finish_response"]["results"]["execute"].update(effect_count=None), "conflated")

    def test_pending_barrier_cannot_acknowledge_stop_early(self):
        self.reject(lambda r: r["outcomes"]["network_pending_dispatch_stop"]["stop_response"].update(pending_count=0), "signed response")

    def test_rollback_must_have_stopped_gateway_and_preserved_external_stores(self):
        self.reject(lambda r: r["outcomes"]["network_restore_consumed_state"]["restore"].update(gateway_stopped_during_copy=False), "rollback evidence")
        self.reject(lambda r: r["outcomes"]["network_restore_stopped_state"]["restore"].update(endpoint_database_not_restored=False), "rollback evidence")

    def test_rollback_must_actually_restore_an_old_authorization(self):
        self.reject(lambda r: r["outcomes"]["network_restore_consumed_state"]["restore"]["gateway_state_after_restore"]["actions"][0].update(status="COMMITTED"), "restored authorization")

    def test_versioned_source_inventory_and_expected_commit_are_checked(self):
        self.reject(lambda r: r["source_files_sha256"].pop("sdk/liminal_agent_control/external_network_endpoint.py"), "transitive Python")
        self.reject(lambda r: r["source_files_sha256"].update({"scripts/verify_external_network_evidence.py": "0" * 64}), "source file digest mismatch")
        self.reject(lambda r: r["source_files_sha256"].update({"../outside": "0" * 64}), "unsafe source")
        with self.assertRaisesRegex(verifier.EvidenceError, "expected clean source commit mismatch"):
            self.verify(expected_source_sha="0" * 40)

    def test_required_docs_and_workflow_cannot_be_omitted(self):
        self.reject(lambda r: r["source_files_sha256"].pop("docs/AGENT_CONTROL_EXTERNAL_NETWORK.md"), "required source")
        self.reject(lambda r: r["source_files_sha256"].pop(".github/workflows/agent-control.yml"), "required source")
        self.reject(lambda r: r["source_files_sha256"].pop("tests/test_agent_control_external_network_authority.py"), "required source")

    def test_checkpoint_signature_and_latest_tip_are_checked(self):
        def corrupt(r):
            entry = r["authority_checkpoints"][0]
            entry["signature"] = "0" * 128
            entry["checkpoint_digest"] = verifier.sha({k: v for k, v in entry.items() if k != "checkpoint_digest"})
        self.reject(corrupt, "signature invalid")
        self.reject(lambda r: r["authority_checkpoints"].pop(), "expected-tip anchor")

    def test_every_child_must_be_separate_and_reaped(self):
        self.reject(lambda r: r["cleanup"].pop(), "lifecycle evidence")
        self.reject(lambda r: r["processes"][0].update(pid=r["controller_pid"]), "process separation")
        self.reject(lambda r: r["cleanup"][0].update(reaped=False), "not reaped")

    def test_restart_cannot_silently_initialize_authority_or_change_pin(self):
        def initialize(r):
            next(item for item in r["processes"][1:] if item["role"] == "external_authority")["explicit_initialization"] = True
        self.reject(initialize, "restart identity/init")
        self.reject(lambda r: r["processes"][1]["startup"]["pin"].update(public_key="0" * 64), "restart identity/init")

    def test_scope_cannot_claim_quiescence_training_or_general_containment(self):
        self.reject(lambda r: r["scope"].update(sender_quiescence="PASS"), "scope overstates")
        self.reject(lambda r: r["scope"].update(model_calls=1), "scope overstates")
        self.reject(lambda r: r["scope"].update(full_worker_socket_mediation="PASS"), "scope overstates")

    def test_cli_exact_report_bytes_and_duplicate_json_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            raw = json.dumps(self.report, sort_keys=True).encode()
            path.write_bytes(raw)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(verifier.main([str(path), "--expected-report-sha256", hashlib.sha256(raw).hexdigest()]), 0, output.getvalue())
            path.write_bytes(raw + b"\n")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(verifier.main([str(path), "--expected-report-sha256", hashlib.sha256(raw).hexdigest()]), 1)
                self.assertIn("report SHA-256 mismatch", output.getvalue())
            path.write_text('{"schema":"a","schema":"b"}')
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(verifier.main([str(path)]), 1)
                self.assertIn("duplicate JSON", output.getvalue())


if __name__ == "__main__":
    unittest.main()
