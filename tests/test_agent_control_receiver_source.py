"""Receiver truth is signed locally, atomically, and pinned outside the packet."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import CHALLENGE_SCHEMA
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_agent_control.receiver_source import (MAX_STATEMENT_BYTES, ReceiverSourceIssuer, SOURCE_DOMAIN,
    validate_issuer_pin, verify_source_statement)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


BROKER_KEY = b"receiver-source-owned-broker-key-" * 2
RECEIPT_KEY = b"receiver-source-owned-receipt-key-" * 2


def request(**overrides):
    result = {"schema": CHALLENGE_SCHEMA, "action_id": "proposal", "root_id": "root", "execution_id": "worker",
        "epoch": 1, "action_digest": digest("proposal"), "projection_digest": digest("projection"),
        "center_id": "center", "predecessor_hash": digest("predecessor"), "nonce": "1" * 64,
        "issued_at": 100.0, "valid_until": 110.0, "observer_id": "reality-observer", "role": "reality",
        "key_id": "observer-key", "ring_profile_digest": digest("ring"), "auth_profile_digest": digest("auth"),
        "policy_digest": "a" * 64, "objective_digest": "b" * 64, "orientation_profile_digest": digest("orientation")}
    result.update(overrides)
    return result


def action(name="effect", execution_id="worker", **overrides):
    value = {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root", "execution_id": execution_id,
             "epoch": 1, "target": "records", "arguments": {"value": name}}
    value.update(overrides)
    return value


@unittest.skipIf(Ed25519PrivateKey is None, "receiver source signatures require cryptography")
class ReceiverSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "receiver.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.receiver = Receiver(self.path, BROKER_KEY, RECEIPT_KEY, admission_controller=self.authority)
        self.authority.create_session("root", controller_id="host", policy_digest="a" * 64,
            objective_digest="b" * 64, max_actions=30, max_executions=4, max_depth=1,
            max_stages=4, lifetime_seconds=120, lease_seconds=60)
        self.receiver.bind_execution("root", "worker")
        self.issuer = self.new_issuer()
        self.pin = self.issuer.enrollment()

    def new_issuer(self, **overrides):
        options = {"issuer_id": "receiver-issuer", "source_id": "reality-source", "key_id": "source-key",
                   "clock": lambda: self.now}
        options.update(overrides)
        return ReceiverSourceIssuer(self.receiver, **options)

    def grant(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": "a" * 64,
                "expires_at": time.time() + 60, "receiver_id": self.receiver.receiver_id}

    def commit(self, proposed):
        receipt = self.receiver.commit(proposed, authorization=self.grant(proposed))
        self.assertEqual(receipt["status"], "COMMITTED")
        return receipt

    def statement(self):
        return self.issuer.issue(request())

    def fixture_signed(self, statement):
        """Owned test key for structurally invalid but cryptographically signed cases."""
        private = Ed25519PrivateKey.generate()
        body = {key: value for key, value in statement.items() if key != "signature"}
        pin = {**self.pin, "public_key": private.public_key().public_bytes_raw().hex()}
        return {**body, "signature": private.sign(SOURCE_DOMAIN + canonical_bytes(body)).hex()}, pin

    def test_empty_real_receiver_export_verifies_without_hmac_secret(self):
        statement = self.statement()
        verified = verify_source_statement(request(), statement, self.pin, now=self.now, max_age_seconds=20)
        self.assertEqual(verified, statement)
        self.assertEqual(verified["export"]["receiver_records"], [])
        snapshot = verified["export"]["receiver_snapshot"]
        self.assertEqual((snapshot["cutoff"], snapshot["accepted_action_ids"], snapshot["receipts"]), (0, [], []))
        self.assertTrue(self.receiver.verify_receipt(snapshot))
        encoded = canonical_bytes({"pin": self.pin, "statement": statement})
        self.assertNotIn(RECEIPT_KEY, encoded)
        self.assertNotIn(BROKER_KEY, encoded)
        self.assertNotIn(b"private_key", encoded)

    def test_actual_committed_effect_and_receipt_are_exported(self):
        receipt = self.commit(action())
        statement = self.statement()
        exported = verify_source_statement(request(), statement, self.pin, now=100)["export"]
        self.assertEqual(exported["receiver_records"], self.receiver.records())
        self.assertEqual(exported["receiver_snapshot"]["receipts"], [receipt])
        self.assertEqual(exported["receiver_snapshot"]["cutoff"], 1)
        self.assertEqual(statement["export_digest"], digest(exported))

    def test_other_execution_is_outside_export_and_cutoff_is_global(self):
        self.receiver.bind_execution("root", "other")
        self.commit(action("foreign", "other"))
        self.commit(action("owned"))
        exported = self.statement()["export"]
        self.assertEqual([record["action"]["action_id"] for record in exported["receiver_records"]], ["owned"])
        self.assertEqual(exported["receiver_snapshot"]["cutoff"], 2)
        verify_source_statement(request(), self.statement(), self.pin, now=100)

    def test_pending_real_acceptance_is_explicit_not_a_committed_effect(self):
        proposed = action("pending")
        self.assertEqual(self.receiver.accept(proposed, authorization=self.grant(proposed))["status"], "ACCEPTED")
        exported = verify_source_statement(request(), self.statement(), self.pin, now=100)["export"]
        self.assertEqual(exported["receiver_records"], [])
        self.assertEqual(exported["receiver_snapshot"]["accepted_action_ids"], ["pending"])
        self.assertEqual(exported["receiver_snapshot"]["cutoff"], 0)

    def test_one_read_transaction_preserves_records_snapshot_and_cutoff_during_real_commit(self):
        self.commit(action("first"))
        original = self.receiver.verify_receipt
        committed = []

        def concurrent_commit(receipt):
            if receipt.get("action_id") == "first" and not committed:
                committed.append(self.commit(action("second")))
            return original(receipt)

        with patch.object(self.receiver, "verify_receipt", side_effect=concurrent_commit):
            export = self.statement()["export"]
        self.assertEqual(len(self.receiver.records()), 2)
        self.assertEqual([record["action"]["action_id"] for record in export["receiver_records"]], ["first"])
        self.assertEqual([receipt["action_id"] for receipt in export["receiver_snapshot"]["receipts"]], ["first"])
        self.assertEqual(export["receiver_snapshot"]["cutoff"], 1)
        self.assertEqual(self.statement()["export"]["receiver_snapshot"]["cutoff"], 2)

    def test_no_arbitrary_export_or_signing_api(self):
        with self.assertRaises(TypeError):
            self.issuer.issue(request(), {"receiver_records": []})
        with self.assertRaises(TypeError):
            self.issuer.issue(request(), export={"receiver_records": []})
        self.assertFalse(hasattr(self.issuer, "sign"))
        self.assertFalse(hasattr(self.issuer, "private_key"))
        self.assertFalse(hasattr(self.issuer, "export_private_key"))

    def test_restart_key_and_enrollment_are_fresh_not_silently_reused(self):
        restarted = self.new_issuer()
        self.assertNotEqual(restarted.enrollment()["public_key"], self.pin["public_key"])
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            verify_source_statement(request(), restarted.issue(request()), self.pin, now=100)

    def test_mutating_returned_enrollment_does_not_change_issuer(self):
        public = self.issuer.enrollment()
        public["receiver_id"] = "invented"
        public["public_key"] = "0" * 64
        self.assertEqual(self.issuer.enrollment(), self.pin)
        verify_source_statement(request(), self.statement(), self.pin, now=100)

    def test_self_declared_packet_public_key_is_rejected(self):
        statement = {**self.statement(), "public_key": self.pin["public_key"]}
        with self.assertRaisesRegex(ControlError, "MALFORMED"):
            verify_source_statement(request(), statement, self.pin, now=100)

    def test_each_enrolled_identity_must_match_independent_pin(self):
        statement = self.statement()
        for field in ("issuer_id", "key_id", "receiver_id", "source_id"):
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "PIN_MISMATCH"):
                verify_source_statement(request(), {**statement, field: "foreign"}, self.pin, now=100)

    def test_nonce_root_execution_epoch_and_all_challenge_fields_are_bound(self):
        statement = self.statement()
        replacements = {"nonce": "2" * 64, "root_id": "other", "execution_id": "other", "epoch": 2,
            "action_id": "different", "observer_id": "different", "key_id": "different", "center_id": "different",
            "action_digest": "c" * 64, "projection_digest": "c" * 64, "predecessor_hash": "c" * 64,
            "ring_profile_digest": "c" * 64, "auth_profile_digest": "c" * 64, "policy_digest": "c" * 64,
            "objective_digest": "c" * 64, "orientation_profile_digest": "c" * 64, "issued_at": 99.0,
            "valid_until": 111.0}
        for field, value in replacements.items():
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                verify_source_statement(request(**{field: value}), statement, self.pin, now=100)

    def test_only_reality_role_can_receive_receiver_statement(self):
        for role in ("continuity", "projection"):
            altered = request(role=role)
            with self.subTest(role=role), self.assertRaisesRegex(ControlError, "ROLE_MISMATCH"):
                self.issuer.issue(altered)
            with self.subTest(role=role), self.assertRaisesRegex(ControlError, "ROLE_MISMATCH"):
                verify_source_statement(altered, self.statement(), self.pin, now=100)

    def test_mutating_export_and_recomputing_digest_cannot_forge_signature(self):
        statement = self.statement()
        forged = copy.deepcopy(statement)
        forged["export"]["receiver_snapshot"]["cutoff"] = 100
        forged["export_digest"] = digest(forged["export"])
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            verify_source_statement(request(), forged, self.pin, now=100)

    def test_domain_separation_rejects_signature_over_plain_body(self):
        statement = self.statement()
        private = Ed25519PrivateKey.generate()
        body = {key: value for key, value in statement.items() if key != "signature"}
        forged = {**body, "signature": private.sign(canonical_bytes(body)).hex()}
        pin = {**self.pin, "public_key": private.public_key().public_bytes_raw().hex()}
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            verify_source_statement(request(), forged, pin, now=100)

    def test_signed_export_digest_still_must_match_export(self):
        signed, pin = self.fixture_signed({**self.statement(), "export_digest": "0" * 64})
        with self.assertRaisesRegex(ControlError, "EXPORT_DIGEST_MISMATCH"):
            verify_source_statement(request(), signed, pin, now=100)

    def test_signed_inconsistent_snapshot_or_receipt_is_rejected(self):
        self.commit(action())
        original = self.statement()
        variants = []
        empty = copy.deepcopy(original)
        empty["export"]["receiver_records"] = []
        variants.append(empty)
        for field, value in (("epoch", True), ("cutoff", True), ("complete", 1), ("receiver_id", "foreign"),
                             ("root_id", "foreign"), ("execution_id", "foreign")):
            altered = copy.deepcopy(original)
            altered["export"]["receiver_snapshot"][field] = value
            variants.append(altered)
        bad_arguments = copy.deepcopy(original)
        bad_arguments["export"]["receiver_records"][0]["arguments"] = {"value": "changed"}
        variants.append(bad_arguments)
        bad_receipt = copy.deepcopy(original)
        bad_receipt["export"]["receiver_records"][0]["receipt"]["effect_count"] = True
        variants.append(bad_receipt)
        for index, altered in enumerate(variants):
            altered["export_digest"] = digest(altered["export"])
            signed, pin = self.fixture_signed(altered)
            with self.subTest(index=index), self.assertRaisesRegex(ControlError, "EXPORT_INVALID"):
                verify_source_statement(request(), signed, pin, now=100)

    def test_issuer_rejects_tampered_real_receipt_hmac(self):
        self.commit(action())
        with connect(self.path) as db:
            receipt = json.loads(db.execute("SELECT receipt_json FROM accepted").fetchone()[0])
            receipt["signature"] = "0" * 64
            db.execute("UPDATE accepted SET receipt_json=?", (canonical_bytes(receipt).decode(),))
        with self.assertRaisesRegex(ControlError, "RECEIPT_INVALID"):
            self.statement()

    def test_issuer_rejects_real_arguments_mismatch_or_missing_effect(self):
        self.commit(action())
        with connect(self.path) as db:
            db.execute("UPDATE effects SET arguments_json=?", (canonical_bytes({"value": "forged"}).decode(),))
        with self.assertRaisesRegex(ControlError, "EXPORT_INVALID"):
            self.statement()
        with connect(self.path) as db:
            db.execute("DELETE FROM effects")
        with self.assertRaisesRegex(ControlError, "EXPORT_INVALID"):
            self.statement()

    def test_orphan_actual_effect_is_not_silently_omitted(self):
        with connect(self.path) as db:
            db.execute("INSERT INTO effects(action_id,arguments_json,committed_at) VALUES (?,?,?)",
                       ("orphan", "{}", 100))
        with self.assertRaisesRegex(ControlError, "EXPORT_INVALID"):
            self.statement()

    def test_unknown_root_execution_wrong_policy_objective_or_epoch_not_signable(self):
        for overrides in ({"root_id": "other"}, {"execution_id": "other"}, {"epoch": 2},
                          {"policy_digest": "c" * 64}, {"objective_digest": "c" * 64}):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                self.issuer.issue(request(**overrides))
        self.receiver.revoke("root")
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.statement()

    def test_changed_receiver_identity_or_profile_not_signable(self):
        for key, value in (("receiver_id", "foreign"), ("enforcement_profile", "baseline_unfenced")):
            with self.subTest(key=key):
                with connect(self.path) as db:
                    original = db.execute("SELECT value FROM receiver_meta WHERE key=?", (key,)).fetchone()[0]
                    db.execute("UPDATE receiver_meta SET value=? WHERE key=?", (value, key))
                with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                    self.statement()
                with connect(self.path) as db:
                    db.execute("UPDATE receiver_meta SET value=? WHERE key=?", (original, key))

    def test_signed_statement_is_stale_before_issue_at_expiry_and_under_age_limit(self):
        statement = self.statement()
        for when in (99, 110, 111):
            with self.subTest(when=when), self.assertRaisesRegex(ControlError, "STALE"):
                verify_source_statement(request(), statement, self.pin, now=when)
        with self.assertRaisesRegex(ControlError, "STALE"):
            verify_source_statement(request(), statement, self.pin, now=100, max_age_seconds=5)
        verify_source_statement(request(), statement, self.pin)

    def test_issuer_caps_expiry_and_rejects_late_future_or_rollback_clock(self):
        issuer = self.new_issuer(max_age_seconds=3)
        self.assertEqual(issuer.issue(request())["expires_at"], 103)
        for when in (99, 110):
            self.now = when
            with self.subTest(when=when), self.assertRaisesRegex(ControlError, "STALE"):
                self.statement()
        for times in ([100, 99], [100, 110]):
            clock = iter(times)
            bad = self.new_issuer(clock=lambda: next(clock))
            with self.subTest(times=times), self.assertRaisesRegex(ControlError, "STALE"):
                bad.issue(request())

    def test_issuer_rejects_expired_session_even_when_request_claims_valid_interval(self):
        self.now = 160
        with self.assertRaisesRegex(ControlError, "STALE"):
            self.issuer.issue(request(issued_at=160, valid_until=170))

    def test_malformed_schema_extra_fields_and_bool_timestamps_not_accepted(self):
        statement = self.statement()
        for overrides in ({"schema": "liminal-receiver-source-v2"}, {"extra": True}, {"issued_at": True},
                          {"expires_at": False}, {"signature": "g" * 128}, {"signature": "0" * 127}):
            with self.subTest(overrides=overrides), self.assertRaises(ControlError):
                verify_source_statement(request(), {**statement, **overrides}, self.pin, now=100)
        with self.assertRaises(ControlError):
            self.issuer.issue(request(epoch=True))
        with self.assertRaises(ControlError):
            verify_source_statement(request(), statement, self.pin, now=True)

    def test_public_pin_has_exact_fields_and_lowercase_public_key(self):
        self.assertEqual(validate_issuer_pin(self.pin), self.pin)
        for pin in ({**self.pin, "extra": 1}, {**self.pin, "public_key": "g" * 64},
                    {**self.pin, "public_key": "A" * 64}, {**self.pin, "source_id": False}):
            with self.subTest(pin=pin), self.assertRaisesRegex(ControlError, "PIN_MALFORMED"):
                validate_issuer_pin(pin)

    def test_missing_database_is_not_recreated_or_signed(self):
        self.path.unlink()
        with self.assertRaisesRegex(ControlError, "EXPORT_INVALID"):
            self.statement()
        self.assertFalse(self.path.exists())

    def test_ungoverned_baseline_receiver_cannot_be_issuer(self):
        legacy = Receiver(self.path.with_name("legacy.sqlite"), BROKER_KEY, RECEIPT_KEY, enforce_epoch=False)
        with self.assertRaisesRegex(ControlError, "GOVERNED_RECEIVER_REQUIRED"):
            ReceiverSourceIssuer(legacy, issuer_id="legacy", source_id="legacy", key_id="legacy")

    def test_oversized_actual_export_fails_closed(self):
        for index in range(6):
            self.commit(action("large-" + str(index), arguments={"text": "x" * 14000}))
        with self.assertRaisesRegex(ControlError, "EXPORT_TOO_LARGE"):
            self.statement()
        malformed = {**self.statement_for_empty_fixture(), "extra": "x" * MAX_STATEMENT_BYTES}
        with self.assertRaisesRegex(ControlError, "MALFORMED"):
            verify_source_statement(request(), malformed, self.pin, now=100)

    def statement_for_empty_fixture(self):
        # A different owned fresh database is used only to bound verifier input;
        # this helper does not sign synthetic exports or mutate the issuer key.
        authority = SessionAuthority(self.path.with_name("empty.sqlite"), clock=lambda: 100)
        receiver = Receiver(authority.db_path, BROKER_KEY, RECEIPT_KEY, admission_controller=authority)
        authority.create_session("root", controller_id="host", policy_digest="a" * 64,
            objective_digest="b" * 64, max_actions=1, max_executions=1, max_depth=0,
            max_stages=0, lifetime_seconds=120, lease_seconds=60)
        receiver.bind_execution("root", "worker")
        issuer = ReceiverSourceIssuer(receiver, issuer_id="fresh", source_id="fresh", key_id="fresh", clock=lambda: 100)
        return issuer.issue(request())


if __name__ == "__main__":
    unittest.main()
