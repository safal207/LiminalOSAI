"""Signed principals, exact challenges, replay and persisted effect gates."""
import json
import threading
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import ObserverAuthStore, sign_attestation
from sdk.liminal_agent_control.observer_ring import ObserverRingStore
from tests import test_agent_control_observer_ring as ring_tests
from tests.test_agent_control_observer_ring import action, ring_profile

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


@unittest.skipIf(Ed25519PrivateKey is None, "signed observer tests require cryptography")
class ObserverAuthTests(unittest.TestCase):
    project = ring_tests.ObserverRingTests.project
    check = ring_tests.ObserverRingTests.check

    def setUp(self):
        ring_tests.ObserverRingTests.setUp(self)
        self.auth = ObserverAuthStore(self.authority)
        self.private = {role + "-observer": bytes.fromhex(digest("fixture-key-" + role))
                        for role in ("reality", "continuity", "projection")}

    def profile(self, **overrides):
        profile = {"keys": [{"observer_id": observer, "key_id": "key-" + observer,
            "public_key": Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes_raw().hex()}
            for observer, key in self.private.items()], "max_challenge_age_seconds": 20, "max_challenges": 100}
        profile.update(overrides)
        return profile

    def install(self, **overrides):
        self.ring.install("root", ring_profile())
        result = self.auth.install("root", self.profile(**overrides))
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        return result

    def envelope(self, observer="reality-observer", verdict="SUPPORT", action_id="a", **overrides):
        request = self.auth.challenge(action_id, observer, self.now + 10)
        fields = {"private_key": self.private[observer], "verdict": verdict,
                  "evidence_digest": digest(observer + verdict), "observed_at": self.now, "valid_until": self.now + 10}
        fields.update(overrides)
        return sign_attestation(request, **fields)

    def support(self, action_id="a"):
        return [self.auth.ingest(self.envelope(observer, action_id=action_id)) for observer in self.private]

    def stored_counts(self):
        with connect(self.path) as db:
            return tuple(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in
                ("observer_ring_attestations", "observer_auth_proofs"))

    def test_valid_roles_use_distinct_keys_and_real_admission(self):
        self.install()
        projection = self.project()
        self.support()
        self.assertIsNone(self.check())
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.stored_counts(), (3, 3))
        snapshot = self.auth.snapshot("root")
        self.assertFalse(snapshot["execution_authorized"])
        self.assertTrue(all(item["consumed_at"] == self.now for item in snapshot["challenges"]))
        self.assertEqual(projection["action_digest"], snapshot["challenges"][0]["action_digest"])

    def test_raw_attestation_blocked_after_reopening_plain_ring(self):
        self.install()
        self.project()
        reopened = ObserverRingStore(SessionAuthority(self.path, clock=lambda: self.now))
        with self.assertRaisesRegex(ControlError, "OBSERVER_RING_AUTH_REQUIRED"):
            reopened.attest("a", observer_id="reality-observer", verdict="SUPPORT",
                evidence_digest=digest("fake"), observed_at=self.now, valid_until=self.now + 10)
        self.assertEqual(self.stored_counts(), (0, 0))
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_RING_ROLE_REQUIRED")

    def test_profile_requires_ring_and_exact_observer_coverage(self):
        with self.assertRaisesRegex(ControlError, "RING_REQUIRED"):
            self.auth.install("root", self.profile())
        self.ring.install("root", ring_profile())
        for keys in (self.profile()["keys"][:-1], self.profile()["keys"] + [{
            "observer_id": "outsider", "key_id": "outsider", "public_key": "1" * 64}]):
            with self.assertRaisesRegex(ControlError, "COVERAGE_REQUIRED"):
                self.auth.install("root", self.profile(keys=keys))

    def test_duplicate_public_key_cannot_supply_two_roles(self):
        self.ring.install("root", ring_profile())
        profile = self.profile()
        profile["keys"][1]["public_key"] = profile["keys"][0]["public_key"]
        with self.assertRaisesRegex(ControlError, "DUPLICATE_KEY"):
            self.auth.install("root", profile)

    def test_duplicate_identity_or_key_id_rejected(self):
        self.ring.install("root", ring_profile())
        for field in ("observer_id", "key_id"):
            profile = self.profile()
            profile["keys"][1][field] = profile["keys"][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "DUPLICATE_KEY"):
                self.auth.install("root", profile)

    def test_profile_is_immutable_and_caller_mutation_cannot_change_enrollment(self):
        self.ring.install("root", ring_profile())
        profile = self.profile()
        installed = self.auth.install("root", profile)
        profile["keys"][0]["public_key"] = "f" * 64
        self.assertEqual(installed["profile"], self.auth.snapshot("root")["profile"])
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.auth.install("root", self.profile())

    def test_auth_cannot_be_added_after_trajectory_seed(self):
        self.ring.install("root", ring_profile())
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        with self.assertRaisesRegex(ControlError, "no seeds"):
            self.auth.install("root", self.profile())

    def test_missing_projection_cannot_issue_nonce(self):
        self.install()
        with self.assertRaisesRegex(ControlError, "PROJECTION_REQUIRED"):
            self.auth.challenge("a", "reality-observer", 110)
        self.assertEqual(self.auth.snapshot("root")["challenges"], [])

    def test_wrong_private_key_and_mutated_signed_payload_rejected_without_root_hold(self):
        self.install()
        self.project()
        envelope = self.envelope(private_key=self.private["projection-observer"])
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            self.auth.ingest(envelope)
        envelope = self.envelope()
        for field, value in (("verdict", "VETO"), ("evidence_digest", digest("fake")),
                             ("observed_at", 101), ("valid_until", 109)):
            altered = {**envelope, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
                self.auth.ingest(altered)
        self.assertIsNone(self.auth.snapshot("root")["hold"])
        self.assertEqual(self.stored_counts(), (0, 0))

    def test_request_binding_changes_are_not_reusable_even_if_resigned(self):
        self.install()
        self.project()
        envelope = self.envelope()
        for field, value in (("nonce", "0" * 64), ("action_id", "other"), ("execution_id", "other"),
                             ("root_id", "other"), ("epoch", 2), ("center_id", "other"),
                             ("predecessor_hash", digest("other")), ("role", "projection"),
                             ("key_id", "key-projection-observer"), ("auth_profile_digest", digest("other"))):
            request = {**envelope["request"], field: value}
            altered = sign_attestation(request, private_key=self.private["reality-observer"], verdict="SUPPORT",
                evidence_digest=envelope["evidence_digest"], observed_at=100, valid_until=110)
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.auth.ingest(altered)
        self.assertEqual(self.stored_counts(), (0, 0))

    def test_exact_retry_returns_original_without_refreshing_validity(self):
        self.install()
        self.project()
        envelope = self.envelope()
        first = self.auth.ingest(envelope)
        self.now = 110
        self.assertEqual(self.auth.ingest(envelope), first)
        self.assertEqual(self.stored_counts(), (1, 1))
        self.assertEqual(self.check(), "OBSERVER_RING_ATTESTATION_STALE")
        self.assertEqual(self.auth.snapshot("root")["challenges"][0]["consumed_at"], 100)

    def test_changed_verdict_with_consumed_nonce_is_replay(self):
        self.install()
        self.project()
        envelope = self.envelope()
        self.auth.ingest(envelope)
        veto = sign_attestation(envelope["request"], private_key=self.private["reality-observer"],
            verdict="VETO", evidence_digest=digest("veto"), observed_at=100, valid_until=110)
        with self.assertRaisesRegex(ControlError, "CHALLENGE_REPLAY"):
            self.auth.ingest(veto)
        self.assertEqual(self.stored_counts(), (1, 1))
        self.assertIsNone(self.auth.snapshot("root")["hold"])

    def test_second_nonce_cannot_refresh_or_replace_same_statement(self):
        self.install()
        self.project()
        self.auth.ingest(self.envelope())
        with self.assertRaisesRegex(ControlError, "ATTESTATION_IMMUTABLE"):
            self.auth.ingest(self.envelope())
        self.assertEqual(self.stored_counts(), (1, 1))
        self.assertIsNone(self.auth.snapshot("root")["challenges"][1]["consumed_at"])

    def test_expired_nonce_or_overextended_envelope_cannot_append(self):
        self.install()
        self.project()
        envelope = self.envelope()
        extended = sign_attestation(envelope["request"], private_key=self.private["reality-observer"],
            verdict="SUPPORT", evidence_digest=digest("extended"), observed_at=100, valid_until=111)
        with self.assertRaisesRegex(ControlError, "CHALLENGE_STALE"):
            self.auth.ingest(extended)
        self.now = 110
        with self.assertRaisesRegex(ControlError, "CHALLENGE_STALE"):
            self.auth.ingest(envelope)
        self.assertEqual(self.stored_counts(), (0, 0))

    def test_invalid_host_challenge_times_and_unknown_observer_rejected(self):
        self.install()
        self.project()
        for deadline in (100, 121, float("nan"), True):
            with self.subTest(deadline=deadline), self.assertRaises(ControlError):
                self.auth.challenge("a", "reality-observer", deadline)
        with self.assertRaisesRegex(ControlError, "UNKNOWN_OBSERVER"):
            self.auth.challenge("a", "outsider", 110)

    def test_challenge_quota_latches_root_hold_instead_of_dropping_safety_signal(self):
        self.install(max_challenges=3)
        self.project()
        self.support()
        with self.assertRaisesRegex(ControlError, "CHALLENGE_LIMIT"):
            self.envelope(verdict="VETO")
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_AUTH_CHALLENGE_LIMIT")
        self.assertIsNotNone(self.auth.snapshot("root")["hold"])

    def test_unsigned_attestations_inserted_in_database_cannot_supply_coverage(self):
        self.install()
        projection = self.project()
        ring_digest = self.ring.snapshot("root")["profile_digest"]
        with connect(self.path) as db:
            for observer in ring_profile()["observers"]:
                body = {field: projection[field] for field in ("action_id", "root_id", "execution_id", "epoch",
                    "action_digest", "projection_digest", "center_id", "predecessor_hash")}
                body.update(**observer, verdict="SUPPORT", evidence_digest=digest(observer), observed_at=100,
                            valid_until=110, ring_profile_digest=ring_digest)
                db.execute("INSERT INTO observer_ring_attestations VALUES (?,?,?,?,?,?,?)", (digest(body), "a", "root",
                    observer["observer_id"], "ASSESSMENT", canonical_bytes(body).decode(), 100))
        self.assertEqual(self.check(), "OBSERVER_AUTH_PROOF_REQUIRED")
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "OBSERVER_AUTH_PROOF_REQUIRED")
        self.assertEqual(plain.status("root")["action_count"], 0)

    def test_proof_is_reverified_before_later_stage_on_plain_authority(self):
        self.install()
        self.project()
        self.support()
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        with connect(self.path) as db:
            db.execute("DELETE FROM observer_auth_proofs WHERE rowid=(SELECT MIN(rowid) FROM observer_auth_proofs)")
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        result = plain.begin_stage("a", stage_id="connect")
        self.assertEqual(result["reason"], "OBSERVER_AUTH_PROOF_REQUIRED")
        self.assertEqual(plain.status("root")["stage_count"], 0)

    def test_signed_proof_tampering_is_detected_even_after_rehashing(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            proof = db.execute("SELECT * FROM observer_auth_proofs LIMIT 1").fetchone()
            envelope = json.loads(proof["envelope_json"])
            envelope["signature"] = "0" * 128
            db.execute("UPDATE observer_auth_proofs SET envelope_digest=?,envelope_json=? WHERE nonce=?",
                (digest(envelope), canonical_bytes(envelope).decode(), proof["nonce"]))
            db.execute("UPDATE observer_auth_challenges SET envelope_digest=? WHERE nonce=?",
                (digest(envelope), proof["nonce"]))
        self.assertEqual(self.check(), "OBSERVER_AUTH_SIGNATURE_INVALID")

    def test_auth_profile_and_challenge_integrity_rechecked(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            row = db.execute("SELECT * FROM observer_auth_profiles").fetchone()
            profile = json.loads(row["profile_json"])
            profile["max_challenge_age_seconds"] = 200
            db.execute("UPDATE observer_auth_profiles SET profile_json=?", (canonical_bytes(profile).decode(),))
        self.assertEqual(self.check(), "OBSERVER_AUTH_BINDING_MISMATCH")
        with connect(self.path) as db:
            db.execute("UPDATE observer_auth_profiles SET profile_json=?", (row["profile_json"],))
            db.execute("UPDATE observer_auth_challenges SET issued_at=99 WHERE rowid=1")
        self.assertEqual(self.check(), "OBSERVER_AUTH_BINDING_MISMATCH")

    def test_public_key_revocation_holds_existing_support_and_unconsumed_challenge(self):
        self.install()
        self.project()
        pending = self.envelope()
        self.support()
        result = self.auth.revoke("root", "key-reality-observer", "compromised principal")
        self.assertEqual(self.check(), "OBSERVER_AUTH_KEY_REVOKED")
        self.assertFalse(result["execution_authorized"])
        with self.assertRaisesRegex(ControlError, "KEY_REVOKED"):
            self.auth.ingest(pending)
        reopened = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.reserve(action(), channel="egress")["reason"], "OBSERVER_AUTH_KEY_REVOKED")
        self.now = 105
        self.assertEqual(result, self.auth.revoke("root", "key-reality-observer", "other"))
        self.assertEqual(len(self.auth.snapshot("root")["revocations"]), 1)

    def test_late_signed_veto_requires_fresh_nonce_and_permanently_holds_descendants(self):
        self.install()
        self.project(deadline=108)
        for observer in self.private:
            self.auth.ingest(self.envelope(observer, valid_until=108))
        self.assertIsNone(self.check())
        self.authority.bind_execution("root", "child", parent_execution_id="worker")
        self.orientation.seed("root", "child", "center", evidence_digest=digest("child"), observed_at=100)
        child = action("child-action", "child")
        self.project(child)
        self.support(child["action_id"])
        self.now = 109
        self.auth.ingest(self.envelope(verdict="VETO"))
        self.assertEqual(self.check(child["action_id"]), "OBSERVER_RING_VETO")
        self.assertEqual(self.authority.reserve(child, channel="egress")["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(len(self.ring.snapshot("root")["attestations"]), 7)

    def test_missing_crypto_fails_closed_for_signed_root_at_use_time(self):
        self.install()
        self.project()
        self.support()
        with patch("sdk.liminal_agent_control.observer_auth._crypto", side_effect=ControlError("OBSERVER_AUTH_CRYPTO_UNAVAILABLE")):
            self.assertEqual(self.check(), "OBSERVER_AUTH_CRYPTO_UNAVAILABLE")
            self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_AUTH_CRYPTO_UNAVAILABLE")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_old_unsigned_root_does_not_import_crypto(self):
        self.ring.install("root", ring_profile())
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=100)
        self.project()
        with patch("sdk.liminal_agent_control.observer_auth._crypto", side_effect=AssertionError("eager crypto")):
            for role in ("reality", "continuity", "projection"):
                self.ring.attest("a", observer_id=role + "-observer", verdict="SUPPORT",
                    evidence_digest=digest(role), observed_at=100, valid_until=110)
            self.assertIsNone(self.check())

    def test_concurrent_exact_replay_commits_one_proof_and_one_attestation(self):
        self.install()
        self.project()
        envelope = self.envelope()
        barrier = threading.Barrier(2)
        results = []
        def run():
            barrier.wait()
            results.append(self.auth.ingest(envelope))
        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.stored_counts(), (1, 1))

    def test_concurrent_different_envelopes_on_one_nonce_cannot_replace_each_other(self):
        self.install()
        self.project()
        support = self.envelope()
        unknown = sign_attestation(support["request"], private_key=self.private["reality-observer"],
            verdict="UNKNOWN", evidence_digest=digest("unknown"), observed_at=100, valid_until=110)
        barrier = threading.Barrier(2)
        results = []
        def run(envelope):
            barrier.wait()
            try:
                self.auth.ingest(envelope)
                results.append("stored")
            except ControlError as error:
                results.append(str(error))
        threads = [threading.Thread(target=run, args=(envelope,)) for envelope in (support, unknown)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ["stored", "OBSERVER_AUTH_CHALLENGE_REPLAY"])
        self.assertEqual(self.stored_counts(), (1, 1))

    def test_clock_rollback_closes_session_before_signed_write(self):
        self.install()
        self.project()
        envelope = self.envelope()
        self.now = 99
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            self.auth.ingest(envelope)
        self.assertEqual(self.stored_counts(), (0, 0))
        self.assertEqual(self.authority.status("root")["status"], "CLOCK_UNSAFE")

    def test_snapshot_exposes_only_public_enrollment_and_does_not_refresh_clock(self):
        self.install()
        self.project()
        self.support()
        self.now = 105
        snapshot = self.auth.snapshot("root")
        encoded = canonical_bytes(snapshot).decode()
        for private in self.private.values():
            self.assertNotIn(private.hex(), encoded)
        self.assertFalse(snapshot["execution_authorized"])
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT last_now FROM brakes_sessions").fetchone()[0], 100)

    def test_signature_uses_domain_separation(self):
        self.install()
        self.project()
        envelope = self.envelope()
        body = {key: value for key, value in envelope.items() if key != "signature"}
        unsigned_domain = {**body, "signature": Ed25519PrivateKey.from_private_bytes(
            self.private["reality-observer"]).sign(canonical_bytes(body)).hex()}
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            self.auth.ingest(unsigned_domain)
        self.assertEqual(self.stored_counts(), (0, 0))

    def test_external_integer_signed_times_reconstruct_the_same_ring_statement(self):
        self.install()
        self.project()
        for observer in self.private:
            request = self.auth.challenge("a", observer, 110)
            self.auth.ingest(sign_attestation(request, private_key=self.private[observer], verdict="SUPPORT",
                evidence_digest=digest(observer), observed_at=100, valid_until=110))
        self.assertIsNone(self.check())
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")

    def test_one_bad_proof_denies_even_when_redundant_roles_cover_every_requirement(self):
        self.private["extra-observer"] = bytes.fromhex(digest("extra-fixture-key"))
        ring = ring_profile()
        ring["observers"].append({"observer_id": "extra-observer", "role": "reality"})
        self.ring.install("root", ring)
        self.auth.install("root", self.profile())
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=100)
        self.project()
        self.support()
        self.assertIsNone(self.check())
        with connect(self.path) as db:
            proof = db.execute("SELECT p.* FROM observer_auth_proofs p JOIN observer_ring_attestations a "
                "USING(attestation_digest) WHERE a.observer_id='extra-observer'").fetchone()
            envelope = json.loads(proof["envelope_json"])
            envelope["observed_at"] = "malformed"
            db.execute("UPDATE observer_auth_proofs SET envelope_json=? WHERE nonce=?",
                       (canonical_bytes(envelope).decode(), proof["nonce"]))
        self.assertEqual(self.check(), "OBSERVER_AUTH_BINDING_MISMATCH")
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_AUTH_BINDING_MISMATCH")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_proof_persistence_failure_rolls_back_ring_append_and_nonce_consumption(self):
        import sqlite3
        self.install()
        self.project()
        envelope = self.envelope()
        with connect(self.path) as db:
            db.execute("CREATE TRIGGER fail_proof BEFORE INSERT ON observer_auth_proofs "
                       "BEGIN SELECT RAISE(ABORT, 'injected proof persistence failure'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "proof persistence failure"):
            self.auth.ingest(envelope)
        self.assertEqual(self.stored_counts(), (0, 0))
        self.assertIsNone(self.auth.snapshot("root")["challenges"][0]["consumed_at"])
        self.assertEqual(self.check(), "OBSERVER_RING_ROLE_REQUIRED")


if __name__ == "__main__":
    unittest.main()
