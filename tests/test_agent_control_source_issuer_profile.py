"""Receiver signatures remain mandatory across persisted source effect gates."""
import json
import unittest

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import sign_attestation
from sdk.liminal_agent_control.observer_sources import ObserverSourceStore, _BINDING_FIELDS
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_agent_control.receiver_source import ReceiverSourceIssuer, SOURCE_DOMAIN
from tests import test_agent_control_observer_auth as auth_tests
from tests.test_agent_control_observer_ring import action, ring_profile


@unittest.skipIf(auth_tests.Ed25519PrivateKey is None, "source issuer tests require cryptography")
class SourceIssuerProfileTests(unittest.TestCase):
    project = auth_tests.ObserverAuthTests.project
    check = auth_tests.ObserverAuthTests.check
    profile = auth_tests.ObserverAuthTests.profile
    stored_counts = auth_tests.ObserverAuthTests.stored_counts

    def setUp(self):
        auth_tests.ObserverAuthTests.setUp(self)
        self.sources = ObserverSourceStore(self.authority)
        self.receiver = Receiver(self.path, b"b" * 32, b"r" * 32, admission_controller=self.authority)
        self.issuer = ReceiverSourceIssuer(self.receiver, issuer_id="owned-receiver-issuer",
            key_id="owned-source-key", source_id="source-reality-observer", clock=lambda: self.now)
        self.pin = self.issuer.enrollment()
        self.fixture_key = auth_tests.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(digest("fixture-issuer")))

    def source_profile(self, **overrides):
        value = {"sources": [{"observer_id": observer, "source_id": "source-" + observer}
                             for observer in self.private], "max_source_age_seconds": 20}
        value["sources"][0]["issuer"] = dict(self.pin)
        value.update(overrides)
        return value

    def install(self, **overrides):
        if "max_source_age_seconds" in overrides:
            self.issuer = ReceiverSourceIssuer(self.receiver, issuer_id="owned-receiver-issuer",
                key_id="owned-source-key", source_id="source-reality-observer", clock=lambda: self.now,
                max_age_seconds=overrides["max_source_age_seconds"])
            self.pin = self.issuer.enrollment()
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        result = self.sources.install("root", self.source_profile(**overrides))
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        return result

    def packet(self, request):
        value = {"source_id": "source-" + request["observer_id"], "role": request["role"],
                 "request_digest": digest(request), "observed_at": self.now, "payload": {"record_count": 0}}
        if request["role"] == "reality":
            statement = self.issuer.issue(request)
            value["observed_at"] = statement["issued_at"]
            value["payload"] = {**statement["export"], "receiver_source_statement": statement}
        return json.loads(canonical_bytes(value))

    def envelope(self, observer="reality-observer", verdict="SUPPORT"):
        request = self.auth.challenge("a", observer, self.now + 10)
        packet = self.packet(request)
        self.sources.bind(request, packet)
        envelope = sign_attestation(request, private_key=self.private[observer], verdict=verdict,
            evidence_digest=digest(packet), observed_at=self.now, valid_until=self.now + 10)
        return envelope, packet

    def support(self):
        return [self.auth.ingest(self.envelope(observer)[0]) for observer in self.private]

    def resigner_fixture(self):
        """Only an owned test fixture can sign arbitrary intentionally bad statements."""
        self.pin["public_key"] = self.fixture_key.public_key().public_bytes_raw().hex()

    def resign(self, statement):
        body = {key: value for key, value in statement.items() if key != "signature"}
        return {**body, "signature": self.fixture_key.sign(SOURCE_DOMAIN + canonical_bytes(body)).hex()}

    def request_for(self, nonce):
        with connect(self.path) as db:
            return json.loads(db.execute("SELECT request_json FROM observer_auth_challenges WHERE nonce=?",
                (nonce,)).fetchone()[0])

    def rewrite_binding(self, request, packet):
        """Model stored evidence corruption, retaining internally consistent hashes."""
        with connect(self.path) as db:
            row = dict(db.execute("SELECT * FROM observer_source_bindings WHERE nonce=?", (request["nonce"],)).fetchone())
            row.update(packet_json=canonical_bytes(packet).decode(), packet_digest=digest(packet))
            binding_digest = digest({field: row[field] for field in _BINDING_FIELDS})
            db.execute("UPDATE observer_source_bindings SET packet_json=?,packet_digest=?,binding_digest=? WHERE nonce=?",
                (row["packet_json"], row["packet_digest"], binding_digest, request["nonce"]))

    def test_pinned_actual_export_allows_reopened_admission_and_next_stage(self):
        installed = self.install()
        self.project()
        self.support()
        self.assertIsNone(self.check())
        self.assertEqual(installed["profile"]["sources"][0]["issuer"], self.pin)
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.assertEqual(plain.begin_stage("a", stage_id="connect")["status"], "ADMITTED")
        self.assertEqual(self.stored_counts(), (3, 3))

    def test_host_verified_flag_cannot_replace_receiver_signature(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        del packet["payload"]["receiver_source_statement"]
        packet["payload"]["receiver_snapshot_verified_by_host"] = True
        with self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_REQUIRED"):
            self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])
        self.assertIsNone(self.auth.snapshot("root")["challenges"][0]["consumed_at"])

    def test_attacker_signature_and_packet_key_override_cannot_replace_pin(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        packet["payload"]["receiver_source_statement"] = self.resign(packet["payload"]["receiver_source_statement"])
        packet["payload"]["public_key"] = self.fixture_key.public_key().public_bytes_raw().hex()
        packet["payload"]["key_id"] = self.pin["key_id"]
        with self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_SIGNATURE_INVALID"):
            self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_changed_signature_and_signed_fields_are_rejected_before_binding(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        original = self.packet(request)
        for field, value in (("signature", "0" * 128), ("source_id", "other-source"),
                             ("receiver_id", "other-receiver"), ("issuer_id", "other-issuer"),
                             ("request_digest", digest("different-request")), ("issued_at", 99.0)):
            packet = json.loads(canonical_bytes(original))
            packet["payload"]["receiver_source_statement"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_"):
                self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_valid_signature_over_wrong_nonce_root_or_export_is_rejected(self):
        self.resigner_fixture()
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        original = self.packet(request)
        variants = []
        for fields in ({"nonce": "0" * 64}, {"root_id": "other-root"}):
            packet = json.loads(canonical_bytes(original))
            statement = packet["payload"]["receiver_source_statement"]
            statement["request_digest"] = digest({**request, **fields})
            packet["payload"]["receiver_source_statement"] = self.resign(statement)
            variants.append(packet)
        packet = json.loads(canonical_bytes(original))
        statement = packet["payload"]["receiver_source_statement"]
        statement["export_digest"] = digest("different-export")
        packet["payload"]["receiver_source_statement"] = self.resign(statement)
        variants.append(packet)
        for packet in variants:
            with self.subTest(packet=packet), self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_"):
                self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_packet_cannot_change_signed_export_or_collection_instant(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        original = self.packet(request)
        variants = []
        for field in ("receiver_records", "receiver_snapshot"):
            packet = json.loads(canonical_bytes(original))
            packet["payload"][field] = [] if field == "receiver_snapshot" else {}
            variants.append(packet)
        packet = json.loads(canonical_bytes(original))
        packet["observed_at"] += 0.5
        variants.append(packet)
        packet = json.loads(canonical_bytes(original))
        packet["observed_at"] = int(packet["observed_at"])
        variants.append(packet)
        for packet in variants:
            with self.subTest(packet=packet), self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_BINDING_MISMATCH"):
                self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_old_signed_statement_cannot_be_rewrapped_for_a_fresh_nonce(self):
        self.install()
        self.project()
        first = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(first)
        second = self.auth.challenge("a", "reality-observer", 110)
        packet["request_digest"] = digest(second)
        with self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_BINDING_MISMATCH"):
            self.sources.bind(second, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_issuer_pin_is_immutable_and_covered_by_profile_digest(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        profile = self.source_profile()
        installed = self.sources.install("root", profile)
        self.assertEqual(installed["profile_digest"], digest(profile))
        profile["sources"][0]["issuer"]["public_key"] = "f" * 64
        self.assertEqual(self.sources.snapshot("root")["profile"], installed["profile"])
        self.assertNotEqual(digest(profile), installed["profile_digest"])
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.sources.install("root", profile)

    def test_invalid_issuer_pin_fields_and_source_identity_fail_install(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        for changes in ({"public_key": "F" * 64}, {"public_key": "f" * 63},
                        {"public_key": True}, {"source_id": "different-source"}, {"issuer_id": ""}):
            profile = self.source_profile()
            profile["sources"][0]["issuer"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.sources.install("root", profile)
        profile = self.source_profile()
        profile["sources"][0]["issuer"]["extra"] = "untrusted"
        with self.assertRaisesRegex(ControlError, "PROFILE_MALFORMED"):
            self.sources.install("root", profile)
        self.assertIsNone(self.sources.snapshot("root")["profile"])

    def test_issuer_enrollment_cannot_be_applied_to_an_unimplemented_role(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        profile = self.source_profile()
        profile["sources"][1]["issuer"] = {**self.pin, "source_id": "source-continuity-observer"}
        with self.assertRaisesRegex(ControlError, "ISSUER_ROLE_UNSUPPORTED"):
            self.sources.install("root", profile)

    def test_issuer_enrollment_cannot_be_added_after_seed_or_challenge(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        self.project()
        self.auth.challenge("a", "reality-observer", 110)
        with self.assertRaisesRegex(ControlError, "no seeds"):
            self.sources.install("root", self.source_profile())

    def test_signature_is_rechecked_on_ingest_after_binding_corruption(self):
        self.install()
        self.project()
        envelope, packet = self.envelope()
        packet["payload"]["receiver_source_statement"]["signature"] = "0" * 128
        self.rewrite_binding(envelope["request"], packet)
        envelope = sign_attestation(envelope["request"], private_key=self.private["reality-observer"],
            verdict="SUPPORT", evidence_digest=digest(packet), observed_at=self.now, valid_until=110)
        with self.assertRaisesRegex(ControlError, "RECEIVER_SOURCE_SIGNATURE_INVALID"):
            self.auth.ingest(envelope)
        self.assertEqual(self.stored_counts(), (0, 0))
        self.assertIsNone(self.auth.snapshot("root")["challenges"][0]["consumed_at"])

    def test_signature_is_rechecked_before_admission_after_plain_restart(self):
        self.install()
        self.project()
        self.support()
        binding = self.sources.snapshot("root")["bindings"][0]
        request = self.request_for(binding["nonce"])
        packet = binding["packet"]
        packet["payload"]["receiver_source_statement"]["signature"] = "0" * 128
        self.rewrite_binding(request, packet)
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "RECEIVER_SOURCE_SIGNATURE_INVALID")
        self.assertEqual(plain.status("root")["action_count"], 0)

    def test_signature_is_rechecked_before_next_stage_after_plain_restart(self):
        self.install()
        self.project()
        self.support()
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        binding = self.sources.snapshot("root")["bindings"][0]
        request = self.request_for(binding["nonce"])
        packet = binding["packet"]
        packet["payload"]["receiver_source_statement"]["signature"] = "0" * 128
        self.rewrite_binding(request, packet)
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.begin_stage("a", stage_id="transport")["reason"], "RECEIVER_SOURCE_SIGNATURE_INVALID")
        self.assertEqual(plain.status("root")["stage_count"], 0)

    def test_deleted_statement_cannot_restore_legacy_host_flag_at_use(self):
        self.install()
        self.project()
        self.support()
        binding = self.sources.snapshot("root")["bindings"][0]
        request = self.request_for(binding["nonce"])
        packet = binding["packet"]
        del packet["payload"]["receiver_source_statement"]
        packet["payload"]["receiver_snapshot_verified_by_host"] = True
        self.rewrite_binding(request, packet)
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "RECEIVER_SOURCE_REQUIRED")

    def test_mutated_issuer_profile_blocks_existing_support_after_restart(self):
        self.install()
        self.project()
        self.support()
        profile = self.sources.snapshot("root")["profile"]
        profile["sources"][0]["issuer"]["public_key"] = "f" * 64
        with connect(self.path) as db:
            db.execute("UPDATE observer_source_profiles SET profile_json=?", (canonical_bytes(profile).decode(),))
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "OBSERVER_SOURCE_PROFILE_MISMATCH")

    def test_signed_expiry_caps_source_binding_and_execution(self):
        self.issuer = ReceiverSourceIssuer(self.receiver, issuer_id="owned-receiver-issuer", key_id="owned-source-key",
            source_id="source-reality-observer", clock=lambda: self.now, max_age_seconds=3)
        self.pin = self.issuer.enrollment()
        self.install()
        self.project()
        self.support()
        self.assertEqual(self.sources.snapshot("root")["bindings"][0]["expires_at"], 103)
        self.now = 103
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "RECEIVER_SOURCE_STALE")
        self.assertEqual(plain.status("root")["action_count"], 0)

    def test_exact_signed_retries_retain_history_without_refreshing_lifetime(self):
        self.install(max_source_age_seconds=5)
        self.project()
        envelope, packet = self.envelope()
        before = self.sources.bind(envelope["request"], packet)
        attestation = self.auth.ingest(envelope)
        self.now = 106
        self.assertEqual(self.sources.bind(envelope["request"], packet), before)
        self.assertEqual(self.auth.ingest(envelope), attestation)
        self.assertEqual(self.sources.snapshot("root")["bindings"][0]["bound_at"], 100)
        self.assertIsNotNone(self.check())

    def test_fresh_signed_veto_remains_permanent_after_source_expiry(self):
        self.install(max_source_age_seconds=5)
        self.project()
        envelope, packet = self.envelope(verdict="VETO")
        self.auth.ingest(envelope)
        self.now = 106
        self.assertEqual(self.check(), "OBSERVER_RING_VETO")
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.sources.bind(envelope["request"], packet)["bound_at"], 100)


if __name__ == "__main__":
    unittest.main()
