"""Exact persisted collector packets must remain fresh at every effect gate."""
import json
from pathlib import Path
import threading
import unittest

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import sign_attestation
from sdk.liminal_agent_control.observer_sources import ObserverSourceStore, validate_source_packet, write_source_packet
from tests import test_agent_control_observer_auth as auth_tests
from tests.test_agent_control_observer_ring import action, ring_profile


@unittest.skipIf(auth_tests.Ed25519PrivateKey is None, "source-bound observer tests require cryptography")
class ObserverSourceTests(unittest.TestCase):
    project = auth_tests.ObserverAuthTests.project
    check = auth_tests.ObserverAuthTests.check
    profile = auth_tests.ObserverAuthTests.profile
    stored_counts = auth_tests.ObserverAuthTests.stored_counts

    def setUp(self):
        auth_tests.ObserverAuthTests.setUp(self)
        self.sources = ObserverSourceStore(self.authority)

    def source_profile(self, **overrides):
        profile = {"sources": [{"observer_id": observer, "source_id": "source-" + observer}
                               for observer in self.private], "max_source_age_seconds": 20}
        profile.update(overrides)
        return profile

    def install(self, **overrides):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        result = self.sources.install("root", self.source_profile(**overrides))
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        return result

    def packet(self, request, **overrides):
        packet = {"source_id": "source-" + request["observer_id"], "role": request["role"],
                  "request_digest": digest(request), "observed_at": self.now, "payload": {"record_count": 0}}
        packet.update(overrides)
        return packet

    def envelope(self, observer="reality-observer", verdict="SUPPORT", action_id="a", *, bind=True, packet_overrides=None,
                 **overrides):
        request = self.auth.challenge(action_id, observer, self.now + 10)
        packet = self.packet(request, **(packet_overrides or {}))
        if bind:
            self.sources.bind(request, packet)
        fields = {"private_key": self.private[observer], "verdict": verdict, "evidence_digest": digest(packet),
                  "observed_at": self.now, "valid_until": self.now + 10}
        fields.update(overrides)
        return sign_attestation(request, **fields)

    def support(self):
        return [self.auth.ingest(self.envelope(observer)) for observer in self.private]

    def test_distinct_persisted_source_packets_allow_admission_and_stage(self):
        self.install()
        self.project()
        self.support()
        self.assertIsNone(self.check())
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.authority.begin_stage("a", stage_id="connect")["status"], "ADMITTED")
        self.assertEqual(self.stored_counts(), (3, 3))
        snapshot = self.sources.snapshot("root")
        self.assertEqual(len(snapshot["bindings"]), 3)
        self.assertEqual(len({item["source_id"] for item in snapshot["bindings"]}), 3)
        self.assertFalse(snapshot["execution_authorized"])

    def test_valid_signature_without_host_source_binding_is_rejected(self):
        self.install()
        self.project()
        with self.assertRaisesRegex(ControlError, "OBSERVER_SOURCE_BINDING_REQUIRED"):
            self.auth.ingest(self.envelope(bind=False))
        self.assertEqual(self.stored_counts(), (0, 0))
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertIsNone(self.auth.snapshot("root")["challenges"][0]["consumed_at"])

    def test_signer_cannot_choose_a_different_evidence_digest(self):
        self.install()
        self.project()
        with self.assertRaisesRegex(ControlError, "OBSERVER_SOURCE_BINDING_MISMATCH"):
            self.auth.ingest(self.envelope(evidence_digest=digest("invented observer evidence")))
        self.assertEqual(self.stored_counts(), (0, 0))

    def test_packet_request_digest_role_and_enrolled_source_id_are_exact(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        for fields in ({"request_digest": digest("other")}, {"role": "continuity"},
                       {"source_id": "source-projection-observer"}):
            with self.subTest(fields=fields), self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                self.sources.bind(request, self.packet(request, **fields))
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_packet_for_one_nonce_cannot_bind_another_nonce(self):
        self.install()
        self.project()
        first = self.auth.challenge("a", "reality-observer", 110)
        second = self.auth.challenge("a", "reality-observer", 110)
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.sources.bind(second, self.packet(first))

    def test_unknown_or_mutated_challenge_cannot_be_bound(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        altered = {**request, "nonce": "0" * 64}
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.sources.bind(altered, self.packet(altered))

    def test_source_profile_requires_authenticated_observer_enrollment(self):
        self.ring.install("root", ring_profile())
        with self.assertRaisesRegex(ControlError, "AUTH_PROFILE_REQUIRED"):
            self.sources.install("root", self.source_profile())

    def test_source_ids_and_observer_ids_cannot_be_duplicated(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        for field in ("source_id", "observer_id"):
            profile = self.source_profile()
            profile["sources"][1][field] = profile["sources"][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "DUPLICATE_SOURCE"):
                self.sources.install("root", profile)

    def test_source_profile_requires_exact_observer_coverage(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        profile = self.source_profile()
        profile["sources"] = profile["sources"][:-1]
        with self.assertRaisesRegex(ControlError, "COVERAGE_REQUIRED"):
            self.sources.install("root", profile)

    def test_profile_is_immutable_and_does_not_retain_caller_objects(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        profile = self.source_profile()
        installed = self.sources.install("root", profile)
        profile["sources"][0]["source_id"] = "changed"
        self.assertEqual(installed["profile"], self.sources.snapshot("root")["profile"])
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.sources.install("root", self.source_profile())

    def test_profile_cannot_be_added_after_seed_or_existing_challenge(self):
        self.ring.install("root", ring_profile())
        self.auth.install("root", self.profile())
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=100)
        self.project()
        self.auth.challenge("a", "reality-observer", 110)
        with self.assertRaisesRegex(ControlError, "no seeds"):
            self.sources.install("root", self.source_profile())

    def test_old_or_future_packet_is_rejected_at_host_binding(self):
        self.install(max_source_age_seconds=5)
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        for timestamp in (95, 94, 101):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(ControlError, "SOURCE_STALE"):
                self.sources.bind(request, self.packet(request, observed_at=timestamp))
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_source_expiry_blocks_plain_reopened_authority_admission(self):
        self.install(max_source_age_seconds=5)
        self.project()
        self.support()
        self.now = 105
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "OBSERVER_SOURCE_STALE")
        self.assertEqual(plain.status("root")["action_count"], 0)

    def test_source_expiry_blocks_next_stage_of_an_already_admitted_action(self):
        self.install(max_source_age_seconds=5)
        self.project()
        self.support()
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.now = 105
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.begin_stage("a", stage_id="transport")["reason"], "OBSERVER_SOURCE_STALE")
        self.assertEqual(plain.status("root")["stage_count"], 0)

    def test_source_can_expire_before_signed_response_without_extending_source_lifetime(self):
        self.install(max_source_age_seconds=5)
        self.project()
        self.support()
        snapshot = self.sources.snapshot("root")
        self.assertTrue(all(item["expires_at"] == 105 for item in snapshot["bindings"]))
        self.now = 104
        self.assertIsNone(self.check())
        self.now = 105
        self.assertEqual(self.check(), "OBSERVER_SOURCE_STALE")

    def test_exact_bind_and_response_retries_do_not_refresh_collection_time(self):
        self.install(max_source_age_seconds=5)
        self.project()
        envelope = self.envelope()
        request = envelope["request"]
        packet = self.packet(request)
        before = self.sources.bind(request, packet)
        attestation = self.auth.ingest(envelope)
        self.now = 106
        self.assertEqual(before, self.sources.bind(request, packet))
        self.assertEqual(attestation, self.auth.ingest(envelope))
        self.assertEqual(self.check(), "OBSERVER_SOURCE_STALE")
        self.assertEqual(self.sources.snapshot("root")["bindings"][0]["bound_at"], 100)

    def test_packet_rebinding_is_immutable_even_before_nonce_consumption(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        self.sources.bind(request, self.packet(request))
        with self.assertRaisesRegex(ControlError, "BINDING_IMMUTABLE"):
            self.sources.bind(request, self.packet(request, payload={"record_count": 99}))
        self.assertEqual(len(self.sources.snapshot("root")["bindings"]), 1)

    def test_deleted_binding_denies_existing_authenticated_attestation_after_restart(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            db.execute("DELETE FROM observer_source_bindings WHERE rowid=1")
        plain = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(plain.reserve(action(), channel="egress")["reason"], "OBSERVER_SOURCE_BINDING_REQUIRED")

    def test_source_profile_integrity_is_rechecked_at_use_time(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            profile = self.source_profile(max_source_age_seconds=200)
            db.execute("UPDATE observer_source_profiles SET profile_json=?", (canonical_bytes(profile).decode(),))
        self.assertEqual(self.check(), "OBSERVER_SOURCE_PROFILE_MISMATCH")

    def test_rehashed_source_profile_still_cannot_retarget_existing_bindings(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            profile = self.source_profile(max_source_age_seconds=200)
            db.execute("UPDATE observer_source_profiles SET profile_json=?,profile_digest=?",
                       (canonical_bytes(profile).decode(), digest(profile)))
        self.assertEqual(self.check(), "OBSERVER_SOURCE_BINDING_MISMATCH")

    def test_binding_metadata_or_packet_tampering_cannot_supply_coverage(self):
        self.install()
        self.project()
        self.support()
        with connect(self.path) as db:
            row = db.execute("SELECT * FROM observer_source_bindings LIMIT 1").fetchone()
            packet = json.loads(row["packet_json"])
            packet["payload"]["record_count"] = 100
            db.execute("UPDATE observer_source_bindings SET packet_json=?,packet_digest=? WHERE nonce=?",
                (canonical_bytes(packet).decode(), digest(packet), row["nonce"]))
        self.assertEqual(self.check(), "OBSERVER_SOURCE_BINDING_MISMATCH")

    def test_late_veto_requires_fresh_packet_but_latches_after_source_expiry(self):
        self.install(max_source_age_seconds=5)
        self.project(deadline=108)
        for observer in self.private:
            self.auth.ingest(self.envelope(observer, valid_until=108))
        self.now = 109
        self.auth.ingest(self.envelope(verdict="VETO"))
        self.assertEqual(self.check(), "OBSERVER_RING_VETO")
        self.now = 120
        self.assertEqual(self.check(), "OBSERVER_RING_VETO")
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_RING_VETO")

    def test_bad_signature_does_not_consume_pinned_source_packet(self):
        self.install()
        self.project()
        envelope = self.envelope()
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            self.auth.ingest({**envelope, "signature": "0" * 128})
        self.assertEqual(len(self.sources.snapshot("root")["bindings"]), 1)
        self.assertIsNone(self.auth.snapshot("root")["challenges"][0]["consumed_at"])
        self.auth.ingest(envelope)
        self.assertEqual(self.stored_counts(), (1, 1))

    def test_packet_numbers_are_preserved_and_integer_timestamp_can_be_signed(self):
        self.install()
        self.project()
        for observer in self.private:
            request = self.auth.challenge("a", observer, 110)
            packet = self.packet(request, observed_at=100)
            self.sources.bind(request, packet)
            self.auth.ingest(sign_attestation(request, private_key=self.private[observer], verdict="SUPPORT",
                evidence_digest=digest(packet), observed_at=100, valid_until=110))
        self.assertIsNone(self.check())
        self.assertIs(type(self.sources.snapshot("root")["bindings"][0]["packet"]["observed_at"]), int)

    def test_clock_rollback_closes_session_before_source_write(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        self.now = 99
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            self.sources.bind(request, packet)
        self.assertEqual(self.sources.snapshot("root")["bindings"], [])

    def test_snapshot_is_read_only_and_contains_public_packets(self):
        self.install()
        self.project()
        self.support()
        self.now = 105
        snapshot = self.sources.snapshot("root")
        encoded = canonical_bytes(snapshot).decode()
        for key in self.private.values():
            self.assertNotIn(key.hex(), encoded)
        self.assertFalse(snapshot["execution_authorized"])
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT last_now FROM brakes_sessions").fetchone()[0], 100)

    def test_packet_validator_rejects_extra_fields_nonobjects_and_oversize(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        for invalid in ({**packet, "private_key": "bad"}, {**packet, "payload": []},
                        {**packet, "payload": {"huge": "x" * 262144}}):
            with self.subTest(invalid_type=type(invalid)), self.assertRaises(ControlError):
                validate_source_packet(request, invalid)

    def test_atomic_packet_writer_uses_nonce_only_name_and_immutable_regular_file(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        directory = Path(self.temp.name) / "evidence"
        directory.mkdir()
        target = write_source_packet(directory, request, packet)
        self.assertEqual(target.name, request["nonce"] + ".json")
        self.assertEqual(target.read_bytes(), canonical_bytes(packet))
        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertEqual(write_source_packet(directory, request, packet), target)
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            write_source_packet(directory, request, self.packet(request, payload={"changed": True}))

    def test_packet_writer_rejects_symlink_directory_and_target(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        packet = self.packet(request)
        directory = Path(self.temp.name) / "evidence"
        directory.mkdir()
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(ControlError, "DIRECTORY_UNSAFE"):
            write_source_packet(alias, request, packet)
        target = directory / (request["nonce"] + ".json")
        target.symlink_to(self.path)
        with self.assertRaisesRegex(ControlError, "DIRECTORY_UNSAFE"):
            write_source_packet(directory, request, packet)

    def test_concurrent_packet_writers_cannot_replace_an_existing_nonce_file(self):
        self.install()
        self.project()
        request = self.auth.challenge("a", "reality-observer", 110)
        directory = Path(self.temp.name) / "evidence"
        directory.mkdir()
        barrier = threading.Barrier(2)
        results = []
        def run(count):
            packet = self.packet(request, payload={"record_count": count})
            barrier.wait()
            try:
                write_source_packet(directory, request, packet)
                results.append(("stored", packet))
            except ControlError as exc:
                results.append((str(exc), packet))
        threads = [threading.Thread(target=run, args=(count,)) for count in (1, 2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual([result[0] for result in results], ["stored", "OBSERVER_SOURCE_BINDING_IMMUTABLE"])
        stored = next(packet for status, packet in results if status == "stored")
        self.assertEqual((directory / (request["nonce"] + ".json")).read_bytes(), canonical_bytes(stored))


if __name__ == "__main__":
    unittest.main()
