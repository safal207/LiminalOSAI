"""Fixed receiver issuer pins at the observer command and source boundary.

These are owned temporary receiver and protocol tests. They authenticate a
receiver statement separately from the source collector's assertions and never
start Docker or authorize an agent effect through the observer.
"""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control import observer_container as module
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_agent_control.receiver_source import ReceiverSourceIssuer
from tests.test_agent_control_observer_process import fixtures


BROKER_KEY = b"observer-source-owned-broker-key" * 2
RECEIPT_KEY = b"observer-source-owned-receipt-key" * 2


class ReceiverSourceObserverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.source = self.directory / "reality"
        self.source.mkdir()
        self.request, self.evidence = fixtures()
        self.now = 100.0
        authority = SessionAuthority(self.directory / "authority.sqlite", clock=lambda: self.now)
        self.receiver = Receiver(authority.db_path, BROKER_KEY, RECEIPT_KEY,
                                 admission_controller=authority)
        authority.create_session("root", controller_id="host", policy_digest=self.request["policy_digest"],
            objective_digest=self.request["objective_digest"], max_actions=4, max_executions=1,
            max_depth=0, max_stages=4, lifetime_seconds=100, lease_seconds=20)
        self.receiver.bind_execution("root", "agent")
        self.issuer = self.new_issuer()
        self.pin = self.issuer.enrollment()
        self.image = "sha256:" + "a" * 64

    def new_issuer(self):
        return ReceiverSourceIssuer(self.receiver, issuer_id="owned-receiver-issuer",
            source_id="owned-reality", key_id="owned-receiver-source-key", clock=lambda: self.now)

    def packet(self, issuer=None):
        statement = (issuer or self.issuer).issue(self.request)
        payload = {**copy.deepcopy(self.evidence), **copy.deepcopy(statement["export"]),
                   "receiver_source_statement": statement}
        return {"source_id": "owned-reality", "role": "reality", "request_digest": digest(self.request),
                "observed_at": statement["issued_at"], "payload": payload}

    def observer(self, **overrides):
        arguments = {"image_id": self.image, "observer_id": "reality-observer", "role": "reality",
                     "key_id": "reality-key", "source_directory": self.source, "source_issuer": self.pin}
        arguments.update(overrides)
        with patch.object(module.shutil, "which", return_value=sys.executable):
            return module.DockerObserver(**arguments)

    def verdict(self, packet, request=None, now=100):
        return module.evaluate_source_packet(request or self.request, packet,
                                             issuer_pin=self.pin, now=now)[0]

    def assert_no_support(self, packet, request=None, now=100):
        try:
            verdict = self.verdict(packet, request=request, now=now)
        except ControlError:
            return
        self.assertIn(verdict, {"UNKNOWN", "VETO"})

    def test_signed_receiver_export_supports_without_collector_verification_claim(self):
        for assertion in (None, False, True):
            with self.subTest(assertion=assertion):
                packet = self.packet()
                if assertion is not None:
                    packet["payload"]["receiver_snapshot_verified_by_host"] = assertion
                self.assertEqual(self.verdict(packet), "SUPPORT")
                verdict, evidence_digest, observed_at = module.evaluate_source_packet(
                    self.request, packet, issuer_pin=self.pin, now=100)
                self.assertEqual((verdict, evidence_digest, observed_at), ("SUPPORT", digest(packet), 100))

    def test_collector_true_and_structural_snapshot_cannot_replace_issuer_signature(self):
        for statement in (None, {}, {"signature": "0" * 128}):
            packet = self.packet()
            packet["payload"]["receiver_snapshot_verified_by_host"] = True
            packet["payload"]["receiver_snapshot"]["signature"] = "0" * 64
            if statement is None:
                packet["payload"].pop("receiver_source_statement")
            else:
                packet["payload"]["receiver_source_statement"] = statement
            with self.subTest(statement=statement):
                self.assert_no_support(packet)

    def test_attacker_packet_pin_and_signing_key_cannot_replace_provisioned_issuer(self):
        attacker = self.new_issuer()
        packet = self.packet(attacker)
        self.assertNotEqual(attacker.enrollment()["public_key"], self.pin["public_key"])
        packet["payload"].update(source_issuer=attacker.enrollment(), issuer_pin=attacker.enrollment(),
                                  receiver_snapshot_verified_by_host=True)
        self.assert_no_support(packet)

    def test_issuer_signature_and_export_mutation_cannot_gain_support(self):
        mutations = (
            lambda p: p["receiver_source_statement"].update(signature="0" * 128),
            lambda p: p["receiver_source_statement"].update(issuer_id="other-issuer"),
            lambda p: p["receiver_source_statement"].update(source_id="other-source"),
            lambda p: p["receiver_source_statement"].update(key_id="other-key"),
            lambda p: p["receiver_source_statement"]["export"]["receiver_snapshot"].update(cutoff=1),
            lambda p: p["receiver_snapshot"].update(cutoff=1),
            lambda p: p["receiver_snapshot"].update(epoch=True),
            lambda p: p["receiver_snapshot"].update(cutoff=False),
        )
        for index, mutate in enumerate(mutations):
            packet = self.packet()
            packet["payload"]["receiver_snapshot_verified_by_host"] = True
            mutate(packet["payload"])
            with self.subTest(mutation=index):
                self.assert_no_support(packet)

    def test_exact_nonce_and_outer_source_binding_are_required(self):
        request = copy.deepcopy(self.request)
        request["nonce"] = digest("different-observer-challenge")
        packet = self.packet()
        packet["request_digest"] = digest(request)
        self.assert_no_support(packet, request=request)
        packet = self.packet()
        packet["source_id"] = "unrelated-collector"
        self.assert_no_support(packet)

    def test_collector_timestamp_cannot_relabel_signed_statement_age(self):
        for observed_at in (99, 101, 109):
            packet = self.packet()
            packet["observed_at"] = observed_at
            with self.subTest(observed_at=observed_at):
                self.assert_no_support(packet)

    def test_signed_timestamp_binding_preserves_json_number_type(self):
        packet = self.packet()
        self.assertIs(type(packet["observed_at"]), float)
        self.assertEqual(packet["observed_at"], 100)
        packet["observed_at"] = 100
        self.assert_no_support(packet)

    def test_invalid_provisioning_pin_never_falls_back_to_host_verification_claim(self):
        packet = self.packet()
        packet["payload"]["receiver_snapshot_verified_by_host"] = True
        for pin in ({}, {**self.pin, "public_key": "invalid"}, {**self.pin, "extra": "untrusted"}):
            with self.subTest(pin=pin):
                try:
                    verdict = module.evaluate_source_packet(self.request, packet, issuer_pin=pin, now=100)[0]
                except ControlError:
                    verdict = "UNKNOWN"
                self.assertNotEqual(verdict, "SUPPORT")

    def test_fixed_receiver_pin_cannot_authenticate_another_observer_role(self):
        statement = self.packet()["payload"]["receiver_source_statement"]
        for role, kind in (("continuity", "append-only exported audit copy"),
                           ("projection", "installed immutable policy export")):
            request, evidence = fixtures(role)
            packet = {"source_id": self.pin["source_id"], "role": role,
                      "request_digest": digest(request), "observed_at": 100,
                      "payload": {**evidence, "collector_kind": kind,
                                  "receiver_source_statement": copy.deepcopy(statement)}}
            with self.subTest(role=role):
                self.assert_no_support(packet, request=request)

    def test_signed_interval_is_checked_at_use_including_exact_expiry(self):
        packet = self.packet()
        for when in (99, 110, 111):
            with self.subTest(now=when):
                self.assert_no_support(packet, now=when)
        self.assertEqual(self.verdict(packet, now=109.999), "SUPPORT")
        with patch.object(module.time, "time", return_value=110):
            try:
                verdict = module.evaluate_source_packet(self.request, packet, issuer_pin=self.pin)[0]
            except ControlError:
                verdict = "UNKNOWN"
        self.assertNotEqual(verdict, "SUPPORT")

    def test_committed_receipt_boolean_substitution_cannot_match_signed_export(self):
        action = {"action_id": "previous", "attempt_id": "previous-attempt", "root_id": "root",
                  "execution_id": "agent", "epoch": 1, "target": "records", "arguments": {"value": 1}}
        with patch("sdk.liminal_agent_control.receiver.time.time", return_value=100):
            receipt = self.receiver.commit(action, authorization={"action_digest": digest(action),
                "policy_version": self.request["policy_digest"], "expires_at": 200,
                "receiver_id": self.receiver.receiver_id})
        self.assertEqual(receipt["status"], "COMMITTED")
        original = self.packet()
        self.assertEqual(self.verdict(original), "SUPPORT")
        for field in ("epoch", "effect_count", "accepted_epoch"):
            packet = copy.deepcopy(original)
            changed = packet["payload"]["receiver_records"][0]["receipt"]
            changed[field] = True
            packet["payload"]["receiver_snapshot"]["receipts"][0][field] = True
            with self.subTest(field=field):
                self.assert_no_support(packet)
        packet = copy.deepcopy(original)
        packet["payload"]["receiver_records"][0]["arguments"] = {"value": True}
        self.assert_no_support(packet)

    def test_worker_command_copies_exact_public_pin_before_caller_mutates_it(self):
        caller_pin = copy.deepcopy(self.pin)
        observer = self.observer(source_issuer=caller_pin)
        expected = canonical_bytes(self.pin).decode()
        caller_pin.update(public_key="0" * 64, source_id="attacker-source")
        exposed_pin = observer.source_issuer
        exposed_pin.update(public_key="1" * 64, source_id="another-attacker-source")
        command = observer.create_command()
        self.assertEqual(command.count("--source-issuer"), 1)
        self.assertEqual(command[command.index("--source-issuer") + 1], expected)
        self.assertEqual(observer.source_issuer, self.pin)
        self.assertEqual(json.loads(expected), self.pin)
        self.assertNotIn("private_key", expected)
        self.assertNotIn(str(self.receiver.db_path), repr(command))
        self.assertNotIn(BROKER_KEY.hex(), repr(command))
        self.assertNotIn(RECEIPT_KEY.hex(), repr(command))

    def test_only_reality_observer_accepts_valid_issuer_pin(self):
        for role in ("continuity", "projection"):
            with self.subTest(role=role), self.assertRaises(ControlError):
                self.observer(role=role, observer_id=role + "-observer", key_id=role + "-key")
        malformed = [{}, {**self.pin, "command": "replacement"},
                     {**self.pin, "public_key": "not-a-public-key"}, {**self.pin, "source_id": True}]
        for pin in malformed:
            with self.subTest(pin=pin), self.assertRaises(ControlError):
                self.observer(source_issuer=pin)
        # None selects the explicitly supported legacy collector mode.
        self.assertFalse(any(argument.startswith("--source-issuer")
                             for argument in self.observer(source_issuer=None).create_command()))

    def worker_exchange(self, packet, *, role="reality", now=100):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = b"x" * 32
        public_key = Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes_raw().hex()
        output = io.BytesIO()
        with patch.object(module, "_new_private_key", return_value=(key, public_key)), \
                patch.object(module, "_source_packet", return_value=packet), \
                patch.object(module.time, "time", return_value=now), \
                patch.object(module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(canonical_bytes(self.request) + b"\n"))), \
                patch.object(module.sys, "stdout", SimpleNamespace(buffer=output)):
            code = module._container_worker("reality-observer", role, "reality-key", source_issuer=self.pin)
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_worker_uses_fixed_pin_and_never_exports_receiver_secrets(self):
        code, records = self.worker_exchange(self.packet())
        self.assertEqual(code, 0)
        self.assertEqual(records[1]["status"], "PASS")
        self.assertEqual(records[1]["envelope"]["verdict"], "SUPPORT")
        self.assertFalse(records[1]["execution_authorized"])
        raw = json.dumps(records)
        for secret in (BROKER_KEY.hex(), RECEIPT_KEY.hex(), (b"x" * 32).hex(), str(self.receiver.db_path)):
            self.assertNotIn(secret, raw)

    def test_worker_cannot_follow_packet_key_override_or_expired_signature(self):
        attacker = self.new_issuer()
        packet = self.packet(attacker)
        packet["payload"].update(source_issuer=attacker.enrollment(), issuer_pin=attacker.enrollment(),
                                  receiver_snapshot_verified_by_host=True)
        for source, now in ((packet, 100), (self.packet(), 110)):
            with self.subTest(now=now):
                code, records = self.worker_exchange(source, now=now)
                self.assertEqual(code, 0)
                self.assertFalse(records[1]["execution_authorized"])
                envelope = records[1].get("envelope")
                self.assertTrue(envelope is None or envelope["verdict"] != "SUPPORT")

    def test_worker_rejects_issuer_on_other_role_before_key_creation(self):
        with patch.object(module, "_new_private_key") as generate:
            self.assertEqual(module._container_worker("continuity-observer", "continuity", "continuity-key",
                                                    source_issuer=self.pin), 2)
        generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
