"""External network authority regressions with synthetic endpoint signatures."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest, sign_document
from sdk.liminal_agent_control.external_authority import EXTERNAL_PROFILE, ExternalAuthorityStore
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain
from sdk.liminal_agent_control.external_network_authority import NETWORK_PROFILE, ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.observer_auth import _crypto


AUTHORITY_KEY = b"a" * 32
ENDPOINT_KEY = b"e" * 32
RECEIPT_KEY = b"r" * 32
OPERATOR_KEY = b"o" * 32
REQUEST_KEY = b"q" * 32
POLICY = "b" * 64
RECEIPT_DOMAIN = b"liminal-external-network-receipt-v1\x00"


def endpoint_pin(key=ENDPOINT_KEY, *, endpoint_id="endpoint", key_id="endpoint-key"):
    private, _ = _crypto()
    return {"endpoint_id": endpoint_id, "key_id": key_id,
            "public_key": private.from_private_bytes(key).public_key().public_bytes_raw().hex()}


def action(name="action", **changes):
    result = {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
              "execution_id": "worker", "epoch": 1, "target": "network",
              "arguments": {"method": "POST", "url": "http://127.0.0.1:49152/v1/record",
                            "body": {"synthetic_marker": "dummy:" + name}}}
    result.update(changes)
    return result


def grant(proposed, **changes):
    result = {"action_digest": digest(proposed), "receiver_id": "endpoint",
              "policy_version": POLICY, "expires_at": 180}
    result.update(changes)
    return result


def signed_terminal(proposed, authorization, permit, *, key=ENDPOINT_KEY, **changes):
    result = {"schema": "liminal.external-network.receipt.v1", "endpoint_id": "endpoint",
              "key_id": "endpoint-key", "reservation_id": permit["reservation_id"],
              **{field: proposed[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
              "action_digest": digest(proposed), "authorization_digest": digest(authorization),
              "body_digest": digest(proposed["arguments"]["body"]), "committed_at": 100.0,
              "status": "COMMITTED", "effect_count": 1}
    result.update(changes)
    private, _ = _crypto()
    result["signature"] = private.from_private_bytes(key).sign(RECEIPT_DOMAIN + canonical_bytes(result)).hex()
    return result


class ExternalNetworkAuthorityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "authority.sqlite"
        self.now = 100.0
        self.pin = endpoint_pin()
        self.store = self._open(create=True)
        self.store.create_root("root", "endpoint", POLICY, 10, 100)
        self.store.bind_execution("root", "worker")

    def _options(self, **changes):
        result = {"authority_id": "authority", "key_id": "authority-key", "private_key": AUTHORITY_KEY,
                  "receipt_key": RECEIPT_KEY, "clock": lambda: self.now, "create": False}
        result.update(changes)
        return result

    def _open(self, **changes):
        pin = changes.pop("endpoint_pin", self.pin)
        return ExternalNetworkAuthorityStore(self.path, endpoint_pin=pin, **self._options(**changes))

    def _permitted(self, name="action"):
        proposed = action(name)
        authorization = grant(proposed)
        permit = self.store.begin(proposed, authorization)
        self.assertEqual(permit["status"], "PERMITTED")
        return proposed, authorization, permit

    def test_external_endpoint_receipt_settles_exact_permit(self):
        proposed, authorization, permit = self._permitted()
        terminal = signed_terminal(proposed, authorization, permit)
        result = self.store.finish(permit["reservation_id"], terminal)
        self.assertEqual((result["status"], result["outcome"]), ("SETTLED", "COMMITTED"))
        self.assertEqual(result["reason"], "AUTHENTICATED_ENDPOINT_COMMITTED")
        self.assertEqual(result["receipt"], terminal)
        self.assertEqual(self.store.status("root")["committed_count"], 1)
        self.assertEqual(self.store.status("root")["pending_count"], 0)
        self.assertEqual(self.store.begin(proposed, authorization)["status"], "CONSUMED")

    def test_stop_ack_waits_for_endpoint_commit_and_remains_stopped_on_restart(self):
        proposed, authorization, permit = self._permitted()
        ack = self.store.stop("root")
        self.assertEqual((ack["status"], ack["epoch"], ack["pending_count"]), ("STOP_PENDING", 2, 1))
        self.now = 500
        self.assertEqual(self._open().stop("root")["status"], "STOP_PENDING")
        result = self._open().finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit))
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertEqual(self._open().stop("root")["status"], "STOPPED")
        late = action("late")
        self.assertEqual(self.store.begin(late, grant(late, expires_at=600))["status"], "DENIED")

    def test_pending_duplicate_never_reissues_or_expires_without_receipt(self):
        proposed, authorization, _ = self._permitted()
        self.assertEqual(self._open().begin(proposed, authorization)["status"], "UNKNOWN")
        self.now = 10000
        self.assertEqual(self.store.query(proposed["action_id"])["status"], "UNKNOWN")
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self._open().status("root")["pending_count"], 1)

    def test_network_database_rejects_records_reopen_and_records_rejects_network(self):
        with self.assertRaises(ControlError):
            ExternalAuthorityStore(self.path, **self._options())
        records_path = self.path.with_name("records.sqlite")
        ExternalAuthorityStore(records_path, **self._options(create=True))
        with self.assertRaises(ControlError):
            ExternalNetworkAuthorityStore(records_path, endpoint_pin=self.pin, **self._options())

    def test_profile_and_endpoint_pin_are_persisted_exactly(self):
        with sqlite3.connect(self.path) as db:
            metadata = dict(db.execute("SELECT key,value FROM external_meta"))
        self.assertEqual(metadata["profile"], NETWORK_PROFILE)
        self.assertEqual(json.loads(metadata["endpoint_pin"]), self.pin)
        self.assertEqual(set(metadata), {"schema", "pin", "receipt_key_digest", "profile", "endpoint_pin", "last_now", "clock_fault"})

    def test_reopen_rejects_pin_or_endpoint_identity_drift(self):
        for pin in (endpoint_pin(b"x" * 32), endpoint_pin(endpoint_id="other"), endpoint_pin(key_id="other")):
            with self.subTest(pin=pin), self.assertRaises(ControlError):
                self._open(endpoint_pin=pin)

    def test_live_pin_mutation_cannot_switch_terminal_verifier(self):
        proposed, authorization, permit = self._permitted()
        self.store._endpoint_pin = endpoint_pin(b"x" * 32)
        with self.assertRaises(ControlError):
            self.store.finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit, key=b"x" * 32))
        with self.assertRaises(ControlError):
            self.store.status("root")
        self.assertEqual(self._open().status("root")["pending_count"], 1)

    def test_constructor_copies_supplied_endpoint_pin(self):
        original = self.store.endpoint_pin()
        self.pin["key_id"] = "mutated"
        self.assertEqual(self.store.endpoint_pin(), original)
        self.assertEqual(self.store.status("root")["state"], "ACTIVE")

    def test_missing_profile_or_pin_is_not_repaired(self):
        for field in ("profile", "endpoint_pin"):
            with self.subTest(field=field):
                with sqlite3.connect(self.path) as db:
                    value = db.execute("SELECT value FROM external_meta WHERE key=?", (field,)).fetchone()[0]
                    db.execute("DELETE FROM external_meta WHERE key=?", (field,))
                with self.assertRaises(ControlError):
                    self._open()
                with self.assertRaises(ControlError):
                    ExternalAuthorityStore(self.path, **self._options())
                with sqlite3.connect(self.path) as db:
                    db.execute("INSERT INTO external_meta VALUES (?,?)", (field, value))

    def test_profile_corruption_rejected_at_running_public_boundaries(self):
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE external_meta SET value='records' WHERE key='profile'")
        for operation in (lambda: self.store.stop("root"), lambda: self.store.query("action"),
                          lambda: self.store.checkpoints()):
            with self.subTest(operation=operation), self.assertRaises(ControlError):
                operation()

    def test_endpoint_and_authority_signers_must_use_distinct_keys(self):
        bad_path = self.path.with_name("collapsed.sqlite")
        with self.assertRaisesRegex(ControlError, "ENDPOINT_KEY_MUST_DIFFER"):
            ExternalNetworkAuthorityStore(bad_path, endpoint_pin=endpoint_pin(AUTHORITY_KEY), **self._options(create=True))
        self.assertFalse(bad_path.exists())

    def test_root_cannot_claim_an_unpinned_effect_receiver(self):
        with self.assertRaisesRegex(ControlError, "ENDPOINT_IDENTITY_MISMATCH"):
            self.store.create_root("other", "gateway", POLICY, 10, 100)

    def test_records_hmac_receipt_cannot_drain_network_permit(self):
        proposed, _, permit = self._permitted()
        body = {"schema": "liminal.agent-control.receipt.v1", "status": "COMMITTED", "reason": "LOCAL_CALLBACK_RETURNED",
                **{field: proposed[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
                "action_digest": digest(proposed), "effect_count": 1, "accepted_epoch": 1,
                "accepted_at": 100, "receiver_id": "endpoint", "observed_at": 100,
                "key_id": "receiver-hmac-v1", "enforcement_profile": EXTERNAL_PROFILE}
        self.store.stop("root")
        with self.assertRaises(ControlError):
            self.store.finish(permit["reservation_id"], sign_document(body, RECEIPT_KEY))
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")

    def test_endpoint_denial_unknown_and_zero_effect_are_not_terminal_proof(self):
        proposed, authorization, permit = self._permitted()
        for changes in ({"status": "DENIED", "effect_count": 0}, {"status": "UNKNOWN"},
                        {"effect_count": 0}, {"effect_count": 2}, {"effect_count": True}):
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit, **changes))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_endpoint_signature_and_domain_are_independently_checked(self):
        proposed, authorization, permit = self._permitted()
        wrong_key = signed_terminal(proposed, authorization, permit, key=AUTHORITY_KEY)
        wrong_domain = signed_terminal(proposed, authorization, permit)
        private, _ = _crypto()
        wrong_domain["signature"] = private.from_private_bytes(ENDPOINT_KEY).sign(
            b"another-domain\x00" + canonical_bytes({k: v for k, v in wrong_domain.items() if k != "signature"})).hex()
        for terminal in (wrong_key, wrong_domain):
            with self.subTest(terminal=terminal), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], terminal)

    def test_endpoint_signed_receipt_requires_every_persisted_action_binding(self):
        proposed, authorization, permit = self._permitted()
        mutations = [{"action_id": "other"}, {"attempt_id": "other"}, {"root_id": "other"},
                     {"execution_id": "other"}, {"epoch": 2}, {"epoch": True},
                     {"endpoint_id": "other"}, {"key_id": "other"}, {"reservation_id": "other"},
                     {"action_digest": "c" * 64}, {"authorization_digest": "c" * 64},
                     {"body_digest": "c" * 64}, {"schema": "other"}, {"committed_at": -1}]
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit, **changes))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_extra_missing_or_tampered_receipt_field_is_rejected(self):
        proposed, authorization, permit = self._permitted()
        terminal = signed_terminal(proposed, authorization, permit)
        missing = {k: v for k, v in terminal.items() if k != "body_digest"}
        extra = {**terminal, "gateway_claim": "success"}
        tampered = {**terminal, "effect_count": 0}
        for receipt in (missing, extra, tampered):
            with self.subTest(receipt=receipt), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], receipt)

    def test_terminal_is_immutable_and_retry_settles_without_new_admission(self):
        proposed, authorization, permit = self._permitted()
        terminal = signed_terminal(proposed, authorization, permit)
        first = self.store.finish(permit["reservation_id"], terminal)
        self.assertEqual(self._open().finish(permit["reservation_id"], terminal), first)
        with self.assertRaisesRegex(ControlError, "TERMINAL_IMMUTABLE"):
            self.store.finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit, committed_at=101))
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_cross_reservation_endpoint_receipt_cannot_settle_another_action(self):
        one, authorization_one, permit_one = self._permitted("one")
        _, _, permit_two = self._permitted("two")
        with self.assertRaises(ControlError):
            self.store.finish(permit_two["reservation_id"], signed_terminal(one, authorization_one, permit_one))
        self.assertEqual(self.store.status("root")["pending_count"], 2)

    def test_network_begin_validates_complete_exact_post_shape_before_admission(self):
        valid = action()
        variations = [
            {**valid, "target": "records"},
            {**valid, "arguments": {**valid["arguments"], "method": "GET"}},
            {**valid, "arguments": {**valid["arguments"], "url": "http://localhost:49152/v1/record"}},
            {**valid, "arguments": {**valid["arguments"], "url": "http://127.0.0.1:49152/v1/record?redirect=1"}},
            {**valid, "arguments": {**valid["arguments"], "body": {"secret": "synthetic"}}},
            {**valid, "arguments": {**valid["arguments"], "headers": {"X-Arbitrary": "extra"}}},
        ]
        for proposed in variations:
            with self.subTest(proposed=proposed), self.assertRaises(ControlError):
                self.store.begin(proposed, grant(proposed))
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_concurrent_begin_issues_only_one_network_permit(self):
        proposed = action()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self._open().begin(proposed, grant(proposed)), range(8)))
        self.assertEqual(sum(result["status"] == "PERMITTED" for result in results), 1)
        self.assertEqual(sum(result["status"] == "UNKNOWN" for result in results), 7)

    def test_external_grant_time_is_sampled_after_writer_lock(self):
        blocker = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")
        proposed = action()
        started = threading.Event()
        def begin():
            started.set()
            return self.store.begin(proposed, grant(proposed, expires_at=101))
        with ThreadPoolExecutor(max_workers=1) as pool:
            waiting = pool.submit(begin)
            self.assertTrue(started.wait(1))
            self.now = 102
            blocker.execute("COMMIT")
            result = waiting.result(timeout=3)
        self.assertEqual(result["reason"], "EXTERNAL_AUTHORITY_EXPIRED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_public_checkpoint_chain_retains_endpoint_terminal_digest(self):
        proposed, authorization, permit = self._permitted()
        terminal = signed_terminal(proposed, authorization, permit)
        self.store.finish(permit["reservation_id"], terminal)
        entries = self.store.checkpoints()
        self.assertEqual(entries[-1]["receipt_digest"], digest(terminal))
        pin = self.store.pin()
        report = verify_checkpoint_chain(entries, **pin, signer_id=pin["authority_id"])
        self.assertEqual(report["verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertFalse(report["execution_authorized"])

    def test_http_roles_preserve_signed_negative_cross_profile_result(self):
        server = make_server(self.store, OPERATOR_KEY, REQUEST_KEY)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = HTTPExternalAuthorityClient("http://127.0.0.1:" + str(server.server_address[1]), REQUEST_KEY, self.store.pin())
        proposed, authorization, permit = self._permitted()
        with self.assertRaises(ControlError):
            client.finish(permit["reservation_id"], sign_document({"status": "COMMITTED"}, RECEIPT_KEY))
        self.assertEqual(client.last_statement["result"]["status"], "ERROR")
        self.assertEqual(client.evidence[-1]["request"]["operation"], "finish")
        with self.assertRaisesRegex(ControlError, "ROLE_DENIED"):
            client.stop("root")
        self.assertEqual(client.finish(permit["reservation_id"], signed_terminal(proposed, authorization, permit))["status"], "SETTLED")


if __name__ == "__main__":
    unittest.main()
