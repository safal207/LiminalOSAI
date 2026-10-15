"""Actual receiver effects against a separate, authenticated HTTP authority.

Faults are placed at the BEGIN/COMMIT/FINISH boundaries, where missing replies
must not become fresh permission or evidence that an effect never occurred.
"""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sdk.liminal_agent_control import ControlError, HTTPReceiverClient, Receiver, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.external_authority import ExternalAuthorityStore
from sdk.liminal_agent_control.external_authority_service import (
    HTTPExternalAuthorityClient, make_server as make_external_server,
)
from sdk.liminal_agent_control.receiver import make_server as make_receiver_server


BROKER_KEY = b"external-test-broker-owned-key-0001" * 2
RECEIPT_KEY = b"external-test-receipt-owned-key-0002" * 2
OPERATOR_KEY = b"external-test-operator-owned-key-0003" * 2
REQUEST_KEY = b"external-test-receiver-request-key-0004" * 2
SIGNING_KEY = b"\x15" * 32
POLICY = "a" * 64


def action(name="record", *, execution_id="worker", epoch=1):
    return {"action_id": name, "attempt_id": "attempt:" + name,
            "root_id": "root", "execution_id": execution_id, "epoch": epoch,
            "target": "records", "arguments": {"value": name}}


class ExternalReceiverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "receiver.sqlite"
        self.external_path = self.directory / "external" / "authority.sqlite"
        self.local_now = 100.0
        self.external_now = time.time()
        self.store = ExternalAuthorityStore(
            self.external_path, authority_id="controller", key_id="controller-key",
            private_key=SIGNING_KEY, receipt_key=RECEIPT_KEY,
            clock=lambda: self.external_now,
        )
        self.server = make_external_server(
            self.store, operator_key=OPERATOR_KEY, receiver_key=REQUEST_KEY,
        )
        self.start_server(self.server)
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        self.client = HTTPExternalAuthorityClient(
            self.url, REQUEST_KEY, self.store.pin(), role="receiver",
        )
        self.local = SessionAuthority(self.path, clock=lambda: self.local_now)
        self.receiver = Receiver(
            self.path, BROKER_KEY, RECEIPT_KEY,
            admission_controller=self.local, external_controller=self.client,
        )
        self.local.create_session(
            "root", controller_id="host", policy_digest=POLICY,
            objective_digest="b" * 64, max_actions=16, max_executions=4,
            max_depth=2, max_stages=4, lifetime_seconds=3600, lease_seconds=3600,
        )
        self.receiver.bind_execution("root", "worker")
        self.store.create_root("root", self.receiver.receiver_id, POLICY, 16, 3600)
        self.store.bind_execution("root", "worker")

    def start_server(self, server):
        thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.01), daemon=True,
        )
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(3)
            self.assertFalse(thread.is_alive(), "HTTP authority thread leaked")

        self.addCleanup(close)

    def grant(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": POLICY,
                "expires_at": self.external_now + 60,
                "receiver_id": self.receiver.receiver_id}

    def commit(self, proposed, grant=None):
        return self.receiver.commit(
            proposed, authorization=self.grant(proposed) if grant is None else grant,
        )

    def reopen(self):
        self.local = SessionAuthority(self.path, clock=lambda: self.local_now)
        self.receiver = Receiver(
            self.path, BROKER_KEY, RECEIPT_KEY,
            admission_controller=self.local, external_controller=self.client,
        )

    def save_local(self):
        snapshot = self.directory / "before.sqlite"
        with sqlite3.connect(self.path) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
        return snapshot

    def restore_local(self, snapshot):
        with sqlite3.connect(snapshot) as source, sqlite3.connect(self.path) as target:
            source.backup(target)
        self.reopen()

    def test_positive_http_permit_commits_one_effect_and_consumption_survives_reopen(self):
        proposed = action()
        grant = self.grant(proposed)
        receipt = self.commit(proposed, grant)
        self.assertEqual(receipt["status"], "COMMITTED")
        self.assertEqual(receipt["enforcement_profile"], "external_governed_v1")
        self.assertTrue(self.receiver.verify_receipt(receipt))
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.store.status("root")["committed_count"], 1)
        self.assertEqual(self.store.status("root")["pending_count"], 0)
        self.reopen()
        self.assertEqual(self.commit(proposed, grant), receipt)
        self.assertEqual(self.receiver.query(proposed["action_id"]), receipt)
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_acknowledged_stop_survives_restore_of_old_local_database_and_clock(self):
        snapshot = self.save_local()
        stopped = self.store.stop("root")
        self.assertEqual((stopped["status"], stopped["epoch"]), ("STOPPED", 2))
        self.local_now = 101.0
        self.restore_local(snapshot)
        self.local_now = 100.0
        receipt = self.commit(action("restored-worker"))
        self.assertEqual(receipt["status"], "DENIED")
        self.assertEqual(receipt["reason"], "EXTERNAL_AUTHORITY_STOPPED")
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["state"], "STOPPED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_delayed_permit_across_stop_keeps_stop_pending_until_actual_commit(self):
        received, release = threading.Event(), threading.Event()
        original_begin = self.client.begin
        results, errors = [], []

        def delayed_begin(proposed, authorization):
            permit = original_begin(proposed, authorization)
            self.assertEqual(permit["status"], "PERMITTED")
            received.set()
            if not release.wait(5):
                raise RuntimeError("test failed to release the received permit")
            return permit

        def commit_in_thread():
            try:
                results.append(self.commit(action("inflight")))
            except BaseException as exc:
                errors.append(exc)

        with patch.object(self.client, "begin", side_effect=delayed_begin):
            thread = threading.Thread(target=commit_in_thread)
            thread.start()
            try:
                self.assertTrue(received.wait(3))
                stopped = self.store.stop("root")
                self.assertEqual((stopped["status"], stopped["epoch"]), ("STOP_PENDING", 2))
                self.assertEqual(stopped["pending_count"], 1)
                self.assertEqual(stopped["committed_count"], 0)
                self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
            finally:
                release.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0]["status"], "COMMITTED")
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.store.status("root")["state"], "STOPPED")
        self.assertEqual(self.store.status("root")["pending_count"], 0)
        self.assertEqual(self.commit(action("after-ack"))["status"], "DENIED")
        self.assertEqual(len(self.receiver.records()), 1)

    def test_lost_begin_reply_never_reissues_permit_or_acknowledges_quiescence(self):
        proposed = action("lost-begin")
        grant = self.grant(proposed)
        original_begin = self.client.begin

        def lose_reply(candidate, authorization):
            original_begin(candidate, authorization)
            raise ControlError("simulated lost BEGIN reply")

        with patch.object(self.client, "begin", side_effect=lose_reply):
            first = self.commit(proposed, grant)
        self.assertEqual(first["status"], "UNKNOWN")
        self.assertIsNone(first["effect_count"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["pending_count"], 1)
        self.reopen()
        self.assertEqual(self.commit(proposed, grant)["status"], "UNKNOWN")
        self.assertEqual(self.store.status("root")["issued_count"], 1)
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.external_now += 100000
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self.store.status("root")["pending_count"], 1)
        self.assertEqual(self.receiver.records(), [])

    def test_lost_finish_reply_recovers_actual_committed_receipt_without_new_effect(self):
        proposed = action("lost-finish")
        grant = self.grant(proposed)
        original_finish = self.client.finish

        def lose_reply(reservation_id, receipt):
            original_finish(reservation_id, receipt)
            raise ControlError("simulated lost FINISH reply")

        with patch.object(self.client, "finish", side_effect=lose_reply):
            first = self.commit(proposed, grant)
        self.assertEqual(first["status"], "UNKNOWN")
        self.assertIsNone(first["effect_count"])
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.store.status("root")["committed_count"], 1)
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        self.reopen()
        recovered = self.receiver.query(proposed["action_id"])
        self.assertEqual(recovered["status"], "COMMITTED")
        self.assertTrue(self.receiver.verify_receipt(recovered))
        self.assertEqual(self.commit(proposed, grant), recovered)
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_crash_after_begin_before_local_commit_keeps_external_permit_unresolved(self):
        proposed = action("crash-before-commit")
        grant = self.grant(proposed)
        with patch.object(self.receiver, "_finalize", side_effect=RuntimeError("receiver crash")):
            first = self.commit(proposed, grant)
        self.assertEqual(first["status"], "UNKNOWN")
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.local.status("root")["action_count"], 0)
        self.assertEqual(self.store.status("root")["pending_count"], 1)
        self.reopen()
        self.assertEqual(self.receiver.query(proposed["action_id"])["status"], "UNKNOWN")
        self.assertEqual(self.commit(proposed, grant)["status"], "UNKNOWN")
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_consumed_action_cannot_execute_again_after_old_local_snapshot_is_restored(self):
        snapshot = self.save_local()
        proposed = action("consumed-before-restore")
        grant = self.grant(proposed)
        self.assertEqual(self.commit(proposed, grant)["status"], "COMMITTED")
        self.assertEqual(len(self.receiver.records()), 1)
        self.restore_local(snapshot)
        self.assertEqual(self.receiver.records(), [])
        receipt = self.commit(proposed, grant)
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertIsNone(receipt["effect_count"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["committed_count"], 1)
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_external_time_rejects_expired_grant_even_with_old_local_clock(self):
        proposed = action("expired-grant")
        grant = self.grant(proposed)
        self.external_now = grant["expires_at"] + 1
        self.local_now = 100.0
        receipt = self.commit(proposed, grant)
        self.assertEqual(receipt["status"], "DENIED")
        self.assertEqual(receipt["reason"], "EXTERNAL_AUTHORITY_EXPIRED")
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_external_outage_preserves_unknown_and_has_no_record_effect(self):
        # Close admission transport before BEGIN; no timeout is interpreted as
        # permission. The independently owned controller remains inspectable.
        self.server.shutdown()
        self.server.server_close()
        receipt = self.commit(action("service-unavailable"))
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertIsNone(receipt["effect_count"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_misbound_new_permit_leaves_unknown_and_does_not_execute(self):
        original_begin = self.client.begin

        def misbound(proposed, authorization):
            permit = original_begin(proposed, authorization)
            return {**permit, "receiver_id": "receiver:wrong"}

        with patch.object(self.client, "begin", side_effect=misbound):
            receipt = self.commit(action("wrong-permit"))
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertEqual(receipt["reason"], "EXTERNAL_PERMIT_BINDING_MISMATCH")
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")

    def test_external_profile_disables_split_accept_finalize_and_receiver_owned_stop_over_http(self):
        server = make_receiver_server(self.receiver)
        self.start_server(server)
        host, port = server.server_address
        client = HTTPReceiverClient(f"http://{host}:{port}", BROKER_KEY, RECEIPT_KEY)
        proposed = action("split-bypass")
        for attempt, reason in (
            (lambda: client.accept(proposed, authorization=self.grant(proposed)), "atomic commit only"),
            (lambda: client.finalize(proposed["action_id"]), "atomic commit only"),
            (lambda: client.revoke("root"), "separate operator controller"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ControlError, reason):
                attempt()
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.store.status("root")["issued_count"], 0)
        self.assertEqual(self.store.status("root")["state"], "ACTIVE")

    def test_external_profile_cannot_downgrade_or_change_persisted_trust_configuration(self):
        with self.assertRaisesRegex(ControlError, "profile is immutable"):
            Receiver(self.path, BROKER_KEY, RECEIPT_KEY, admission_controller=self.local)
        with self.assertRaisesRegex(ControlError, "profile is immutable"):
            Receiver(self.path, BROKER_KEY, RECEIPT_KEY)

        altered = [
            ("authority pin", HTTPExternalAuthorityClient(
                self.url, REQUEST_KEY, {**self.store.pin(), "authority_id": "other"}, role="receiver"),
             BROKER_KEY, RECEIPT_KEY),
            ("request key", HTTPExternalAuthorityClient(
                self.url, b"different-external-request-key-0005" * 2, self.store.pin(), role="receiver"),
             BROKER_KEY, RECEIPT_KEY),
            ("endpoint", HTTPExternalAuthorityClient(
                "http://127.0.0.1:1", REQUEST_KEY, self.store.pin(), role="receiver"),
             BROKER_KEY, RECEIPT_KEY),
            ("broker key", self.client, b"different-broker-key-owned-000006" * 2, RECEIPT_KEY),
            ("receipt key", self.client, BROKER_KEY, b"different-receipt-key-owned-000007" * 2),
        ]
        for label, controller, broker_key, receipt_key in altered:
            with self.subTest(configuration=label), self.assertRaisesRegex(ControlError, "configuration is immutable"):
                Receiver(self.path, broker_key, receipt_key,
                         admission_controller=self.local, external_controller=controller)
        self.assertEqual(self.commit(action("unchanged-config"))["status"], "COMMITTED")

    def test_removing_live_controller_cannot_route_persisted_external_profile_into_legacy(self):
        committed = action("before-controller-removal")
        self.assertEqual(self.commit(committed)["status"], "COMMITTED")
        proposed = action("after-controller-removal")
        grant = self.grant(proposed)
        with patch.object(self.receiver, "external_controller", None):
            attempts = (
                ("commit", lambda: self.receiver.commit(proposed, authorization=grant)),
                ("accept", lambda: self.receiver.accept(proposed, authorization=grant)),
                ("finalize", lambda: self.receiver.finalize(proposed["action_id"])),
                ("revoke", lambda: self.receiver.revoke("root")),
                ("query", lambda: self.receiver.query(committed["action_id"])),
            )
            for boundary, attempt in attempts:
                with self.subTest(boundary=boundary), self.assertRaisesRegex(
                    ControlError, "configuration is immutable",
                ):
                    attempt()
            self.assertEqual(len(self.receiver.records()), 1)
            state = self.store.status("root")
            self.assertEqual((state["issued_count"], state["committed_count"]), (1, 1))
            self.assertEqual(state["state"], "ACTIVE")
        # Returning the exact original controller restores operation; the
        # failed mutation attempts never consumed the prepared fresh action.
        self.assertEqual(self.commit(proposed, grant)["status"], "COMMITTED")
        self.assertEqual(len(self.receiver.records()), 2)

    def test_mutated_live_client_configuration_fails_before_authority_or_effect_boundaries(self):
        committed = action("before-client-mutations")
        self.assertEqual(self.commit(committed)["status"], "COMMITTED")
        changes = (
            ("role", self.client, "role", "admin"),
            ("endpoint", self.client, "url", "http://127.0.0.1:1"),
            ("authority identity", self.client, "_pin", {**self.store.pin(), "authority_id": "other"}),
            ("signer key", self.client, "_pin", {**self.store.pin(), "public_key": "44" * 32}),
            ("request key", self.client, "_request_key", b"mutated-external-request-key-0008" * 2),
            ("broker key", self.receiver, "broker_key", b"mutated-broker-key-owned-0000009" * 2),
            ("receipt key", self.receiver, "receipt_key", b"mutated-receipt-key-owned-000010" * 2),
        )
        for index, (label, target, attribute, value) in enumerate(changes):
            proposed = action(f"after-client-mutation-{index}")
            grant = self.grant(proposed)
            with self.subTest(configuration=label), patch.object(target, attribute, value):
                attempts = (
                    ("commit", lambda: self.receiver.commit(proposed, authorization=grant)),
                    ("accept", lambda: self.receiver.accept(proposed, authorization=grant)),
                    ("finalize", lambda: self.receiver.finalize(proposed["action_id"])),
                    ("revoke", lambda: self.receiver.revoke("root")),
                    ("query", lambda: self.receiver.query(committed["action_id"])),
                )
                for boundary, attempt in attempts:
                    with self.subTest(boundary=boundary), self.assertRaisesRegex(
                        ControlError, "configuration is immutable",
                    ):
                        attempt()
                self.assertEqual(len(self.receiver.records()), 1)
                state = self.store.status("root")
                self.assertEqual((state["issued_count"], state["committed_count"]), (1, 1))
                self.assertEqual(state["state"], "ACTIVE")
        self.assertEqual(self.commit(action("restored-client"))["status"], "COMMITTED")
        self.assertEqual(len(self.receiver.records()), 2)


if __name__ == "__main__":
    unittest.main()
