"""Controlled record effects share the durable session transaction and budget."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sdk.liminal_agent_control import Broker, ControlError, HTTPReceiverClient, Receiver, digest
from sdk.liminal_agent_control.authority import AuthorityStore, connect
from sdk.liminal_agent_control.brakes_store import SessionAuthority


BROKER_KEY = b"brakes-test-broker-key-owned-only" * 2
RECEIPT_KEY = b"brakes-test-receipt-key-owned-only" * 2


def action(name="record", execution_id="worker"):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
            "execution_id": execution_id, "epoch": 1, "target": "records", "arguments": {"value": name}}


class BrakesReceiverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db_path = self.directory / "authority.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.db_path, clock=lambda: self.now)
        self.receiver = Receiver(self.db_path, BROKER_KEY, RECEIPT_KEY, admission_controller=self.authority)
        self.authority.create_session("root", controller_id="host", policy_digest="a" * 64,
            objective_digest="b" * 64, max_actions=2, max_executions=2, max_depth=1,
            max_stages=4, lifetime_seconds=120, lease_seconds=10)
        self.receiver.bind_execution("root", "worker")

    def authorization(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": "a" * 64,
                "expires_at": time.time() + 60, "receiver_id": self.receiver.receiver_id}

    def commit(self, proposed):
        return self.receiver.commit(proposed, authorization=self.authorization(proposed))

    def test_exact_broker_grant_commits_with_shared_budget_and_authenticated_profile(self):
        broker = Broker(self.directory / "broker.sqlite", self.receiver)
        proposed = action()
        broker.authorize(proposed, policy_version="a" * 64)
        result = broker.handle(proposed)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["receipt"]["enforcement_profile"], "governed_v1")
        self.assertTrue(self.receiver.verify_receipt(result["receipt"]))
        state = self.authority.status("root")
        self.assertEqual((state["action_count"], state["pending_action_count"]), (1, 0))
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.receiver.commit(proposed), result["receipt"])
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_no_grant_or_wrong_exact_grant_never_reserves_capacity(self):
        proposed = action()
        self.assertEqual(self.receiver.commit(proposed)["reason"], "GRANT_REQUIRED")
        wrong = self.authorization(action("different"))
        self.assertEqual(self.receiver.commit(proposed, authorization=wrong)["reason"], "GRANT_BINDING_MISMATCH")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.receiver.records(), [])

    def test_grant_policy_must_match_immutable_session_policy(self):
        proposed = action()
        grant = {**self.authorization(proposed), "policy_version": "c" * 64}
        self.assertEqual(self.receiver.commit(proposed, authorization=grant)["reason"], "POLICY_MISMATCH")
        label_only = {**grant, "policy_version": "unbound-label"}
        self.assertEqual(self.receiver.commit(proposed, authorization=label_only)["status"], "DENIED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.receiver.records(), [])

    def test_stop_closes_records_and_egress_and_survives_reopen(self):
        self.receiver.bind_execution("root", "child", "worker")
        ack = self.receiver.revoke("root")
        self.assertTrue(self.receiver.verify_receipt(ack))
        self.assertEqual((ack["status"], ack["epoch"], ack["session_state"]), ("REVOKED", 2, "STOPPED"))
        restarted_authority = SessionAuthority(self.db_path, clock=lambda: self.now)
        self.receiver = Receiver(self.db_path, BROKER_KEY, RECEIPT_KEY, admission_controller=restarted_authority)
        self.assertEqual(self.commit(action("late", "child"))["reason"], "AUTHORITY_REVOKED")
        self.assertEqual(restarted_authority.reserve(action("network"), channel="egress")["status"], "BLOCKED")
        self.assertEqual(self.receiver.revoke("root")["epoch"], 2)
        self.assertEqual(self.receiver.records(), [])

    def test_governed_profile_cannot_be_reopened_without_controller_or_downgraded(self):
        for enforce_epoch in (True, False):
            with self.subTest(enforce_epoch=enforce_epoch), self.assertRaisesRegex(ControlError, "profile is immutable"):
                Receiver(self.db_path, BROKER_KEY, RECEIPT_KEY, enforce_epoch=enforce_epoch)
        with self.assertRaisesRegex(ControlError, "epoch enforcement"):
            Receiver(self.db_path, BROKER_KEY, RECEIPT_KEY, enforce_epoch=False, admission_controller=self.authority)
        other = SessionAuthority(self.directory / "other.sqlite")
        with self.assertRaisesRegex(ControlError, "same authority database"):
            Receiver(self.db_path, BROKER_KEY, RECEIPT_KEY, admission_controller=other)
        self.assertEqual(self.commit(action())["status"], "COMMITTED")

    def test_existing_legacy_profile_cannot_be_silently_upgraded(self):
        path = self.directory / "legacy.sqlite"
        Receiver(path, BROKER_KEY, RECEIPT_KEY)
        with self.assertRaisesRegex(ControlError, "profile is immutable"):
            Receiver(path, BROKER_KEY, RECEIPT_KEY, admission_controller=SessionAuthority(path))

    def test_roots_require_explicit_session_and_raw_authority_binding_does_not_admit(self):
        with self.assertRaisesRegex(ControlError, "create_session"):
            self.receiver.create_root("another")
        raw = AuthorityStore(self.db_path)
        raw.bind_execution("root", "unregistered", "worker")
        result = self.commit(action("bypass", "unregistered"))
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "EXECUTION_NOT_REGISTERED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_controlled_binding_enforces_fanout_and_depth(self):
        self.receiver.bind_execution("root", "child", "worker")
        with self.assertRaisesRegex(ControlError, "EXECUTION_BUDGET_EXHAUSTED"):
            self.receiver.bind_execution("root", "sibling", "worker")
        with self.assertRaisesRegex(ControlError, "EXECUTION_DEPTH_EXCEEDED"):
            self.receiver.bind_execution("root", "grandchild", "child")

    def test_record_and_egress_actions_share_permanent_capacity(self):
        self.assertEqual(self.commit(action("first"))["status"], "COMMITTED")
        network = {**action("network"), "target": "egress"}
        self.assertEqual(self.authority.reserve(network, channel="egress")["status"], "ADMITTED")
        self.authority.finish_action("network", outcome="UNKNOWN")
        self.assertEqual(self.commit(action("overflow"))["reason"], "ACTION_BUDGET_EXHAUSTED")
        restarted = SessionAuthority(self.db_path, clock=lambda: self.now)
        self.assertEqual(restarted.status("root")["remaining_actions"], 0)
        self.assertEqual(len(self.receiver.records()), 1)

    def test_record_cannot_reuse_identity_reserved_for_egress(self):
        proposed = action()
        self.assertEqual(self.authority.reserve(proposed, channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.commit(proposed)["reason"], "ACTION_BINDING_MISMATCH")
        self.assertEqual(self.receiver.records(), [])

    def test_preaccepted_record_completes_after_stop_without_new_admission(self):
        proposed = action()
        accepted = self.receiver.accept(proposed, authorization=self.authorization(proposed))
        self.assertEqual(accepted["status"], "ACCEPTED")
        self.assertEqual(self.authority.status("root")["pending_action_count"], 1)
        self.receiver.revoke("root")
        committed = self.receiver.finalize(proposed["action_id"])
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertEqual(self.authority.status("root")["pending_action_count"], 0)
        self.assertEqual(self.authority.status("root")["action_count"], 1)
        self.assertEqual(self.receiver.finalize(proposed["action_id"]), committed)
        self.assertEqual(self.commit(action("after"))["status"], "DENIED")
        self.assertEqual(len(self.receiver.records()), 1)

    def test_queued_accept_reads_session_clock_after_database_lock(self):
        entered, finished = threading.Event(), threading.Event()
        results = []
        proposed = action()
        authorization = self.authorization(proposed)

        def attempt():
            entered.set()
            try:
                results.append(self.receiver.commit(proposed, authorization=authorization))
            finally:
                finished.set()

        lock = connect(self.db_path)
        lock.execute("BEGIN IMMEDIATE")
        thread = threading.Thread(target=attempt)
        try:
            thread.start()
            self.assertTrue(entered.wait(2))
            self.assertFalse(finished.wait(0.05))
            self.now = 111.0
        finally:
            lock.commit()
            lock.close()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["reason"], "LEASE_EXPIRED")
        self.assertEqual(self.authority.status("root")["state"], "EXPIRED")
        self.assertEqual(self.receiver.records(), [])

    def test_receiver_failure_rolls_back_record_and_its_budget_reservation(self):
        with connect(self.db_path) as db:
            db.execute("CREATE TRIGGER reject_owned_effect BEFORE INSERT ON effects BEGIN SELECT RAISE(ABORT,'owned failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.commit(action())
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.receiver.query("record")["status"], "UNKNOWN")
        self.assertEqual(self.receiver.records(), [])

    def test_real_receiver_process_requires_governed_flag_and_preserves_identity(self):
        # A real fresh process opens the same durable service, using the wall
        # clock profile that a deployed service uses, rather than our fake clock.
        path = self.directory / "live.sqlite"
        authority = SessionAuthority(path)
        receiver = Receiver(path, BROKER_KEY, RECEIPT_KEY, admission_controller=authority)
        authority.create_session("root", controller_id="host", policy_digest="a" * 64,
            objective_digest="b" * 64, max_actions=1, max_executions=1, max_depth=0,
            max_stages=0, lifetime_seconds=60, lease_seconds=60)
        receiver.bind_execution("root", "worker")
        broker_key, receipt_key = self.directory / "broker.key", self.directory / "receipt.key"
        broker_key.write_bytes(BROKER_KEY)
        receipt_key.write_bytes(RECEIPT_KEY)
        command = [sys.executable, "-m", "sdk.liminal_agent_control.receiver", "--db", str(path),
            "--broker-key-file", str(broker_key), "--receipt-key-file", str(receipt_key)]
        wrong = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("profile is immutable", wrong.stderr)
        process = subprocess.Popen(command + ["--governed"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            endpoint = json.loads(process.stdout.readline())
            client = HTTPReceiverClient(endpoint["url"], BROKER_KEY, RECEIPT_KEY)
            self.assertEqual(client.identity()["receiver_id"], receiver.receiver_id)
            broker = Broker(self.directory / "http-broker.sqlite", client)
            broker.authorize(action(), policy_version="a" * 64)
            self.assertEqual(broker.handle(action())["status"], "COMMITTED")
            self.assertEqual(authority.status("root")["remaining_actions"], 0)
        finally:
            process.terminate()
            process.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
