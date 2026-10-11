"""Owned localhost / dummy-record tests; no model, production service or secret."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sdk.liminal_agent_control import Broker, ControlError, HTTPReceiverClient, Receiver, digest, verify_receipt

BROKER_KEY = b"test-broker-key-no-secret-material" * 2
RECEIPT_KEY = b"test-receiver-key-no-secret-material" * 2


def action(name="a", execution_id="worker", root_id="root"):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": root_id,
            "execution_id": execution_id, "epoch": 1, "target": "records", "arguments": {"value": "dummy"}}


class AgentControlAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp_path = Path(temporary.name)
        self.receiver = Receiver(self.tmp_path / "receiver.sqlite", BROKER_KEY, RECEIPT_KEY)
        self.receiver.create_root("root")
        self.receiver.bind_execution("root", "worker")

    def test_authorized_exact_effect_and_idempotent_receiver(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        broker = Broker(tmp_path / "broker.sqlite", receiver)
        proposed = action()
        broker.authorize(proposed)
        result = broker.handle(proposed)
        self.assertTrue(result["status"] == "COMMITTED")
        self.assertTrue(verify_receipt(result["receipt"], RECEIPT_KEY))
        self.assertTrue(result["receipt"]["action_digest"] == digest(proposed))
        self.assertTrue(broker.handle(proposed)["reason"] == "ACTION_ALREADY_CONSUMED")
        self.assertTrue(receiver.commit(proposed) == result["receipt"])
        self.assertTrue(len(receiver.records()) == 1)

    def test_mutated_authorization_blocked(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        cases = [
            ("arguments", {"value": "changed"}), ("target", "network"),
            ("execution_id", "other"), ("root_id", "other"),
            ("attempt_id", "retry"), ("epoch", 2),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                broker = Broker(tmp_path / "broker.sqlite", receiver)
                original = action()
                broker.authorize(original)
                changed = {**original, field: value}
                self.assertTrue(broker.handle(changed)["status"] == "BLOCKED")
                self.assertTrue(receiver.records() == [])

    def test_malformed_proposals_fail_closed(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        mutations = [
            lambda a: a.update(extra=True),
            lambda a: a.update(epoch=True),
            lambda a: a.update(arguments={"bad": float("nan")}),
            lambda a: a.update(arguments={"bad": float("inf")}),
            lambda a: a.update(arguments={1: "non-string-key"}),
            lambda a: a.update(action_id=""),
        ]
        for case_index, mutate in enumerate(mutations):
            with self.subTest(case=case_index):
                broker = Broker(tmp_path / "broker.sqlite", receiver)
                proposed = action()
                mutate(proposed)
                self.assertTrue(broker.handle(proposed)["status"] == "BLOCKED")
                with self.assertRaises(ControlError):
                    receiver.commit(proposed)
                self.assertTrue(receiver.records() == [])

    def test_revoke_ack_survives_restart_and_blocks_entire_descendant_tree(self):
        receiver = self.receiver
        receiver.bind_execution("root", "child", "worker")
        receiver.bind_execution("root", "grandchild", "child")
        ack = receiver.revoke("root")
        self.assertTrue(ack["status"] == "REVOKED" and ack["epoch"] == 2)
        restarted = Receiver(receiver.db_path, BROKER_KEY, RECEIPT_KEY)
        for child in ("worker", "child", "grandchild"):
            result = restarted.commit(action(child, execution_id=child))
            self.assertTrue(result["status"] == "DENIED")
            self.assertTrue(result["reason"] == "AUTHORITY_REVOKED")
        self.assertTrue(restarted.revoke("root")["epoch"] == 2)
        with self.assertRaises(ControlError):
            restarted.create_root("root")
        self.assertTrue(restarted.records() == [])

    def test_execution_cannot_self_rebind_or_cross_parent(self):
        receiver = self.receiver
        receiver.create_root("other")
        with self.assertRaises(ControlError):
            receiver.bind_execution("other", "child", "worker")
        with self.assertRaises(ControlError):
            receiver.bind_execution("other", "worker")
        self.assertTrue(receiver.commit(action(root_id="other"))["reason"] == "EXECUTION_BINDING_MISMATCH")

    def test_accepted_before_revoke_can_complete_but_later_accept_cannot(self):
        receiver = self.receiver
        accepted = receiver.accept(action())
        self.assertTrue(accepted["status"] == "ACCEPTED")
        ack = receiver.revoke("root")
        late = receiver.accept(action("late"))
        committed = receiver.finalize("a")
        self.assertTrue(late["status"] == "DENIED")
        self.assertTrue(committed["status"] == "COMMITTED")
        self.assertTrue(committed["accepted_at"] <= ack["revoked_at"] <= committed["observed_at"])
        self.assertTrue(len(receiver.records()) == 1)

    def test_parallel_receiver_retries_commit_once(self):
        receiver = self.receiver
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(lambda _: receiver.commit(action()), range(16)))
        self.assertTrue({r["status"] for r in receipts} == {"COMMITTED"})
        self.assertTrue(len(receiver.records()) == 1)

    def test_competing_acceptance_and_revocation_have_one_durable_order(self):
        receiver = self.receiver
        for trial in range(16):
            with self.subTest(trial=trial):
                root_id = f"race-root:{trial}"
                execution_id = f"race-worker:{trial}"
                receiver.create_root(root_id)
                receiver.bind_execution(root_id, execution_id)
                proposed = action(f"race-action:{trial}", execution_id, root_id)
                start = threading.Barrier(3)

                def accept():
                    start.wait(timeout=5)
                    return receiver.accept(proposed)

                def revoke():
                    start.wait(timeout=5)
                    return receiver.revoke(root_id)

                with ThreadPoolExecutor(max_workers=2) as pool:
                    accepting = pool.submit(accept)
                    revoking = pool.submit(revoke)
                    start.wait(timeout=5)
                    admitted = accepting.result(timeout=30)
                    ack = revoking.result(timeout=30)

                self.assertIn(admitted["status"], {"ACCEPTED", "DENIED"})
                self.assertEqual(ack["status"], "REVOKED")
                self.assertEqual(ack["epoch"], 2)
                self.assertTrue(receiver.verify_receipt(admitted))
                self.assertTrue(receiver.verify_receipt(ack))
                restarted = Receiver(receiver.db_path, BROKER_KEY, RECEIPT_KEY)
                self.assertEqual(restarted.revoke(root_id)["epoch"], 2)
                later = action(f"race-later:{trial}", execution_id, root_id)
                self.assertEqual(restarted.accept(later)["reason"], "AUTHORITY_REVOKED")

                if admitted["status"] == "ACCEPTED":
                    # Admission won the SQLite write ordering. Completion may
                    # follow the ack because revocation does not undo admission.
                    self.assertLessEqual(admitted["accepted_at"], ack["revoked_at"])
                    self.assertEqual(admitted["accepted_epoch"], 1)
                    self.assertEqual(restarted.query(proposed["action_id"])["status"], "ACCEPTED")
                    committed = restarted.finalize(proposed["action_id"])
                    self.assertEqual(committed["status"], "COMMITTED")
                    self.assertEqual(committed["effect_count"], 1)
                    self.assertEqual(restarted.finalize(proposed["action_id"]), committed)
                    expected_effects = 1
                else:
                    # Revocation won. No accepted slot exists to finalize later.
                    self.assertEqual(admitted["reason"], "AUTHORITY_REVOKED")
                    self.assertEqual(restarted.query(proposed["action_id"])["status"], "UNKNOWN")
                    self.assertEqual(restarted.finalize(proposed["action_id"])["status"], "UNKNOWN")
                    expected_effects = 0
                snapshot = restarted.snapshot(root_id, execution_id)
                self.assertEqual(snapshot["epoch"], 2)
                self.assertEqual(len(snapshot["receipts"]), expected_effects)
                self.assertEqual(snapshot["accepted_action_ids"], [])

    def test_parallel_brokers_share_durable_reservation(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        path = tmp_path / "broker.sqlite"
        broker = Broker(path, receiver)
        broker.authorize(action())
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: Broker(path, receiver).handle(action()), range(16)))
        self.assertTrue(sum(r["status"] == "COMMITTED" for r in results) == 1)
        self.assertTrue(len(receiver.records()) == 1)

    def test_lost_response_unknown_survives_restart_and_reconciles_without_dispatch(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class LoseResponse:
            receiver_id = receiver.receiver_id

            def commit(self, proposal, **kwargs):
                receiver.commit(proposal, **kwargs)
                raise TimeoutError("synthetic response loss after real receiver commit")

            def verify_receipt(self, receipt):
                return receiver.verify_receipt(receipt)

        path = tmp_path / "broker.sqlite"
        broker = Broker(path, LoseResponse())
        broker.authorize(action())
        self.assertTrue(broker.handle(action())["status"] == "UNKNOWN")
        fresh = Broker(path, receiver)
        self.assertTrue(fresh.state("a")["status"] == "UNKNOWN")
        self.assertTrue(fresh.handle(action())["reason"] == "RECONCILIATION_REQUIRED")
        self.assertTrue(fresh.reconcile("a")["status"] == "COMMITTED")
        self.assertTrue(len(receiver.records()) == 1)

    def test_absence_is_unknown_not_retry_permission(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class Unavailable:
            receiver_id = receiver.receiver_id

            def commit(self, proposal, **kwargs):
                raise TimeoutError("before receiver contact")

        path = tmp_path / "broker.sqlite"
        broker = Broker(path, Unavailable())
        broker.authorize(action())
        self.assertTrue(broker.handle(action())["status"] == "UNKNOWN")
        fresh = Broker(path, receiver)
        self.assertTrue(fresh.reconcile("a")["status"] == "UNKNOWN")
        self.assertTrue(fresh.handle(action())["status"] == "BLOCKED")
        self.assertTrue(receiver.records() == [])

    def test_other_signed_attempt_cannot_reconcile(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class WrongReceipt:
            receiver_id = receiver.receiver_id

            def commit(self, proposed, **kwargs):
                raise TimeoutError()

            def query(self, action_id):
                return receiver.commit(action("different"))

            def verify_receipt(self, receipt):
                return receiver.verify_receipt(receipt)

        broker = Broker(tmp_path / "broker.sqlite", WrongReceipt())
        broker.authorize(action())
        broker.handle(action())
        self.assertTrue(broker.reconcile("a")["status"] == "UNKNOWN")

    def test_expiry_and_policy_immutable(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        now = [10.0]
        broker = Broker(tmp_path / "broker.sqlite", receiver, clock=lambda: now[0])
        broker.authorize(action(), ttl_seconds=1, policy_version="v1")
        with self.assertRaises(ControlError):
            broker.authorize(action(), policy_version="v2")
        now[0] = 11.0
        self.assertTrue(broker.authorize(action(), ttl_seconds=100, policy_version="v1")["expires_at"] == 11.0)
        self.assertTrue(broker.handle(action())["reason"] == "AUTHORIZATION_EXPIRED")
        self.assertTrue(receiver.records() == [])

    def test_signed_snapshot_complete_scope_and_tamper_detection(self):
        receiver = self.receiver
        receiver.commit(action())
        receiver.accept(action("pending"))
        snapshot = receiver.snapshot("root", "worker")
        self.assertTrue(verify_receipt(snapshot, RECEIPT_KEY))
        self.assertTrue(snapshot["complete"] is True)
        self.assertTrue(len(snapshot["receipts"]) == 1)
        self.assertTrue(snapshot["accepted_action_ids"] == ["pending"])
        snapshot["receipts"] = []
        self.assertTrue(not verify_receipt(snapshot, RECEIPT_KEY))

    def test_unfenced_baseline_is_explicit_and_observable(self):
        tmp_path = self.tmp_path
        receiver = Receiver(tmp_path / "baseline.sqlite", BROKER_KEY, RECEIPT_KEY, enforce_epoch=False)
        receiver.create_root("root")
        receiver.bind_execution("root", "worker")
        receiver.revoke("root")
        receipt = receiver.commit(action())
        self.assertTrue(receipt["status"] == "COMMITTED")
        self.assertTrue(receipt["enforcement_profile"] == "baseline_unfenced")

    def test_broker_revoke_fences_before_receiver_ack_and_survives_restart(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class Down:
            receiver_id = receiver.receiver_id

            def revoke(self, root_id):
                raise TimeoutError("receiver unavailable")

        path = tmp_path / "broker.sqlite"
        broker = Broker(path, Down())
        broker.authorize(action())
        incomplete = broker.revoke("root")
        self.assertTrue(incomplete["status"] == "INCOMPLETE" and incomplete["broker_fenced"])
        self.assertTrue(broker.state("a")["status"] == "CANCELLED")
        restarted = Broker(path, receiver)
        self.assertTrue(restarted.handle(action())["reason"] == "ROOT_REVOKED")
        with self.assertRaises(ControlError):
            restarted.authorize(action("fresh"))
        ack = restarted.revoke("root")
        self.assertTrue(ack["status"] == "REVOKED" and ack["epoch"] == 2)
        self.assertTrue(verify_receipt(ack["receiver_ack"], RECEIPT_KEY))
        self.assertTrue(Broker(path, receiver).revoke("root") == ack)  # Persisted ack with matching pinned receiver.
        self.assertTrue(Broker(path, Down()).revoke("root")["status"] == "INCOMPLETE")
        self.assertTrue(receiver.records() == [])

    def test_cached_ack_cannot_claim_replacement_receiver_is_revoked(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        path = tmp_path / "broker.sqlite"
        first = Broker(path, receiver).revoke("root")
        replacement = Receiver(tmp_path / "replacement.sqlite", BROKER_KEY, RECEIPT_KEY)
        replacement.create_root("root")
        replacement.bind_execution("root", "worker")
        second = Broker(path, replacement).revoke("root")
        self.assertTrue(second["status"] == "REVOKED")
        self.assertTrue(second["receiver_ack"]["receiver_id"] != first["receiver_ack"]["receiver_id"])
        self.assertTrue(replacement.verify_receipt(second["receiver_ack"]))
        self.assertTrue(replacement.commit(action())["status"] == "DENIED")

    def test_reconciliation_pins_original_receiver_even_with_same_keys(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class Lost:
            receiver_id = receiver.receiver_id

            def commit(self, proposed, **kwargs):
                receiver.commit(proposed, **kwargs)
                raise TimeoutError()

        path = tmp_path / "broker.sqlite"
        broker = Broker(path, Lost())
        broker.authorize(action())
        self.assertTrue(broker.handle(action())["status"] == "UNKNOWN")
        replacement = Receiver(tmp_path / "replacement.sqlite", BROKER_KEY, RECEIPT_KEY)
        replacement.create_root("root")
        replacement.bind_execution("root", "worker")
        replacement.commit(action())  # A real effect elsewhere cannot prove the original attempt.
        swapped = Broker(path, replacement)
        self.assertTrue(swapped.reconcile("a")["status"] == "UNKNOWN")
        self.assertTrue(swapped.handle(action())["reason"] == "RECEIVER_IDENTITY_MISMATCH")
        with self.assertRaisesRegex(ControlError, "receiver identity"):
            swapped.authorize(action())
        self.assertTrue(Broker(path, receiver).reconcile("a")["status"] == "COMMITTED")

    def test_legacy_unbound_grant_migration_never_infers_receiver_identity(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        import time
        path = tmp_path / "legacy.sqlite"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE grants(action_id TEXT PRIMARY KEY,attempt_id TEXT UNIQUE NOT NULL,action_json TEXT NOT NULL,action_digest TEXT NOT NULL,policy_version TEXT NOT NULL,expires_at REAL NOT NULL,status TEXT NOT NULL,receipt_json TEXT)")
            db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,NULL)", ("a", "attempt:a", json.dumps(action()), digest(action()), "owned-pilot-v1", time.time() + 60, "UNKNOWN"))
        receiver.commit(action())
        broker = Broker(path, receiver)
        self.assertTrue(broker.state("a")["receiver_id"] is None)
        self.assertTrue(broker.reconcile("a")["reason"] == "RECEIVER_IDENTITY_UNBOUND")
        self.assertTrue(broker.handle(action())["reason"] == "RECEIVER_IDENTITY_MISMATCH")

    def test_baseline_database_cannot_be_relabelled_guarded(self):
        tmp_path = self.tmp_path
        path = tmp_path / "baseline.sqlite"
        Receiver(path, BROKER_KEY, RECEIPT_KEY, enforce_epoch=False)
        with self.assertRaisesRegex(ControlError, "profile"):
            Receiver(path, BROKER_KEY, RECEIPT_KEY)

    def test_broker_revoke_preserves_unknown_and_allows_read_only_reconciliation(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        class LoseResponse:
            receiver_id = receiver.receiver_id

            def commit(self, proposal, **kwargs):
                receiver.commit(proposal, **kwargs)
                raise TimeoutError()

            def revoke(self, root_id):
                return receiver.revoke(root_id)

            def verify_receipt(self, receipt):
                return receiver.verify_receipt(receipt)

        path = tmp_path / "broker.sqlite"
        broker = Broker(path, LoseResponse())
        broker.authorize(action())
        broker.handle(action())
        self.assertTrue(broker.revoke("root")["status"] == "REVOKED")
        self.assertTrue(broker.state("a")["status"] == "UNKNOWN")
        restarted = Broker(path, receiver)
        self.assertTrue(restarted.reconcile("a")["status"] == "COMMITTED")
        self.assertTrue(len(receiver.records()) == 1)

    def test_foreign_receiver_revoke_ack_is_not_aggregate_ack(self):
        receiver = self.receiver
        tmp_path = self.tmp_path
        receiver.create_root("other")

        class WrongRoot:
            receiver_id = receiver.receiver_id

            def revoke(self, root_id):
                return receiver.revoke("other")

            def verify_receipt(self, receipt):
                return receiver.verify_receipt(receipt)

        broker = Broker(tmp_path / "broker.sqlite", WrongRoot())
        self.assertTrue(broker.revoke("root")["status"] == "INCOMPLETE")
        self.assertTrue(broker.handle(action())["reason"] == "ROOT_REVOKED")

    def test_receiver_rechecks_transmitted_grant_expiry(self):
        receiver = self.receiver
        proposed = action()
        receipt = receiver.commit(proposed, authorization={"action_digest": digest(proposed),
            "expires_at": 0, "policy_version": "owned-pilot-v1", "receiver_id": receiver.receiver_id})
        self.assertTrue(receipt["status"] == "DENIED" and receipt["reason"] == "AUTHORIZATION_EXPIRED")
        self.assertTrue(receiver.records() == [])

    def test_http_redirect_never_forwards_authenticated_request(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hit = []

        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                hit.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()

            def do_GET(self):
                hit.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            client = HTTPReceiverClient(f"http://127.0.0.1:{server.server_port}", BROKER_KEY, RECEIPT_KEY)
            with self.assertRaisesRegex(ControlError, "redirects"):
                client.commit(action())
            self.assertTrue(hit == ["/v1/control"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_real_separate_receiver_process(self):
        tmp_path = self.tmp_path
        broker_file, receipt_file = tmp_path / "broker.key", tmp_path / "receipt.key"
        broker_file.write_bytes(BROKER_KEY)
        receipt_file.write_bytes(RECEIPT_KEY)
        for path in (broker_file, receipt_file):
            path.chmod(0o600)
        command = [sys.executable, "-m", "sdk.liminal_agent_control.receiver", "--db", str(tmp_path / "http.sqlite"),
            "--broker-key-file", str(broker_file), "--receipt-key-file", str(receipt_file), "--port", "0"]
        process = subprocess.Popen(command,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=Path(__file__).parents[1])
        try:
            ready = json.loads(process.stdout.readline())
            client = HTTPReceiverClient(ready["url"], BROKER_KEY, RECEIPT_KEY)
            self.assertTrue(client.create_root("root")["epoch"] == 1)
            client.bind_execution("root", "worker")
            client = HTTPReceiverClient(ready["url"], BROKER_KEY, RECEIPT_KEY)
            self.assertTrue(client.receiver_id is None)
            broker = Broker(tmp_path / "broker.sqlite", client)
            broker.authorize(action())
            self.assertTrue(client.receiver_id == ready["receiver_id"])  # Authenticated identity handshake.
            self.assertTrue(broker.handle(action())["status"] == "COMMITTED")
            self.assertTrue(len(client.records()) == 1)
            self.assertTrue(client.snapshot("root")["complete"] is True)
            self.assertTrue(client.revoke("root")["epoch"] == 2)
            self.assertTrue(client.commit(action("late"))["status"] == "DENIED")
            process.kill()  # Actual process loss after durable receiver acknowledgement.
            process.communicate(timeout=10)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, cwd=Path(__file__).parents[1])
            restarted = json.loads(process.stdout.readline())
            self.assertTrue(restarted["receiver_id"] == ready["receiver_id"])
            client = HTTPReceiverClient(restarted["url"], BROKER_KEY, RECEIPT_KEY)
            self.assertTrue(client.query("a")["status"] == "COMMITTED")
            self.assertTrue(client.commit(action("after-restart"))["reason"] == "AUTHORITY_REVOKED")
            bad_client = HTTPReceiverClient(restarted["url"], b"wrong-key" * 4, RECEIPT_KEY)
            with self.assertRaises(Exception):
                bad_client.commit(action("unauthenticated"))
            self.assertTrue(len(client.records()) == 1)
        finally:
            process.terminate()
            process.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
