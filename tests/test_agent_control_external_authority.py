"""Bounded owned-service tests: no models, production targets or real secrets."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sdk.liminal_agent_control.authority import ControlError, digest, sign_document
from sdk.liminal_agent_control.external_authority import EXTERNAL_PROFILE, ExternalAuthorityStore
from sdk.liminal_agent_control.external_authority_service import (
    HTTPExternalAuthorityClient, RESPONSE_DOMAIN, make_server, verify_authority_response)
from sdk.liminal_agent_control.external_checkpoint import checkpoint_anchor, verify_checkpoint_chain


SIGNING_KEY = b"s" * 32
RECEIPT_KEY = b"r" * 32
OPERATOR_KEY = b"o" * 32
REQUEST_KEY = b"q" * 32
POLICY = "a" * 64


def action(name="a", *, root_id="root", execution_id="worker", epoch=1):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": root_id,
            "execution_id": execution_id, "epoch": epoch, "target": "records", "arguments": {"value": "dummy"}}


def grant(proposed, *, expires_at=180):
    return {"action_digest": digest(proposed), "receiver_id": "receiver", "policy_version": POLICY,
            "expires_at": expires_at}


def receipt(proposed, status="COMMITTED", **changes):
    committed = status == "COMMITTED"
    body = {"schema": "liminal.agent-control.receipt.v1", "status": status, "reason": "TEST_TERMINAL",
        **{field: proposed[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
        "action_digest": digest(proposed), "effect_count": 1 if committed else 0,
        "accepted_epoch": proposed["epoch"] if committed else None, "accepted_at": 100 if committed else None,
        "receiver_id": "receiver", "observed_at": 100, "key_id": "receiver-hmac-v1",
        "enforcement_profile": EXTERNAL_PROFILE}
    body.update(changes)
    return sign_document(body, RECEIPT_KEY)


class ExternalAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authority.sqlite"
        self.now = 100.0
        self.store = self._open(create=True)
        self.store.create_root("root", "receiver", POLICY, 10, 100)
        self.store.bind_execution("root", "worker")

    def _open(self, *, create=False, **changes):
        kwargs = {"authority_id": "authority", "key_id": "authority-key", "private_key": SIGNING_KEY,
                  "receipt_key": RECEIPT_KEY, "clock": lambda: self.now, "create": create}
        kwargs.update(changes)
        return ExternalAuthorityStore(self.path, **kwargs)

    def test_permit_is_one_shot_across_reopen_and_unknown_does_not_expire(self):
        proposed = action()
        first = self.store.begin(proposed, grant(proposed))
        self.assertEqual(first["status"], "PERMITTED")
        reopened = self._open()
        self.assertEqual(reopened.begin(proposed, grant(proposed))["status"], "UNKNOWN")
        self.now = 10000
        self.assertEqual(reopened.query("a")["status"], "UNKNOWN")
        self.assertEqual(reopened.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(reopened.status("root")["pending_count"], 1)

    def test_stop_pending_drains_only_exact_authenticated_terminal_then_irreversible(self):
        proposed = action()
        permit = self.store.begin(proposed, grant(proposed))
        ack = self.store.stop("root")
        self.assertEqual((ack["status"], ack["epoch"], ack["pending_count"]), ("STOP_PENDING", 2, 1))
        self.assertTrue(ack["admission_closed"])
        self.assertEqual(self.store.stop("root")["epoch"], 2)
        self.assertEqual(self.store.begin(action("late"), grant(action("late")))["status"], "DENIED")
        self.now = 1000  # Expiry does not prevent reconciliation of a real commit.
        terminal = receipt(proposed)
        result = self.store.finish(permit["reservation_id"], terminal)
        self.assertEqual((result["status"], result["outcome"]), ("SETTLED", "COMMITTED"))
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        self.assertEqual(self._open().stop("root")["status"], "STOPPED")
        self.assertEqual(self.store.finish(permit["reservation_id"], terminal), result)
        with self.assertRaises(ControlError):
            self.store.finish(permit["reservation_id"], receipt(proposed, status="DENIED"))
        with self.assertRaises(ControlError):
            self.store.create_root("root", "receiver", POLICY, 10, 100)
        self.assertEqual(self.store.begin(proposed, grant(proposed))["status"], "CONSUMED")

    def test_authenticated_denial_can_drain_live_permit_without_effect(self):
        proposed = action()
        permit = self.store.begin(proposed, grant(proposed))
        self.store.stop("root")
        result = self.store.finish(permit["reservation_id"], receipt(proposed, status="DENIED"))
        self.assertEqual(result["outcome"], "DENIED")
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        self.assertEqual(self.store.status("root")["committed_count"], 0)

    def test_receipt_bindings_and_status_cannot_be_forged_even_with_valid_fixture_signature(self):
        proposed = action()
        permit = self.store.begin(proposed, grant(proposed))
        bad = [{"receiver_id": "other"}, {"root_id": "other"}, {"epoch": 2}, {"attempt_id": "other"},
               {"execution_id": "other"}, {"action_digest": "b" * 64}, {"effect_count": 0},
               {"effect_count": True}, {"accepted_epoch": 2}, {"enforcement_profile": "governed_v1"},
               {"status": "UNKNOWN"}, {"schema": "other"}]
        for mutation in bad:
            with self.subTest(mutation=mutation), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], receipt(proposed, **mutation))
        wrong_key = sign_document(receipt(proposed), REQUEST_KEY)
        with self.assertRaises(ControlError):
            self.store.finish(permit["reservation_id"], wrong_key)
        with self.assertRaises(ControlError):
            self.store.finish(permit["reservation_id"], receipt(proposed, status="DENIED", effect_count=1))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_policy_receiver_epoch_lineage_expiry_and_budget_rejections_are_sticky(self):
        cases = [
            ({}, {"policy_version": "b" * 64}, "GRANT_MISMATCH"),
            ({}, {"receiver_id": "other"}, "GRANT_MISMATCH"),
            ({"epoch": 2}, {}, "STOPPED"),
            ({"execution_id": "unknown"}, {}, "LINEAGE_MISMATCH"),
            ({}, {"expires_at": 100}, "EXPIRED"),
            ({}, {"action_digest": "b" * 64}, "GRANT_MISMATCH"),
        ]
        for i, (action_changes, grant_changes, reason) in enumerate(cases):
            proposed = {**action(str(i)), **action_changes}
            authorization = {**grant(proposed), **grant_changes}
            result = self.store.begin(proposed, authorization)
            self.assertEqual(result["status"], "DENIED")
            self.assertTrue(result["reason"].endswith(reason))
            self.assertEqual(self.store.begin(proposed, authorization)["status"], "CONSUMED")
        self.store.create_root("small", "receiver", POLICY, 1, 100)
        self.store.bind_execution("small", "small-worker")
        first = action("small-one", root_id="small", execution_id="small-worker")
        second = action("small-two", root_id="small", execution_id="small-worker")
        self.assertEqual(self.store.begin(first, grant(first))["status"], "PERMITTED")
        self.assertTrue(self.store.begin(second, grant(second))["reason"].endswith("BUDGET_EXHAUSTED"))
        self.assertEqual(self.store.status("small")["issued_count"], 1)

    def test_action_and_attempt_reuse_barrier_is_global_and_exact(self):
        proposed = action()
        self.store.begin(proposed, grant(proposed))
        changed = {**proposed, "arguments": {"value": "changed"}}
        self.assertEqual(self.store.begin(changed, grant(changed))["reason"], "EXTERNAL_AUTHORITY_REUSE_MISMATCH")
        other = {**action("other"), "attempt_id": proposed["attempt_id"]}
        self.assertEqual(self.store.begin(other, grant(other))["status"], "DENIED")
        self.store.create_root("other-root", "receiver", POLICY, 10, 100)
        self.store.bind_execution("other-root", "other-worker")
        across = {**proposed, "root_id": "other-root", "execution_id": "other-worker"}
        self.assertEqual(self.store.begin(across, grant(across))["reason"], "EXTERNAL_AUTHORITY_REUSE_MISMATCH")
        self.assertEqual(self.store.status("root")["pending_count"], 1)
        self.assertEqual(self.store.status("other-root")["issued_count"], 0)

    def test_concurrent_begin_stop_never_acknowledges_stopped_with_live_permit(self):
        for i in range(8):
            root, worker = "race:" + str(i), "race-worker:" + str(i)
            self.store.create_root(root, "receiver", POLICY, 1, 100)
            self.store.bind_execution(root, worker)
            proposed = action("race-action:" + str(i), root_id=root, execution_id=worker)
            barrier = threading.Barrier(2)
            def begin():
                barrier.wait()
                return self._open().begin(proposed, grant(proposed))
            def stop():
                barrier.wait()
                return self._open().stop(root)
            with ThreadPoolExecutor(max_workers=2) as pool:
                permitted, ack = pool.submit(begin), pool.submit(stop)
                begin_result, stop_result = permitted.result(), ack.result()
            if begin_result["status"] == "PERMITTED":
                self.assertEqual(stop_result["status"], "STOP_PENDING")
                self.store.finish(begin_result["reservation_id"], receipt(proposed))
            else:
                self.assertEqual(stop_result["status"], "STOPPED")
                self.assertEqual(begin_result["status"], "DENIED")
            self.assertEqual(self.store.stop(root)["status"], "STOPPED")

    def test_concurrent_exact_begin_issues_only_one_executable_response(self):
        proposed = action()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self._open().begin(proposed, grant(proposed)), range(8)))
        self.assertEqual(sum(r["status"] == "PERMITTED" for r in results), 1)
        self.assertEqual(sum(r["status"] == "UNKNOWN" for r in results), 7)
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_external_time_sample_after_lock_denies_expired_grant(self):
        blocker = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")
        started = threading.Event()
        proposed = action()
        def waiting_begin():
            started.set()
            return self.store.begin(proposed, grant(proposed, expires_at=101))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(waiting_begin)
            self.assertTrue(started.wait(1))
            self.now = 102
            blocker.execute("COMMIT")
            result = pending.result(timeout=3)
        self.assertEqual(result["reason"], "EXTERNAL_AUTHORITY_EXPIRED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_clock_fault_is_sticky_and_never_releases_pending(self):
        proposed = action()
        self.store.begin(proposed, grant(proposed))
        self.now = 99
        with self.assertRaisesRegex(ControlError, "CLOCK_ROLLBACK"):
            self.store.begin(action("back"), grant(action("back")))
        self.now = 110
        reopened = self._open()
        self.assertTrue(reopened.status("root")["clock_fault"])
        self.assertTrue(reopened.status("root")["admission_closed"])
        self.assertEqual(reopened.status("root")["pending_count"], 1)
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            reopened.stop("root")
        self.assertEqual(reopened.query("a")["status"], "UNKNOWN")

    def test_root_expiry_closes_epoch_without_releasing_live_permit(self):
        proposed = action()
        permit = self.store.begin(proposed, grant(proposed))
        self.now = 201
        before = self.store.status("root")
        self.assertTrue(before["deadline_reached"])
        self.assertTrue(before["admission_closed"])
        result = self.store.begin(action("expired"), grant(action("expired"), expires_at=250))
        self.assertEqual(result["reason"], "EXTERNAL_AUTHORITY_EXPIRED")
        closed = self.store.status("root")
        self.assertEqual((closed["state"], closed["epoch"], closed["pending_count"]), ("STOPPING", 2, 1))
        self.assertEqual(closed["stop_reason"], "EXPIRED")
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.store.finish(permit["reservation_id"], receipt(proposed))
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        self.assertEqual(self.store.status("root")["epoch"], 2)

    def test_expired_execution_binding_persists_closure_before_denial(self):
        self.now = 201
        result = self.store.bind_execution("root", "late-worker")
        self.assertEqual(result["status"], "DENIED")
        reopened = self._open()
        state = reopened.status("root")
        self.assertEqual((state["state"], state["epoch"], state["stop_reason"]), ("STOPPED", 2, "EXPIRED"))

    def test_reopen_never_repairs_missing_state_schema_or_changed_pins(self):
        for changes in ({"authority_id": "other"}, {"key_id": "other"}, {"private_key": b"z" * 32}, {"receipt_key": b"x" * 32}):
            with self.subTest(changes=list(changes)), self.assertRaises(ControlError):
                self._open(**changes)
        missing = self.path.with_name("missing.sqlite")
        with self.assertRaises(ControlError):
            ExternalAuthorityStore(missing, authority_id="authority", key_id="authority-key", private_key=SIGNING_KEY,
                                   receipt_key=RECEIPT_KEY, create=False)
        self.assertFalse(missing.exists())
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE external_executions")
        with self.assertRaises(ControlError):
            self._open(create=True)

    def test_checkpoint_and_authority_mutation_roll_back_together(self):
        before = len(self.store.checkpoints())
        proposed = action()
        with patch("sdk.liminal_agent_control.external_checkpoint.append_checkpoint", side_effect=ControlError("fault")):
            with self.assertRaises(ControlError):
                self.store.begin(proposed, grant(proposed))
        self.assertEqual(self.store.query("a")["reason"], "NOT_OBSERVED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)
        self.assertEqual(len(self.store.checkpoints()), before)
        entries = self.store.checkpoints()
        pin = self.store.pin()
        verified = verify_checkpoint_chain(entries, authority_id=pin["authority_id"], signer_id=pin["authority_id"],
            key_id=pin["key_id"], public_key=pin["public_key"], anchor=checkpoint_anchor(entries[-1]))
        self.assertEqual(verified["verification_status"], "EXTERNAL_ANCHORED_VERIFIED")

    def test_global_capacity_bounds_denials_without_blocking_stop_or_settlement(self):
        proposed = action()
        permit = self.store.begin(proposed, grant(proposed))
        with patch("sdk.liminal_agent_control.external_authority.MAX_RECORDED_ACTIONS", 3):
            for name in ("denied-one", "denied-two"):
                denied = action(name)
                self.assertEqual(self.store.begin(denied, grant(denied, expires_at=100))["status"], "DENIED")
            checkpoint_count = len(self.store.checkpoints())
            for i in range(12):
                denied = action("overflow:" + str(i))
                self.assertEqual(self.store.begin(denied, grant(denied))["reason"], "EXTERNAL_AUTHORITY_ACTION_CAPACITY")
            with sqlite3.connect(self.path) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM external_actions").fetchone()[0], 3)
            self.assertEqual(len(self.store.checkpoints()), checkpoint_count)
            self.assertEqual(self.store.begin(proposed, grant(proposed))["status"], "UNKNOWN")
            self.assertEqual(self.store.query("a")["status"], "UNKNOWN")
            self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
            terminal = receipt(proposed)
            self.assertEqual(self.store.finish(permit["reservation_id"], terminal)["status"], "SETTLED")
            self.assertEqual(self._open().finish(permit["reservation_id"], terminal)["status"], "SETTLED")
            self.assertEqual(self.store.begin(proposed, grant(proposed))["status"], "CONSUMED")
            self.assertEqual(self.store.stop("root")["status"], "STOPPED")

    def test_global_root_and_execution_limits_preserve_exact_existing_bindings(self):
        with patch("sdk.liminal_agent_control.external_authority.MAX_ROOTS", 1):
            self.assertEqual(self.store.create_root("root", "receiver", POLICY, 10, 100)["status"], "ROOT_CREATED")
            with self.assertRaisesRegex(ControlError, "ROOT_CAPACITY"):
                self.store.create_root("extra-root", "receiver", POLICY, 1, 100)
        with patch("sdk.liminal_agent_control.external_authority.MAX_EXECUTIONS", 1):
            self.assertEqual(self.store.bind_execution("root", "worker")["status"], "BOUND")
            with self.assertRaisesRegex(ControlError, "EXECUTION_LIMIT"):
                self.store.bind_execution("root", "extra-worker")
        with patch("sdk.liminal_agent_control.external_authority.MAX_RECORDED_ACTIONS", 2):
            with self.assertRaisesRegex(ControlError, "LIMIT_INVALID"):
                self.store.create_root("too-large", "receiver", POLICY, 3, 100)

    def _server_clients(self):
        server = make_server(self.store, OPERATOR_KEY, REQUEST_KEY)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = "http://127.0.0.1:" + str(server.server_address[1])
        receiver = HTTPExternalAuthorityClient(url, REQUEST_KEY, self.store.pin())
        operator = HTTPExternalAuthorityClient(url, OPERATOR_KEY, self.store.pin(), role="admin")
        return url, receiver, operator

    def test_http_role_separation_pinned_signature_and_public_challenge_evidence(self):
        url, client, operator = self._server_clients()
        proposed = action()
        self.assertEqual(client.begin(proposed, grant(proposed))["status"], "PERMITTED")
        self.assertEqual(client.begin(proposed, grant(proposed))["status"], "UNKNOWN")
        with self.assertRaisesRegex(ControlError, "ROLE_DENIED"):
            client.stop("root")
        wrong_role_key = HTTPExternalAuthorityClient(url, REQUEST_KEY, self.store.pin(), role="admin")
        with self.assertRaises(ControlError):
            wrong_role_key.stop("root")
        self.assertEqual(operator.stop("root")["status"], "STOP_PENDING")
        for evidence in client.evidence:
            self.assertNotIn("signature", evidence["request"])
            self.assertEqual(evidence["response"]["request_digest"], digest(evidence["request"]))
            verify_authority_response(evidence["request"], evidence["response"], self.store.pin())
        captured = client.evidence[-1]
        changed_request = {**captured["request"], "nonce": "0" * 64}
        with self.assertRaises(ControlError):
            verify_authority_response(changed_request, captured["response"], self.store.pin())
        changed_response = {**captured["response"], "result": {"status": "PERMITTED"}}
        with self.assertRaises(ControlError):
            verify_authority_response(captured["request"], changed_response, self.store.pin())
        changed_pin = {**self.store.pin(), "public_key": "0" * 64}
        with self.assertRaises(ControlError):
            verify_authority_response(captured["request"], captured["response"], changed_pin)
        copy = client.evidence
        copy[0]["response"]["result"]["status"] = "PERMITTED_FOREVER"
        self.assertNotEqual(client.evidence[0]["response"]["result"]["status"], "PERMITTED_FOREVER")

    def test_http_rejects_oversized_and_unauthenticated_requests_without_mutation(self):
        url, client, _ = self._server_clients()
        request = Request(url + "/v1/authority", data=b"x" * 32769, method="POST")
        with self.assertRaises(HTTPError):
            urlopen(request, timeout=2)
        request = Request(url + "/v1/authority", data=b'{"role":"admin","operation":"stop"}', method="POST")
        with self.assertRaises(HTTPError):
            urlopen(request, timeout=2)
        self.assertEqual(self.store.status("root")["state"], "ACTIVE")
        self.assertEqual(self.store.status("root")["issued_count"], 0)
        for endpoint in ("https://127.0.0.1:1", "http://localhost:1", "http://127.0.0.1:1/path", "http://user@127.0.0.1:1"):
            with self.assertRaises(ControlError):
                HTTPExternalAuthorityClient(endpoint, REQUEST_KEY, self.store.pin())


if __name__ == "__main__":
    unittest.main()
