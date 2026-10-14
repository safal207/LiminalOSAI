"""Receiver-local fence ordering, exact replay and process-crash regressions."""
from __future__ import annotations

import copy
import json
import multiprocessing
import os
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority_service import (
    REQUEST_SCHEMA as AUTHORITY_REQUEST_SCHEMA, RESPONSE_SCHEMA as AUTHORITY_RESPONSE_SCHEMA,
    RESPONSE_DOMAIN as AUTHORITY_RESPONSE_DOMAIN,
)
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.external_agent_receiver import (
    HTTPReceiverFenceClient, ReceiverFenceStore, REQUEST_SCHEMA, _request_signature,
    make_receiver_server, verify_receiver_response,
)
from sdk.liminal_agent_control.external_agent_receiver_protocol import (
    receiver_action, receipt_matches_action, verify_receiver_fence, verify_receiver_receipt,
)
from sdk.liminal_agent_control.external_network_protocol import verify_endpoint_receipt


AUTHORITY_KEY = b"a" * 32
RECEIVER_KEY = b"e" * 32
GATEWAY_KEY = b"g" * 32
OPERATOR_KEY = b"o" * 32
POLICY = "b" * 64


def _crash_with_staged_write(path, configuration, inputs):
    store = ReceiverFenceStore(path, create=False, **configuration)
    store.commit(*inputs, before_commit=lambda: os._exit(81))


class ExternalAgentReceiverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "receiver.sqlite"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.pin = {"endpoint_id": "endpoint", "key_id": "receiver-key",
            "public_key": Ed25519PrivateKey.from_private_bytes(RECEIVER_KEY).public_key().public_bytes_raw().hex()}
        self.authority = ExternalNetworkAuthorityStore(self.directory / "authority.sqlite",
            endpoint_pin=self.pin, authority_id="authority", key_id="authority-key",
            private_key=AUTHORITY_KEY, receipt_key=b"r" * 32)
        self.authority.create_root("root", "endpoint", POLICY, 100, 300)
        self.authority.bind_execution("root", "worker")
        self.configuration = dict(endpoint_id="endpoint", key_id="receiver-key", private_key=RECEIVER_KEY,
            authority_pin=self.authority.pin(), endpoint_url=self.url,
            gateway_key=GATEWAY_KEY, operator_key=OPERATOR_KEY)
        self.store = ReceiverFenceStore(self.path, **self.configuration)
        self.store.create_root("root")
        self.store.bind_execution("root", "worker")
        self.server = None

    def issue(self, name="one", *, action=None):
        if action is None:
            action = receiver_action(root_id="root", execution_id="worker", epoch=1,
                action_id=name, attempt_id="attempt:" + name, endpoint_url=self.url, marker=name)
        authorization = {"action_digest": digest(action), "policy_version": POLICY,
            "expires_at": time.time() + 120, "receiver_id": "endpoint"}
        request = {"schema": AUTHORITY_REQUEST_SCHEMA, "role": "receiver", "operation": "begin",
            "nonce": secrets.token_hex(32), "payload": {"action": action, "authorization": authorization}}
        result = self.authority.begin(action, authorization)
        self.assertEqual(result["status"], "PERMITTED")
        permit = {"schema": AUTHORITY_RESPONSE_SCHEMA, "authority_id": "authority", "key_id": "authority-key",
            "operation": "begin", "request_digest": digest(request), "issued_at": time.time(), "result": result}
        permit["signature"] = Ed25519PrivateKey.from_private_bytes(AUTHORITY_KEY).sign(
            AUTHORITY_RESPONSE_DOMAIN + canonical_bytes(permit)).hex()
        return action, authorization, request, permit

    def client(self, **options):
        if self.server is None:
            self.server = make_receiver_server(self.store, port=self.port, **options)
            server = self.server
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            thread.start()
            def close():
                server.shutdown()
                server.server_close()
                thread.join(3)
                self.assertFalse(thread.is_alive())
            self.addCleanup(close)
        return HTTPReceiverFenceClient(self.url, GATEWAY_KEY, self.pin, operator_key=OPERATOR_KEY)

    def reopen(self, **changes):
        configuration = {**self.configuration, **changes}
        return ReceiverFenceStore(self.path, create=False, **configuration)

    def fresh_stop(self, root_id, nonce, epoch=1):
        """Authenticated external caller with an explicitly fresh challenge."""
        body = {"schema": REQUEST_SCHEMA, "role": "operator", "operation": "stop",
            "nonce": nonce * 64, "payload": {"root_id": root_id, "epoch": epoch}}
        packet = {**body, "signature": _request_signature(body, OPERATOR_KEY)}
        request = Request(self.url + "/v1/receiver-control", data=canonical_bytes(packet), method="POST",
            headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=3) as incoming:
            response = json.loads(incoming.read())
        result = verify_receiver_response(body, response, self.pin)
        if result["status"] == "ERROR":
            raise ControlError(result["reason"])
        return result, {"request": body, "response": response}

    def test_http_commit_has_exact_proof_and_one_effect(self):
        inputs = self.issue()
        observed = self.client().commit(*inputs)
        receipt = observed["receipt"]
        self.assertEqual((observed["status"], observed["effect_count"]), ("OBSERVED", 1))
        self.assertEqual(receipt["status"], "COMMITTED")
        self.assertTrue(verify_receiver_receipt(receipt, self.pin))
        self.assertFalse(verify_endpoint_receipt(receipt, self.pin), "G03 proof must not enter G02")
        self.assertTrue(receipt_matches_action(receipt, *inputs[:2], receipt["reservation_id"], self.pin))
        self.assertGreaterEqual(receipt["terminal_at"], inputs[3]["issued_at"])
        self.assertEqual(self.reopen().query("one", receipt["reservation_id"]), observed)
        self.assertEqual(len(self.store.inventory()["effects"]), 1)

    def test_stop_wins_outside_transaction_yields_signed_no_effect(self):
        inputs = self.issue()
        reached, release = threading.Event(), threading.Event()
        def outside():
            reached.set()
            self.assertTrue(release.wait(5))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.store.commit, *inputs, before_transaction=outside)
            try:
                self.assertTrue(reached.wait(3))
                ack = self.store.stop("root")
                self.assertTrue(verify_receiver_fence(ack, self.pin))
                self.assertEqual(self.reopen().inventory()["fences"], [ack], "ACK must follow durable COMMIT")
            finally:
                release.set()
            receipt = pending.result(5)
        self.assertEqual((receipt["status"], receipt["effect_count"]), ("NO_EFFECT", 0))
        self.assertEqual(receipt["fence_digest"], digest(ack))
        self.assertGreater(receipt["terminal_sequence"], ack["fence_sequence"])
        self.assertGreaterEqual(receipt["terminal_at"], ack["fenced_at"])
        self.assertTrue(verify_receiver_receipt(receipt, self.pin))
        self.assertEqual(self.store.inventory()["effects"], [])
        self.assertEqual(self.reopen().commit(*inputs), receipt)

    def test_commit_wins_stop_waits_for_same_transaction(self):
        inputs = self.issue()
        reached, release, stop_started = threading.Event(), threading.Event(), threading.Event()
        def inside():
            reached.set()
            self.assertTrue(release.wait(5))
        def stop():
            stop_started.set()
            return self.store.stop("root")
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.store.commit, *inputs, before_commit=inside)
            try:
                self.assertTrue(reached.wait(3))
                stopping = pool.submit(stop)
                self.assertTrue(stop_started.wait(3))
                # The effect is staged but invisible; STOP cannot acknowledge
                # while the other connection holds BEGIN IMMEDIATE.
                self.assertEqual(self.reopen().inventory()["effects"], [])
                self.assertFalse(stopping.done())
            finally:
                release.set()
            receipt, ack = pending.result(5), stopping.result(5)
        self.assertEqual(receipt["status"], "COMMITTED")
        self.assertEqual(len(self.reopen().inventory()["effects"]), 1)
        self.assertGreaterEqual(ack["fenced_at"], receipt["terminal_at"])
        self.assertLess(receipt["terminal_sequence"], ack["fence_sequence"])
        self.assertEqual(self.store.commit(*inputs), receipt)

    def test_stop_then_late_issued_permit_is_no_effect_for_bound_lineage(self):
        inputs = self.issue()
        ack = self.store.stop("root")
        client = self.client()
        receipt = client.commit(*inputs)["receipt"]
        self.assertEqual(receipt["status"], "NO_EFFECT")
        self.assertEqual(client.stop("root"), ack)
        self.assertEqual(client.query("one", receipt["reservation_id"])["receipt"], receipt)
        self.assertEqual(self.store.inventory()["effects"], [])

    def test_lost_commit_response_query_recovers_without_second_dispatch(self):
        inputs = self.issue()
        client = self.client(drop_commit_response=True)
        with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
            client.commit(*inputs)
        reservation = inputs[3]["result"]["reservation_id"]
        proof = client.query("one", reservation)
        self.assertEqual(proof["receipt"]["status"], "COMMITTED")
        inventory = self.reopen().inventory()
        self.assertEqual((len(inventory["effects"]), inventory["commit_request_count"]), (1, 1))

    def test_lost_stop_response_recovers_same_durable_fence(self):
        client = self.client(drop_stop_response=True)
        with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
            client.stop("root")
        persisted = self.reopen().inventory()["fences"][0]
        self.assertEqual(client.stop("root"), persisted)
        self.assertTrue(verify_receiver_fence(persisted, self.pin))
        receipt = client.commit(*self.issue())["receipt"]
        self.assertEqual(receipt["status"], "NO_EFFECT")

    def test_lost_reserved_stop_ack_recovers_across_client_and_receiver_restart(self):
        self.store.create_root("other")
        self.store.bind_execution("other", "other-worker")
        client = self.client(drop_stop_response=True)
        with patch("sdk.liminal_agent_control.external_agent_receiver.MAX_REQUESTS", 4), \
                patch("sdk.liminal_agent_control.external_agent_receiver.MAX_ROOTS", 2):
            for _ in range(4):
                self.assertEqual(client.query("missing", "missing")["status"], "UNKNOWN")
            with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
                client.stop("root")
            self.assertIsNone(client.last_call_evidence())
            persisted = self.reopen().inventory()
            first = persisted["fences"][0]
            self.assertEqual(len(persisted["authenticated_requests"]), 5)
            # Restart the loopback server, reopen SQLite and replace the client;
            # no in-memory packet/result cache reconstructs the challenge.
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.store = self.reopen()
            restarted_client = self.client()
            self.assertEqual(restarted_client.stop("root"), first)
            pair = restarted_client.last_call_evidence()
            self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.pin), first)
            self.assertEqual(self.reopen().inventory(), persisted)
            second = restarted_client.stop("other")
            final = self.reopen().inventory()
            self.assertEqual(len(final["authenticated_requests"]), 6)
            self.assertEqual(final["stop_request_count"], 2)
            self.assertEqual(final["transition_sequence"], 2)
            for _ in range(5):
                self.assertEqual(client.stop("root"), first)
                self.assertEqual(restarted_client.stop("other"), second)
            self.assertEqual(self.reopen().inventory(), final)
            self.assertEqual(len(client.evidence), 5, "four queries plus one recovered STOP")
            self.assertEqual(len(restarted_client.evidence), 2)
            self.assertEqual(len({item["request"]["nonce"] for item in restarted_client.evidence}), 2)

    def test_stop_challenge_binds_context_and_cannot_borrow_an_ack(self):
        client = self.client()
        client.stop("root")
        pair = client.last_call_evidence()
        payload = pair["request"]["payload"]
        self.assertEqual(self.client()._stop_nonce(payload), pair["request"]["nonce"])
        changed_pin = {**self.pin, "key_id": "another-key"}
        variants = [HTTPReceiverFenceClient(self.url, GATEWAY_KEY, self.pin, operator_key=b"x" * 32),
            HTTPReceiverFenceClient("http://127.0.0.1:1", GATEWAY_KEY, self.pin, operator_key=OPERATOR_KEY),
            HTTPReceiverFenceClient(self.url, GATEWAY_KEY, changed_pin, operator_key=OPERATOR_KEY)]
        for variant in variants:
            nonce = variant._stop_nonce(payload)
            self.assertNotEqual(nonce, pair["request"]["nonce"])
            with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                verify_receiver_response({**pair["request"], "nonce": nonce}, pair["response"], self.pin)
        for changes in ({"root_id": "other"}, {"epoch": 2}):
            changed = {**payload, **changes}
            self.assertNotEqual(client._stop_nonce(changed), pair["request"]["nonce"])
            with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                verify_receiver_response({**pair["request"], "payload": changed}, pair["response"], self.pin)
            # Reusing the original nonce with a changed authenticated payload
            # also fails at the receiver rather than yielding the old fence.
            with self.assertRaisesRegex(ControlError, "NONCE_REUSED"):
                self.reopen().handle_authenticated_request({**pair["request"], "payload": changed})
        with patch("sdk.liminal_agent_control.external_agent_receiver.STOP_CHALLENGE_DOMAIN", b"other-domain\x00"):
            self.assertNotEqual(client._stop_nonce(payload), pair["request"]["nonce"])
        with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
            variants[0].stop("root")
        self.assertIsNone(variants[0].last_call_evidence())
        for epoch in (True, "1"):
            with self.assertRaisesRegex(ControlError, "EPOCH_INVALID"):
                client.stop("root", epoch)

    def test_concurrent_stop_replays_keep_one_history_pair_and_each_call_proof(self):
        client = self.client()
        barrier = threading.Barrier(6)
        def stop(_):
            barrier.wait()
            ack = client.stop("root")
            return ack, client.last_call_evidence()
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(stop, range(6)))
        self.assertEqual(len(client.evidence), 1)
        for ack, pair in results:
            self.assertEqual(pair, client.evidence[0])
            self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.pin), ack)
        self.assertIsNone(client.last_call_evidence(), "another thread's proof cannot be borrowed")
        self.assertEqual(len(self.reopen().inventory()["authenticated_requests"]), 1)
        # A conflicting signed refusal for the same challenge must remain
        # visible; exact replay revalidates the persisted fence, not local ACK.
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM receiver_fences")
        with self.assertRaises(ControlError):
            client.stop("root")
        self.assertEqual(len(client.evidence), 2)
        self.assertEqual(client.last_call_evidence()["response"]["result"]["status"], "ERROR")
        self.assertEqual(client.evidence[0]["request"], client.evidence[1]["request"])

    def test_repeated_fresh_stop_cannot_spend_another_roots_fence_reserve(self):
        self.store.create_root("other")
        self.store.bind_execution("other", "other-worker")
        client = self.client()
        with patch("sdk.liminal_agent_control.external_agent_receiver.MAX_REQUESTS", 4), \
                patch("sdk.liminal_agent_control.external_agent_receiver.MAX_ROOTS", 2):
            first, first_pair = self.fresh_stop("root", "1")
            for nonce in ("2", "3", "4"):
                result, pair = self.fresh_stop("root", nonce)
                self.assertEqual(result, first)
                self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.pin), first)
                with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
                    verify_receiver_response(pair["request"], first_pair["response"], self.pin)
            full = self.reopen().inventory()
            self.assertEqual(len(full["authenticated_requests"]), 4)
            for nonce in ("5", "6", "7", "8"):
                with self.assertRaisesRegex(ControlError, "REQUEST_CAPACITY"):
                    self.fresh_stop("root", nonce)
            self.assertEqual(self.reopen().inventory(), full)
            # Neither an unknown root nor an unbound epoch can rent a reserve.
            for root_id, epoch in (("never-enrolled", 1), ("other", 2)):
                with self.assertRaisesRegex(ControlError, "ROOT_BINDING_MISMATCH"):
                    client.stop(root_id, epoch)
            self.assertEqual(self.reopen().inventory(), full)
            self.assertEqual(self.fresh_stop("root", "1")[0], first)
            self.assertEqual(self.reopen().inventory(), full)
            second = client.stop("other")
            self.assertTrue(verify_receiver_fence(second, self.pin))
            self.assertNotEqual(second["root_id"], first["root_id"])
            restarted = self.reopen().inventory()
            self.assertEqual(len(restarted["authenticated_requests"]), 5)
            self.assertEqual(sorted(restarted["fences"], key=lambda value: value["fence_sequence"]), [first, second])
            self.assertEqual(restarted["stop_request_count"], 5)

    def test_fence_reserve_survives_restart_and_exact_replay_at_total_capacity(self):
        self.store.create_root("other")
        self.store.bind_execution("other", "other-worker")
        client = self.client()
        with patch("sdk.liminal_agent_control.external_agent_receiver.MAX_REQUESTS", 4), \
                patch("sdk.liminal_agent_control.external_agent_receiver.MAX_ROOTS", 2):
            for nonce in ("1", "2", "3", "4"):
                with patch("sdk.liminal_agent_control.external_agent_receiver.secrets.token_hex", return_value=nonce * 64):
                    self.assertEqual(client.query("not-issued", "not-issued")["status"], "UNKNOWN")
            first = client.stop("root")
            first_request = client.last_call_evidence()["request"]
            restarted = self.reopen()
            second_request = {**first_request, "nonce": "6" * 64, "payload": {"root_id": "other", "epoch": 1}}
            second = restarted.handle_authenticated_request(second_request)
            self.assertTrue(verify_receiver_fence(second, self.pin))
            final = self.reopen().inventory()
            self.assertEqual(len(final["authenticated_requests"]), 6)
            self.assertEqual(final["transition_sequence"], 2)
            self.assertEqual(sorted(final["fences"], key=lambda value: value["fence_sequence"]), [first, second])
            # Same nonce/body remains observable at the total storage ceiling.
            self.assertEqual(client.stop("root"), first)
            changed = {**first_request, "payload": {"root_id": "other", "epoch": 1}}
            with self.assertRaisesRegex(ControlError, "REQUEST_NONCE_REUSED"):
                self.reopen().handle_authenticated_request(changed)
            self.assertEqual(self.reopen().handle_authenticated_request(second_request), second)
            for root_id in ("root", "other"):
                with self.assertRaisesRegex(ControlError, "REQUEST_CAPACITY"):
                    self.fresh_stop(root_id, "7")
            with self.assertRaisesRegex(ControlError, "REQUEST_CAPACITY"):
                client.query("not-issued", "not-issued")
            self.assertEqual(self.reopen().inventory(), final)

    def test_absent_query_and_query_outage_remain_unknown(self):
        inputs = self.issue()
        reservation = inputs[3]["result"]["reservation_id"]
        absent = self.store.query("one", reservation)
        self.assertEqual((absent["status"], absent["effect_count"], absent["receipt"]), ("UNKNOWN", None, None))
        client = self.client(query_unavailable=True)
        client.commit(*inputs)
        hidden = client.query("one", reservation)
        self.assertEqual((hidden["status"], hidden["effect_count"], hidden["receipt"]), ("UNKNOWN", None, None))
        self.assertEqual(len(self.store.inventory()["effects"]), 1)

    def test_exception_with_staged_rows_rolls_back_both(self):
        inputs = self.issue()
        def fail():
            raise ControlError("staged fault")
        with self.assertRaisesRegex(ControlError, "staged fault"):
            self.store.commit(*inputs, before_commit=fail)
        inventory = self.reopen().inventory()
        self.assertEqual((inventory["effects"], inventory["terminals"]), ([], []))
        self.assertEqual(self.store.query("one", inputs[3]["result"]["reservation_id"])["status"], "UNKNOWN")

    def test_process_death_with_staged_rows_then_restart_has_no_terminal(self):
        inputs = self.issue()
        process = multiprocessing.get_context("spawn").Process(target=_crash_with_staged_write,
            args=(self.path, self.configuration, inputs))
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join(3)
            self.fail("owned receiver crash process did not exit")
        self.assertEqual(process.exitcode, 81)
        reopened = self.reopen()
        self.assertEqual((reopened.inventory()["effects"], reopened.inventory()["terminals"]), ([], []))
        self.assertEqual(reopened.query("one", inputs[3]["result"]["reservation_id"])["status"], "UNKNOWN")
        ack = reopened.stop("root")
        recovered = reopened.commit(*inputs)
        self.assertEqual((recovered["status"], recovered["fence_digest"]), ("NO_EFFECT", digest(ack)))

    def test_concurrent_identical_retries_produce_one_terminal_and_one_effect(self):
        inputs = self.issue()
        barrier = threading.Barrier(6)
        def commit(_):
            barrier.wait()
            return self.store.commit(*inputs)
        with ThreadPoolExecutor(max_workers=6) as pool:
            receipts = list(pool.map(commit, range(6)))
        self.assertTrue(all(receipt == receipts[0] for receipt in receipts))
        inventory = self.store.inventory()
        self.assertEqual((len(inventory["effects"]), len(inventory["terminals"])), (1, 1))
        self.assertEqual(inventory["transition_sequence"], 1)

    def test_exact_packet_nonce_retry_is_idempotent_conflicting_payload_rejected(self):
        client = self.client()
        inputs = self.issue()
        with patch("sdk.liminal_agent_control.external_agent_receiver.secrets.token_hex", return_value="c" * 64):
            first = client.commit(*inputs)
            second = client.commit(*inputs)
            self.assertEqual(first, second)
            with self.assertRaisesRegex(ControlError, "NONCE_REUSED"):
                client.query("one", first["reservation_id"])
        inventory = self.store.inventory()
        self.assertEqual(inventory["commit_request_count"], 1)
        self.assertEqual(len(inventory["authenticated_requests"]), 1)

    def test_conflicting_original_permit_nonce_and_numeric_type_rejected(self):
        inputs = self.issue()
        first = self.store.commit(*inputs)
        changed = list(copy.deepcopy(inputs))
        changed[1]["expires_at"] = int(changed[1]["expires_at"])
        changed[2]["payload"]["authorization"] = changed[1]
        # A genuine second signed permit for a reused action is also rejected:
        # exact permit identity is part of the persisted terminal binding.
        changed[2]["nonce"] = "d" * 64
        changed[3]["request_digest"] = digest(changed[2])
        changed[3]["signature"] = Ed25519PrivateKey.from_private_bytes(AUTHORITY_KEY).sign(
            AUTHORITY_RESPONSE_DOMAIN + canonical_bytes({k: v for k, v in changed[3].items() if k != "signature"})).hex()
        with self.assertRaisesRegex(ControlError, "REUSE_MISMATCH"):
            self.store.commit(*changed)
        self.assertEqual(self.store.commit(*inputs), first)
        self.assertEqual(len(self.store.inventory()["effects"]), 1)

    def test_bound_authority_execution_missing_at_receiver_never_proves_no_effect(self):
        self.authority.bind_execution("root", "unbound")
        action = receiver_action(root_id="root", execution_id="unbound", epoch=1,
            action_id="unbound-action", attempt_id="unbound-attempt", endpoint_url=self.url, marker="unbound")
        inputs = self.issue(action=action)
        self.store.stop("root")
        with self.assertRaisesRegex(ControlError, "EXECUTION_BINDING_MISMATCH"):
            self.store.commit(*inputs)
        queried = self.store.query(action["action_id"], inputs[3]["result"]["reservation_id"])
        self.assertEqual((queried["status"], queried["effect_count"], queried["receipt"]), ("UNKNOWN", None, None))
        self.assertEqual(self.store.inventory()["terminals"], [])

    def test_epoch_root_and_execution_bindings_are_immutable(self):
        for call in (lambda: self.store.create_root("root", 2),
                     lambda: self.store.stop("root", 2),
                     lambda: self.store.bind_execution("root", "worker", 2)):
            with self.assertRaises(ControlError):
                call()
        self.store.create_root("other")
        with self.assertRaisesRegex(ControlError, "EXECUTION_IMMUTABLE"):
            self.store.bind_execution("other", "worker")
        self.store.stop("root")
        with self.assertRaises(ControlError):
            self.store.create_root("root")
        with self.assertRaisesRegex(ControlError, "ROOT_FENCED"):
            self.store.bind_execution("root", "new-execution")

    def test_http_gateway_key_cannot_fence_or_initialize_lineage(self):
        self.client()
        body = {"schema": REQUEST_SCHEMA, "role": "operator", "operation": "stop", "nonce": "f" * 64,
            "payload": {"root_id": "root", "epoch": 1}}
        packet = {**body, "signature": _request_signature(body, GATEWAY_KEY)}
        request = Request(self.url + "/v1/receiver-control", data=canonical_bytes(packet), method="POST",
            headers={"Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as refused:
            urlopen(request, timeout=3)
        self.assertEqual(refused.exception.code, 403)
        self.assertEqual(self.store.inventory()["fences"], [])
        unprivileged = HTTPReceiverFenceClient(self.url, GATEWAY_KEY, self.pin)
        with self.assertRaisesRegex(ControlError, "OPERATOR_KEY_REQUIRED"):
            unprivileged.stop("root")

    def test_configuration_key_and_profile_changes_refuse_reopen(self):
        for changes in ({"gateway_key": b"x" * 32}, {"operator_key": b"y" * 32},
                        {"endpoint_url": "http://127.0.0.1:1"}, {"private_key": b"z" * 32}):
            with self.assertRaises(ControlError):
                self.reopen(**changes)
        with sqlite3.connect(self.path) as db:
            configuration = json.loads(db.execute("SELECT value FROM receiver_meta WHERE key='configuration'").fetchone()[0])
            configuration["profile"] = "owned-loopback-network-v1"
            db.execute("UPDATE receiver_meta SET value=? WHERE key='configuration'", (canonical_bytes(configuration).decode(),))
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            self.reopen()

    def test_future_permit_clock_never_creates_terminal(self):
        inputs = list(self.issue())
        permit = inputs[3]
        permit["issued_at"] = time.time() + 1000
        permit["signature"] = Ed25519PrivateKey.from_private_bytes(AUTHORITY_KEY).sign(
            AUTHORITY_RESPONSE_DOMAIN + canonical_bytes({k: v for k, v in permit.items() if k != "signature"})).hex()
        with self.assertRaisesRegex(ControlError, "CLOCK_BINDING_MISMATCH"):
            self.store.commit(*inputs)
        self.assertEqual(self.store.inventory()["terminals"], [])

    def test_deleted_effect_or_fence_cannot_replay_signed_terminal(self):
        receipt = self.store.commit(*self.issue())
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM receiver_effects")
        with self.assertRaisesRegex(ControlError, "EFFECT_CORRUPT"):
            self.store.query("one", receipt["reservation_id"])
        # A separate clean receiver demonstrates that a removed durable fence
        # invalidates NO_EFFECT, even though the receipt signature remains valid.
        other_path = self.directory / "other-receiver.sqlite"
        other = ReceiverFenceStore(other_path, **self.configuration)
        other.create_root("root")
        other.bind_execution("root", "worker")
        other.stop("root")
        no_effect = other.commit(*self.issue("two"))
        with sqlite3.connect(other_path) as db:
            db.execute("DELETE FROM receiver_fences")
        with self.assertRaisesRegex(ControlError, "FENCE_CORRUPT"):
            other.query("two", no_effect["reservation_id"])

    def test_tampered_signed_response_and_terminal_are_rejected(self):
        client = self.client()
        observed = client.commit(*self.issue())
        evidence = client.evidence[-1]
        tampered = copy.deepcopy(evidence["response"])
        tampered["result"]["effect_count"] = 0
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            verify_receiver_response(evidence["request"], tampered, self.pin)
        receipt = copy.deepcopy(observed["receipt"])
        receipt["status"], receipt["effect_count"] = "NO_EFFECT", 0
        self.assertFalse(verify_receiver_receipt(receipt, self.pin))

    def test_rebound_persisted_execution_invalidates_terminal_observation(self):
        receipt = self.store.commit(*self.issue())
        self.store.create_root("other")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE receiver_executions SET root_id='other' WHERE execution_id='worker'")
        with self.assertRaisesRegex(ControlError, "EXECUTION_BINDING_MISMATCH"):
            self.store.query("one", receipt["reservation_id"])
        with self.assertRaisesRegex(ControlError, "EXECUTION_BINDING_MISMATCH"):
            self.store.inventory()

    def test_cached_observed_query_revalidates_effect_after_deletion(self):
        client = self.client()
        first = client.commit(*self.issue())
        with patch("sdk.liminal_agent_control.external_agent_receiver.secrets.token_hex", return_value="9" * 64):
            self.assertEqual(client.query("one", first["reservation_id"]), first)
            with sqlite3.connect(self.path) as db:
                db.execute("DELETE FROM receiver_effects")
            with self.assertRaisesRegex(ControlError, "EFFECT_CORRUPT"):
                client.query("one", first["reservation_id"])

    def test_cached_unknown_query_stays_unknown_after_later_commit(self):
        client = self.client()
        inputs = self.issue()
        reservation = inputs[3]["result"]["reservation_id"]
        with patch("sdk.liminal_agent_control.external_agent_receiver.secrets.token_hex", return_value="8" * 64):
            unknown = client.query("one", reservation)
        client.commit(*inputs)
        with patch("sdk.liminal_agent_control.external_agent_receiver.secrets.token_hex", return_value="8" * 64):
            self.assertEqual(client.query("one", reservation), unknown)
        self.assertIsNone(unknown["receipt"])
        self.assertEqual(client.query("one", reservation)["receipt"]["status"], "COMMITTED")

    def test_concurrent_client_calls_keep_their_own_signed_evidence(self):
        client = self.client()
        first_returned, second_returned = threading.Event(), threading.Event()
        def first():
            client.query("first", "reservation:first")
            first_returned.set()
            self.assertTrue(second_returned.wait(3))
            return client.last_call_evidence()
        def second():
            self.assertTrue(first_returned.wait(3))
            client.query("second", "reservation:second")
            second_returned.set()
            return client.last_call_evidence()
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(first), pool.submit(second)
            pairs = [a.result(5), b.result(5)]
        self.assertEqual([pair["request"]["payload"]["action_id"] for pair in pairs], ["first", "second"])
        self.assertNotEqual(pairs[0]["request"]["nonce"], pairs[1]["request"]["nonce"])
        self.assertIsNone(client.last_call_evidence(), "a different thread cannot borrow call evidence")
        for pair in pairs:
            self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.pin), pair["response"]["result"])

    def test_call_evidence_is_detached_and_clears_after_transport_failure(self):
        client = self.client()
        client.query("missing", "reservation:missing")
        original = client.last_call_evidence()
        changed = client.last_call_evidence()
        changed["response"]["result"]["status"] = "FORGED"
        self.assertEqual(client.last_call_evidence(), original)
        self.assertEqual(client.evidence[-1], original)
        with patch.object(client._opener, "open", side_effect=URLError("owned fixture outage")):
            with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
                client.query("missing", "reservation:missing")
        self.assertIsNone(client.last_call_evidence())
        self.assertEqual(client.evidence[-1], original)


if __name__ == "__main__":
    unittest.main()
