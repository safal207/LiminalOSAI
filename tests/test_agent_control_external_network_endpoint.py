"""Actual owned-loopback effects, endpoint proof, and fail-closed replay tests.

The endpoint has a separate durable database and signing key. It accepts only
an already issued permit and performs one synthetic SQLite record transaction;
timeouts and absent queries are never negative proof of an external effect.
"""
from __future__ import annotations

import copy
import json
import socket
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority_service import (
    HTTPExternalAuthorityClient, RESPONSE_DOMAIN as AUTHORITY_RESPONSE_DOMAIN,
    make_server as make_authority_server, verify_authority_response,
)
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.external_network_endpoint import (
    HTTPNetworkEndpointClient, MAX_PACKET_BYTES, NetworkEndpointStore,
    REQUEST_SCHEMA, _request_signature, make_endpoint_server, verify_endpoint_response,
)
from sdk.liminal_agent_control.external_network_protocol import (
    network_action, receipt_matches_action, verify_endpoint_receipt,
)


AUTHORITY_PRIVATE = b"a" * 32
ENDPOINT_PRIVATE = b"e" * 32
RECEIPT_KEY = b"r" * 32
OPERATOR_KEY = b"o" * 32
AUTHORITY_REQUEST_KEY = b"q" * 32
GATEWAY_KEY = b"g" * 32
POLICY = "b" * 64


class ExternalNetworkEndpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.endpoint_path = self.directory / "endpoint.sqlite"
        # Reserve a numeric loopback origin before fixing its durable identity.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.endpoint_port = reservation.getsockname()[1]
        self.endpoint_url = f"http://127.0.0.1:{self.endpoint_port}"
        self.endpoint_pin = {
            "endpoint_id": "endpoint", "key_id": "endpoint-key",
            "public_key": Ed25519PrivateKey.from_private_bytes(ENDPOINT_PRIVATE)
                .public_key().public_bytes_raw().hex(),
        }
        self.now = 100.0
        self.authority = ExternalNetworkAuthorityStore(
            self.directory / "authority.sqlite", endpoint_pin=self.endpoint_pin,
            authority_id="authority", key_id="authority-key", private_key=AUTHORITY_PRIVATE,
            receipt_key=RECEIPT_KEY, clock=lambda: self.now,
        )
        self.authority.create_root("root", "endpoint", POLICY, 32, 100)
        self.authority.bind_execution("root", "worker")
        authority_server = make_authority_server(self.authority, OPERATOR_KEY, AUTHORITY_REQUEST_KEY)
        self.start_server(authority_server)
        self.authority_client = HTTPExternalAuthorityClient(
            f"http://127.0.0.1:{authority_server.server_address[1]}",
            AUTHORITY_REQUEST_KEY, self.authority.pin(),
        )
        self.store = self.open_store()
        self.endpoint_server = None

    def start_server(self, server):
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(3)
            self.assertFalse(thread.is_alive(), "owned service thread leaked")

        self.addCleanup(close)
        return server

    def open_store(self, *, create=True, db_path=None, **changes):
        options = dict(endpoint_id="endpoint", key_id="endpoint-key", private_key=ENDPOINT_PRIVATE,
                       authority_pin=self.authority.pin(), endpoint_url=self.endpoint_url,
                       gateway_key=GATEWAY_KEY, create=create)
        options.update(changes)
        return NetworkEndpointStore(self.endpoint_path if db_path is None else db_path, **options)

    def client(self, **server_options):
        if self.endpoint_server is None:
            self.endpoint_server = self.start_server(make_endpoint_server(
                self.store, port=self.endpoint_port, **server_options,
            ))
        return HTTPNetworkEndpointClient(self.endpoint_url, GATEWAY_KEY, self.endpoint_pin)

    def issue(self, name="one", *, expires_at=150):
        action = network_action(root_id="root", execution_id="worker", epoch=1,
            action_id=name, attempt_id="attempt:" + name, endpoint_url=self.endpoint_url, marker=name)
        authorization = {"action_digest": digest(action), "policy_version": POLICY,
                         "expires_at": expires_at, "receiver_id": "endpoint"}
        result = self.authority_client.begin(action, authorization)
        self.assertEqual(result["status"], "PERMITTED")
        evidence = self.authority_client.evidence[-1]
        return action, authorization, evidence["request"], evidence["response"]

    def assert_no_effects(self):
        inventory = self.store.inventory()
        self.assertEqual(inventory["effects"], [])
        self.assertEqual(inventory["receipts"], [])
        self.assertEqual(inventory["requests"], [])

    def test_real_http_commit_has_one_effect_and_exact_endpoint_signed_proof(self):
        inputs = self.issue()
        observed = self.client().commit(*inputs)
        receipt = observed["receipt"]
        reservation_id = inputs[3]["result"]["reservation_id"]
        self.assertEqual((observed["status"], observed["effect_count"]), ("OBSERVED", 1))
        self.assertTrue(verify_endpoint_receipt(receipt, self.endpoint_pin))
        self.assertTrue(receipt_matches_action(receipt, *inputs[:2], reservation_id, self.endpoint_pin))
        inventory = self.store.inventory()
        self.assertEqual(len(inventory["effects"]), 1)
        self.assertEqual(inventory["effects"][0]["body"], {"synthetic_marker": "one"})
        self.assertEqual(inventory["receipts"], [receipt])
        self.assertEqual(inventory["requests"][0]["permit"], inputs[3])
        self.assertNotIn("signature", inventory["requests"][0]["permit_request"])
        self.assertEqual(self.authority.status("root")["pending_count"], 1)
        self.assertEqual(self.authority.finish(reservation_id, receipt)["outcome"], "COMMITTED")
        self.assertEqual(self.authority.status("root")["pending_count"], 0)

    def test_identical_http_retry_and_query_return_existing_receipt_without_new_effect(self):
        inputs = self.issue()
        client = self.client()
        first = client.commit(*inputs)
        self.assertEqual(client.commit(*inputs), first)
        queried = client.query("one", first["reservation_id"])
        self.assertEqual(queried, first)
        reopened = self.open_store(create=False)
        self.assertEqual(reopened.commit(*inputs), first["receipt"])
        self.assertEqual(len(reopened.inventory()["effects"]), 1)
        self.assertEqual(reopened.inventory()["commit_request_count"], 3)

    def test_exact_original_permit_replay_after_stopped_returns_same_proof_without_new_effect(self):
        inputs = self.issue()
        client = self.client()
        first = client.commit(*inputs)
        self.authority.finish(first["reservation_id"], first["receipt"])
        ack = self.authority.stop("root")
        self.assertEqual((ack["status"], ack["pending_count"]), ("STOPPED", 0))
        self.assertEqual(client.commit(*inputs), first)
        self.assertEqual(client.query("one", first["reservation_id"]), first)
        inventory = self.store.inventory()
        self.assertEqual(len(inventory["effects"]), 1)
        self.assertEqual(inventory["receipts"], [first["receipt"]])
        self.assertEqual(inventory["commit_request_count"], 2)
        self.assertEqual(self.authority.status("root")["committed_count"], 1)
        self.assertEqual(self.authority.stop("root")["status"], "STOPPED")

    def test_concurrent_identical_http_retries_commit_exactly_one_record(self):
        inputs = self.issue()
        self.client()
        barrier = threading.Barrier(8)

        def commit(_):
            candidate = HTTPNetworkEndpointClient(self.endpoint_url, GATEWAY_KEY, self.endpoint_pin)
            barrier.wait()
            return candidate.commit(*inputs)

        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(commit, range(8)))
        self.assertTrue(all(item == receipts[0] for item in receipts))
        self.assertEqual(len(self.store.inventory()["effects"]), 1)
        self.assertEqual(self.store.inventory()["commit_request_count"], 8)
        self.assertEqual(self.authority.status("root")["issued_count"], 1)

    def test_absent_or_wrong_reservation_query_is_unknown_with_no_negative_proof(self):
        inputs = self.issue()
        client = self.client()
        reservation = inputs[3]["result"]["reservation_id"]
        for action_id, reservation_id in (("one", reservation), ("other", reservation), ("one", "other-reservation")):
            unknown = client.query(action_id, reservation_id)
            self.assertEqual(unknown["status"], "UNKNOWN")
            self.assertIsNone(unknown["effect_count"])
            self.assertIsNone(unknown["receipt"])
        self.assert_no_effects()
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self.authority.status("root")["pending_count"], 1)

    def test_delayed_issued_permit_commits_after_stop_request_and_deadline(self):
        inputs = self.issue(expires_at=101)
        reached, release = threading.Event(), threading.Event()

        def delayed():
            reached.set()
            if not release.wait(5):
                raise ControlError("test barrier timed out")

        client = self.client(before_commit=delayed)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.commit, *inputs)
            try:
                self.assertTrue(reached.wait(3))
                ack = self.authority.stop("root")
                self.assertEqual((ack["status"], ack["pending_count"]), ("STOP_PENDING", 1))
                self.now = 1000
                self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
            finally:
                release.set()
            observed = pending.result(timeout=5)
        self.assertEqual(len(self.store.inventory()["effects"]), 1)
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        self.authority.finish(observed["reservation_id"], observed["receipt"])
        self.assertEqual(self.authority.stop("root")["status"], "STOPPED")

    def test_lost_commit_response_recovers_by_read_query_only(self):
        inputs = self.issue()
        client = self.client(drop_commit_response=True)
        with self.assertRaisesRegex(ControlError, "UNAVAILABLE"):
            client.commit(*inputs)
        inventory = self.store.inventory()
        self.assertEqual((len(inventory["effects"]), inventory["commit_request_count"]), (1, 1))
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        proof = client.query("one", inputs[3]["result"]["reservation_id"])
        self.assertEqual(proof["status"], "OBSERVED")
        self.assertEqual(self.store.inventory()["commit_request_count"], 1)
        self.authority.finish(proof["reservation_id"], proof["receipt"])
        self.assertEqual(self.authority.stop("root")["status"], "STOPPED")

    def test_unavailable_query_hides_existing_effect_as_unknown_and_never_drains_stop(self):
        inputs = self.issue()
        client = self.client(query_unavailable=True)
        committed = client.commit(*inputs)
        unknown = client.query("one", committed["reservation_id"])
        self.assertEqual(unknown["status"], "UNKNOWN")
        self.assertIsNone(unknown["effect_count"])
        self.assertIsNone(unknown["receipt"])
        self.assertEqual(len(self.store.inventory()["effects"]), 1)
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")

    def test_fault_before_atomic_commit_has_no_record_or_receipt_and_retains_external_pending(self):
        inputs = self.issue()

        def fail():
            raise ControlError("injected before atomic commit")

        with self.assertRaises(ControlError):
            self.store.commit(*inputs, before_commit=fail)
        self.assert_no_effects()
        queried = self.store.query("one", inputs[3]["result"]["reservation_id"])
        self.assertEqual(queried["status"], "UNKNOWN")
        self.assertIsNone(queried["effect_count"])
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")

    def test_action_authorization_and_permit_request_mutations_fail_before_effect(self):
        original = self.issue()
        mutations = [
            (0, lambda v: v.update(action_id="other")),
            (0, lambda v: v.update(attempt_id="other")),
            (0, lambda v: v.update(execution_id="other")),
            (0, lambda v: v.update(epoch=True)),
            (0, lambda v: v["arguments"]["body"].update(synthetic_marker="changed")),
            (0, lambda v: v["arguments"].update(method="GET")),
            (0, lambda v: v["arguments"].update(url="http://127.0.0.1:1/v1/record")),
            (0, lambda v: v["arguments"]["body"].update(secret="forbidden")),
            (1, lambda v: v.update(receiver_id="other")),
            (1, lambda v: v.update(policy_version="c" * 64)),
            (1, lambda v: v.update(expires_at=151)),
            (2, lambda v: v.update(nonce="0" * 64)),
            (2, lambda v: v.update(role="admin")),
            (2, lambda v: v.update(operation="query")),
        ]
        for number, (index, mutate) in enumerate(mutations):
            with self.subTest(mutation=number):
                inputs = copy.deepcopy(original)
                mutate(inputs[index])
                with self.assertRaises(ControlError):
                    self.store.commit(*inputs)
                self.assert_no_effects()
        self.assertEqual(self.authority.status("root")["pending_count"], 1)

    def test_corrupt_or_wrong_pin_permit_is_not_endpoint_authorization(self):
        inputs = self.issue()
        corrupt = copy.deepcopy(inputs)
        corrupt[3]["signature"] = "0" * 128
        with self.assertRaises(ControlError):
            self.store.commit(*corrupt)
        self.assert_no_effects()
        other_path = self.directory / "wrong-pin.sqlite"
        wrong_pin = {**self.authority.pin(), "public_key": "0" * 64}
        other_store = self.open_store(db_path=other_path, authority_pin=wrong_pin)
        with self.assertRaises(ControlError):
            other_store.commit(*inputs)
        self.assertEqual(other_store.inventory()["effects"], [])

    def test_equal_numeric_value_with_different_canonical_grant_cannot_cross_permit_binding(self):
        inputs = list(self.issue(expires_at=150))
        inputs[1] = {**inputs[1], "expires_at": 150.0}
        # Python's dict equality accepts 150 == 150.0, while their committed
        # canonical bytes and authority authorization digests are different.
        self.assertNotEqual(digest(inputs[1]), digest(inputs[2]["payload"]["authorization"]))
        with self.assertRaises(ControlError):
            self.store.commit(*inputs)
        self.assert_no_effects()

    def test_mutable_caller_permit_is_frozen_before_callback_and_evidence_commit(self):
        inputs = self.issue()
        original = copy.deepcopy(inputs)

        def mutate_caller_input():
            inputs[2]["nonce"] = "f" * 64
            inputs[3]["result"]["status"] = "UNKNOWN"

        receipt = self.store.commit(*inputs, before_commit=mutate_caller_input)
        captured = self.store.inventory()["requests"][0]
        self.assertEqual(captured["permit_request"], original[2])
        self.assertEqual(captured["permit"], original[3])
        self.assertEqual(captured["permit_digest"], digest(original[3]))
        verify_authority_response(captured["permit_request"], captured["permit"], self.authority.pin())
        self.assertEqual(self.store.commit(*original), receipt)

    def test_authenticated_unknown_authority_response_never_becomes_permit(self):
        inputs = self.issue()
        self.assertEqual(self.authority_client.begin(*inputs[:2])["status"], "UNKNOWN")
        evidence = self.authority_client.evidence[-1]
        with self.assertRaisesRegex(ControlError, "PERMIT_BINDING"):
            self.store.commit(*inputs[:2], evidence["request"], evidence["response"])
        self.assert_no_effects()

    def test_alternate_signed_permit_for_same_action_cannot_replace_recorded_permit(self):
        inputs = self.issue()
        first = self.store.commit(*inputs)
        changed = copy.deepcopy(inputs)
        changed[3]["issued_at"] += 1
        body = {key: value for key, value in changed[3].items() if key != "signature"}
        changed[3]["signature"] = Ed25519PrivateKey.from_private_bytes(AUTHORITY_PRIVATE).sign(
            AUTHORITY_RESPONSE_DOMAIN + canonical_bytes(body)).hex()
        with self.assertRaisesRegex(ControlError, "REUSE_MISMATCH"):
            self.store.commit(*changed)
        self.assertEqual(self.store.inventory()["receipts"], [first])
        self.assertEqual(len(self.store.inventory()["effects"]), 1)

    def test_request_credentials_role_path_payload_and_duplicate_json_fail_closed(self):
        inputs = self.issue()
        client = self.client()
        wrong_key = HTTPNetworkEndpointClient(self.endpoint_url, b"x" * 32, self.endpoint_pin)
        with self.assertRaises(ControlError):
            wrong_key.commit(*inputs)
        body = {"schema": REQUEST_SCHEMA, "role": "gateway", "operation": "commit", "nonce": "1" * 64,
                "payload": dict(zip(("action", "authorization", "permit_request", "permit"), inputs))}

        def wire(candidate):
            return canonical_bytes({**candidate, "signature": _request_signature(candidate, GATEWAY_KEY)})

        invalid = [
            ("/v1/record", wire({**body, "role": "admin"}), "application/json"),
            ("/v1/query", wire(body), "application/json"),
            ("/wrong", wire(body), "application/json"),
            ("/v1/record", wire(body), "text/plain"),
            ("/v1/record", b"x" * (MAX_PACKET_BYTES + 1), "application/json"),
            ("/v1/record", b'{"schema":"one","schema":"two"}', "application/json"),
        ]
        for path, payload, content_type in invalid:
            with self.subTest(path=path, content_type=content_type, size=len(payload)):
                request = Request(self.endpoint_url + path, data=payload, method="POST",
                                  headers={"Content-Type": content_type})
                with self.assertRaises(HTTPError):
                    urlopen(request, timeout=2)
                self.assert_no_effects()
        extra = {**body["payload"], "extra": "not-authorized"}
        with self.assertRaisesRegex(ControlError, "PAYLOAD_INVALID"):
            client._call("commit", extra)
        self.assert_no_effects()
        self.assertEqual(self.store.inventory()["commit_request_count"], 0)

    def test_response_proof_is_fresh_bound_pinned_and_returns_detached_evidence(self):
        inputs = self.issue()
        client = self.client()
        client.commit(*inputs)
        captured = client.evidence[-1]
        self.assertNotIn("signature", captured["request"])
        verify_endpoint_response(captured["request"], captured["response"], self.endpoint_pin)
        with self.assertRaises(ControlError):
            verify_endpoint_response({**captured["request"], "nonce": "2" * 64},
                                     captured["response"], self.endpoint_pin)
        changed = copy.deepcopy(captured["response"])
        changed["result"]["effect_count"] = 0
        with self.assertRaises(ControlError):
            verify_endpoint_response(captured["request"], changed, self.endpoint_pin)
        with self.assertRaises(ControlError):
            verify_endpoint_response(captured["request"], captured["response"],
                                     {**self.endpoint_pin, "public_key": "0" * 64})
        captured["response"]["result"]["effect_count"] = 999
        self.assertEqual(client.evidence[-1]["response"]["result"]["effect_count"], 1)

    def test_reopen_configuration_and_live_configuration_drift_fail_closed(self):
        inputs = self.issue()
        first = self.store.commit(*inputs)
        for changes in ({"endpoint_id": "other"}, {"key_id": "other"},
                        {"private_key": b"z" * 32}, {"gateway_key": b"x" * 32},
                        {"endpoint_url": "http://127.0.0.1:1"},
                        {"authority_pin": {**self.authority.pin(), "public_key": "0" * 64}}):
            with self.subTest(fields=list(changes)), self.assertRaises(ControlError):
                self.open_store(create=False, **changes)
        self.store.url = "http://127.0.0.1:1"
        with self.assertRaises(ControlError):
            self.store.commit(*inputs)
        self.store.url = self.endpoint_url
        self.assertEqual(self.store.inventory()["receipts"], [first])

    def test_missing_state_and_damaged_schema_are_never_silently_initialized(self):
        missing = self.directory / "missing.sqlite"
        with self.assertRaises(ControlError):
            self.open_store(create=False, db_path=missing)
        self.assertFalse(missing.exists())
        with sqlite3.connect(self.endpoint_path) as db:
            db.execute("DROP TABLE network_endpoint_effects")
        with self.assertRaises((ControlError, sqlite3.DatabaseError)):
            self.open_store(create=True)
        with sqlite3.connect(self.endpoint_path) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='network_endpoint_effects'").fetchone())

    def test_capacity_denies_new_effect_but_preserves_exact_retry_and_query(self):
        one, two = self.issue("one"), self.issue("two")
        with patch("sdk.liminal_agent_control.external_network_endpoint.MAX_EFFECTS", 1):
            first = self.store.commit(*one)
            with self.assertRaisesRegex(ControlError, "CAPACITY"):
                self.store.commit(*two)
            self.assertEqual(self.store.commit(*one), first)
            self.assertEqual(self.store.query("one", first["reservation_id"])["receipt"], first)
        self.assertEqual(len(self.store.inventory()["effects"]), 1)
        self.assertEqual(self.authority.stop("root")["pending_count"], 2)

    def test_numeric_origin_and_server_port_cannot_be_substituted(self):
        for url in ("https://127.0.0.1:1", "http://localhost:1", "http://127.0.0.1:1/",
                    "http://127.0.0.1:1/v1/record", "http://user@127.0.0.1:1",
                    "http://127.0.0.1:1?x=1", "http://127.0.0.1:01", "http://127.0.0.1:0"):
            with self.subTest(url=url), self.assertRaises(ControlError):
                HTTPNetworkEndpointClient(url, GATEWAY_KEY, self.endpoint_pin)
        with self.assertRaises(ControlError):
            make_endpoint_server(self.store, port=1 if self.endpoint_port != 1 else 2)
        with self.assertRaises(ControlError):
            HTTPNetworkEndpointClient(self.endpoint_url, GATEWAY_KEY, self.endpoint_pin, timeout=True)


if __name__ == "__main__":
    unittest.main()
