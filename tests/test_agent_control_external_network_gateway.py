"""Real HTTP and durable state regressions for the exact host-grant gateway."""
from __future__ import annotations

import copy
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server as make_authority_server
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.external_network_endpoint import (
    HTTPNetworkEndpointClient, NetworkEndpointStore, make_endpoint_server,
)
from sdk.liminal_agent_control.external_network_gateway import (
    HTTPNetworkGatewayClient, NetworkGateway, make_gateway_server,
    REQUEST_SCHEMA, REQUEST_DOMAIN, _signature,
)
from sdk.liminal_agent_control.external_network_protocol import network_action, verify_endpoint_receipt
from sdk.liminal_agent_control.observer_auth import _crypto


AUTHORITY_SIGNING = b"\x71" * 32
ENDPOINT_SIGNING = b"\x72" * 32
AUTHORITY_RECEIPT = b"network-authority-unused-hmac-001" * 2
AUTHORITY_OPERATOR = b"network-authority-operator-key-002" * 2
AUTHORITY_REQUEST = b"network-authority-gateway-key-003" * 2
ENDPOINT_REQUEST = b"network-endpoint-gateway-key-004" * 2
GATEWAY_OPERATOR = b"network-gateway-operator-key-005" * 2
GATEWAY_WORKER = b"network-gateway-worker-key-006" * 2
POLICY = "a" * 64


class ExternalNetworkGatewayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.servers = []
        self.addCleanup(self.close_servers)
        private, _ = _crypto()
        self.endpoint_pin = {"endpoint_id": "owned-endpoint", "key_id": "endpoint-key",
            "public_key": private.from_private_bytes(ENDPOINT_SIGNING).public_key().public_bytes_raw().hex()}
        self.authority_now = 100.0
        self.authority = ExternalNetworkAuthorityStore(self.directory / "authority.sqlite",
            endpoint_pin=self.endpoint_pin, authority_id="external-controller", key_id="controller-key",
            private_key=AUTHORITY_SIGNING, receipt_key=AUTHORITY_RECEIPT, clock=lambda: self.authority_now)
        self.authority_server = make_authority_server(self.authority, AUTHORITY_OPERATOR, AUTHORITY_REQUEST)
        self.start(self.authority_server)
        self.authority_url = "http://127.0.0.1:" + str(self.authority_server.server_address[1])
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.endpoint_port = reservation.getsockname()[1]
        self.endpoint_url = "http://127.0.0.1:" + str(self.endpoint_port)
        self.endpoint = NetworkEndpointStore(self.directory / "endpoint.sqlite", endpoint_id="owned-endpoint",
            key_id="endpoint-key", private_key=ENDPOINT_SIGNING, authority_pin=self.authority.pin(),
            endpoint_url=self.endpoint_url, gateway_key=ENDPOINT_REQUEST)
        self.endpoint_server = make_endpoint_server(self.endpoint, port=self.endpoint_port)
        self.start(self.endpoint_server)
        self.gateway_path = self.directory / "gateway.sqlite"
        self.gateway = self.new_gateway()
        self.gateway_server = make_gateway_server(self.gateway)
        self.start(self.gateway_server)
        self.gateway_url = "http://127.0.0.1:" + str(self.gateway_server.server_address[1])
        self.admin = HTTPNetworkGatewayClient(self.gateway_url, GATEWAY_OPERATOR, role="admin")
        self.worker = HTTPNetworkGatewayClient(self.gateway_url, GATEWAY_WORKER)
        self.authority.create_root("root", "owned-endpoint", POLICY, 32, 3600)
        self.authority.bind_execution("root", "worker")

    def start(self, server):
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.005), daemon=True)
        thread.start()
        self.servers.append([server, thread, False])

    def stop(self, server):
        for entry in self.servers:
            if entry[0] is server and not entry[2]:
                server.shutdown()
                server.server_close()
                entry[1].join(3)
                self.assertFalse(entry[1].is_alive())
                entry[2] = True

    def close_servers(self):
        for server, _, _ in self.servers[::-1]:
            self.stop(server)

    def new_gateway(self, *, create=True, drop_begin_response=False, drop_finish_response=False):
        return NetworkGateway(self.gateway_path, gateway_id="gateway",
            external_controller=HTTPExternalAuthorityClient(self.authority_url, AUTHORITY_REQUEST, self.authority.pin()),
            endpoint_client=HTTPNetworkEndpointClient(self.endpoint_url, ENDPOINT_REQUEST, self.endpoint_pin),
            operator_key=GATEWAY_OPERATOR, worker_key=GATEWAY_WORKER, create=create,
            drop_begin_response=drop_begin_response, drop_finish_response=drop_finish_response)

    def action(self, name="operation"):
        return network_action(root_id="root", execution_id="worker", epoch=1, action_id=name,
            attempt_id="attempt:" + name, endpoint_url=self.endpoint_url, marker=name)

    def grant(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": POLICY,
            "expires_at": 200.0, "receiver_id": "owned-endpoint"}

    def authorize(self, proposed):
        return self.admin.authorize(proposed, self.grant(proposed))

    def snapshot(self):
        path = self.directory / "snapshot.sqlite"
        with sqlite3.connect(self.gateway_path) as source, sqlite3.connect(path) as target:
            source.backup(target)
        return path

    def restore(self, snapshot):
        with sqlite3.connect(snapshot) as source, sqlite3.connect(self.gateway_path) as target:
            source.backup(target)
        self.gateway = self.new_gateway(create=False)
        return self.gateway

    def test_operator_stored_exact_grant_executes_one_actual_effect_and_public_evidence(self):
        proposed = self.action()
        self.assertEqual(self.authorize(proposed)["status"], "AUTHORIZED")
        result = self.worker.execute(proposed)
        self.assertEqual((result["status"], result["effect_count"], result["remote_outcome"], result["settlement_status"]),
            ("COMMITTED", 1, "COMMITTED", "SETTLED"))
        self.assertTrue(result["dispatch_finished"])
        self.assertFalse(result["execution_authorized"])
        self.assertTrue(verify_endpoint_receipt(result["receipt"], self.endpoint_pin))
        self.assertEqual(len(self.endpoint.inventory()["effects"]), 1)
        self.assertEqual(self.authority.status("root")["committed_count"], 1)
        inventory = self.admin.inventory()
        self.assertEqual(len(inventory["authority_evidence"]), 2)
        self.assertEqual(len(inventory["endpoint_evidence"]), 1)
        self.assertEqual(inventory["actions"][0]["receipt"], result["receipt"])
        for pair in inventory["authority_evidence"] + inventory["endpoint_evidence"]:
            self.assertNotIn("signature", pair["request"])
            self.assertIn("signature", pair["response"])

    def test_worker_without_host_grant_cannot_contact_authority_or_endpoint(self):
        result = self.worker.execute(self.action())
        self.assertEqual(result["status"], "DENIED")
        self.assertIsNone(result["effect_count"])
        self.assertEqual(self.authority.status("root")["issued_count"], 0)
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.admin.inventory()["authority_evidence"], [])

    def test_worker_changed_proposal_cannot_use_operator_grant(self):
        proposed = self.action()
        self.authorize(proposed)
        changed = copy.deepcopy(proposed)
        changed["arguments"]["body"]["synthetic_marker"] = "changed"
        result = self.worker.execute(changed)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_grant_exact_canonical_identity_is_immutable(self):
        proposed = self.action()
        self.authorize(proposed)
        changed = self.grant(proposed)
        changed["expires_at"] = 200
        with self.assertRaisesRegex(ControlError, "GRANT_IMMUTABLE"):
            self.admin.authorize(proposed, changed)
        self.assertEqual(self.admin.inventory()["actions"][0]["authorization"]["expires_at"], 200.0)

    def test_worker_cannot_authorize_or_export_evidence_even_with_valid_worker_hmac(self):
        proposed = self.action()
        with self.assertRaisesRegex(ControlError, "ROLE_DENIED"):
            self.worker.authorize(proposed, self.grant(proposed))
        body = {"schema": REQUEST_SCHEMA, "role": "worker", "operation": "authorize", "nonce": "a" * 64,
            "payload": {"action": proposed, "authorization": self.grant(proposed)}}
        packet = {**body, "signature": _signature(body, GATEWAY_WORKER, REQUEST_DOMAIN)}
        opener = build_opener(ProxyHandler({}))
        with self.assertRaises(HTTPError) as error:
            opener.open(Request(self.gateway_url + "/v1/gateway", data=canonical_bytes(packet), method="POST",
                headers={"Content-Type": "application/json"}), timeout=3)
        self.assertEqual(error.exception.code, 403)
        with self.assertRaisesRegex(ControlError, "ROLE_DENIED"):
            self.worker.inventory()
        self.assertEqual(self.admin.inventory()["actions"], [])

    def test_admin_credentials_cannot_be_substituted_with_worker_key(self):
        impostor = HTTPNetworkGatewayClient(self.gateway_url, GATEWAY_WORKER, role="admin")
        with self.assertRaises(ControlError):
            impostor.authorize(self.action(), self.grant(self.action()))
        self.assertEqual(self.admin.inventory()["actions"], [])

    def test_repeated_execute_uses_fresh_authority_observation_without_second_post(self):
        proposed = self.action()
        self.authorize(proposed)
        first = self.worker.execute(proposed)
        second = self.worker.execute(proposed)
        self.assertEqual(second["receipt"], first["receipt"])
        self.assertFalse(second["dispatch_finished"])
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)
        self.assertEqual(self.authority.status("root")["issued_count"], 1)
        self.assertEqual(len(self.admin.inventory()["authority_evidence"]), 3)

    def test_reconcile_never_creates_permit_or_dispatch_for_unexecuted_grant(self):
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.reconcile(proposed["action_id"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["effect_count"])
        self.assertEqual(self.authority.status("root")["issued_count"], 0)
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual([pair["request"]["operation"] for pair in self.admin.inventory()["authority_evidence"]], ["query"])

    def test_lost_begin_response_consumes_permit_and_unknown_query_cannot_release_stop(self):
        self.gateway._drop_begin_response = True
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.execute(proposed)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["dispatch_finished"])
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        reconciled = self.worker.reconcile(proposed["action_id"])
        self.assertEqual(reconciled["status"], "UNKNOWN")
        self.assertIsNone(reconciled["effect_count"])
        self.assertEqual(self.authority.status("root")["pending_count"], 1)
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)

    def test_lost_endpoint_response_does_not_retry_and_query_receipt_settles(self):
        self.stop(self.endpoint_server)
        self.endpoint_server = make_endpoint_server(self.endpoint, port=self.endpoint_port, drop_commit_response=True)
        self.start(self.endpoint_server)
        proposed = self.action()
        self.authorize(proposed)
        unknown = self.worker.execute(proposed)
        self.assertEqual(unknown["status"], "UNKNOWN")
        self.assertTrue(unknown["dispatch_finished"])
        self.assertIsNone(unknown["effect_count"])
        self.assertEqual(len(self.endpoint.inventory()["effects"]), 1)
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        repeated = self.worker.execute(proposed)
        self.assertEqual(repeated["status"], "UNKNOWN")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)
        reconciled = self.worker.reconcile(proposed["action_id"])
        self.assertEqual((reconciled["status"], reconciled["effect_count"]), ("COMMITTED", 1))
        self.assertFalse(reconciled["dispatch_finished"])
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)
        self.assertEqual(self.authority.stop("root")["status"], "STOPPED")

    def test_local_callback_finished_without_receipt_still_keeps_remote_outcome_unknown(self):
        self.stop(self.endpoint_server)
        self.endpoint_server = make_endpoint_server(self.endpoint, port=self.endpoint_port,
            drop_commit_response=True, query_unavailable=True)
        self.start(self.endpoint_server)
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.execute(proposed)
        self.assertTrue(result["dispatch_finished"])
        self.assertIsNone(result["remote_outcome"])
        self.assertEqual(len(self.endpoint.inventory()["effects"]), 1)
        self.assertEqual(self.worker.reconcile(proposed["action_id"])["status"], "UNKNOWN")
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)

    def test_lost_finish_response_preserves_committed_proof_and_reconciles_without_dispatch(self):
        self.gateway._drop_finish_response = True
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.execute(proposed)
        self.assertEqual((result["status"], result["effect_count"], result["remote_outcome"], result["settlement_status"]),
            ("UNKNOWN", 1, "COMMITTED", "UNKNOWN"))
        self.assertEqual(self.authority.status("root")["pending_count"], 0)
        observed = self.worker.reconcile(proposed["action_id"])
        self.assertEqual(observed["status"], "COMMITTED")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)
        self.assertEqual(observed["receipt"], result["receipt"])

    def test_endpoint_outage_consumes_pending_permit_and_never_asserts_zero_effect(self):
        self.stop(self.endpoint_server)
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.execute(proposed)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(result["dispatch_finished"])
        self.assertIsNone(result["effect_count"])
        self.assertEqual(self.authority.status("root")["pending_count"], 1)
        self.assertEqual(self.worker.execute(proposed)["status"], "UNKNOWN")
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")

    def test_external_authority_outage_cannot_send_endpoint_post(self):
        self.stop(self.authority_server)
        proposed = self.action()
        self.authorize(proposed)
        result = self.worker.execute(proposed)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["dispatch_finished"])
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_restore_gateway_database_after_terminal_cannot_dispatch_cached_permit(self):
        proposed = self.action()
        self.authorize(proposed)
        snapshot = self.snapshot()
        first = self.worker.execute(proposed)
        restored = self.restore(snapshot)
        replayed = restored.execute(proposed)
        self.assertEqual(replayed["receipt"], first["receipt"])
        self.assertFalse(replayed["dispatch_finished"])
        self.assertEqual(restored.reconcile(proposed["action_id"])["status"], "COMMITTED")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 1)
        self.assertEqual(len(self.endpoint.inventory()["effects"]), 1)
        self.assertEqual(self.authority.status("root")["issued_count"], 1)

    def test_restore_old_gateway_grant_after_stop_ack_cannot_send_post(self):
        proposed = self.action()
        self.authorize(proposed)
        snapshot = self.snapshot()
        self.assertEqual(self.authority.stop("root")["status"], "STOPPED")
        result = self.restore(snapshot).execute(proposed)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_live_boundary_configuration_cannot_downgrade_or_change_pins_roles_keys_urls(self):
        proposed = self.action()
        self.authorize(proposed)
        mutations = [
            (self.gateway, "external_controller", None),
            (self.gateway.external_controller, "role", "admin"),
            (self.gateway.external_controller, "url", "http://127.0.0.1:1"),
            (self.gateway.external_controller, "_request_key", b"changed-authority-key" * 2),
            (self.gateway.external_controller, "_pin", {**self.authority.pin(), "key_id": "changed"}),
            (self.gateway.endpoint_client, "url", "http://127.0.0.1:1"),
            (self.gateway.endpoint_client, "request_key", b"changed-endpoint-key" * 2),
            (self.gateway.endpoint_client, "_pin", {**self.endpoint_pin, "key_id": "changed"}),
            (self.gateway, "operator_key", b"changed-operator-key" * 2),
            (self.gateway, "worker_key", b"changed-worker-key" * 2),
        ]
        for target, field, replacement in mutations:
            original = getattr(target, field)
            setattr(target, field, replacement)
            try:
                with self.subTest(field=field), self.assertRaises(ControlError):
                    self.gateway.execute(proposed)
                with self.assertRaises(ControlError):
                    self.gateway.reconcile(proposed["action_id"])
            finally:
                setattr(target, field, original)
        self.assertEqual(self.endpoint.inventory()["commit_request_count"], 0)
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_missing_gateway_state_requires_explicit_initialization_without_silent_repair(self):
        missing = self.directory / "missing.sqlite"
        with self.assertRaisesRegex(ControlError, "STATE_MISSING"):
            NetworkGateway(missing, gateway_id="gateway", external_controller=self.gateway.external_controller,
                endpoint_client=self.gateway.endpoint_client, operator_key=GATEWAY_OPERATOR,
                worker_key=GATEWAY_WORKER, create=False)
        self.assertFalse(missing.exists())
        with sqlite3.connect(self.gateway_path) as db:
            db.execute("DELETE FROM network_gateway_meta")
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            self.new_gateway(create=True)
        with sqlite3.connect(self.gateway_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM network_gateway_meta").fetchone()[0], 0)

    def test_gateway_role_credentials_must_all_differ(self):
        with self.assertRaisesRegex(ControlError, "KEYS_MUST_DIFFER"):
            NetworkGateway(self.directory / "bad.sqlite", gateway_id="bad", external_controller=self.gateway.external_controller,
                endpoint_client=self.gateway.endpoint_client, operator_key=GATEWAY_WORKER, worker_key=GATEWAY_WORKER)


if __name__ == "__main__":
    unittest.main()
