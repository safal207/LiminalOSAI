"""G03 signed loopback settlement and coordinator races with explicit Docker doubles.

Authorities, receiver effects, HTTP signatures and durable journals are real.
The supervisor/bridge doubles provide no Docker containment measurement.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_authority import ExternalAgentAuthorityStore
from sdk.liminal_agent_control.external_agent_bridge import ExternalAgentBridge
from sdk.liminal_agent_control.external_agent_receiver_bridge import ReceiverFencedAgentBridge
from sdk.liminal_agent_control.external_agent_coordinator import (
    RUN_SCHEMA, ExternalAgentCoordinator, agent_policy_digest,
)
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256, agent_action, agent_spec
from sdk.liminal_agent_control.external_agent_receiver import (
    HTTPReceiverFenceClient, ReceiverFenceStore, make_receiver_server, verify_receiver_response,
)
from sdk.liminal_agent_control.external_agent_receiver_authority import ExternalAgentReceiverAuthorityStore
from sdk.liminal_agent_control.external_agent_receiver_gateway import ReceiverFencedEffectGateway
from sdk.liminal_agent_control import external_agent_receiver_protocol as receiver_protocol
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.external_network_protocol import network_action
from tests.test_agent_control_external_agent_coordinator import FakeSupervisor
from tests.test_agent_control_external_agent_supervisor import FakeBridge, public_pin

IMAGE = "sha256:" + "c" * 64
RECEIVER_PRIVATE_KEY = b"D" * 32


class ExternalAgentReceiverIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.supervisor_pin = public_pin("supervisor", b"B" * 32, "supervisor")
        self.endpoint_pin = public_pin("endpoint", RECEIVER_PRIVATE_KEY, "endpoint")
        self.command_store = ExternalAgentAuthorityStore(
            self.directory / "command.sqlite", supervisor_pin=self.supervisor_pin,
            authority_id="command-authority", key_id="command-key", private_key=b"A" * 32,
            receipt_key=b"unused-command-receipt" * 2,
        )
        self.effect_store = ExternalAgentReceiverAuthorityStore(
            self.directory / "effect.sqlite", endpoint_pin=self.endpoint_pin,
            authority_id="effect-authority", key_id="effect-key", private_key=b"C" * 32,
            receipt_key=b"unused-effect-receipt" * 2,
        )
        self.servers, self.threads = [], []
        self.command_admin, self.command_receiver = self.serve_authority(self.command_store, b"ca" * 16, b"cr" * 16)
        self.effect_admin, self.effect_receiver = self.serve_authority(self.effect_store, b"ea" * 16, b"er" * 16)
        self.addCleanup(self.shutdown)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.receiver = ReceiverFenceStore(
            self.directory / "receiver.sqlite", endpoint_id="endpoint", key_id="endpoint-key",
            private_key=RECEIVER_PRIVATE_KEY, authority_pin=self.effect_store.pin(), endpoint_url=self.url,
            gateway_key=b"g" * 32, operator_key=b"o" * 32,
        )
        self.start_server(make_receiver_server(self.receiver, port=port))
        self.endpoint = HTTPReceiverFenceClient(self.url, b"g" * 32, self.endpoint_pin, operator_key=b"o" * 32)
        spec = agent_spec("owned-command", IMAGE, str(self.directory / "workspace"))
        self.spec = spec
        self.action = network_action(
            action_id="effect-action", attempt_id="effect-attempt", root_id="effect-root",
            execution_id="effect-worker", epoch=1, endpoint_url=self.url, marker="bounded-marker",
        )
        self.binding = {
            "schema": RUN_SCHEMA, "run_id": "receiver-run",
            "command": {"root_id": "command-root", "execution_id": "command-worker", "epoch": 1, "authority_pin": self.command_store.pin()},
            "effect": {"root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1, "authority_pin": self.effect_store.pin()},
            "supervisor_pin": self.supervisor_pin, "endpoint_pin": self.endpoint_pin,
            "effect_actions": [self.action], "effect_action_digests": [digest(self.action)],
            "source_digest": AGENT_FIXTURE_SHA256, "spec_digest": digest(spec),
        }
        for branch, store, endpoint in (
            ("command", self.command_store, "supervisor"), ("effect", self.effect_store, "endpoint"),
        ):
            store.create_root(self.binding[branch]["root_id"], endpoint, agent_policy_digest(self.binding, branch), 32, 3600)
            store.bind_execution(self.binding[branch]["root_id"], self.binding[branch]["execution_id"])
        self.endpoint.create_root("effect-root")
        self.endpoint.bind_execution("effect-root", "effect-worker")
        self.gateway = ReceiverFencedEffectGateway(
            self.directory / "gateway.sqlite", run_binding=self.binding, gateway_id="gateway",
            external_controller=self.effect_receiver, endpoint_client=self.endpoint,
            operator_key=b"go" * 16, worker_key=b"gw" * 16,
        )
        self.authorization = {
            "action_digest": digest(self.action), "policy_version": agent_policy_digest(self.binding, "effect"),
            "expires_at": time.time() + 120, "receiver_id": "endpoint",
        }
        self.gateway.authorize(self.action, self.authorization)
        self.bridge = FakeBridge({
            "run_binding": {"run_id": "receiver-run", "root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1},
            "actions": [self.action], "effect_gateway_configuration": json.loads(self.gateway._configuration()),
        })
        self.bridge.executor = self.gateway.execute
        self.bridge._configuration["effect_gateway_configuration"] = json.loads(self.gateway._configuration())
        self.supervisor = FakeSupervisor(self.supervisor_pin, self.bridge)
        self.coordinator = ExternalAgentCoordinator(
            self.directory / "coordinator.sqlite", run_binding=self.binding, supervisor=self.supervisor,
            command_admin_client=self.command_admin, effect_admin_client=self.effect_admin,
            effect_gateway=self.gateway, bridge=self.bridge, start_watcher=False,
            receiver_fence_client=self.endpoint,
        )

    def start_server(self, server):
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.005), daemon=True)
        thread.start()
        self.servers.append(server)
        self.threads.append(thread)

    def serve_authority(self, store, admin_key, receiver_key):
        server = make_server(store, admin_key, receiver_key)
        self.start_server(server)
        url = f"http://127.0.0.1:{server.server_address[1]}"
        return (
            HTTPExternalAuthorityClient(url, admin_key, store.pin(), role="admin"),
            HTTPExternalAuthorityClient(url, receiver_key, store.pin()),
        )

    def shutdown(self):
        if hasattr(self, "coordinator"):
            self.coordinator.close()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(3)
            self.assertFalse(thread.is_alive())

    def begin(self):
        result = self.effect_receiver.begin(self.action, self.authorization)
        self.assertEqual(result["status"], "PERMITTED")
        return result, self.effect_receiver.evidence[-1]

    def terminal(self, *, stop=False):
        result, pair = self.begin()
        fence = self.endpoint.stop("effect-root") if stop else None
        observed = self.endpoint.commit(self.action, self.authorization, pair["request"], pair["response"])
        self.assertEqual(observed["reservation_id"], result["reservation_id"])
        return observed["receipt"], fence

    def test_committed_receipt_settles_original_permit_without_second_dispatch(self):
        receipt, _ = self.terminal()
        first = self.gateway.reconcile(self.action["action_id"])
        second = self.gateway.reconcile(self.action["action_id"])
        for result in (first, second):
            self.assertEqual((result["status"], result["remote_outcome"], result["effect_count"]), ("COMMITTED", "COMMITTED", 1))
            self.assertEqual(result["receipt"], receipt)
            self.assertEqual(result["settlement_status"], "SETTLED")
            self.assertFalse(result["dispatch_finished"])
        authority = self.effect_receiver.query(self.action["action_id"])
        self.assertEqual((authority["status"], authority["outcome"]), ("CONSUMED", "COMMITTED"))
        self.assertEqual(self.effect_store.status("effect-root")["pending_count"], 0)
        inventory = self.receiver.inventory()
        self.assertEqual((len(inventory["effects"]), inventory["commit_request_count"]), (1, 1))
        self.assertEqual(self.effect_receiver.begin(self.action, self.authorization)["status"], "CONSUMED")

    def test_signed_no_effect_settles_denied_and_closes_pending_authority_root(self):
        receipt, fence = self.terminal(stop=True)
        self.assertEqual(self.effect_admin.stop("effect-root")["status"], "STOP_PENDING")
        first = self.gateway.reconcile(self.action["action_id"])
        second = self.gateway.reconcile(self.action["action_id"])
        for result in (first, second):
            self.assertEqual((result["status"], result["remote_outcome"], result["effect_count"]), ("NO_EFFECT", "NO_EFFECT", 0))
            self.assertEqual(result["receipt"], receipt)
            self.assertEqual(result["settlement_status"], "SETTLED")
        self.assertEqual(receipt["fence_digest"], digest(fence))
        authority = self.effect_receiver.query(self.action["action_id"])
        self.assertEqual((authority["status"], authority["outcome"]), ("CONSUMED", "DENIED"))
        root = self.effect_store.status("effect-root")
        self.assertEqual((root["state"], root["pending_count"], root["denied_count"]), ("STOPPED", 0, 1))
        inventory = self.receiver.inventory()
        self.assertEqual((inventory["effects"], inventory["commit_request_count"]), ([], 1))

    def test_absent_query_after_fence_preserves_unknown_consumed_reservation(self):
        permit, _ = self.begin()
        self.endpoint.stop("effect-root")
        self.effect_admin.stop("effect-root")
        result = self.gateway.reconcile(self.action["action_id"])
        self.assertEqual((result["status"], result["settlement_status"]), ("UNKNOWN", "UNKNOWN"))
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["effect_count"])
        self.assertEqual(result["reservation_id"], permit["reservation_id"])
        self.assertEqual(self.effect_store.status("effect-root")["pending_count"], 1)
        retry = self.effect_receiver.begin(self.action, self.authorization)
        self.assertEqual((retry["status"], retry["outcome"]), ("UNKNOWN", None))
        self.assertEqual(retry["reservation_id"], permit["reservation_id"])
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 1)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 0)

    def test_legacy_authority_rejects_g03_terminal_domain(self):
        receipt, _ = self.terminal(stop=True)
        legacy = ExternalNetworkAuthorityStore(
            self.directory / "legacy.sqlite", endpoint_pin=self.endpoint_pin,
            authority_id="legacy", key_id="legacy", private_key=b"L" * 32, receipt_key=b"r" * 32,
        )
        with self.assertRaisesRegex(ControlError, "ENDPOINT_RECEIPT_INVALID"):
            legacy.finish(receipt["reservation_id"], receipt)
        with self.assertRaises(ControlError):
            ExternalNetworkAuthorityStore(
                self.effect_store.db_path, endpoint_pin=self.endpoint_pin,
                authority_id="effect-authority", key_id="effect-key", private_key=b"C" * 32,
                receipt_key=b"unused-effect-receipt" * 2, create=False,
            )

    def test_tampered_terminal_does_not_settle_pending_authority(self):
        receipt, _ = self.terminal(stop=True)
        tampered = copy.deepcopy(receipt)
        tampered["fence_digest"] = "0" * 64
        with self.assertRaisesRegex(ControlError, "RECEIVER_RECEIPT_INVALID"):
            self.effect_receiver.finish(receipt["reservation_id"], tampered)
        self.assertEqual(self.effect_store.status("effect-root")["pending_count"], 1)
        self.assertEqual(self.gateway.reconcile(self.action["action_id"])["status"], "NO_EFFECT")

    def test_inconsistent_signed_authority_outcome_cannot_become_settled_gateway_proof(self):
        receipt, _ = self.terminal()
        self.assertEqual(self.gateway.reconcile(self.action["action_id"])["status"], "COMMITTED")
        # An independently signed receiver proof remains COMMITTED, but a
        # malformed authority row now makes its fresh signed query say DENIED.
        with sqlite3.connect(self.effect_store.db_path) as database:
            database.execute("UPDATE external_actions SET status='DENIED',reason='AUTHENTICATED_RECEIVER_DENIED' WHERE action_id=?", (self.action["action_id"],))
        contradiction = self.effect_receiver.query(self.action["action_id"])
        self.assertEqual(contradiction["outcome"], "DENIED")
        self.assertEqual(contradiction["receipt"], receipt)
        result = self.gateway.reconcile(self.action["action_id"])
        self.assertEqual((result["status"], result["settlement_status"]), ("UNKNOWN", "UNKNOWN"))
        self.assertEqual(result["reason"], "AGENT_RECEIVER_SETTLEMENT_OUTCOME_MISMATCH")
        self.assertEqual(result["reservation_id"], receipt["reservation_id"])
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["effect_count"])
        inventory = self.receiver.inventory()
        self.assertEqual((len(inventory["effects"]), inventory["commit_request_count"]), (1, 1))

    def test_coordinator_stop_requires_receiver_fence_and_persists_the_exact_ack(self):
        result = self.coordinator.stop()
        self.assertEqual(result["status"], "STOPPED")
        self.assertIs(result["receiver_fence_verified"], True)
        self.assertTrue(receiver_protocol.verify_receiver_fence(result["receiver_fence"], self.endpoint_pin))
        self.assertEqual(result["receiver_fence"], self.receiver.inventory()["fences"][0])
        self.assertEqual(self.coordinator.inventory()["state"]["aggregate"]["receiver_fence"], result["receiver_fence"])
        self.assertFalse(result["execution_authorized"])

    def test_concurrent_stop_retry_cannot_publish_verified_true_with_missing_ack(self):
        initial = self.coordinator.stop()
        self.assertEqual(initial["status"], "STOPPED")
        ready, release = threading.Event(), threading.Event()
        original_stop, original_state = self.endpoint.stop, self.coordinator._state
        main_thread = threading.get_ident()
        started = False
        future = None

        def delayed_stop(*args, **kwargs):
            ready.set()
            self.assertTrue(release.wait(5))
            return original_stop(*args, **kwargs)

        with ThreadPoolExecutor(max_workers=1) as pool:
            def interleaved_state():
                nonlocal started, future
                if threading.get_ident() == main_thread and not started:
                    started = True
                    future = pool.submit(self.coordinator.stop, "CONCURRENT_RETRY")
                    self.assertTrue(ready.wait(3))
                return original_state()
            try:
                with patch.object(self.endpoint, "stop", side_effect=delayed_stop):
                    with patch.object(self.coordinator, "_state", side_effect=interleaved_state):
                        result = self.coordinator._reconcile_closed()
                self.assertEqual(result["status"], "STOPPED")
                self.assertIs(result["receiver_fence_verified"], True)
                self.assertEqual(result["receiver_fence"], initial["receiver_fence"])
                self.assertTrue(receiver_protocol.verify_receiver_fence(result["receiver_fence"], self.endpoint_pin))
            finally:
                release.set()
            self.assertIsNotNone(future)
            self.assertEqual(future.result(5)["status"], "STOPPED")

    def test_stop_event_keeps_exact_stop_pair_when_query_overwrites_shared_history(self):
        original_verify = receiver_protocol.verify_receiver_fence
        queried = False

        def interleaved_query(fence, pin):
            nonlocal queried
            valid = original_verify(fence, pin)
            if not queried and threading.current_thread() is threading.main_thread():
                queried = True
                self.endpoint.query("unobserved-action", "unobserved-reservation")
            return valid

        with patch.object(receiver_protocol, "verify_receiver_fence", side_effect=interleaved_query):
            self.coordinator._stop_receiver()
        self.assertTrue(queried)
        self.assertEqual(self.endpoint.evidence[-1]["request"]["operation"], "query")
        event = [event for event in self.coordinator.inventory()["events"] if event["kind"] == "RECEIVER_STOP"][-1]
        pair = event["pair"]
        self.assertEqual((pair["request"]["role"], pair["request"]["operation"]), ("operator", "stop"))
        self.assertEqual(pair["request"]["payload"], {"root_id": "effect-root", "epoch": 1})
        self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.endpoint_pin), event["result"])

    def test_completed_capture_is_read_only_and_does_not_reopen_admission(self):
        self.coordinator.close()
        before = self.receiver.inventory()
        first = self.coordinator.inventory(completed=True)
        second = self.coordinator.inventory(completed=True)
        self.assertEqual(first, second)
        self.assertEqual(first["state"]["state"], "STOPPED")
        self.assertFalse(first["watcher_alive"])
        self.assertFalse(first["execution_authorized"])
        self.assertTrue(self.coordinator._closed)
        self.assertEqual(self.receiver.inventory(), before)
        with self.assertRaisesRegex(ControlError, "STATE_MISSING"):
            self.coordinator.inventory()
        with self.assertRaisesRegex(ControlError, "STATE_MISSING"):
            self.coordinator._update(state="ACTIVE")
        action = agent_action(action_id="closed-create", attempt_id="closed-attempt",
            root_id="command-root", execution_id="command-worker", epoch=1, stage="CREATE", spec=self.spec)
        result = self.coordinator.launch(action)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "AGENT_RUN_CLOSED"))
        self.assertEqual(self.supervisor.executions, [])
        self.assertEqual(self.coordinator.inventory(completed=True), first)
        self.assertEqual(self.receiver.inventory(), before)

    def test_completed_capture_rejects_pending_root_and_nonboolean_selector(self):
        self.begin()
        self.coordinator.close()
        with self.assertRaisesRegex(ControlError, "CAPTURE_NOT_STOPPED"):
            self.coordinator.inventory(completed=True)
        with self.assertRaisesRegex(ControlError, "COMPLETED_RECEIVER_CAPTURE_REQUIRED"):
            self.coordinator.inventory(completed=1)

    def test_completed_capture_still_checks_immutable_live_configuration(self):
        self.coordinator.close()
        accepted = self.coordinator.inventory(completed=True)
        original = self.endpoint.operator_key
        try:
            self.endpoint.operator_key = b"x" * 32
            with self.assertRaises(ControlError):
                self.coordinator.inventory(completed=True)
        finally:
            self.endpoint.operator_key = original
        self.assertEqual(self.coordinator.inventory(completed=True), accepted)
        self.assertTrue(self.coordinator._closed)

    def receiver_bridge(self, bridge_type=ReceiverFencedAgentBridge):
        configuration = self.bridge.configuration()
        return bridge_type(run_binding=configuration["run_binding"], actions=[self.action],
            executor=self.gateway.execute, fence_check=lambda: {"closed": False},
            trusted_configuration=configuration)

    def test_receiver_bridge_retains_actual_no_effect_proof_that_legacy_bridge_rejects(self):
        receipt, _ = self.terminal(stop=True)
        result = self.gateway.reconcile(self.action["action_id"])
        public = self.receiver_bridge()._public_result(self.action, result)
        self.assertEqual(public, result)
        self.assertEqual((public["status"], public["remote_outcome"], public["effect_count"]), ("NO_EFFECT", "NO_EFFECT", 0))
        self.assertEqual(public["receipt"], receipt)
        self.assertEqual(public["settlement_status"], "SETTLED")
        self.assertFalse(public["execution_authorized"])
        with self.assertRaisesRegex(ControlError, "HOST_RESULT_INVALID"):
            self.receiver_bridge(ExternalAgentBridge)._public_result(self.action, result)

    def test_receiver_bridge_rejects_tampered_signature_wrong_count_and_unproved_zero(self):
        self.terminal(stop=True)
        accepted = self.gateway.reconcile(self.action["action_id"])
        bridge = self.receiver_bridge()
        for mutation in ("signature", "count", "boolean_count", "zero_without_receipt", "unproved_commit", "known_count_without_receipt"):
            with self.subTest(mutation=mutation):
                result = copy.deepcopy(accepted)
                if mutation == "signature":
                    result["receipt"]["signature"] = "0" * 128
                elif mutation == "count":
                    result["effect_count"] = 1
                elif mutation == "boolean_count":
                    result["effect_count"] = False
                elif mutation == "zero_without_receipt":
                    result.update(status="UNKNOWN", settlement_status="UNKNOWN", receipt=None)
                elif mutation == "unproved_commit":
                    result.update(status="COMMITTED", receipt=None, effect_count=None, remote_outcome=None)
                else:
                    result.update(status="UNKNOWN", settlement_status="UNKNOWN", receipt=None, effect_count=1, remote_outcome="COMMITTED")
                with self.assertRaises(ControlError):
                    bridge._public_result(self.action, result)
        self.assertEqual(bridge._public_result(self.action, accepted), accepted)
        self.assertEqual(self.receiver.inventory()["effects"], [])

    def test_receiver_bridge_preserves_known_no_effect_when_authority_settlement_is_unknown(self):
        self.terminal(stop=True)
        result = self.gateway.reconcile(self.action["action_id"])
        result.update(status="UNKNOWN", settlement_status="UNKNOWN")
        public = self.receiver_bridge()._public_result(self.action, result)
        self.assertEqual(public["status"], "UNKNOWN")
        self.assertEqual(public["settlement_status"], "UNKNOWN")
        self.assertEqual((public["effect_count"], public["remote_outcome"]), (0, "NO_EFFECT"))
        self.assertEqual(public["receipt"], result["receipt"])
        self.assertFalse(public["execution_authorized"])
        public["receipt"]["effect_count"] = 1
        self.assertEqual(result["receipt"]["effect_count"], 0)
        restored = self.receiver_bridge()._public_result(self.action, result)
        self.assertEqual((restored["status"], restored["effect_count"]), ("UNKNOWN", 0))

    def test_gateway_keeps_its_query_pair_when_another_thread_appends_operator_stop(self):
        original_query = self.endpoint.query

        def query_with_competing_operator(*args):
            result = original_query(*args)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(self.endpoint.stop, "effect-root").result(3)
            return result

        with patch.object(self.endpoint, "query", side_effect=query_with_competing_operator):
            result = self.gateway._call("endpoint", "query", "unobserved-action", "unobserved-reservation")
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(self.endpoint.evidence[-1]["request"]["operation"], "stop")
        pair = self.gateway.inventory()["endpoint_evidence"][-1]
        self.assertEqual((pair["request"]["role"], pair["request"]["operation"]), ("gateway", "query"))
        self.assertEqual(pair["request"]["payload"], {"action_id": "unobserved-action", "reservation_id": "unobserved-reservation"})
        self.assertEqual(verify_receiver_response(pair["request"], pair["response"], self.endpoint_pin), result)


if __name__ == "__main__":
    unittest.main()
