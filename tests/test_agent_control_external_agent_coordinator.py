"""Durable two-controller STOP unit regressions with explicit host doubles.

Controller state and response signatures are real. Docker observations and
effect executor calls here are unit doubles, not containment measurements.
"""
from __future__ import annotations

import copy
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_authority import ExternalAgentAuthorityStore
from sdk.liminal_agent_control.external_agent_coordinator import (
    RUN_SCHEMA, ExternalAgentCoordinator, agent_policy_digest, validate_run_binding,
)
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256, agent_action, agent_spec
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.external_network_protocol import network_action
from tests.test_agent_control_external_agent_supervisor import FakeBridge, public_pin

IMAGE = "sha256:" + "c" * 64


class FakeSupervisor:
    def __init__(self, pin, bridge):
        self._pin, self.bridge = pin, bridge
        self.cleanup_calls = []
        self.process_quiescent = True
        self.grants = []
        self.commands = []
        self.executions = []

    def pin(self):
        return copy.deepcopy(self._pin)

    def execute(self, action):
        self.executions.append(action)
        self.commands = [{"command_id": action["arguments"]["spec"]["command_id"]}]
        return {"status": "UNKNOWN", "action_id": action["action_id"], "execution_authorized": False}

    def cleanup(self, command_id):
        self.cleanup_calls.append(command_id)
        return {"status": "QUIESCENT" if self.process_quiescent else "UNKNOWN",
                "process_quiescent": self.process_quiescent, "stages": [], "execution_authorized": False}

    def inventory(self):
        return {"grants": copy.deepcopy(self.grants), "commands": copy.deepcopy(self.commands),
                "bridge": self.bridge.inventory(), "attach_processes": []}


class FakeGateway:
    def __init__(self, controller, endpoint_pin):
        self.external_controller = controller
        self.endpoint_client = SimpleNamespace(pin=lambda: copy.deepcopy(endpoint_pin))
        self.reconcile_calls = []
        self.fail_if_called = False

    def reconcile(self, action_id):
        if self.fail_if_called:
            raise AssertionError("must not acquire pending executor lock")
        self.reconcile_calls.append(action_id)
        return {"status": "UNKNOWN", "action_id": action_id, "execution_authorized": False}

    def _configuration(self):
        return canonical_bytes({"schema": "explicit-unit-gateway", "authority_pin": self.external_controller.pin(),
                                "endpoint_pin": self.endpoint_client.pin()}).decode()

    def execute(self, action):
        return {"status": "UNKNOWN", "action_id": action["action_id"], "execution_authorized": False}


class ExternalAgentCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.supervisor_pin = public_pin("supervisor", b"\x42" * 32, "supervisor")
        self.endpoint_pin = public_pin("endpoint", b"\x44" * 32, "endpoint")
        self.command_store = ExternalAgentAuthorityStore(self.path / "command.sqlite", supervisor_pin=self.supervisor_pin,
            authority_id="command-authority", key_id="command-authority-key", private_key=b"\x41" * 32,
            receipt_key=b"unused-command-receipt" * 2, clock=lambda: 100.0)
        self.effect_store = ExternalNetworkAuthorityStore(self.path / "effect.sqlite", endpoint_pin=self.endpoint_pin,
            authority_id="effect-authority", key_id="effect-authority-key", private_key=b"\x43" * 32,
            receipt_key=b"unused-effect-receipt" * 2, clock=lambda: 100.0)
        self.servers, self.threads = [], []
        self.command_admin, self.command_receiver = self.serve(self.command_store, b"command-admin" * 3, b"command-receiver" * 3)
        self.effect_admin, self.effect_receiver = self.serve(self.effect_store, b"effect-admin" * 3, b"effect-receiver" * 3)
        self.addCleanup(self.shutdown)
        self.spec = agent_spec("owned-command", IMAGE, str(self.path / "workspace"))
        self.effect_action = network_action(action_id="effect-action", attempt_id="effect-attempt", root_id="effect-root",
            execution_id="effect-worker", epoch=1, endpoint_url="http://127.0.0.1:12345", marker="owned-agent")
        self.binding = {"schema": RUN_SCHEMA, "run_id": "agent-run",
            "command": {"root_id": "command-root", "execution_id": "command-worker", "epoch": 1, "authority_pin": self.command_store.pin()},
            "effect": {"root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1, "authority_pin": self.effect_store.pin()},
            "supervisor_pin": self.supervisor_pin, "endpoint_pin": self.endpoint_pin,
            "effect_actions": [self.effect_action], "effect_action_digests": [digest(self.effect_action)],
            "source_digest": AGENT_FIXTURE_SHA256, "spec_digest": digest(self.spec)}
        self.bridge = FakeBridge({"run_binding": {"run_id": "agent-run", "root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1},
                                  "actions": [self.effect_action]})
        self.supervisor = FakeSupervisor(self.supervisor_pin, self.bridge)
        self.gateway = FakeGateway(self.effect_receiver, self.endpoint_pin)
        self.bridge.executor = self.gateway.execute
        self.bridge._configuration["effect_gateway_configuration"] = json.loads(self.gateway._configuration())
        for branch, store, receiver in (("command", self.command_store, "supervisor"), ("effect", self.effect_store, "endpoint")):
            store.create_root(self.binding[branch]["root_id"], receiver, agent_policy_digest(self.binding, branch), 32, 3600)
            store.bind_execution(self.binding[branch]["root_id"], self.binding[branch]["execution_id"])
        self.coordinator = self.new_coordinator()

    def serve(self, store, admin_key, receiver_key):
        server = make_server(store, admin_key, receiver_key)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.005), daemon=True)
        thread.start()
        self.servers.append(server)
        self.threads.append(thread)
        url = "http://127.0.0.1:" + str(server.server_address[1])
        return (HTTPExternalAuthorityClient(url, admin_key, store.pin(), role="admin"),
                HTTPExternalAuthorityClient(url, receiver_key, store.pin()))

    def new_coordinator(self, create=True, start_watcher=False):
        return ExternalAgentCoordinator(self.path / "coordinator.sqlite", run_binding=self.binding,
            supervisor=self.supervisor, command_admin_client=self.command_admin, effect_admin_client=self.effect_admin,
            effect_gateway=self.gateway, bridge=self.bridge, create=create, start_watcher=start_watcher, watcher_interval=.02)

    def shutdown(self):
        if hasattr(self, "coordinator"):
            try:
                self.coordinator.close()
            except ControlError:
                pass
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(2)

    def action(self):
        return agent_action(action_id="create", attempt_id="create-attempt", root_id="command-root",
            execution_id="command-worker", epoch=1, stage="CREATE", spec=self.spec)

    def launch(self):
        return self.coordinator.launch(self.action())

    def pending_effect(self):
        grant = {"action_digest": digest(self.effect_action), "policy_version": agent_policy_digest(self.binding, "effect"),
                 "expires_at": 200.0, "receiver_id": "endpoint"}
        self.assertEqual(self.effect_store.begin(self.effect_action, grant)["status"], "PERMITTED")

    def test_active_requires_fresh_signed_both_root_policies(self):
        status = self.coordinator.status()
        self.assertEqual(status["status"], "ACTIVE")
        self.assertEqual({row["branch"] for row in status["authority_observations"]}, {"command", "effect"})
        self.assertFalse(status["execution_authorized"])

    def test_stop_persists_fence_before_external_stop(self):
        self.launch()
        original = self.command_admin.stop
        snapshots = []
        def checked_stop(root_id):
            snapshots.append(self.coordinator.fence_state())
            self.assertTrue(self.bridge.fenced)
            return original(root_id)
        with patch.object(self.command_admin, "stop", side_effect=checked_stop):
            result = self.coordinator.stop()
        self.assertEqual(result["status"], "STOPPED")
        self.assertTrue(snapshots[0]["closed"])
        self.assertEqual(snapshots[0]["state"], "CLOSING")

    def test_stopped_process_cannot_hide_pending_endpoint_effect(self):
        self.launch()
        self.pending_effect()
        result = self.coordinator.stop()
        self.assertTrue(result["process_quiescent"])
        self.assertEqual(result["effect_state"]["pending_count"], 1)
        self.assertEqual(result["status"], "STOP_PENDING")

    def test_pending_effect_callback_does_not_block_stop_on_gateway_lock(self):
        self.launch()
        self.pending_effect()
        self.bridge.finished.clear()
        self.gateway.fail_if_called = True
        started = time.monotonic()
        result = self.coordinator.stop()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(result["status"], "STOP_PENDING")
        self.assertEqual(self.gateway.reconcile_calls, [])
        self.bridge.finished.set()
        self.gateway.fail_if_called = False

    def test_missing_positive_process_census_cannot_claim_stopped(self):
        self.launch()
        self.supervisor.process_quiescent = False
        result = self.coordinator.stop()
        self.assertEqual(result["command_state"]["state"], "STOPPED")
        self.assertEqual(result["effect_state"]["state"], "STOPPED")
        self.assertEqual(result["status"], "UNKNOWN")

    def test_authority_outage_fences_and_attempts_owned_cleanup(self):
        self.launch()
        with patch.object(self.effect_admin, "status", side_effect=ControlError("EXTERNAL_AUTHORITY_UNAVAILABLE")):
            result = self.coordinator.reconcile()
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertTrue(self.coordinator.fence_state()["closed"])
            self.assertTrue(self.bridge.fenced)
            self.assertIn("owned-command", self.supervisor.cleanup_calls)
        self.assertEqual(self.coordinator.reconcile()["status"], "STOPPED")

    def test_watchdog_contains_bridge_deadline_without_explicit_stop(self):
        self.launch()
        self.coordinator.start_watcher()
        self.bridge.fence("WORKER_DEADLINE_EXCEEDED")
        deadline = time.monotonic() + 2
        while not self.supervisor.cleanup_calls and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(self.coordinator.fence_state()["closed"])
        self.assertIn("owned-command", self.supervisor.cleanup_calls)
        self.assertEqual(self.command_store.status("command-root")["state"], "STOPPED")

    def test_watcher_failure_preserves_local_containment_and_unknown(self):
        self.launch()
        with patch.object(self.coordinator, "reconcile", side_effect=RuntimeError("unit-watchdog-failure")):
            self.coordinator.start_watcher()
            deadline = time.monotonic() + 2
            while not self.supervisor.cleanup_calls and time.monotonic() < deadline:
                time.sleep(.01)
        self.assertTrue(self.bridge.fenced)
        self.assertTrue(self.coordinator.fence_state()["closed"])
        self.assertIn("owned-command", self.supervisor.cleanup_calls)
        self.assertEqual(self.coordinator.status()["status"], "UNKNOWN")

    def test_missing_coordinator_database_cannot_skip_external_stop_or_owned_cleanup(self):
        self.launch()
        self.coordinator.db_path.unlink()
        self.coordinator.start_watcher()
        deadline = time.monotonic() + 2
        while not self.supervisor.cleanup_calls and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(self.bridge.fenced)
        self.assertIn("owned-command", self.supervisor.cleanup_calls)
        self.assertEqual(self.command_store.status("command-root")["state"], "STOPPED")
        self.assertEqual(self.effect_store.status("effect-root")["state"], "STOPPED")
        self.assertEqual(self.coordinator.status()["status"], "UNKNOWN")

    def test_reopen_active_run_is_closed_before_any_launch(self):
        self.coordinator._closed = True  # Simulated dead host owner, no graceful STOP.
        self.coordinator = self.new_coordinator(create=False)
        self.assertTrue(self.coordinator.fence_state()["closed"])
        self.assertEqual(self.coordinator.launch(self.action())["status"], "DENIED")
        self.assertEqual(self.supervisor.executions, [])
        self.assertEqual(self.coordinator.reconcile()["status"], "STOPPED")

    def test_changed_exact_effect_action_reopen_is_rejected(self):
        self.coordinator._closed = True
        self.binding["effect_actions"][0]["arguments"]["body"]["synthetic_marker"] = "changed"
        self.binding["effect_action_digests"] = [digest(self.binding["effect_actions"][0])]
        with self.assertRaisesRegex(ControlError, "BRIDGE_BINDING_MISMATCH|CONFIGURATION_IMMUTABLE"):
            self.new_coordinator(create=False)
        self.binding["effect_actions"] = [self.effect_action]
        self.binding["effect_action_digests"] = [digest(self.effect_action)]

    def test_wrong_root_policy_is_not_run_binding_evidence(self):
        with self.effect_store._connection() as db:
            db.execute("UPDATE external_roots SET policy_digest=? WHERE root_id=?", ("f" * 64, "effect-root"))
        result = self.coordinator.status()
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(self.coordinator.fence_state()["closed"])

    def test_duplicate_effect_lineage_or_source_digest_rejected(self):
        for field, value in (("source_digest", "0" * 64), ("effect_action_digests", ["0" * 64])):
            changed = copy.deepcopy(self.binding)
            changed[field] = value
            with self.assertRaises(ControlError):
                validate_run_binding(changed)

    def test_supervisor_receipt_count_must_equal_external_issued_count(self):
        self.launch()
        grant = {"action_digest": digest(self.action()), "policy_version": agent_policy_digest(self.binding, "command"),
                 "expires_at": 200.0, "receiver_id": "supervisor"}
        self.command_store.begin(self.action(), grant)
        # Even a compromised host summary cannot infer callbacks or provide a
        # terminal receipt for this independently pending reservation.
        result = self.coordinator.stop()
        self.assertFalse(result["lifecycle_receipts_verified"])
        self.assertEqual(result["status"], "STOP_PENDING")


if __name__ == "__main__":
    unittest.main()
