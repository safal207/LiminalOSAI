"""Final effect dispatch tests with real signed loopback HTTP and SQLite.

Command lifecycle, controller and bridge objects are explicit unit doubles: no
Docker agent is launched. Most health observations are supplied snapshots. One
separate test uses the real coordinator watcher and its durable admission store.
An admitted but undispatched reservation stays UNKNOWN/pending, never STOPPED.
"""
from __future__ import annotations

import json
from copy import deepcopy
import unittest

from sdk.liminal_agent_control.authority import ControlError, digest
from sdk.liminal_agent_control.external_agent_authority import ExternalAgentAuthorityStore
from sdk.liminal_agent_control.external_agent_coordinator import (
    RUN_SCHEMA, ExternalAgentCoordinator, agent_policy_digest,
)
from sdk.liminal_agent_control.external_agent_effect_gateway import ClosedChannelEffectGateway
from sdk.liminal_agent_control.external_agent_launch import ClosedChannelLaunchGate, build_channel_inventory
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256, agent_spec
from sdk.liminal_agent_control.external_authority_service import (
    HTTPExternalAuthorityClient, make_server, verify_authority_response,
)
from sdk.liminal_agent_control.external_network_endpoint import HTTPNetworkEndpointClient, make_endpoint_server
from sdk.liminal_agent_control.external_network_gateway import NetworkGateway
from sdk.liminal_agent_control.external_network_protocol import verify_endpoint_receipt
from tests import test_agent_control_external_network_gateway as network_fixtures
from tests import test_agent_control_external_agent_launch as launch_fixtures
from tests import test_agent_control_external_agent_supervisor as supervisor_fixtures


class SnapshotBridge(launch_fixtures.UnitBridge):
    """Only the host-facing bridge observation interface; no worker or STDIO."""
    def __init__(self, *args):
        super().__init__(*args)
        self.fenced = False

    def fence(self, reason="UNIT_FENCE"):
        self.fenced = True

    def close_admission(self, reason, durable_close):
        result = durable_close()
        self.fence(reason)
        return result

    def inventory(self):
        return {"fenced": self.fenced, "outstanding_effect_calls": 0, "callback_finished": True}

    def callbacks_finished(self):
        return True


class SnapshotSupervisor(launch_fixtures.UnitClosedSupervisor):
    def inventory(self):
        return {"grants": [], "commands": [], "bridge": self.bridge.inventory(), "attach_processes": []}


class SnapshotCoordinator(launch_fixtures.UnitCoordinator):
    """Explicit health/fence snapshots, not an actual watchdog measurement."""
    def __init__(self, *args):
        super().__init__(*args)
        self.health_error = None
        self.close_reasons = []

    def watcher_health(self, *, max_age_seconds):
        if self.health_error is not None:
            raise self.health_error
        return super().watcher_health(max_age_seconds=max_age_seconds)

    def close_admission(self, reason):
        self.close_reasons.append(reason)
        self.closed = True
        self.bridge.fence(reason)
        return self.fence_state()


class ExternalAgentEffectGatewayTests(unittest.TestCase):
    def setUp(self):
        # Composition prevents rediscovering all inherited legacy gateway tests.
        self.fixture = network_fixtures.ExternalNetworkGatewayTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.path = self.fixture.directory / "closed-effect.sqlite"
        self.proposed = self.fixture.action()
        self.spec = agent_spec("unit-command", "sha256:" + "c" * 64,
                               str(self.fixture.directory / "unlaunched-worker"))
        self.binding = {"schema": RUN_SCHEMA, "run_id": "unit-effect-run",
            "command": {"root_id": "command-root", "execution_id": "command-worker", "epoch": 1,
                "authority_pin": supervisor_fixtures.public_pin("authority", b"\x73" * 32, "unit-command-authority")},
            "effect": {"root_id": "root", "execution_id": "worker", "epoch": 1,
                "authority_pin": self.fixture.authority.pin()},
            "supervisor_pin": supervisor_fixtures.public_pin("supervisor", b"\x74" * 32, "unit-supervisor"),
            "endpoint_pin": self.fixture.endpoint_pin, "effect_actions": [self.proposed],
            "effect_action_digests": [digest(self.proposed)], "source_digest": AGENT_FIXTURE_SHA256,
            "spec_digest": digest(self.spec)}
        self.policy = agent_policy_digest(self.binding, "effect")
        with self.fixture.authority._connection() as db:
            db.execute("UPDATE external_roots SET policy_digest=? WHERE root_id='root'", (self.policy,))
        self.gateway = self.new_gateway()
        self.bind_graph(self.gateway)

    def new_gateway(self, *, create=True, drop_begin_response=False, drop_finish_response=False):
        return ClosedChannelEffectGateway(self.path, gateway_id="unit-closed-effect",
            run_binding=self.binding,
            external_controller=HTTPExternalAuthorityClient(self.fixture.authority_url,
                network_fixtures.AUTHORITY_REQUEST, self.fixture.authority.pin()),
            endpoint_client=HTTPNetworkEndpointClient(self.fixture.endpoint_url,
                network_fixtures.ENDPOINT_REQUEST, self.fixture.endpoint_pin),
            operator_key=network_fixtures.GATEWAY_OPERATOR, worker_key=network_fixtures.GATEWAY_WORKER,
            create=create, drop_begin_response=drop_begin_response, drop_finish_response=drop_finish_response)

    def bind_graph(self, gateway, *, real_watcher=False):
        effect_admin = HTTPExternalAuthorityClient(self.fixture.authority_url,
            network_fixtures.AUTHORITY_OPERATOR, self.fixture.authority.pin(), role="admin")
        if real_watcher:
            command_store = ExternalAgentAuthorityStore(self.fixture.directory / "real-command-authority.sqlite",
                supervisor_pin=self.binding["supervisor_pin"], authority_id="unit-command-authority",
                key_id="unit-command-authority-key", private_key=b"\x73" * 32,
                receipt_key=b"unused-command-receipt" * 2, clock=lambda: self.fixture.authority_now)
            command_admin_key, command_receiver_key = b"unit-command-admin" * 3, b"unit-command-receiver" * 3
            server = make_server(command_store, command_admin_key, command_receiver_key)
            self.fixture.start(server)
            command_url = "http://127.0.0.1:" + str(server.server_port)
            command_admin = HTTPExternalAuthorityClient(command_url, command_admin_key, command_store.pin(), role="admin")
            command_receiver = HTTPExternalAuthorityClient(command_url, command_receiver_key, command_store.pin())
            command_store.create_root("command-root", "unit-supervisor", agent_policy_digest(self.binding, "command"), 32, 3600)
            command_store.bind_execution("command-root", "command-worker")
        else:
            command_url = "http://127.0.0.1:12001"
            command_admin = launch_fixtures.UnitAuthority(command_url, "admin", self.binding["command"]["authority_pin"])
            command_receiver = launch_fixtures.UnitAuthority(command_url, "receiver", self.binding["command"]["authority_pin"])
        bridge_configuration = {"run_binding": {"run_id": self.binding["run_id"],
                **{key: self.binding["effect"][key] for key in ("root_id", "execution_id", "epoch")}},
            "actions": self.binding["effect_actions"], "admission_observer_required": True,
            "owned_run_binding_digest": digest(self.binding),
            "owned_command_binding": {key: self.binding["command"][key] for key in ("root_id", "execution_id", "epoch")},
            "effect_gateway_configuration": json.loads(gateway._configuration())}
        inputs = dict(spec=self.spec, run_binding=self.binding, bridge_configuration=bridge_configuration,
            command_authority_url=command_url, effect_authority_url=self.fixture.authority_url)
        gate = ClosedChannelLaunchGate(**inputs, channels=build_channel_inventory(**inputs))
        bridge = SnapshotBridge(bridge_configuration, gateway)
        supervisor = SnapshotSupervisor(gate, self.binding, bridge, command_receiver)
        if real_watcher:
            coordinator = ExternalAgentCoordinator(self.fixture.directory / "real-coordinator.sqlite",
                run_binding=self.binding, supervisor=supervisor, command_admin_client=command_admin,
                effect_admin_client=effect_admin, effect_gateway=gateway, bridge=bridge,
                watcher_interval=.02, start_watcher=True)
            self.addCleanup(coordinator.close)
        else:
            coordinator = SnapshotCoordinator(self.binding, supervisor, bridge, gateway, command_admin, effect_admin)
        gate.bind(coordinator)
        gateway.bind_launch_gate(gate)
        if real_watcher:
            self.assertTrue(coordinator.wait_watcher_ready(timeout=2))
        self.gate, self.coordinator, self.effect_admin = gate, coordinator, effect_admin
        self.bridge, self.supervisor = bridge, supervisor

    def authorize(self):
        return self.gateway.authorize(self.proposed, {"action_digest": digest(self.proposed),
            "policy_version": self.policy, "expires_at": 200.0, "receiver_id": self.fixture.endpoint_pin["endpoint_id"]})

    def signed_pending(self, pair, reservation_id):
        observed = verify_authority_response(pair["request"], pair["response"], self.fixture.authority.pin())
        self.assertEqual((observed["status"], observed["reservation_id"]), ("PERMITTED", reservation_id))
        state = self.fixture.authority.status("root")
        self.assertEqual((state["issued_count"], state["pending_count"]), (1, 1))
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def assert_unsent_pending(self, result, *, reservation_known=True):
        self.assertEqual(result["status"], "UNKNOWN")
        if reservation_known:
            self.assertIsNotNone(result["reservation_id"])
        else:
            self.assertIsNone(result["reservation_id"])
        self.assertIsNone(result["effect_count"])
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["remote_outcome"])
        self.assertFalse(result["dispatch_finished"])
        endpoint = self.fixture.endpoint.inventory()
        self.assertEqual((endpoint["commit_request_count"], len(endpoint["effects"]), len(endpoint["receipts"])), (0, 0, 0))
        state = self.fixture.authority.status("root")
        self.assertEqual((state["issued_count"], state["pending_count"], state["committed_count"]), (1, 1, 0))

    def test_healthy_bound_gateway_commits_one_real_endpoint_effect(self):
        calls = []
        def observe(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            calls.append(reservation_id)
        self.gateway.before_dispatch_hook = observe
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assertEqual((result["status"], result["effect_count"], result["settlement_status"]), ("COMMITTED", 1, "SETTLED"))
        self.assertTrue(result["dispatch_finished"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(verify_endpoint_receipt(result["receipt"], self.fixture.endpoint_pin))
        self.assertEqual((self.fixture.endpoint.inventory()["commit_request_count"], len(self.fixture.endpoint.inventory()["effects"])), (1, 1))
        self.assertEqual(self.fixture.authority.status("root")["pending_count"], 0)

    def test_dead_watchdog_snapshot_after_signed_begin_blocks_new_post(self):
        def lose_health(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.coordinator.health["alive"] = False
        self.gateway.before_dispatch_hook = lose_health
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(result)
        self.assertTrue(self.coordinator.fence_state()["closed"])
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")

    def test_stale_watchdog_snapshot_after_signed_begin_blocks_new_post(self):
        def lose_health(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.coordinator.health["fresh"] = False
        self.gateway.before_dispatch_hook = lose_health
        self.authorize()
        self.assert_unsent_pending(self.gateway.execute(self.proposed))

    def test_host_fence_after_signed_begin_blocks_new_post_without_false_stopped(self):
        def stop(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.coordinator.close_admission("UNIT_HOST_STOP")
            self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")
        self.gateway.before_dispatch_hook = stop
        self.authorize()
        self.assert_unsent_pending(self.gateway.execute(self.proposed))
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")

    def test_real_watcher_shutdown_after_signed_begin_blocks_new_post(self):
        # The already-bound snapshot graph is not reattached. A fresh object
        # uses the same empty persisted dispatch store and actual coordinator.
        self.gateway = self.new_gateway(create=False)
        self.bind_graph(self.gateway, real_watcher=True)
        def stop_watcher(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.coordinator._watcher_stop.set()
            self.coordinator._watcher.join(2)
            self.assertFalse(self.coordinator.watcher_health()["alive"])
        self.gateway.before_dispatch_hook = stop_watcher
        self.authorize()
        self.assert_unsent_pending(self.gateway.execute(self.proposed))
        self.assertTrue(self.coordinator.fence_state()["closed"])
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")

    def test_recovered_snapshot_retry_reopen_and_reconcile_never_redispatch_pending(self):
        self.gateway.before_dispatch_hook = lambda *args: self.coordinator.health.update(fresh=False)
        self.authorize()
        first = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(first)
        closed_retry = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(closed_retry)
        self.assertEqual(closed_retry["reservation_id"], first["reservation_id"])
        self.gateway = self.new_gateway(create=False)
        self.bind_graph(self.gateway)  # Explicit fresh unit health owner, no resume claim.
        repeated = self.gateway.execute(self.proposed)
        reconciled = self.gateway.reconcile(self.proposed["action_id"])
        self.assert_unsent_pending(repeated)
        self.assertEqual(reconciled["status"], "UNKNOWN")
        self.assertIsNone(reconciled["effect_count"])
        self.assertEqual(first["reservation_id"], repeated["reservation_id"])
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")

    def test_prebegin_unready_snapshot_and_optional_hook_none_do_not_issue_permit(self):
        self.gateway.before_dispatch_hook = None
        self.coordinator.health["alive"] = False
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "AGENT_LAUNCH_WATCHDOG_UNREADY"))
        self.assertEqual(self.fixture.authority.status("root")["issued_count"], 0)
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def test_mandatory_final_method_cannot_be_replaced_by_an_empty_fault_hook(self):
        self.authorize()
        self.gateway._before_endpoint_commit = lambda *args: None
        result = self.gateway.execute(self.proposed)
        self.assertEqual(result["status"], "DENIED")
        self.assertIn(result["reason"], ("AGENT_EFFECT_GATE_ROUTE_CHANGED", "AGENT_LAUNCH_CALLABLE_CHANGED"))
        self.assertEqual(self.fixture.authority.status("root")["issued_count"], 0)
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def test_gate_can_bind_only_once(self):
        with self.assertRaisesRegex(ControlError, "GATE_ALREADY_BOUND"):
            self.gateway.bind_launch_gate(self.gate)
        self.assertEqual(self.fixture.authority.status("root")["issued_count"], 0)

    def test_fault_hook_cannot_mutate_frozen_permit_or_proposal_into_dispatch(self):
        def mutate(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            action["arguments"]["body"]["synthetic_marker"] = "mutated-unit-marker"
            pair["response"]["signature"] = "0" * 128
        self.gateway.before_dispatch_hook = mutate
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(result)
        self.assertEqual(result["reason"], "AGENT_EFFECT_DISPATCH_INPUT_IMMUTABLE")
        self.assertEqual(self.proposed["arguments"]["body"]["synthetic_marker"], "operation")

    def test_route_key_drift_after_begin_never_fakes_denial_or_clears_pending(self):
        original_key = self.gateway.endpoint_client.request_key
        def mutate_route(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.gateway.endpoint_client.request_key = b"synthetic-changed-endpoint-key" * 2
        self.gateway.before_dispatch_hook = mutate_route
        self.authorize()
        try:
            result = self.gateway.execute(self.proposed)
            self.assert_unsent_pending(result)
            repeated = self.gateway.execute(self.proposed)
            self.assert_unsent_pending(repeated)
            self.assertEqual(repeated["reservation_id"], result["reservation_id"])
            changed = deepcopy(self.proposed)
            changed["arguments"]["body"]["synthetic_marker"] = "different-unapproved-marker"
            unbound_proof = self.gateway.execute(changed)
            self.assertIsNone(unbound_proof["reservation_id"])
            self.assertIsNone(unbound_proof["receipt"])
            self.assertIsNone(unbound_proof["effect_count"])
        finally:
            self.gateway.endpoint_client.request_key = original_key
        state = self.gateway.inventory()["actions"][0]
        self.assertIn(state["status"], ("PENDING", "UNKNOWN"))
        self.assertEqual(state["reservation_id"], result["reservation_id"])
        self.assertIsNone(state["receipt"])
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")

    def test_restored_route_cannot_admit_second_action_while_only_bridge_is_fenced(self):
        # Build both allowed actions before the new gateway/real watcher graph.
        # Holding the operation lock keeps a fresh watcher from repairing the
        # failed durable close until this exact restored-route race is checked.
        second = deepcopy(self.proposed)
        second["action_id"] += "-second"
        second["attempt_id"] += "-second"
        second["arguments"]["body"]["synthetic_marker"] = "second-owned-marker"
        self.binding["effect_actions"].append(second)
        self.binding["effect_action_digests"].append(digest(second))
        self.policy = agent_policy_digest(self.binding, "effect")
        with self.fixture.authority._connection() as db:
            db.execute("UPDATE external_roots SET policy_digest=? WHERE root_id='root'", (self.policy,))
        self.path = self.fixture.directory / "two-action-closed-effect.sqlite"
        self.gateway = self.new_gateway()
        self.bind_graph(self.gateway, real_watcher=True)
        self.authorize()
        self.gateway.authorize(second, {"action_digest": digest(second), "policy_version": self.policy,
            "expires_at": 200.0, "receiver_id": self.fixture.endpoint_pin["endpoint_id"]})
        original_key = self.gateway.endpoint_client.request_key
        self.gateway.before_dispatch_hook = lambda *args: setattr(self.gateway.endpoint_client,
            "request_key", b"synthetic-changed-endpoint-key" * 2)
        with self.coordinator._operation_lock:
            try:
                first = self.gateway.execute(self.proposed)
            finally:
                self.gateway.endpoint_client.request_key = original_key
                self.gateway.before_dispatch_hook = None
            self.assert_unsent_pending(first)
            self.assertTrue(self.bridge.fenced)
            self.assertFalse(self.coordinator.fence_state()["closed"])
            self.assertTrue(self.coordinator.watcher_health()["fresh"])
            denied = self.gateway.execute(second)
            self.assertEqual(denied["status"], "DENIED")
            self.assertIn(denied["reason"], ("AGENT_LAUNCH_BRIDGE_FENCED", "AGENT_EFFECT_DISPATCH_CLOSED"))
            self.assertIsNone(denied["reservation_id"])
            self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)
            state = self.fixture.authority.status("root")
            self.assertEqual((state["issued_count"], state["pending_count"], state["committed_count"]), (1, 1, 0))

    def test_unbound_gateway_fails_before_begin_or_endpoint_post(self):
        self.gateway = self.new_gateway(create=False)
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "AGENT_EFFECT_GATE_UNBOUND"))
        self.assertEqual(self.fixture.authority.status("root")["issued_count"], 0)
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def test_replaced_gate_and_legacy_store_reopen_fail_closed(self):
        self.authorize()
        self.gateway.launch_gate = object()
        result = self.gateway.execute(self.proposed)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "AGENT_EFFECT_GATE_IMMUTABLE"))
        self.assertEqual(self.fixture.authority.status("root")["issued_count"], 0)
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            NetworkGateway(self.path, gateway_id="unit-closed-effect",
                external_controller=self.gateway.external_controller, endpoint_client=self.gateway.endpoint_client,
                operator_key=network_fixtures.GATEWAY_OPERATOR, worker_key=network_fixtures.GATEWAY_WORKER, create=False)
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def test_unexpected_final_guard_error_is_unknown_without_private_exception_text(self):
        def fail_health(action, authorization, reservation_id, pair):
            self.signed_pending(pair, reservation_id)
            self.coordinator.health_error = RuntimeError("synthetic private diagnostic text")
        self.gateway.before_dispatch_hook = fail_health
        self.authorize()
        result = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(result)
        self.assertEqual(result["reason"], "AGENT_EFFECT_DISPATCH_CHECK_FAILED")
        self.assertNotIn("synthetic private", str(result))

    def test_lost_begin_response_remains_unsent_pending(self):
        self.gateway._drop_begin_response = True
        self.authorize()
        first = self.gateway.execute(self.proposed)
        self.assert_unsent_pending(first, reservation_known=False)
        self.coordinator.close_admission("UNIT_HOST_STOP")
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")
        reconciled = self.gateway.reconcile(self.proposed["action_id"])
        self.assertEqual(reconciled["status"], "UNKNOWN")
        self.assertIsNone(reconciled["effect_count"])
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 0)

    def test_lost_endpoint_response_recovers_by_query_finish_after_closed_gate(self):
        self.fixture.stop(self.fixture.endpoint_server)
        server = make_endpoint_server(self.fixture.endpoint, port=self.fixture.endpoint_port, drop_commit_response=True)
        self.fixture.start(server)
        self.authorize()
        unknown = self.gateway.execute(self.proposed)
        self.assertEqual(unknown["status"], "UNKNOWN")
        self.assertTrue(unknown["dispatch_finished"])
        self.assertIsNone(unknown["effect_count"])
        self.assertIsNone(unknown["receipt"])
        self.assertEqual((self.fixture.endpoint.inventory()["commit_request_count"], len(self.fixture.endpoint.inventory()["effects"])), (1, 1))
        self.coordinator.close_admission("UNIT_HOST_STOP")
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOP_PENDING")
        reconciled = self.gateway.reconcile(self.proposed["action_id"])
        self.assertEqual((reconciled["status"], reconciled["effect_count"], reconciled["settlement_status"]), ("COMMITTED", 1, "SETTLED"))
        self.assertFalse(reconciled["dispatch_finished"])
        self.assertEqual(self.fixture.endpoint.inventory()["commit_request_count"], 1)
        self.assertEqual(self.effect_admin.stop("root")["status"], "STOPPED")
        self.assertEqual(unknown["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
