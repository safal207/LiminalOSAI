"""Closed launch admission unit tests with explicit route/controller doubles.

These tests measure pre-BEGIN/pre-dispatch decisions and persistence binding.
The doubles are not Docker isolation or external-effect runtime evidence.
"""
from __future__ import annotations

import copy
import json
import threading
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_coordinator import RUN_SCHEMA
from sdk.liminal_agent_control.external_agent_launch import (
    ClosedChannelAgentSupervisor, ClosedChannelLaunchGate, build_channel_inventory,
)
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256, agent_action, agent_spec
from sdk.liminal_agent_control.external_agent_supervisor import ExternalAgentSupervisor
from sdk.liminal_agent_control.external_network_protocol import network_action
from tests.test_agent_control_external_agent_channels import safe_inspect_fixture


def pin(kind, name, byte):
    return {kind + "_id": name, "key_id": name + "-key", "public_key": byte * 64}


class UnitAuthority:
    def __init__(self, url, role, signing_pin):
        self.url, self.role, self._pin = url, role, signing_pin

    def pin(self):
        return copy.deepcopy(self._pin)

    def begin(self, *args):
        return None

    def status(self, *args):
        return None

    def stop(self, *args):
        return None


class UnitEndpoint:
    def __init__(self, signing_pin):
        self.url, self._pin = "http://127.0.0.1:12003", signing_pin

    def pin(self):
        return copy.deepcopy(self._pin)

    def commit(self, *args):
        return None

    def query(self, *args):
        return None


class UnitGateway:
    def __init__(self, receiver, endpoint):
        self.external_controller, self.endpoint_client = receiver, endpoint
        self.calls = 0

    def _configuration(self):
        return canonical_bytes({"schema": "explicit-unit-route", "authority_url": self.external_controller.url,
            "authority_pin": self.external_controller.pin(), "endpoint_url": self.endpoint_client.url,
            "endpoint_pin": self.endpoint_client.pin()}).decode()

    def execute(self, action):
        self.calls += 1

    def reconcile(self, *args):
        return None


class UnitController:
    def __init__(self):
        self.docker_binary = "explicit-unit-docker"
        self.dispatches = 0
        self.verifications = 0
        self.inspected = None
        self.after_verify = None

    def command(self, *args):
        self.dispatches += 1

    def verify_configuration(self, *args):
        self.verifications += 1
        if self.after_verify is not None:
            self.after_verify()

    def _inspect(self, *args):
        return copy.deepcopy(self.inspected)


class UnitBridge:
    def __init__(self, configuration, gateway):
        self._configuration = copy.deepcopy(configuration)
        self.executor = gateway.execute
        self.fence_check = lambda: {"closed": False}
        self.admission_observer = lambda action: None
        self.admission_observer_required = True

    def configuration(self):
        return copy.deepcopy(self._configuration)

    def run(self, *args):
        return None

    def fence(self, *args):
        return None


class UnitClosedSupervisor(ClosedChannelAgentSupervisor):
    """Explicitly skip host persistence; use inherited direct execute boundary."""
    def __init__(self, gate, binding, bridge, receiver):
        self.launch_gate = self._launch_gate_identity = gate
        self.run_binding, self.bridge, self.authority_client = copy.deepcopy(binding), bridge, receiver
        self.controller = UnitController()
        self._lock = threading.RLock()
        self.begin_count = 0
        self.grant_action = None
        self.reservation_id = None
        self._channel_observation_lock = threading.RLock()
        self._channel_observations = []
        self._user_before_dispatch_hook = None
        self.command = None

    def pin(self):
        return copy.deepcopy(self.run_binding["supervisor_pin"])

    def _grant(self, action_id):
        return {"action": self.grant_action, "reservation_id": self.reservation_id, "receipt": None,
                "authorization": {}, "callback_phase": "NOT_DISPATCHED", "settlement_status": None}

    def _call(self, *args):
        self.begin_count += 1
        return {"status": "DENIED", "reason": "EXPLICIT_UNIT_AUTHORITY_DENIAL"}

    def _command(self, command_id):
        return copy.deepcopy(self.command)

    def cleanup(self, *args):
        return None


class UnitCoordinator:
    def __init__(self, binding, supervisor, bridge, gateway, command_admin, effect_admin):
        self.run_binding, self.supervisor, self.bridge = copy.deepcopy(binding), supervisor, bridge
        self.effect_gateway, self.command_admin_client, self.effect_admin_client = gateway, command_admin, effect_admin
        self.closed = False
        self.health = {"ready": True, "alive": True, "fresh": True}
        self.health_maximum = None

    def fence_state(self):
        return {"closed": self.closed}

    def watcher_health(self, *, max_age_seconds):
        self.health_maximum = max_age_seconds
        return copy.deepcopy(self.health)

    def stop(self, *args):
        self.closed = True


class ClosedChannelLaunchTests(unittest.TestCase):
    def setUp(self):
        self.spec = agent_spec("unit-command", "sha256:" + "c" * 64, "/tmp/explicit-unit-workspace")
        self.effect = network_action(action_id="unit-effect", attempt_id="unit-attempt", root_id="effect-root",
            execution_id="effect-worker", epoch=1, endpoint_url="http://127.0.0.1:12003", marker="unit-marker")
        self.binding = {"schema": RUN_SCHEMA, "run_id": "unit-run",
            "command": {"root_id": "command-root", "execution_id": "command-worker", "epoch": 1,
                        "authority_pin": pin("authority", "command-authority", "1")},
            "effect": {"root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1,
                       "authority_pin": pin("authority", "effect-authority", "2")},
            "supervisor_pin": pin("supervisor", "unit-supervisor", "3"),
            "endpoint_pin": pin("endpoint", "unit-endpoint", "4"),
            "effect_actions": [self.effect], "effect_action_digests": [digest(self.effect)],
            "source_digest": AGENT_FIXTURE_SHA256, "spec_digest": digest(self.spec)}
        self.command_url, self.effect_url = "http://127.0.0.1:12001", "http://127.0.0.1:12002"
        self.command_admin = UnitAuthority(self.command_url, "admin", self.binding["command"]["authority_pin"])
        self.command_receiver = UnitAuthority(self.command_url, "receiver", self.binding["command"]["authority_pin"])
        self.effect_admin = UnitAuthority(self.effect_url, "admin", self.binding["effect"]["authority_pin"])
        self.effect_receiver = UnitAuthority(self.effect_url, "receiver", self.binding["effect"]["authority_pin"])
        self.endpoint = UnitEndpoint(self.binding["endpoint_pin"])
        self.gateway = UnitGateway(self.effect_receiver, self.endpoint)
        self.bridge_configuration = {"run_binding": {"run_id": "unit-run", "root_id": "effect-root",
                "execution_id": "effect-worker", "epoch": 1}, "actions": [self.effect],
            "admission_observer_required": True, "owned_run_binding_digest": digest(self.binding),
            "owned_command_binding": {name: self.binding["command"][name] for name in ("root_id", "execution_id", "epoch")},
            "effect_gateway_configuration": json.loads(self.gateway._configuration())}
        self.arguments = dict(spec=self.spec, run_binding=self.binding, bridge_configuration=self.bridge_configuration,
            command_authority_url=self.command_url, effect_authority_url=self.effect_url)
        self.channels = build_channel_inventory(**self.arguments)
        self.gate = ClosedChannelLaunchGate(**self.arguments, channels=self.channels)
        self.bridge = UnitBridge(self.bridge_configuration, self.gateway)
        self.supervisor = UnitClosedSupervisor(self.gate, self.binding, self.bridge, self.command_receiver)
        self.coordinator = UnitCoordinator(self.binding, self.supervisor, self.bridge, self.gateway,
            self.command_admin, self.effect_admin)
        self.action = agent_action(action_id="unit-create", attempt_id="unit-create-attempt", root_id="command-root",
            execution_id="command-worker", epoch=1, stage="CREATE", spec=self.spec)
        self.supervisor.grant_action = copy.deepcopy(self.action)

    def bind(self):
        self.gate.bind(self.coordinator)

    def test_inventory_required(self):
        with self.assertRaisesRegex(ControlError, "CHANNEL_INVENTORY_REQUIRED"):
            ClosedChannelLaunchGate(**self.arguments)

    def test_missing_extra_or_unmediated_channel_rejected(self):
        missing, extra, unmediated = (copy.deepcopy(self.channels) for _ in range(3))
        del missing["worker_network"]
        extra["provider_api"] = {"mode": "MEDIATED"}
        unmediated["worker_stdio_proposals"]["gate"] = None
        for channels in (missing, extra, unmediated):
            with self.subTest(channels=channels), self.assertRaisesRegex(ControlError, "CHANNEL_INVENTORY_MISMATCH"):
                ClosedChannelLaunchGate(**self.arguments, channels=channels)

    def test_changed_route_declaration_rejected(self):
        channels = copy.deepcopy(self.channels)
        channels["host_endpoint_effect"]["endpoint_url"] = "http://127.0.0.1:12004"
        with self.assertRaisesRegex(ControlError, "CHANNEL_INVENTORY_MISMATCH"):
            ClosedChannelLaunchGate(**self.arguments, channels=channels)

    def test_undeclared_provider_route_in_bridge_configuration_rejected(self):
        arguments = copy.deepcopy(self.arguments)
        arguments["bridge_configuration"]["provider_route"] = "http://127.0.0.1:12004"
        with self.assertRaisesRegex(ControlError, "INPUT_BINDING_MISMATCH"):
            build_channel_inventory(**arguments)

    def test_config_is_defensive_and_never_authorizes(self):
        configuration = self.gate.configuration()
        configuration["channels"].clear()
        self.assertEqual(self.gate.configuration()["channels"], self.channels)
        self.assertIs(self.gate.configuration()["execution_authorized"], False)
        with self.assertRaisesRegex(ControlError, "UNBOUND"):
            self.gate.assert_ready(self.action)
        self.assertEqual(self.supervisor.begin_count, 0)

    def test_bound_ready_graph_is_necessary_but_never_dispatches(self):
        self.bind()
        self.gate.assert_ready(self.action)
        self.assertEqual(self.coordinator.health_maximum, 2.0)
        self.assertEqual(self.supervisor.begin_count, 0)
        self.assertEqual(self.gateway.calls, 0)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_bind_once_and_gate_identity_required(self):
        self.supervisor.launch_gate = object()
        with self.assertRaisesRegex(ControlError, "ROUTE_BINDING_MISMATCH"):
            self.bind()
        self.supervisor.launch_gate = self.gate
        self.bind()
        with self.assertRaisesRegex(ControlError, "ALREADY_BOUND"):
            self.bind()

    def test_actual_authority_url_and_role_mismatch_denied(self):
        self.command_receiver.url = "http://127.0.0.1:12004"
        with self.assertRaisesRegex(ControlError, "AUTHORITY_ROUTE_MISMATCH"):
            self.bind()
        self.command_receiver.url, self.command_receiver.role = self.command_url, "admin"
        with self.assertRaisesRegex(ControlError, "AUTHORITY_ROUTE_MISMATCH"):
            self.bind()

    def test_endpoint_pin_and_url_mutations_denied(self):
        self.bind()
        self.endpoint._pin["key_id"] = "changed-key"
        with self.assertRaisesRegex(ControlError, "ROUTE_BINDING_MISMATCH"):
            self.gate.assert_ready()

    def test_replacement_same_configuration_object_rejected(self):
        self.bind()
        self.coordinator.command_admin_client = UnitAuthority(self.command_url, "admin", self.command_admin.pin())
        with self.assertRaisesRegex(ControlError, "ROUTE_IDENTITY_CHANGED"):
            self.gate.assert_ready()

    def test_replaced_executor_callable_rejected(self):
        self.bind()
        self.bridge.executor = lambda action: None
        with self.assertRaisesRegex(ControlError, "CALLABLE_CHANGED"):
            self.gate.assert_ready()

    def test_replaced_endpoint_commit_callable_rejected(self):
        self.bind()
        self.endpoint.commit = lambda *args: None
        with self.assertRaisesRegex(ControlError, "CALLABLE_CHANGED"):
            self.gate.assert_ready()

    def test_other_action_lineage_denied(self):
        self.bind()
        changed = copy.deepcopy(self.action)
        changed["execution_id"] = "other-worker"
        with self.assertRaisesRegex(ControlError, "ACTION_BINDING_MISMATCH"):
            self.gate.assert_ready(changed)

    def test_fence_and_absent_dead_stale_watchdog_deny(self):
        self.bind()
        self.coordinator.closed = True
        with self.assertRaisesRegex(ControlError, "FENCED"):
            self.gate.assert_ready()
        self.coordinator.closed = False
        for name in ("ready", "alive", "fresh"):
            self.coordinator.health = {"ready": True, "alive": True, "fresh": True}
            self.coordinator.health[name] = False
            with self.subTest(name=name), self.assertRaisesRegex(ControlError, "WATCHDOG_UNREADY"):
                self.gate.assert_ready()

    def test_direct_supervisor_execute_cannot_bypass_missing_watchdog(self):
        self.bind()
        self.coordinator.health["alive"] = False
        with patch.object(ExternalAgentSupervisor, "_ready") as parent_ready:
            result = self.supervisor.execute(self.action)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "AGENT_LAUNCH_WATCHDOG_UNREADY")
        parent_ready.assert_not_called()
        self.assertEqual(self.supervisor.begin_count, 0)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_reserved_retry_cannot_contact_begin_with_dead_watchdog(self):
        self.supervisor.reservation_id = "explicit-unit-existing-reservation"
        self.bind()
        self.coordinator.health["alive"] = False
        with patch.object(ExternalAgentSupervisor, "_ready") as first_admission:
            result = self.supervisor.execute(self.action)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "AGENT_LAUNCH_WATCHDOG_UNREADY")
        first_admission.assert_not_called()
        self.assertEqual(self.supervisor.begin_count, 0)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_exact_gated_create_argv_pins_flags_image_and_fixture(self):
        self.bind()
        record = {"session_id": "liminal-control-" + "0" * 32, "registry_id": "unit-registry",
            "ownership_token": "unit-owner", "plan_sha256": self.spec["plan_sha256"]}
        command = {"spec": self.spec, "registry_record": record}
        expected = ["create", "--interactive", "--name", record["session_id"],
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--user", "65534:65534",
            "--pids-limit", "64", "--memory", "256m", "--cpus", "1.0",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "--workdir", "/workspace",
            "--mount", "type=bind,src=/tmp/explicit-unit-workspace,dst=/workspace,readonly",
            "--entrypoint", "python3", "--log-driver", "none",
            "--label", "liminal.control.registry=unit-registry", "--label", "liminal.control.owner=unit-owner",
            "--label", "liminal.control.plan=" + self.spec["plan_sha256"],
            "--ipc", "private", "--cgroupns", "private", "--runtime", "runc",
            self.spec["image_id"], *self.spec["argv"]]
        self.assertEqual(self.supervisor._create_argv(command), expected)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_create_argv_final_boundary_rejects_dead_watchdog(self):
        self.bind()
        self.coordinator.health["fresh"] = False
        command = {"spec": self.spec, "registry_record": {"session_id": "liminal-control-" + "0" * 32,
            "registry_id": "unit-registry", "ownership_token": "unit-owner", "plan_sha256": self.spec["plan_sha256"]}}
        with self.assertRaisesRegex(ControlError, "WATCHDOG_UNREADY"):
            self.supervisor._create_argv(command)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_ready_inventory_does_not_replace_external_admission(self):
        self.bind()
        with patch.object(ExternalAgentSupervisor, "_ready") as parent_ready:
            result = self.supervisor.execute(self.action)
        parent_ready.assert_called_once()
        self.assertEqual(self.supervisor.begin_count, 1)
        self.assertEqual(result["reason"], "EXPLICIT_UNIT_AUTHORITY_DENIAL")
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_direct_observe_proposal_denied_when_unready(self):
        self.bind()
        self.coordinator.health["fresh"] = False
        with patch.object(ExternalAgentSupervisor, "observe_proposal") as observer:
            with self.assertRaisesRegex(ControlError, "WATCHDOG_UNREADY"):
                self.supervisor.observe_proposal(self.effect)
        observer.assert_not_called()

    def prepare_start(self):
        raw = safe_inspect_fixture()
        raw["Config"]["WorkingDir"] = "/workspace"
        raw["Config"]["Cmd"] = self.spec["argv"]
        self.supervisor.controller.inspected = raw
        command = {"command_id": self.spec["command_id"], "spec": self.spec,
            "registry_record": {"session_id": "explicit-unit-session"},
            "image_environment_digest": digest(raw["Config"]["Env"])}
        self.supervisor.command = command
        action = agent_action(action_id="unit-start", attempt_id="unit-start-attempt", root_id="command-root",
            execution_id="command-worker", epoch=1, stage="START", spec=self.spec,
            parent_reservation_id="unit-parent", container_id=raw["Id"])
        return action, command

    def test_start_readiness_denies_unsafe_actual_channels_before_begin(self):
        start, _ = self.prepare_start()
        self.supervisor.controller.inspected["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/kvm"}]
        self.supervisor.grant_action = start
        self.bind()
        with patch.object(ExternalAgentSupervisor, "_ready"):
            result = self.supervisor.execute(start)
        self.assertEqual(result["reason"], "AGENT_DOCKER_CHANNELS_INVALID")
        self.assertEqual(self.supervisor.begin_count, 0)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_start_dispatch_rechecks_after_blocking_configuration_observation(self):
        start, command = self.prepare_start()
        self.bind()
        self.supervisor.controller.after_verify = lambda: self.coordinator.health.update(fresh=False)
        with patch.object(ExternalAgentSupervisor, "_start_dispatch") as starter:
            with self.assertRaisesRegex(ControlError, "WATCHDOG_UNREADY"):
                self.supervisor._start_dispatch(start, command)
        self.assertEqual(self.supervisor.controller.verifications, 1)
        starter.assert_not_called()
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_start_dispatch_rechecks_actual_channels_before_start(self):
        start, command = self.prepare_start()
        self.supervisor.controller.inspected["HostConfig"]["PortBindings"] = {"80/tcp": []}
        self.bind()
        with patch.object(ExternalAgentSupervisor, "_start_dispatch") as starter:
            with self.assertRaisesRegex(ControlError, "DOCKER_CHANNELS_INVALID"):
                self.supervisor._start_dispatch(start, command)
        starter.assert_not_called()
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_start_observation_is_bounded_public_provenance(self):
        start, command = self.prepare_start()
        self.bind()
        with patch.object(ExternalAgentSupervisor, "_start_dispatch", return_value="unit-started"):
            self.assertEqual(self.supervisor._start_dispatch(start, command), "unit-started")
        item = self.supervisor._channel_observations[0]
        self.assertEqual(item["container_id"], "a" * 64)
        self.assertEqual(item["source"], "owned_docker_inspect")
        self.assertEqual(item["boundary"], "BEFORE_DOCKER_START")
        self.assertIs(item["projection"]["execution_authorized"], False)

    def test_mandatory_dispatch_gate_survives_fault_hook_assignment(self):
        self.bind()
        self.supervisor.before_dispatch_hook = lambda stage, action: self.coordinator.health.update(alive=False)
        with self.assertRaisesRegex(ControlError, "WATCHDOG_UNREADY"):
            self.supervisor.before_dispatch_hook("CREATE", self.action)
        self.assertEqual(self.supervisor.controller.dispatches, 0)

    def test_configuration_remains_readable_after_closed_admission(self):
        self.bind()
        contract = self.gate.configuration()
        self.coordinator.stop()
        self.assertEqual(self.gate.configuration(), contract)
        with self.assertRaisesRegex(ControlError, "FENCED"):
            self.gate.assert_ready()


class ClosedChannelStoreTests(unittest.TestCase):
    def test_health_lost_after_real_signed_begin_finishes_callback_without_docker_dispatch(self):
        # The authority and journal are real. Docker and watchdog observations
        # are explicit doubles; the test establishes callback/admission logic.
        from sdk.liminal_agent_control.external_agent_coordinator import agent_policy_digest
        from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient
        from tests.test_agent_control_external_agent_supervisor import ExternalAgentSupervisorTests
        case = ExternalAgentSupervisorTests("test_agent_create_reuses_external_one_shot")
        self.addCleanup(case.doCleanups)
        case.setUp()
        command_receiver = case.supervisor.authority_client
        case.supervisor.close()
        command_admin = HTTPExternalAuthorityClient(command_receiver.url, b"command-admin-key" * 3,
            case.authority.pin(), role="admin")
        effect_url = "http://127.0.0.1:12002"
        effect_receiver = UnitAuthority(effect_url, "receiver", case.binding["effect"]["authority_pin"])
        effect_admin = UnitAuthority(effect_url, "admin", case.binding["effect"]["authority_pin"])
        endpoint = UnitEndpoint(case.binding["endpoint_pin"])
        endpoint.url = case.effect_action["arguments"]["url"].removesuffix("/v1/record")
        gateway = UnitGateway(effect_receiver, endpoint)
        case.bridge.gateway, case.bridge.executor = gateway, gateway.execute
        case.bridge._configuration["effect_gateway_configuration"] = json.loads(gateway._configuration())
        arguments = dict(spec=case.spec, run_binding=case.binding, bridge_configuration=case.bridge.configuration(),
            command_authority_url=command_receiver.url, effect_authority_url=effect_url)
        gate = ClosedChannelLaunchGate(**arguments, channels=build_channel_inventory(**arguments))
        gated = ClosedChannelAgentSupervisor(case.path / "callback-supervisor.sqlite", case.path / "callback-registry.sqlite",
            supervisor_id="supervisor", key_id="supervisor-key", private_key=b"\x42" * 32,
            authority_client=command_receiver, controller=case.docker, bridge=case.bridge,
            run_binding=case.binding, launch_gate=gate)
        self.addCleanup(gated.close)
        coordinator = UnitCoordinator(case.binding, gated, case.bridge, gateway, command_admin, effect_admin)
        gate.bind(coordinator)
        action = case.action()
        gated.authorize(action, {"action_digest": digest(action), "policy_version": agent_policy_digest(case.binding, "command"),
            "expires_at": 200.0, "receiver_id": "supervisor"})
        gated.before_dispatch_hook = lambda stage, proposed: coordinator.health.update(alive=False)
        first = gated.execute(action)
        self.assertEqual(first["status"], "UNKNOWN")
        callback = gated._calls[action["action_id"]]
        callback.thread.join(2)
        self.assertFalse(callback.thread.is_alive())
        state = gated._grant(action["action_id"])
        self.assertIsNotNone(state["reservation_id"])
        self.assertEqual(state["callback_phase"], "FINISHED")
        self.assertIs(state["callback_result"]["returned"], False)
        self.assertEqual(state["callback_result"]["error"], "AGENT_LAUNCH_WATCHDOG_UNREADY")
        self.assertEqual(state["status"], "UNKNOWN")
        self.assertIsNone(state["receipt"])
        begins = [pair for pair in command_receiver.evidence if pair["request"]["operation"] == "begin"]
        self.assertEqual(len(begins), 1)
        retry = gated.execute(action)
        self.assertEqual(retry["status"], "DENIED")
        self.assertEqual(retry["reason"], "AGENT_LAUNCH_WATCHDOG_UNREADY")
        self.assertEqual(len([pair for pair in command_receiver.evidence if pair["request"]["operation"] == "begin"]), 1)
        external = case.authority.status("command-root")
        self.assertEqual(external["issued_count"], 1)
        self.assertEqual(external["pending_count"], 1)
        self.assertEqual(case.docker.dispatch_count("create"), 0)
        self.assertEqual(case.docker.dispatch_count("start"), 0)

    def test_gated_store_cannot_reopen_via_legacy_supervisor(self):
        # Reuse a real signed client/persisted registry setup; Docker stays an
        # explicit double and no lifecycle or effect dispatch is requested.
        from tests.test_agent_control_external_agent_supervisor import ExternalAgentSupervisorTests
        case = ExternalAgentSupervisorTests("test_agent_create_reuses_external_one_shot")
        self.addCleanup(case.doCleanups)
        case.setUp()
        authority_url = case.supervisor.authority_client.url
        arguments = dict(spec=case.spec, run_binding=case.binding, bridge_configuration=case.bridge.configuration(),
            command_authority_url=authority_url, effect_authority_url="http://127.0.0.1:12002")
        gate = ClosedChannelLaunchGate(**arguments, channels=build_channel_inventory(**arguments))
        parameters = dict(supervisor_id="supervisor", key_id="supervisor-key", private_key=b"\x42" * 32,
            authority_client=case.supervisor.authority_client, controller=case.docker,
            bridge=case.bridge, run_binding=case.binding)
        state_path, registry_path = case.path / "gated-supervisor.sqlite", case.path / "gated-registry.sqlite"
        gated = ClosedChannelAgentSupervisor(state_path, registry_path, launch_gate=gate, **parameters)
        self.assertEqual(gated._configuration_extra()["launch_contract_digest"], gate.contract_digest)
        gated.close()
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            ExternalAgentSupervisor(state_path, registry_path, create=False, **parameters)
        # Conversely, an old store never silently gains G01 provenance.
        case.supervisor.close()
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            ClosedChannelAgentSupervisor(case.path / "supervisor.sqlite", case.path / "registry.sqlite",
                launch_gate=gate, create=False, **parameters)
        self.assertEqual(case.docker.dispatch_count("create"), 0)
        self.assertEqual(case.docker.dispatch_count("start"), 0)


if __name__ == "__main__":
    unittest.main()
