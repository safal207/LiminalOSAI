"""Closed channels and live host admission for one fixed synthetic workflow.

The inventory describes the trusted launcher's complete, finite route set. Its
digest is configuration provenance, never an execution grant. Actual route
objects, host fencing, watchdog health and Docker inspection still gate every
launch/effect boundary. Worker-local tmpfs and subprocesses stay confined to
the owned container; no model, MCP, host shell or delegated route is supported.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from .authority import ControlError, canonical_bytes, digest
from .external_agent_coordinator import validate_run_binding
from .external_agent_protocol import validate_agent_action, validate_agent_spec
from .external_agent_supervisor import ExternalAgentSupervisor
from .external_network_protocol import validate_endpoint_base_url

LAUNCH_SCHEMA = "liminal-closed-channel-agent-launch-v1"
WORKFLOW = "owned-fixed-fixture-synthetic-record-v1"
WATCHDOG_MAX_AGE_SECONDS = 2.0


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _inputs(*, spec: Any, run_binding: Any, bridge_configuration: Any,
            command_authority_url: Any, effect_authority_url: Any) -> dict:
    spec = validate_agent_spec(spec)
    binding = validate_run_binding(run_binding)
    bridge = _copy(bridge_configuration)
    command_url = validate_endpoint_base_url(command_authority_url)
    effect_url = validate_endpoint_base_url(effect_authority_url)
    expected_effect = {"run_id": binding["run_id"], **{
        name: binding["effect"][name] for name in ("root_id", "execution_id", "epoch")}}
    expected_command = {name: binding["command"][name] for name in ("root_id", "execution_id", "epoch")}
    if (binding["spec_digest"] != digest(spec) or binding["source_digest"] != spec["fixture_sha256"]
            or type(bridge) is not dict
            or set(bridge) != {"run_binding", "actions", "admission_observer_required",
                "owned_run_binding_digest", "owned_command_binding", "effect_gateway_configuration"}
            or canonical_bytes(bridge.get("run_binding")) != canonical_bytes(expected_effect)
            or canonical_bytes(bridge.get("actions")) != canonical_bytes(binding["effect_actions"])
            or bridge.get("admission_observer_required") is not True
            or bridge.get("owned_run_binding_digest") != digest(binding)
            or canonical_bytes(bridge.get("owned_command_binding")) != canonical_bytes(expected_command)
            or type(bridge.get("effect_gateway_configuration")) is not dict):
        raise ControlError("AGENT_LAUNCH_INPUT_BINDING_MISMATCH")
    endpoints = {action["arguments"]["url"] for action in binding["effect_actions"]}
    if len(endpoints) != 1:
        raise ControlError("AGENT_LAUNCH_SINGLE_ENDPOINT_REQUIRED")
    endpoint_url = validate_endpoint_base_url(next(iter(endpoints)).removesuffix("/v1/record"))
    return {"spec": spec, "run_binding": binding, "bridge_configuration": bridge,
            "command_authority_url": command_url, "effect_authority_url": effect_url,
            "endpoint_url": endpoint_url}


def build_channel_inventory(*, spec: Any, run_binding: Any, bridge_configuration: Any,
                            command_authority_url: Any, effect_authority_url: Any) -> dict:
    """Derive the fixed workflow's exact inventory in trusted launcher code."""
    item = _inputs(spec=spec, run_binding=run_binding, bridge_configuration=bridge_configuration,
        command_authority_url=command_authority_url, effect_authority_url=effect_authority_url)
    spec, binding = item["spec"], item["run_binding"]
    bridge_digest = digest(item["bridge_configuration"])
    gate = "exact-host-grant-and-fresh-external-BEGIN"
    watcher = "bound-live-fresh-host-watchdog"
    return {
        "worker_network": {"mode": "DENIED", "boundary": "docker-network-none"},
        "worker_workspace": {"mode": "READ_ONLY", "mount": _copy(spec["workspace_mount"]),
                             "fixture_sha256": spec["fixture_sha256"]},
        "worker_host_filesystem": {"mode": "DENIED", "boundary": "no-extra-host-mounts"},
        "worker_control_sockets_devices": {"mode": "DENIED", "boundary": "no-added-host-socket-device-or-volume-routes"},
        "worker_host_namespaces": {"mode": "RESTRICTED", "boundary": "no-pid-ipc-uts-cgroup-sharing",
            "user_namespace_isolation": "NOT_ESTABLISHED",
            "create_flags": ["--ipc", "private", "--cgroupns", "private", "--runtime", "runc"]},
        "worker_local_tmpfs_processes": {"mode": "CONFINED", "isolation": _copy(spec["isolation"]),
                                       "external_authority": False},
        "worker_stdio_proposals": {"mode": "MEDIATED", "bridge_configuration_digest": bridge_digest,
            "effect_action_digests": _copy(binding["effect_action_digests"]), "gate": gate,
            "watchdog": watcher, "owned_observation_required": True},
        "worker_stdio_claims": {"mode": "OBSERVATION_ONLY", "external_authority": False},
        "worker_stderr": {"mode": "OBSERVATION_ONLY", "external_authority": False},
        "host_command_lifecycle": {"mode": "MEDIATED", "spec_digest": digest(spec),
            "authority_url": item["command_authority_url"], "authority_pin": _copy(binding["command"]["authority_pin"]),
            "supervisor_pin": _copy(binding["supervisor_pin"]), "gate": gate, "watchdog": watcher},
        "host_endpoint_effect": {"mode": "MEDIATED", "endpoint_url": item["endpoint_url"],
            "endpoint_pin": _copy(binding["endpoint_pin"]), "gate": gate, "watchdog": watcher,
            "effect_gateway_configuration_digest": digest(item["bridge_configuration"]["effect_gateway_configuration"])},
        "host_authority_control": {"mode": "TRUSTED_CONTROL", "command_url": item["command_authority_url"],
            "effect_url": item["effect_authority_url"], "effect_pin": _copy(binding["effect"]["authority_pin"]),
            "agent_credentials": False},
        "host_watchdog_stop_reconciliation": {"mode": "TRUSTED_CONTROL", "watchdog": watcher,
            "maximum_health_age_seconds": WATCHDOG_MAX_AGE_SECONDS, "reconciliation_dispatches_effects": False},
        "external_model_mcp_host_shell_delegation": {"mode": "DENIED", "supported_routes": []},
    }


def _callable_identity(value: Any) -> tuple:
    if not callable(value):
        raise ControlError("AGENT_LAUNCH_ROUTE_MISSING")
    return (getattr(value, "__self__", None), getattr(value, "__func__", value))


class ClosedChannelLaunchGate:
    def __init__(self, *, spec: Any, run_binding: Any, bridge_configuration: Any,
                 command_authority_url: Any, effect_authority_url: Any, channels: Any = None):
        if channels is None:
            raise ControlError("AGENT_CHANNEL_INVENTORY_REQUIRED")
        arguments = dict(spec=spec, run_binding=run_binding, bridge_configuration=bridge_configuration,
            command_authority_url=command_authority_url, effect_authority_url=effect_authority_url)
        item = _inputs(**arguments)
        expected = build_channel_inventory(**arguments)
        if type(channels) is not dict or canonical_bytes(channels) != canonical_bytes(expected):
            raise ControlError("AGENT_CHANNEL_INVENTORY_MISMATCH")
        self._inputs_bytes = canonical_bytes(item)
        body = {"schema": LAUNCH_SCHEMA, "workflow": WORKFLOW,
            "source_digest": item["spec"]["fixture_sha256"], "spec_digest": digest(item["spec"]),
            "run_binding_digest": digest(item["run_binding"]),
            "bridge_configuration_digest": digest(item["bridge_configuration"]),
            "channels": expected, "execution_authorized": False}
        self._contract_bytes = canonical_bytes({**body, "contract_digest": digest(body)})
        self._contract_hash = digest(json.loads(self._contract_bytes))
        self._coordinator = None
        self._objects: dict[str, Any] = {}
        self._routes: dict[tuple[str, str], tuple] = {}

    def configuration(self) -> dict:
        """Immutable provenance remains readable after STOP and during init."""
        contract = json.loads(self._contract_bytes)
        if digest(contract) != self._contract_hash:
            raise ControlError("AGENT_LAUNCH_CONFIGURATION_IMMUTABLE")
        return contract

    @property
    def contract_digest(self) -> str:
        return self.configuration()["contract_digest"]

    def _live_objects(self, coordinator: Any) -> dict:
        try:
            supervisor, bridge, gateway = coordinator.supervisor, coordinator.bridge, coordinator.effect_gateway
            return {"coordinator": coordinator, "supervisor": supervisor, "bridge": bridge, "gateway": gateway,
                "controller": supervisor.controller, "command_admin": coordinator.command_admin_client,
                "effect_admin": coordinator.effect_admin_client, "command_receiver": supervisor.authority_client,
                "effect_receiver": gateway.external_controller, "endpoint": gateway.endpoint_client}
        except AttributeError as exc:
            raise ControlError("AGENT_LAUNCH_ROUTE_MISSING") from exc

    def _validate_bindings(self, objects: dict) -> None:
        item = json.loads(self._inputs_bytes)
        binding = item["run_binding"]
        coordinator, supervisor, bridge, gateway = (objects[key] for key in ("coordinator", "supervisor", "bridge", "gateway"))
        if (getattr(supervisor, "launch_gate", None) is not self
                or supervisor.bridge is not bridge
                or canonical_bytes(coordinator.run_binding) != canonical_bytes(binding)
                or canonical_bytes(supervisor.run_binding) != canonical_bytes(binding)
                or canonical_bytes(bridge.configuration()) != canonical_bytes(item["bridge_configuration"])
                or getattr(bridge.executor, "__self__", None) is not gateway
                or _callable_identity(bridge.executor) != _callable_identity(gateway.execute)
                or bridge.admission_observer_required is not True
                or not callable(bridge.admission_observer)
                or not callable(bridge.fence_check)
                or canonical_bytes(json.loads(gateway._configuration())) != canonical_bytes(
                    item["bridge_configuration"]["effect_gateway_configuration"])):
            raise ControlError("AGENT_LAUNCH_ROUTE_BINDING_MISMATCH")
        if (self._coordinator is not None
                and item["bridge_configuration"]["effect_gateway_configuration"].get("schema")
                    == "liminal-closed-channel-effect-gateway-store-v1"
                and getattr(gateway, "launch_gate", None) is not self):
            raise ControlError("AGENT_LAUNCH_EFFECT_GATE_BINDING_MISMATCH")
        for name, branch, role, url in (
            ("command_admin", "command", "admin", item["command_authority_url"]),
            ("command_receiver", "command", "receiver", item["command_authority_url"]),
            ("effect_admin", "effect", "admin", item["effect_authority_url"]),
            ("effect_receiver", "effect", "receiver", item["effect_authority_url"]),
        ):
            client = objects[name]
            if (client.url != url or client.role != role
                    or canonical_bytes(client.pin()) != canonical_bytes(binding[branch]["authority_pin"])):
                raise ControlError("AGENT_LAUNCH_AUTHORITY_ROUTE_MISMATCH")
        if (objects["endpoint"].url != item["endpoint_url"]
                or canonical_bytes(objects["endpoint"].pin()) != canonical_bytes(binding["endpoint_pin"])
                or canonical_bytes(supervisor.pin()) != canonical_bytes(binding["supervisor_pin"])):
            raise ControlError("AGENT_LAUNCH_ENDPOINT_ROUTE_MISMATCH")

    def bind(self, coordinator: Any) -> None:
        """Attach once to the constructed trusted component graph, never a worker."""
        if self._coordinator is not None:
            raise ControlError("AGENT_LAUNCH_ALREADY_BOUND")
        objects = self._live_objects(coordinator)
        self._validate_bindings(objects)
        route_names = {
            "coordinator": ("fence_state", "watcher_health", "stop"),
            "supervisor": ("execute", "observe_proposal", "_ready", "_create_argv", "_start_dispatch", "cleanup"),
            "bridge": ("run", "configuration", "executor", "fence_check", "admission_observer", "fence"),
            "gateway": ("execute", "reconcile", "_configuration"),
            "controller": ("command", "verify_configuration", "_inspect"),
            "command_admin": ("status", "stop"), "effect_admin": ("status", "stop"),
            "command_receiver": ("begin",), "effect_receiver": ("begin",),
            "endpoint": ("commit", "query"),
        }
        if json.loads(self._inputs_bytes)["bridge_configuration"]["effect_gateway_configuration"].get("schema") \
                == "liminal-closed-channel-effect-gateway-store-v1":
            route_names["coordinator"] += ("close_admission",)
            route_names["gateway"] += ("_before_endpoint_commit", "bind_launch_gate")
            route_names["bridge"] += ("inventory",)
        routes = {(name, method): _callable_identity(getattr(objects[name], method, None))
            for name, methods in route_names.items() for method in methods}
        self._objects, self._routes, self._coordinator = objects, routes, coordinator

    def assert_ready(self, action: Any = None) -> None:
        """Readiness is necessary, and never replaces the external grant/BEGIN."""
        self.configuration()
        if self._coordinator is None:
            raise ControlError("AGENT_LAUNCH_UNBOUND")
        objects = self._live_objects(self._coordinator)
        if any(objects.get(name) is not value for name, value in self._objects.items()):
            raise ControlError("AGENT_LAUNCH_ROUTE_IDENTITY_CHANGED")
        if any(_callable_identity(getattr(objects[name], method, None)) != identity
               for (name, method), identity in self._routes.items()):
            raise ControlError("AGENT_LAUNCH_CALLABLE_CHANGED")
        self._validate_bindings(objects)
        if action is not None:
            action = validate_agent_action(action)
            item = json.loads(self._inputs_bytes)
            command = item["run_binding"]["command"]
            if (any(type(action[name]) is not type(command[name]) or action[name] != command[name]
                    for name in ("root_id", "execution_id", "epoch"))
                    or canonical_bytes(action["arguments"]["spec"]) != canonical_bytes(item["spec"])):
                raise ControlError("AGENT_LAUNCH_ACTION_BINDING_MISMATCH")
        state = self._coordinator.fence_state()
        if type(state) is not dict or state.get("closed") is not False:
            raise ControlError("AGENT_LAUNCH_FENCED")
        if json.loads(self._inputs_bytes)["bridge_configuration"]["effect_gateway_configuration"].get("schema") \
                == "liminal-closed-channel-effect-gateway-store-v1":
            bridge_state = objects["bridge"].inventory()
            if type(bridge_state) is not dict or bridge_state.get("fenced") is not False:
                raise ControlError("AGENT_LAUNCH_BRIDGE_FENCED")
        health = self._coordinator.watcher_health(max_age_seconds=WATCHDOG_MAX_AGE_SECONDS)
        if type(health) is not dict or any(health.get(name) is not True for name in ("ready", "alive", "fresh")):
            raise ControlError("AGENT_LAUNCH_WATCHDOG_UNREADY")


class ClosedChannelAgentSupervisor(ExternalAgentSupervisor):
    """Separate persisted profile that cannot silently reopen without its gate."""
    def __init__(self, *args, launch_gate: ClosedChannelLaunchGate, **kwargs):
        if not isinstance(launch_gate, ClosedChannelLaunchGate):
            raise ControlError("AGENT_LAUNCH_GATE_REQUIRED")
        self.launch_gate = launch_gate
        self._launch_gate_identity = launch_gate
        self._channel_observation_lock = threading.RLock()
        self._channel_observations: list[dict] = []
        super().__init__(*args, **kwargs)

    @property
    def before_dispatch_hook(self):
        # Parent _dispatch invokes this inside its try/final journaling path.
        # A mandatory wrapper cannot be removed by a trusted fault-hook setter.
        return self._closed_channel_before_dispatch

    @before_dispatch_hook.setter
    def before_dispatch_hook(self, callback):
        if callback is not None and not callable(callback):
            raise ControlError("AGENT_LAUNCH_DISPATCH_HOOK_INVALID")
        self._user_before_dispatch_hook = callback

    def _closed_channel_before_dispatch(self, stage: str, action: dict) -> None:
        self.launch_gate.assert_ready(action)
        if self._user_before_dispatch_hook is not None:
            self._user_before_dispatch_hook(stage, action)
        self.launch_gate.assert_ready(action)

    def _store_schema(self) -> str:
        return "liminal-closed-channel-agent-supervisor-store-v1"

    def _create_argv(self, command: dict) -> list[str]:
        argv = super()._create_argv(command)
        index = argv.index(command["spec"]["image_id"])
        argv[index:index] = ["--ipc", "private", "--cgroupns", "private", "--runtime", "runc"]
        self.launch_gate.assert_ready()
        return argv

    def _configuration_extra(self) -> dict:
        if self.launch_gate is not self._launch_gate_identity:
            raise ControlError("AGENT_LAUNCH_GATE_IMMUTABLE")
        configuration = super()._configuration_extra()
        configuration["launch_contract"] = self.launch_gate.configuration()
        configuration["launch_contract_digest"] = self.launch_gate.contract_digest
        return configuration

    def _ready(self, action: dict) -> None:
        self.launch_gate.assert_ready(action)
        super()._ready(action)
        if action["arguments"]["stage"] == "START":
            command = self._command(action["arguments"]["spec"]["command_id"])
            self._record_channels(self._verify_fixed_configuration(command), "BEFORE_BEGIN_START")
        self.launch_gate.assert_ready(action)

    def execute(self, proposed: Any) -> dict:
        # Include already-reserved attempts: the reference supervisor may
        # contact BEGIN for their reconciliation but must never redispatch.
        action = self._validate_action(proposed)
        try:
            self.launch_gate.assert_ready(action)
        except ControlError as exc:
            return {"status": "DENIED", "reason": str(exc), "action_id": action["action_id"],
                    "execution_authorized": False}
        return super().execute(action)

    def _record_channels(self, inspected: dict, boundary: str) -> None:
        from .external_agent_channels import verify_agent_channels
        projection = verify_agent_channels(inspected)
        item = {"container_id": projection["container_id"], "source": "owned_docker_inspect",
                "boundary": boundary, "observed_at": time.time(), "projection": projection}
        with self._channel_observation_lock:
            if len(self._channel_observations) >= 128:
                raise ControlError("AGENT_LAUNCH_CHANNEL_OBSERVATION_CAPACITY")
            self._channel_observations.append(item)

    def _start_dispatch(self, action: dict, command: dict):
        self.launch_gate.assert_ready(action)
        session = command["registry_record"]["session_id"]
        self.controller.verify_configuration(session, self._plan(command["spec"]))
        inspected = self._verify_fixed_configuration(command)
        self._record_channels(inspected, "BEFORE_DOCKER_START")
        # Config inspection may block; recheck health/fencing immediately at
        # the actual trusted Docker dispatch boundary, rather than at BEGIN.
        self.launch_gate.assert_ready(action)
        return super()._start_dispatch(action, command)

    def observe_proposal(self, action: dict) -> dict:
        self.launch_gate.assert_ready()
        observation = super().observe_proposal(action)
        command = self._command(observation["command_id"])
        self._record_channels(self._verify_fixed_configuration(command), "BEFORE_EFFECT_ADMISSION")
        self.launch_gate.assert_ready()
        return observation

    def inventory(self) -> dict:
        result = super().inventory()
        with self._channel_observation_lock:
            observations = _copy(self._channel_observations)
        result["launch_boundary"] = {"contract": self.launch_gate.configuration(),
            "contract_digest": self.launch_gate.contract_digest,
            "channel_observations": observations, "execution_authorized": False}
        return result
