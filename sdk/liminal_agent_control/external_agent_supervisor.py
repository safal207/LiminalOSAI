"""Owned Docker agent supervisor with a fenced, bounded STDIO proposal bridge.

The agent sees a fixed read-only fixture and public action proposals. Docker,
controller and endpoint credentials stay in the host process. A reaped attach
CLI alone is not a lifecycle proof: outstanding host effect callbacks keep the
START callback INFLIGHT until they have actually returned.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .authority import ControlError, canonical_bytes, digest
from .external_agent_protocol import (
    AGENT_FIXTURE_SHA256, AGENT_PROFILE, AGENT_RECEIPT_DOMAIN, AGENT_RECEIPT_SCHEMA,
    agent_plan, validate_agent_action, validate_agent_authorization, verify_agent_receipt,
)
from .external_command_supervisor import ExternalCommandSupervisor, _copy


class ExternalAgentSupervisor(ExternalCommandSupervisor):
    def __init__(self, *args, bridge: Any, run_binding: dict,
                 bridge_configuration: dict | None = None, **kwargs):
        from .external_agent_coordinator import validate_run_binding
        self.run_binding = validate_run_binding(run_binding)
        if not callable(getattr(bridge, "run", None)) or not callable(getattr(bridge, "configuration", None)):
            raise ControlError("AGENT_BRIDGE_CONFIGURATION_INVALID")
        self.bridge = bridge
        self._bridge_configuration = _copy(bridge.configuration() if bridge_configuration is None else bridge_configuration)
        if canonical_bytes(self._bridge_configuration) != canonical_bytes(bridge.configuration()):
            raise ControlError("AGENT_BRIDGE_CONFIGURATION_BINDING_MISMATCH")
        if (getattr(bridge, "admission_observer_required", False) is not True
                or self._bridge_configuration.get("admission_observer_required") is not True
                or not callable(getattr(bridge, "admission_observer", None))
                or self._bridge_configuration.get("owned_run_binding_digest") != digest(self.run_binding)
                or canonical_bytes(self._bridge_configuration.get("owned_command_binding")) != canonical_bytes({
                    k: self.run_binding["command"][k] for k in ("root_id", "execution_id", "epoch")})):
            raise ControlError("AGENT_BRIDGE_OWNED_OBSERVER_REQUIRED")
        self._effect_gateway = getattr(bridge.executor, "__self__", None)
        if (self._effect_gateway is None or not callable(getattr(self._effect_gateway, "_configuration", None))
                or canonical_bytes(self._bridge_configuration.get("effect_gateway_configuration")) !=
                canonical_bytes(json.loads(self._effect_gateway._configuration()))):
            raise ControlError("AGENT_BRIDGE_EFFECT_GATEWAY_BINDING_REQUIRED")
        # Process-local callable references supplement persisted public route
        # identity. They are never persisted as nondeterministic Python IDs.
        self._bridge_methods = {name: getattr(bridge, name).__func__ if hasattr(getattr(bridge, name), "__func__")
                                else getattr(bridge, name) for name in ("run", "configuration", "callbacks_finished", "fence", "close_admission")}
        self._bridge_callback_refs = {name: getattr(bridge, name, None) for name in
                                      ("executor", "fence_check", "before_proposal", "admission_observer")}
        self._attach_lock = threading.RLock()
        self._attach_processes: list[dict] = []
        self._live_observations: list[dict] = []
        super().__init__(*args, **kwargs)

    def _profile_name(self) -> str:
        return AGENT_PROFILE

    def _store_schema(self) -> str:
        return "liminal-agent-supervisor-store-v1"

    def _configuration_extra(self) -> dict:
        if any(getattr(self.bridge, name, None) is not original for name, original in self._bridge_callback_refs.items()):
            raise ControlError("AGENT_BRIDGE_CALLBACK_IMMUTABLE")
        if canonical_bytes(self._bridge_configuration["effect_gateway_configuration"]) != canonical_bytes(
                json.loads(self._effect_gateway._configuration())):
            raise ControlError("AGENT_BRIDGE_EFFECT_GATEWAY_IMMUTABLE")
        for name, original in self._bridge_methods.items():
            current = getattr(self.bridge, name)
            current = current.__func__ if hasattr(current, "__func__") else current
            if current is not original:
                raise ControlError("AGENT_BRIDGE_CALLABLE_IMMUTABLE")
        current = self.bridge.configuration()
        if canonical_bytes(current) != canonical_bytes(self._bridge_configuration):
            raise ControlError("AGENT_BRIDGE_CONFIGURATION_IMMUTABLE")
        if (canonical_bytes(self.pin()) != canonical_bytes(self.run_binding["supervisor_pin"])
                or canonical_bytes(self.authority_client.pin()) != canonical_bytes(self.run_binding["command"]["authority_pin"])):
            raise ControlError("AGENT_SUPERVISOR_RUN_PIN_MISMATCH")
        return {"bridge_configuration": _copy(current), "bridge_configuration_digest": digest(current),
                "run_binding": _copy(self.run_binding), "run_binding_digest": digest(self.run_binding),
                "bridge_budget": asdict(self.bridge.budget)}

    def _validate_action(self, action: Any) -> dict:
        action = validate_agent_action(action)
        binding = self.run_binding["command"]
        if (any(type(action[k]) is not type(binding[k]) or action[k] != binding[k]
                for k in ("root_id", "execution_id", "epoch"))
                or digest(action["arguments"]["spec"]) != self.run_binding["spec_digest"]):
            raise ControlError("AGENT_SUPERVISOR_RUN_BINDING_MISMATCH")
        return action

    def _validate_authorization(self, action: Any, authorization: Any) -> dict:
        return validate_agent_authorization(action, authorization, self.supervisor_id)

    def _plan(self, spec: Any):
        return agent_plan(spec)

    def _verify_receipt(self, receipt: Any) -> bool:
        return verify_agent_receipt(receipt, self.pin())

    def _receipt_schema(self) -> str:
        return AGENT_RECEIPT_SCHEMA

    def _receipt_domain(self) -> bytes:
        return AGENT_RECEIPT_DOMAIN

    @staticmethod
    def _verify_workspace(spec: dict) -> None:
        workspace = Path(spec["host_workspace"])
        fixture = workspace / "external_agent_fixture.py"
        if (not workspace.is_dir() or not fixture.is_file()
                or any(path.is_symlink() for path in (workspace, *workspace.parents, fixture))
                or {path.name for path in workspace.iterdir()} != {fixture.name}
                or fixture.stat().st_mode & 0o222
                or hashlib.sha256(fixture.read_bytes()).hexdigest() != AGENT_FIXTURE_SHA256):
            raise ControlError("AGENT_FIXED_WORKSPACE_MISMATCH")

    def _start_dispatch(self, action: dict, command: dict):
        # No shell, environment injection, mutable container name or Docker
        # socket enters the worker. These are the complete attach CLI arguments.
        argv = [self.controller.docker_binary, "start", "--attach", "--interactive", command["container_id"]]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, close_fds=True)
        entry = {"container_id": command["container_id"], "action_id": action["action_id"],
                 "pid": process.pid, "argv": argv, "started_at": time.time(),
                 "reaped": False, "returncode": None}
        with self._attach_lock:
            self._attach_processes.append(entry)
        try:
            result = self.bridge.run(process)
        except BaseException:
            # A bridge failure fences future proposals. The trusted cleanup
            # path must still terminate the actual owned Docker workload.
            self.bridge.fence("BRIDGE_FAILURE")
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            raise
        finally:
            # A timeout may have reaped docker CLI while an HTTP callback is
            # still completing. Hold durable INFLIGHT; cleanup holds the host
            # lock, so this wait must not acquire it or call coordinator.stop.
            while not self.bridge.callbacks_finished():
                time.sleep(0.01)
            if process.poll() is None:
                self.bridge.fence("ATTACH_UNREAPED")
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            with self._attach_lock:
                entry.update(reaped=True, returncode=process.returncode, finished_at=time.time())
        if not isinstance(result, subprocess.CompletedProcess):
            raise ControlError("AGENT_BRIDGE_RESULT_INVALID")
        return result

    def cleanup(self, command_id: str) -> dict:
        self.bridge.fence("OWNED_WORKLOAD_CLEANUP")
        return super().cleanup(command_id)

    def observe_proposal(self, action: dict) -> dict:
        """Fresh owned process observation on the actual host effect thread.

        This read never takes the cleanup lock. A pending gateway callback can
        finish while host cleanup holds that lock and waits for the callback.
        The observation establishes this instant only; external BEGIN remains
        the authority and accounts for a race with a later STOP.
        """
        from .external_network_protocol import validate_network_action
        action = validate_network_action(action)
        if canonical_bytes(action) not in {canonical_bytes(item) for item in self.run_binding["effect_actions"]}:
            raise ControlError("AGENT_PROPOSAL_ACTION_BINDING_MISMATCH")
        commands = self._commands()
        if len(commands) != 1:
            raise ControlError("AGENT_PROPOSAL_OWNED_WORKLOAD_UNAVAILABLE")
        command = commands[0]
        if command["closing"] or not command["create_confirmed"] or command["cleanup_complete"]:
            raise ControlError("AGENT_PROPOSAL_OWNED_WORKLOAD_CLOSED")
        session = command["registry_record"]["session_id"]
        self.controller.verify_configuration(session, self._plan(command["spec"]))
        self._verify_fixed_configuration(command)
        observed = self.controller.inspect_session(session)
        item = self.controller._inspect(session)
        if (observed.get("exists") is not True or observed.get("running") is not True
                or item is None or item.get("Id") != command["container_id"]
                or item.get("State", {}).get("Running") is not True
                or item.get("State", {}).get("Paused") is not False):
            raise ControlError("AGENT_PROPOSAL_OWNED_WORKLOAD_NOT_RUNNING")
        body = {"schema": "liminal-owned-agent-observation-v1", "run_id": self.run_binding["run_id"],
                "source": "owned_docker_inspect", "root_id": self.run_binding["command"]["root_id"],
                "execution_id": self.run_binding["command"]["execution_id"], "configuration_valid": True,
                "run_binding_digest": digest(self.run_binding), "action_id": action["action_id"],
                "action_digest": digest(action), "command_id": command["command_id"],
                "container_id": command["container_id"], "plan_sha256": command["plan_sha256"],
                "ownership_digest": digest(command["registry_record"]), "observed_at": time.time(),
                "inspect": self._bounded_inspect(item), "process": _copy(self.controller.process_evidence[session]),
                "exists": True, "running": True, "execution_authorized": False}
        observation = {**body, "observation_digest": digest(body)}
        with self._attach_lock:
            self._live_observations.append(observation)
        return observation

    def inventory(self) -> dict:
        result = super().inventory()
        # This immutable snapshot is diagnostic provenance. It grants neither
        # effects nor lifecycle authority. Bridge lock fixes a complete trace.
        result["bridge"] = self.bridge.inventory()
        with self._attach_lock:
            result["attach_processes"] = _copy(self._attach_processes)
            result["live_observations"] = _copy(self._live_observations)
        return result
