"""Agent profile unit regressions with real signed authority and fake Docker.

No test here claims Docker isolation. Required process evidence lives in the
separate owned Docker runtime matrix.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_authority import ExternalAgentAuthorityStore
from sdk.liminal_agent_control.external_agent_bridge import BridgeBudget
from sdk.liminal_agent_control.external_agent_coordinator import RUN_SCHEMA, agent_policy_digest
from sdk.liminal_agent_control.external_agent_protocol import AGENT_FIXTURE_SHA256, agent_action, agent_spec, verify_agent_receipt
from sdk.liminal_agent_control.external_agent_supervisor import ExternalAgentSupervisor
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_network_protocol import network_action
from sdk.liminal_agent_control.observer_auth import _crypto
from tests.test_agent_control_external_command_supervisor import FakeDocker, IMAGE, CONTAINER


def public_pin(kind, key, name):
    private, _ = _crypto()
    return {kind + "_id": name, "key_id": name + "-key",
            "public_key": private.from_private_bytes(key).public_key().public_bytes_raw().hex()}


class FakeBridge:
    def __init__(self, configuration):
        self._configuration = copy.deepcopy(configuration)
        self.budget = BridgeBudget()
        self.gateway = FakeRoute()
        self._configuration["effect_gateway_configuration"] = json.loads(self.gateway._configuration())
        self.executor = self.gateway.execute
        self.fence_check = lambda: {"closed": False}
        self.before_proposal = None
        self.admission_observer = lambda action: None
        self.admission_observer_required = True
        self.finished = threading.Event()
        self.finished.set()
        self.fenced = False
        self.entered = threading.Event()

    def configuration(self):
        return copy.deepcopy(self._configuration)

    def fence(self, reason="STOP"):
        self.fenced = True

    def close_admission(self, reason, durable_close):
        durable_close()
        self.fence(reason)

    def run(self, process):
        self.entered.set()
        stdout, stderr = process.communicate(timeout=2)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def callbacks_finished(self):
        return self.finished.is_set()

    def inventory(self):
        return {"configuration_digest": digest(self.configuration()), "callback_finished": self.callbacks_finished(),
                "outstanding_effect_calls": 0 if self.finished.is_set() else 1, "fenced": self.fenced}


class FakeRoute:
    def _configuration(self):
        return canonical_bytes({"schema": "explicit-unit-gateway", "measurement": "NOT_DOCKER_RUNTIME"}).decode()

    def execute(self, action):
        return None


class ExternalAgentSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.workspace = self.path / "workspace"
        self.workspace.mkdir()
        fixture = Path(__file__).resolve().parents[1] / "experiments/agent_control/external_agent_fixture.py"
        shutil.copyfile(fixture, self.workspace / fixture.name)
        (self.workspace / fixture.name).chmod(0o444)
        self.supervisor_pin = public_pin("supervisor", b"\x42" * 32, "supervisor")
        self.authority = ExternalAgentAuthorityStore(self.path / "authority.sqlite", supervisor_pin=self.supervisor_pin,
            authority_id="command-authority", key_id="command-authority-key", private_key=b"\x41" * 32,
            receipt_key=b"receipt-key-unused-agent" * 2, clock=lambda: 100.0)
        self.server = make_server(self.authority, b"command-admin-key" * 3, b"command-request-key" * 3)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.005), daemon=True)
        self.thread.start()
        self.effect_action = network_action(action_id="effect", attempt_id="effect-attempt", root_id="effect-root",
            execution_id="effect-worker", epoch=1, endpoint_url="http://127.0.0.1:12345", marker="owned-agent")
        self.spec = agent_spec("owned-command", IMAGE, str(self.workspace))
        self.binding = {"schema": RUN_SCHEMA, "run_id": "agent-run",
            "command": {"root_id": "command-root", "execution_id": "command-worker", "epoch": 1, "authority_pin": self.authority.pin()},
            "effect": {"root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1,
                       "authority_pin": public_pin("authority", b"\x43" * 32, "effect-authority")},
            "supervisor_pin": self.supervisor_pin, "endpoint_pin": public_pin("endpoint", b"\x44" * 32, "endpoint"),
            "effect_actions": [self.effect_action], "effect_action_digests": [digest(self.effect_action)],
            "source_digest": AGENT_FIXTURE_SHA256, "spec_digest": digest(self.spec)}
        self.bridge = FakeBridge({"run_binding": {"run_id": "agent-run", "root_id": "effect-root", "execution_id": "effect-worker", "epoch": 1},
                                  "actions": [self.effect_action], "admission_observer_required": True,
                                  "owned_run_binding_digest": digest(self.binding),
                                  "owned_command_binding": {k: self.binding["command"][k] for k in ("root_id", "execution_id", "epoch")}})
        self.docker = FakeDocker()
        self.supervisor = self.new_supervisor()
        self.authority.create_root("command-root", "supervisor", agent_policy_digest(self.binding, "command"), 32, 3600)
        self.authority.bind_execution("command-root", "command-worker")
        self.addCleanup(self.shutdown)

    def new_supervisor(self, create=True):
        return ExternalAgentSupervisor(self.path / "supervisor.sqlite", self.path / "registry.sqlite",
            supervisor_id="supervisor", key_id="supervisor-key", private_key=b"\x42" * 32,
            authority_client=HTTPExternalAuthorityClient("http://127.0.0.1:" + str(self.server.server_address[1]),
                b"command-request-key" * 3, self.authority.pin()), controller=self.docker,
            bridge=self.bridge, run_binding=self.binding, create=create)

    def shutdown(self):
        self.bridge.finished.set()
        for call in self.supervisor._calls.values():
            call.thread.join(2)
        try:
            self.supervisor.cleanup("owned-command")
            self.supervisor.close()
        except ControlError:
            pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def action(self, stage="CREATE", parent=None, container=None):
        return agent_action(action_id=stage.lower(), attempt_id="attempt:" + stage.lower(), root_id="command-root",
            execution_id="command-worker", epoch=1, stage=stage, spec=self.spec,
            parent_reservation_id=parent, container_id=container)

    def authorize(self, action):
        self.supervisor.authorize(action, {"action_digest": digest(action), "policy_version": agent_policy_digest(self.binding, "command"),
                                          "expires_at": 200.0, "receiver_id": "supervisor"})

    def create(self):
        action = self.action()
        self.authorize(action)
        self.supervisor.execute(action)
        self.supervisor._calls[action["action_id"]].thread.join(2)
        self.supervisor.reconcile(action["action_id"])
        return self.supervisor.inventory()["commands"][0]

    def test_agent_create_reuses_external_one_shot(self):
        command = self.create()
        self.assertTrue(command["create_confirmed"])
        self.assertEqual(self.supervisor.execute(self.action())["status"], "UNKNOWN")
        self.assertEqual(self.docker.dispatch_count("create"), 1)

    def test_other_run_lineage_cannot_be_host_authorized(self):
        action = self.action()
        action["root_id"] = "other-root"
        with self.assertRaisesRegex(ControlError, "RUN_BINDING_MISMATCH"):
            self.authorize(action)
        self.assertEqual(self.authority.status("command-root")["issued_count"], 0)

    def test_other_spec_cannot_change_worker_mode(self):
        action = self.action()
        action["arguments"]["spec"] = agent_spec("owned-command", IMAGE, str(self.workspace), "forged_report")
        with self.assertRaisesRegex(ControlError, "RUN_BINDING_MISMATCH"):
            self.authorize(action)

    def test_bridge_callback_mutation_is_rejected_at_boundary(self):
        original = self.bridge.executor
        self.bridge.executor = lambda action: {"changed": True}
        try:
            with self.assertRaisesRegex(ControlError, "CALLBACK_IMMUTABLE"):
                self.supervisor.inventory()
        finally:
            self.bridge.executor = original

    def test_bridge_public_configuration_mutation_is_rejected(self):
        self.bridge._configuration["actions"][0]["arguments"]["body"]["synthetic_marker"] = "changed"
        try:
            with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
                self.supervisor.inventory()
        finally:
            self.bridge._configuration["actions"] = [self.effect_action]

    def test_actual_gateway_route_config_cannot_change_behind_bridge_digest(self):
        with patch.object(self.bridge.gateway, "_configuration", return_value='{"route":"changed"}'):
            with self.assertRaisesRegex(ControlError, "EFFECT_GATEWAY_IMMUTABLE"):
                self.supervisor.inventory()

    def test_owned_observation_mandatory_before_state_initialization(self):
        self.supervisor.close()
        self.bridge.admission_observer_required = False
        with self.assertRaisesRegex(ControlError, "OWNED_OBSERVER_REQUIRED"):
            self.new_supervisor(create=False)
        self.bridge.admission_observer_required = True
        self.supervisor = self.new_supervisor(create=False)

    def test_fixed_agent_workspace_denies_injected_file(self):
        (self.workspace / "secret.txt").write_text("synthetic")
        action = self.action()
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["reason"], "AGENT_FIXED_WORKSPACE_MISMATCH")
        self.assertEqual(self.docker.dispatch_count("create"), 0)

    def test_owned_live_observation_binds_actual_running_container(self):
        self.create()
        self.docker.item["State"].update(Running=True, Paused=False, Pid=3001, StartedAt="2026-10-13T01:00:00Z")
        observation = self.supervisor.observe_proposal(self.effect_action)
        self.assertEqual(observation["container_id"], CONTAINER)
        self.assertTrue(observation["running"])
        self.assertEqual(observation["action_digest"], digest(self.effect_action))
        self.assertFalse(observation["execution_authorized"])
        body = {k: v for k, v in observation.items() if k != "observation_digest"}
        self.assertEqual(observation["observation_digest"], digest(body))

    def test_stopped_or_paused_process_cannot_propose_effect(self):
        self.create()
        for state in ({"Running": False, "Paused": False, "Pid": 0}, {"Running": True, "Paused": True, "Pid": 3001}):
            self.docker.item["State"].update(state)
            with self.assertRaisesRegex(ControlError, "NOT_RUNNING"):
                self.supervisor.observe_proposal(self.effect_action)

    def test_cleanup_closes_proposal_observation(self):
        self.create()
        self.supervisor.cleanup("owned-command")
        with self.assertRaisesRegex(ControlError, "CLOSED"):
            self.supervisor.observe_proposal(self.effect_action)

    def test_two_agent_receipts_have_distinct_domain_from_commands(self):
        self.create()
        cleanup = self.supervisor.cleanup("owned-command")
        receipt = cleanup["stages"][0]["receipt"]
        self.assertTrue(verify_agent_receipt(receipt, self.supervisor.pin()))
        from sdk.liminal_agent_control.external_command_protocol import verify_command_receipt
        self.assertFalse(verify_command_receipt(receipt, self.supervisor.pin()))

    def test_start_callback_waits_late_effect_after_attach_cli_reaped(self):
        command = self.create()
        start = self.action("START", command["stages"][0]["reservation_id"], CONTAINER)
        self.authorize(start)
        self.bridge.finished.clear()
        real_popen = subprocess.Popen
        def fake_popen(argv, **kwargs):
            self.assertEqual(argv, ["fake-docker", "start", "--attach", "--interactive", CONTAINER])
            self.docker.item["State"].update(Running=False, Paused=False, Pid=0, StartedAt="2026-10-13T01:00:00Z")
            return real_popen(["python3", "-c", "print('synthetic attach')"], **kwargs)
        with patch("sdk.liminal_agent_control.external_agent_supervisor.subprocess.Popen", side_effect=fake_popen):
            self.supervisor.execute(start)
            self.assertTrue(self.bridge.entered.wait(1))
            time.sleep(.05)
            state = self.supervisor._grant(start["action_id"])
            self.assertEqual(state["callback_phase"], "INFLIGHT")
            self.authority.stop("command-root")
            self.assertEqual(self.supervisor.cleanup("owned-command")["status"], "UNKNOWN")
            self.assertEqual(self.authority.status("command-root")["state"], "STOPPING")
            self.bridge.finished.set()
            self.supervisor._calls[start["action_id"]].thread.join(2)
            self.assertEqual(self.supervisor.cleanup("owned-command")["status"], "QUIESCENT")
        self.assertTrue(self.supervisor.inventory()["attach_processes"][0]["reaped"])


if __name__ == "__main__":
    unittest.main()
