"""Real external authority plus fake Docker boundary unit regressions.

These tests do not claim Docker process containment. The separate required
runtime matrix exercises that boundary with actual owned Docker objects.
"""
from __future__ import annotations

import copy
import json
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_command_authority import ExternalCommandAuthorityStore
from sdk.liminal_agent_control.external_command_protocol import command_action, command_spec, verify_command_receipt
from sdk.liminal_agent_control.external_command_supervisor import ExternalCommandSupervisor
from sdk.liminal_agent_control.observer_auth import _crypto
from sdk.liminal_agent_control.runtime import DockerController, RuntimeBoundaryError
from sdk.liminal_agent_control.supervisor_registry import RegistryError

IMAGE = "sha256:" + "c" * 64
CONTAINER = "d" * 64
POLICY = "a" * 64
AUTHORITY_KEY = b"\x41" * 32
SUPERVISOR_KEY = b"\x42" * 32
REQUEST_KEY = b"command-receiver-request-key" * 2
ADMIN_KEY = b"command-controller-admin-key" * 2
RECEIPT_KEY = b"unused-command-receipt-key" * 2


class FakeDocker(DockerController):
    def __init__(self):
        super().__init__("fake-docker")
        self.calls = []
        self.item = None
        self.observation_unavailable = False
        self.start_without_witness = False
        self.kill_noop = False
        self.descendant_done = threading.Event()

    def command(self, args, *, timeout=10):
        args = list(args)
        self.calls.append(args)
        def answer(code=0, stdout=b"", stderr=b""):
            return subprocess.CompletedProcess(args, code, stdout, stderr)
        if args[:2] == ["image", "inspect"]:
            if "--format" in args:
                return answer(stdout=(IMAGE + "\n").encode())
            return answer(stdout=canonical_bytes([{"Id": IMAGE, "Config": {"Env": ["PATH=/usr/bin"]}}]))
        if args[0] == "create":
            index = args.index(IMAGE)
            labels = {args[i + 1].split("=", 1)[0]: args[i + 1].split("=", 1)[1]
                      for i, value in enumerate(args[:index]) if value == "--label"}
            mount = args[args.index("--mount") + 1]
            workspace = mount.split("src=", 1)[1].split(",", 1)[0]
            self.item = {"Id": CONTAINER, "Image": IMAGE,
                "Config": {"Labels": labels, "User": "65534:65534", "Entrypoint": ["python3"],
                           "Cmd": args[index + 1:], "WorkingDir": "/workspace", "Env": ["PATH=/usr/bin"]},
                "HostConfig": {"NetworkMode": "none", "LogConfig": {"Type": "none"}, "ReadonlyRootfs": True,
                    "Privileged": False, "PidMode": "", "IpcMode": "", "CapDrop": ["ALL"], "CapAdd": None,
                    "SecurityOpt": ["no-new-privileges:true"], "PidsLimit": 64, "Memory": 256 * 1024 * 1024,
                    "NanoCpus": 1000000000, "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}},
                "Mounts": [{"Source": workspace, "Destination": "/workspace", "RW": False}],
                "State": {"Running": False, "Paused": False, "Pid": 0,
                          "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0}}
            return answer(stdout=(CONTAINER + "\n").encode())
        if args[0] == "inspect":
            if self.observation_unavailable:
                return answer(1, stderr=b"Cannot connect to daemon")
            if self.item is None:
                return answer(1, stderr=b"Error: No such object: container")
            return answer(stdout=canonical_bytes([copy.deepcopy(self.item)]))
        if args[0] == "start":
            if self.start_without_witness:
                return answer(stdout=b"synthetic unattested start\n")
            self.item["State"].update(Running=True, Pid=3001, StartedAt="2026-10-13T01:00:00Z")
            if self.item["Config"]["Cmd"][-1] == "descendant":
                self.descendant_done.wait(3)
            self.item["State"].update(Running=False, Paused=False, Pid=0, FinishedAt="2026-10-13T01:00:01Z")
            return answer(stdout=b"LIMINAL_COMMAND_POSITIVE\n")
        if args[0] == "top":
            return answer(stdout=b"UID PID PPID CMD\n65534 3001 1001 root\n65534 3002 3001 child\n")
        if args[0] == "kill":
            if not self.kill_noop:
                self.item["State"].update(Running=False, Paused=False, Pid=0)
                self.descendant_done.set()
            return answer()
        if args[0] == "unpause":
            self.item["State"]["Paused"] = False
            return answer()
        if args[0] == "rm":
            self.item = None
            return answer()
        raise AssertionError(args)

    def dispatch_count(self, operation):
        return sum(args[0] == operation for args in self.calls)


class ExternalCommandSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.workspace = self.directory / "workspace"
        self.workspace.mkdir(mode=0o755)
        source = Path(__file__).resolve().parents[1] / "experiments/agent_control/external_command_fixture.py"
        shutil.copyfile(source, self.workspace / source.name)
        (self.workspace / source.name).chmod(0o444)
        private, _ = _crypto()
        supervisor_pin = {"supervisor_id": "supervisor", "key_id": "supervisor-key",
            "public_key": private.from_private_bytes(SUPERVISOR_KEY).public_key().public_bytes_raw().hex()}
        self.authority = ExternalCommandAuthorityStore(self.directory / "authority.sqlite", supervisor_pin=supervisor_pin,
            authority_id="controller", key_id="controller-key", private_key=AUTHORITY_KEY,
            receipt_key=RECEIPT_KEY, clock=lambda: 100.0)
        self.server = make_server(self.authority, ADMIN_KEY, REQUEST_KEY)
        self.server_thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.005), daemon=True)
        self.server_thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.docker = FakeDocker()
        self.supervisor = self.new_supervisor()
        self.releases = []
        self.addCleanup(self.shutdown)
        self.authority.create_root("root", "supervisor", POLICY, 32, 3600)
        self.authority.bind_execution("root", "worker")

    def new_supervisor(self, create=True):
        return ExternalCommandSupervisor(self.directory / "supervisor.sqlite", self.directory / "registry.sqlite",
            supervisor_id="supervisor", key_id="supervisor-key", private_key=SUPERVISOR_KEY,
            authority_client=HTTPExternalAuthorityClient(self.url, REQUEST_KEY, self.authority.pin()),
            controller=self.docker, create=create)

    def shutdown(self):
        for release in self.releases:
            release.set()
        self.docker.descendant_done.set()
        for call in self.supervisor._calls.values():
            call.thread.join(2)
        try:
            for command in self.supervisor.inventory()["commands"]:
                self.supervisor.cleanup(command["command_id"])
            self.supervisor.close()
        except ControlError:
            pass
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(2)

    def action(self, stage="CREATE", *, name=None, fixture="positive", parent=None, container=None):
        name = name or stage.lower()
        return command_action(action_id=name, attempt_id="attempt:" + name, root_id="root", execution_id="worker",
            epoch=1, stage=stage, spec=command_spec("command", IMAGE, str(self.workspace), fixture),
            parent_reservation_id=parent, container_id=container)

    def authorize(self, action):
        grant = {"action_digest": digest(action), "policy_version": POLICY,
                 "expires_at": 200.0, "receiver_id": "supervisor"}
        self.supervisor.authorize(action, grant)
        return grant

    def finish_callback(self, action):
        call = self.supervisor._calls.get(action["action_id"])
        if call:
            call.thread.join(2)
            self.assertFalse(call.thread.is_alive())

    def create(self, fixture="positive"):
        action = self.action(fixture=fixture)
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.finish_callback(action)
        self.supervisor.reconcile(action["action_id"])
        command = self.supervisor.inventory()["commands"][0]
        self.assertTrue(command["create_confirmed"])
        return action, command

    def start(self, fixture="positive", *, wait=True):
        create, command = self.create(fixture)
        action = self.action("START", fixture=fixture, parent=command["stages"][0]["reservation_id"], container=CONTAINER)
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        if wait:
            self.finish_callback(action)
        return create, action

    def hold(self, stage, *, after=False):
        reached, release = threading.Event(), threading.Event()
        self.releases.append(release)
        def hook(actual, action, *unused):
            if actual == stage:
                reached.set()
                release.wait(3)
        setattr(self.supervisor, "after_dispatch_hook" if after else "before_dispatch_hook", hook)
        return reached, release

    def test_exact_host_grant_required(self):
        action = self.action()
        result = self.supervisor.execute(action)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(self.docker.dispatch_count("create"), 0)
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_immutable_grant_preserves_numeric_canonical_bytes(self):
        action = self.action()
        grant = self.authorize(action)
        grant["expires_at"] = 200
        with self.assertRaisesRegex(ControlError, "GRANT_IMMUTABLE"):
            self.supervisor.authorize(action, grant)

    def test_repeated_execute_never_creates_again(self):
        action, _ = self.create()
        for _ in range(3):
            self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.assertEqual(self.docker.dispatch_count("create"), 1)
        self.assertEqual(self.authority.status("root")["pending_count"], 1)

    def test_two_admitted_stages_share_one_final_census(self):
        create, start = self.start()
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "QUIESCENT")
        self.assertEqual([r["status"] for r in cleanup["stages"]], ["QUIESCENT", "QUIESCENT"])
        inventory = self.supervisor.inventory()
        receipts = [s["receipt"] for s in inventory["commands"][0]["stages"]]
        self.assertEqual(receipts[0]["observed_at"], receipts[1]["observed_at"])
        self.assertEqual(receipts[0]["observation_digest"], receipts[1]["observation_digest"])
        self.assertTrue(all(verify_command_receipt(r, self.supervisor.pin()) for r in receipts))
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")
        self.assertEqual(self.docker.dispatch_count("start"), 1)
        self.assertFalse(cleanup["execution_authorized"])

    def test_stop_between_create_start_denies_launch(self):
        _, command = self.create()
        self.authority.stop("root")
        start = self.action("START", parent=command["stages"][0]["reservation_id"], container=CONTAINER)
        self.authorize(start)
        self.assertEqual(self.supervisor.execute(start)["status"], "DENIED")
        self.assertEqual(self.docker.dispatch_count("start"), 0)
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")

    def test_create_callback_pending_never_signs_absence(self):
        reached, release = self.hold("CREATE")
        action = self.action()
        self.authorize(action)
        self.supervisor.execute(action)
        self.assertTrue(reached.wait(1))
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")
        self.assertEqual(self.supervisor.cleanup("command")["status"], "UNKNOWN")
        self.assertIsNone(self.supervisor.inventory()["grants"][0]["receipt"])
        release.set()
        self.finish_callback(action)
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")
        self.assertEqual(self.docker.dispatch_count("create"), 1)

    def test_start_callback_delivery_hold_keeps_pending_after_kill(self):
        create, command = self.create()
        reached, release = self.hold("START", after=True)
        start = self.action("START", parent=command["stages"][0]["reservation_id"], container=CONTAINER)
        self.authorize(start)
        self.supervisor.execute(start)
        self.assertTrue(reached.wait(1))
        self.authority.stop("root")
        self.assertEqual(self.supervisor.cleanup("command")["status"], "UNKNOWN")
        self.assertEqual(self.authority.status("root")["state"], "STOPPING")
        self.assertTrue(all(s["receipt"] is None for s in self.supervisor.inventory()["grants"]))
        release.set()
        self.finish_callback(start)
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")

    def test_descendant_callback_finishes_only_after_owned_kill(self):
        _, start = self.start("descendant", wait=False)
        deadline = time.monotonic() + 1
        while not self.docker.item["State"]["Running"] and time.monotonic() < deadline:
            time.sleep(0.005)
        self.authority.stop("root")
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "QUIESCENT")
        self.assertEqual(self.docker.dispatch_count("kill"), 1)
        command = self.supervisor.inventory()["commands"][0]
        self.assertTrue(any(o["kind"] == "process_tree" and len(o["value"]["processes"]) == 2 for o in command["observations"]))

    def test_daemon_observation_outage_keeps_unknown(self):
        _, _ = self.start()
        self.authority.stop("root")
        self.docker.observation_unavailable = True
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "UNKNOWN")
        self.assertFalse(cleanup["process_quiescent"])
        self.assertEqual(self.authority.status("root")["state"], "STOPPING")

    def test_absence_without_durable_stopped_observation_is_not_quiescence(self):
        self.start()
        self.docker.item = None
        self.authority.stop("root")
        self.assertEqual(self.supervisor.cleanup("command")["reason"], "COMMAND_ABSENCE_IS_NOT_QUIESCENCE")
        self.assertTrue(all(state["receipt"] is None for state in self.supervisor.inventory()["grants"]))

    def test_paused_owned_object_does_not_count_as_stopped(self):
        self.start()
        self.docker.item["State"].update(Running=True, Paused=True, Pid=3001)
        self.docker.kill_noop = True
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "UNKNOWN")
        self.assertFalse(cleanup["process_quiescent"])
        self.assertEqual(self.docker.dispatch_count("rm"), 0)

    def test_parent_mutation_denied_before_admission(self):
        self.create()
        start = self.action("START", parent="wrong-parent", container=CONTAINER)
        self.authorize(start)
        self.assertEqual(self.supervisor.execute(start)["status"], "DENIED")
        self.assertEqual(self.authority.status("root")["issued_count"], 1)

    def test_cleanup_closes_start_admission_permanently(self):
        _, command = self.create()
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")
        start = self.action("START", parent=command["stages"][0]["reservation_id"], container=CONTAINER)
        self.authorize(start)
        self.assertEqual(self.supervisor.execute(start)["status"], "DENIED")
        self.assertEqual(self.docker.dispatch_count("start"), 0)
        self.assertTrue(self.supervisor.inventory()["commands"][0]["closing"])

    def test_lost_begin_response_is_not_replayed(self):
        action = self.action()
        self.authorize(action)
        self.supervisor.drop_begin_response = True
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.assertEqual(self.docker.dispatch_count("create"), 0)
        self.assertEqual(self.authority.stop("root")["status"], "STOP_PENDING")

    def test_lost_finish_keeps_known_quiescence_and_reconciles(self):
        create, _ = self.create()
        self.authority.stop("root")
        self.supervisor.drop_finish_response = True
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "QUIESCENT")
        self.assertEqual(cleanup["stages"][0]["status"], "UNKNOWN")
        self.assertTrue(cleanup["stages"][0]["process_quiescent"])
        self.assertEqual(self.supervisor.reconcile(create["action_id"])["status"], "QUIESCENT")
        self.assertEqual(self.docker.dispatch_count("create"), 1)

    def test_reopen_finished_journal_never_redispatches(self):
        action, _ = self.create()
        self.supervisor.close()
        self.supervisor = self.new_supervisor(create=False)
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.assertEqual(self.docker.dispatch_count("create"), 1)
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")

    def test_reopen_inflight_journal_cannot_infer_callback_completion(self):
        action, _ = self.create()
        state = self.supervisor._grant(action["action_id"])
        state.update(callback_phase="INFLIGHT", callback_result=None)
        self.supervisor._save_grant(state)
        self.supervisor.close()
        self.supervisor = self.new_supervisor(create=False)
        self.assertEqual(self.supervisor.cleanup("command")["reason"], "COMMAND_CALLBACKS_UNRESOLVED")
        self.assertEqual(self.docker.dispatch_count("rm"), 0)

    def test_mutated_fixture_denied_before_admission(self):
        fixture = self.workspace / "external_command_fixture.py"
        fixture.chmod(0o644)
        fixture.write_bytes(b"print('changed')\n")
        fixture.chmod(0o444)
        action = self.action()
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["reason"], "COMMAND_FIXED_WORKSPACE_MISMATCH")
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_writable_fixture_denied(self):
        (self.workspace / "external_command_fixture.py").chmod(0o644)
        action = self.action()
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["status"], "DENIED")

    def test_argv_entrypoint_and_environment_drift_block_start(self):
        _, command = self.create()
        start = self.action("START", parent=command["stages"][0]["reservation_id"], container=CONTAINER)
        self.authorize(start)
        for field, value in (("Entrypoint", ["sh"]), ("Cmd", ["-c", "true"]), ("Env", ["INJECTED=1"])):
            original = self.docker.item["Config"][field]
            self.docker.item["Config"][field] = value
            self.assertEqual(self.supervisor.execute(start)["status"], "DENIED")
            self.docker.item["Config"][field] = original
        self.assertEqual(self.docker.dispatch_count("start"), 0)

    def test_start_cli_success_without_owned_start_witness_cannot_settle(self):
        self.docker.start_without_witness = True
        self.start()
        self.authority.stop("root")
        self.assertEqual(self.supervisor.cleanup("command")["reason"], "COMMAND_START_OUTCOME_UNRESOLVED")
        self.assertEqual(self.authority.status("root")["state"], "STOPPING")

    def test_stopped_garbage_start_timestamp_cannot_settle(self):
        self.docker.start_without_witness = True
        self.start()
        self.authority.stop("root")
        for invalid in ("garbage", "2026-02-30T01:00:00Z", "2026-10-13T25:00:00Z",
                        "2026-10-13T01:00:00", "2026-10-13T01:00:00.1234567890Z",
                        "2026-10-13T01:00:00+01:99",
                        "0001-01-01T00:00:00.000000000Z"):
            with self.subTest(started_at=invalid):
                self.docker.item["State"]["StartedAt"] = invalid
                self.supervisor.reconcile("start")
                cleanup = self.supervisor.cleanup("command")
                self.assertEqual(cleanup["status"], "UNKNOWN")
                self.assertEqual(cleanup["reason"], "COMMAND_START_OUTCOME_UNRESOLVED")
                self.assertFalse(self.supervisor.inventory()["commands"][0]["start_observed"])
                self.assertTrue(all(s["receipt"] is None for s in self.supervisor.inventory()["grants"]))
                self.assertEqual(self.authority.status("root")["state"], "STOPPING")

    def test_stopped_valid_nanosecond_start_timestamp_is_positive_witness(self):
        self.docker.start_without_witness = True
        self.start()
        self.docker.item["State"]["StartedAt"] = "2026-10-13T01:00:00.123456789Z"
        self.authority.stop("root")
        self.assertEqual(self.supervisor.cleanup("command")["status"], "QUIESCENT")
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")

    def test_live_supervisor_lease_excludes_second_owner(self):
        with self.assertRaisesRegex(RegistryError, "SUPERVISOR_BUSY"):
            self.new_supervisor(create=False)

    def test_live_authority_client_configuration_cannot_change(self):
        self.supervisor.authority_client._request_key = b"another-command-request-key" * 2
        with self.assertRaisesRegex(ControlError, "CONFIGURATION_IMMUTABLE"):
            self.supervisor.inventory()
        self.supervisor.authority_client._request_key = REQUEST_KEY

    def test_extra_workspace_content_cannot_widen_fixed_command(self):
        (self.workspace / "injected.py").write_text("print('unapproved')")
        action = self.action()
        self.authorize(action)
        self.assertEqual(self.supervisor.execute(action)["status"], "DENIED")
        self.assertEqual(self.authority.status("root")["issued_count"], 0)

    def test_interrupted_two_database_completion_recovers_exact_closed_registry(self):
        self.create()
        self.authority.stop("root")
        original = self.supervisor._save_command
        def interrupted(command):
            if command["cleanup_complete"]:
                raise ControlError("COMMAND_SAVE_COMPLETION_UNAVAILABLE")
            return original(command)
        self.supervisor._save_command = interrupted
        first = self.supervisor.cleanup("command")
        self.assertEqual(first["status"], "UNKNOWN")
        self.assertEqual(self.supervisor.registry.unfinished(), [])
        self.assertEqual(self.authority.status("root")["state"], "STOPPING")
        self.supervisor._save_command = original
        self.supervisor.close()
        self.supervisor = self.new_supervisor(create=False)
        recovered = self.supervisor.cleanup("command")
        self.assertEqual(recovered["status"], "QUIESCENT")
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")
        self.assertEqual(self.docker.dispatch_count("create"), 1)
        self.assertEqual(self.docker.dispatch_count("rm"), 1)

    def test_live_registry_identity_drift_blocks_boundary(self):
        with self.supervisor.registry._connect() as db:
            db.execute("UPDATE supervisor_meta SET value='replacement' WHERE key='registry_id'")
        with self.assertRaisesRegex(ControlError, "REGISTRY_IDENTITY_CHANGED"):
            self.supervisor.inventory()
        with self.supervisor.registry._connect() as db:
            db.execute("UPDATE supervisor_meta SET value=? WHERE key='registry_id'", (self.supervisor.registry.registry_id,))

    def test_reconcile_lost_begin_recovers_identity_without_dispatch(self):
        action = self.action()
        self.authorize(action)
        self.supervisor.drop_begin_response = True
        self.supervisor.execute(action)
        self.assertEqual(self.supervisor.reconcile(action["action_id"])["status"], "UNKNOWN")
        state = self.supervisor.inventory()["grants"][0]
        self.assertIsNotNone(state["reservation_id"])
        self.assertEqual(state["callback_phase"], "NOT_DISPATCHED")
        self.assertEqual(self.docker.dispatch_count("create"), 0)
        self.assertEqual(self.supervisor.execute(action)["status"], "UNKNOWN")
        self.assertEqual(self.docker.dispatch_count("create"), 0)

    def test_closed_registry_completion_with_wrong_callbacks_cannot_release_permit(self):
        self.create()
        self.authority.stop("root")
        original = self.supervisor._save_command
        def interrupted(command):
            if command["cleanup_complete"]:
                raise ControlError("COMMAND_SAVE_COMPLETION_UNAVAILABLE")
            original(command)
        self.supervisor._save_command = interrupted
        self.supervisor.cleanup("command")
        self.supervisor._save_command = original
        with self.supervisor.registry._connect() as db:
            row = db.execute("SELECT session_id,completion_json FROM workloads").fetchone()
            completion = json.loads(row["completion_json"])
            completion["evidence"]["callbacks_digest"] = "0" * 64
            db.execute("UPDATE workloads SET completion_json=? WHERE session_id=?",
                (canonical_bytes(completion).decode(), row["session_id"]))
        cleanup = self.supervisor.cleanup("command")
        self.assertEqual(cleanup["status"], "UNKNOWN")
        self.assertEqual(cleanup["reason"], "COMMAND_REGISTRY_COMPLETION_BINDING_MISMATCH")
        self.assertEqual(self.authority.status("root")["state"], "STOPPING")


if __name__ == "__main__":
    unittest.main()
