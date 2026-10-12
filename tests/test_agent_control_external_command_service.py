"""Real child-process command-service startup and credential-role boundaries.

These tests deliberately submit no approved Docker operation. They verify
processes, HTTP routes and denial before admission; they do not establish any
Docker execution, process containment or positive command-runtime result.
"""
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient
from sdk.liminal_agent_control.external_command_demo import _FixtureClient
from sdk.liminal_agent_control.external_command_protocol import COMMAND_PROFILE, command_action, command_spec
from sdk.liminal_agent_control.external_stop_demo import _Child
from sdk.liminal_agent_control.observer_auth import _crypto


class ExternalCommandServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.children = []
        self.addCleanup(self._reap_children)
        self.keys = {
            "authority_signer": b"a" * 32, "receipt": b"r" * 32,
            "authority_admin": b"o" * 32, "authority_receiver": b"q" * 32,
            "supervisor_signer": b"s" * 32, "fixture_admin": b"h" * 32,
            "fixture_worker": b"w" * 32,
        }
        self.key_files = {}
        for name, value in self.keys.items():
            path = self.directory / (name + ".key")
            path.write_bytes(value)
            path.chmod(0o600)
            self.key_files[name] = path
        private, _ = _crypto()
        self.supervisor_pin = {"supervisor_id": "supervisor", "key_id": "supervisor-key",
            "public_key": private.from_private_bytes(self.keys["supervisor_signer"]).public_key().public_bytes_raw().hex()}
        self.supervisor_pin_file = self.directory / "supervisor-pin.json"
        self.supervisor_pin_file.write_bytes(canonical_bytes(self.supervisor_pin))
        self.policy = "b" * 64
        self.spec = command_spec("command", "sha256:" + "f" * 64, str(self.directory / "workspace"))
        self.action = command_action(action_id="create", attempt_id="create-attempt", root_id="root",
            execution_id="worker", epoch=1, stage="CREATE", spec=self.spec)
        self.grant = {"action_digest": digest(self.action), "policy_version": self.policy,
                      "expires_at": time.time() + 120, "receiver_id": "supervisor"}

    def _reap_children(self):
        for child in reversed(self.children):
            result = child.stop()
            self.assertTrue(result["reaped"], "owned service child was not reaped")
            self.assertIsNotNone(result["exit_code"])
        self.children.clear()

    def _authority_arguments(self, database, *, include_profile=True, include_pin=True):
        values = ["--db", str(database), "--authority-id", "authority", "--key-id", "authority-key",
            "--signing-key-file", str(self.key_files["authority_signer"]),
            "--receipt-key-file", str(self.key_files["receipt"]),
            "--operator-key-file", str(self.key_files["authority_admin"]),
            "--receiver-key-file", str(self.key_files["authority_receiver"]), "--initialize"]
        if include_profile:
            values += ["--profile", COMMAND_PROFILE]
        if include_pin:
            values += ["--supervisor-pin-file", str(self.supervisor_pin_file)]
        return values

    def _start(self, module, arguments):
        child = _Child(module, arguments)
        self.children.append(child)
        startup = child.start()
        self.assertIsNone(child.process.poll())
        return child, startup

    def _start_surfaces(self):
        self.authority_child, authority_startup = self._start("sdk.liminal_agent_control.external_authority_service",
            self._authority_arguments(self.directory / "authority.sqlite"))
        self.authority_pin = authority_startup["pin"]
        authority_pin_file = self.directory / "authority-pin.json"
        authority_pin_file.write_bytes(canonical_bytes(self.authority_pin))
        self.authority_admin = HTTPExternalAuthorityClient(authority_startup["url"], self.keys["authority_admin"],
            self.authority_pin, role="admin")
        self.authority_receiver = HTTPExternalAuthorityClient(authority_startup["url"], self.keys["authority_receiver"],
            self.authority_pin, role="receiver")
        self.authority_admin.create_root("root", "supervisor", self.policy, 2, 180)
        self.authority_admin.bind_execution("root", "worker")
        supervisor_arguments = ["--supervisor-service", "--db", str(self.directory / "supervisor.sqlite"),
            "--registry", str(self.directory / "registry.sqlite"), "--supervisor-id", "supervisor",
            "--key-id", "supervisor-key", "--private-key-file", str(self.key_files["supervisor_signer"]),
            "--authority-url", authority_startup["url"], "--authority-request-key-file",
            str(self.key_files["authority_receiver"]), "--authority-pin-file", str(authority_pin_file),
            "--operator-key-file", str(self.key_files["fixture_admin"]), "--worker-key-file",
            str(self.key_files["fixture_worker"]), "--docker-binary", str(self.directory / "never-invoke-docker"),
            "--initialize"]
        self.supervisor_child, self.supervisor_startup = self._start("sdk.liminal_agent_control.external_command_demo",
            supervisor_arguments)
        self.dispatcher_child, self.dispatcher_startup = self._start("sdk.liminal_agent_control.external_command_demo",
            ["--dispatcher-service", "--db", str(self.directory / "dispatcher.sqlite"), "--supervisor-url",
             self.supervisor_startup["url"], "--operator-key-file", str(self.key_files["fixture_admin"]),
             "--worker-key-file", str(self.key_files["fixture_worker"])])
        self.supervisor_admin = _FixtureClient(self.supervisor_startup["url"], self.keys["fixture_admin"], "admin")
        self.supervisor_worker = _FixtureClient(self.supervisor_startup["url"], self.keys["fixture_worker"], "worker")
        self.dispatcher_admin = _FixtureClient(self.dispatcher_startup["url"], self.keys["fixture_admin"], "admin")
        self.dispatcher_worker = _FixtureClient(self.dispatcher_startup["url"], self.keys["fixture_worker"], "worker")
        return authority_startup

    def _assert_no_dispatch(self, *, expected_grants=0):
        inventory = self.supervisor_admin.call("inventory")
        self.assertEqual(inventory["profile"], COMMAND_PROFILE)
        self.assertEqual(len(inventory["grants"]), expected_grants)
        self.assertEqual(inventory["commands"], [])
        self.assertEqual(inventory["unfinished_registry"], [])
        self.assertEqual(inventory["docker_calls"], [])
        self.assertEqual(inventory["authority_evidence"], [])
        self.assertFalse(inventory["execution_authorized"])
        state = self.authority_admin.status("root")
        self.assertEqual((state["issued_count"], state["pending_count"]), (0, 0))
        return inventory

    def test_command_authority_cli_requires_profile_and_supervisor_pin_together(self):
        root = Path(__file__).resolve().parents[1]
        for index, options in enumerate(({"include_profile": True, "include_pin": False},
                                         {"include_profile": False, "include_pin": True})):
            with self.subTest(options=options):
                result = subprocess.run([sys.executable, "-m", "sdk.liminal_agent_control.external_authority_service",
                    *self._authority_arguments(self.directory / ("invalid-" + str(index) + ".sqlite"), **options)],
                    cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                    check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
        self._start_surfaces()
        self._assert_no_dispatch()

    def test_real_service_startup_pins_distinct_processes_and_all_children_are_reaped(self):
        self._start_surfaces()
        self.assertEqual(self.supervisor_startup["role"], "owned_workload_supervisor")
        self.assertEqual(self.supervisor_startup["pin"], self.supervisor_pin)
        self.assertEqual(self.dispatcher_startup["role"], "proposal_dispatcher")
        self.assertNotEqual(self.authority_pin["public_key"], self.supervisor_pin["public_key"])
        self.assertEqual(len({child.pid for child in self.children}), 3)
        self._assert_no_dispatch()
        self._reap_children()
        self.assertEqual(self.children, [])

    def test_worker_routes_cannot_authorize_cleanup_inventory_or_set_faults(self):
        self._start_surfaces()
        for client in (self.supervisor_worker, self.dispatcher_worker):
            for operation, payload in (("authorize", {"action": self.action, "grant": self.grant}),
                                       ("cleanup", {"command_id": "command"}), ("inventory", {}),
                                       ("faults", {"observation_unavailable": True})):
                with self.subTest(url=client.url, operation=operation):
                    result = client.call(operation, **payload)
                    self.assertEqual((result["status"], result["reason"]), ("ERROR", "FIXTURE_OPERATION_DENIED"))
                    self.assertFalse(result["execution_authorized"])
        self._assert_no_dispatch()

    def test_cross_role_keys_are_rejected_on_fixture_and_authority_services(self):
        startup = self._start_surfaces()
        for url in (self.supervisor_startup["url"], self.dispatcher_startup["url"]):
            for role, key, operation in (("admin", self.keys["fixture_worker"], "inventory"),
                                         ("worker", self.keys["fixture_admin"], "execute")):
                with self.subTest(url=url, role=role):
                    result = _FixtureClient(url, key, role).call(operation, action=self.action)
                    self.assertEqual((result["status"], result["reason"]), ("ERROR", "FIXTURE_ROLE_DENIED"))
        wrong_admin = HTTPExternalAuthorityClient(startup["url"], self.keys["authority_receiver"],
                                                 self.authority_pin, role="admin")
        wrong_worker = HTTPExternalAuthorityClient(startup["url"], self.keys["authority_admin"],
                                                  self.authority_pin, role="receiver")
        with self.assertRaises(ControlError):
            wrong_admin.stop("root")
        with self.assertRaises(ControlError):
            wrong_worker.begin(self.action, self.grant)
        self.assertEqual(self.authority_admin.status("root")["state"], "ACTIVE")
        self._assert_no_dispatch()

    def test_forged_grant_and_malformed_unregistered_proposals_never_reach_admission(self):
        self._start_surfaces()
        for client in (self.supervisor_worker, self.dispatcher_worker):
            with self.subTest(url=client.url, proposal="forged-grant"):
                result = client.call("execute", action=self.action, grant=self.grant, signature="0" * 128)
                expected = (("ERROR", "DISPATCHER_PACKET_INVALID") if client is self.dispatcher_worker
                            else ("DENIED", "COMMAND_EXACT_HOST_GRANT_REQUIRED"))
                self.assertEqual((result["status"], result["reason"]), expected)
                if client is self.supervisor_worker:
                    self.assertIsNone(result["reservation_id"])
                self.assertFalse(result["execution_authorized"])
            malformed = {**self.action, "target": "records"}
            with self.subTest(url=client.url, proposal="wrong-profile"):
                result = client.call("execute", action=malformed)
                self.assertEqual(result["status"], "ERROR")
                self.assertFalse(result["execution_authorized"])
        cache = self.dispatcher_admin.call("inventory")
        self.assertEqual(cache["rows"], [], "rejected extra-field or malformed proposals entered the cache")
        self._assert_no_dispatch()

    def test_dispatcher_capacity_denies_new_proposals_and_preserves_existing_observation_routes(self):
        self._start_surfaces()
        # Trusted test-harness setup fills the non-authorizing cache directly.
        # No HTTP execute, grant, authority permit or Docker call creates rows.
        cached = []
        for index in range(1024):
            action = {**self.action, "action_id": "cached:" + str(index), "attempt_id": "cached-attempt:" + str(index)}
            cached.append((action["action_id"], canonical_bytes(action).decode(), None))
        database_path = self.directory / "dispatcher.sqlite"
        with sqlite3.connect(database_path) as database:
            database.executemany("INSERT INTO proposals VALUES (?,?,?)", cached)
        result = self.dispatcher_worker.call("execute", action=self.action)
        self.assertEqual((result["status"], result["reason"]), ("ERROR", "DISPATCHER_PROPOSAL_CAPACITY"))
        self.assertFalse(result["execution_authorized"])
        existing_action = json.loads(cached[0][1])
        changed = {**existing_action, "attempt_id": "changed-existing-attempt"}
        result = self.dispatcher_worker.call("execute", action=changed)
        self.assertEqual((result["status"], result["reason"]), ("ERROR", "DISPATCHER_PROPOSAL_IMMUTABLE"))
        # An existing exact proposal may still reach the supervisor. It remains
        # unapproved and cannot dispatch, even though capacity is exhausted.
        observed = self.dispatcher_worker.call("execute", action=existing_action)
        self.assertEqual((observed["status"], observed["reason"]), ("DENIED", "COMMAND_EXACT_HOST_GRANT_REQUIRED"))
        reconciled = self.dispatcher_worker.call("reconcile", action_id=existing_action["action_id"])
        self.assertEqual((reconciled["status"], reconciled["reason"]), ("UNKNOWN", "COMMAND_NOT_OBSERVED"))
        self.assertEqual(reconciled["action_id"], existing_action["action_id"])
        self.assertFalse(reconciled["execution_authorized"])
        with sqlite3.connect(database_path) as database:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM proposals").fetchone()[0], 1024)
            self.assertIsNone(database.execute("SELECT action_id FROM proposals WHERE action_id=?",
                                              (self.action["action_id"],)).fetchone())
            self.assertEqual(database.execute("SELECT action_json FROM proposals WHERE action_id=?",
                                             (existing_action["action_id"],)).fetchone()[0], cached[0][1])
        self._assert_no_dispatch()

    def test_dispatcher_cannot_authorize_and_changed_approved_proposal_is_denied(self):
        self._start_surfaces()
        result = self.dispatcher_admin.call("authorize", action=self.action, grant=self.grant)
        self.assertEqual((result["status"], result["reason"]), ("ERROR", "DISPATCHER_CANNOT_AUTHORIZE"))
        malformed = copy.deepcopy(self.action)
        malformed["arguments"]["spec"]["argv"] = ["-c", "print('unapproved')"]
        result = self.supervisor_admin.call("authorize", action=malformed,
            grant={**self.grant, "action_digest": digest(malformed)})
        self.assertEqual((result["status"], result["reason"]), ("ERROR", "COMMAND_SPEC_BINDING_MISMATCH"))
        self._assert_no_dispatch()
        authorized = self.supervisor_admin.call("authorize", action=self.action, grant=self.grant)
        self.assertEqual(authorized["status"], "AUTHORIZED")
        changed = {**self.action, "attempt_id": "unapproved-attempt"}
        result = self.dispatcher_worker.call("execute", action=changed)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "COMMAND_EXACT_HOST_GRANT_REQUIRED"))
        inventory = self._assert_no_dispatch(expected_grants=1)
        stored = inventory["grants"][0]
        self.assertEqual(stored["action"], self.action)
        self.assertIsNone(stored["reservation_id"])
        self.assertEqual(stored["callback_phase"], "NOT_DISPATCHED")


if __name__ == "__main__":
    unittest.main()
