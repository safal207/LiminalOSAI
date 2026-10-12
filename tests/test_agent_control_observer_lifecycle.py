"""Managed observer cleanup and launch boundaries using owned fake Docker state.

Real SQLite authority/registry transitions are exercised. Docker observations are
mocked: these tests establish API/race safety contracts, not OS containment.
"""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control import observer_lifecycle as module
from sdk.liminal_agent_control.observer_auth import sign_attestation
from sdk.liminal_agent_control.observer_registry import ObserverRingRegistry, ObserverRegistryError, ownership_labels
from tests.test_agent_control_observer_process import fixtures


ROOT = "root:observer-lifecycle"
IMAGE = "sha256:" + "a" * 64


class FakeDocker:
    def __init__(self):
        self.documents = {}
        self.commands = []
        self.unavailable = False
        self.rm_failure = set()
        self.id_substitution = {}
        self.before_command = None

    def __call__(self, binary, arguments, timeout):
        self.commands.append(list(arguments))
        if self.before_command is not None:
            self.before_command(arguments)
        if self.unavailable:
            raise ControlError("OBSERVER_DOCKER_OBSERVATION_UNAVAILABLE")
        if arguments[:2] == ["container", "ls"]:
            selector = arguments[arguments.index("--filter") + 1]
            if selector.startswith("name=^/"):
                name = selector[len("name=^/"):-1]
                values = [identifier for identifier, document in self.documents.items()
                          if document["name"] == "/" + name]
            else:
                identifier = selector.removeprefix("id=")
                identifier = self.id_substitution.get(identifier, identifier)
                values = [identifier] if identifier in self.documents else []
            return ("\n".join(values) + ("\n" if values else "")).encode()
        if arguments[0] == "inspect":
            return json.dumps(self.documents[arguments[-1]]).encode()
        if arguments[:2] == ["rm", "--force"]:
            identifier = arguments[-1]
            if identifier in self.rm_failure:
                raise ControlError("OBSERVER_DOCKER_OBSERVATION_UNAVAILABLE")
            self.documents.pop(identifier, None)
            return b""
        raise AssertionError(arguments)

    def add(self, record, child, identifier):
        self.documents[identifier] = {"id": identifier, "name": "/" + child["container_name"],
                                     "image": record["image_id"],
                                     "labels": ownership_labels(record, child["observer_id"])}


class ObserverLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name).resolve()
        self.authority = SessionAuthority(self.path / "authority.db")
        self.create_root(ROOT)
        self.registry = ObserverRingRegistry(self.path / "observer-registry.db")
        self.observers = [{"observer_id": role + "-observer", "role": role,
                           "key_id": role + "-key", "container_name": "liminal-observer-" + char * 32}
                          for role, char in zip(module.ROLES, "abc")]
        self.sources = {role: self.path / role for role in module.ROLES}
        for directory in self.sources.values():
            directory.mkdir()
        self.docker = FakeDocker()

    def create_root(self, root_id, authority=None):
        (authority or self.authority).create_session(root_id, controller_id="host:controller",
            policy_digest="b" * 64, objective_digest="c" * 64, max_actions=10,
            max_executions=3, max_depth=1, max_stages=10, lifetime_seconds=60, lease_seconds=30)

    def registered(self, *, pending_index=None, never_created=False):
        with self.registry.controller_lease():
            record = self.registry.register_ring(root_id=ROOT, authority_db=self.authority.db_path.resolve(),
                image_id=IMAGE, observers=self.observers, lifetime_seconds=30)
            if not never_created:
                for index, child in enumerate(self.observers):
                    identifier = str(index + 1) * 64
                    self.registry.mark_create_pending(record, child["observer_id"])
                    self.docker.add(record, child, identifier)
                    if index != pending_index:
                        self.registry.confirm_created(record, child["observer_id"], identifier)
                        self.registry.confirm_enrolled(record, child["observer_id"],
                            {"observer_id": child["observer_id"], "role": child["role"],
                             "key_id": child["key_id"], "public_key": str(index + 4) * 64})
        return record

    def recover(self, record, authority=None):
        with patch.object(module, "_docker", side_effect=self.docker):
            return module.recover_observer_ring(self.registry, record,
                authority=authority or self.authority, docker_binary="owned-fake-docker",
                reason="OWNED_RECOVERY_TEST", timeout_seconds=.2)

    def test_recovery_closes_admission_first_and_removes_only_three_verified_ids(self):
        record = self.registered()
        foreign = "f" * 64
        self.docker.documents[foreign] = {"id": foreign, "name": "/unrelated-host-container",
                                         "image": IMAGE, "labels": {"owner": "another-user"}}
        self.docker.before_command = lambda _: self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")
        report = self.recover(record)
        self.assertEqual(report["status"], "RECOVERED", report)
        self.assertTrue(report["admission_closed"])
        self.assertTrue(report["observers_removed"])
        self.assertFalse(report["external_effect_completion_verified"])
        self.assertEqual(set(self.docker.documents), {foreign})
        removed = {command[-1] for command in self.docker.commands if command[:2] == ["rm", "--force"]}
        self.assertEqual(removed, {str(index) * 64 for index in (1, 2, 3)})
        self.assertEqual(self.registry.snapshot(record)["status"], "CLOSED")

    def test_renamed_owned_container_is_removed_using_pinned_id(self):
        record = self.registered()
        self.docker.documents["1" * 64]["name"] = "/host-renamed-observer"
        report = self.recover(record)
        self.assertEqual(report["status"], "RECOVERED", report)
        self.assertFalse(self.docker.documents)
        self.assertIn(["rm", "--force", "1" * 64], self.docker.commands)

    def test_reused_name_leaves_foreign_container_and_keeps_ring_incomplete(self):
        record = self.registered()
        self.docker.documents["1" * 64]["name"] = "/owned-renamed"
        foreign = "f" * 64
        self.docker.documents[foreign] = {"id": foreign, "name": "/" + self.observers[0]["container_name"],
                                         "image": IMAGE, "labels": {"liminal.observer.owner": "foreign"}}
        report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["observers_removed"])
        self.assertEqual(report["cleanup"][0]["reason"], "OBSERVER_CONTAINER_NAME_REUSED")
        self.assertIn(foreign, self.docker.documents)
        self.assertNotIn(["rm", "--force", foreign], self.docker.commands)
        self.assertNotIn("1" * 64, self.docker.documents)
        self.assertEqual(self.registry.snapshot(record)["status"], "CLOSING")

    def test_changed_ownership_label_is_not_removed(self):
        record = self.registered()
        self.docker.documents["1" * 64]["labels"]["liminal.observer.owner"] = "foreign"
        report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["cleanup"][0]["reason"], "OBSERVER_CONTAINER_OWNERSHIP_MISMATCH")
        self.assertEqual(set(self.docker.documents), {"1" * 64})
        self.assertNotIn(["rm", "--force", "1" * 64], self.docker.commands)

    def test_changed_image_is_not_removed(self):
        record = self.registered()
        self.docker.documents["1" * 64]["image"] = "sha256:" + "e" * 64
        report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["cleanup"][0]["reason"], "OBSERVER_CONTAINER_OWNERSHIP_MISMATCH")
        self.assertEqual(set(self.docker.documents), {"1" * 64})
        self.assertNotIn(["rm", "--force", "1" * 64], self.docker.commands)

    def test_daemon_observation_failure_never_becomes_absence(self):
        record = self.registered()
        self.docker.unavailable = True
        report = self.recover(record)
        self.assertTrue(report["admission_closed"])
        self.assertFalse(report["observers_removed"])
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertTrue(all(child["reason"] == "OBSERVER_DOCKER_OBSERVATION_UNAVAILABLE"
                            for child in report["cleanup"]))
        self.assertEqual(len(self.docker.documents), 3)
        self.assertFalse(any(command[0] == "rm" for command in self.docker.commands))

    def test_positive_pending_candidate_removed_but_create_uncertainty_retained(self):
        record = self.registered(pending_index=0)
        report = self.recover(record)
        self.assertFalse(self.docker.documents)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["observers_removed"])
        self.assertEqual(report["cleanup"][0]["reason"], "CREATE_OUTCOME_UNCONFIRMED")
        self.assertEqual(report["cleanup"][0]["observed_removed_id"], "1" * 64)
        self.assertFalse(report["cleanup"][0]["removed"])
        self.assertEqual(self.registry.snapshot(record)["children"][0]["phase"], "CREATE_PENDING")
        with self.registry.controller_lease(), self.assertRaisesRegex(ObserverRegistryError, "RECOVERY_REQUIRED"):
            self.registry.register_ring(root_id="root:fresh", authority_db=self.authority.db_path.resolve(),
                image_id=IMAGE, observers=self.observers, lifetime_seconds=30)

    def test_only_two_removals_cannot_report_complete_ring(self):
        record = self.registered()
        self.docker.rm_failure.add("3" * 64)
        report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["observers_removed"])
        self.assertEqual(sum(child["removed"] for child in report["cleanup"]), 2)
        self.assertEqual(set(self.docker.documents), {"3" * 64})
        self.assertEqual(self.registry.snapshot(record)["status"], "CLOSING")

    def test_stop_failure_never_inherits_admission_claim_from_container_removal(self):
        record = self.registered()
        with patch.object(self.authority, "stop", side_effect=ControlError("owned-stop-failure")):
            report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["admission_closed"])
        self.assertTrue(report["observers_removed"])
        self.assertEqual(self.authority.status(ROOT)["status"], "ACTIVE")
        self.assertFalse(self.docker.documents)

    def test_authority_existing_only_reopen_never_creates_missing_database(self):
        missing = self.path / "missing-authority.db"
        with self.assertRaises(sqlite3.Error):
            SessionAuthority(missing, create=False)
        self.assertFalse(missing.exists())
        reopened = SessionAuthority(self.authority.db_path, create=False)
        self.assertEqual(reopened.status(ROOT)["status"], "ACTIVE")

    def test_authority_deleted_after_startup_fails_status_and_stop_without_recreation(self):
        reopened = SessionAuthority(self.authority.db_path, create=False)
        self.authority.db_path.unlink()
        for authority in (self.authority, reopened):
            for operation in (lambda: authority.status(ROOT),
                              lambda: authority.stop(ROOT, reason="OWNED_LOST_DATABASE_TEST")):
                with self.assertRaises(sqlite3.Error):
                    operation()
                self.assertFalse(authority.db_path.exists())

    def test_forged_root_record_cannot_stop_either_root_or_touch_docker(self):
        record = self.registered()
        other_root = "root:other-owned-session"
        self.create_root(other_root)
        report = self.recover({**record, "root_id": other_root})
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["admission_closed"])
        self.assertEqual(self.authority.status(ROOT)["status"], "ACTIVE")
        self.assertEqual(self.authority.status(other_root)["status"], "ACTIVE")
        self.assertFalse(self.docker.commands)

    def test_authority_database_substitution_cannot_stop_wrong_database(self):
        record = self.registered()
        other = SessionAuthority(self.path / "other-authority.db")
        self.create_root(ROOT, other)
        report = self.recover(record, other)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertFalse(report["admission_closed"])
        self.assertEqual(self.authority.status(ROOT)["status"], "ACTIVE")
        self.assertEqual(other.status(ROOT)["status"], "ACTIVE")
        self.assertFalse(self.docker.commands)

    def test_id_filter_substitution_cannot_remove_unpinned_duplicate(self):
        record = self.registered()
        duplicate = "f" * 64
        self.docker.add(record, self.observers[0], duplicate)
        self.docker.documents[duplicate]["name"] = "/same-owner-unpinned-duplicate"
        self.docker.id_substitution["1" * 64] = duplicate
        report = self.recover(record)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertIn("1" * 64, self.docker.documents)
        self.assertIn(duplicate, self.docker.documents)
        self.assertNotIn(["rm", "--force", duplicate], self.docker.commands)

    def supervisor(self):
        with patch.object(module.shutil, "which", return_value=sys.executable):
            return module.ObserverRingSupervisor(self.authority, ROOT,
                registry_path=self.registry.path, image_id=IMAGE,
                source_directories=self.sources, lifetime_seconds=30, timeout_seconds=.2)

    def managed_fixture(self, supervisor, stack, *, readiness_failure=False, die_at_ready=False):
        events = []
        watchdog = SimpleNamespace(pid=9999, returncode=None, stdout=io.BytesIO())
        watchdog.poll = lambda: watchdog.returncode
        def wait(timeout):
            self.assertFalse(supervisor.registry.controller_present())
            report = module.recover_observer_ring(supervisor.registry, supervisor.record,
                authority=self.authority, docker_binary=supervisor.docker_binary,
                reason="MOCK_WATCHDOG_CLOSE", timeout_seconds=.2)
            supervisor.watchdog_output.write_text(json.dumps(report))
            watchdog.returncode = 0
            return 0
        watchdog.wait = wait
        def ready():
            events.append("ready")
            self.assertEqual([child["phase"] for child in supervisor.registry.snapshot(supervisor.record)["children"]],
                             ["REGISTERED"] * 3)
            self.assertFalse(self.docker.commands)
            if readiness_failure:
                raise ControlError("OBSERVER_WATCHDOG_READY_UNAVAILABLE")
            if die_at_ready:
                watchdog.returncode = 1
        stack.enter_context(patch.object(module.subprocess, "Popen", return_value=watchdog))
        stack.enter_context(patch.object(supervisor, "_ready", side_effect=ready))
        stack.enter_context(patch.object(module, "_docker", side_effect=self.docker))
        stack.enter_context(patch.object(module, "_kill_and_reap"))
        for index, service in enumerate(supervisor.services.values()):
            identifier = str(index + 1) * 64
            enrollment = {"observer_id": service.observer_id, "role": service.role,
                          "key_id": service.key_id, "public_key": str(index + 4) * 64}
            def command(arguments, service=service, identifier=identifier):
                self.assertEqual(events[0], "ready")
                snapshot = supervisor.registry.snapshot(supervisor.record)
                row = next(child for child in snapshot["children"] if child["observer_id"] == service.observer_id)
                self.assertEqual(row["phase"], "CREATE_PENDING")
                self.assertEqual(len(snapshot["children"]), 3)
                self.assertEqual(arguments[1], "create")
                labels = {arguments[i + 1].split("=", 1)[0]: arguments[i + 1].split("=", 1)[1]
                          for i, value in enumerate(arguments) if value == "--label"}
                self.assertEqual(labels, ownership_labels(supervisor.record, service.observer_id))
                self.docker.add(supervisor.record, row, identifier)
                events.append("create:" + service.role)
                return 0, identifier.encode(), None
            def spawn(arguments, service=service, identifier=identifier):
                row = next(child for child in supervisor.registry.snapshot(supervisor.record)["children"]
                           if child["observer_id"] == service.observer_id)
                self.assertEqual(row["phase"], "CREATED")
                self.assertEqual(row["container_id"], identifier)
                self.assertEqual(arguments[-1], identifier)
                events.append("attach:" + service.role)
                return SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO())
            def line(wire=None, service=service, enrollment=enrollment):
                self.assertIsNone(wire, "attestation must be denied before transport in negative scenarios")
                events.append("enroll:" + service.role)
                return json.dumps(enrollment).encode()
            stack.enter_context(patch.object(service, "_command", side_effect=command))
            stack.enter_context(patch.object(service, "_spawn", side_effect=spawn))
            stack.enter_context(patch.object(service, "_line", side_effect=line))
            stack.enter_context(patch("sdk.liminal_agent_control.observer_container._kill_and_reap"))
        return events, watchdog

    def test_managed_start_registers_all_children_waits_ready_and_pins_before_attach(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, _ = self.managed_fixture(supervisor, stack)
            supervisor.start()
            self.assertEqual(len(supervisor.enrollments), 3)
            self.assertEqual([child["phase"] for child in supervisor.registry.snapshot(supervisor.record)["children"]],
                             ["ENROLLED"] * 3)
            self.assertEqual(events, ["ready", "create:reality", "attach:reality", "enroll:reality",
                "create:continuity", "attach:continuity", "enroll:continuity",
                "create:projection", "attach:projection", "enroll:projection"])
            report = supervisor.close()
            self.assertEqual(report["status"], "RECOVERED", report)
            self.assertTrue(report["admission_closed"] and report["observers_removed"])
            self.assertFalse(self.docker.documents)
            self.assertFalse(supervisor.registry.controller_present())
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")
            self.assertEqual(supervisor.close(), report)
            with self.assertRaisesRegex(ControlError, "RESTART_FORBIDDEN"):
                supervisor.start()

    def test_readiness_failure_prevents_first_create_and_closes_root(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, _ = self.managed_fixture(supervisor, stack, readiness_failure=True)
            with self.assertRaisesRegex(ControlError, "READY_UNAVAILABLE"):
                supervisor.start()
            self.assertEqual(events, ["ready"])
            self.assertFalse(any(command[0] in ("create", "rm") for command in self.docker.commands))
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")
            self.assertFalse(supervisor.registry.controller_present())

    def test_watchdog_dies_before_first_launch_no_docker_create_occurs(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, _ = self.managed_fixture(supervisor, stack, die_at_ready=True)
            with self.assertRaisesRegex(ControlError, "WATCHDOG_UNAVAILABLE"):
                supervisor.start()
            self.assertEqual(events, ["ready"])
            self.assertFalse(any(command[0] in ("create", "rm") for command in self.docker.commands))
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")

    def test_dead_watchdog_blocks_attestation_before_transport_and_stops_ring(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, watchdog = self.managed_fixture(supervisor, stack)
            supervisor.start()
            before = events[:]
            watchdog.returncode = 1
            request, _ = fixtures()
            request["root_id"] = ROOT
            result = supervisor.services["reality"].attest(request)
            self.assertEqual(result["process"]["status"], "HOLD")
            self.assertIsNone(result["envelope"])
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(events, before)
            self.assertFalse(self.docker.documents)
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")

    def test_wrong_root_attestation_never_reaches_transport(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, _ = self.managed_fixture(supervisor, stack)
            supervisor.start()
            before = events[:]
            request, _ = fixtures()
            request["root_id"] = "root:unrelated"
            result = supervisor.services["reality"].attest(request)
            self.assertEqual(result["process"]["status"], "HOLD")
            self.assertIsNone(result["envelope"])
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(events, before)
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")

    def test_watchdog_death_during_valid_signed_response_discards_attestation(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        # Synthetic fixture key, unrelated to any deployed credential.
        private_key = b"x" * 32
        public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw().hex()
        supervisor = self.supervisor()
        reality = supervisor.services["reality"]
        with ExitStack() as stack:
            _, watchdog = self.managed_fixture(supervisor, stack)
            enrollment = {"observer_id": reality.observer_id, "role": reality.role,
                          "key_id": reality.key_id, "public_key": public_key}
            with patch.object(reality, "_line", return_value=json.dumps(enrollment).encode()):
                supervisor.start()
            request, _ = fixtures()
            request["root_id"] = ROOT
            envelope = sign_attestation(request, private_key=private_key, verdict="SUPPORT",
                evidence_digest="e" * 64, observed_at=100, valid_until=110)
            def reply(wire):
                self.assertEqual(json.loads(wire), request)
                watchdog.returncode = 1
                return json.dumps({"envelope": envelope, "status": "PASS", "reason": None,
                                   "execution_authorized": False}).encode()
            with patch.object(reality, "_line", side_effect=reply):
                result = reality.attest(request)
            self.assertEqual(result["process"]["status"], "HOLD")
            self.assertEqual(result["process"]["reason"], "OBSERVER_WATCHDOG_UNAVAILABLE")
            self.assertIsNone(result["envelope"])
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(self.docker.documents)
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")

    def assert_deadline_blocks_attestation(self, *, clock_kind):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, watchdog = self.managed_fixture(supervisor, stack)
            supervisor.start()
            before = events[:]
            request, _ = fixtures()
            request["root_id"] = ROOT
            self.assertIsNone(watchdog.poll(), "deadline rejection must not rely on dead watchdog")
            if clock_kind == "expired-wall":
                clock_patch = patch.object(module.time, "time", return_value=supervisor.record["deadline_at"])
            elif clock_kind == "wall-rollback":
                clock_patch = patch.object(module.time, "time", return_value=supervisor.record["registered_at"] - 1)
            else:
                clock_patch = patch.object(module.time, "monotonic", return_value=supervisor._monotonic_deadline + 1)
            with clock_patch:
                result = supervisor.services["reality"].attest(request)
            self.assertEqual(result["process"]["status"], "HOLD")
            self.assertIsNone(result["envelope"])
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(events, before, "expired ring must reject before sending challenge")
            self.assertFalse(self.docker.documents)
            self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")

    def test_expired_ring_denies_attestation_even_with_live_watchdog(self):
        self.assert_deadline_blocks_attestation(clock_kind="expired-wall")

    def test_authority_observation_crossing_deadline_is_rechecked_before_transport(self):
        supervisor = self.supervisor()
        with ExitStack() as stack:
            events, watchdog = self.managed_fixture(supervisor, stack)
            supervisor.start()
            initial = supervisor.record["registered_at"] + .01
            clock = [initial]
            def observation(*_):
                clock[0] = supervisor.record["deadline_at"]
            with patch.object(module.time, "time", side_effect=lambda: clock[0]), \
                    patch.object(module, "_active", side_effect=observation):
                with self.assertRaisesRegex(ControlError, "OBSERVER_RING_EXPIRED"):
                    supervisor._healthy()
            self.assertIsNone(watchdog.poll())
            self.assertEqual(len([e for e in events if e.startswith("create:")]), 3)
            supervisor.close()

    def test_wall_clock_rollback_denies_attestation_even_with_live_watchdog(self):
        self.assert_deadline_blocks_attestation(clock_kind="wall-rollback")

    def test_local_monotonic_deadline_denies_attestation_before_watchdog_poll(self):
        self.assert_deadline_blocks_attestation(clock_kind="monotonic")

    def assert_real_ready_failure(self, payload, expected_reason, *, already_dead=False):
        """Run the actual readiness parser against an owned Python stdout pipe."""
        supervisor = self.supervisor()
        children = []
        real_popen = subprocess.Popen
        def launch(_command, **_options):
            program = ("import sys,time\n" + ("sys.exit(0)\n" if already_dead else
                "sys.stdout.buffer.write(" + repr(payload) + ")\n"
                "sys.stdout.buffer.flush()\ntime.sleep(.35)\n"))
            child = real_popen([sys.executable, "-I", "-u", "-c", program],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, start_new_session=True)
            children.append(child)
            if already_dead:
                child.wait(timeout=2)
            return child
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(module.subprocess, "Popen", side_effect=launch))
                stack.enter_context(patch.object(module, "_docker", side_effect=self.docker))
                calls = [stack.enter_context(patch.object(service, "_command",
                    side_effect=AssertionError("first create occurred before valid watchdog readiness")))
                    for service in supervisor.services.values()]
                started = time.monotonic()
                with self.assertRaisesRegex(ControlError, expected_reason):
                    supervisor.start()
                self.assertLess(time.monotonic() - started, 3, "owned readiness failure was not bounded")
                self.assertTrue(all(call.call_count == 0 for call in calls))
                self.assertEqual(self.authority.status(ROOT)["status"], "STOPPED")
                self.assertFalse(supervisor.registry.controller_present())
                snapshot = supervisor.registry.snapshot(supervisor.record)
                self.assertTrue(all(child["absence_kind"] == "NEVER_CREATE_SUBMITTED"
                                    for child in snapshot["children"]))
                self.assertFalse(any(command[0] in ("create", "rm") for command in self.docker.commands))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=2)
                for stream in (child.stdout, child.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()

    def test_real_ready_malformed_json_denies_launch(self):
        self.assert_real_ready_failure(b"{not-json}\n", "OBSERVER_WATCHDOG_READY_INVALID")

    def test_real_ready_malformed_utf8_denies_launch(self):
        self.assert_real_ready_failure(b"\xff\n", "OBSERVER_WATCHDOG_READY_INVALID")

    def test_real_ready_oversized_stdout_denies_launch(self):
        self.assert_real_ready_failure(b"x" * (module.MAX_REPORT_BYTES + 1), "OBSERVER_WATCHDOG_READY_INVALID")

    def test_real_ready_silent_live_process_timeout_denies_launch(self):
        self.assert_real_ready_failure(b"", "OBSERVER_WATCHDOG_READY_UNAVAILABLE")

    def test_real_ready_dead_process_denies_launch(self):
        self.assert_real_ready_failure(b"", "OBSERVER_WATCHDOG_READY_UNAVAILABLE", already_dead=True)

    def test_ready_announcement_requires_exact_root_registry_ring_and_pid(self):
        supervisor = self.supervisor()
        with supervisor.registry.controller_lease():
            supervisor.record = supervisor.registry.register_ring(root_id=ROOT,
                authority_db=self.authority.db_path.resolve(), image_id=IMAGE, observers=self.observers,
                lifetime_seconds=30)
            expected = {"schema": "liminal.observer-watchdog-ready.v1", "root_id": ROOT,
                        "registry_id": supervisor.registry.registry_id,
                        "ring_id": supervisor.record["ring_id"], "pid": 1234}
            for field, value in (("root_id", "root:other"), ("ring_id", "other-ring"),
                                 ("registry_id", "f" * 32), ("pid", 9999)):
                with self.subTest(field=field):
                    read_fd, write_fd = os.pipe()
                    with os.fdopen(read_fd, "rb") as stream:
                        os.write(write_fd, json.dumps({**expected, field: value}).encode() + b"\n")
                        os.close(write_fd)
                        supervisor.watchdog = SimpleNamespace(stdout=stream, pid=1234, poll=lambda: None)
                        with self.assertRaisesRegex(ControlError, "READY_INVALID"):
                            supervisor._ready()
            self.assertEqual([child["phase"] for child in supervisor.registry.snapshot(supervisor.record)["children"]],
                             ["REGISTERED"] * 3)


if __name__ == "__main__":
    unittest.main()
