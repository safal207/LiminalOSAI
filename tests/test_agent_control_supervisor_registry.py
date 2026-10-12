"""Durable recovery/race negatives. Fake Docker observations are not OS proof."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.runtime import DockerController, _broker_context, recover_workloads, run_fixture
from sdk.liminal_agent_control.supervisor_registry import RegistryError, SupervisorRegistry, ownership_labels


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.receiver = Receiver(self.path / "receiver.db", b"b" * 32, b"r" * 32)
        self.broker = Broker(self.path / "broker.db", self.receiver)
        self.registry = SupervisorRegistry(self.path / "supervisor.db")
        self.root_id = "root:recovery"
        self.receiver.create_root(self.root_id)
        self.receiver.bind_execution(self.root_id, "execution:recovery")

    def tearDown(self):
        self.directory.cleanup()

    def register(self, registry=None):
        registry = registry or self.registry
        return registry.register(session_id="liminal-control-" + "a" * 32, root_id=self.root_id,
                                 action_id="action:recovery", image_id="sha256:" + "b" * 64,
                                 plan_sha256="c" * 64, backend_identity_sha256="d" * 64,
                                 receiver_id=self.receiver.receiver_id, broker_context_sha256=_broker_context(self.broker))

    def test_durable_unfinished_slot_blocks_fresh_admission(self):
        with self.registry.lease():
            record = self.register()
        restarted = SupervisorRegistry(self.registry.path)
        self.assertEqual(restarted.unfinished(), [record])
        with restarted.lease(), self.assertRaisesRegex(RegistryError, "RECOVERY_REQUIRED"):
            self.register(restarted)
        result = run_fixture("honest", broker=self.broker, image="sha256:" + "b" * 64,
                             registry_path=self.registry.path)
        self.assertEqual(result["reason"], "RECOVERY_REQUIRED")
        self.assertFalse(result["registered_before_start"])
        self.assertEqual(self.receiver.records(), [])

    def test_exclusive_controller_lease_rejects_concurrent_admission_and_recovery(self):
        competitor = SupervisorRegistry(self.registry.path)
        with self.registry.lease():
            record = self.register()
            with self.assertRaisesRegex(RegistryError, "SUPERVISOR_BUSY"):
                with competitor.lease():
                    self.fail("second controller acquired a live lease")
            self.assertEqual(recover_workloads(self.registry.path, broker=self.broker)["status"], "BUSY")
            # Failed competitor must not invalidate the first controller's lease.
            self.registry.confirm_created(record, "e" * 64)
            self.registry.complete(record, {"verified": True, "zero_survivors": True})
        self.assertEqual(competitor.unfinished(), [])

    def test_process_crash_releases_lease_but_keeps_registration(self):
        program = """
import json, sys, time
from sdk.liminal_agent_control.supervisor_registry import SupervisorRegistry
r = SupervisorRegistry(sys.argv[1])
with r.lease():
    r.register(**json.loads(sys.argv[2]))
    print('registered', flush=True)
    time.sleep(30)
"""
        params = dict(session_id="liminal-control-" + "a" * 32, root_id=self.root_id,
                      action_id="action:recovery", image_id="sha256:" + "b" * 64, plan_sha256="c" * 64,
                      backend_identity_sha256="d" * 64, receiver_id=self.receiver.receiver_id,
                      broker_context_sha256=_broker_context(self.broker))
        child = subprocess.Popen([sys.executable, "-c", program, str(self.registry.path), json.dumps(params)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            import selectors
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(3), "child did not durably register")
                self.assertEqual(child.stdout.readline().strip(), "registered")
            with self.assertRaisesRegex(RegistryError, "SUPERVISOR_BUSY"):
                with self.registry.lease():
                    pass
            child.kill()
            child.wait(timeout=3)
            with self.registry.lease():
                self.assertEqual(len(self.registry.unfinished()), 1)
                with self.assertRaisesRegex(RegistryError, "RECOVERY_REQUIRED"):
                    self.register()
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()

    def test_incomplete_or_forged_completion_cannot_release_slot(self):
        with self.registry.lease():
            record = self.register()
            with self.assertRaisesRegex(RegistryError, "RECOVERY_INCOMPLETE"):
                self.registry.complete(record, {"verified": False, "zero_survivors": True})
            changed = {**record, "ownership_token": "someone-else"}
            with self.assertRaisesRegex(RegistryError, "REGISTRY_BINDING_MISMATCH"):
                self.registry.complete(changed, {"verified": True, "zero_survivors": True})
        self.assertEqual(len(self.registry.unfinished()), 1)

    def fake_docker(self, record, *, absent=False, wrong_owner=False, unavailable=False):
        state = {"exists": not absent, "paused": False, "commands": []}

        class OwnedDocker(DockerController):
            def command(self, args, **_kwargs):
                state["commands"].append(args)
                if args[0] == "inspect":
                    if unavailable:
                        return subprocess.CompletedProcess(args, 1, b"", b"Cannot connect to Docker daemon")
                    if not state["exists"]:
                        return subprocess.CompletedProcess(args, 1, b"", b"Error: No such object: owned-test")
                    labels = ownership_labels(record)
                    if wrong_owner:
                        labels["liminal.control.owner"] = "different-owner"
                    body = [{"Id": "e" * 64, "Image": record["image_id"], "Config": {"Labels": labels},
                             "State": {"Running": True, "Paused": state["paused"], "Pid": 123}}]
                    return subprocess.CompletedProcess(args, 0, json.dumps(body).encode(), b"")
                if args[0] == "top":
                    return subprocess.CompletedProcess(args, 0, b"UID PID PPID\n65534 123 1\n65534 124 123\n", b"")
                if args[0] == "pause":
                    state["paused"] = True
                elif args[:2] == ["rm", "--force"]:
                    state["exists"] = False
                else:
                    raise AssertionError(args)
                return subprocess.CompletedProcess(args, 0, b"", b"")
        return state, OwnedDocker

    def test_recovery_revokes_and_removes_only_bound_registered_workload(self):
        with self.registry.lease():
            record = self.register()
        state, docker = self.fake_docker(record)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                patch("sdk.liminal_agent_control.runtime.DockerController", docker):
            result = recover_workloads(self.registry.path, broker=self.broker)
        self.assertEqual(result["status"], "RECOVERED", result)
        self.assertFalse(state["exists"])
        self.assertEqual(self.registry.unfinished(), [])
        ack = result["recovered"][0]["containment"]["revocation_ack"]["receiver_ack"]
        self.assertTrue(self.receiver.verify_receipt(ack))
        self.assertEqual(ack["root_id"], record["root_id"])
        self.assertEqual(ack["epoch"], 2)
        inspections = [args[-1] for args in state["commands"] if args[0] == "inspect"]
        self.assertEqual(inspections[0], record["session_id"])
        self.assertEqual(set(inspections[1:]), {"e" * 64})
        self.assertEqual({args[-1] for args in state["commands"] if args[0] == "top"}, {"e" * 64})
        self.assertEqual({args[-1] for args in state["commands"] if args[0] in {"pause", "rm"}}, {"e" * 64})

    def test_absent_container_still_requires_authenticated_revocation(self):
        with self.registry.lease():
            record = self.register()
            self.registry.confirm_created(record, "e" * 64)
        state, docker = self.fake_docker(record, absent=True)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                patch("sdk.liminal_agent_control.runtime.DockerController", docker):
            result = recover_workloads(self.registry.path, broker=self.broker)
        self.assertEqual(result["status"], "RECOVERED", result)
        self.assertFalse(any(args[0] in {"pause", "rm"} for args in state["commands"]))
        self.assertEqual(self.receiver.snapshot(self.root_id)["epoch"], 2)

    def test_absence_without_confirmed_create_retains_slot_after_revocation(self):
        with self.registry.lease():
            record = self.register()
            self.registry.mark_create_pending(record)
            with self.assertRaisesRegex(RegistryError, "CREATE_OUTCOME_UNCONFIRMED"):
                self.registry.complete(record, {"verified": True, "zero_survivors": True})
        state, docker = self.fake_docker(record, absent=True)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                patch("sdk.liminal_agent_control.runtime.DockerController", docker):
            result = recover_workloads(self.registry.path, broker=self.broker)
        self.assertEqual(result["status"], "INCOMPLETE", result)
        self.assertFalse(result["admission_allowed"])
        containment = result["recovered"][0]["containment"]
        self.assertFalse(containment["zero_survivors"])
        self.assertFalse(containment["verified"])
        self.assertIn("CREATE_OUTCOME_UNCONFIRMED", containment["partial_failures"])
        self.assertTrue(self.receiver.verify_receipt(containment["revocation_ack"]["receiver_ack"]))
        self.assertEqual(len(self.registry.unfinished()), 1)

    @unittest.skipUnless(os.name == "posix", "bounded subprocess crash fixture requires POSIX")
    def test_orphan_create_after_supervisor_crash_cannot_release_slot(self):
        """Real child/CLI crash; fake Docker is an API-race test, not OS proof."""
        state, entered, release, cli_done = [self.path / name for name in
                                           ("fake-container.json", "create-entered", "create-release", "create-done")]
        fake_docker = self.path / "docker-fake"
        fake_docker.write_text("#!" + sys.executable + "\n" + '''
import json, os, sys, time
from pathlib import Path
state, entered, release, done = [Path(value) for value in ''' + repr([str(state), str(entered), str(release), str(cli_done)]) + ''']
args = sys.argv[1:]
if args[:2] == ['image', 'inspect']:
    print(args[-1]); sys.exit(0)
if args[0] == 'create':
    entered.write_text(str(os.getpid()))
    deadline = time.monotonic() + 8
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    if not release.exists():
        done.write_text('aborted'); sys.exit(1)
    labels = dict(args[i + 1].split('=', 1) for i, value in enumerate(args) if value == '--label')
    image = next(value for value in args if value.startswith('sha256:'))
    state.write_text(json.dumps({'Id': 'e' * 64, 'Image': image, 'Config': {'Labels': labels},
                                'State': {'Running': False, 'Paused': False, 'Pid': 0}}))
    done.write_text('created'); sys.exit(0)
if args[0] == 'inspect':
    if not state.exists():
        print('Error: No such object: ' + args[1], file=sys.stderr); sys.exit(1)
    print('[' + state.read_text() + ']'); sys.exit(0)
if args[:2] == ['rm', '--force']:
    state.unlink(missing_ok=True); sys.exit(0)
if args[0] == 'pause': sys.exit(0)
sys.exit(2)
''')
        fake_docker.chmod(0o700)
        program = '''
import sys
from pathlib import Path
from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.runtime import run_fixture
p = Path(sys.argv[1])
r = Receiver(p / 'receiver.db', b'b' * 32, b'r' * 32)
b = Broker(p / 'broker.db', r)
run_fixture('honest', broker=b, image='sha256:' + 'b' * 64,
            registry_path=p / 'orphan-registry.db', docker_binary=sys.argv[2])
'''
        child = subprocess.Popen([sys.executable, "-c", program, str(self.path), str(fake_docker)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        import time
        def wait_for(path, seconds=4):
            deadline = time.monotonic() + seconds
            while not path.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(path.exists(), "bounded fixture did not reach " + path.name)
        try:
            wait_for(entered)
            registry = SupervisorRegistry(self.path / "orphan-registry.db")
            record = registry.unfinished()[0]
            self.assertEqual(registry.launch_state(record)["phase"], "CREATE_PENDING")
            child.kill()
            child.wait(timeout=2)
            recovered = recover_workloads(registry.path, broker=self.broker, docker_binary=str(fake_docker))
            self.assertEqual(recovered["status"], "INCOMPLETE", recovered)
            self.assertFalse(recovered["admission_allowed"])
            self.assertFalse(recovered["recovered"][0]["containment"]["zero_survivors"])
            self.assertEqual(len(registry.unfinished()), 1)
            blocked = run_fixture("honest", broker=self.broker, image="sha256:" + "b" * 64,
                                  registry_path=registry.path, docker_binary=str(fake_docker))
            self.assertEqual(blocked["reason"], "RECOVERY_REQUIRED")
            release.touch()
            wait_for(cli_done)
            self.assertEqual(cli_done.read_text(), "created")
            self.assertTrue(state.exists(), "orphan create did not complete")
            recovered = recover_workloads(registry.path, broker=self.broker, docker_binary=str(fake_docker))
            self.assertEqual(recovered["status"], "RECOVERED", recovered)
            self.assertFalse(state.exists())
            self.assertEqual(registry.unfinished(), [])
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            # The owned fake CLI has a hard eight-second exit bound. Release it
            # and collect its exit marker; no PID-based resource reclamation.
            release.touch()
            if entered.exists():
                wait_for(cli_done, seconds=9)
            child.stdout.close()
            child.stderr.close()

    def test_wrong_container_owner_or_dead_observer_never_mutates_container(self):
        with self.registry.lease():
            record = self.register()
        for options in ({"wrong_owner": True}, {"unavailable": True}):
            with self.subTest(options=options):
                state, docker = self.fake_docker(record, **options)
                with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                        patch("sdk.liminal_agent_control.runtime.DockerController", docker):
                    result = recover_workloads(self.registry.path, broker=self.broker)
                self.assertEqual(result["status"], "INCOMPLETE", result)
                self.assertFalse(result["admission_allowed"])
                self.assertFalse(any(args[0] in {"pause", "rm"} for args in state["commands"]))
                self.assertEqual(len(self.registry.unfinished()), 1)
        self.assertEqual(self.receiver.snapshot(self.root_id)["epoch"], 1)

    def test_replacement_receiver_context_cannot_recover_old_slot(self):
        with self.registry.lease():
            self.register()
        replacement = Receiver(self.path / "replacement.db", b"b" * 32, b"r" * 32)
        broker = Broker(self.path / "broker.db", replacement)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"):
            result = recover_workloads(self.registry.path, broker=broker)
        self.assertEqual(result["reason"], "RECOVERY_CONTEXT_MISMATCH")
        self.assertEqual(len(self.registry.unfinished()), 1)

    def test_changed_keys_on_same_receiver_store_cannot_release_old_slot(self):
        with self.registry.lease():
            record = self.register()
        for broker_key, receipt_key in ((b"x" * 32, b"r" * 32), (b"b" * 32, b"y" * 32)):
            with self.subTest(changed_broker_key=broker_key != b"b" * 32):
                receiver = Receiver(self.receiver.db_path, broker_key, receipt_key)
                broker = Broker(self.broker.db_path, receiver)
                self.assertEqual(receiver.receiver_id, self.receiver.receiver_id)
                state, docker = self.fake_docker(record)
                with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                        patch("sdk.liminal_agent_control.runtime.DockerController", docker):
                    result = recover_workloads(self.registry.path, broker=broker)
                self.assertEqual(result["reason"], "RECOVERY_CONTEXT_MISMATCH", result)
                self.assertFalse(result["admission_allowed"])
                self.assertEqual(state["commands"], [])
                self.assertEqual(len(self.registry.unfinished()), 1)
        self.assertEqual(self.receiver.snapshot(self.root_id)["epoch"], 1)

    def test_baseline_unfenced_receiver_cannot_claim_recovered_authority(self):
        receiver = Receiver(self.path / "baseline.db", b"b" * 32, b"r" * 32, enforce_epoch=False)
        broker = Broker(self.path / "baseline-broker.db", receiver)
        with self.registry.lease():
            self.register()
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"):
            result = recover_workloads(self.registry.path, broker=broker)
        self.assertEqual(result["reason"], "RECOVERY_REQUIRES_GUARDED_RECEIVER")
        self.assertFalse(result["admission_allowed"])
        self.assertEqual(len(self.registry.unfinished()), 1)

    def test_mutations_target_validated_immutable_id_when_name_is_reused(self):
        original_id, reused_name = "f" * 64, "liminal-control-" + "a" * 32
        commands = []
        class NameReusedDocker(DockerController):
            def _inspect(self, session):
                # The name may be reused immediately after this observation.
                return {"Id": original_id}
            def command(self, args, **_kwargs):
                commands.append(args)
                return subprocess.CompletedProcess(args, 0, b"", b"")
        controller = NameReusedDocker()
        controller.freeze_session(reused_name)
        controller.terminate_session(reused_name)
        self.assertEqual(commands, [["pause", original_id], ["rm", "--force", original_id]])

    def test_renamed_owned_container_is_observed_and_recovered_by_pinned_id(self):
        with self.registry.lease():
            record = self.register()
            self.registry.confirm_created(record, "e" * 64)
        state, docker = self.fake_docker(record)
        class RenamedDocker(docker):
            def command(self, args, **kwargs):
                if args[0] in {"inspect", "top"} and args[-1] == record["session_id"]:
                    state["commands"].append(args)
                    return subprocess.CompletedProcess(args, 1, b"", b"Error: No such object: old-name")
                return super().command(args, **kwargs)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                patch("sdk.liminal_agent_control.runtime.DockerController", RenamedDocker):
            result = recover_workloads(self.registry.path, broker=self.broker)
        self.assertEqual(result["status"], "RECOVERED", result)
        self.assertFalse(state["exists"], "old name absence must not hide the live pinned object")
        self.assertEqual(self.registry.unfinished(), [])
        self.assertTrue(any(args[:2] == ["rm", "--force"] for args in state["commands"]))
        self.assertEqual({args[-1] for args in state["commands"]}, {"e" * 64})


if __name__ == "__main__":
    unittest.main()
