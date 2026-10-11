"""Durable recovery/race negatives. Fake Docker observations are not OS proof."""
import json
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
        self.assertEqual({args[-1] for args in state["commands"] if args[0] in {"inspect", "top"}}, {record["session_id"]})
        self.assertEqual({args[-1] for args in state["commands"] if args[0] in {"pause", "rm"}}, {"e" * 64})

    def test_absent_container_still_requires_authenticated_revocation(self):
        with self.registry.lease():
            record = self.register()
        state, docker = self.fake_docker(record, absent=True)
        with patch("sdk.liminal_agent_control.runtime.shutil.which", return_value="docker"), \
                patch("sdk.liminal_agent_control.runtime.DockerController", docker):
            result = recover_workloads(self.registry.path, broker=self.broker)
        self.assertEqual(result["status"], "RECOVERED", result)
        self.assertFalse(any(args[0] in {"pause", "rm"} for args in state["commands"]))
        self.assertEqual(self.receiver.snapshot(self.root_id)["epoch"], 2)

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


if __name__ == "__main__":
    unittest.main()
