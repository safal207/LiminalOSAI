"""Owned subprocess crash/lease tests; Docker cleanup requires a pinned image."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.authority import connect
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.brakes_watchdog import main, run_watchdog
from sdk.liminal_agent_control.runtime import DockerController, contain_workload, recover_workloads
from sdk.liminal_agent_control.supervisor_registry import SupervisorRegistry
from sdk.liminal_process_tree import ProcessTreeSupervisor


PROJECT = Path(__file__).parents[1]
POLICY = "a" * 64
ROOT = "root:watchdog"
CONTROLLER_PROGRAM = r"""
from pathlib import Path
import json, sys, threading, time
from sdk.liminal_agent_control.brakes_store import SessionAuthority
path = Path(sys.argv[1])
authority = SessionAuthority(path / 'receiver.db')
state = authority.status('root:watchdog')
def heartbeat():
    global state
    while True:
        state = authority.renew('root:watchdog', controller_id='host:controller',
            expected_epoch=state['epoch'], expected_revision=state['lease_revision'])
        time.sleep(0.1)
threading.Thread(target=heartbeat, daemon=True).start()
print('ready', flush=True)
if len(sys.argv) > 2:
    from sdk.liminal_agent_control import Broker, Receiver
    from sdk.liminal_agent_control.runtime import run_fixture
    receiver = Receiver(path / 'receiver.db', b'b' * 32, b'r' * 32, admission_controller=authority)
    broker = Broker(path / 'broker.db', receiver)
    action = json.loads((path / 'action.json').read_text())
    print(json.dumps(run_fixture('descendant_timeout', broker=broker, image=sys.argv[2],
        timeout_seconds=120, action=action, registry_path=path / 'registry.db')), flush=True)
else:
    time.sleep(60)
"""


def action():
    return {"action_id": "action:watchdog", "attempt_id": "attempt:watchdog", "root_id": ROOT,
            "execution_id": "execution:watchdog", "epoch": 1, "target": "records",
            "arguments": {"value": "owned useful action"}}


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.authority = SessionAuthority(self.path / "receiver.db")
        self.authority.create_session(ROOT, controller_id="host:controller", policy_digest=POLICY,
            objective_digest="b" * 64, max_actions=10, max_executions=3, max_depth=1,
            max_stages=10, lifetime_seconds=60, lease_seconds=2)
        self.authority.bind_execution(ROOT, "execution:watchdog")
        self.receiver = Receiver(self.path / "receiver.db", b"b" * 32, b"r" * 32,
                                 admission_controller=self.authority)
        self.broker = Broker(self.path / "broker.db", self.receiver)
        self.broker.authorize(action(), policy_version=POLICY)

    def tearDown(self):
        self.directory.cleanup()

    def launch_controller(self, image=None):
        args = [sys.executable, "-c", CONTROLLER_PROGRAM, str(self.path)]
        if image is not None:
            (self.path / "action.json").write_text(json.dumps(action()))
            args.append(image)
        child = subprocess.Popen(args, cwd=PROJECT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.addCleanup(self.cleanup_process, child)
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(ready.select(5), "controller did not start")
            self.assertEqual(child.stdout.readline().strip(), "ready")
        return child

    @staticmethod
    def cleanup_process(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    def launch_watchdog(self, *extra):
        child = subprocess.Popen([sys.executable, "-m", "sdk.liminal_agent_control.brakes_watchdog",
            "--authority-db", str(self.path / "receiver.db"), "--root-id", ROOT,
            "--poll-interval", "0.02", "--max-wait", "20",
            "--output", str(self.path / "watchdog.json"), *extra], cwd=PROJECT,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        self.addCleanup(self.cleanup_process, child)
        return child

    def test_real_controller_sigkill_leaves_independent_watchdog_to_expire_authority(self):
        controller = self.launch_controller()
        watchdog = self.launch_watchdog()
        self.assertNotEqual(os.getpgid(controller.pid), os.getpgid(watchdog.pid))
        controller.kill()
        controller.wait(timeout=3)
        self.assertIsNone(watchdog.poll())
        _, stderr = watchdog.communicate(timeout=8)
        self.assertEqual(watchdog.returncode, 0, stderr)
        # Read persisted state without calling status(), which could itself expire it.
        with connect(self.authority.db_path) as db:
            row = db.execute("SELECT state,stop_reason FROM brakes_sessions WHERE root_id=?", (ROOT,)).fetchone()
            self.assertEqual(tuple(row), ("EXPIRED", "LEASE_EXPIRED"))
            self.assertEqual(db.execute("SELECT revoked FROM roots WHERE root_id=?", (ROOT,)).fetchone()[0], 1)
        report = json.loads((self.path / "watchdog.json").read_text())
        self.assertTrue(report["admission_closed"])
        self.assertFalse(report["workload_verified"])
        self.assertEqual(report["reason"], "LEASE_EXPIRED")
        self.assertEqual(self.broker.handle(action())["status"], "BLOCKED")
        self.assertEqual(self.receiver.records(), [])

    def test_watchdog_deadline_persists_stop_without_renewing(self):
        initial = self.authority.status(ROOT)
        report = run_watchdog(self.authority, ROOT, max_wait_seconds=0.03, poll_interval_seconds=0.01)
        self.assertTrue(report["admission_closed"])
        self.assertEqual(report["reason"], "WATCHDOG_DEADLINE")
        self.assertEqual(report["session"]["lease_until"], initial["lease_until"])
        self.assertEqual(report["session"]["lease_revision"], initial["lease_revision"])

    def test_fence_does_not_call_receiver_or_injected_admission_clock(self):
        def broken_clock():
            raise AssertionError("fence called admission clock")
        broker = Broker(self.broker.db_path, object(), clock=broken_clock)
        result = broker.fence(ROOT)
        self.assertTrue(result["broker_fenced"])
        self.assertEqual(result["status"], "FENCED")
        self.assertEqual(self.broker.handle(action())["reason"], "ROOT_REVOKED")

    def test_authority_failure_preserves_unknown_and_attempts_configured_cleanup(self):
        called = []
        with patch.object(self.authority, "status", side_effect=OSError("owned store unavailable")):
            report = run_watchdog(self.authority, ROOT, recovery=lambda: called.append(True))
        self.assertFalse(report["admission_closed"])
        self.assertIsNone(report["pending_reservations"])
        self.assertFalse(report["external_effect_completion_verified"])
        self.assertEqual(called, [True])

    def test_recovery_runs_only_after_durable_closure_and_is_separate(self):
        self.authority.stop(ROOT)
        def recover():
            with connect(self.authority.db_path) as db:
                self.assertEqual(db.execute("SELECT revoked FROM roots WHERE root_id=?", (ROOT,)).fetchone()[0], 1)
            self.assertEqual(self.broker.handle(action())["status"], "BLOCKED")
            return {"status": "RECOVERED", "admission_allowed": True, "recovered": [
                {"root_id": ROOT, "containment": {"verified": True, "zero_survivors": True}}]}
        report = run_watchdog(self.authority, ROOT, recovery=recover)
        self.assertTrue(report["admission_closed"])
        self.assertTrue(report["workload_verified"])
        self.assertFalse(report["pending_reservations"])
        self.assertFalse(report["external_effect_completion_verified"])

    def test_incomplete_or_wrong_root_recovery_does_not_claim_workload_stopped(self):
        self.authority.stop(ROOT)
        for result in ({"status": "EMPTY", "admission_allowed": True, "recovered": []},
                       {"status": "BUSY", "admission_allowed": False, "recovered": []},
                       {"status": "RECOVERED", "admission_allowed": True, "recovered": [
                           {"root_id": "other", "containment": {"verified": True, "zero_survivors": True}}]}):
            with self.subTest(result=result):
                report = run_watchdog(self.authority, ROOT, recovery=lambda: result)
                self.assertTrue(report["admission_closed"])
                self.assertFalse(report["workload_verified"])

    def test_recovery_timeout_preserves_unknown_and_never_claims_callback_cancelled(self):
        release = threading.Event()
        ended = threading.Event()
        self.authority.stop(ROOT)
        def delayed():
            release.wait(3)
            ended.set()
            return {"status": "EMPTY"}
        try:
            report = run_watchdog(self.authority, ROOT, recovery=delayed, recovery_timeout_seconds=0.02)
            self.assertTrue(report["admission_closed"])
            self.assertFalse(report["workload_verified"])
            self.assertEqual(report["recovery"]["status"], "UNKNOWN")
            self.assertTrue(report["recovery_call"]["still_running"])
            self.assertFalse(report["recovery_call"]["cancellation_confirmed"])
            frozen = json.dumps(report, sort_keys=True)
            release.set()
            self.assertTrue(ended.wait(1))
            self.assertEqual(json.dumps(report, sort_keys=True), frozen)
        finally:
            release.set()

    def test_pending_effect_and_stage_are_not_silently_cleared_by_stop(self):
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.authority.begin_stage(action()["action_id"], stage_id="dns")["status"], "ADMITTED")
        self.authority.stop(ROOT)
        report = run_watchdog(self.authority, ROOT)
        self.assertTrue(report["pending_reservations"])
        self.assertEqual(report["session"]["pending_action_count"], 1)
        self.assertEqual(report["session"]["pending_stage_count"], 1)

    def test_returned_action_does_not_hide_pending_stage(self):
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.authority.begin_stage(action()["action_id"], stage_id="dns")["status"], "ADMITTED")
        self.authority.finish_action(action()["action_id"], outcome="RETURNED")
        self.authority.stop(ROOT)
        report = run_watchdog(self.authority, ROOT)
        self.assertTrue(report["pending_reservations"])
        self.assertEqual(report["session"]["pending_action_count"], 0)
        self.assertEqual(report["session"]["pending_stage_count"], 1)

    def test_unknown_session_keeps_closure_unverified_but_attempts_configured_cleanup(self):
        called = []
        report = run_watchdog(self.authority, "root:missing", recovery=lambda: called.append(True))
        self.assertFalse(report["admission_closed"])
        self.assertFalse(report["workload_verified"])
        self.assertEqual(called, [True])

    def test_cli_recovery_opens_existing_governed_receiver_and_root_binds_cleanup(self):
        self.authority.stop(ROOT)
        SupervisorRegistry(self.path / "registry.db")
        for name, value in (("broker.key", b"b" * 32), ("receipt.key", b"r" * 32)):
            (self.path / name).write_bytes(value)
        with patch("sdk.liminal_agent_control.brakes_watchdog.recover_workloads") as recover:
            recover.return_value = {"status": "EMPTY", "admission_allowed": True, "recovered": []}
            code = main(["--authority-db", str(self.path / "receiver.db"), "--root-id", ROOT,
                "--registry", str(self.path / "registry.db"), "--broker-db", str(self.path / "broker.db"),
                "--broker-key-file", str(self.path / "broker.key"), "--receipt-key-file", str(self.path / "receipt.key"),
                "--output", str(self.path / "watchdog.json")])
            self.assertEqual(code, 1)  # No registered workload is physical cleanup evidence.
            self.assertEqual(recover.call_args.kwargs["expected_root_id"], ROOT)
            self.assertEqual(recover.call_args.kwargs["broker"].receiver.enforcement_profile, "governed_v1")
        self.assertTrue(json.loads((self.path / "watchdog.json").read_text())["admission_closed"])

    def test_recovery_refuses_different_registered_root_before_any_docker_call(self):
        registry = SupervisorRegistry(self.path / "registry.db")
        with registry.lease():
            record = registry.register(session_id="liminal-control-" + "c" * 32,
                root_id="root:different", action_id="action:different", image_id="sha256:" + "d" * 64,
                plan_sha256="e" * 64, backend_identity_sha256="f" * 64,
                receiver_id=self.receiver.receiver_id, broker_context_sha256="c" * 64)
        with patch("sdk.liminal_agent_control.runtime.DockerController") as docker:
            result = recover_workloads(registry.path, broker=self.broker, expected_root_id=ROOT)
            self.assertEqual(result["reason"], "RECOVERY_ROOT_MISMATCH")
            docker.assert_not_called()
        self.assertEqual(registry.unfinished(), [record])

    def test_local_fence_precedes_hanging_or_failed_host_observation(self):
        broker = self.broker
        entered = threading.Event()
        release = threading.Event()
        class Host:
            exists = True
            running = True
            def inspect_session(self, session):
                self.assert_fenced()
                entered.set()
                release.wait(3)
                return {"exists": self.exists, "running": self.running, "descendant_count": 0,
                        "tree_sha256": "c" * 64 if self.exists else "0" * 64}
            def assert_fenced(self):
                if broker.handle(action())["reason"] != "ROOT_REVOKED":
                    raise AssertionError("observer ran before durable fence")
            def freeze_session(self, session):
                self.assert_fenced()
                self.running = False
            def terminate_session(self, session):
                self.exists = False
                self.running = False
        host = Host()
        supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
            freeze_session=host.freeze_session, terminate_session=host.terminate_session)
        supervisor.register_session(session_id="session", operation_id="operation", plan_sha256="c" * 64,
                                    backend_identity_sha256="d" * 64)
        results = []
        worker = threading.Thread(target=lambda: results.append(contain_workload(supervisor, host,
            session_id="session", broker=broker, root_id=ROOT)))
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            restarted = Broker(broker.db_path, self.receiver)
            self.assertEqual(restarted.handle(action())["reason"], "ROOT_REVOKED")
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0]["verified"])
        self.assertLessEqual(results[0]["t_stop_decision"], results[0]["t_local_fenced"])
        self.assertLessEqual(results[0]["t_local_fenced"], results[0]["t_revoke_ack"])
        self.assertEqual(self.receiver.records(), [])

    @unittest.skipUnless(os.environ.get("LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"), "set pinned Docker image for real watchdog cleanup")
    def test_independent_watchdog_cleans_owned_docker_descendants_after_controller_sigkill(self):
        image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
        registry = SupervisorRegistry(self.path / "registry.db")
        controller = self.launch_controller(image)
        docker = DockerController()
        record = None
        watchdog = None
        try:
            deadline = time.monotonic() + 20
            observed = None
            while time.monotonic() < deadline:
                pending = registry.unfinished()
                if pending:
                    record = pending[0]
                    docker.bind_ownership(record)
                    observed = docker.inspect_session(record["session_id"])
                    if observed["running"] and observed["descendant_count"] >= 1:
                        break
                self.assertIsNone(controller.poll(), "controller exited before owned crash injection")
                time.sleep(0.05)
            self.assertIsNotNone(record)
            self.assertTrue(observed and observed["running"], observed)
            self.assertGreaterEqual(observed["descendant_count"], 1)
            for name, value in (("broker.key", b"b" * 32), ("receipt.key", b"r" * 32)):
                (self.path / name).write_bytes(value)
            watchdog = self.launch_watchdog("--registry", str(registry.path), "--broker-db", str(self.broker.db_path),
                "--broker-key-file", str(self.path / "broker.key"), "--receipt-key-file", str(self.path / "receipt.key"))
            self.assertNotEqual(os.getpgid(controller.pid), os.getpgid(watchdog.pid))
            controller.kill()
            controller.wait(timeout=3)
            after_crash = docker.inspect_session(record["session_id"])
            self.assertTrue(after_crash["running"], after_crash)
            _, stderr = watchdog.communicate(timeout=35)
            self.assertEqual(watchdog.returncode, 0, stderr)
            report = json.loads((self.path / "watchdog.json").read_text())
            self.assertTrue(report["admission_closed"])
            self.assertTrue(report["workload_verified"], report)
            self.assertEqual(report["reason"], "LEASE_EXPIRED")
            self.assertEqual(registry.unfinished(), [])
            self.assertFalse(docker.inspect_session(record["session_id"])["exists"])
            self.assertEqual(self.broker.handle(action())["reason"], "ROOT_REVOKED")
            self.assertEqual(self.receiver.records(), [])
            artifact = os.environ.get("LIMINAL_AGENT_CONTROL_WATCHDOG_EVIDENCE")
            if artifact:
                target = Path(artifact)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps({"mode": "actual-docker-independent-watchdog-controller-sigkill",
                    "image_id": image, "registered": record, "before_crash": observed,
                    "after_crash": after_crash, "watchdog": report}, indent=2) + "\n")
        finally:
            if watchdog is not None and watchdog.poll() is None:
                watchdog.kill()
                watchdog.wait(timeout=3)
            if controller.poll() is None:
                controller.kill()
                controller.wait(timeout=3)
            if record is not None:
                docker.terminate_session(record["session_id"])
                self.broker.revoke(ROOT)


if __name__ == "__main__":
    unittest.main()
