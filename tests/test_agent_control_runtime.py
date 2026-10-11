"""Protocol/cleanup negatives; actual Docker tests require an explicit local image."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.runtime import (
    DockerController, RuntimeBoundaryError, WorkerBridge, contain_workload,
    MatchedWorkerBridge, OrdinaryRecordTool, PreAcceptanceQueue, contain_process_workload,
    decode_message, recover_workloads, run_fixture, run_matched_arm, validate_action,
    _exchange,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_process_tree import ProcessTreeSupervisor
from sdk.liminal_agent_control.supervisor_registry import SupervisorRegistry


def base_action():
    return {"action_id": "action:runtime", "attempt_id": "attempt:runtime", "root_id": "root:runtime",
            "execution_id": "execution:runtime", "epoch": 1, "target": "records", "arguments": {"value": "approved"}}


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


class RuntimeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name)
        self.receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
        self.broker = Broker(path / "broker.db", self.receiver)
        self.action = base_action()
        self.receiver.create_root(self.action["root_id"])
        self.receiver.bind_execution(self.action["root_id"], self.action["execution_id"])
        self.broker.authorize(self.action)
        self.bridge = WorkerBridge(self.broker, self.action)
        self.bridge.accept(encode({"type": "ready", "protocol": 1}))

    def tearDown(self):
        self.directory.cleanup()

    def propose(self, action):
        return self.bridge.accept(encode({"type": "proposal", "action": action}))

    def test_authorized_record_requires_broker_and_receiver(self):
        result = self.propose(self.action)
        self.assertEqual(result, {"status": "COMMITTED"})
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertNotIn("signature", result)

    def test_forged_success_is_only_an_untrusted_claim(self):
        self.bridge.accept(encode({"type": "claim", "status": "SUCCEEDED", "action_id": self.action["action_id"]}))
        self.assertFalse(self.bridge.claims[0]["trusted"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.broker.state(self.action["action_id"])["status"], "AUTHORIZED")

    def test_changed_arguments_do_not_commit(self):
        wrong = copy.deepcopy(self.action)
        wrong["arguments"]["value"] = "unapproved"
        self.assertEqual(self.propose(wrong)["status"], "BLOCKED")
        self.assertEqual(self.receiver.records(), [])

    def test_worker_cannot_impersonate_a_separately_authorized_execution(self):
        wrong = copy.deepcopy(self.action)
        wrong.update(action_id="action:other", attempt_id="attempt:other", execution_id="execution:other")
        self.receiver.bind_execution(wrong["root_id"], wrong["execution_id"])
        self.broker.authorize(wrong)
        self.assertEqual(self.propose(wrong)["status"], "BLOCKED")
        self.assertEqual(self.bridge.actions[-1]["reason"], "WORKER_IDENTITY_MISMATCH")
        self.assertEqual(self.broker.state(wrong["action_id"])["status"], "AUTHORIZED")
        self.assertEqual(self.receiver.records(), [])

    def test_revoked_receiver_blocks_previously_authorized_action(self):
        self.receiver.revoke(self.action["root_id"])
        self.assertEqual(self.propose(self.action)["status"], "BLOCKED")
        self.assertEqual(self.receiver.records(), [])

    def test_mandatory_observer_failure_blocks_without_dispatch_and_stays_closed(self):
        def unavailable():
            raise OSError("host observation unavailable")
        self.bridge.observer_required = True
        self.bridge.observer = unavailable
        with self.assertRaisesRegex(RuntimeBoundaryError, "MANDATORY_OBSERVER_UNAVAILABLE"):
            self.propose(self.action)
        self.assertTrue(self.bridge.admission_closed)
        self.assertEqual(self.bridge.actions[-1]["status"], "BLOCKED")
        self.assertEqual(self.bridge.dispatch_calls, [])
        self.assertEqual(self.broker.state(self.action["action_id"])["status"], "AUTHORIZED")
        self.assertEqual(self.receiver.records(), [])
        self.bridge.observer = lambda: {"exists": True, "running": True}
        with self.assertRaises(RuntimeBoundaryError):
            self.propose(self.action)
        self.assertEqual(self.bridge.dispatch_calls, [])

    def test_observer_timeout_cannot_dispatch_or_reopen_admission_later(self):
        release = threading.Event()
        def delayed():
            release.wait(2)
            return {"exists": True, "running": True}
        self.bridge.observer_required = True
        self.bridge.observer = delayed
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeBoundaryError, "MANDATORY_OBSERVER_UNAVAILABLE"):
                self.bridge.accept(encode({"type": "proposal", "action": self.action}), deadline=time.monotonic() + 0.05)
            self.assertLess(time.monotonic() - started, 0.4)
            self.assertEqual(self.bridge.dispatch_calls, [])
            frozen = copy.deepcopy(self.bridge.admission_observations)
            release.set()
            self.bridge.observer_calls[0].thread.join(timeout=1)
            self.assertEqual(self.bridge.admission_observations, frozen)
            self.assertTrue(self.bridge.admission_closed)
            self.assertEqual(self.receiver.records(), [])
        finally:
            release.set()

    def test_each_proposal_requires_fresh_observer_before_broker(self):
        observations = iter([{"exists": True, "running": True}, {"exists": False, "running": False}])
        self.bridge.observer_required = True
        self.bridge.observer = lambda: next(observations)
        self.assertEqual(self.propose(self.action)["status"], "COMMITTED")
        with self.assertRaisesRegex(RuntimeBoundaryError, "MANDATORY_OBSERVER_UNAVAILABLE"):
            self.propose(self.action)
        self.assertEqual(len(self.bridge.dispatch_calls), 1)
        self.assertEqual(len(self.bridge.admission_observations), 2)

    def test_protocol_rejects_duplicate_nonfinite_authority_and_network_fields(self):
        for line in [b'{"type":"done","type":"proposal"}', b'{"type":"proposal","action":NaN}',
                     b'{"type":"authorize","action":{}}', b'{"type":"proposal","url":"https://example.com"}']:
            with self.subTest(line=line):
                with self.assertRaises(RuntimeBoundaryError):
                    self.bridge.accept(line)
        self.assertEqual(self.receiver.records(), [])

    def test_boolean_epoch_depth_and_output_limits(self):
        wrong = copy.deepcopy(self.action)
        wrong["epoch"] = True
        with self.assertRaises(RuntimeBoundaryError):
            validate_action(wrong)
        nested = {}
        for _ in range(14):
            nested = {"nested": nested}
        wrong = copy.deepcopy(self.action)
        wrong["arguments"] = nested
        with self.assertRaises(RuntimeBoundaryError):
            validate_action(wrong)
        with self.assertRaises(RuntimeBoundaryError):
            decode_message(b"x" * 30000)

    def test_worker_never_receives_authorization_or_signed_receipt(self):
        fixture = Path(__file__).parents[1] / "sdk/liminal_agent_control/worker_fixture.py"
        data = encode({"action": self.action}) + b'\n{"status":"COMMITTED"}\nrelease\n'
        result = subprocess.run([sys.executable, "-I", str(fixture), "honest"], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=True)
        messages = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([m["type"] for m in messages], ["ready", "proposal", "claim", "done"])
        self.assertEqual(messages[1]["action"], self.action)
        self.assertNotIn("signature", result.stdout.decode())

    def test_pipe_exchange_rejects_flood_and_crash_with_bounded_time(self):
        fixture_path = Path(__file__).parents[1] / "sdk/liminal_agent_control/worker_fixture.py"
        for fixture in ("output_flood", "crash", "malformed"):
            with self.subTest(fixture=fixture):
                process = subprocess.Popen([sys.executable, "-I", "-u", str(fixture_path), fixture],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                bridge = WorkerBridge(self.broker, self.action)
                started = time.monotonic()
                try:
                    with self.assertRaises(RuntimeBoundaryError):
                        _exchange(process, bridge, 2)
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertEqual(self.receiver.records(), [])
                finally:
                    process.kill()
                    process.wait(timeout=2)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()

    def test_dispatch_hang_cannot_block_deadline_cleanup_or_rewrite_unknown(self):
        release = threading.Event()
        entered = threading.Event()
        real_broker = self.broker

        class DelayedBroker:
            receiver = real_broker.receiver

            def handle(self, action):
                entered.set()
                release.wait(2)
                return real_broker.handle(action)

            def revoke(self, root_id):
                return real_broker.revoke(root_id)

        fixture = Path(__file__).parents[1] / "sdk/liminal_agent_control/worker_fixture.py"
        process = subprocess.Popen([sys.executable, "-I", "-u", str(fixture), "honest"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        broker = DelayedBroker()
        bridge = WorkerBridge(broker, self.action)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeBoundaryError, "HOST_CALLBACK_DEADLINE_EXCEEDED"):
                _exchange(process, bridge, 0.15)
            self.assertTrue(entered.is_set())
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertTrue(bridge.dispatch_unresolved)
            self.assertEqual(bridge.actions[0]["status"], "UNKNOWN")
            frozen_actions = copy.deepcopy(bridge.actions)
            host = StatefulHost()
            supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
                                               freeze_session=host.freeze_session, terminate_session=host.terminate_session)
            supervisor.register_session(session_id="session", operation_id="operation",
                                        plan_sha256="a" * 64, backend_identity_sha256="b" * 64)
            contained = contain_workload(supervisor, host, session_id="session", broker=broker,
                                         root_id=self.action["root_id"])
            self.assertTrue(contained["verified"])
            self.assertIn("terminate", host.events)
            release.set()
            bridge.dispatch_calls[0].thread.join(timeout=1)
            self.assertFalse(bridge.dispatch_calls[0].thread.is_alive())
            self.assertEqual(bridge.actions, frozen_actions)
            self.assertEqual(self.receiver.records(), [])  # Late dispatch meets a durable revoked root.
            with self.assertRaises(RuntimeBoundaryError):
                bridge.accept(encode({"type": "proposal", "action": self.action}))
            self.assertEqual(len(bridge.dispatch_calls), 1)
        finally:
            release.set()
            for call in bridge.dispatch_calls:
                call.thread.join(timeout=1)
            process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


class StatefulHost:
    """Failure-injection model of independent host observations, not Docker proof."""
    def __init__(self, *, freeze_fails=False, survivor=False, observation_fails=False):
        self.exists, self.running, self.descendants = True, True, 2
        self.freeze_fails, self.survivor, self.observation_fails = freeze_fails, survivor, observation_fails
        self.events = []
        self.receiver = self

    def inspect_session(self, _session):
        if self.observation_fails:
            raise OSError("observer unavailable")
        return {"exists": self.exists, "running": self.running, "descendant_count": self.descendants,
                "tree_sha256": canonical_sha256([self.running, self.descendants]) if self.exists else "0" * 64}

    def freeze_session(self, _session):
        self.events.append("freeze")
        if self.freeze_fails:
            raise OSError("freeze failed")
        self.running = False

    def terminate_session(self, _session):
        self.events.append("terminate")
        if not self.survivor:
            self.exists, self.running, self.descendants = False, False, 0

    def revoke(self, root_id):
        self.events.append("revoke")
        return {"status": "REVOKED", "root_id": root_id, "broker_fenced": True,
                "receiver_ack": {"status": "REVOKED", "root_id": root_id}}

    def verify_receipt(self, receipt):
        return receipt.get("status") == "REVOKED"


class RuntimeCleanupTests(unittest.TestCase):
    def contain(self, host, **kwargs):
        supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
                                           freeze_session=host.freeze_session, terminate_session=host.terminate_session)
        supervisor.register_session(session_id="session", operation_id="operation",
                                    plan_sha256="a" * 64, backend_identity_sha256="b" * 64)
        return contain_workload(supervisor, host, session_id="session", broker=host, root_id="root", **kwargs)

    def test_freeze_revoke_terminate_and_independent_zero_survivors(self):
        host = StatefulHost()
        result = self.contain(host)
        self.assertEqual(host.events, ["freeze", "revoke", "terminate"])
        self.assertTrue(result["verified"])
        self.assertTrue(result["zero_survivors"])

    def test_process_only_stop_does_not_claim_authority_revocation(self):
        host = StatefulHost()
        supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
                                           freeze_session=host.freeze_session, terminate_session=host.terminate_session)
        supervisor.register_session(session_id="session", operation_id="operation",
                                    plan_sha256="a" * 64, backend_identity_sha256="b" * 64)
        result = contain_process_workload(supervisor, host, session_id="session")
        self.assertEqual(host.events, ["freeze", "terminate"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["authority_revocation_requested"])
        self.assertIsNone(result["revocation_ack"])
        self.assertIsNone(result["t_revoke_ack"])
        self.assertIsNotNone(result["t_quiescent"])

    def test_freeze_failure_still_terminates_and_cannot_claim_clean_containment(self):
        host = StatefulHost(freeze_fails=True)
        result = self.contain(host)
        self.assertIn("terminate", host.events)
        self.assertTrue(result["zero_survivors"])
        self.assertFalse(result["verified"])
        self.assertIn("FREEZE_INCOMPLETE", result["partial_failures"])

    def test_surviving_descendant_or_dead_observer_cannot_produce_pass(self):
        for host in (StatefulHost(survivor=True), StatefulHost(observation_fails=True)):
            with self.subTest(host=host):
                result = self.contain(host)
                self.assertFalse(result["verified"])
                self.assertFalse(result["zero_survivors"])
                self.assertIn("terminate", host.events)

    def test_unverified_aggregate_revoke_still_stops_but_does_not_pass(self):
        class IncompleteRevocation(StatefulHost):
            def revoke(self, root_id):
                self.events.append("revoke")
                return {"status": "INCOMPLETE", "root_id": root_id, "broker_fenced": True}
        host = IncompleteRevocation()
        result = self.contain(host)
        self.assertTrue(result["zero_survivors"])
        self.assertFalse(result["verified"])
        self.assertIn("REVOCATION_UNVERIFIED", result["partial_failures"])
        self.assertEqual(host.events, ["freeze", "revoke", "terminate"])

    def test_hung_revocation_does_not_prevent_termination(self):
        release = threading.Event()

        class HungRevocation(StatefulHost):
            def revoke(self, root_id):
                self.events.append("revoke")
                release.wait(2)
                return {"status": "REVOKED", "root_id": root_id, "broker_fenced": True,
                        "receiver_ack": {"status": "REVOKED", "root_id": root_id}}

        host = HungRevocation()
        started = time.monotonic()
        try:
            result = self.contain(host, revoke_timeout_seconds=0.05)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(result["zero_survivors"])
            self.assertFalse(result["verified"])
            self.assertIsNone(result["revocation_ack"])
            self.assertTrue(result["revocation_call"]["still_running"])
            self.assertFalse(result["revocation_call"]["cancellation_confirmed"])
            self.assertEqual(host.events, ["freeze", "revoke", "terminate"])
            frozen = copy.deepcopy(result)
            release.set()
            self.assertEqual(result, frozen)
        finally:
            release.set()

    def test_docker_daemon_failure_is_not_container_absence(self):
        class UnavailableDocker(DockerController):
            def command(self, args, **kwargs):
                return subprocess.CompletedProcess(args, 1, b"", b"Cannot connect to Docker daemon")
        with self.assertRaises(RuntimeBoundaryError):
            UnavailableDocker().inspect_session("session")

    def test_mutable_image_ref_is_refused_before_docker(self):
        with self.assertRaises(RuntimeBoundaryError):
            DockerController().image_id("python:latest")


class MatchedQueueProtocolTests(unittest.TestCase):
    """Real receiver and worker pipes; these are not Docker isolation evidence."""

    def test_same_worker_queue_produces_baseline_effect_but_revoked_receiver_denial(self):
        fixture = Path(__file__).parents[1] / "sdk/liminal_agent_control/worker_fixture.py"
        for arm in ("A", "B", "C"):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32, enforce_epoch=arm == "C")
                action = base_action()
                positive = {**action, "action_id": "positive", "attempt_id": "positive-attempt"}
                receiver.create_root(action["root_id"])
                receiver.bind_execution(action["root_id"], action["execution_id"])
                queue = PreAcceptanceQueue(receiver, action, wait_seconds=3)
                route = Broker(path / "broker.db", queue) if arm == "C" else OrdinaryRecordTool(queue)
                if arm == "C":
                    route.authorize(positive)
                    route.authorize(action)
                process = subprocess.Popen([sys.executable, "-I", "-u", str(fixture), "queued_after_stop"],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                barriers = []

                def stop_and_release(_deadline):
                    before = receiver.query(action["action_id"])
                    self.assertTrue(receiver.verify_receipt(before))
                    self.assertEqual(before["status"], "UNKNOWN")
                    self.assertEqual(before["reason"], "NOT_OBSERVED")
                    self.assertEqual(len(receiver.records()), 1)
                    self.assertEqual(queue.queued_action_sha256, canonical_sha256(action))
                    if arm == "C":
                        self.assertEqual(route.state(action["action_id"])["status"], "UNKNOWN")
                        self.assertEqual(route.revoke(action["root_id"])["status"], "REVOKED")
                        self.assertIsNotNone(queue.queued_authorization_sha256)
                    else:
                        self.assertIsNone(queue.queued_authorization_sha256)
                    if arm in {"B", "C"}:
                        process.kill()  # Local pipe fixture only; real cgroup evidence is below.
                        process.wait(timeout=1)
                    barriers.append(before)
                    queue.release.set()
                    return arm in {"B", "C"}

                bridge = MatchedWorkerBridge(route, positive, action, queue, stop_and_release)
                try:
                    protocol = _exchange(process, bridge, 3)
                    self.assertEqual(len(barriers), 1)
                    self.assertEqual(len(bridge.actions), 2)
                    self.assertEqual(bridge.actions[0]["status"], "COMMITTED")
                    self.assertEqual(bridge.actions[1]["status"], "BLOCKED" if arm == "C" else "COMMITTED")
                    self.assertEqual(len(receiver.records()), 1 if arm == "C" else 2)
                    self.assertEqual(protocol.get("stopped_by_host", False), arm in {"B", "C"})
                    self.assertTrue(receiver.verify_receipt(bridge.actions[1]["receipt"]))
                finally:
                    queue.cancel()
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=1)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()

    def test_aborted_supervision_leaves_unknown_without_receiver_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
            action = base_action()
            positive = {**action, "action_id": "positive", "attempt_id": "positive-attempt"}
            receiver.create_root(action["root_id"])
            receiver.bind_execution(action["root_id"], action["execution_id"])
            queue = PreAcceptanceQueue(receiver, action, wait_seconds=2)
            route = Broker(path / "broker.db", queue)
            route.authorize(positive)
            route.authorize(action)

            def fail_stop(_deadline):
                raise RuntimeBoundaryError("STOP_FAILED")

            bridge = MatchedWorkerBridge(route, positive, action, queue, fail_stop)
            bridge.accept(encode({"type": "ready", "protocol": 1}))
            bridge.accept(encode({"type": "proposal", "action": positive}))
            with self.assertRaisesRegex(RuntimeBoundaryError, "STOP_FAILED"):
                bridge.accept(encode({"type": "proposal", "action": action}))
            for call in bridge.dispatch_calls:
                call.thread.join(timeout=1)
            self.assertTrue(queue.cancelled.is_set())
            self.assertEqual(bridge.actions[-1]["status"], "UNKNOWN")
            self.assertEqual(route.state(action["action_id"])["status"], "UNKNOWN")
            self.assertEqual(receiver.query(action["action_id"])["reason"], "NOT_OBSERVED")
            self.assertEqual(len(receiver.records()), 1)

    def test_changed_queued_arguments_cannot_enter_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            receiver = Receiver(Path(directory) / "receiver.db", b"b" * 32, b"r" * 32)
            action = base_action()
            queue = PreAcceptanceQueue(receiver, action, wait_seconds=0.1)
            wrong = {**action, "arguments": {"value": "changed"}}
            with self.assertRaisesRegex(RuntimeBoundaryError, "QUEUED_ACTION_CHANGED"):
                queue.commit(wrong)
            self.assertFalse(queue.entered.is_set())
            self.assertEqual(receiver.records(), [])


@unittest.skipUnless(os.environ.get("LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"), "set explicit immutable Docker image to run real containment")
class DockerRuntimeIntegrationTests(unittest.TestCase):
    def test_crashed_supervisor_requires_explicit_owned_resource_recovery(self):
        image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
        project = Path(__file__).parents[1]
        program = """
from pathlib import Path
import sys
from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.runtime import run_fixture
path = Path(sys.argv[1])
receiver = Receiver(path / 'receiver.db', b'b' * 32, b'r' * 32)
broker = Broker(path / 'broker.db', receiver)
run_fixture('descendant_timeout', broker=broker, image=sys.argv[2], timeout_seconds=120,
            registry_path=path / 'supervisor.db')
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
            broker = Broker(path / "broker.db", receiver)
            registry = SupervisorRegistry(path / "supervisor.db")
            child = subprocess.Popen([sys.executable, "-c", program, str(path), image], cwd=project,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            record = None
            controller = DockerController()
            try:
                end = time.monotonic() + 20
                observed = None
                while time.monotonic() < end:
                    pending = registry.unfinished()
                    if pending:
                        record = pending[0]
                        controller.bind_ownership(record)
                        observed = controller.inspect_session(record["session_id"])
                        if observed["running"] and observed["descendant_count"] >= 1:
                            break
                    self.assertIsNone(child.poll(), "supervisor exited before the crash injection")
                    time.sleep(0.05)
                self.assertIsNotNone(record)
                self.assertTrue(observed and observed["running"], observed)
                self.assertGreaterEqual(observed["descendant_count"], 1, observed)
                self.assertEqual(recover_workloads(registry.path, broker=broker)["status"], "BUSY")
                child.kill()  # Deliberately bypass Python finally in this owned controller only.
                child.wait(timeout=3)
                after_crash = controller.inspect_session(record["session_id"])
                self.assertTrue(after_crash["running"], after_crash)
                blocked = run_fixture("honest", broker=broker, image=image, registry_path=registry.path)
                self.assertEqual(blocked["reason"], "RECOVERY_REQUIRED", blocked)
                self.assertEqual(receiver.records(), [])
                recovered = recover_workloads(registry.path, broker=broker)
                self.assertEqual(recovered["status"], "RECOVERED", recovered)
                evidence = recovered["recovered"][0]["containment"]
                self.assertTrue(evidence["verified"], recovered)
                self.assertTrue(evidence["zero_survivors"], recovered)
                self.assertTrue(receiver.verify_receipt(evidence["revocation_ack"]["receiver_ack"]))
                self.assertEqual(registry.unfinished(), [])
                self.assertFalse(controller.inspect_session(record["session_id"])["exists"])
                resumed = run_fixture("honest", broker=broker, image=image, registry_path=registry.path)
                self.assertEqual(resumed["status"], "COMPLETED", resumed)
                self.assertTrue(resumed["admission_guard"]["mandatory"], resumed)
                self.assertTrue(resumed["admission_guard"]["observations"][0]["admitted"], resumed)
                self.assertEqual(resumed["supervisor_registry"]["status"], "CLOSED", resumed)
                artifact_path = os.environ.get("LIMINAL_AGENT_CONTROL_RECOVERY_EVIDENCE")
                if artifact_path:
                    # Artifact capture is supplementary; assertions above are
                    # the test oracle and must not depend on file availability.
                    try:
                        artifact = Path(artifact_path)
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        artifact.write_text(json.dumps({"mode": "actual-docker-supervisor-crash-recovery",
                            "registered": record, "before_crash": observed, "after_crash": after_crash,
                            "admission_before_recovery": blocked, "recovery": recovered,
                            "resumed": resumed, "final_records": receiver.records()}, indent=2) + "\n")
                    except OSError as exc:
                        print("supplementary recovery artifact unavailable: " + type(exc).__name__)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                if record is not None:
                    # Exact recorded ownership is rechecked before any cleanup.
                    controller.terminate_session(record["session_id"])
                    broker.revoke(record["root_id"])

    def test_matched_actual_docker_arms_queue_after_stop(self):
        image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
        worker_hashes = set()
        for arm in ("A", "B", "C"):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32, enforce_epoch=arm == "C")
                result = run_matched_arm(arm, image=image, broker_db_path=path / "broker.db", receiver=receiver)
                self.assertEqual(result["status"], "BLOCKED" if arm == "C" else "COMPLETED", result)
                self.assertTrue(result["registered_before_start"], result)
                self.assertTrue(result["containment"]["verified"], result)
                self.assertTrue(result["containment"]["zero_survivors"], result)
                self.assertTrue(result["worker_at_trigger"]["running"], result)
                self.assertGreaterEqual(len(result["worker_processes_at_trigger"]["processes"]), 1, result)
                worker_hashes.add(result["worker_sha256"])
                self.assertEqual(len(receiver.records()), 1 if arm == "C" else 2, result)
                self.assertTrue(receiver.verify_receipt(result["receiver_before_release"]), result)
                self.assertEqual(result["receiver_before_release"]["reason"], "NOT_OBSERVED", result)
                timing = result["timing"]
                self.assertLessEqual(result["queue_entered_at"], timing["t_decision"], result)
                self.assertLess(timing["t_decision"], timing["t_queue_released"], result)
                self.assertEqual(receiver.query(result["positive_action"]["action_id"])["status"], "COMMITTED", result)
                queued = result["actions"][1]["receipt"]
                self.assertTrue(receiver.verify_receipt(queued), result)
                if arm in {"B", "C"}:
                    self.assertLess(timing["t_quiescent"], timing["t_queue_released"], result)
                    self.assertTrue(result["protocol"]["stopped_by_host"], result)
                else:
                    self.assertIsNone(timing["t_quiescent"], result)
                    self.assertTrue(result["cleanup_after_queue_release"], result)
                if arm == "C":
                    self.assertLess(timing["t_revoke_ack"], timing["t_queue_released"], result)
                    self.assertEqual(result["broker_state_at_barrier"]["status"], "UNKNOWN", result)
                    self.assertEqual(queued["status"], "DENIED", result)
                else:
                    self.assertIsNone(timing["t_revoke_ack"], result)
                    self.assertIsNone(result["containment"]["revocation_ack"], result)
                    self.assertGreaterEqual(queued["accepted_at"], timing["t_queue_released"], result)
        self.assertEqual(len(worker_hashes), 1)

    def test_real_worker_effects_and_container_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
            broker = Broker(path / "broker.db", receiver)
            image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
            for fixture in ("honest", "forged_success", "argument_mutation", "stale_authority",
                            "delegated_after_revoke", "delayed_post_ack", "descendant_timeout", "crash", "output_flood"):
                with self.subTest(fixture=fixture):
                    before = len(receiver.records())
                    result = run_fixture(fixture, broker=broker, image=image, timeout_seconds=2 if fixture == "descendant_timeout" else 10)
                    self.assertNotEqual(result["status"], "SKIPPED", result)
                    self.assertTrue(result["registered_before_start"], result)
                    self.assertTrue(result["containment"]["verified"], result)
                    self.assertEqual(len(receiver.records()) - before, 1 if fixture == "honest" else 0, result)
                    if fixture == "honest":
                        self.assertEqual(result["actions"][0]["status"], "COMMITTED", result)
                    if fixture in {"descendant_timeout", "crash", "output_flood"}:
                        self.assertEqual(result["status"], "ERROR", result)
                    if fixture == "descendant_timeout":
                        self.assertTrue(result["fixture_complete"], result)
                        self.assertGreaterEqual(result["containment"]["pre_stop_observation"]["descendant_count"], 1, result)
                        self.assertGreaterEqual(len(result["containment"]["pre_stop_process_evidence"]["processes"]), 2, result)


if __name__ == "__main__":
    unittest.main()
