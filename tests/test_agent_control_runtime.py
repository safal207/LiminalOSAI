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
from sdk.liminal_agent_control.supervisor_registry import SupervisorRegistry, ownership_labels


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

            def fence(self, root_id):
                return real_broker.fence(root_id)

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

    def fence(self, root_id):
        self.events.append("fence")
        return {"status": "FENCED", "root_id": root_id, "broker_fenced": True}

    def verify_receipt(self, receipt):
        return receipt.get("status") == "REVOKED"


class RuntimeCleanupTests(unittest.TestCase):
    def contain(self, host, **kwargs):
        supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
                                           freeze_session=host.freeze_session, terminate_session=host.terminate_session)
        supervisor.register_session(session_id="session", operation_id="operation",
                                    plan_sha256="a" * 64, backend_identity_sha256="b" * 64)
        return contain_workload(supervisor, host, session_id="session", broker=host, root_id="root", **kwargs)

    def test_fence_revoke_before_freeze_and_independent_zero_survivors(self):
        host = StatefulHost()
        result = self.contain(host)
        self.assertEqual(host.events, ["fence", "revoke", "freeze", "terminate"])
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
        self.assertEqual(host.events, ["fence", "revoke", "freeze", "terminate"])

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
            self.assertEqual(host.events, ["fence", "revoke", "freeze", "terminate"])
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


class DockerObservationRaceTests(unittest.TestCase):
    """Deterministic Docker command interleavings, not real OS evidence."""

    def payload(self, *, running=True, paused=False):
        return {"Id": "a" * 64, "Image": "sha256:" + "b" * 64,
                "State": {"Running": running, "Paused": paused, "Pid": 100 if running else 0},
                "Config": {"Labels": ownership_labels(self.record())}}

    def record(self):
        return {"session_id": "session", "image_id": "sha256:" + "b" * 64,
                "registry_id": "registry:fixture", "ownership_token": "owned-token", "plan_sha256": "c" * 64}

    def inspect_result(self, payload):
        return subprocess.CompletedProcess([], 0, json.dumps([payload]).encode(), b"")

    def controller(self, results):
        class ScriptedDocker(DockerController):
            def __init__(self):
                super().__init__()
                self.calls = []
                self.results = iter(results)
            def command(self, args, **kwargs):
                self.calls.append(args)
                result = next(self.results)
                if isinstance(result, Exception):
                    raise result
                return result
        controller = ScriptedDocker()
        controller.bind_ownership(self.record())
        controller.bind_container_id("session", "a" * 64)
        return controller

    def test_exit_between_inspect_and_failed_or_empty_top_requires_positive_owned_stopped_reread(self):
        for top in (subprocess.CompletedProcess([], 1, b"", b"private command stderr"),
                    subprocess.CompletedProcess([], 0, b"PID PPID\n", b""),
                    subprocess.CompletedProcess([], 0, b"", b"")):
            with self.subTest(top_returncode=top.returncode, top_stdout=top.stdout):
                controller = self.controller([self.inspect_result(self.payload()), top,
                    self.inspect_result(self.payload(running=False))])
                observed = controller.inspect_session("session")
                self.assertEqual(controller.calls, [["inspect", "a" * 64], ["top", "a" * 64], ["inspect", "a" * 64]])
                self.assertTrue(observed["exists"])
                self.assertFalse(observed["running"])
                self.assertEqual(observed["descendant_count"], 0)
                evidence = controller.process_evidence["session"]
                self.assertTrue(evidence["available"])
                self.assertEqual(evidence["processes"], [])
                failure = evidence["observation_attempts"][0]
                self.assertEqual(failure["returncode"], top.returncode)
                self.assertEqual(failure["failure_code"], "PROCESS_OBSERVATION_UNAVAILABLE" if top.returncode else "PROCESS_OBSERVATION_EMPTY")
                self.assertEqual(failure["resolved_by"], "fresh_owned_stopped_inspect")
                self.assertNotIn("stderr", json.dumps(evidence))

    def test_still_running_paused_or_invalid_fresh_state_cannot_resolve_failed_top(self):
        nonzero_pid = self.payload(running=False)
        nonzero_pid["State"]["Pid"] = 100
        boolean_pid = self.payload(running=False)
        boolean_pid["State"]["Pid"] = False
        for payload in (self.payload(), self.payload(paused=True), self.payload(running="false"),
                        self.payload(running=False, paused=None), self.payload(running=False, paused=True),
                        nonzero_pid, boolean_pid):
            with self.subTest(state=payload["State"]):
                controller = self.controller([self.inspect_result(self.payload()),
                    subprocess.CompletedProcess([], 1, b"", b"stopped?"), self.inspect_result(payload)])
                with self.assertRaisesRegex(RuntimeBoundaryError, "PROCESS_OBSERVATION_UNAVAILABLE"):
                    controller.inspect_session("session")
                self.assertEqual(len(controller.calls), 3)
                self.assertFalse(controller.process_evidence["session"]["available"])
                self.assertNotIn("resolved_by", controller.process_evidence["session"]["observation_attempts"][0])

    def test_missing_daemon_failed_or_replaced_owned_object_cannot_resolve_failed_top(self):
        replaced = self.payload(running=False)
        replaced["Id"] = "d" * 64
        labels_changed = self.payload(running=False)
        labels_changed["Config"]["Labels"]["liminal.control.owner"] = "different-owner"
        image_changed = self.payload(running=False)
        image_changed["Image"] = "sha256:" + "e" * 64
        fresh_results = [subprocess.CompletedProcess([], 1, b"", b"No such object: pinned-id"),
                         subprocess.CompletedProcess([], 1, b"", b"Cannot connect to Docker daemon"),
                         subprocess.TimeoutExpired(["docker", "inspect"], 10),
                         self.inspect_result(replaced), self.inspect_result(labels_changed),
                         self.inspect_result(image_changed)]
        for fresh in fresh_results:
            with self.subTest(fresh=type(fresh).__name__, stderr=getattr(fresh, "stderr", None)):
                controller = self.controller([self.inspect_result(self.payload()),
                    subprocess.CompletedProcess([], 1, b"", b"private top failure"), fresh])
                with self.assertRaisesRegex(RuntimeBoundaryError, "PROCESS_OBSERVATION_UNAVAILABLE"):
                    controller.inspect_session("session")
                attempt = controller.process_evidence["session"]["observation_attempts"][0]
                self.assertIn("fresh_inspect_failure", attempt)
                self.assertNotIn("resolved_by", attempt)
                self.assertEqual(len(controller.calls), 3)

    def test_malformed_lineage_and_missing_original_root_remain_failure_without_reread(self):
        for stdout, reason in ((b"not a process header\n", "PROCESS_LINEAGE_UNAVAILABLE"),
                               (b"PID PPID\ninvalid 1\n", "PROCESS_LINEAGE_INVALID"),
                               (b"PID PPID\n101 1\n", "PROCESS_ROOT_NOT_OBSERVED"),
                               (b"PID PPID\n100 1\n100 1\n", "PROCESS_ROOT_NOT_OBSERVED")):
            with self.subTest(reason=reason):
                controller = self.controller([self.inspect_result(self.payload()),
                    subprocess.CompletedProcess([], 0, stdout, b"")])
                with self.assertRaisesRegex(RuntimeBoundaryError, reason):
                    controller.inspect_session("session")
                self.assertEqual(len(controller.calls), 2)
                self.assertEqual(controller.process_evidence["session"]["observation_attempts"][0]["failure_code"], reason)

    def test_unpinned_or_unowned_metadata_cannot_use_stopped_reread(self):
        for missing in ("owned_container_ids", "owned_sessions"):
            with self.subTest(missing=missing):
                controller = self.controller([self.inspect_result(self.payload()),
                    subprocess.CompletedProcess([], 1, b"", b"top failure")])
                getattr(controller, missing).clear()
                with self.assertRaisesRegex(RuntimeBoundaryError, "PROCESS_OBSERVATION_UNAVAILABLE"):
                    controller.inspect_session("session")
                self.assertEqual(len(controller.calls), 2)

    def test_top_timeout_records_unavailability_without_stopped_reread(self):
        controller = self.controller([self.inspect_result(self.payload()),
            subprocess.TimeoutExpired(["docker", "top"], 10)])
        with self.assertRaisesRegex(RuntimeBoundaryError, "PROCESS_OBSERVATION_UNAVAILABLE"):
            controller.inspect_session("session")
        attempt = controller.process_evidence["session"]["observation_attempts"][0]
        self.assertEqual(attempt["exception_type"], "TimeoutExpired")
        self.assertEqual(len(controller.calls), 2)

    def test_freeze_state_interleavings_preserve_supervisor_quiescence(self):
        fixture = self
        class StatefulDocker(DockerController):
            def __init__(self, when, inactive):
                super().__init__()
                self.when, self.inactive = when, inactive
                self.calls, self.inspects = [], 0
                self.exists, self.state = True, fixture.payload()["State"]
                self.bind_ownership(fixture.record())
                self.bind_container_id("session", "a" * 64)
            def command(self, args, **kwargs):
                self.calls.append(args)
                if args[0] == "inspect":
                    self.inspects += 1
                    if self.inspects == 2 and self.when == "before_callback_inspect":
                        self.state = copy.deepcopy(self.inactive["State"])
                    if not self.exists:
                        return subprocess.CompletedProcess(args, 1, b"", b"No such object: pinned-id")
                    value = fixture.payload()
                    value["State"] = copy.deepcopy(self.state)
                    return fixture.inspect_result(value)
                if args[0] == "top":
                    return subprocess.CompletedProcess(args, 0, b"PID PPID\n100 1\n", b"")
                if args[0] == "pause":
                    if self.when == "after_callback_inspect":
                        self.state = copy.deepcopy(self.inactive["State"])
                    if not self.state["Running"] or self.state["Paused"]:
                        return subprocess.CompletedProcess(args, 1, b"", b"untrusted pause stderr")
                    self.state["Paused"] = True
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                if args[:2] == ["rm", "--force"]:
                    self.exists = False
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                raise AssertionError(args)
        for when in ("before_callback_inspect", "after_callback_inspect"):
            for inactive in (self.payload(running=False), self.payload(paused=True)):
                with self.subTest(when=when, state=inactive["State"]):
                    controller = StatefulDocker(when, inactive)
                    supervisor = ProcessTreeSupervisor(inspect_session=controller.inspect_session,
                        freeze_session=controller.freeze_session, terminate_session=controller.terminate_session)
                    supervisor.register_session(session_id="session", operation_id="operation",
                        plan_sha256="c" * 64, backend_identity_sha256="d" * 64)
                    frozen = supervisor.freeze_all()
                    self.assertEqual(frozen["failure_codes"], [])
                    self.assertEqual(frozen["frozen_count"], 1)
                    self.assertNotIn(["rm", "--force", "a" * 64], controller.calls)
                    quiescence = supervisor.quiesce_all(incident_id="stop:session")
                    self.assertTrue(quiescence["zero_survivors"])
                    self.assertEqual(quiescence["failure_codes"], [])
                    self.assertEqual(controller.calls.count(["pause", "a" * 64]),
                                     int(when == "after_callback_inspect"))

    def test_failed_pause_requires_positive_owned_inactive_reread(self):
        invalid_pid = self.payload(running=False)
        invalid_pid["State"]["Pid"] = False
        nonzero_stopped_pid = self.payload(running=False)
        nonzero_stopped_pid["State"]["Pid"] = 100
        zero_paused_pid = self.payload(paused=True)
        zero_paused_pid["State"]["Pid"] = 0
        foreign_id = self.payload(running=False)
        foreign_id["Id"] = "d" * 64
        foreign_image = self.payload(running=False)
        foreign_image["Image"] = "sha256:" + "e" * 64
        foreign_owner = self.payload(running=False)
        foreign_owner["Config"]["Labels"]["liminal.control.owner"] = "different-owner"
        malformed_state = self.payload(running=False)
        malformed_state["State"] = []
        fresh_results = [self.inspect_result(value) for value in (
            self.payload(), self.payload(running="false"), self.payload(paused=None),
            self.payload(running=False, paused=True), invalid_pid, nonzero_stopped_pid,
            zero_paused_pid, foreign_id, foreign_image, foreign_owner, malformed_state)]
        fresh_results.extend([
            subprocess.CompletedProcess([], 1, b"", b"No such object: pinned-id"),
            subprocess.CompletedProcess([], 1, b"", b"Cannot connect to Docker daemon"),
            subprocess.TimeoutExpired(["docker", "inspect"], 10),
        ])
        for fresh in fresh_results:
            with self.subTest(fresh=fresh):
                controller = self.controller([self.inspect_result(self.payload()),
                    subprocess.CompletedProcess([], 1, b"", b"container is already paused"), fresh])
                with self.assertRaisesRegex(RuntimeBoundaryError, "FREEZE_FAILED"):
                    controller.freeze_session("session")
                self.assertNotIn(["rm", "--force", "a" * 64], controller.calls)

    def test_inactive_freeze_reconciliation_requires_pinned_ownership(self):
        for missing in ("owned_container_ids", "owned_sessions"):
            for inactive in (self.payload(running=False), self.payload(paused=True)):
                with self.subTest(missing=missing, state=inactive["State"]):
                    controller = self.controller([self.inspect_result(inactive),
                        subprocess.CompletedProcess([], 1, b"", b"already inactive"),
                        self.inspect_result(inactive)])
                    getattr(controller, missing).clear()
                    with self.assertRaisesRegex(RuntimeBoundaryError, "FREEZE_FAILED"):
                        controller.freeze_session("session")
                    self.assertEqual(controller.calls[1], ["pause", "a" * 64])

    def test_pause_transport_failure_does_not_reconcile_from_a_later_state(self):
        for failure in (subprocess.TimeoutExpired(["docker", "pause"], 10), OSError("transport failed")):
            with self.subTest(failure=type(failure).__name__):
                controller = self.controller([self.inspect_result(self.payload()), failure,
                    self.inspect_result(self.payload(running=False))])
                with self.assertRaises(type(failure)):
                    controller.freeze_session("session")
                self.assertEqual(len(controller.calls), 2)

    def test_supervisor_rechecks_running_state_after_freeze_reconciliation(self):
        top = subprocess.CompletedProcess([], 0, b"PID PPID\n100 1\n", b"")
        controller = self.controller([self.inspect_result(self.payload()), top,
            self.inspect_result(self.payload()), subprocess.CompletedProcess([], 1, b"", b"pause failed"),
            self.inspect_result(self.payload(paused=True)), self.inspect_result(self.payload()), top])
        supervisor = ProcessTreeSupervisor(inspect_session=controller.inspect_session,
            freeze_session=controller.freeze_session, terminate_session=controller.terminate_session)
        supervisor.register_session(session_id="session", operation_id="operation",
            plan_sha256="c" * 64, backend_identity_sha256="d" * 64)
        frozen = supervisor.freeze_all()
        self.assertEqual(frozen["frozen_count"], 0)
        self.assertEqual(len(frozen["failure_codes"]), 1)
        self.assertTrue(frozen["failure_codes"][0].startswith("still_running:"))
        self.assertNotIn(["rm", "--force", "a" * 64], controller.calls)


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
    def test_independent_output_flood_exits_keep_error_and_verified_owned_cleanup(self):
        """Five separate owned actions exercise the observed exit interleaving.

        These are independent runs, not retries of a failed action or an
        estimate of security efficacy. Raw protocol ERROR must remain visible.
        """
        image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
        roots = set()
        for attempt in range(5):
            with self.subTest(attempt=attempt), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
                broker = Broker(path / "broker.db", receiver)
                before = len(receiver.records())
                result = run_fixture("output_flood", broker=broker, image=image, timeout_seconds=10)
                self.assertEqual(result["status"], "ERROR", result)
                self.assertTrue(result["registered_before_start"], result)
                self.assertTrue(result["containment"]["verified"], result)
                self.assertTrue(result["containment"]["zero_survivors"], result)
                self.assertEqual(len(receiver.records()), before, result)
                self.assertEqual(result["actions"], [], result)
                self.assertEqual(result["supervisor_registry"]["status"], "CLOSED", result)
                roots.add(result["root_id"])
                evidence = result["containment"].get("pre_stop_process_evidence") or {}
                attempts = evidence.get("observation_attempts", [])
                self.assertLessEqual(len(attempts), 32, result)
                for observation in attempts:
                    self.assertIn(observation["stage"], {"docker inspect", "docker top"}, result)
                    self.assertIsInstance(observation["failure_code"], str, result)
                    self.assertIsInstance(observation["observed_at"], (int, float), result)
                    self.assertNotIn("stdout", observation, result)
                    self.assertNotIn("stderr", observation, result)
                    self.assertNotIn("environment", observation, result)
        self.assertEqual(len(roots), 5)

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
