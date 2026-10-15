"""Transactional/stdio fault regressions; real Docker tests need pinned image."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from sdk.liminal_agent_control import Broker, Receiver
from sdk.liminal_agent_control.runtime import BoundedHostCall, RuntimeBoundaryError, _exchange, run_fixture
from sdk.liminal_agent_control.runtime_faults import (
    AcceptedFinalizeBarrier, FaultExperiment, LostResponseReceiver, UnavailableReceiver,
    FAULT_SCENARIOS, run_fault_fixture,
)
from sdk.liminal_process_tree import ProcessTreeSupervisor


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


class HostFixture:
    """Explicit offline host lifecycle fixture, never Docker evidence."""
    docker_binary = "docker"

    def __init__(self):
        self.exists = self.running = True
        self.process_evidence = {}
        self.owned_container_ids = {"session": "a" * 64}
        self.commands = []

    def inspect_session(self, session):
        return {"exists": self.exists, "running": self.running, "descendant_count": 0,
                "tree_sha256": "a" * 64 if self.exists else "0" * 64}

    def freeze_session(self, session):
        self.running = False

    def terminate_session(self, session):
        self.exists = self.running = False

    def command(self, args, *, timeout):
        self.commands.append(args)
        return subprocess.CompletedProcess(args, 1, b"", b"private unavailable socket")


class FaultRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.receiver = Receiver(self.path / "receiver.db", b"b" * 32, b"r" * 32)
        self.broker = Broker(self.path / "broker.db", self.receiver)
        self.action = {"action_id": "action:fault", "attempt_id": "attempt:fault", "root_id": "root:fault",
                       "execution_id": "worker:fault", "epoch": 1, "target": "records", "arguments": {"value": "approved"}}
        self.receiver.create_root(self.action["root_id"])
        self.receiver.bind_execution(self.action["root_id"], self.action["execution_id"])
        self.broker.authorize(self.action)

    def tearDown(self):
        self.directory.cleanup()

    def setup_experiment(self, scenario):
        experiment = FaultExperiment(scenario, self.broker, self.action, timeout_seconds=3)
        bridge = experiment.make_bridge()
        bridge.accept(encode({"type": "ready", "protocol": 1}))
        host = HostFixture()
        supervisor = ProcessTreeSupervisor(inspect_session=host.inspect_session,
            freeze_session=host.freeze_session, terminate_session=host.terminate_session)
        supervisor.register_session(session_id="session", operation_id=self.action["action_id"],
                                    plan_sha256="a" * 64, backend_identity_sha256="b" * 64)
        bridge.observer_required = True
        bridge.observer = lambda: host.inspect_session("session")
        experiment.bind_runtime(bridge, host, supervisor, "session")
        return experiment, bridge, host

    def test_authenticated_pending_acceptance_releases_only_after_original_ack_and_stop(self):
        experiment, bridge, host = self.setup_experiment("pre_ack_inflight")
        result = bridge.accept(encode({"type": "proposal", "action": self.action}), deadline=time.monotonic() + 3)
        self.assertEqual(result, {"status": "COMMITTED"})
        experiment.finish_calls(bridge)
        fault = experiment.finish_report(bridge, {})
        evidence = fault["protocol_evidence"]
        self.assertTrue(fault["activated"])
        self.assertTrue(fault["collection_complete"])
        self.assertTrue(evidence["finalization_joined"])
        self.assertTrue(bridge.worker_stopped)
        self.assertFalse(host.exists)
        self.assertEqual(evidence["broker_state_at_barrier"]["status"], "UNKNOWN")
        self.assertTrue(self.receiver.verify_receipt(evidence["acceptance_receipt"]))
        self.assertEqual(evidence["acceptance_receipt"]["status"], "ACCEPTED")
        self.assertIn(self.action["action_id"], evidence["pending_snapshot"]["accepted_action_ids"])
        self.assertEqual(evidence["pending_snapshot"]["receipts"], [])
        self.assertTrue(evidence["stop_evidence"]["verified"])
        self.assertTrue(self.receiver.verify_receipt(evidence["stop_evidence"]["revocation_ack"]["receiver_ack"]))
        timing = evidence["timing"]
        self.assertLessEqual(timing["accepted_at"], timing["t_decision"])
        self.assertLessEqual(timing["t_decision"], timing["t_revoke_ack"])
        self.assertLessEqual(timing["t_revoke_ack"], timing["t_finalize_released"])
        self.assertLessEqual(timing["t_quiescent"], timing["t_finalize_released"])
        self.assertLessEqual(timing["t_finalize_released"], timing["t_finalize_complete"])
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(evidence["finalized_receipt"]["accepted_epoch"], 1)

    def test_acceptance_barrier_abort_joins_without_finalizing_pending_effect(self):
        barrier = AcceptedFinalizeBarrier(self.receiver, self.action, wait_seconds=3)
        broker = Broker(self.broker.db_path, barrier)
        call = BoundedHostCall(lambda: broker.handle(self.action), name="test-preack-abort")
        self.assertTrue(barrier.accepted.wait(1))
        self.assertEqual(self.receiver.query(self.action["action_id"])["status"], "ACCEPTED")
        barrier.cancel()
        result = call.result_before(time.monotonic() + 1)
        call.thread.join(timeout=1)
        self.assertFalse(call.thread.is_alive())
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(self.receiver.records(), [])
        self.assertIn(self.action["action_id"], self.receiver.snapshot(self.action["root_id"])["accepted_action_ids"])

    def test_failed_stop_cancels_finalization_and_retains_original_partial_stop(self):
        experiment, bridge, host = self.setup_experiment("pre_ack_inflight")
        def failed_freeze(_session):
            raise OSError("offline freeze fault")
        experiment.supervisor.freeze_session = failed_freeze
        with self.assertRaisesRegex(RuntimeBoundaryError, "PRE_ACK_STOP_UNVERIFIED"):
            bridge.accept(encode({"type": "proposal", "action": self.action}), deadline=time.monotonic() + 3)
        original_stop = copy.deepcopy(experiment.stop_evidence)
        experiment.finish_calls(bridge)
        fault = experiment.finish_report(bridge, {})
        self.assertTrue(fault["collection_complete"])
        self.assertFalse(fault["protocol_evidence"]["finalization_joined"])
        self.assertTrue(fault["protocol_evidence"]["cancelled"])
        self.assertEqual(experiment.stop_evidence, original_stop)
        self.assertFalse(original_stop["verified"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(bridge.actions[0]["status"], "UNKNOWN")

    def test_changed_action_cannot_activate_real_acceptance_or_loss(self):
        changed = copy.deepcopy(self.action)
        changed["arguments"]["value"] = "mutated"
        for adapter in (AcceptedFinalizeBarrier(self.receiver, self.action, wait_seconds=1),
                        LostResponseReceiver(self.receiver, self.action)):
            with self.subTest(adapter=type(adapter).__name__):
                with self.assertRaisesRegex(RuntimeBoundaryError, "FAULT_ACTION_BINDING_MISMATCH"):
                    adapter.commit(changed)
        self.assertEqual(self.receiver.records(), [])

    def test_lost_response_reopens_unknown_blocks_duplicate_then_observation_reconciles(self):
        experiment, bridge, _ = self.setup_experiment("lost_response_restart")
        self.assertEqual(bridge.accept(encode({"type": "proposal", "action": self.action})), {"status": "UNKNOWN"})
        self.assertEqual(self.broker.state(self.action["action_id"])["status"], "UNKNOWN")
        self.broker.revoke(self.action["root_id"])
        experiment.finish_calls(bridge)
        fault = experiment.finish_report(bridge, {})
        evidence = fault["protocol_evidence"]
        self.assertTrue(fault["activated"])
        self.assertTrue(fault["collection_complete"])
        for key in ("before_reopen", "reopened_state", "after_replay"):
            self.assertEqual(evidence[key]["status"], "UNKNOWN")
        self.assertEqual(evidence["replay_result"]["status"], "BLOCKED")
        self.assertEqual(evidence["replay_result"]["reason"], "ROOT_REVOKED")
        self.assertEqual(evidence["commit_calls_after_replay"], 1)
        self.assertEqual(evidence["reconciled_state"]["status"], "COMMITTED")
        self.assertTrue(self.receiver.verify_receipt(evidence["committed_receipt"]))
        self.assertEqual(evidence["committed_receipt"], evidence["final_receipt"])
        self.assertLessEqual(evidence["committed_receipt"]["observed_at"], evidence["response_lost_at"])
        self.assertTrue(self.receiver.verify_receipt(evidence["final_receipt"]))
        self.assertEqual(len(self.receiver.records()), 1)

    def test_receiver_outage_attempts_all_failed_routes_and_keeps_revocation_healthy(self):
        experiment, bridge, _ = self.setup_experiment("receiver_down")
        self.assertEqual(bridge.accept(encode({"type": "proposal", "action": self.action})), {"status": "UNKNOWN"})
        ack = experiment.broker.revoke(self.action["root_id"])
        self.assertEqual(ack["status"], "REVOKED")
        experiment.finish_calls(bridge)
        fault = experiment.finish_report(bridge, {})
        self.assertTrue(fault["activated"])
        evidence = fault["protocol_evidence"]
        self.assertFalse(evidence["primary_observation_available"])
        self.assertTrue(evidence["diagnostic_receiver_only"])
        self.assertEqual([item["operation"] for item in evidence["transport_failures"]], ["commit", "query", "snapshot"])
        self.assertEqual(self.receiver.records(), [])

    def test_observer_failure_is_before_admission_and_not_replaced_by_good_cleanup(self):
        experiment, bridge, host = self.setup_experiment("observer_down")
        try:
            with self.assertRaisesRegex(RuntimeBoundaryError, "MANDATORY_OBSERVER_UNAVAILABLE"):
                bridge.accept(encode({"type": "proposal", "action": self.action}))
            experiment.finish_calls(bridge)
            fault = experiment.finish_report(bridge, {})
            self.assertTrue(fault["activated"])
            self.assertTrue(bridge.admission_closed)
            self.assertEqual(bridge.dispatch_calls, [])
            self.assertEqual(self.broker.state(self.action["action_id"])["status"], "AUTHORIZED")
            self.assertEqual(host.commands[0][0], "--host")
            self.assertTrue(host.commands[0][1].startswith("unix://"))
            self.assertEqual(host.commands[0][-1], "a" * 64)
            self.assertEqual(fault["protocol_evidence"]["dispatch_calls"], 0)
            self.assertEqual(self.receiver.records(), [])
        finally:
            experiment.finish_calls(bridge)

    def test_omitted_claim_is_failed_untrusted_despite_actual_committed_record(self):
        experiment = FaultExperiment("omitted_effect_claim", self.broker, self.action, timeout_seconds=3)
        bridge = experiment.make_bridge()
        worker = Path(__file__).parents[1] / "sdk/liminal_agent_control/worker_fixture.py"
        process = subprocess.Popen([sys.executable, "-I", "-u", str(worker), "omitted_effect_claim"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        try:
            _exchange(process, bridge, 3)
            experiment.finish_calls(bridge)
            fault = experiment.finish_report(bridge, {})
            self.assertTrue(fault["activated"])
            self.assertEqual(bridge.actions[0]["status"], "COMMITTED")
            self.assertEqual(bridge.claims[0]["status"], "FAILED")
            self.assertFalse(bridge.claims[0]["trusted"])
            self.assertEqual(len(self.receiver.records()), 1)
            self.assertNotIn("signature", bridge.claims[0])
        finally:
            process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_arbitrary_hook_enum_rejected_before_managed_runtime(self):
        for scenario in ("arbitrary-worker-hook", {}, ["honest"]):
            with self.subTest(scenario=scenario):
                with self.assertRaisesRegex(RuntimeBoundaryError, "UNKNOWN_FAULT_SCENARIO"):
                    run_fixture("honest", broker=self.broker, image="sha256:" + "a" * 64, fault_scenario=scenario)


@unittest.skipUnless(os.environ.get("LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"), "requires explicit immutable Docker image")
class DockerFaultRuntimeIntegrationTests(unittest.TestCase):
    def test_all_six_real_worker_faults_preserve_measured_semantics_and_cleanup(self):
        image = os.environ["LIMINAL_AGENT_CONTROL_DOCKER_IMAGE"]
        expected_effects = {"honest": 1, "pre_ack_inflight": 1, "lost_response_restart": 1,
                           "receiver_down": 0, "observer_down": 0, "omitted_effect_claim": 1}
        for scenario in FAULT_SCENARIOS:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                receiver = Receiver(path / "receiver.db", b"b" * 32, b"r" * 32)
                broker = Broker(path / "broker.db", receiver)
                root_id = "root:" + scenario
                receiver.create_root(root_id)
                receiver.bind_execution(root_id, root_id + ":worker")
                action = {"action_id": root_id + ":action", "attempt_id": root_id + ":attempt",
                          "root_id": root_id, "execution_id": root_id + ":worker", "epoch": 1,
                          "target": "records", "arguments": {"value": "owned actual Docker fault"}}
                broker.authorize(action)
                report, fault = run_fault_fixture(scenario, broker=broker, image=image, action=action)
                self.assertNotEqual(report["status"], "SKIPPED", report)
                self.assertTrue(report["registered_before_start"], report)
                self.assertTrue(report["containment"]["verified"], report)
                self.assertTrue(report["containment"]["zero_survivors"], report)
                self.assertTrue(receiver.verify_receipt(report["containment"]["revocation_ack"]["receiver_ack"]))
                self.assertTrue(fault["activated"], report)
                self.assertTrue(fault["collection_complete"], report)
                self.assertTrue(report["host_dispatch"]["collection_complete"], report)
                self.assertEqual(len(receiver.records()), expected_effects[scenario], report)
                if scenario == "observer_down":
                    self.assertEqual(report["status"], "ERROR", report)
                    self.assertTrue(report["admission_guard"]["closed"], report)
                    self.assertEqual(report["host_dispatch"]["calls"], [], report)
                    self.assertNotEqual(fault["protocol_evidence"]["admission_observer_attempt"]["returncode"], 0)
                elif scenario in {"receiver_down", "lost_response_restart"}:
                    self.assertEqual(report["status"], "UNKNOWN", report)
                else:
                    self.assertEqual(report["status"], "COMPLETED", report)


if __name__ == "__main__":
    unittest.main()
