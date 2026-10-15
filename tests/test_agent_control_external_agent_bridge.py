"""Real STDIO exchanges with mock effects, not Docker containment evidence."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, digest
from sdk.liminal_agent_control.external_agent_bridge import BridgeBudget, ExternalAgentBridge, STDIO_SCHEMA
from sdk.liminal_agent_control.external_network_protocol import network_action

FIXTURE = Path(__file__).resolve().parents[1] / "experiments/agent_control/external_agent_fixture.py"
BINDING = {"run_id": "run", "root_id": "root", "execution_id": "worker", "epoch": 1}


def action(index=1):
    return network_action(root_id="root", execution_id="worker", epoch=1, action_id="action-" + str(index),
        attempt_id="attempt-" + str(index), endpoint_url="http://127.0.0.1:1", marker="synthetic-" + str(index))


def host_result(proposed, status="COMMITTED"):
    known = status == "COMMITTED"
    return {"status": status, "reason": "MOCK_EFFECT", "action_id": proposed["action_id"], "reservation_id": "mock-reservation",
        "effect_count": 1 if known else None, "remote_outcome": "COMMITTED" if known else None,
        "receipt": {"mock": True} if known else None, "dispatch_finished": True,
        "settlement_status": "SETTLED" if known else "UNKNOWN", "execution_authorized": False}


class ExternalAgentBridgeTests(unittest.TestCase):
    def bridge(self, *, actions=None, executor=None, fence=None, hook=None, budget=None, configuration=None,
               observer=None, observer_required=False):
        self.calls = []
        def execute(proposed):
            self.calls.append(copy.deepcopy(proposed))
            return host_result(proposed)
        return ExternalAgentBridge(run_binding=copy.deepcopy(BINDING), actions=[action()] if actions is None else actions,
            executor=execute if executor is None else executor, fence_check=(lambda: {"closed": False}) if fence is None else fence,
            before_proposal=hook, budget=budget, trusted_configuration=configuration,
            admission_observer=observer, admission_observer_required=observer_required)

    def observation(self, a):
        body = {"schema": "liminal-owned-agent-observation-v1", "source": "owned_docker_inspect", "run_id": "run",
            "run_binding_digest": "b" * 64, "root_id": "root", "execution_id": "worker", "configuration_valid": True,
            "action_id": a["action_id"], "action_digest": digest(a), "command_id": "command", "container_id": "c" * 64,
            "plan_sha256": "d" * 64, "ownership_digest": "e" * 64, "observed_at": time.time(),
            "inspect": {"Id": "c" * 64, "State": {"Running": True, "Paused": False}}, "process": {},
            "exists": True, "running": True, "execution_authorized": False}
        return {**body, "observation_digest": digest(body)}

    def launch(self, mode="useful_completion", script=None):
        argv = [sys.executable, "-I", "-u", str(FIXTURE), mode] if script is None else [sys.executable, "-I", "-u", "-c", script]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        return process

    def exchange(self, mode, bridge=None):
        bridge = self.bridge() if bridge is None else bridge
        process = self.launch(mode)
        result = bridge.run(process)
        self.assertIsNotNone(process.poll())
        self.assertTrue(bridge.inventory()["cli_reaped"])
        return bridge, result

    def packets(self, bridge, kind):
        return [event["value"] for event in bridge.trace if event["kind"] == kind]

    def scripted(self, following):
        ready = {"schema": STDIO_SCHEMA, "kind": "ready", "protocol": 1, "mode": "useful_completion"}
        return "import sys,json,time\nprint(" + repr(json.dumps(ready)) + ",flush=True)\njson.loads(sys.stdin.readline())\n" + following

    def test_useful_response_driven_worker_completes(self):
        bridge, result = self.exchange("useful_completion")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.calls, [action()])
        self.assertEqual(bridge.inventory()["bridge_status"], "FINISHED")
        self.assertTrue(bridge.callbacks_finished())
        self.assertEqual(self.packets(bridge, "claim")[0]["outcome"], "COMMITTED")

    def test_duplicate_selected_only_after_commit(self):
        bridge, _ = self.exchange("duplicate_after_commit")
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0], self.calls[1])
        self.assertEqual(len(self.packets(bridge, "proposal")), 2)

    def test_duplicate_mode_does_not_repeat_unknown(self):
        bridge = self.bridge(executor=lambda a: host_result(a, "UNKNOWN"))
        self.exchange("duplicate_after_commit", bridge)
        self.assertEqual(len(self.packets(bridge, "proposal")), 1)

    def test_lost_response_mode_attempts_same_exact_action(self):
        bridge = self.bridge(executor=lambda a: host_result(a, "UNKNOWN"))
        self.exchange("lost_endpoint_response", bridge)
        self.assertEqual(len(self.packets(bridge, "proposal")), 2)
        self.assertTrue(all(v["result"]["status"] == "UNKNOWN" for v in self.packets(bridge, "host_result")))

    def test_argument_mutation_never_calls_executor(self):
        bridge, _ = self.exchange("argument_mutation")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["reason"], "AGENT_EXACT_ACTION_REQUIRED")

    def test_lineage_swap_never_calls_executor(self):
        bridge, _ = self.exchange("lineage_swap")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "DENIED")

    def test_forged_report_remains_untrusted_claim(self):
        bridge, _ = self.exchange("forged_report")
        self.assertEqual(self.calls, [])
        self.assertEqual(bridge.inventory()["effect_calls"], [])
        claim = next(event for event in bridge.trace if event["kind"] == "claim")
        self.assertEqual(claim["origin"], "untrusted_worker")
        self.assertEqual(claim["value"]["outcome"], "COMMITTED")

    def test_configuration_contains_only_run_and_actions(self):
        bridge, _ = self.exchange("useful_completion")
        self.assertEqual(self.packets(bridge, "configuration"), [{"run_id": "run", "actions": [action()]}])
        self.assertNotIn("trusted_configuration", json.dumps(self.packets(bridge, "configuration")))

    def test_host_fence_before_worker_blocks_dispatch(self):
        bridge = self.bridge(fence=lambda: {"closed": True})
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["reason"], "AGENT_HOST_FENCED")

    def test_sticky_local_fence_cannot_reopen(self):
        state = {"closed": False}
        bridge = self.bridge(fence=lambda: state)
        bridge.fence("TEST_STOP")
        state["closed"] = False
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(len(self.packets(bridge, "fence")), 1)

    def test_queued_second_proposal_fenced_during_inflight_effect(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def execute(a):
            calls.append(a)
            entered.set()
            release.wait(1)
            return host_result(a)
        def hook(index, a, bridge):
            if index == 2:
                self.assertTrue(entered.wait(1))
                bridge.fence("TEST_STOP")
                release.set()
        bridge = self.bridge(actions=[action(), action(2)], executor=execute, hook=hook)
        self.exchange("pending_effect_stop", bridge)
        self.assertEqual(calls, [action()])
        results = self.packets(bridge, "host_result")
        self.assertEqual(next(v for v in results if v["proposal_id"] == "proposal-2")["result"]["reason"], "AGENT_HOST_FENCED")

    def test_parallel_proposal_held_while_callback_inflight(self):
        release = threading.Event()
        calls = []
        def execute(a):
            calls.append(a)
            release.wait(0.05)
            return host_result(a)
        bridge = self.bridge(actions=[action(), action(2)], executor=execute)
        self.exchange("queued_after_stop", bridge)
        self.assertEqual(calls, [action()])
        self.assertEqual(next(v for v in self.packets(bridge, "host_result") if v["proposal_id"] == "proposal-2")["result"]["reason"], "AGENT_HOST_CALL_PENDING")

    def test_timeout_keeps_outstanding_callback_unknown_until_actual_finish(self):
        release = threading.Event()
        self.addCleanup(release.set)
        bridge = self.bridge(executor=lambda a: (release.wait(2), host_result(a))[1],
            budget=BridgeBudget(duration_seconds=0.4, effect_seconds=0.05, reap_seconds=0.1))
        self.exchange("useful_completion", bridge)
        inventory = bridge.inventory()
        self.assertFalse(inventory["callback_finished"])
        self.assertEqual(inventory["outstanding_effect_calls"], 1)
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")
        release.set()
        for _ in range(100):
            if bridge.callbacks_finished():
                break
            time.sleep(0.005)
        self.assertTrue(bridge.callbacks_finished())
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")
        self.assertEqual(self.packets(bridge, "effect_finished")[0]["result"]["status"], "COMMITTED")
        self.assertFalse(bridge.inventory()["effect_calls"][0]["cancellation_confirmed"])

    def test_inventory_observation_never_consumes_pending_response(self):
        entered, release = threading.Event(), threading.Event()
        bridge = self.bridge(executor=lambda a: (entered.set(), release.wait(1), host_result(a))[2])
        process = self.launch()
        result = []
        exchange = threading.Thread(target=lambda: result.append(bridge.run(process)))
        exchange.start()
        self.assertTrue(entered.wait(1))
        release.set()
        for _ in range(100):
            bridge.inventory()
            if not exchange.is_alive():
                break
            time.sleep(0.001)
        exchange.join(2)
        self.assertFalse(exchange.is_alive())
        self.assertEqual(result[0].returncode, 0)
        self.assertEqual(bridge.inventory()["bridge_status"], "FINISHED")

    def test_claims_and_snapshots_have_no_mutable_aliases(self):
        bridge, _ = self.exchange("forged_report")
        first = bridge.inventory()
        first["trace"].clear()
        first["run_binding"]["epoch"] = 999
        self.assertGreater(len(bridge.trace), 0)
        self.assertEqual(bridge.inventory()["run_binding"]["epoch"], 1)

    def test_exact_hash_chain_and_origins(self):
        bridge, _ = self.exchange("useful_completion")
        previous = "0" * 64
        for index, event in enumerate(bridge.trace, 1):
            self.assertEqual(event["sequence"], index)
            self.assertEqual(event["prev_hash"], previous)
            self.assertEqual(event["event_hash"], digest({k: v for k, v in event.items() if k != "event_hash"}))
            self.assertEqual(event["origin"], "untrusted_worker" if event["kind"] in {"ready", "proposal", "claim", "done"} else "trusted_host")
            previous = event["event_hash"]
        self.assertEqual(bridge.inventory()["trace_head"], previous)

    def test_invalid_start_config_is_not_delivered(self):
        bridge, process = self.bridge(), self.launch()
        with self.assertRaises(ControlError):
            bridge.run(process, {"run_id": "run", "actions": [action()], "grant": {}})
        process.kill()
        process.communicate()

    def test_constructor_binds_root_execution_epoch(self):
        for field, value in (("root_id", "other"), ("execution_id", "other"), ("epoch", 2)):
            a = action()
            a[field] = value
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.bridge(actions=[a])

    def test_constructor_rejects_duplicate_id_or_attempt(self):
        for field in ("action_id", "attempt_id"):
            a = action(2)
            a[field] = action()[field]
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.bridge(actions=[action(), a])

    def test_original_action_mutation_does_not_widen_allowlist(self):
        a = action()
        bridge = self.bridge(actions=[a])
        a["arguments"]["body"]["synthetic_marker"] = "other"
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [action()])

    def test_trusted_configuration_is_separate_and_immutable(self):
        configuration = {"run_binding": BINDING, "actions": [action()], "endpoint_public_pin": "public"}
        bridge = self.bridge(configuration=configuration)
        expected = digest(configuration)
        configuration["endpoint_public_pin"] = "changed"
        self.exchange("useful_completion", bridge)
        self.assertEqual(bridge.configuration_digest, expected)
        self.assertEqual(bridge.configuration()["endpoint_public_pin"], "public")
        self.assertNotIn("endpoint_public_pin", str(self.packets(bridge, "configuration")))

    def test_callback_identity_swap_fails_closed(self):
        for field in ("executor", "fence_check", "before_proposal"):
            bridge = self.bridge()
            setattr(bridge, field, lambda *args: {"closed": False})
            with self.subTest(field=field):
                self.exchange("useful_completion", bridge)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.packets(bridge, "fence")[0]["reason"], "CALLBACK_CONFIGURATION_CHANGED")

    def test_bad_fence_snapshot_fails_closed(self):
        for snapshot in ({}, {"closed": 0}, None):
            bridge = self.bridge(fence=lambda: snapshot)
            with self.subTest(snapshot=snapshot):
                self.exchange("useful_completion", bridge)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.packets(bridge, "fence")[0]["reason"], "FENCE_OBSERVATION_UNAVAILABLE")

    def test_host_exception_private_text_not_exported(self):
        def fail(a):
            raise ValueError("sensitive-private-message")
        bridge = self.bridge(executor=fail)
        self.exchange("useful_completion", bridge)
        self.assertNotIn("sensitive-private-message", json.dumps(bridge.inventory()))
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")

    def test_worker_cannot_supply_grant_in_proposal(self):
        packet = {"schema": STDIO_SCHEMA, "kind": "proposal", "proposal_id": "p", "action": action(), "authorization": {}}
        script = self.scripted("print(" + repr(json.dumps(packet)) + ",flush=True)\n")
        bridge = self.bridge()
        bridge.run(self.launch(script=script))
        self.assertEqual(self.calls, [])
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_duplicate_json_keys_rejected(self):
        raw = '{"schema":"liminal.agent-stdio.v1","kind":"claim","claim":{},"claim":{"outcome":"COMMITTED"}}'
        bridge = self.bridge()
        bridge.run(self.launch(script=self.scripted("print(" + repr(raw) + ",flush=True)\n")))
        self.assertEqual(self.packets(bridge, "claim"), [])
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_nonfinite_json_rejected(self):
        raw = '{"schema":"liminal.agent-stdio.v1","kind":"claim","claim":{"x":NaN}}'
        bridge = self.bridge()
        bridge.run(self.launch(script=self.scripted("print(" + repr(raw) + ",flush=True)\n")))
        self.assertEqual(self.packets(bridge, "claim"), [])

    def test_ready_required_before_proposal(self):
        packet = {"schema": STDIO_SCHEMA, "kind": "proposal", "proposal_id": "p", "action": action()}
        bridge = self.bridge()
        bridge.run(self.launch(script="print(" + repr(json.dumps(packet)) + ",flush=True)"))
        self.assertEqual(self.calls, [])

    def test_protocol_boolean_ready_not_integer(self):
        packet = {"schema": STDIO_SCHEMA, "kind": "ready", "protocol": True, "mode": "useful_completion"}
        bridge = self.bridge()
        bridge.run(self.launch(script="print(" + repr(json.dumps(packet)) + ",flush=True)"))
        self.assertEqual(self.packets(bridge, "configuration"), [])

    def test_proposal_id_replay_fails_closed(self):
        packet = {"schema": STDIO_SCHEMA, "kind": "proposal", "proposal_id": "p", "action": action()}
        line = "print(" + repr(json.dumps(packet)) + ",flush=True)\n"
        bridge = self.bridge()
        bridge.run(self.launch(script=self.scripted(line + "json.loads(sys.stdin.readline())\n" + line)))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_step_limit_closes_admission(self):
        bridge = self.bridge(budget=BridgeBudget(max_steps=1))
        self.exchange("duplicate_after_commit", bridge)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.packets(bridge, "host_result")[-1]["result"]["status"], "DENIED")

    def test_claim_message_limit_reaps_cli(self):
        packet = {"schema": STDIO_SCHEMA, "kind": "claim", "claim": {}}
        script = self.scripted("for _ in range(30): print(" + repr(json.dumps(packet)) + ",flush=True)\n")
        bridge = self.bridge(budget=BridgeBudget(max_messages=4))
        result = bridge.run(self.launch(script=script))
        self.assertIsNotNone(result.returncode)
        self.assertLessEqual(bridge.inventory()["messages"], 5)

    def test_stdout_flood_bounded_and_reaped(self):
        script = self.scripted("print('x'*20000,flush=True)\ntime.sleep(1)\n")
        bridge = self.bridge(budget=BridgeBudget(max_output_bytes=1024, max_frame_bytes=512))
        result = bridge.run(self.launch(script=script))
        self.assertLessEqual(len(result.stdout), 1024)
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_stderr_flood_bounded_and_reaped(self):
        script = self.scripted("sys.stderr.write('x'*20000);sys.stderr.flush()\ntime.sleep(1)\n")
        bridge = self.bridge(budget=BridgeBudget(max_output_bytes=1024))
        result = bridge.run(self.launch(script=script))
        self.assertLessEqual(len(result.stderr), 1024)
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_partial_frame_fails_closed(self):
        bridge = self.bridge()
        bridge.run(self.launch(script=self.scripted("sys.stdout.write('{');sys.stdout.flush()\n")))
        self.assertEqual(bridge.inventory()["bridge_status"], "BOUNDARY_ERROR")

    def test_proposal_after_done_never_dispatches(self):
        done = {"schema": STDIO_SCHEMA, "kind": "done", "reason": "finished"}
        proposal = {"schema": STDIO_SCHEMA, "kind": "proposal", "proposal_id": "p", "action": action()}
        script = self.scripted("print(" + repr(json.dumps(done)) + ",flush=True)\nprint(" + repr(json.dumps(proposal)) + ",flush=True)\n")
        bridge = self.bridge()
        bridge.run(self.launch(script=script))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "DENIED")

    def test_host_result_cannot_export_extra_credentials(self):
        bridge = self.bridge(executor=lambda a: {**host_result(a), "private_key": "do-not-export"})
        self.exchange("useful_completion", bridge)
        self.assertNotIn("do-not-export", json.dumps(bridge.inventory()))
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")

    def test_host_result_execution_authorized_never_true(self):
        bridge = self.bridge(executor=lambda a: {**host_result(a), "execution_authorized": True})
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")

    def test_cli_deadline_cannot_claim_workload_quiescence(self):
        script = self.scripted("time.sleep(2)\n")
        bridge = self.bridge(budget=BridgeBudget(duration_seconds=0.05, reap_seconds=0.05))
        bridge.run(self.launch(script=script))
        self.assertEqual(bridge.inventory()["bridge_status"], "DEADLINE_EXCEEDED")
        self.assertEqual(self.packets(bridge, "cli_exit")[0]["workload_quiescence"], "NOT_ESTABLISHED")
        self.assertEqual(bridge.inventory()["sender_quiescence"], "NOT_ESTABLISHED")

    def test_invalid_budget_types_and_ranges(self):
        for values in ({"max_steps": True}, {"duration_seconds": float("nan")}, {"effect_seconds": 0}, {"max_output_bytes": 10**9}):
            with self.subTest(values=values), self.assertRaises(ControlError):
                BridgeBudget(**values)

    def test_bridge_run_cannot_repeat(self):
        bridge, _ = self.exchange("useful_completion")
        process = self.launch()
        with self.assertRaises(ControlError):
            bridge.run(process)
        process.kill()
        process.communicate()

    def test_required_observer_cannot_be_missing(self):
        with self.assertRaises(ControlError):
            self.bridge(observer_required=True)

    def test_live_observation_precedes_registration_and_actual_callback(self):
        bridge = self.bridge(observer=self.observation, observer_required=True)
        self.exchange("useful_completion", bridge)
        kinds = [event["kind"] for event in bridge.trace]
        self.assertEqual(kinds.count("owned_agent_observation"), 2)
        self.assertLess(kinds.index("owned_agent_observation"), kinds.index("effect_started"))
        callback_index = kinds.index("effect_callback_started")
        self.assertEqual(kinds[callback_index - 1], "owned_agent_observation")
        self.assertEqual(bridge.inventory()["outstanding_observation_calls"], 0)
        self.assertEqual(len(bridge.inventory()["observation_calls"]), 2)

    def test_live_observation_failure_never_registers_effect(self):
        def unavailable(a):
            raise OSError("synthetic-observation-outage")
        bridge = self.bridge(observer=unavailable, observer_required=True)
        self.exchange("observation_outage", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "effect_started"), [])
        self.assertEqual(self.packets(bridge, "host_result")[0]["result"]["status"], "UNKNOWN")
        self.assertEqual(self.packets(bridge, "fence")[0]["reason"], "OWNED_AGENT_OBSERVATION_UNAVAILABLE")

    def test_nonpositive_or_unbound_observation_fences(self):
        for field, value in (("running", False), ("configuration_valid", False), ("action_digest", "0" * 64),
                             ("container_id", "1" * 64), ("execution_authorized", True), ("root_id", "other")):
            def observer(a):
                packet = self.observation(a)
                packet[field] = value
                packet["observation_digest"] = digest({k: v for k, v in packet.items() if k != "observation_digest"})
                return packet
            with self.subTest(field=field):
                bridge = self.bridge(observer=observer, observer_required=True)
                self.exchange("useful_completion", bridge)
                self.assertEqual(self.calls, [])
                self.assertEqual(self.packets(bridge, "effect_started"), [])

    def test_fresh_dispatch_observation_failure_retains_registered_call(self):
        count = 0
        def observer(a):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("second-inspect-failed")
            return self.observation(a)
        bridge = self.bridge(observer=observer, observer_required=True)
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(len(self.packets(bridge, "effect_started")), 1)
        self.assertEqual(self.packets(bridge, "effect_callback_started"), [])
        self.assertTrue(bridge.callbacks_finished())
        self.assertEqual(bridge.inventory()["effect_calls"][0]["result"]["status"], "UNKNOWN")

    def test_observer_timeout_is_bounded_and_keeps_callback_pending(self):
        release = threading.Event()
        self.addCleanup(release.set)
        bridge = self.bridge(observer=lambda a: (release.wait(2), self.observation(a))[1], observer_required=True,
            budget=BridgeBudget(duration_seconds=0.4, effect_seconds=0.05, reap_seconds=0.1))
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "effect_started"), [])
        self.assertFalse(bridge.callbacks_finished())
        self.assertEqual(bridge.inventory()["outstanding_observation_calls"], 1)
        release.set()
        for _ in range(100):
            if bridge.callbacks_finished():
                break
            time.sleep(0.005)
        self.assertTrue(bridge.callbacks_finished())

    def test_atomic_durable_close_blocks_registration_after_observation(self):
        entered, release = threading.Event(), threading.Event()
        durable = []
        def observer(a):
            entered.set()
            release.wait(1)
            return self.observation(a)
        bridge = self.bridge(observer=observer, observer_required=True)
        process = self.launch()
        exchange = threading.Thread(target=lambda: bridge.run(process))
        exchange.start()
        self.assertTrue(entered.wait(1))
        bridge.close_admission("TEST_DURABLE_STOP", lambda: durable.append("CLOSING"))
        release.set()
        exchange.join(2)
        self.assertFalse(exchange.is_alive())
        self.assertEqual(durable, ["CLOSING"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "effect_started"), [])

    def test_failed_durable_close_still_fences(self):
        bridge = self.bridge()
        def fail():
            raise OSError("disk-unavailable")
        with self.assertRaises(OSError):
            bridge.close_admission("TEST_STOP", fail)
        self.exchange("useful_completion", bridge)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.packets(bridge, "fence")[0]["reason"], "DURABLE_CLOSE_FAILED")

    def test_registration_and_trace_snapshot_share_same_lock(self):
        bridge = self.bridge()
        real_event = bridge._event
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def pause_event(origin, kind, value):
            real_event(origin, kind, value)
            if kind == "effect_started":
                entered.set()
                release.wait(1)
        bridge._event = pause_event
        exchange = threading.Thread(target=lambda: bridge.run(self.launch()))
        exchange.start()
        self.assertTrue(entered.wait(1))
        observed = []
        snapshot = threading.Thread(target=lambda: observed.append(bridge.inventory()))
        snapshot.start()
        time.sleep(0.01)
        self.assertEqual(observed, [])
        release.set()
        snapshot.join(1)
        exchange.join(2)
        self.assertEqual(len(observed[0]["effect_calls"]), 1)

    def test_inventory_does_not_collect_again_mid_projection(self):
        bridge, _ = self.exchange("useful_completion")
        bridge.callbacks_finished = lambda: self.fail("inventory must derive from one collected snapshot")
        inventory = bridge.inventory()
        self.assertTrue(inventory["callback_finished"])
        self.assertEqual(inventory["effect_calls"][0]["state"], "FINISHED")

    def test_parsed_stdout_hash_is_atomic_worker_trace_prefix(self):
        bridge, result = self.exchange("useful_completion")
        inventory = bridge.inventory()
        self.assertEqual(inventory["stdout_trace_bytes"], len(result.stdout))
        self.assertEqual(inventory["stdout_trace_sha256"], inventory["stdout_sha256"])

    def test_observer_census_uses_one_captured_thread_observation(self):
        bridge = self.bridge(observer=self.observation, observer_required=True)
        self.exchange("useful_completion", bridge)
        class AlternatingThread:
            def __init__(self):
                self.calls = 0
            def is_alive(self):
                self.calls += 1
                return self.calls == 1
        thread = AlternatingThread()
        bridge._observation_calls[0]["call"].thread = thread
        inventory = bridge.inventory()
        self.assertEqual(thread.calls, 1)
        self.assertTrue(inventory["observation_calls"][0]["still_running"])
        self.assertEqual(inventory["outstanding_observation_calls"], 1)
        self.assertFalse(inventory["callback_finished"])

    def test_done_event_alone_does_not_publish_effect_thread_finished(self):
        release = threading.Event()
        self.addCleanup(release.set)
        bridge = self.bridge(executor=lambda a: (release.wait(1), host_result(a))[1])
        process = self.launch()
        exchange = threading.Thread(target=lambda: bridge.run(process))
        exchange.start()
        for _ in range(100):
            with bridge._lock:
                records = list(bridge._calls.values())
            if records:
                break
            time.sleep(0.005)
        self.assertTrue(records)
        call = records[0]["call"]
        call.value = host_result(action())
        call.done.set()
        inventory = bridge.inventory()
        self.assertEqual(inventory["outstanding_effect_calls"], 1)
        self.assertEqual(inventory["effect_calls"][0]["state"], "INFLIGHT")
        release.set()
        exchange.join(2)
        self.assertFalse(exchange.is_alive())


if __name__ == "__main__":
    unittest.main()
