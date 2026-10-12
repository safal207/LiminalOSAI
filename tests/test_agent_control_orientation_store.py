"""Trajectory controls use real SQLite transactions and independently bound evidence."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.orientation import OrientationStore
from sdk.liminal_agent_control.receiver import Receiver


def profile(**overrides):
    value = {"nodes": [{"node_id": n, "space_id": "owned-workspace", "phase": n}
                       for n in ("center", "work", "far")],
             "edges": [{"edge_id": name, "source": source, "destination": dest, "channel": "egress"}
                       for name, source, dest in (("out", "center", "work"), ("farther", "work", "far"),
                           ("back", "work", "center"), ("recover", "far", "center"), ("loop", "work", "work"))],
             "center_nodes": ["center"], "max_steps": 10, "max_visits": 5, "max_away_steps": 3,
             "max_observation_age_seconds": 20, "observers": {"records": "receiver", "egress": "sink"}}
    value.update(overrides)
    return value


def action(name="a", execution="worker"):
    return {"action_id": name, "attempt_id": "try:" + name, "root_id": "root", "execution_id": execution,
            "epoch": 1, "target": "network", "arguments": {"request_sha256": digest(name)}}


class OrientationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.authority.create_session("root", controller_id="host", policy_digest=digest("policy"),
            objective_digest=digest("objective"), max_actions=20, max_executions=4, max_depth=1,
            max_stages=20, lifetime_seconds=200, lease_seconds=200)
        self.authority.bind_execution("root", "worker")
        self.store = OrientationStore(self.authority)

    def install(self, **overrides):
        self.profile_digest = self.store.install("root", profile(**overrides))["profile_digest"]
        self.store.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)

    def observation(self, value, outcome="CONFIRMED", **overrides):
        result = {key: value[key] for key in ("action_id", "root_id", "execution_id", "epoch")}
        result.update(action_digest=digest(value), profile_digest=self.profile_digest,
                      observed_at=self.now, evidence_digest=digest("sink:" + value["action_id"]),
                      observer_id="sink", outcome=outcome)
        result.update(overrides)
        return result

    def state(self, execution="worker"):
        return next(s for s in self.store.snapshot("root")["executions"] if s["execution_id"] == execution)

    def reserve(self, value, edge, revision):
        self.store.prepare(value, edge_id=edge, expected_revision=revision)
        return self.authority.reserve(value, channel="egress")

    def complete(self, value, edge, revision):
        self.assertEqual(self.reserve(value, edge, revision)["status"], "ADMITTED")
        self.authority.finish_action(value["action_id"], outcome="RETURNED")
        self.store.observe(value["action_id"], observation=self.observation(value))

    def test_missing_ticket_and_seed_deny_without_spending(self):
        self.store.install("root", profile())
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "ORIENTATION_SEED_REQUIRED")
        self.store.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=100)
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "ORIENTATION_TICKET_REQUIRED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_returned_is_not_observed_success_and_ticket_is_not_authority(self):
        self.install()
        value = action()
        self.assertEqual(self.reserve(value, "out", 0)["status"], "ADMITTED")
        self.assertEqual((self.state()["node_id"], self.state()["revision"]), ("center", 0))
        self.authority.finish_action("a", outcome="RETURNED")
        with self.assertRaisesRegex(ControlError, "OBSERVATION_REQUIRED"):
            self.store.prepare(action("next"), edge_id="out", expected_revision=0)
        self.store.observe("a", observation=self.observation(value))
        self.assertEqual((self.state()["node_id"], self.state()["revision"]), ("work", 1))
        self.assertIsNone(self.state()["pending_action_id"])
        seed = self.store.snapshot("root")["seeds"][0]
        self.assertEqual((seed["node_id"], seed["evidence_digest"]), ("center", digest("seed")))

    def test_two_real_processes_cannot_fork_one_revision(self):
        self.install()
        values = [action("race-" + str(i)) for i in range(2)]
        for value in values:
            self.store.prepare(value, edge_id="out", expected_revision=0)
        code = '''import json,sys
from sdk.liminal_agent_control.brakes_store import SessionAuthority
s=SessionAuthority(sys.argv[1],clock=lambda:100)
print("READY",flush=True)
sys.stdin.readline()
print(json.dumps(s.reserve(json.loads(sys.argv[2]),channel="egress")),flush=True)
'''
        processes = [subprocess.Popen([sys.executable, "-c", code, str(self.path), json.dumps(value)],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for value in values]
        for process in processes:
            self.addCleanup(lambda p=process: p.kill() if p.poll() is None else None)
            self.assertEqual(process.stdout.readline().strip(), "READY")
        for process in processes:
            process.stdin.write("GO\n")
            process.stdin.flush()
        results = []
        for process in processes:
            out, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, err)
            results.append(json.loads(out))
        self.assertCountEqual([r["status"] for r in results], ["ADMITTED", "BLOCKED"])
        self.assertEqual(self.authority.status("root")["action_count"], 1)
        self.assertEqual(len(self.store.snapshot("root")["occurrences"]), 1)

    def test_center_return_resets_only_away_counter_and_visits_stop_cycles(self):
        self.install(max_away_steps=1, max_visits=2)
        self.complete(action("out1"), "out", 0)
        self.assertEqual(self.reserve(action("far"), "farther", 1)["reason"], "ORIENTATION_AWAY_LIMIT")
        self.complete(action("back1"), "back", 1)
        self.assertEqual((self.state()["steps"], self.state()["away_steps"], self.state()["visits"]["center"]), (2, 0, 2))
        self.complete(action("out2"), "out", 2)
        self.assertEqual(self.reserve(action("back2"), "back", 3)["reason"], "ORIENTATION_VISIT_LIMIT")
        self.assertEqual(self.authority.status("root")["action_count"], 3)

    def test_pending_unknown_center_return_does_not_report_balance(self):
        self.install()
        self.complete(action("out1"), "out", 0)
        returning = action("return")
        self.assertEqual(self.reserve(returning, "back", 1)["status"], "ADMITTED")
        self.assertEqual((self.state()["node_id"], self.state()["away_steps"]), ("work", 1))
        self.authority.finish_action("return", outcome="UNKNOWN")
        self.store.observe("return", observation=self.observation(returning, "UNKNOWN"))
        self.assertEqual((self.state()["node_id"], self.state()["away_steps"]), ("work", 1))
        self.store.observe("return", observation=self.observation(returning))
        self.assertEqual((self.state()["node_id"], self.state()["away_steps"], self.state()["steps"]), ("center", 0, 2))
        self.assertEqual(self.authority.status("root")["action_count"], 2)

    def test_preaccepted_record_return_resets_away_only_on_effect_commit(self):
        receiver = Receiver(self.path, b"b" * 32, b"r" * 32, admission_controller=self.authority)
        graph = profile()
        for edge in graph["edges"]:
            if edge["edge_id"] == "back":
                edge["channel"] = "records"
        self.install(edges=graph["edges"], observers={"records": receiver.receiver_id, "egress": "sink"})
        self.complete(action("out1"), "out", 0)
        returning = {**action("record-return"), "target": "records", "arguments": {"value": "owned"}}
        self.store.prepare(returning, edge_id="back", expected_revision=1)
        authorization = {"action_digest": digest(returning), "policy_version": digest("policy"),
                         "expires_at": time.time() + 60, "receiver_id": receiver.receiver_id}
        self.assertEqual(receiver.accept(returning, authorization=authorization)["status"], "ACCEPTED")
        self.assertEqual((self.state()["node_id"], self.state()["away_steps"]), ("work", 1))
        self.assertEqual(receiver.records(), [])
        self.authority.stop("root")
        self.assertEqual(receiver.finalize("record-return")["status"], "COMMITTED")
        self.assertEqual((self.state()["node_id"], self.state()["away_steps"], self.state()["steps"]), ("center", 0, 2))
        self.assertEqual(len(receiver.records()), 1)
        self.assertEqual(self.authority.status("root")["status"], "STOPPED")

    def test_total_step_limit_is_not_reset_by_center(self):
        self.install(max_steps=2)
        self.complete(action("out1"), "out", 0)
        self.complete(action("back1"), "back", 1)
        self.assertEqual(self.reserve(action("third"), "out", 2)["reason"], "ORIENTATION_STEP_LIMIT")

    def test_profile_seed_and_ticket_immutable(self):
        self.install()
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.store.install("root", profile(max_steps=100))
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.store.seed("root", "worker", "work", evidence_digest=digest("new"), observed_at=100)
        value = action()
        first = self.store.prepare(value, edge_id="out", expected_revision=0)
        self.assertEqual(self.store.prepare(value, edge_id="out", expected_revision=0), first)
        changed = {**value, "arguments": {"new": True}}
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            self.store.prepare(changed, edge_id="out", expected_revision=0)

    def test_profile_cannot_be_added_after_unoriented_action(self):
        self.authority.reserve(action(), channel="egress")
        with self.assertRaisesRegex(ControlError, "no admitted actions"):
            self.store.install("root", profile())

    def test_stale_observation_and_ingest_cannot_refresh_evidence(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.finish_action("a", outcome="RETURNED")
        self.now = 121
        with self.assertRaisesRegex(ControlError, "STALE"):
            self.store.observe("a", observation=self.observation(value, observed_at=100))
        self.assertEqual(self.state()["observed_at"], 100)
        self.store.observe("a", observation=self.observation(value, observed_at=120))
        self.assertEqual(self.state()["observed_at"], 120)
        self.now = 141
        with self.assertRaisesRegex(ControlError, "STALE"):
            self.store.prepare(action("next"), edge_id="back", expected_revision=1)

    def test_cross_execution_evidence_and_future_or_preadmission_time_rejected(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.finish_action("a", outcome="RETURNED")
        for changes in ({"execution_id": "other"}, {"root_id": "other"}, {"epoch": True},
                        {"profile_digest": digest("other")}, {"observer_id": "model"},
                        {"observed_at": 99}, {"observed_at": 101}, {"action_digest": digest("other")}):
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.store.observe("a", observation=self.observation(value, **changes))
        self.assertEqual(self.state()["revision"], 0)

    def test_unknown_restarts_and_confirms_without_refund_or_redispatch(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.finish_action("a", outcome="UNKNOWN")
        self.store.observe("a", observation=self.observation(value, "UNKNOWN"))
        other = OrientationStore(SessionAuthority(self.path, clock=lambda: 100))
        self.assertEqual(other.snapshot("root")["executions"][0]["pending_action_id"], "a")
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "ACTION_ALREADY_RESERVED")
        other.observe("a", observation=self.observation(value))
        self.assertEqual(self.state()["revision"], 1)
        self.assertEqual(self.authority.status("root")["action_count"], 1)
        other.observe("a", observation=self.observation(value))  # Exact observation replay is harmless.
        self.assertEqual(len(other.snapshot("root")["observations"]), 2)

    def test_inflight_confirmation_blocked_and_contradiction_holds_stages(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.begin_stage("a", stage_id="dns")
        with self.assertRaisesRegex(ControlError, "IN_FLIGHT"):
            self.store.observe("a", observation=self.observation(value))
        self.store.observe("a", observation=self.observation(value, "CONTRADICTED"))
        self.assertEqual(self.authority.begin_stage("a", stage_id="transport")["reason"], "ORIENTATION_CONTRADICTION_HOLD")
        self.authority.finish_stage("a", "dns", outcome="RETURNED")
        self.authority.finish_action("a", outcome="RETURNED")
        with self.assertRaisesRegex(ControlError, "NOT_PENDING"):
            self.store.observe("a", observation=self.observation(value))
        self.assertEqual(self.state()["revision"], 0)

    def test_stale_stage_observation_blocks_before_next_callback(self):
        self.install()
        self.reserve(action(), "out", 0)
        self.now = 121
        self.assertEqual(self.authority.begin_stage("a", stage_id="transport")["reason"], "ORIENTATION_OBSERVATION_STALE")
        self.assertEqual(self.authority.status("root")["stage_count"], 0)

    def test_independent_agent_trajectory_and_late_stop_observation(self):
        self.install()
        self.authority.bind_execution("root", "peer", "worker")
        self.store.seed("root", "peer", "center", evidence_digest=digest("peer"), observed_at=100)
        self.complete(action(), "out", 0)
        self.assertEqual((self.state()["node_id"], self.state("peer")["node_id"]), ("work", "center"))
        second = action("back")
        self.reserve(second, "back", 1)
        self.authority.stop("root")
        self.authority.finish_action("back", outcome="RETURNED")
        self.store.observe("back", observation=self.observation(second))
        self.assertEqual((self.state()["node_id"], self.state()["revision"]), ("center", 2))
        self.assertEqual(self.authority.status("root")["status"], "STOPPED")
        with self.assertRaisesRegex(ControlError, "STOP"):
            self.store.prepare(action("again"), edge_id="out", expected_revision=2)

    def test_observation_is_frozen_before_waiting_for_database_lock(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.finish_action("a", outcome="RETURNED")
        observation = self.observation(value)
        waiting, results = threading.Event(), []
        blocker = connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        def waiting_connect(path):
            connection = connect(path)
            waiting.set()
            return connection
        def ingest():
            try:
                results.append(self.store.observe("a", observation=observation))
            except Exception as error:
                results.append(error)
        with patch("sdk.liminal_agent_control.orientation.connect", side_effect=waiting_connect):
            worker = threading.Thread(target=ingest)
            worker.start()
            try:
                self.assertTrue(waiting.wait(2))
                observation.update(outcome="CONTRADICTED", execution_id="caller-mutated")
            finally:
                blocker.commit()
                blocker.close()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], dict, str(results[0]))
        self.assertEqual(results[0]["status"], "CONFIRMED")
        self.assertEqual(self.state()["node_id"], "work")
        self.assertIsNone(self.state()["hold_reason"])

    def test_observer_clock_rollback_closes_session_without_certifying(self):
        self.install()
        value = action()
        self.reserve(value, "out", 0)
        self.authority.finish_action("a", outcome="RETURNED")
        self.now = 105
        self.authority.status("root")
        self.now = 104
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            self.store.observe("a", observation=self.observation(value))
        self.assertEqual(self.authority.status("root")["status"], "CLOCK_UNSAFE")
        self.assertEqual(self.state()["revision"], 0)
        self.assertEqual(self.state()["pending_action_id"], "a")

    def test_invalid_graph_and_nonfinite_data_rejected(self):
        for change in ({"center_nodes": ["missing"]}, {"max_steps": True},
                       {"max_observation_age_seconds": float("nan")}, {"max_visits": 0}):
            with self.subTest(change=change), self.assertRaises(ControlError):
                self.store.install("root", profile(**change))
        unreachable = profile()
        unreachable["edges"] = [e for e in unreachable["edges"] if e["source"] != "far"]
        with self.assertRaisesRegex(ControlError, "return path"):
            self.store.install("root", unreachable)


if __name__ == "__main__":
    unittest.main()
