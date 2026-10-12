"""Durable session tests, including real process contention; owned temporary DBs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from sdk.liminal_agent_control.authority import AuthorityStore, ControlError, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority


def action(name="one", execution="worker"):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
            "execution_id": execution, "epoch": 1, "target": "records", "arguments": {"dummy": True}}


class SessionAuthorityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "authority.sqlite"
        self.now = 100.0
        self.store = SessionAuthority(self.path, clock=lambda: self.now)

    def create(self, **overrides):
        config = dict(controller_id="host", policy_digest=digest("policy"), objective_digest=digest("objective"),
                      max_actions=2, max_executions=4, max_depth=2, max_stages=3,
                      lifetime_seconds=100, lease_seconds=10)
        config.update(overrides)
        result = self.store.create_session("root", **config)
        self.store.bind_execution("root", "worker")
        return result

    def test_records_and_egress_share_budget_without_refunds(self):
        self.create()
        self.assertEqual(self.store.reserve(action(), channel="records")["status"], "ADMITTED")
        self.store.finish_action("one", outcome="UNKNOWN")
        self.assertEqual(self.store.reserve(action("two"), channel="egress")["status"], "ADMITTED")
        self.store.finish_action("two", outcome="RETURNED")
        self.assertEqual(self.store.reserve(action("three"), channel="records")["reason"], "ACTION_BUDGET_EXHAUSTED")
        status = self.store.status("root")
        self.assertEqual((status["action_count"], status["remaining_actions"], status["pending_action_count"]), (2, 0, 1))

    def test_two_real_processes_compete_for_last_action(self):
        self.create(max_actions=1)
        code = '''import json,sys
from sdk.liminal_agent_control.brakes_store import SessionAuthority
s=SessionAuthority(sys.argv[1],clock=lambda:100)
print("READY",flush=True)
sys.stdin.readline()
a=json.loads(sys.argv[2])
print(json.dumps(s.reserve(a,channel=sys.argv[3])),flush=True)
'''
        processes = [subprocess.Popen([sys.executable, "-c", code, str(self.path), json.dumps(action(str(i))), channel],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for i, channel in enumerate(("records", "egress"))]
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
        self.assertEqual(next(r["reason"] for r in results if r["status"] == "BLOCKED"), "ACTION_BUDGET_EXHAUSTED")
        self.assertEqual(self.store.status("root")["remaining_actions"], 0)

    def test_restart_preserves_unknown_and_stop(self):
        self.create()
        self.store.reserve(action(), channel="egress")
        self.store.begin_stage("one", stage_id="transport")
        self.store.finish_stage("one", "transport", outcome="UNKNOWN")
        self.store.finish_action("one", outcome="UNKNOWN")
        before = self.store.stop("root")
        restarted = SessionAuthority(self.path, clock=lambda: 101)
        after = restarted.status("root")
        self.assertEqual((after["status"], after["epoch"], after["action_count"], after["pending_stage_count"]),
                         ("STOPPED", 2, 1, 1))
        self.assertEqual(restarted.stop("root")["epoch"], before["epoch"])
        self.assertEqual(restarted.reserve(action("late"), channel="egress")["status"], "BLOCKED")
        with self.assertRaises(ControlError):
            restarted.renew("root", controller_id="host", expected_epoch=1, expected_revision=0)

    def test_lease_is_rechecked_after_waiting_for_write_lock(self):
        self.create()
        waiting, results = threading.Event(), []
        blocker = connect(self.path)
        blocker.execute("BEGIN IMMEDIATE")
        def reserve():
            waiting.set()
            results.append(self.store.reserve(action(), channel="records"))
        thread = threading.Thread(target=reserve)
        thread.start()
        self.assertTrue(waiting.wait(2))
        self.now = 110  # exactly lease deadline, while the other writer owns lock
        blocker.commit()
        blocker.close()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["reason"], "LEASE_EXPIRED")
        self.assertEqual(self.store.status("root")["action_count"], 0)

    def test_expired_renewal_commits_terminal_state(self):
        self.create()
        self.now = 110
        with self.assertRaisesRegex(ControlError, "LEASE_EXPIRED"):
            self.store.renew("root", controller_id="host", expected_epoch=1, expected_revision=0)
        self.now = 100
        status = self.store.status("root")
        self.assertEqual((status["status"], status["epoch"]), ("EXPIRED", 2))

    def test_renewal_identity_epoch_lifetime_and_budget(self):
        self.create(lifetime_seconds=15)
        self.store.reserve(action(), channel="records")
        for identity, epoch in (("worker", 1), ("host", 0), ("host", True)):
            with self.assertRaisesRegex(ControlError, "MISMATCH"):
                self.store.renew("root", controller_id=identity, expected_epoch=epoch, expected_revision=0)
        self.now = 109
        renewed = self.store.renew("root", controller_id="host", expected_epoch=1, expected_revision=0)
        self.assertEqual((renewed["lease_until"], renewed["remaining_actions"]), (115, 1))
        self.assertEqual(renewed["lease_revision"], 1)
        self.now = 111
        with self.assertRaisesRegex(ControlError, "MISMATCH"):
            self.store.renew("root", controller_id="host", expected_epoch=1, expected_revision=0)
        self.assertEqual(self.store.status("root")["lease_revision"], 1)
        self.now = 115
        self.assertEqual(self.store.reserve(action("late"), channel="records")["reason"], "HARD_DEADLINE_EXPIRED")

    def test_concurrent_renewals_cannot_consume_same_revision_twice(self):
        self.create()
        self.now = 109
        start = threading.Barrier(2)
        def renew():
            other = SessionAuthority(self.path, clock=lambda: 109)
            start.wait(timeout=2)
            try:
                return other.renew("root", controller_id="host", expected_epoch=1, expected_revision=0)["lease_revision"]
            except ControlError as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(renew) for _ in range(2)]
            results = [future.result(timeout=5) for future in futures]
        self.assertCountEqual(results, [1, "CONTROLLER_OR_EPOCH_MISMATCH"])
        self.assertEqual(self.store.status("root")["lease_revision"], 1)

    def test_fanout_depth_and_count_cannot_be_reset_by_rebind(self):
        self.create(max_executions=3, max_depth=1)
        self.store.bind_execution("root", "child", "worker")
        self.store.bind_execution("root", "child", "worker")
        with self.assertRaisesRegex(ControlError, "DEPTH"):
            self.store.bind_execution("root", "grandchild", "child")
        self.store.bind_execution("root", "sibling", "worker")
        with self.assertRaisesRegex(ControlError, "BUDGET"):
            self.store.bind_execution("root", "fourth")
        with self.assertRaisesRegex(ControlError, "BINDING"):
            self.store.bind_execution("root", "child")
        self.assertEqual(self.store.status("root")["execution_count"], 3)

    def test_stages_share_budget_and_never_replay(self):
        self.create(max_stages=2)
        self.store.reserve(action(), channel="egress")
        self.store.reserve(action("two"), channel="egress")
        self.assertEqual(self.store.begin_stage("one", stage_id="dns")["status"], "ADMITTED")
        self.store.finish_stage("one", "dns", outcome="RETURNED")
        self.assertEqual(self.store.begin_stage("one", stage_id="dns")["reason"], "STAGE_ALREADY_RESERVED")
        self.assertEqual(self.store.begin_stage("two", stage_id="dns")["status"], "ADMITTED")
        self.store.finish_stage("two", "dns", outcome="UNKNOWN")
        self.assertEqual(self.store.begin_stage("one", stage_id="transport")["reason"], "STAGE_BUDGET_EXHAUSTED")

    def test_stop_between_preparation_and_transport(self):
        self.create()
        self.store.reserve(action(), channel="egress")
        self.store.begin_stage("one", stage_id="dns")
        self.store.finish_stage("one", "dns", outcome="RETURNED")
        self.store.stop("root")
        self.assertEqual(self.store.begin_stage("one", stage_id="transport")["status"], "BLOCKED")
        self.assertEqual(self.store.status("root")["stage_count"], 1)

    def test_clock_rollback_and_invalid_clock_are_terminal(self):
        for value in (99, float("nan"), float("inf"), True):
            with self.subTest(value=value):
                path = self.path.with_name("clock-" + str(value) + ".sqlite")
                store = SessionAuthority(path, clock=lambda: self.now)
                self.store, self.now = store, 100
                self.create()
                self.now = value
                self.assertEqual(store.reserve(action(), channel="records")["reason"], "CLOCK_UNSAFE")
                self.now = 101
                self.assertEqual(store.status("root")["status"], "CLOCK_UNSAFE")

    def test_root_revocation_outside_session_still_closes_admission(self):
        self.create()
        AuthorityStore(self.path).revoke("root")
        self.assertEqual(self.store.reserve(action(), channel="egress")["reason"], "ROOT_REVOKED")
        self.assertEqual(self.store.status("root")["epoch"], 2)

    def test_legacy_execution_registration_cannot_bypass_session_limits(self):
        self.create(max_executions=1)
        AuthorityStore(self.path).bind_execution("root", "legacy", "worker")
        self.assertEqual(self.store.reserve(action("bypass", execution="legacy"), channel="records")["reason"],
                         "EXECUTION_NOT_REGISTERED")
        with self.assertRaisesRegex(ControlError, "NOT_REGISTERED"):
            self.store.bind_execution("root", "legacy", "worker")
        with self.assertRaisesRegex(ControlError, "PARENT_LINEAGE"):
            self.store.bind_execution("root", "grandchild", "legacy")

    def test_unknown_session_mismatch_and_policy_fail_closed(self):
        self.assertEqual(self.store.reserve(action(), channel="records")["reason"], "UNKNOWN_SESSION")
        self.create()
        self.assertEqual(self.store.reserve(action(), channel="unmediated")["reason"], "INVALID_ACTION_BINDING")
        self.assertEqual(self.store.reserve(action(), channel="records", policy_digest=digest("other"))["reason"], "POLICY_MISMATCH")
        self.store.reserve(action(), channel="records", payload_digest=digest("payload"))
        for changed in ({"arguments": {"changed": True}}, {"attempt_id": "new"}, {"action_id": "new"}):
            self.assertEqual(self.store.reserve({**action(), **changed}, channel="records", payload_digest=digest("payload"))["reason"], "ACTION_BINDING_MISMATCH")
        self.assertEqual(self.store.reserve(action(), channel="egress", payload_digest=digest("payload"))["reason"], "ACTION_BINDING_MISMATCH")

    def test_accepted_record_may_complete_after_stop_without_new_admission(self):
        self.create()
        with connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            self.assertEqual(self.store.admit_in_transaction(db, action(), channel="records")["status"], "ADMITTED")
        self.store.stop("root")
        with connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            self.store.finish_action_in_transaction(db, "one", outcome="COMMITTED")
        self.assertEqual(self.store.status("root")["pending_action_count"], 0)
        self.assertEqual(self.store.reserve(action("later"), channel="records")["status"], "BLOCKED")

    def test_session_policy_and_root_are_immutable(self):
        self.create()
        with self.assertRaisesRegex(ControlError, "new"):
            self.create(max_actions=999)
        self.assertEqual(self.store.status("root")["max_actions"], 2)

    def test_foreign_database_transaction_is_rejected(self):
        self.create()
        other = self.path.with_name("other.sqlite")
        SessionAuthority(other, clock=lambda: 100)
        with connect(other) as db:
            db.execute("BEGIN IMMEDIATE")
            for callback in (
                    lambda: self.store.admit_in_transaction(db, action(), channel="records"),
                    lambda: self.store.check_session_in_transaction(db, "root"),
                    lambda: self.store.finish_action_in_transaction(db, "one", outcome="COMMITTED")):
                with self.assertRaisesRegex(ControlError, "different authority"):
                    callback()


if __name__ == "__main__":
    unittest.main()
