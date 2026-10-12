"""Independent role coverage binds exact projections and vetoes are irreversible."""
import json
from pathlib import Path
import tempfile
import threading
import unittest

from sdk.liminal_agent_control.authority import ControlError, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.center_continuity import CenterContinuityStore
from sdk.liminal_agent_control.observer_ring import ObserverRingStore, check_in_transaction
from sdk.liminal_agent_control.orientation import OrientationStore


def orientation_profile():
    return {"nodes": [{"node_id": node, "space_id": "owned", "phase": node} for node in ("center", "work")],
            "edges": [{"edge_id": edge, "source": source, "destination": destination, "channel": "egress"}
                      for edge, source, destination in (("out", "center", "work"), ("back", "work", "center"))],
            "center_nodes": ["center"], "max_steps": 20, "max_visits": 10, "max_away_steps": 10,
            "max_observation_age_seconds": 100, "observers": {"records": "receiver", "egress": "sink"}}


def center_profile():
    return {"windows": [{"center_id": "window-1", "previous_center_id": None,
                         "starts_at": 100, "ends_at": 200, "center_nodes": ["center"]}],
            "max_past_age_seconds": 100, "max_future_horizon_seconds": 40,
            "max_transition_seconds": 40, "max_away_seconds": 90, "max_idle_seconds": 90,
            "progress_edge_ids": ["out"], "max_ideas": 30}


def ring_profile(**overrides):
    profile = {"observers": [{"observer_id": role + "-observer", "role": role}
                             for role in ("reality", "continuity", "projection")],
               "required_roles": ["reality", "continuity", "projection"],
               "max_attestation_age_seconds": 20, "max_attestations": 100}
    profile.update(overrides)
    return profile


def action(name="a", execution="worker"):
    return {"action_id": name, "attempt_id": "try-" + name, "root_id": "root", "execution_id": execution,
            "epoch": 1, "target": "network", "arguments": {"request_sha256": digest(name)}}


class ObserverRingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.authority.create_session("root", controller_id="host", policy_digest=digest("policy"),
            objective_digest=digest("objective"), max_actions=20, max_executions=10, max_depth=2,
            max_stages=20, lifetime_seconds=200, lease_seconds=200)
        self.authority.bind_execution("root", "worker")
        self.orientation = OrientationStore(self.authority)
        self.center = CenterContinuityStore(self.authority)
        self.ring = ObserverRingStore(self.authority)
        self.orientation.install("root", orientation_profile())
        self.center.install("root", center_profile())

    def install(self, **overrides):
        self.ring.install("root", ring_profile(**overrides))
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)

    def project(self, value=None, edge="out", deadline=None):
        value = value or action()
        state = next(item for item in self.center.snapshot("root")["states"] if item["execution_id"] == value["execution_id"])
        idea = "idea-" + value["action_id"]
        self.center.record_idea("root", value["execution_id"], idea, digest(idea), state["head_hash"])
        self.orientation.prepare(value, edge_id=edge, expected_revision=state["revision"])
        return self.center.project(value, edge_id=edge, expected_revision=state["revision"],
            predecessor_hash=state["head_hash"], idea_id=idea, not_before=self.now,
            deadline=deadline or self.now + 20)

    def attest(self, role="reality", verdict="SUPPORT", action_id="a", **overrides):
        arguments = {"observer_id": role + "-observer", "verdict": verdict,
                     "evidence_digest": digest(role + verdict), "observed_at": self.now, "valid_until": self.now + 10}
        arguments.update(overrides)
        return self.ring.attest(action_id, **arguments)

    def support(self, action_id="a"):
        return [self.attest(role, action_id=action_id) for role in ("reality", "continuity", "projection")]

    def check(self, action_id="a", root_id="root"):
        with connect(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            return check_in_transaction(db, action_id, now=self.now, root_id=root_id)

    def test_missing_projection_cannot_be_attested_or_dispatched(self):
        self.install()
        with self.assertRaisesRegex(ControlError, "PROJECTION_REQUIRED"):
            self.attest()
        self.assertEqual(self.check(), "OBSERVER_RING_PROJECTION_REQUIRED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_required_roles_not_vote_count(self):
        profile = ring_profile()
        profile["observers"].extend({"observer_id": "copy-" + str(i), "role": "reality"} for i in range(4))
        self.install(observers=profile["observers"])
        self.project()
        self.attest()
        for i in range(4):
            self.attest(observer_id="copy-" + str(i))
        self.assertEqual(self.check(), "OBSERVER_RING_ROLE_REQUIRED")
        self.attest("continuity")
        self.assertEqual(self.check(), "OBSERVER_RING_ROLE_REQUIRED")
        self.attest("projection")
        self.assertIsNone(self.check())
        self.assertFalse(self.ring.snapshot("root")["execution_authorized"])

    def test_duplicate_identity_cannot_supply_two_roles(self):
        value = ring_profile()
        value["observers"][1]["observer_id"] = value["observers"][0]["observer_id"]
        with self.assertRaisesRegex(ControlError, "duplicate observer identity"):
            self.ring.install("root", value)
        self.assertIsNone(self.ring.snapshot("root")["profile"])

    def test_unknown_and_self_observers_rejected(self):
        profile = ring_profile()
        profile["observers"].append({"observer_id": "worker", "role": "reality"})
        self.install(observers=profile["observers"])
        self.project()
        for observer, reason in (("unknown", "UNKNOWN_OBSERVER"), ("worker", "SELF_ENDORSEMENT")):
            with self.subTest(observer=observer), self.assertRaisesRegex(ControlError, reason):
                self.attest(observer_id=observer)
        self.assertEqual(self.ring.snapshot("root")["attestations"], [])

    def test_profiles_frozen_before_trajectory_and_caller_mutation(self):
        profile = ring_profile()
        installed = self.ring.install("root", profile)
        profile["observers"][0]["role"] = "forged"
        self.assertEqual(installed["profile"]["observers"][0]["role"], "reality")
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.ring.install("root", ring_profile())

    def test_profile_cannot_be_added_after_seed(self):
        self.orientation.seed("root", "worker", "center", evidence_digest=digest("seed"), observed_at=self.now)
        with self.assertRaisesRegex(ControlError, "no seeds"):
            self.ring.install("root", ring_profile())

    def test_attestation_binds_every_projection_subject(self):
        self.install()
        projection = self.project()
        attestation = self.attest()
        for field in ("action_id", "action_digest", "root_id", "execution_id", "epoch",
                      "projection_digest", "center_id", "predecessor_hash"):
            self.assertEqual(attestation[field], projection[field])
        self.assertFalse(attestation["execution_authorized"])
        with connect(self.path) as db:
            db.execute("UPDATE center_projections SET predecessor_hash=? WHERE action_id='a'", (digest("forged"),))
        self.assertEqual(self.check(), "OBSERVER_RING_BINDING_MISMATCH")
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.attest("continuity")

    def test_forged_attestation_or_other_action_cannot_reuse_coverage(self):
        self.install()
        self.project()
        self.support()
        self.project(action("b"))
        self.assertEqual(self.check("b"), "OBSERVER_RING_ROLE_REQUIRED")
        with connect(self.path) as db:
            stored = db.execute("SELECT * FROM observer_ring_attestations LIMIT 1").fetchone()
            body = json.loads(stored["attestation_json"])
            body["center_id"] = "forged"
            db.execute("UPDATE observer_ring_attestations SET attestation_json=? WHERE attestation_digest=?",
                       (json.dumps(body), stored["attestation_digest"]))
        self.assertEqual(self.check(), "OBSERVER_RING_BINDING_MISMATCH")

    def test_idempotent_replay_cannot_refresh_evidence(self):
        self.install()
        self.project()
        first = self.support()[0]
        self.now = 110
        replay = self.attest(observed_at=100, valid_until=110)
        self.assertEqual(first, replay)
        self.assertEqual(len(self.ring.snapshot("root")["attestations"]), 3)
        self.assertEqual(self.check(), "OBSERVER_RING_ATTESTATION_STALE")
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            self.attest(observed_at=110, valid_until=120)

    def test_invalid_time_windows_cannot_create_attestation(self):
        self.install()
        self.project(deadline=115)
        for fields in ({"observed_at": 99}, {"observed_at": 101}, {"observed_at": float("nan")},
                       {"valid_until": 100}, {"valid_until": 121}, {"valid_until": 116}):
            with self.subTest(fields=fields), self.assertRaises(ControlError):
                self.attest(**fields)
        self.assertEqual(self.ring.snapshot("root")["attestations"], [])

    def test_unknown_required_role_cannot_be_outvoted(self):
        profile = ring_profile()
        profile["observers"].append({"observer_id": "copy", "role": "reality"})
        self.install(observers=profile["observers"])
        self.project()
        self.support()
        self.attest(observer_id="copy", verdict="UNKNOWN")
        self.assertEqual(self.check(), "OBSERVER_RING_UNKNOWN")

    def test_support_can_append_veto_but_veto_cannot_be_replaced(self):
        self.install()
        self.project()
        self.support()
        self.assertIsNone(self.check())
        self.attest(verdict="VETO")
        history = self.ring.snapshot("root")["attestations"]
        self.assertEqual(len(history), 4)
        self.assertEqual([item["verdict"] for item in history if item["observer_id"] == "reality-observer"], ["SUPPORT", "VETO"])
        self.assertEqual(self.check(), "OBSERVER_RING_VETO")
        self.now = 115
        reopened = ObserverRingStore(SessionAuthority(self.path, clock=lambda: self.now))
        self.assertEqual(reopened.snapshot("root")["execution_holds"][0]["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.check(), "OBSERVER_RING_VETO")
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            self.attest(evidence_digest=digest("retract"))

    def test_late_veto_after_effect_stops_new_projection_without_rewriting_history(self):
        self.install()
        self.project(deadline=108)
        for role in ("reality", "continuity", "projection"):
            self.attest(role, valid_until=108)
        self.assertEqual(self.authority.reserve(action(), channel="egress")["status"], "ADMITTED")
        self.authority.finish_action("a", outcome="RETURNED")
        self.orientation.observe("a", observation={"action_id": "a", "action_digest": digest(action()),
            "root_id": "root", "execution_id": "worker", "epoch": 1,
            "profile_digest": self.orientation.snapshot("root")["profile_digest"],
            "observed_at": 100, "evidence_digest": digest("effect"), "observer_id": "sink", "outcome": "CONFIRMED"})
        self.now = 109
        self.project(action("b"), edge="back")
        self.support("b")
        self.assertIsNone(self.check("b"))
        self.attest(verdict="VETO", action_id="a", valid_until=119)
        self.assertEqual(self.check("b"), "OBSERVER_RING_VETO")
        self.assertEqual(self.authority.reserve(action("b"), channel="egress")["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.orientation.snapshot("root")["occurrences"][0]["status"], "CONFIRMED")
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_veto_holds_existing_and_future_descendants_but_not_independent_sibling(self):
        self.install()
        self.authority.bind_execution("root", "existing-child", parent_execution_id="worker")
        self.orientation.seed("root", "existing-child", "center", evidence_digest=digest("child"), observed_at=self.now)
        existing = action("existing-action", "existing-child")
        self.project(existing)
        self.support(existing["action_id"])
        self.project()
        self.attest(verdict="VETO")
        self.assertEqual(self.authority.reserve(existing, channel="egress")["reason"], "OBSERVER_RING_VETO")
        self.authority.bind_execution("root", "future-child", parent_execution_id="worker")
        self.orientation.seed("root", "future-child", "center", evidence_digest=digest("new-child"), observed_at=self.now)
        future = action("future-action", "future-child")
        self.project(future)
        self.support(future["action_id"])
        self.assertEqual(self.authority.reserve(future, channel="egress")["reason"], "OBSERVER_RING_VETO")
        self.authority.bind_execution("root", "independent-sibling")
        self.orientation.seed("root", "independent-sibling", "center", evidence_digest=digest("sibling"), observed_at=self.now)
        sibling = action("sibling-action", "independent-sibling")
        self.project(sibling)
        self.support(sibling["action_id"])
        self.assertEqual(self.authority.reserve(sibling, channel="egress")["status"], "ADMITTED")
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_invalid_or_cyclic_lineage_fails_closed(self):
        self.install()
        self.authority.bind_execution("root", "child", parent_execution_id="worker")
        self.orientation.seed("root", "child", "center", evidence_digest=digest("child"), observed_at=self.now)
        value = action("child-action", "child")
        self.project(value)
        self.support(value["action_id"])
        with connect(self.path) as db:
            db.execute("UPDATE brakes_executions SET parent_execution_id='missing' WHERE execution_id='child'")
        self.assertEqual(self.check(value["action_id"]), "OBSERVER_RING_LINEAGE_MISMATCH")
        with connect(self.path) as db:
            db.execute("UPDATE brakes_executions SET parent_execution_id='child' WHERE execution_id='child'")
            db.execute("UPDATE executions SET parent_execution_id='child' WHERE execution_id='child'")
        self.assertEqual(self.check(value["action_id"]), "OBSERVER_RING_LINEAGE_MISMATCH")

    def test_full_history_does_not_drop_late_safety_signal(self):
        self.install(max_attestations=3)
        self.project()
        self.support()
        self.assertIsNone(self.check())
        with self.assertRaisesRegex(ControlError, "ATTESTATION_LIMIT"):
            self.attest(verdict="VETO")
        self.assertEqual(self.check(), "OBSERVER_RING_ATTESTATION_LIMIT")
        snapshot = self.ring.snapshot("root")
        self.assertEqual(len(snapshot["attestations"]), 3)
        self.assertIsNotNone(snapshot["hold"])
        self.assertEqual(self.authority.reserve(action(), channel="egress")["reason"], "OBSERVER_RING_ATTESTATION_LIMIT")

    def test_concurrent_assessments_cannot_replace_each_other(self):
        self.install()
        self.project()
        barrier = threading.Barrier(2)
        results = []
        def run(verdict):
            barrier.wait()
            try:
                self.attest(verdict=verdict)
                results.append("stored")
            except ControlError as error:
                results.append(str(error))
        threads = [threading.Thread(target=run, args=(verdict,)) for verdict in ("SUPPORT", "UNKNOWN")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ["stored", "OBSERVER_RING_ATTESTATION_IMMUTABLE"])
        self.assertEqual(len(self.ring.snapshot("root")["attestations"]), 1)

    def test_clock_rollback_closes_authority_before_observer_write(self):
        self.install()
        self.project()
        self.support()
        self.now = 99
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            self.attest(verdict="VETO")
        self.assertEqual(self.authority.status("root")["status"], "CLOCK_UNSAFE")
        self.assertEqual(self.check(), "CLOCK_UNSAFE")

    def test_snapshot_is_read_only_history_not_a_permission(self):
        self.install()
        self.project()
        self.support()
        initial = self.ring.snapshot("root")
        self.now = 105
        again = self.ring.snapshot("root")
        self.assertEqual(initial["attestations"], again["attestations"])
        self.assertFalse(again["execution_authorized"])
        self.assertTrue(again["downstream_gates_required"])
        self.assertEqual(again["evaluated_at"], 105)
        self.assertIsNone(again["coverage"][0]["reason"])
        self.now = 110
        self.assertEqual(self.ring.snapshot("root")["coverage"][0]["reason"], "OBSERVER_RING_ATTESTATION_STALE")
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT last_now FROM brakes_sessions").fetchone()[0], 100)

    def test_snapshot_clock_failure_and_rollback_hold_without_mutation(self):
        self.install()
        self.project()
        self.support()
        self.now = 99
        self.assertEqual(self.ring.snapshot("root")["coverage"][0]["reason"], "CLOCK_UNSAFE")
        self.now = float("nan")
        snapshot = self.ring.snapshot("root")
        self.assertIsNone(snapshot["evaluated_at"])
        self.assertEqual(snapshot["coverage"][0]["reason"], "CLOCK_UNSAFE")
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT state FROM brakes_sessions").fetchone()[0], "ACTIVE")

    def test_hook_requires_transaction_and_unconfigured_root_stays_compatible(self):
        with connect(self.path) as db:
            with self.assertRaisesRegex(ControlError, "requires transaction"):
                check_in_transaction(db, "unknown", now=100, root_id="root")
            db.execute("BEGIN IMMEDIATE")
            self.assertIsNone(check_in_transaction(db, "unknown", now=100, root_id="root"))


if __name__ == "__main__":
    unittest.main()
