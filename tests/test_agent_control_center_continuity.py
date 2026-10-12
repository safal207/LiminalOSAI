"""Real SQLite checks for observed history, projected futures and moving centers."""
import json
from pathlib import Path
import tempfile
import unittest

from sdk.liminal_agent_control.authority import ControlError, connect, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.center_continuity import CenterContinuityStore
from sdk.liminal_agent_control.orientation import OrientationStore
from sdk.liminal_agent_control.orientation_guidance import guidance


def orientation_profile():
    return {"nodes": [{"node_id": n, "space_id": "owned", "phase": n} for n in ("c1", "c2", "work")],
            "edges": [{"edge_id": name, "source": source, "destination": destination, "channel": "egress"}
                      for name, source, destination in (("out", "c1", "work"), ("back", "work", "c1"),
                          ("next", "c1", "c2"), ("old", "c2", "c1"), ("out2", "c2", "work"),
                          ("back2", "work", "c2"), ("loop", "work", "work"), ("review", "c1", "c1"),
                          ("review2", "c2", "c2"))],
            "center_nodes": ["c1", "c2"], "max_steps": 30, "max_visits": 30, "max_away_steps": 30,
            "max_observation_age_seconds": 100, "observers": {"records": "receiver", "egress": "sink"}}


def center_profile(**updates):
    result = {"windows": [{"center_id": "a", "previous_center_id": None, "starts_at": 100,
                           "ends_at": 140, "center_nodes": ["c1"]},
                          {"center_id": "b", "previous_center_id": "a", "starts_at": 140,
                           "ends_at": 280, "center_nodes": ["c2"]}],
              "max_past_age_seconds": 100, "max_future_horizon_seconds": 20,
              "max_transition_seconds": 20, "max_away_seconds": 10, "max_idle_seconds": 30,
              "progress_edge_ids": ["out", "out2"], "max_ideas": 30}
    result.update(updates)
    return result


def action(name="a", execution="worker"):
    return {"action_id": name, "attempt_id": "try:" + name, "root_id": "root", "execution_id": execution,
            "epoch": 1, "target": "network", "arguments": {"request_sha256": digest(name)}}


class CenterContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "control.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.authority.create_session("root", controller_id="host", policy_digest=digest("policy"),
            objective_digest=digest("objective"), max_actions=50, max_executions=4, max_depth=1,
            max_stages=50, lifetime_seconds=200, lease_seconds=200)
        self.authority.bind_execution("root", "worker")
        self.orientation = OrientationStore(self.authority)
        self.orientation_digest = self.orientation.install("root", orientation_profile())["profile_digest"]
        self.center = CenterContinuityStore(self.authority)

    def install(self, **updates):
        self.center.install("root", center_profile(**updates))
        self.orientation.seed("root", "worker", "c1", evidence_digest=digest("seed"), observed_at=self.now)

    def snapshot(self):
        return self.center.snapshot("root")

    def state(self):
        return self.snapshot()["states"][0]

    def project(self, value, edge="out", **updates):
        state = self.state()
        self.orientation.prepare(value, edge_id=edge, expected_revision=state["revision"])
        idea_id = "idea:" + value["action_id"]
        self.center.record_idea("root", value["execution_id"], idea_id, digest(idea_id), state["head_hash"])
        args = {"edge_id": edge, "expected_revision": state["revision"], "predecessor_hash": state["head_hash"],
                "idea_id": idea_id, "not_before": self.now, "deadline": min(self.now + 8, 140 if self.now < 140 else 280)}
        args.update(updates)
        return self.center.project(value, **args)

    def observe(self, value, outcome="CONFIRMED", **updates):
        obs = {key: value[key] for key in ("action_id", "root_id", "execution_id", "epoch")}
        obs.update(action_digest=digest(value), profile_digest=self.orientation_digest,
                   observed_at=self.now, evidence_digest=digest("effect:" + value["action_id"] + outcome),
                   observer_id="sink", outcome=outcome)
        obs.update(updates)
        return self.orientation.observe(value["action_id"], observation=obs)

    def complete(self, value, edge="out"):
        self.project(value, edge)
        self.assertEqual(self.authority.reserve(value, channel="egress")["status"], "ADMITTED")
        self.authority.finish_action(value["action_id"], outcome="RETURNED")
        self.observe(value)

    def test_profile_rejects_gap_overlap_broken_parent_and_noncenter(self):
        for mutate in (lambda p: p["windows"][1].update(starts_at=141),
                       lambda p: p["windows"][1].update(starts_at=139),
                       lambda p: p["windows"][1].update(previous_center_id="wrong"),
                       lambda p: p["windows"][0].update(center_nodes=["work"]),
                       lambda p: p.update(max_away_seconds=float("nan"))):
            profile = center_profile()
            mutate(profile)
            with self.subTest(profile=profile), self.assertRaises((ControlError, ValueError)):
                self.center.install("root", profile)
        self.install()
        with self.assertRaisesRegex(ControlError, "immutable"):
            self.center.install("root", center_profile())

    def test_profile_must_precede_seed(self):
        self.orientation.seed("root", "worker", "c1", evidence_digest=digest("seed"), observed_at=100)
        with self.assertRaisesRegex(ControlError, "precede seeds"):
            self.center.install("root", center_profile())

    def test_ideas_are_not_observations_and_do_not_refresh_progress_or_head(self):
        self.install(max_ideas=2)
        before = self.state()
        self.now = 105
        idea = self.center.record_idea("root", "worker", "idea", digest("proposal"), before["head_hash"])
        self.assertFalse(idea["execution_authorized"])
        self.assertEqual(self.state()["head_hash"], before["head_hash"])
        self.assertEqual(self.state()["last_observed_at"], 100)
        self.assertEqual(self.state()["last_progress_at"], 100)
        self.assertEqual(len(self.snapshot()["events"]), 1)
        self.now = 106
        retried = self.center.record_idea("root", "worker", "idea", digest("proposal"), before["head_hash"])
        self.assertEqual((idea["recorded_at"], retried["recorded_at"]), (105, 105))
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            self.center.record_idea("root", "worker", "idea", digest("changed"), before["head_hash"])
        self.center.record_idea("root", "worker", "second", digest("second"), before["head_hash"])
        with self.assertRaisesRegex(ControlError, "IDEA_LIMIT"):
            self.center.record_idea("root", "worker", "third", digest("third"), before["head_hash"])

    def test_projection_required_and_never_admits_or_advances_by_itself(self):
        self.install()
        value = action()
        self.orientation.prepare(value, edge_id="out", expected_revision=0)
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_PROJECTION_REQUIRED")
        projected = self.project(value)
        self.assertFalse(projected["execution_authorized"])
        self.assertEqual(self.state()["sequence"], 1)
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        changed = {**projected, "deadline": projected["deadline"] + 1}
        with self.assertRaisesRegex(ControlError, "IMMUTABLE"):
            self.center.project(value, **{k: changed[k] for k in ("edge_id", "expected_revision", "predecessor_hash", "idea_id", "not_before", "deadline")})

    def test_confirmed_effect_forms_hash_linked_chain_and_rejects_old_parent(self):
        self.install()
        head = self.state()["head_hash"]
        self.complete(action())
        events = self.snapshot()["events"]
        self.assertEqual([e["kind"] for e in events], ["SEED", "ADMITTED", "OBSERVED"])
        self.assertEqual(events[1]["parent_hash"], events[0]["event_hash"])
        self.assertEqual(events[2]["parent_hash"], events[1]["event_hash"])
        self.assertEqual((self.state()["node_id"], self.state()["revision"]), ("work", 1))
        with self.assertRaisesRegex(ControlError, "PREDECESSOR"):
            self.center.record_idea("root", "worker", "old", digest("old"), head)
        self.assertEqual(self.state()["diagnosis"], "READY_FOR_RECHECK")

    def test_window_crossing_denies_old_projection_without_budget_spending(self):
        self.install(max_idle_seconds=100)
        self.now = 139
        value = action()
        self.project(value, deadline=140)
        self.now = 140
        denied = self.authority.reserve(value, channel="egress")
        self.assertEqual(denied["reason"], "CENTER_WINDOW_CLOSED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.state()["active_center_id"], "b")
        self.assertEqual(self.snapshot()["events"][0]["center_id"], "a")

    def test_stage_cannot_cross_deadline_or_center_window(self):
        self.install(max_idle_seconds=100)
        self.now = 139
        value = action()
        self.project(value, deadline=140)
        self.authority.reserve(value, channel="egress")
        self.now = 140
        self.assertEqual(self.authority.begin_stage("a", stage_id="dispatch")["reason"], "CENTER_WINDOW_CLOSED")
        self.assertEqual(self.authority.status("root")["stage_count"], 0)

    def test_exclusive_deadline_and_not_before(self):
        self.install()
        value = action()
        self.project(value, not_before=102, deadline=104)
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_NOT_BEFORE")
        self.now = 104
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_TRANSITION_EXPIRED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_projection_rejects_future_horizon_and_crossing_window(self):
        self.install()
        for deadlines in ({"deadline": 121}, {"not_before": 120, "deadline": 141}, {"deadline": 100}):
            with self.subTest(deadlines=deadlines), self.assertRaisesRegex(ControlError, "TIME_BOUNDS"):
                self.project(action(), **deadlines)

    def test_away_elapsed_allows_only_return_without_refunding_budget(self):
        self.install()
        self.complete(action("out"))
        self.now = 110
        looping = action("loop")
        self.project(looping, "loop")
        self.assertEqual(self.authority.reserve(looping, channel="egress")["reason"], "CENTER_RETURN_REQUIRED")
        self.complete(action("back"), "back")
        self.assertIsNone(self.state()["away_since"])
        self.assertEqual(self.state()["last_progress_at"], 100)
        self.assertEqual(self.authority.status("root")["action_count"], 2)

    def test_review_loop_and_ideas_cannot_reset_stagnation(self):
        self.install()
        for at in (105, 115, 125):
            self.now = at
            self.complete(action("review" + str(at)), "review")
        self.assertEqual(self.state()["last_progress_at"], 100)
        self.assertEqual(self.state()["last_observed_at"], 125)
        self.now = 130
        value = action("real-work")
        self.project(value)
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_STAGNATION_HOLD")
        self.assertEqual(self.authority.status("root")["action_count"], 3)

    def test_stagnant_outside_can_return_then_holds_at_center(self):
        self.install(max_away_seconds=100)
        self.complete(action("out"))
        self.now = 130
        self.complete(action("back"), "back")
        self.assertEqual(self.state()["diagnosis"], "CENTER_STAGNATION_HOLD")
        self.assertEqual(self.state()["last_progress_at"], 100)

    def test_late_return_preserves_fact_but_does_not_recenter_or_restore_progress(self):
        self.install()
        self.complete(action("out"))
        self.now = 101
        value = action("back")
        self.project(value, "back", deadline=105)
        self.authority.reserve(value, channel="egress")
        self.authority.finish_action("back", outcome="RETURNED")
        self.now = 105
        self.observe(value)
        state = self.state()
        self.assertEqual((state["node_id"], state["revision"]), ("c1", 2))
        self.assertEqual(state["hold_reason"], "CENTER_LATE_OBSERVATION_HOLD")
        self.assertEqual((state["away_since"], state["last_progress_at"]), (100, 100))
        self.assertEqual(self.orientation.snapshot("root")["executions"][0]["away_steps"], 1)
        self.assertFalse(self.snapshot()["events"][-1]["details"]["timely"])
        with self.assertRaisesRegex(ControlError, "LATE_OBSERVATION"):
            self.project(action("new"))

    def test_unknown_is_recorded_without_progress_then_confirmed_once(self):
        self.install()
        value = action()
        self.project(value)
        self.authority.reserve(value, channel="egress")
        self.authority.finish_action("a", outcome="UNKNOWN")
        self.observe(value, "UNKNOWN")
        self.assertEqual(self.state()["node_id"], "c1")
        self.now = 102
        self.observe(value)
        self.assertEqual(self.state()["node_id"], "work")
        self.assertEqual(self.state()["last_progress_at"], 102)
        self.assertEqual(self.state()["sequence"], 4)
        self.observe(value)
        self.assertEqual(self.state()["sequence"], 4)

    def test_after_stop_return_preserves_fact_without_resetting_checkpoint_or_progress(self):
        self.install()
        self.complete(action("out"))
        self.now = 102
        value = action("back")
        self.project(value, "back")
        self.authority.reserve(value, channel="egress")
        self.authority.finish_action("back", outcome="RETURNED")
        self.authority.stop("root")
        self.observe(value)
        state = self.state()
        self.assertEqual((state["node_id"], state["last_observed_at"]), ("c1", 102))
        self.assertEqual((state["away_since"], state["last_progress_at"]), (100, 100))
        self.assertEqual(state["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual(self.authority.status("root")["status"], "STOPPED")
        self.assertFalse(self.snapshot()["events"][-1]["details"]["timely"])

    def test_corrupt_history_denies_and_persists_hold_on_reopen(self):
        self.install()
        value = action()
        self.project(value)
        with connect(self.path) as db:
            db.execute("UPDATE center_events SET parent_hash=?", (digest("wrong"),))
        reopened = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.reserve(value, channel="egress")["reason"], "CENTER_CHAIN_BROKEN")
        self.assertEqual(self.state()["hold_reason"], "CENTER_CHAIN_BROKEN")
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_changed_state_timer_is_detected_as_broken_history(self):
        self.install()
        value = action()
        self.project(value)
        with connect(self.path) as db:
            db.execute("UPDATE center_states SET last_progress_at=120")
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_CHAIN_BROKEN")

    def test_schedule_moving_onto_agent_cannot_erase_away_time_or_verify_checkpoint(self):
        self.install(max_idle_seconds=150)
        self.complete(action("next"), "next")
        self.assertEqual((self.state()["away_since"], self.state()["checkpoint_center_id"]), (100, "a"))
        self.now = 140
        value = action("leave-new-center")
        self.project(value, "old")
        self.assertEqual(self.authority.reserve(value, channel="egress")["reason"], "CENTER_REORIENTATION_REQUIRED")
        self.assertEqual((self.state()["away_since"], self.state()["checkpoint_center_id"]), (100, "a"))
        self.assertEqual(self.state()["diagnosis"], "CENTER_REORIENTATION_REQUIRED")
        self.now = 141
        self.complete(action("verify-new-center"), "review2")
        self.assertEqual((self.state()["away_since"], self.state()["checkpoint_center_id"]), (None, "b"))
        self.assertEqual(self.state()["last_progress_at"], 100)

    def test_snapshot_rejects_clock_rollback_relative_to_session_not_only_observation(self):
        self.install()
        self.now = 110
        self.center.record_idea("root", "worker", "fresh-idea", digest("idea"), self.state()["head_hash"])
        self.now = 105
        self.assertEqual(self.state()["diagnosis"], "CLOCK_UNSAFE")
        self.assertEqual(self.state()["last_observed_at"], 100)

    def test_center_bound_review_cannot_be_declared_progress(self):
        with self.assertRaisesRegex(ControlError, "cannot count as progress"):
            self.center.install("root", center_profile(progress_edge_ids=["review"]))

    def test_malformed_history_remains_visible_as_broken_in_snapshot(self):
        self.install()
        with connect(self.path) as db:
            db.execute("UPDATE center_events SET event_json='broken JSON'")
        snapshot = self.snapshot()
        self.assertEqual(snapshot["states"][0]["diagnosis"], "CENTER_CHAIN_BROKEN")
        self.assertTrue(snapshot["events"][0]["invalid_payload"])

    def test_cross_agent_parent_does_not_merge_trajectories(self):
        self.install()
        self.authority.bind_execution("root", "other")
        self.orientation.seed("root", "other", "c1", evidence_digest=digest("other"), observed_at=100)
        other = next(s for s in self.snapshot()["states"] if s["execution_id"] == "other")
        worker = next(s for s in self.snapshot()["states"] if s["execution_id"] == "worker")
        self.assertNotEqual(worker["head_hash"], other["head_hash"])
        with self.assertRaisesRegex(ControlError, "PREDECESSOR"):
            self.center.record_idea("root", "other", "cross", digest("cross"), worker["head_hash"])

    def test_guidance_requires_center_context_and_remains_non_authorizing(self):
        self.install()
        graph, status = self.orientation.snapshot("root"), self.authority.status("root")
        graph["requires_center_context"] = True
        self.assertEqual(guidance(graph, status, "worker")["reason"], "CENTER_CONTEXT_REQUIRED")
        advice = guidance(graph, status, "worker", continuity_snapshot=self.snapshot())
        self.assertEqual(advice["disposition"], "TRANSITION_CANDIDATE")
        self.assertFalse(advice["execution_authorized"])
        self.assertTrue(advice["downstream_gates_required"])

    def test_guidance_recomputes_current_center_from_time_not_cached_active_window(self):
        self.install(max_idle_seconds=100)
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        self.assertEqual(continuity["active_center"]["center_id"], "a")
        self.now = 140
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual(advice["active_center_id"], "b")
        self.assertEqual(advice["disposition"], "RETURN_CANDIDATE")
        self.assertEqual([e["edge_id"] for e in advice["candidates"]], ["next"])

    def test_guidance_rechecks_elapsed_away_and_excludes_old_or_future_center(self):
        self.install()
        self.complete(action("out"))
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        self.now = 110
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual([e["edge_id"] for e in advice["candidates"]], ["back"])
        self.assertEqual(advice["disposition"], "RETURN_CANDIDATE")

    def test_guidance_rechecks_stagnation_at_fresh_authority_time(self):
        self.install()
        self.now = 125
        self.complete(action("review"), "review")
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        self.assertEqual(continuity["states"][0]["diagnosis"], "READY_FOR_RECHECK")
        self.now = 130
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual((advice["disposition"], advice["reason"], advice["candidates"]),
                         ("HOLD", "CENTER_STAGNATION_HOLD", []))

    def test_guidance_rejects_wrong_roots_bindings_and_schedule_digest(self):
        self.install()
        graph, status, continuity = self.orientation.snapshot("root"), self.authority.status("root"), self.snapshot()
        graph["center_profile_digest"] = continuity["profile_digest"]
        for key, value in (("root_id", "other"), ("epoch", 2), ("policy_digest", digest("wrong")),
                           ("objective_digest", digest("wrong")), ("orientation_profile_digest", digest("wrong")),
                           ("profile_digest", digest("wrong"))):
            changed = {**continuity, key: value}
            with self.subTest(key=key):
                self.assertEqual(guidance(graph, status, "worker", continuity_snapshot=changed)["reason"],
                                 "CENTER_CONTEXT_BINDING_MISMATCH")
        changed = json.loads(json.dumps(continuity))
        changed["states"][0]["root_id"] = "other"
        self.assertEqual(guidance(graph, status, "worker", continuity_snapshot=changed)["reason"],
                         "CENTER_CONTEXT_BINDING_MISMATCH")
        wrong_actor = json.loads(json.dumps(graph))
        wrong_actor["executions"][0]["root_id"] = "other"
        advice = guidance(wrong_actor, status, "worker", continuity_snapshot=continuity)
        self.assertEqual(advice["reason"], "ORIENTATION_STATE_BINDING_MISMATCH")
        self.assertNotIn("node_id", advice)

    def test_guidance_rejects_future_snapshot_and_negative_authority_clock(self):
        self.install()
        graph, status, continuity = self.orientation.snapshot("root"), self.authority.status("root"), self.snapshot()
        future = {**continuity, "snapshot_at": status["last_now"] + 1}
        self.assertEqual(guidance(graph, status, "worker", continuity_snapshot=future)["reason"], "CLOCK_UNSAFE")
        self.assertEqual(guidance(graph, {**status, "last_now": -1}, "worker", continuity_snapshot=continuity)["reason"], "CLOCK_UNSAFE")

    def test_guidance_keeps_broken_history_and_stale_past_on_hold(self):
        self.install(max_past_age_seconds=5)
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        self.now = 106
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual(advice["reason"], "CENTER_PAST_STALE")
        with connect(self.path) as db:
            db.execute("UPDATE center_events SET event_json='broken'")
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=self.snapshot())
        self.assertEqual(advice["reason"], "CENTER_CHAIN_BROKEN")

    def test_guidance_propagates_known_observer_veto_without_candidates(self):
        self.install()
        graph = self.orientation.snapshot("root")
        graph["executions"][0]["observer_hold_reason"] = "OBSERVER_VETO_HOLD"
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=self.snapshot())
        self.assertEqual((advice["disposition"], advice["reason"], advice["candidates"]),
                         ("HOLD", "OBSERVER_VETO_HOLD", []))

    def test_guidance_recomputes_cached_stagnation_when_center_window_changes(self):
        self.install()
        self.now = 130
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        self.assertEqual(continuity["states"][0]["diagnosis"], "CENTER_STAGNATION_HOLD")
        self.now = 140
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual(advice["disposition"], "RETURN_CANDIDATE")
        self.assertEqual(advice["active_center_id"], "b")
        self.assertEqual([e["edge_id"] for e in advice["candidates"]], ["next"])

    def test_guidance_malformed_continuity_state_returns_hold(self):
        self.install()
        graph, continuity = self.orientation.snapshot("root"), self.snapshot()
        continuity["states"] = [None]
        advice = guidance(graph, self.authority.status("root"), "worker", continuity_snapshot=continuity)
        self.assertEqual((advice["disposition"], advice["reason"], advice["candidates"]),
                         ("HOLD", "CENTER_CONTEXT_INVALID", []))


if __name__ == "__main__":
    unittest.main()
