"""Required G03 orientation veto with signed loopback HTTP and real SQLite.

The external authorities, receiver, signatures and sidecar are real. Bridge,
command lifecycle and watcher-health snapshots are explicit test doubles, not
Docker containment evidence. A local admission check does not replace the receiver transaction or
prove universal escape resistance, and no receipt auto-advances orientation.
"""
from __future__ import annotations

import concurrent.futures
from contextlib import contextmanager
import copy
import json
import sqlite3
import sys
import threading
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.center_continuity import CenterContinuityStore
from sdk.liminal_agent_control.external_agent_coordinator import agent_policy_digest
from sdk.liminal_agent_control.external_agent_launch import ClosedChannelLaunchGate, build_channel_inventory
from sdk.liminal_agent_control.external_agent_orientation import (
    ORIENTATION_STAGE, OrientationAdmissionGuard, OrientationFencedEffectGateway,
)
from sdk.liminal_agent_control.external_agent_receiver_gateway import ReceiverFencedEffectGateway
from sdk.liminal_agent_control.orientation import OrientationStore
import tests.test_agent_control_external_agent_receiver_integration as receiver_fixture
import tests.test_agent_control_external_agent_effect_gateway as dispatch_fixture


def orientation_profile():
    return {
        "nodes": [{"node_id": "center", "space_id": "owned", "phase": "verified"},
                  {"node_id": "work", "space_id": "owned", "phase": "active"}],
        "edges": [{"edge_id": "out", "source": "center", "destination": "work", "channel": "egress"},
                  {"edge_id": "back", "source": "work", "destination": "center", "channel": "egress"}],
        "center_nodes": ["center"], "max_steps": 10, "max_visits": 10,
        "max_away_steps": 3, "max_observation_age_seconds": 30,
        "observers": {"records": "owned-record-observer", "egress": "owned-g03-observer"},
    }


def center_profile():
    return {
        "windows": [{"center_id": "owned-center", "previous_center_id": None,
                     "starts_at": 100, "ends_at": 300, "center_nodes": ["center"]}],
        "max_past_age_seconds": 30, "max_future_horizon_seconds": 20,
        "max_transition_seconds": 10, "max_away_seconds": 20,
        "max_idle_seconds": 30, "progress_edge_ids": ["out"], "max_ideas": 10,
    }


class ReceiverSnapshotCoordinator(dispatch_fixture.SnapshotCoordinator):
    """Explicit health snapshots plus the real receiver STOP route."""

    def _stop_receiver(self):
        return self.receiver_fence_client.stop(self.run_binding["effect"]["root_id"])


class ExternalAgentOrientationTests(unittest.TestCase):
    # Reuse only setup/server helpers; inheriting the fixture would silently
    # duplicate its entire regression suite in test discovery.
    start_server = receiver_fixture.ExternalAgentReceiverIntegrationTests.start_server
    serve_authority = receiver_fixture.ExternalAgentReceiverIntegrationTests.serve_authority
    shutdown = receiver_fixture.ExternalAgentReceiverIntegrationTests.shutdown

    def setUp(self):
        receiver_fixture.ExternalAgentReceiverIntegrationTests.setUp(self)
        self._counter = 0
        self.context = self.make_context()

    def make_context(self, *, install_orientation=True, install_center=True,
                     seed=True, prepare=True, idea=True, projection=True, **session_updates):
        self._counter += 1
        prefix = "orientation-" + str(self._counter)
        clock = [100.0]
        authority = SessionAuthority(self.directory / (prefix + ".sqlite"), clock=lambda: clock[0])
        settings = {
            "controller_id": "owned-host", "policy_digest": agent_policy_digest(self.binding, "effect"),
            "objective_digest": digest("owned-g03-objective"), "max_actions": 10,
            "max_executions": 3, "max_depth": 1, "max_stages": 10,
            "lifetime_seconds": 1000, "lease_seconds": 1000,
        }
        settings.update(session_updates)
        authority.create_session("effect-root", **settings)
        authority.bind_execution("effect-root", "effect-worker")
        orientation, center = OrientationStore(authority), CenterContinuityStore(authority)
        if install_orientation:
            orientation.install("effect-root", orientation_profile())
        if install_center:
            center.install("effect-root", center_profile())
        if seed and install_orientation:
            orientation.seed("effect-root", "effect-worker", "center",
                             evidence_digest=digest("owned-g03-seed"), observed_at=clock[0])
        if prepare and seed and install_orientation:
            orientation.prepare(self.action, edge_id="out", expected_revision=0)
        if seed and install_center:
            head = center.snapshot("effect-root")["states"][0]["head_hash"]
            if idea:
                center.record_idea("effect-root", "effect-worker", "owned-idea",
                                   digest(self.action), head)
            if projection and idea and prepare:
                center.project(self.action, edge_id="out", expected_revision=0,
                               predecessor_hash=head, idea_id="owned-idea", not_before=100, deadline=108)
        return {"authority": authority, "orientation": orientation, "center": center,
                "clock": clock, "prefix": prefix}

    def guard(self, context=None):
        return OrientationAdmissionGuard((context or self.context)["authority"], run_binding=self.binding)

    def gateway_arguments(self):
        return {"run_binding": self.binding, "gateway_id": "orientation-gateway",
                "external_controller": self.effect_receiver, "endpoint_client": self.endpoint,
                "operator_key": b"go" * 16, "worker_key": b"gw" * 16}

    def make_gateway(self, context=None):
        context = context or self.context
        guard = self.guard(context)
        path = self.directory / (context["prefix"] + "-gateway.sqlite")
        gateway = OrientationFencedEffectGateway(path, orientation_guard=guard, **self.gateway_arguments())
        gateway.authorize(self.action, self.authorization)
        bridge_configuration = {
            "run_binding": {"run_id": "receiver-run", "root_id": "effect-root",
                            "execution_id": "effect-worker", "epoch": 1},
            "actions": [self.action], "effect_gateway_configuration": json.loads(gateway._configuration()),
            "admission_observer_required": True, "owned_run_binding_digest": digest(self.binding),
            "owned_command_binding": {key: self.binding["command"][key]
                                      for key in ("root_id", "execution_id", "epoch")},
        }
        inputs = {"spec": self.spec, "run_binding": self.binding,
                  "bridge_configuration": bridge_configuration,
                  "command_authority_url": self.command_admin.url,
                  "effect_authority_url": self.effect_admin.url}
        gate = ClosedChannelLaunchGate(**inputs, channels=build_channel_inventory(**inputs))
        # The gate and route identities are real. Command/Docker lifecycle and
        # watcher-health observations are explicitly supplied test snapshots.
        bridge = dispatch_fixture.SnapshotBridge(bridge_configuration, gateway)
        supervisor = dispatch_fixture.SnapshotSupervisor(gate, self.binding, bridge, self.command_receiver)
        coordinator = ReceiverSnapshotCoordinator(
            self.binding, supervisor, bridge, gateway, self.command_admin, self.effect_admin)
        coordinator.receiver_fence_client = self.endpoint
        gate.bind(coordinator)
        gateway.bind_launch_gate(gate)
        context.update(guard=guard, gateway=gateway, coordinator=coordinator, bridge=bridge, path=path)
        return gateway

    def rows(self, context, table):
        self.assertIn(table, {"brakes_actions", "brakes_stages", "orientation_tickets",
                              "orientation_states", "orientation_occurrences", "orientation_observations",
                              "center_ideas", "center_projections", "center_states", "center_events"})
        with sqlite3.connect(context["authority"].db_path) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM " + table)]

    def no_external_begin_or_post(self, result):
        self.assertEqual(result["status"], "DENIED", result)
        self.assertIsNone(result["reservation_id"])
        self.assertIsNone(result["receipt"])
        root = self.effect_store.status("effect-root")
        self.assertEqual((root["issued_count"], root["pending_count"]), (0, 0))
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 0)
        self.assertEqual(self.receiver.inventory()["effects"], [])
        self.assertFalse(result["execution_authorized"])

    def retained_unknown(self, result):
        self.assertEqual(result["status"], "UNKNOWN", result)
        self.assertIsNotNone(result["reservation_id"])
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["effect_count"])
        self.assertIsNone(result["remote_outcome"])
        self.assertFalse(result["dispatch_finished"])
        self.assertFalse(result["execution_authorized"])
        root = self.effect_store.status("effect-root")
        self.assertEqual((root["issued_count"], root["pending_count"]), (1, 1))
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 0)
        pending = self.effect_receiver.query(self.action["action_id"])
        self.assertEqual(pending["reservation_id"], result["reservation_id"])
        self.assertIsNone(pending["receipt"])
        self.assertEqual(self.receiver.inventory()["terminals"], [])

    @contextmanager
    def _execute_with_blocked_orientation_writer(self, target, closure):
        fixture = ExternalAgentOrientationTests("test_positive_commit_does_not_auto_complete_or_advance_local_trajectory")
        fixture.setUp()
        context = fixture.context
        gateway = fixture.make_gateway(context)
        entered, held, attempted = (threading.Event() for _ in range(3))
        active = False

        def trace(frame, event, argument):
            nonlocal active
            direct_final_check = (target != "check" or (
                frame.f_back.f_code.co_name == "_before_endpoint_commit"
                and frame.f_back.f_code.co_filename.endswith("/external_agent_orientation.py")))
            if (event == "call" and frame.f_code.co_name == target
                    and frame.f_code.co_filename.endswith("/external_agent_orientation.py")
                    and direct_final_check and not entered.is_set()):
                entered.set()
                if not held.wait(3):
                    raise AssertionError("independent sidecar writer was not acquired")
                active = True
            if (active and event == "return" and frame.f_code.co_name == "_connect"
                    and frame.f_code.co_filename.endswith("/brakes_store.py")):
                argument.set_trace_callback(
                    lambda sql: attempted.set() if sql == "BEGIN IMMEDIATE" else None)
            return trace

        def execute():
            # Observe call entry and SQL only. Protected admission routes retain
            # their original identity and execute against real SQLite/HTTP.
            sys.settrace(trace)
            try:
                return gateway.execute(fixture.action)
            finally:
                sys.settrace(None)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(execute)
                try:
                    self.assertTrue(entered.wait(3), "orientation boundary was not reached")
                    with sqlite3.connect(context["authority"].db_path, isolation_level=None) as writer:
                        writer.execute("BEGIN IMMEDIATE")
                        held.set()
                        self.assertTrue(attempted.wait(3), "sidecar writer was not attempted")
                        with self.assertRaises(concurrent.futures.TimeoutError):
                            future.result(timeout=.05)
                        if closure == "bridge":
                            context["bridge"].fence("UNIT_SIDECAR_STORAGE_RACE")
                        elif closure == "coordinator":
                            context["coordinator"].close_admission("UNIT_SIDECAR_STORAGE_RACE")
                        elif closure == "watchdog":
                            context["coordinator"].health_error = ControlError("UNIT_WATCHDOG_DEAD")
                        else:
                            self.assertIsNone(closure)
                        self.assertEqual(writer.execute(
                            "SELECT state FROM brakes_sessions WHERE root_id='effect-root'"
                        ).fetchone()[0], "ACTIVE")
                        writer.rollback()
                finally:
                    # Release the entry rendezvous even if acquiring the writer
                    # or an assertion fails, so the worker cannot be stranded.
                    held.set()
                result = future.result(timeout=5)
            yield fixture, result, context, gateway
        finally:
            fixture.doCleanups()

    def test_gate_rechecked_after_bound_sidecar_writer_before_external_begin(self):
        for closure in (None, "bridge", "coordinator", "watchdog"):
            with self.subTest(closure=closure), self._execute_with_blocked_orientation_writer(
                    "assert_bound", closure) as (fixture, result, context, _):
                if closure is None:
                    self.assertEqual(result["status"], "COMMITTED", result)
                else:
                    fixture.no_external_begin_or_post(result)
                    self.assertEqual(context["authority"].status("effect-root")["action_count"], 0)

    def test_gate_rechecked_after_admit_sidecar_writer_before_external_begin(self):
        for closure in (None, "bridge", "coordinator", "watchdog"):
            with self.subTest(closure=closure), self._execute_with_blocked_orientation_writer(
                    "admit", closure) as (fixture, result, context, _):
                if closure is None:
                    self.assertEqual(result["status"], "COMMITTED", result)
                else:
                    fixture.no_external_begin_or_post(result)
                status = context["authority"].status("effect-root")
                self.assertEqual((status["action_count"], status["pending_action_count"],
                                  status["stage_count"], status["pending_stage_count"]), (1, 1, 1, 1))

    def test_gate_rechecked_after_final_sidecar_writer_blocks_endpoint_post(self):
        for closure in (None, "bridge", "coordinator", "watchdog"):
            with self.subTest(closure=closure), self._execute_with_blocked_orientation_writer(
                    "check", closure) as (fixture, result, context, gateway):
                if closure is None:
                    self.assertEqual(result["status"], "COMMITTED", result)
                else:
                    fixture.retained_unknown(result)
                    events = gateway.inventory()["dispatch_boundary"]["events"]
                    self.assertEqual(events[-1]["result"], "BLOCKED")
                    self.assertEqual(events[-1]["reservation_id"], result["reservation_id"])
                status = context["authority"].status("effect-root")
                self.assertEqual((status["action_count"], status["pending_action_count"],
                                  status["stage_count"], status["pending_stage_count"]), (1, 1, 1, 1))

    def test_required_guard_rejected_before_gateway_database_creation(self):
        for value in (None, object()):
            with self.subTest(value=type(value).__name__):
                path = self.directory / (type(value).__name__ + "-missing-guard.sqlite")
                with self.assertRaisesRegex(ControlError, "AGENT_ORIENTATION_GUARD_REQUIRED"):
                    OrientationFencedEffectGateway(path, orientation_guard=value, **self.gateway_arguments())
                self.assertFalse(path.exists())
        with self.assertRaisesRegex(ControlError, "AGENT_ORIENTATION_GUARD_REQUIRED"):
            OrientationFencedEffectGateway(self.directory / "omitted.sqlite", **self.gateway_arguments())
        self.assertFalse((self.directory / "omitted.sqlite").exists())

    def test_both_profiles_required_despite_legacy_optional_profile_semantics(self):
        for missing in ("orientation", "center"):
            with self.subTest(missing=missing):
                context = self.make_context(install_orientation=missing != "orientation",
                                            install_center=False, seed=False, prepare=False,
                                            idea=False, projection=False)
                path = self.directory / (missing + "-missing-profile.sqlite")
                with self.assertRaisesRegex(ControlError, "PROFILE_REQUIRED"):
                    guard = self.guard(context)
                    OrientationFencedEffectGateway(path, orientation_guard=guard, **self.gateway_arguments())
                self.assertFalse(path.exists())

    def test_patched_guard_method_before_gateway_creation_is_not_trusted(self):
        guard = self.guard()
        path = self.directory / "prepatched-guard.sqlite"
        with patch.object(guard, "check", lambda *args: None):
            with self.assertRaises(ControlError):
                OrientationFencedEffectGateway(path, orientation_guard=guard, **self.gateway_arguments())
        self.assertFalse(path.exists())
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 0)

    def test_guard_for_different_run_is_rejected_before_gateway_creation(self):
        path = self.directory / "wrong-run-guard.sqlite"
        arguments = self.gateway_arguments()
        arguments["run_binding"] = copy.deepcopy(self.binding)
        arguments["run_binding"]["run_id"] = "different-run"
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            OrientationFencedEffectGateway(path, orientation_guard=self.guard(), **arguments)
        self.assertFalse(path.exists())

    def test_session_policy_must_match_exact_effect_run(self):
        context = self.make_context(policy_digest=digest("different-policy"))
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.guard(context)
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 0)

    def test_positive_commit_does_not_auto_complete_or_advance_local_trajectory(self):
        gateway = self.make_gateway()
        before = self.rows(self.context, "center_states")[0]
        result = gateway.execute(self.action)
        self.assertEqual((result["status"], result["remote_outcome"], result["effect_count"]),
                         ("COMMITTED", "COMMITTED", 1))
        self.assertIsNotNone(result["receipt"])
        state = self.context["authority"].status("effect-root")
        self.assertEqual((state["action_count"], state["stage_count"], state["pending_action_count"],
                          state["pending_stage_count"]), (1, 1, 1, 1))
        self.assertEqual(self.rows(self.context, "brakes_stages")[0]["stage_id"], ORIENTATION_STAGE)
        self.assertEqual(self.rows(self.context, "brakes_actions")[0]["status"], "RESERVED")
        self.assertEqual(self.rows(self.context, "center_projections")[0]["status"], "CONSUMED")
        self.assertEqual(self.rows(self.context, "orientation_occurrences")[0]["status"], "PENDING")
        after = self.rows(self.context, "center_states")[0]
        self.assertEqual((after["node_id"], after["revision"], after["last_progress_at"]),
                         (before["node_id"], before["revision"], before["last_progress_at"]))
        self.assertEqual(after["pending_action_id"], self.action["action_id"])
        self.assertEqual(self.rows(self.context, "orientation_observations"), [])
        self.assertEqual([row["sequence"] for row in self.rows(self.context, "center_events")], [1, 2])
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_duplicate_success_never_reserves_or_stages_or_posts_twice(self):
        gateway = self.make_gateway()
        first = gateway.execute(self.action)
        second = gateway.execute(self.action)
        third = gateway.reconcile(self.action["action_id"])
        for result in (first, second, third):
            self.assertEqual(result["status"], "COMMITTED", result)
            self.assertEqual(result["reservation_id"], first["reservation_id"])
            self.assertEqual(result["receipt"], first["receipt"])
        status = self.context["authority"].status("effect-root")
        self.assertEqual((status["action_count"], status["stage_count"]), (1, 1))
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 1)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_host_context_seed_ticket_idea_and_projection_are_not_auto_created(self):
        mutations = {
            "seed": "DELETE FROM orientation_states",
            "center_context": "DELETE FROM center_states",
            "ticket": "DELETE FROM orientation_tickets",
            "idea": "DELETE FROM center_ideas",
            "projection": "DELETE FROM center_projections",
        }
        for missing, statement in mutations.items():
            with self.subTest(missing=missing):
                context = self.make_context()
                gateway = self.make_gateway(context)
                with sqlite3.connect(context["authority"].db_path) as db:
                    db.execute(statement)
                self.no_external_begin_or_post(gateway.execute(self.action))
                table = statement.removeprefix("DELETE FROM ")
                self.assertEqual(self.rows(context, table), [])

    def test_stale_observation_and_expired_projection_deny_before_begin(self):
        for at in (108.0, 131.0):
            with self.subTest(at=at):
                context = self.make_context()
                gateway = self.make_gateway(context)
                context["clock"][0] = at
                self.no_external_begin_or_post(gateway.execute(self.action))
                self.assertEqual(context["authority"].status("effect-root")["action_count"], 0)

    def test_tampered_revision_lineage_and_projection_cannot_admit(self):
        mutations = {
            "revision": "UPDATE orientation_tickets SET expected_revision=1",
            "ticket_lineage": "UPDATE orientation_tickets SET execution_id='other-worker'",
            "ticket_epoch": "UPDATE orientation_tickets SET epoch=2",
            "projection": "UPDATE center_projections SET projection_digest='" + "0" * 64 + "'",
            "projection_parent": "UPDATE center_projections SET predecessor_hash='" + "0" * 64 + "'",
        }
        for name, statement in mutations.items():
            with self.subTest(mutation=name):
                context = self.make_context()
                gateway = self.make_gateway(context)
                with sqlite3.connect(context["authority"].db_path) as db:
                    db.execute(statement)
                self.no_external_begin_or_post(gateway.execute(self.action))

    def test_action_outside_bound_run_never_reaches_authority_or_endpoint(self):
        for field, value in (("root_id", "other-root"), ("execution_id", "other-worker"), ("epoch", 2)):
            with self.subTest(field=field):
                context = self.make_context()
                gateway = self.make_gateway(context)
                proposed = copy.deepcopy(self.action)
                proposed[field] = value
                self.no_external_begin_or_post(gateway.execute(proposed))

    def test_removed_replaced_or_patched_guard_cannot_open_admission(self):
        for mutation in ("missing", "replacement", "admit", "check", "assert_bound", "configuration"):
            with self.subTest(mutation=mutation):
                context = self.make_context()
                gateway = self.make_gateway(context)
                guard = context["guard"]
                if mutation == "missing":
                    change = patch.object(gateway, "orientation_guard", None)
                elif mutation == "replacement":
                    change = patch.object(gateway, "orientation_guard", self.guard(context))
                else:
                    change = patch.object(guard, mutation, lambda *args: None)
                with change:
                    self.no_external_begin_or_post(gateway.execute(self.action))

    def test_replaced_authority_or_live_method_does_not_bypass_guard(self):
        for mutation in ("authority", "reserve", "admit_in_transaction", "begin_stage", "clock"):
            with self.subTest(mutation=mutation):
                context = self.make_context()
                gateway = self.make_gateway(context)
                authority, guard = context["authority"], context["guard"]
                if mutation == "authority":
                    replacement = SessionAuthority(authority.db_path, clock=authority.clock, create=False)
                    change = patch.object(guard, "authority", replacement)
                elif mutation == "clock":
                    change = patch.object(authority, "clock", lambda: 100.0)
                else:
                    change = patch.object(authority, mutation, lambda *args, **kwargs: {"status": "ADMITTED"})
                with change:
                    self.no_external_begin_or_post(gateway.execute(self.action))

    def test_profile_and_objective_binding_changes_fail_closed(self):
        for statement in (
            "UPDATE brakes_sessions SET objective_digest='" + "d" * 64 + "'",
            "UPDATE orientation_profiles SET profile_digest='" + "d" * 64 + "'",
            "UPDATE center_profiles SET objective_digest='" + "d" * 64 + "'",
            "UPDATE brakes_executions SET parent_execution_id='other-parent'",
        ):
            with self.subTest(statement=statement.split(" SET ")[0]):
                context = self.make_context()
                gateway = self.make_gateway(context)
                with sqlite3.connect(context["authority"].db_path) as db:
                    db.execute(statement)
                self.no_external_begin_or_post(gateway.execute(self.action))

    def test_local_stop_before_begin_denies_without_consuming_remote_permit(self):
        gateway = self.make_gateway()
        self.context["authority"].stop("effect-root")
        self.no_external_begin_or_post(gateway.execute(self.action))
        self.assertEqual(self.context["authority"].status("effect-root")["action_count"], 0)

    def test_post_begin_stop_retains_original_consumed_reservation_query_only(self):
        gateway = self.make_gateway()
        gateway.before_dispatch_hook = lambda *args: self.context["authority"].stop("effect-root")
        first = gateway.execute(self.action)
        self.retained_unknown(first)
        retry = gateway.execute(self.action)
        with patch.object(gateway, "orientation_guard", None):
            recovered = gateway.reconcile(self.action["action_id"])
        for result in (retry, recovered):
            self.retained_unknown(result)
            self.assertEqual(result["reservation_id"], first["reservation_id"])
        status = self.context["authority"].status("effect-root")
        self.assertEqual((status["action_count"], status["stage_count"], status["pending_action_count"],
                          status["pending_stage_count"]), (1, 1, 1, 1))
        self.assertEqual(self.rows(self.context, "orientation_occurrences")[0]["status"], "PENDING")

    def test_post_begin_expiry_is_veto_after_original_dispatch_hook(self):
        gateway = self.make_gateway()
        called = []

        def expire_after_begin(*args):
            called.append(self.effect_store.status("effect-root")["issued_count"])
            self.context["clock"][0] = 108.0

        gateway.before_dispatch_hook = expire_after_begin
        result = gateway.execute(self.action)
        self.assertEqual(called, [1])
        self.retained_unknown(result)
        self.assertEqual(self.context["authority"].status("effect-root")["action_count"], 1)

    def test_post_begin_live_guard_removal_cannot_dispatch(self):
        gateway = self.make_gateway()
        guard = gateway.orientation_guard
        gateway.before_dispatch_hook = lambda *args: setattr(gateway, "orientation_guard", None)
        try:
            result = gateway.execute(self.action)
        finally:
            gateway.orientation_guard = guard
        self.retained_unknown(result)

    def test_post_begin_removed_idea_preserves_unknown_and_original_permit(self):
        gateway = self.make_gateway()

        def remove_host_idea(*args):
            with sqlite3.connect(self.context["authority"].db_path) as db:
                db.execute("DELETE FROM center_ideas")

        gateway.before_dispatch_hook = remove_host_idea
        result = gateway.execute(self.action)
        self.retained_unknown(result)
        self.assertEqual(self.rows(self.context, "center_ideas"), [])
        self.assertEqual(self.context["authority"].status("effect-root")["pending_action_count"], 1)

    def test_rehashed_projection_cannot_extend_the_admitted_deadline(self):
        gateway = self.make_gateway()

        def extend_projection_after_admission(*args):
            with sqlite3.connect(self.context["authority"].db_path) as db:
                projection = json.loads(db.execute("SELECT projection_json FROM center_projections").fetchone()[0])
                projection["deadline"] = 109.9
                db.execute("UPDATE center_projections SET projection_json=?,projection_digest=?",
                           (json.dumps(projection), digest(projection)))
            self.context["clock"][0] = 109.0

        gateway.before_dispatch_hook = extend_projection_after_admission
        result = gateway.execute(self.action)
        self.retained_unknown(result)
        self.assertEqual(result["reason"], "CENTER_PROJECTION_MISMATCH")
        admitted = self.rows(self.context, "center_events")[-1]
        self.assertEqual(json.loads(admitted["event_json"])["kind"], "ADMITTED")

    def test_missing_sidecar_database_is_not_recreated_on_admission(self):
        gateway = self.make_gateway()
        path = self.context["authority"].db_path
        path.unlink()
        self.no_external_begin_or_post(gateway.execute(self.action))
        self.assertFalse(path.exists())

    def test_sidecar_loss_after_begin_preserves_pending_and_allows_query_only(self):
        gateway = self.make_gateway()
        path = self.context["authority"].db_path
        gateway.before_dispatch_hook = lambda *args: path.unlink()
        first = gateway.execute(self.action)
        self.retained_unknown(first)
        self.assertFalse(path.exists())
        self.retained_unknown(gateway.reconcile(self.action["action_id"]))
        self.assertFalse(path.exists())

    def test_committed_receipt_reconciles_without_guard_or_sidecar_database(self):
        gateway = self.make_gateway()
        first = gateway.execute(self.action)
        self.assertEqual(first["status"], "COMMITTED", first)
        path = self.context["authority"].db_path
        path.unlink()
        with patch.object(gateway, "orientation_guard", None):
            recovered = gateway.reconcile(self.action["action_id"])
        self.assertEqual(recovered["status"], "COMMITTED", recovered)
        self.assertEqual(recovered["receipt"], first["receipt"])
        self.assertEqual(recovered["reservation_id"], first["reservation_id"])
        self.assertFalse(recovered["dispatch_finished"])
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertFalse(path.exists())

    def test_legacy_gateway_cannot_reopen_required_orientation_contract(self):
        self.make_gateway()
        configuration = json.loads(self.context["gateway"]._configuration())
        self.assertTrue(configuration["orientation_gate"]["required"])
        with self.assertRaises(ControlError):
            ReceiverFencedEffectGateway(self.context["path"], **self.gateway_arguments())
        with sqlite3.connect(self.context["path"]) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM network_gateway_grants").fetchone()[0], 1)

    def test_local_stop_after_final_check_does_not_retroactively_cancel_receiver_commit(self):
        gateway = self.make_gateway()
        # A real endpoint transaction can still commit once a valid permit
        # exists, even if only the local sidecar has since stopped. Its signed
        # receipt is history, not authorization to resume or issue another POST.
        # Exercise the receiver boundary directly after a real sidecar check,
        # without pretending a patched protected route is an accepted profile.
        self.context["guard"].admit(self.action)
        permit = self.effect_receiver.begin(self.action, self.authorization)
        pair = self.effect_receiver.evidence[-1]
        self.assertEqual(permit["status"], "PERMITTED")
        self.context["guard"].check(self.action)
        self.context["authority"].stop("effect-root")
        observed = self.endpoint.commit(self.action, self.authorization, pair["request"], pair["response"])
        self.assertEqual(observed["receipt"]["status"], "COMMITTED")
        self.assertEqual(gateway.reconcile(self.action["action_id"])["status"], "COMMITTED")
        self.assertEqual(self.context["authority"].status("effect-root")["state"], "STOPPED")
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_receiver_stop_still_wins_its_transaction_and_proves_signed_no_effect(self):
        gateway = self.make_gateway()
        gateway.before_dispatch_hook = lambda *args: self.endpoint.stop("effect-root")
        result = gateway.execute(self.action)
        self.assertEqual((result["status"], result["remote_outcome"], result["effect_count"]),
                         ("NO_EFFECT", "NO_EFFECT", 0))
        self.assertEqual(result["receipt"]["status"], "NO_EFFECT")
        self.assertEqual(self.receiver.inventory()["effects"], [])
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        # The independent local trajectory is deliberately not auto-settled.
        self.assertEqual(self.context["authority"].status("effect-root")["pending_action_count"], 1)
        self.assertEqual(self.rows(self.context, "orientation_occurrences")[0]["status"], "PENDING")


if __name__ == "__main__":
    unittest.main()
