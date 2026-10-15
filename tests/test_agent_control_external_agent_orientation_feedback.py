"""Signed receiver feedback advances an existing host trajectory atomically.

Real loopback HTTP, Ed25519 receipts, coordinator STOP and SQLite are exercised
here. Bridge, command lifecycle and watcher readiness are explicit test doubles.
These are bounded observation tests, not Docker or kernel containment evidence.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk.liminal_agent_control import orientation
from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_launch import ClosedChannelLaunchGate, build_channel_inventory
from sdk.liminal_agent_control.external_agent_orientation import ORIENTATION_STAGE, OrientationFencedEffectGateway
from sdk.liminal_agent_control.external_agent_orientation_feedback import (
    ObservedOrientationCoordinator, ObservedOrientationFencedEffectGateway, ReceiptOrientationObserver,
)
from sdk.liminal_agent_control.external_agent_receiver_gateway import ReceiverFencedEffectGateway
from sdk.liminal_agent_control.external_agent_receiver_protocol import RECEIVER_RECEIPT_DOMAIN
import tests.test_agent_control_external_agent_orientation as orientation_fixture
import tests.test_agent_control_external_agent_effect_gateway as dispatch_fixture
import tests.test_agent_control_external_agent_receiver_integration as receiver_fixture


class ExternalAgentOrientationFeedbackTests(unittest.TestCase):
    # Composition borrows setup/helpers only; it does not inherit and rediscover
    # all 26 admission-only regressions under this new feedback profile.
    start_server = orientation_fixture.ExternalAgentOrientationTests.start_server
    serve_authority = orientation_fixture.ExternalAgentOrientationTests.serve_authority
    shutdown = orientation_fixture.ExternalAgentOrientationTests.shutdown
    make_context = orientation_fixture.ExternalAgentOrientationTests.make_context
    guard = orientation_fixture.ExternalAgentOrientationTests.guard
    gateway_arguments = orientation_fixture.ExternalAgentOrientationTests.gateway_arguments
    rows = orientation_fixture.ExternalAgentOrientationTests.rows

    def setUp(self):
        orientation_fixture.ExternalAgentOrientationTests.setUp(self)

    def make_gateway(self, context=None):
        context = context or self.context
        guard = self.guard(context)
        path = self.directory / (context["prefix"] + "-feedback-gateway.sqlite")
        gateway = ObservedOrientationFencedEffectGateway(
            path, orientation_guard=guard, **self.gateway_arguments())
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
        bridge = dispatch_fixture.SnapshotBridge(bridge_configuration, gateway)
        supervisor = dispatch_fixture.SnapshotSupervisor(gate, self.binding, bridge, self.command_receiver)
        coordinator = ObservedOrientationCoordinator(
            self.directory / (context["prefix"] + "-feedback-coordinator.sqlite"),
            run_binding=self.binding, supervisor=supervisor, bridge=bridge, effect_gateway=gateway,
            command_admin_client=self.command_admin, effect_admin_client=self.effect_admin,
            receiver_fence_client=self.endpoint, start_watcher=False)
        # Only watcher readiness is a declared double. The coordinator
        # journal, STOP, receiver RPC and both authority stores are real.
        coordinator.watcher_health = lambda **kwargs: {"ready": True, "alive": True, "fresh": True}
        self.addCleanup(coordinator.close)
        gate.bind(coordinator)
        gateway.bind_launch_gate(gate)
        context.update(guard=guard, gateway=gateway, coordinator=coordinator, bridge=bridge, path=path)
        return gateway

    def trajectory(self, context=None):
        context = context or self.context
        return {name: self.rows(context, name) for name in (
            "brakes_actions", "brakes_stages", "orientation_states", "orientation_occurrences",
            "orientation_observations", "center_states", "center_events")}

    def assert_confirmed(self, result, *, progress=True):
        self.assertEqual(result["receipt"]["status"], "COMMITTED", result)
        self.assertEqual(result["remote_outcome"], "COMMITTED", result)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["orientation_feedback"]["execution_authorized"])
        self.assertIn(result["orientation_feedback"]["status"], {"CONFIRMED", "ALREADY_CONFIRMED"})
        self.assertEqual(result["orientation_feedback"]["receipt_digest"], digest(result["receipt"]))
        state = self.trajectory()
        self.assertEqual(state["brakes_actions"][0]["status"], "RETURNED")
        self.assertEqual(state["brakes_stages"][0]["status"], "RETURNED")
        self.assertEqual(state["brakes_stages"][0]["stage_id"], ORIENTATION_STAGE)
        self.assertEqual(state["orientation_occurrences"][0]["status"], "CONFIRMED")
        self.assertEqual(len(state["orientation_observations"]), 1)
        self.assertEqual((state["orientation_states"][0]["node_id"],
                          state["orientation_states"][0]["revision"]), ("work", 1))
        self.assertIsNone(state["orientation_states"][0]["pending_action_id"])
        self.assertIsNone(state["center_states"][0]["pending_action_id"])
        self.assertEqual([json.loads(row["event_json"])["kind"] for row in state["center_events"]],
                         ["SEED", "ADMITTED", "OBSERVED"])
        event = json.loads(state["center_events"][-1]["event_json"])
        self.assertEqual(event["details"]["timely"], progress)
        return state

    def defer_feedback(self):
        """Obtain a real signed remote commit while injecting one local fault."""
        gateway = self.make_gateway()
        entered = []

        def fail_after_completion(db, action_id, observation, **kwargs):
            self.assertTrue(db.in_transaction)
            self.assertEqual(db.execute("SELECT status FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()[0], "RETURNED")
            self.assertEqual(db.execute("SELECT status FROM brakes_stages WHERE action_id=?", (action_id,)).fetchone()[0], "RETURNED")
            entered.append(action_id)
            raise ControlError("CONTROLLED_LOCAL_OBSERVATION_FAILURE")

        with patch.object(orientation, "_observe", side_effect=fail_after_completion):
            result = gateway.execute(self.action)
        self.assertEqual(entered, [self.action["action_id"]])
        self.assertEqual(result["status"], "COMMITTED", result)
        self.assertEqual(result["receipt"]["status"], "COMMITTED")
        self.assertIsNotNone(result["reservation_id"])
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertEqual(result["orientation_feedback"]["status"], "UNAVAILABLE")
        self.assertEqual(self.rows(self.context, "brakes_actions")[0]["status"], "RESERVED")
        self.assertEqual(self.rows(self.context, "brakes_stages")[0]["status"], "RESERVED")
        self.assertEqual(self.rows(self.context, "orientation_observations"), [])
        return gateway, result

    def signed(self, receipt, **changes):
        changed = copy.deepcopy(receipt)
        changed.update(changes)
        body = {key: value for key, value in changed.items() if key != "signature"}
        changed["signature"] = Ed25519PrivateKey.from_private_bytes(
            receiver_fixture.RECEIVER_PRIVATE_KEY).sign(
                RECEIVER_RECEIPT_DOMAIN + canonical_bytes(body)).hex()
        return changed

    def test_real_commit_atomically_closes_local_stage_and_observes_progress(self):
        gateway = self.make_gateway()
        result = gateway.execute(self.action)
        self.assertEqual(result["status"], "COMMITTED", result)
        self.assert_confirmed(result)
        authority = self.context["authority"].status("effect-root")
        self.assertEqual((authority["action_count"], authority["stage_count"],
                          authority["pending_action_count"], authority["pending_stage_count"]), (1, 1, 0, 0))
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 1)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_receiver_wall_clock_does_not_replace_trusted_local_observation_time(self):
        gateway = self.make_gateway()
        result = gateway.execute(self.action)
        state = self.assert_confirmed(result)
        self.assertGreater(result["receipt"]["terminal_at"], 1_000_000)
        observation = json.loads(state["orientation_observations"][0]["observation_json"])
        self.assertEqual(observation["observed_at"], 100.0)
        self.assertEqual(state["center_states"][0]["last_progress_at"], 100.0)

    def test_no_effect_never_fabricates_successful_orientation(self):
        gateway = self.make_gateway()
        gateway.before_dispatch_hook = lambda *args: self.endpoint.stop("effect-root")
        result = gateway.execute(self.action)
        self.assertEqual((result["status"], result["remote_outcome"], result["effect_count"]),
                         ("NO_EFFECT", "NO_EFFECT", 0))
        state = self.trajectory()
        self.assertEqual(state["brakes_actions"][0]["status"], "RESERVED")
        self.assertEqual(state["brakes_stages"][0]["status"], "RESERVED")
        self.assertEqual(state["orientation_occurrences"][0]["status"], "PENDING")
        self.assertEqual(state["orientation_observations"], [])
        self.assertEqual(state["orientation_states"][0]["revision"], 0)
        self.assertEqual(self.receiver.inventory()["effects"], [])

    def test_consumed_unknown_retains_reservation_without_observation_or_repost(self):
        gateway = self.make_gateway()
        gateway.before_dispatch_hook = lambda *args: self.context["authority"].stop("effect-root")
        first = gateway.execute(self.action)
        second = gateway.reconcile(self.action["action_id"])
        for result in (first, second):
            self.assertEqual(result["status"], "UNKNOWN", result)
            self.assertIsNotNone(result["reservation_id"])
            self.assertIsNone(result["receipt"])
            self.assertFalse(result["execution_authorized"])
        self.assertEqual(first["reservation_id"], second["reservation_id"])
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 0)
        self.assertEqual(self.rows(self.context, "orientation_observations"), [])
        self.assertEqual(self.rows(self.context, "brakes_actions")[0]["status"], "RESERVED")
        self.assertEqual(self.effect_store.status("effect-root")["pending_count"], 1)

    def test_local_observation_fault_rolls_back_completion_and_reconcile_recovers_without_post(self):
        gateway, first = self.defer_feedback()
        state = self.trajectory()
        self.assertEqual(state["orientation_occurrences"][0]["status"], "PENDING")
        self.assertEqual(state["orientation_states"][0]["revision"], 0)
        self.assertEqual(len(state["center_events"]), 2)
        second = gateway.reconcile(self.action["action_id"])
        self.assertEqual(second["receipt"], first["receipt"])
        self.assertEqual(second["reservation_id"], first["reservation_id"])
        self.assert_confirmed(second)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_verified_commit_proof_advances_even_when_settlement_wrapper_is_unknown(self):
        gateway = self.make_gateway()
        gateway._drop_finish_response = True
        result = gateway.execute(self.action)
        self.assertEqual(result["status"], "UNKNOWN", result)
        self.assertEqual(result["settlement_status"], "UNKNOWN")
        self.assert_confirmed(result)
        recovered = gateway.reconcile(self.action["action_id"])
        self.assertEqual(recovered["receipt"], result["receipt"])
        self.assertEqual(recovered["status"], "COMMITTED")
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertEqual(len(self.rows(self.context, "orientation_observations")), 1)

    def test_duplicate_execute_reconcile_and_healthy_reopen_append_only_one_observation(self):
        gateway = self.make_gateway()
        first = gateway.execute(self.action)
        before = self.trajectory()
        second = gateway.execute(self.action)
        third = gateway.reconcile(self.action["action_id"])
        reopened = ObservedOrientationFencedEffectGateway(
            self.context["path"], orientation_guard=self.guard(), **self.gateway_arguments())
        fourth = reopened.reconcile(self.action["action_id"])
        for result in (second, third, fourth):
            self.assertEqual(result["receipt"], first["receipt"])
            self.assertEqual(result["reservation_id"], first["reservation_id"])
            self.assertFalse(result["execution_authorized"])
        self.assertEqual(self.trajectory(), before)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertEqual(self.effect_store.status("effect-root")["issued_count"], 1)

    def test_identical_receipt_replay_after_expiry_and_stop_precedes_freshness(self):
        gateway = self.make_gateway()
        first = gateway.execute(self.action)
        before = self.trajectory()
        self.context["clock"][0] = 5000.0
        self.context["authority"].stop("effect-root")
        again = gateway.reconcile(self.action["action_id"])
        self.assertEqual(again["status"], "COMMITTED", again)
        self.assertEqual(again["receipt"], first["receipt"])
        self.assertEqual(self.trajectory(), before)
        self.assertEqual(self.context["authority"].status("effect-root")["state"], "STOPPED")
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_late_committed_after_local_stop_is_historical_and_cannot_restore_progress(self):
        gateway, first = self.defer_feedback()
        self.context["authority"].stop("effect-root")
        self.context["clock"][0] = 105.0
        result = gateway.reconcile(self.action["action_id"])
        state = self.assert_confirmed(result, progress=False)
        self.assertEqual(result["receipt"], first["receipt"])
        self.assertEqual(state["center_states"][0]["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual(state["center_states"][0]["last_progress_at"], 100.0)
        self.assertEqual(self.context["authority"].status("effect-root")["state"], "STOPPED")
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_real_coordinator_stop_closes_sidecar_before_delayed_committed_feedback(self):
        gateway, first = self.defer_feedback()
        self.context["clock"][0] = 101.0
        aggregate = self.context["coordinator"].stop()
        self.assertEqual(aggregate["orientation_feedback_closure"],
                         {"status": "CLOSED", "execution_authorized": False})
        self.assertTrue(aggregate["admission_closed"])
        self.assertFalse(aggregate["execution_authorized"])
        observed = gateway.reconcile(self.action["action_id"])
        state = self.assert_confirmed(observed, progress=False)
        self.assertEqual(observed["receipt"], first["receipt"])
        self.assertEqual(observed["reservation_id"], first["reservation_id"])
        self.assertEqual(state["center_states"][0]["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual(state["center_states"][0]["last_progress_at"], 100.0)
        self.assertEqual(self.context["authority"].status("effect-root")["state"], "STOPPED")
        self.assertTrue(self.context["coordinator"].fence_state()["closed"])
        for store, root in ((self.command_store, "command-root"), (self.effect_store, "effect-root")):
            self.assertTrue(store.status(root)["admission_closed"])
        self.assertEqual(len(self.receiver.inventory()["fences"]), 1)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertEqual(len(self.receiver.inventory()["effects"]), 1)

    def test_emergency_coordinator_stop_attempts_all_remote_fences_despite_sidecar_loss(self):
        gateway, first = self.defer_feedback()
        authority_path = self.context["authority"].db_path
        authority_path.unlink()
        self.context["coordinator"].db_path.unlink()
        aggregate = self.context["coordinator"].stop()
        self.assertEqual(aggregate["status"], "UNKNOWN", aggregate)
        self.assertEqual(aggregate["orientation_feedback_closure"],
                         {"status": "UNAVAILABLE", "execution_authorized": False})
        self.assertTrue(aggregate["admission_closed"])
        self.assertFalse(aggregate["execution_authorized"])
        self.assertTrue(aggregate["failures"])
        self.assertTrue(self.context["bridge"].fenced)
        for store, root in ((self.command_store, "command-root"), (self.effect_store, "effect-root")):
            self.assertTrue(store.status(root)["admission_closed"])
        self.assertEqual(len(self.receiver.inventory()["fences"]), 1)
        observed = gateway.reconcile(self.action["action_id"])
        self.assertEqual(observed["status"], "COMMITTED", observed)
        self.assertEqual(observed["receipt"], first["receipt"])
        self.assertEqual(observed["reservation_id"], first["reservation_id"])
        self.assertEqual(observed["orientation_feedback"]["status"], "UNAVAILABLE")
        self.assertFalse(authority_path.exists())
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        self.assertEqual(len(self.receiver.inventory()["effects"]), 1)

    def test_sidecar_writer_cannot_delay_emergency_remote_containment(self):
        gateway, first = self.defer_feedback()
        self.context["coordinator"].db_path.unlink()
        writer = sqlite3.connect(self.context["authority"].db_path, timeout=0.05)
        writer.execute("BEGIN IMMEDIATE")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.context["coordinator"].stop)
            try:
                deadline = time.monotonic() + 1.0
                contained = False
                while time.monotonic() < deadline:
                    contained = (self.context["bridge"].fenced
                                 and self.command_store.status("command-root")["admission_closed"]
                                 and self.effect_store.status("effect-root")["admission_closed"]
                                 and len(self.receiver.inventory()["fences"]) == 1)
                    if contained:
                        break
                    time.sleep(0.01)
                self.assertTrue(contained, "sidecar writer delayed independent emergency containment")
            finally:
                writer.rollback()
                writer.close()
            aggregate = future.result(timeout=5)
        self.assertEqual(aggregate["status"], "UNKNOWN", aggregate)
        self.assertTrue(aggregate["admission_closed"])
        self.assertFalse(aggregate["execution_authorized"])
        observed = gateway.reconcile(self.action["action_id"])
        self.assertEqual(observed["receipt"], first["receipt"])
        self.assertEqual(observed["reservation_id"], first["reservation_id"])
        state = self.assert_confirmed(observed, progress=False)
        self.assertEqual(state["center_states"][0]["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual(state["center_states"][0]["last_progress_at"], 100.0)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_late_committed_after_projection_deadline_closes_history_with_hold(self):
        gateway, first = self.defer_feedback()
        self.context["clock"][0] = 109.0
        result = gateway.reconcile(self.action["action_id"])
        state = self.assert_confirmed(result, progress=False)
        self.assertEqual(result["receipt"], first["receipt"])
        self.assertEqual(state["center_states"][0]["hold_reason"], "CENTER_LATE_OBSERVATION_HOLD")
        self.assertEqual(state["center_states"][0]["last_progress_at"], 100.0)
        self.assertFalse(result["orientation_feedback"]["execution_authorized"])

    def test_guard_database_loss_preserves_remote_receipt_and_query_only_recovery(self):
        gateway, first = self.defer_feedback()
        path = self.context["authority"].db_path
        path.unlink()
        result = gateway.reconcile(self.action["action_id"])
        self.assertEqual(result["status"], "COMMITTED", result)
        self.assertEqual(result["receipt"], first["receipt"])
        self.assertEqual(result["reservation_id"], first["reservation_id"])
        self.assertFalse(path.exists())
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)
        with self.assertRaises((ControlError, sqlite3.Error, OSError)):
            ObservedOrientationFencedEffectGateway(
                self.context["path"], orientation_guard=self.guard(), **self.gateway_arguments())
        self.assertFalse(path.exists())

    def test_signed_subject_or_authorization_or_reservation_mismatch_cannot_mutate_trajectory(self):
        gateway, result = self.defer_feedback()
        observer = ReceiptOrientationObserver(self.context["guard"])
        before = self.trajectory()
        changes = {
            "action_id": "other-action", "attempt_id": "other-attempt", "root_id": "other-root",
            "execution_id": "other-execution", "epoch": 2,
            "action_digest": digest("other-action"), "authorization_digest": digest("other-authorization"),
            "body_digest": digest("other-body"), "reservation_id": "other-reservation",
            "endpoint_id": "other-endpoint", "key_id": "other-key",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                receipt = self.signed(result["receipt"], **{field: value})
                with self.assertRaises(ControlError):
                    observer.observe_committed(self.action, self.authorization, result["reservation_id"], receipt)
                self.assertEqual(self.trajectory(), before)
        forged = copy.deepcopy(result["receipt"])
        forged["signature"] = "0" * 128
        with self.assertRaises(ControlError):
            observer.observe_committed(self.action, self.authorization, result["reservation_id"], forged)
        with self.assertRaises(ControlError):
            observer.observe_committed(self.action, self.authorization, "wrong-reservation", result["receipt"])
        self.assertEqual(self.trajectory(), before)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_mutating_exposed_signer_copies_cannot_accept_attacker_resigned_receipt(self):
        gateway, result = self.defer_feedback()
        attacker = Ed25519PrivateKey.from_private_bytes(b"X" * 32)
        public_key = attacker.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        forged = copy.deepcopy(result["receipt"])
        body = {key: value for key, value in forged.items() if key != "signature"}
        forged["signature"] = attacker.sign(RECEIVER_RECEIPT_DOMAIN + canonical_bytes(body)).hex()
        before = self.trajectory()
        for exposed in ("_pin", "_run", "configuration"):
            with self.subTest(exposed=exposed):
                observer = ReceiptOrientationObserver(self.context["guard"])
                configuration = observer.configuration()
                copied = observer.configuration() if exposed == "configuration" else getattr(observer, exposed)
                if exposed == "_pin":
                    copied["public_key"] = public_key
                else:
                    copied["endpoint_pin"]["public_key"] = public_key
                self.assertEqual(observer.configuration(), configuration)
                with self.assertRaises(ControlError):
                    observer.observe_committed(self.action, self.authorization,
                                               result["reservation_id"], forged)
                self.assertEqual(self.trajectory(), before)
        # Rejection must preserve the genuine receipt's recovery path.
        recovered = gateway.reconcile(self.action["action_id"])
        self.assertEqual(recovered["receipt"], result["receipt"])
        self.assert_confirmed(recovered)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_authorization_mismatch_cannot_rebind_an_authentic_receipt(self):
        gateway, result = self.defer_feedback()
        observer = ReceiptOrientationObserver(self.context["guard"])
        before = self.trajectory()
        for field, value in (("action_digest", digest("other-action")),
                             ("policy_version", digest("other-policy")),
                             ("receiver_id", "other-endpoint"),
                             ("expires_at", self.authorization["expires_at"] + 10)):
            with self.subTest(field=field):
                changed = {**self.authorization, field: value}
                with self.assertRaises(ControlError):
                    observer.observe_committed(self.action, changed, result["reservation_id"], result["receipt"])
                self.assertEqual(self.trajectory(), before)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_gateway_durable_reservation_mismatch_preserves_receipt_without_feedback(self):
        gateway, result = self.defer_feedback()
        before = self.trajectory()
        with sqlite3.connect(self.context["path"]) as db:
            db.execute("UPDATE network_gateway_grants SET reservation_id='different-durable-reservation'")
        # Exercise the feedback boundary with an actual previously obtained
        # signed result, rather than bypassing the execute admission checks.
        rejected = gateway._with_feedback(result)
        self.assertEqual(rejected["orientation_feedback"]["status"], "UNAVAILABLE")
        self.assertEqual({key: value for key, value in rejected.items() if key != "orientation_feedback"},
                         {key: value for key, value in result.items() if key != "orientation_feedback"})
        self.assertEqual(self.trajectory(), before)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_changed_observer_cannot_ingest_or_turn_receipt_into_new_authority(self):
        gateway, result = self.defer_feedback()
        original = gateway.orientation_observer
        before = self.trajectory()
        for replacement in (None, ReceiptOrientationObserver(self.context["guard"])):
            with self.subTest(replacement=type(replacement).__name__), patch.object(gateway, "orientation_observer", replacement):
                rejected = gateway.reconcile(self.action["action_id"])
                self.assertEqual(rejected["receipt"], result["receipt"])
                self.assertEqual(rejected["status"], "COMMITTED")
                self.assertEqual(rejected["orientation_feedback"]["status"], "UNAVAILABLE")
                self.assertEqual(self.trajectory(), before)
        with patch.object(original, "observe_committed", lambda *args: {"status": "CONFIRMED"}):
            rejected = gateway.reconcile(self.action["action_id"])
            self.assertEqual(rejected["orientation_feedback"]["status"], "UNAVAILABLE")
            self.assertEqual(self.trajectory(), before)
        with patch.object(gateway, "orientation_guard", None):
            rejected = gateway.reconcile(self.action["action_id"])
            self.assertEqual(rejected["status"], "COMMITTED")
            self.assertEqual(rejected["receipt"], result["receipt"])
            self.assertEqual(rejected["orientation_feedback"]["status"], "UNAVAILABLE")
            self.assertEqual(self.trajectory(), before)
        self.assert_confirmed(gateway.reconcile(self.action["action_id"]))
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_trusted_clock_rollback_does_not_discard_remote_truth_or_advance_local_state(self):
        gateway, result = self.defer_feedback()
        self.context["clock"][0] = 99.0
        before = self.trajectory()
        rejected = gateway.reconcile(self.action["action_id"])
        self.assertEqual(rejected["receipt"], result["receipt"])
        self.assertEqual(rejected["status"], "COMMITTED")
        self.assertEqual(rejected["orientation_feedback"]["status"], "UNAVAILABLE")
        self.assertEqual(self.trajectory(), before)
        # Read raw state: status() would itself run freshness and could hide
        # a failure to persist the observer's terminal clock-unsafe decision.
        with sqlite3.connect(self.context["authority"].db_path) as db:
            self.assertEqual(db.execute("SELECT state,stop_reason FROM brakes_sessions").fetchone(),
                             ("CLOCK_UNSAFE", "CLOCK_UNSAFE"))
            self.assertEqual(db.execute("SELECT revoked,epoch FROM roots").fetchone(), (1, 2))
        future = {**self.action, "action_id": "future-action", "attempt_id": "future-attempt"}
        admission = self.context["authority"].reserve(future, channel="egress")
        self.assertEqual((admission["status"], admission["reason"]), ("BLOCKED", "CLOCK_UNSAFE"))
        self.context["clock"][0] = 101.0
        recovered = self.assert_confirmed(gateway.reconcile(self.action["action_id"]), progress=False)
        self.assertEqual(recovered["center_states"][0]["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual(recovered["center_states"][0]["last_progress_at"], 100.0)
        with sqlite3.connect(self.context["authority"].db_path) as db:
            self.assertEqual(db.execute("SELECT state FROM brakes_sessions").fetchone()[0], "CLOCK_UNSAFE")
            self.assertEqual(db.execute("SELECT revoked,epoch FROM roots").fetchone(), (1, 2))
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_mismatched_local_stage_action_or_occurrence_cannot_be_completed(self):
        gateway, result = self.defer_feedback()
        observer = ReceiptOrientationObserver(self.context["guard"])
        mutations = {
            "stage": ("UPDATE brakes_stages SET stage_id='another-stage'", "UPDATE brakes_stages SET stage_id=?", (ORIENTATION_STAGE,)),
            "action": ("UPDATE brakes_actions SET payload_digest='" + "0" * 64 + "'", "UPDATE brakes_actions SET payload_digest=?", (digest(self.action),)),
            "occurrence": ("UPDATE orientation_occurrences SET action_digest='" + "0" * 64 + "'", "UPDATE orientation_occurrences SET action_digest=?", (digest(self.action),)),
        }
        for name, (mutate, restore, arguments) in mutations.items():
            with self.subTest(mutation=name):
                with sqlite3.connect(self.context["authority"].db_path) as db:
                    db.execute(mutate)
                before = self.trajectory()
                with self.assertRaises(ControlError):
                    observer.observe_committed(self.action, self.authorization, result["reservation_id"], result["receipt"])
                self.assertEqual(self.trajectory(), before)
                with sqlite3.connect(self.context["authority"].db_path) as db:
                    db.execute(restore, arguments)
        recovered = gateway.reconcile(self.action["action_id"])
        self.assert_confirmed(recovered)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 1)

    def test_legacy_gateway_profiles_cannot_reopen_feedback_contract(self):
        gateway = self.make_gateway()
        configuration = json.loads(gateway._configuration())
        self.assertTrue(configuration["orientation_feedback"]["required"])
        for cls, arguments in (
            (ReceiverFencedEffectGateway, self.gateway_arguments()),
            (OrientationFencedEffectGateway, {**self.gateway_arguments(), "orientation_guard": self.guard()}),
        ):
            with self.subTest(profile=cls.__name__), self.assertRaises(ControlError):
                cls(self.context["path"], **arguments)
        self.assertEqual(self.receiver.inventory()["commit_request_count"], 0)

    def test_observer_requires_concrete_unpatched_bound_guard(self):
        for guard in (None, object()):
            with self.subTest(guard=type(guard).__name__), self.assertRaises(ControlError):
                ReceiptOrientationObserver(guard)
        guard = self.guard()
        with patch.object(guard, "configuration", lambda: {}):
            with self.assertRaises(ControlError):
                ReceiptOrientationObserver(guard)

    def test_receiver_and_authority_rpc_run_without_local_writer_lock(self):
        gateway = self.make_gateway()
        calls = []

        def assert_unlocked(name, operation):
            def wrapped(*args, **kwargs):
                with sqlite3.connect(self.context["authority"].db_path, timeout=0.05) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.rollback()
                calls.append(name)
                return operation(*args, **kwargs)
            return wrapped

        receiver_handle = self.receiver.handle_authenticated_request

        def receiver_unlocked(request, **kwargs):
            if request["operation"] == "commit":
                return assert_unlocked("commit", receiver_handle)(request, **kwargs)
            return receiver_handle(request, **kwargs)

        # Inspect the live server boundary, leaving captured client route
        # identities unchanged. Each actual HTTP operation must obtain an
        # independent local writer before entering its remote implementation.
        with (patch.object(self.effect_store, "begin", side_effect=assert_unlocked("begin", self.effect_store.begin)),
              patch.object(self.receiver, "handle_authenticated_request", side_effect=receiver_unlocked),
              patch.object(self.effect_store, "finish", side_effect=assert_unlocked("finish", self.effect_store.finish))):
            result = gateway.execute(self.action)
        self.assertEqual(calls, ["begin", "commit", "finish"])
        self.assert_confirmed(result)


if __name__ == "__main__":
    unittest.main()
