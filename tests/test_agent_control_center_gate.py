"""Real effects must satisfy temporal continuity AND an independent observer ring."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sdk.liminal_agent_control import ControlError, Receiver, digest
from sdk.liminal_agent_control import center_continuity
from sdk.liminal_agent_control.authority import connect
from sdk.liminal_agent_control.brakes_egress import SessionEgressGateway, network_action
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.center_continuity import CenterContinuityStore
from sdk.liminal_agent_control.observer_ring import ObserverRingStore
from sdk.liminal_agent_control.orientation import OrientationStore
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract


BROKER_KEY = b"center-owned-broker-key" * 2
RECEIPT_KEY = b"center-owned-receipt-key" * 2
POLICY = "a" * 64


def action(name="record"):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
            "execution_id": "worker", "epoch": 1, "target": "records", "arguments": {"value": name}}


class CenterGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "authority.sqlite"
        self.now = 100.0
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.receiver = Receiver(self.path, BROKER_KEY, RECEIPT_KEY, admission_controller=self.authority)
        self.authority.create_session("root", controller_id="host", policy_digest=POLICY,
            objective_digest="b" * 64, max_actions=10, max_executions=3, max_depth=1,
            max_stages=10, lifetime_seconds=1000, lease_seconds=1000)
        self.authority.bind_execution("root", "worker")
        self.orientation = OrientationStore(self.authority)
        self.orientation.install("root", {
            "nodes": [{"node_id": "center", "space_id": "workspace", "phase": "verified"},
                      {"node_id": "work", "space_id": "workspace", "phase": "active"}],
            "edges": [
                {"edge_id": "record-out", "source": "center", "destination": "work", "channel": "records"},
                {"edge_id": "record-back", "source": "work", "destination": "center", "channel": "records"},
                {"edge_id": "network-out", "source": "center", "destination": "work", "channel": "egress"}],
            "center_nodes": ["center", "work"], "max_steps": 10, "max_visits": 5, "max_away_steps": 3,
            "max_observation_age_seconds": 100,
            "observers": {"records": self.receiver.receiver_id, "egress": "owned-sink"}})
        self.center = CenterContinuityStore(self.authority)
        self.center.install("root", {
            "windows": [
                {"center_id": "first-center", "previous_center_id": None,
                 "starts_at": 100, "ends_at": 110, "center_nodes": ["center"]},
                {"center_id": "next-center", "previous_center_id": "first-center",
                 "starts_at": 110, "ends_at": 300, "center_nodes": ["work"]}],
            "max_past_age_seconds": 100, "max_future_horizon_seconds": 30,
            "max_transition_seconds": 15, "max_away_seconds": 40,
            "max_idle_seconds": 80, "progress_edge_ids": [],
            "max_ideas": 20})
        self.ring = ObserverRingStore(self.authority)
        self.ring.install("root", {
            "observers": [{"observer_id": "past-reader", "role": "past"},
                          {"observer_id": "reality-reader", "role": "reality"},
                          {"observer_id": "future-reader", "role": "future"},
                          {"observer_id": "contradiction-reader", "role": "contradiction"}],
            "required_roles": ["past", "reality", "future"],
            "max_attestation_age_seconds": 30, "max_attestations": 100})
        self.orientation.seed("root", "worker", "center", evidence_digest="c" * 64, observed_at=self.now)

    def state(self):
        return next(state for state in self.center.snapshot("root")["states"]
                    if state["execution_id"] == "worker")

    def authorization(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": POLICY,
                "expires_at": time.time() + 60, "receiver_id": self.receiver.receiver_id}

    def commit(self, proposed):
        return self.receiver.commit(proposed, authorization=self.authorization(proposed))

    def prepare(self, proposed, *, edge="record-out", revision=0, deadline=108):
        self.orientation.prepare(proposed, edge_id=edge, expected_revision=revision)
        predecessor = self.state()["head_hash"]
        idea_id = "idea:" + proposed["action_id"]
        self.center.record_idea("root", "worker", idea_id, digest({"proposal": proposed["action_id"]}),
                                expected_head_hash=predecessor)
        return self.center.project(proposed, edge_id=edge, expected_revision=revision,
            predecessor_hash=predecessor, idea_id=idea_id, not_before=self.now, deadline=deadline)

    def support(self, proposed, *, count=3, valid_until=108):
        for observer in ("past-reader", "reality-reader", "future-reader")[:count]:
            self.ring.attest(proposed["action_id"], observer_id=observer, verdict="SUPPORT",
                evidence_digest=digest({"observer": observer, "action": proposed["action_id"]}),
                observed_at=self.now, valid_until=valid_until)

    def veto(self, proposed, *, observer="contradiction-reader", valid_until=108):
        self.ring.attest(proposed["action_id"], observer_id=observer, verdict="VETO",
            evidence_digest="d" * 64, observed_at=self.now, valid_until=valid_until)

    def assert_no_effects(self):
        self.assertEqual(self.receiver.records(), [])
        status = self.authority.status("root")
        self.assertEqual((status["action_count"], status["stage_count"]), (0, 0))
        self.assertEqual(self.orientation.snapshot("root")["occurrences"], [])

    def network(self, *, resolver=None, support=True):
        broker = CapabilityBroker()
        broker.admit(CapabilityContract.build(
            capability_id="network-cap", capability_type="network.connect_domain", subject_id="worker",
            issuer_id="host", scope={"domains": ["owned.invalid"], "protocols": ["https"], "ports": [443]},
            issued_at_unix=90, not_before_unix=90, expires_at_unix=1000, max_uses=10,
            delegable=False, parent_capability_id=None, policy_sha256=POLICY).as_document(), at_unix=100)
        self.network_calls = []
        request = GatewayRequest(call_id="network", subject_id="worker", policy_sha256=POLICY,
            method="POST", url="https://owned.invalid/write", headers={}, body_sha256="f" * 64,
            secret_refs={}, at_unix=100)
        proposed = network_action(root_id="root", execution_id="worker", epoch=1,
            action_id="network", attempt_id="attempt:network", request=request)
        gateway = SessionEgressGateway(authority=self.authority, broker=broker,
            resolver=resolver or (lambda host: self.network_calls.append("dns") or ["93.184.216.34"]),
            transport=lambda request: self.network_calls.append("transport") or TransportResponse(200, {}, "f" * 64),
            clock=lambda: int(self.now))
        self.assertEqual(gateway.authorize(proposed, request, capability_id="network-cap")["status"], "AUTHORIZED")
        self.prepare(proposed, edge="network-out")
        if support:
            self.support(proposed)
        return gateway, proposed, request

    def test_absent_ring_evidence_blocks_real_record(self):
        proposed = action()
        self.prepare(proposed)
        result = self.commit(proposed)
        self.assertEqual(result["status"], "DENIED")
        self.assertIn("OBSERVER_RING", result["reason"])
        self.assert_no_effects()

    def test_missing_required_role_blocks_real_record(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed, count=2)
        result = self.commit(proposed)
        self.assertEqual(result["reason"], "OBSERVER_RING_ROLE_REQUIRED")
        self.assert_no_effects()

    def test_expired_ring_evidence_blocks_real_record(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed, valid_until=100.5)
        self.now = 101
        result = self.commit(proposed)
        self.assertEqual(result["reason"], "OBSERVER_RING_ATTESTATION_STALE")
        self.assert_no_effects()

    def test_required_observer_unknown_blocks_real_record(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed, count=2)
        self.ring.attest(proposed["action_id"], observer_id="future-reader", verdict="UNKNOWN",
            evidence_digest="e" * 64, observed_at=self.now, valid_until=108)
        self.assertEqual(self.commit(proposed)["reason"], "OBSERVER_RING_UNKNOWN")
        self.assert_no_effects()

    def test_one_veto_blocks_despite_three_supporting_roles(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        self.veto(proposed)
        self.assertEqual(self.commit(proposed)["reason"], "OBSERVER_RING_VETO")
        self.assert_no_effects()

    def test_three_roles_allow_one_real_effect_and_one_chain_advance(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        before = self.center.snapshot("root")
        result = self.commit(proposed)
        self.assertEqual(result["status"], "COMMITTED")
        after = self.center.snapshot("root")
        self.assertNotEqual(after["states"][0]["head_hash"], before["states"][0]["head_hash"])
        self.assertEqual([event["kind"] for event in after["events"][len(before["events"]):]],
                         ["ADMITTED", "OBSERVED"])
        self.assertEqual(after["states"][0]["revision"], before["states"][0]["revision"] + 1)
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(self.receiver.finalize(proposed["action_id"]), result)
        self.assertEqual(self.center.snapshot("root"), after)
        self.assertEqual(len(self.receiver.records()), 1)

    def test_ring_support_never_substitutes_exact_grant(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        self.assertEqual(self.receiver.commit(proposed)["reason"], "GRANT_REQUIRED")
        self.assert_no_effects()

    def test_ring_support_never_overrides_stop(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        self.authority.stop("root")
        self.assertEqual(self.commit(proposed)["status"], "DENIED")
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")
        self.assert_no_effects()

    def test_prepared_in_first_center_cannot_dispatch_in_next_window(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        self.now = 110
        result = self.commit(proposed)
        self.assertEqual(result["status"], "DENIED")
        self.assertIn(result["reason"], {"CENTER_WINDOW_CLOSED", "CENTER_TRANSITION_EXPIRED",
                                        "OBSERVER_RING_ATTESTATION_STALE"})
        self.assert_no_effects()

    def test_absent_ring_blocks_network_before_any_callback(self):
        gateway, proposed, request = self.network(support=False)
        result = gateway.execute(proposed, request)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("OBSERVER_RING", result["reason"])
        self.assertEqual(self.network_calls, [])
        self.assert_no_effects()

    def test_transition_deadline_crossed_during_dns_blocks_transport(self):
        def resolver(host):
            self.network_calls.append("dns")
            self.now = 109
            return ["93.184.216.34"]

        gateway, proposed, request = self.network(resolver=resolver)
        before = self.state()
        result = gateway.execute(proposed, request)
        self.assertEqual(result["status"], "BLOCKED")
        # SUPPORT cannot outlive its bound projection, so either temporal
        # guard may detect the same closed interval first.
        self.assertIn(result["reason"], {"CENTER_TRANSITION_EXPIRED", "OBSERVER_RING_ATTESTATION_STALE"})
        self.assertEqual(self.network_calls, ["dns"])
        self.assertEqual(self.authority.status("root")["stage_count"], 1)
        self.assertEqual((self.state()["node_id"], self.state()["revision"]),
                         (before["node_id"], before["revision"]))
        self.assertEqual(self.center.snapshot("root")["events"][-1]["kind"], "ADMITTED")

    def test_center_window_crossed_during_dns_blocks_transport(self):
        def resolver(host):
            self.network_calls.append("dns")
            self.now = 110
            return ["93.184.216.34"]

        gateway, proposed, request = self.network(resolver=resolver)
        result = gateway.execute(proposed, request)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn(result["reason"], {"CENTER_WINDOW_CLOSED", "CENTER_TRANSITION_EXPIRED",
                                        "OBSERVER_RING_ATTESTATION_STALE"})
        self.assertEqual(self.network_calls, ["dns"])
        self.assertEqual(self.authority.status("root")["stage_count"], 1)

    def test_new_veto_during_dns_blocks_transport(self):
        def resolver(host):
            self.network_calls.append("dns")
            self.veto(proposed, observer="reality-reader")
            return ["93.184.216.34"]

        gateway, proposed, request = self.network(resolver=resolver)
        result = gateway.execute(proposed, request)
        self.assertEqual(result["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.network_calls, ["dns"])
        self.assertEqual(self.authority.status("root")["stage_count"], 1)

    def test_late_veto_preserves_past_effect_but_blocks_new_projection(self):
        first = action("first")
        self.prepare(first)
        self.support(first)
        self.assertEqual(self.commit(first)["status"], "COMMITTED")
        self.now = 111  # The old projection has expired and the center has moved.
        second = action("second")
        self.prepare(second, edge="record-back", revision=1, deadline=119)
        self.support(second, valid_until=119)
        before = self.center.snapshot("root")
        self.veto(first, observer="reality-reader", valid_until=120)
        self.assertEqual(self.commit(second)["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.center.snapshot("root"), before)
        self.assertEqual([record["action"]["action_id"] for record in self.receiver.records()], ["first"])
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_preaccepted_record_completes_after_veto_but_cannot_authorize_successor(self):
        first = action("preaccepted")
        self.prepare(first)
        self.support(first)
        self.assertEqual(self.receiver.accept(first, authorization=self.authorization(first))["status"], "ACCEPTED")
        self.assertEqual(self.receiver.records(), [])
        self.now = 101
        self.veto(first, observer="reality-reader")
        # ACCEPTED is this receiver's existing commitment boundary: a later
        # veto prevents new admission, but cannot erase an accepted obligation.
        self.assertEqual(self.receiver.finalize(first["action_id"])["status"], "COMMITTED")
        second = action("successor")
        self.prepare(second, edge="record-back", revision=1)
        self.support(second)
        before = self.center.snapshot("root")
        self.assertEqual(self.commit(second)["reason"], "OBSERVER_RING_VETO")
        self.assertEqual(self.center.snapshot("root"), before)
        self.assertEqual([record["action"]["action_id"] for record in self.receiver.records()], ["preaccepted"])
        self.assertEqual([event["kind"] for event in before["events"]], ["SEED", "ADMITTED", "OBSERVED"])
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_preaccepted_late_completion_is_history_and_holds_dependent_actions(self):
        first = action("late-preaccepted")
        self.prepare(first)
        self.support(first)
        self.assertEqual(self.receiver.accept(first, authorization=self.authorization(first))["status"], "ACCEPTED")
        self.now = 111
        self.veto(first, observer="reality-reader", valid_until=120)
        self.assertEqual(self.receiver.finalize(first["action_id"])["status"], "COMMITTED")
        state = self.state()
        self.assertEqual((state["node_id"], state["revision"]), ("work", 1))
        self.assertEqual(state["hold_reason"], "CENTER_LATE_OBSERVATION_HOLD")
        observed = self.center.snapshot("root")["events"][-1]
        self.assertEqual(observed["kind"], "OBSERVED")
        self.assertFalse(observed["details"]["timely"])
        second = action("late-successor")
        with self.assertRaisesRegex(ControlError, "CENTER_LATE_OBSERVATION_HOLD"):
            self.prepare(second, edge="record-back", revision=1, deadline=119)
        self.assertEqual(self.commit(second)["status"], "DENIED")
        self.assertEqual([record["action"]["action_id"] for record in self.receiver.records()], ["late-preaccepted"])
        self.assertEqual(self.authority.status("root")["action_count"], 1)

    def test_preaccepted_return_after_stop_records_fact_without_recentering(self):
        first = action("outbound")
        self.prepare(first)
        self.support(first)
        self.assertEqual(self.commit(first)["status"], "COMMITTED")
        self.now = 101
        returning = action("returning")
        self.prepare(returning, edge="record-back", revision=1)
        self.support(returning)
        self.assertEqual(self.receiver.accept(returning, authorization=self.authorization(returning))["status"], "ACCEPTED")
        before = self.state()
        before_away_steps = self.orientation.snapshot("root")["executions"][0]["away_steps"]
        self.assertIsNotNone(before["away_since"])
        self.now = 102
        self.authority.stop("root")
        self.assertEqual(self.receiver.finalize(returning["action_id"])["status"], "COMMITTED")
        after = self.state()
        self.assertEqual((after["node_id"], after["revision"]), ("center", 2))
        self.assertEqual(after["hold_reason"], "CENTER_AUTHORITY_CLOSED_HOLD")
        self.assertEqual({key: after[key] for key in ("away_since", "last_progress_at", "checkpoint_center_id")},
                         {key: before[key] for key in ("away_since", "last_progress_at", "checkpoint_center_id")})
        self.assertEqual(self.orientation.snapshot("root")["executions"][0]["away_steps"], before_away_steps)
        self.assertFalse(self.center.snapshot("root")["events"][-1]["details"]["timely"])
        self.assertEqual(len(self.receiver.records()), 2)
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")

    def test_failed_effect_rolls_back_temporal_chain_and_reservations(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        before = self.center.snapshot("root")
        with connect(self.path) as db:
            db.execute("CREATE TRIGGER reject_owned_effect BEFORE INSERT ON effects BEGIN SELECT RAISE(ABORT,'owned failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.commit(proposed)
        self.assertEqual(self.center.snapshot("root"), before)
        self.assert_no_effects()
        self.assertEqual(self.receiver.query(proposed["action_id"])["status"], "UNKNOWN")

    def test_reopened_plain_authority_cannot_bypass_ring(self):
        proposed = action()
        self.prepare(proposed)
        reopened = SessionAuthority(self.path, clock=lambda: self.now)
        result = reopened.reserve(proposed, channel="records", policy_digest=POLICY)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("OBSERVER_RING", result["reason"])
        self.assert_no_effects()

    def test_failed_temporal_confirmation_rolls_back_already_inserted_effect(self):
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        before = self.center.snapshot("root")
        original = center_continuity.observe_in_transaction

        def failing_observer(db, *args, **kwargs):
            original(db, *args, **kwargs)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM center_events").fetchone()[0],
                             len(before["events"]) + 2)
            raise ControlError("owned temporal observer failure")

        with patch.object(center_continuity, "observe_in_transaction", failing_observer):
            with self.assertRaisesRegex(ControlError, "owned temporal observer failure"):
                self.commit(proposed)
        self.assertEqual(self.center.snapshot("root"), before)
        self.assert_no_effects()

    def test_ideas_and_projection_do_not_rewrite_confirmed_past(self):
        before = self.center.snapshot("root")
        proposed = action()
        self.prepare(proposed)
        self.support(proposed)
        after = self.center.snapshot("root")
        self.assertEqual(after["states"], before["states"])
        self.assertEqual(after["events"], before["events"])
        self.assertEqual(len(after["ideas"]), len(before["ideas"]) + 1)
        self.assertEqual(len(after["projections"]), len(before["projections"]) + 1)
        self.assert_no_effects()

    def test_two_real_processes_cannot_fork_same_temporal_predecessor(self):
        proposals = [action("one"), action("two")]
        for proposed in proposals:
            self.prepare(proposed)
            self.support(proposed)
        before_events = len(self.center.snapshot("root")["events"])
        code = """
import json,sys
from sdk.liminal_agent_control import Receiver
from sdk.liminal_agent_control.brakes_store import SessionAuthority
authority=SessionAuthority(sys.argv[1],clock=lambda:100.0)
receiver=Receiver(sys.argv[1],b'center-owned-broker-key'*2,b'center-owned-receipt-key'*2,admission_controller=authority)
print('READY',flush=True)
sys.stdin.readline()
print(json.dumps(receiver.commit(json.loads(sys.argv[2]),authorization=json.loads(sys.argv[3]))),flush=True)
"""
        processes = [subprocess.Popen([sys.executable, "-c", code, str(self.path), json.dumps(proposed),
            json.dumps(self.authorization(proposed))], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True) for proposed in proposals]
        try:
            for process in processes:
                self.assertEqual(process.stdout.readline().strip(), "READY")
            for process in processes:
                process.stdin.write("GO\n")
                process.stdin.flush()
            results = []
            for process in processes:
                output, errors = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, errors)
                results.append(json.loads(output))
            self.assertEqual(sorted(result["status"] for result in results), ["COMMITTED", "DENIED"])
            self.assertEqual(self.authority.status("root")["action_count"], 1)
            events = self.center.snapshot("root")["events"][before_events:]
            self.assertEqual([event["kind"] for event in events], ["ADMITTED", "OBSERVED"])
            self.assertEqual(events[1]["parent_hash"], events[0]["event_hash"])
            self.assertEqual(self.state()["revision"], 1)
            self.assertEqual(len(self.receiver.records()), 1)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
