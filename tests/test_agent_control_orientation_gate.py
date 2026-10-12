"""Observe real owned effects across the durable orientation admission boundary."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sdk.liminal_agent_control import Broker, ControlError, Receiver, digest
from sdk.liminal_agent_control.authority import connect
from sdk.liminal_agent_control.brakes_egress import SessionEgressGateway, network_action
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.orientation import OrientationStore
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract


BROKER_KEY = b"orientation-owned-broker-key" * 2
RECEIPT_KEY = b"orientation-owned-receipt-key" * 2
POLICY = "a" * 64


def action(name="record", execution_id="worker"):
    return {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
            "execution_id": execution_id, "epoch": 1, "target": "records", "arguments": {"value": name}}


def profile(receiver_id):
    return {"nodes": [
        {"node_id": "center", "space_id": "workspace", "phase": "verified"},
        {"node_id": "work", "space_id": "workspace", "phase": "active"}],
        "edges": [
            {"edge_id": "record-out", "source": "center", "destination": "work", "channel": "records"},
            {"edge_id": "record-back", "source": "work", "destination": "center", "channel": "records"},
            {"edge_id": "network-out", "source": "center", "destination": "work", "channel": "egress"}],
        "center_nodes": ["center"], "max_steps": 10, "max_visits": 5, "max_away_steps": 3,
        "max_observation_age_seconds": 30,
        "observers": {"records": receiver_id, "egress": "external-observer"}}


class OrientationGateTests(unittest.TestCase):
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
        self.profile = profile(self.receiver.receiver_id)
        self.orientation.install("root", self.profile)
        self.orientation.seed("root", "worker", "center", evidence_digest="c" * 64, observed_at=self.now)

    def authorization(self, proposed):
        return {"action_digest": digest(proposed), "policy_version": POLICY,
                "expires_at": time.time() + 60, "receiver_id": self.receiver.receiver_id}

    def prepare(self, proposed, edge="record-out", revision=0):
        return self.orientation.prepare(proposed, edge_id=edge, expected_revision=revision)

    def commit(self, proposed):
        return self.receiver.commit(proposed, authorization=self.authorization(proposed))

    def rows(self, table):
        self.assertIn(table, {"orientation_states", "orientation_tickets", "orientation_occurrences"})
        with connect(self.path) as db:
            return [dict(row) for row in db.execute("SELECT * FROM " + table).fetchall()]

    def network(self, *, resolver=None):
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
        self.prepare(proposed, "network-out")
        return gateway, proposed, request

    def observation(self, proposed, outcome="CONFIRMED"):
        return {key: proposed[key] for key in ("action_id", "root_id", "execution_id", "epoch")} | {
            "action_digest": digest(proposed), "profile_digest": digest(self.profile),
            "observed_at": self.now, "evidence_digest": "e" * 64,
            "observer_id": "external-observer", "outcome": outcome}

    def test_exact_broker_grant_and_real_record_advance_once(self):
        proposed = action()
        self.prepare(proposed)
        broker = Broker(self.directory / "broker.sqlite", self.receiver)
        broker.authorize(proposed, policy_version=POLICY)
        result = broker.handle(proposed)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(len(self.receiver.records()), 1)
        state = self.rows("orientation_states")[0]
        self.assertEqual(state["node_id"], "work")
        self.assertEqual(state["revision"], 1)
        self.assertIsNone(state["pending_action_id"])
        self.assertEqual(len(self.rows("orientation_occurrences")), 1)
        self.assertEqual(self.receiver.finalize(proposed["action_id"]), result["receipt"])
        self.assertEqual(self.rows("orientation_states"), [state])

    def test_orientation_ticket_is_insufficient_without_exact_grant(self):
        proposed = action()
        self.prepare(proposed)
        self.assertEqual(self.receiver.commit(proposed)["reason"], "GRANT_REQUIRED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 0)
        self.assertEqual(self.receiver.records(), [])

    def test_plain_reopened_authority_cannot_bypass_persisted_profile(self):
        reopened = SessionAuthority(self.path, clock=lambda: self.now)
        result = reopened.reserve(action(), channel="records", policy_digest=POLICY)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("ORIENTATION", result["reason"])
        self.assertEqual(reopened.status("root")["action_count"], 0)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.commit(action())["status"], "DENIED")
        self.assertEqual(self.receiver.records(), [])

    def test_policy_epoch_and_agent_binding_still_required(self):
        proposed = action()
        self.prepare(proposed)
        wrong_policy = {**self.authorization(proposed), "policy_version": "d" * 64}
        self.assertEqual(self.receiver.commit(proposed, authorization=wrong_policy)["reason"], "POLICY_MISMATCH")
        wrong_epoch = {**proposed, "epoch": 2}
        self.assertEqual(self.commit(wrong_epoch)["status"], "DENIED")
        self.authority.bind_execution("root", "other", "worker")
        self.orientation.seed("root", "other", "center", evidence_digest="d" * 64, observed_at=self.now)
        swapped = {**proposed, "execution_id": "other"}
        self.assertEqual(self.commit(swapped)["status"], "DENIED")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.commit(proposed)["status"], "COMMITTED")

    def test_wrong_channel_and_observer_are_denied_before_effect(self):
        proposed = action()
        self.prepare(proposed)
        mismatch = self.authority.reserve(proposed, channel="egress", policy_digest=POLICY)
        self.assertEqual(mismatch["reason"], "ORIENTATION_EDGE_MISMATCH")
        # Persisted service identity corruption is a host configuration fault;
        # it must fail closed before any record can be written.
        with connect(self.path) as db:
            db.execute("UPDATE receiver_meta SET value='wrong-receiver' WHERE key='receiver_id'")
        self.assertEqual(self.commit(proposed)["reason"], "ORIENTATION_OBSERVER_MISMATCH")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.receiver.records(), [])

    def test_shared_budget_denial_does_not_consume_orientation_edge(self):
        # Fixture-only policy reduction makes the shared budget bind first.
        with connect(self.path) as db:
            db.execute("UPDATE brakes_sessions SET max_actions=1 WHERE root_id='root'")
        first = action("first")
        self.prepare(first)
        self.assertEqual(self.commit(first)["status"], "COMMITTED")
        second = action("second")
        self.prepare(second, "record-back", 1)
        state_before, tickets_before = self.rows("orientation_states"), self.rows("orientation_tickets")
        self.assertEqual(self.commit(second)["reason"], "ACTION_BUDGET_EXHAUSTED")
        self.assertEqual(self.rows("orientation_states"), state_before)
        self.assertEqual(self.rows("orientation_tickets"), tickets_before)
        self.assertEqual(len(self.rows("orientation_occurrences")), 1)

    def test_failed_record_rolls_back_effect_capacity_and_orientation(self):
        proposed = action()
        self.prepare(proposed)
        before = self.rows("orientation_states"), self.rows("orientation_tickets")
        with connect(self.path) as db:
            db.execute("CREATE TRIGGER reject_owned_effect BEFORE INSERT ON effects BEGIN SELECT RAISE(ABORT,'owned failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.commit(proposed)
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual((self.rows("orientation_states"), self.rows("orientation_tickets")), before)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.receiver.query(proposed["action_id"])["status"], "UNKNOWN")

    def test_confirmation_failure_rolls_back_actual_record_insert(self):
        proposed = action()
        self.prepare(proposed)
        # Inject a failure after admission and the owned effect INSERT, at the
        # observer boundary, to verify the entire local transaction is atomic.
        original_clock = self.authority.clock
        calls = 0

        def clock():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("owned observation clock failure")
            return self.now

        self.authority.clock = clock
        try:
            with self.assertRaisesRegex(ControlError, "trusted clock unavailable"):
                self.commit(proposed)
        finally:
            self.authority.clock = original_clock
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.rows("orientation_occurrences"), [])
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 0)
        self.assertEqual(self.receiver.records(), [])

    def test_late_preaccepted_completion_is_history_and_does_not_resume_stop(self):
        proposed = action()
        self.prepare(proposed)
        self.assertEqual(self.receiver.accept(proposed, authorization=self.authorization(proposed))["status"], "ACCEPTED")
        self.authority.stop("root")
        self.assertEqual(self.receiver.finalize(proposed["action_id"])["status"], "COMMITTED")
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 1)
        self.assertEqual(self.authority.status("root")["state"], "STOPPED")
        self.assertEqual(self.commit(action("late"))["status"], "DENIED")
        self.assertEqual(len(self.receiver.records()), 1)

    def test_backward_observation_clock_cannot_certify_preaccepted_record(self):
        proposed = action()
        self.prepare(proposed)
        self.assertEqual(self.receiver.accept(proposed, authorization=self.authorization(proposed))["status"], "ACCEPTED")
        self.now = 105.0
        self.assertEqual(self.authority.status("root")["last_now"], 105.0)
        self.now = 104.0
        with self.assertRaisesRegex(ControlError, "CLOCK_UNSAFE"):
            self.receiver.finalize(proposed["action_id"])
        self.assertEqual(self.receiver.records(), [])
        self.assertEqual(self.receiver.query(proposed["action_id"])["status"], "ACCEPTED")
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 0)
        self.assertEqual(self.rows("orientation_occurrences")[0]["status"], "PENDING")

    def test_network_return_does_not_advance_without_bound_observation(self):
        gateway, proposed, request = self.network()
        result = gateway.execute(proposed, request)
        self.assertEqual((result["status"], result["external_effect"]), ("RETURNED", "UNKNOWN"))
        self.assertEqual(self.network_calls, ["dns", "transport"])
        state = self.rows("orientation_states")[0]
        self.assertEqual((state["node_id"], state["revision"], state["pending_action_id"]), ("center", 0, "network"))
        self.assertEqual(self.rows("orientation_occurrences")[0]["status"], "PENDING")
        forged = self.observation(proposed) | {"observer_id": "worker"}
        with self.assertRaisesRegex(ControlError, "OBSERVER_MISMATCH"):
            self.orientation.observe("network", observation=forged)
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 0)
        self.orientation.observe("network", observation=self.observation(proposed))
        state = self.rows("orientation_states")[0]
        self.assertEqual((state["node_id"], state["revision"], state["pending_action_id"]), ("work", 1, None))
        self.assertEqual(self.network_calls, ["dns", "transport"])

    def test_contradiction_during_dns_blocks_transport(self):
        def resolver(host):
            self.network_calls.append("dns")
            self.orientation.observe("network", observation=self.observation(proposed, "CONTRADICTED"))
            return ["93.184.216.34"]

        gateway, proposed, request = self.network(resolver=resolver)
        result = gateway.execute(proposed, request)
        self.assertEqual(result["reason"], "ORIENTATION_CONTRADICTION_HOLD")
        self.assertEqual(self.network_calls, ["dns"])
        state = self.rows("orientation_states")[0]
        self.assertEqual(state["revision"], 0)
        self.assertEqual(state["hold_reason"], "ORIENTATION_CONTRADICTION_HOLD")
        reopened = SessionAuthority(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.reserve(action("later"), channel="records")["reason"], "ORIENTATION_CONTRADICTION_HOLD")
        self.assertEqual(self.authority.status("root")["stage_count"], 1)

    def test_observation_expiry_during_dns_blocks_transport(self):
        def resolver(host):
            self.network_calls.append("dns")
            self.now = 131.0
            return ["93.184.216.34"]

        gateway, proposed, request = self.network(resolver=resolver)
        result = gateway.execute(proposed, request)
        self.assertEqual(result["reason"], "ORIENTATION_OBSERVATION_STALE")
        self.assertEqual(self.network_calls, ["dns"])
        self.assertEqual(self.authority.status("root")["stage_count"], 1)
        self.assertEqual(self.rows("orientation_states")[0]["revision"], 0)

    def test_two_real_processes_cannot_both_commit_same_state_revision(self):
        proposals = [action("one"), action("two")]
        for proposed in proposals:
            self.prepare(proposed)
        code = """
import json,sys
from sdk.liminal_agent_control import Receiver
from sdk.liminal_agent_control.brakes_store import SessionAuthority
authority=SessionAuthority(sys.argv[1],clock=lambda:100.0)
receiver=Receiver(sys.argv[1],b'orientation-owned-broker-key'*2,b'orientation-owned-receipt-key'*2,admission_controller=authority)
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
            self.assertEqual(len(self.rows("orientation_occurrences")), 1)
            self.assertEqual(len(self.receiver.records()), 1)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
