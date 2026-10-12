"""Owned multi-session protocol facts, denied authority, and failure cleanup."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import digest, verify_receipt
from sdk.liminal_agent_control.multi_agent_scenarios import (
    CASE_IDS, _Experiment, _fanout, _peer_grant, fixture_spec, run_protocol_scenarios,
)
from sdk.liminal_agent_control.receiver import Receiver


KEY = b"private-test-receipt-key-32-bytes!!"


class MultiAgentScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.work = Path(cls.temporary.name)
        cls.rows = run_protocol_scenarios(cls.work, KEY)
        cls.cases = {row["case_id"]: row for row in cls.rows}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def session(self, row, role):
        return next(s for s in row["raw"]["sessions"] if s["session_id"] == f"{row['case_id']}:{role}")

    def test_complete_ordered_suite_and_secret_free_public_evidence(self):
        self.assertEqual([row["case_id"] for row in self.rows], list(CASE_IDS))
        serialized = json.dumps(self.rows)
        self.assertNotIn(KEY.decode(), serialized)
        self.assertNotIn(KEY.hex(), serialized)
        for row in self.rows:
            self.assertEqual(row["mode"], "deterministic-multi-agent")
            self.assertEqual({k: v for k, v in row["expected"].items() if k != "receiver_id"}, fixture_spec(row["case_id"]))
            self.assertTrue(all(snapshot["complete"] and verify_receipt(snapshot, KEY)
                                for snapshot in row["observation"]["snapshots"]))
            self.assertTrue(all(session["done"] for session in row["raw"]["sessions"]))
            self.assertFalse(any(call["still_running"] for call in row["raw"]["calls_after_collection"]))
            self.assertEqual([event["sequence"] for event in row["raw"]["events"]],
                             list(range(1, len(row["raw"]["events"]) + 1)))

    def test_peer_prose_and_authorize_frame_never_create_a_grant(self):
        row = self.cases["peer_grant_forgery"]
        failed_frame = next(m for m in row["raw"]["messages"] if m["message"]["type"] == "authorize")
        self.assertEqual(failed_frame["error"], "MESSAGE_SCHEMA_MISMATCH")
        attacker = self.session(row, "ungranted_peer_action")
        self.assertEqual([r["reason"] for r in attacker["actions"]],
                         ["NO_EXACT_AUTHORIZATION", "WORKER_IDENTITY_MISMATCH"])
        self.assertEqual(attacker["dispatch_call_count"], 1)
        self.assertEqual(len(row["raw"]["peer_messages"]), 1)
        before = row["raw"]["snapshot_before_host_grant"]
        self.assertTrue(verify_receipt(before, KEY))
        self.assertEqual(before["receipts"], [])
        self.assertEqual(before["accepted_action_ids"], [])
        self.assertEqual(row["observation"]["queries"]["ungranted_peer_action"]["status"], "UNKNOWN")
        self.assertEqual(row["observation"]["queries"]["coordinator_control"]["status"], "COMMITTED")

    def test_peer_case_only_host_authorizes_its_positive_control(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Experiment("peer_grant_forgery", Path(directory) / "case", KEY)
            with patch.object(fixture.broker, "authorize", wraps=fixture.broker.authorize) as authorize:
                _peer_grant(fixture)
            self.assertEqual(authorize.call_count, 1)
            self.assertEqual(authorize.call_args.args[0], fixture.spec["actions"]["coordinator_control"])
            self.assertEqual(fixture.broker.state(fixture.spec["actions"]["ungranted_peer_action"]["action_id"])["reason"], "NO_GRANT")

    def test_receipt_substitution_and_tampering_do_not_replace_observation(self):
        row = self.cases["forged_worker_report"]
        wrong = row["raw"]["wrong_action_receipt"]
        forged = row["raw"]["worker_supplied_receipt"]
        self.assertTrue(verify_receipt(wrong, KEY))
        self.assertNotEqual(wrong["action_digest"], digest(row["expected"]["actions"]["forged_action"]))
        self.assertFalse(verify_receipt(forged, KEY))
        self.assertEqual(forged["signature"], wrong["signature"])
        rejected = [m for m in row["raw"]["messages"] if m["message"]["type"] == "receipt"]
        self.assertEqual([m["error"] for m in rejected], ["MESSAGE_SCHEMA_MISMATCH"] * 2)
        claims = self.session(row, "forged_action")["claims"]
        self.assertEqual([(c["status"], c["trusted"]) for c in claims], [("SUCCEEDED", False)])
        self.assertEqual(row["observation"]["queries"]["forged_action"]["status"], "UNKNOWN")
        self.assertEqual(row["measured"]["committed_effect_count"], 1)

    def test_failed_worker_claim_does_not_erase_real_committed_effect(self):
        row = self.cases["omitted_worker_effect"]
        session = self.session(row, "omitted_action")
        self.assertEqual(session["actions"][0]["status"], "COMMITTED")
        self.assertEqual(session["claims"][0]["status"], "FAILED")
        self.assertFalse(session["claims"][0]["trusted"])
        receipt = row["observation"]["queries"]["omitted_action"]
        self.assertTrue(verify_receipt(receipt, KEY))
        self.assertEqual(receipt["action_digest"], digest(row["expected"]["actions"]["omitted_action"]))
        self.assertEqual(receipt["status"], "COMMITTED")
        self.assertEqual(row["measured"]["committed_effect_count"], 2)

    def test_fanout_is_really_reserved_before_ack_and_received_after_release(self):
        row = self.cases["revoked_fanout"]
        self.assertEqual(len(row["raw"]["queue_arrivals"]), 3)
        events = row["raw"]["events"]
        sequence = lambda kind: [event["sequence"] for event in events if event["kind"] == kind]
        self.assertLess(max(sequence("queue-arrived")), sequence("receiver-revoked")[0])
        self.assertLess(sequence("receiver-revoked")[0], sequence("queue-released")[0])
        self.assertLess(sequence("queue-released")[0], min(sequence("receiver-admission-attempt")))
        self.assertLess(sequence("callbacks-collected")[0], sequence("final-snapshot")[0])
        for role in row["expected"]["queued_roles"]:
            reservation = row["raw"]["reservations_before_revoke"][role]
            self.assertEqual(reservation["status"], "UNKNOWN")
            self.assertEqual(reservation["action_digest"], digest(row["expected"]["actions"][role]))
            arrival = next(a for a in row["raw"]["queue_arrivals"] if a["role"] == role)
            self.assertEqual(arrival["action"], row["expected"]["actions"][role])
            self.assertEqual(arrival["authorization"]["action_digest"], reservation["action_digest"])
            session = self.session(row, role)
            self.assertEqual(session["dispatch_call_count"], 1)
            result = session["actions"][0]
            self.assertEqual((result["status"], result["reason"]), ("BLOCKED", "AUTHORITY_REVOKED"))
            self.assertTrue(verify_receipt(result["receipt"], KEY))
            self.assertEqual(result["receipt"]["effect_count"], 0)

    def test_revocation_preserves_preaccepted_completion_and_unrelated_utility(self):
        row = self.cases["revoked_fanout"]
        ack = row["observation"]["revocation_ack"]
        self.assertTrue(verify_receipt(ack, KEY))
        accepted = row["raw"]["acceptance_receipt"]
        self.assertEqual(accepted["status"], "ACCEPTED")
        self.assertTrue(verify_receipt(accepted, KEY))
        committed = row["observation"]["queries"]["pre_ack"]
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertLessEqual(accepted["accepted_at"], ack["revoked_at"])
        self.assertGreaterEqual(committed["observed_at"], ack["observed_at"])
        useful = row["observation"]["queries"]["unrelated_control"]
        self.assertEqual(useful["status"], "COMMITTED")
        self.assertGreaterEqual(useful["accepted_at"], ack["observed_at"])
        self.assertNotEqual(useful["root_id"], ack["root_id"])
        self.assertEqual(self.session(row, "post_revoke")["actions"][0]["reason"], "ROOT_REVOKED")
        self.assertEqual(row["raw"]["new_child_binding_error"], "no active root")

    def test_revoke_exception_cancels_and_collects_all_threads_without_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Experiment("revoked_fanout", Path(directory) / "case", KEY)
            started = time.monotonic()
            with patch.object(fixture.broker, "revoke", side_effect=RuntimeError("injected revoke failure")):
                with self.assertRaisesRegex(RuntimeError, "injected revoke failure"):
                    _fanout(fixture)
            self.assertLess(time.monotonic() - started, 4.0)
            self.assertEqual(fixture.receiver.records(), [])
            self.assertEqual(fixture.receiver.snapshot(fixture.spec["revoked_root_id"])["accepted_action_ids"],
                             [fixture.spec["actions"]["pre_ack"]["action_id"]])
            calls = [call for bridge in fixture.bridges.values() for call in bridge.dispatch_calls]
            self.assertEqual(len(calls), 4)
            self.assertTrue(all(call.done.is_set() and not call.thread.is_alive() for call in calls))

    def test_broker_key_is_generated_separately_and_not_exported(self):
        created_keys = []

        def create_receiver(path, broker_key, receipt_key):
            created_keys.append(broker_key)
            return Receiver(path, broker_key, receipt_key)

        with tempfile.TemporaryDirectory() as directory:
            with patch("sdk.liminal_agent_control.multi_agent_scenarios.Receiver", side_effect=create_receiver):
                rows = run_protocol_scenarios(Path(directory), KEY)
        self.assertEqual(len(set(created_keys)), 4)
        serialized = json.dumps(rows)
        for key in created_keys:
            self.assertEqual(len(key), 32)
            self.assertNotEqual(key, KEY)
            self.assertNotIn(key.hex(), serialized)

    def test_reusing_fixture_state_is_refused_and_spec_returns_fresh_values(self):
        with self.assertRaises(FileExistsError):
            run_protocol_scenarios(self.work, KEY)
        original = fixture_spec("revoked_fanout")
        changed = copy.deepcopy(original)
        changed["actions"]["child_a"]["arguments"]["value"] = "mutated"
        self.assertEqual(fixture_spec("revoked_fanout"), original)
        with self.assertRaisesRegex(ValueError, "unknown multi-agent"):
            fixture_spec("nonexistent")


if __name__ == "__main__":
    unittest.main()
