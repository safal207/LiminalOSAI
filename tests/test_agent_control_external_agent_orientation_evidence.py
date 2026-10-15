"""Independent packet/SQLite controls, plus six required real-capture mutations.

Signed loopback controls below establish checker predicates only. They contain
no Docker PASS fixture. Real-capture tests are collected only when CI supplies
an actual report, and then none may skip.
"""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_orientation_offline_test", ROOT / "scripts/verify_external_agent_orientation_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class OrientationPacketEvidenceTests(unittest.TestCase):
    def fixture(self):
        # Composition invokes only actual signed-loopback setup; no inherited
        # TestCase suite or fake Docker matrix can silently add PASS evidence.
        import tests.test_agent_control_external_agent_orientation_feedback as source
        fixture = source.ExternalAgentOrientationFeedbackTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        gateway = fixture.make_gateway()
        from sdk.liminal_agent_control.external_agent_orientation_demo import _orientation_snapshot
        return fixture, gateway, _orientation_snapshot

    def check_rows(self, fixture, gateway, snapshot, *, committed=False):
        receipts = {}
        if committed:
            result = gateway.execute(fixture.action)
            self.assertEqual(result["status"], "COMMITTED", result)
            verifier._network_receipt(result["receipt"], fixture.endpoint_pin, fixture.action,
                                      fixture.authorization, result["reservation_id"])
            receipts[verifier.sha(result["receipt"])] = result["receipt"]
        report = snapshot(fixture.context["authority"].db_path)
        facts = verifier._orientation_inventory(report, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)
        return report, facts, receipts

    def test_actual_prepared_seed_rows_are_not_an_admitted_observation(self):
        fixture, gateway, snapshot = self.fixture()
        _, facts, _ = self.check_rows(fixture, gateway, snapshot)
        self.assertEqual((facts["revision"], facts["admitted"], facts["observations"]), (0, [], {}))

    def test_actual_signed_receipt_reconstructs_one_observation_and_budget(self):
        fixture, gateway, snapshot = self.fixture()
        _, facts, _ = self.check_rows(fixture, gateway, snapshot, committed=True)
        self.assertEqual((facts["revision"], facts["state"]["steps"], facts["pending"]), (1, 1, None))

    def test_missing_signed_receipt_cannot_support_raw_observation(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, _ = self.check_rows(fixture, gateway, snapshot, committed=True)
        with self.assertRaisesRegex(verifier.EvidenceError, "COMMITTED receipt"):
            verifier._orientation_inventory(report, fixture.binding, json.loads(gateway._configuration()), {}, final=True)

    def test_sql_revision_steps_and_visits_cannot_be_recensused(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, receipts = self.check_rows(fixture, gateway, snapshot, committed=True)
        for field, wrong in (("revision", 2), ("steps", 0), ("visits_json", '{}'), ("pending_action_id", fixture.action["action_id"])):
            changed = deepcopy(report); changed["tables"]["orientation_states"][0][field] = wrong
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

    def test_observed_receipt_cannot_leave_local_action_or_stage_reserved(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, receipts = self.check_rows(fixture, gateway, snapshot, committed=True)
        for table in ("brakes_actions", "brakes_stages"):
            changed = deepcopy(report); changed["tables"][table][0]["status"] = "RESERVED"
            with self.subTest(table=table), self.assertRaisesRegex(verifier.EvidenceError, "still RESERVED"):
                verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

    def test_rehashed_future_progress_and_stale_local_ingestion_are_rejected(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, receipts = self.check_rows(fixture, gateway, snapshot, committed=True)
        for field in ("last_progress_at", "last_observed_at", "away_since", "checkpoint_center_id"):
            changed = deepcopy(report)
            state = changed["tables"]["center_states"][0]
            row = changed["tables"]["center_events"][-1]
            event = json.loads(row["event_json"])
            wrong = "forged-checkpoint" if field == "checkpoint_center_id" else 200.0
            event["state_after"][field] = state[field] = wrong
            row["event_json"] = verifier.canonical(event).decode()
            row["event_hash"] = state["head_hash"] = verifier.sha(event)
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)
        changed = deepcopy(report); changed["tables"]["orientation_observations"][0]["ingested_at"] += 1
        with self.assertRaises(verifier.EvidenceError):
            verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

    def test_missing_or_extra_raw_sql_tables_fail_closed(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, receipts = self.check_rows(fixture, gateway, snapshot)
        for extra in (False, True):
            changed = deepcopy(report)
            if extra:
                changed["tables"]["worker_claims"] = []
            else:
                changed["tables"].pop("center_events")
            with self.subTest(extra=extra), self.assertRaises(verifier.EvidenceError):
                verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

        for table in ("roots", "executions", "brakes_executions"):
            changed = deepcopy(report); changed["tables"][table] = []
            with self.subTest(empty_table=table), self.assertRaises(verifier.EvidenceError):
                verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

    def test_rehashed_projection_cannot_change_admitted_deadline(self):
        fixture, gateway, snapshot = self.fixture()
        report, _, receipts = self.check_rows(fixture, gateway, snapshot, committed=True)
        changed = deepcopy(report)
        row = changed["tables"]["center_projections"][0]
        projection = json.loads(row["projection_json"]); projection["deadline"] += 1
        row["projection_json"] = verifier.canonical(projection).decode(); row["projection_digest"] = verifier.sha(projection)
        with self.assertRaises(verifier.EvidenceError):
            verifier._orientation_inventory(changed, fixture.binding, json.loads(gateway._configuration()), receipts, final=True)

    def test_signed_receipt_tamper_fails_public_crypto(self):
        fixture, gateway, snapshot = self.fixture()
        _, _, receipts = self.check_rows(fixture, gateway, snapshot, committed=True)
        receipt = deepcopy(next(iter(receipts.values()))); receipt["body_digest"] = "0" * 64
        with self.assertRaises(verifier.EvidenceError):
            verifier._network_receipt(receipt, fixture.endpoint_pin)

    def test_feedback_descriptor_cannot_promote_observation_to_authority(self):
        fixture, gateway, _ = self.fixture()
        route = json.loads(gateway._configuration())
        verifier._feedback_contract(route["orientation_feedback"], fixture.binding, route["orientation_gate"])
        for field, wrong in (("required", False), ("execution_authorized", True), ("receipt", "WORKER_CLAIM")):
            changed = deepcopy(route["orientation_feedback"]); changed[field] = wrong
            changed["contract_digest"] = verifier.sha({k: v for k, v in changed.items() if k != "contract_digest"})
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._feedback_contract(changed, fixture.binding, route["orientation_gate"])

    def test_feedback_success_cannot_use_missing_or_no_effect_receipt(self):
        value = {"schema": "liminal-agent-orientation-feedback-v1", "status": "CONFIRMED", "reason": "SIGNED_RECEIPT_OBSERVED",
                 "action_id": "action", "receipt_digest": "a" * 64, "observation_digest": "b" * 64, "execution_authorized": False}
        for receipt in (None, {"status": "NO_EFFECT"}):
            with self.subTest(receipt=receipt), self.assertRaises(verifier.EvidenceError):
                verifier._feedback(value, {"action_id": "action"}, receipt)

    def test_duplicate_and_nonfinite_json_cannot_enter_checker(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1e999}'):
            with self.subTest(raw=raw), self.assertRaises((verifier.EvidenceError, ValueError)):
                verifier._json(raw)

    def test_legacy_report_or_worker_pass_claim_is_not_strict_runtime_evidence(self):
        for value in ({"schema": verifier._RAW.SCHEMA, "passed": True}, {"schema": verifier.SCHEMA, "passed": True}, None):
            with self.subTest(value=value), self.assertRaises((verifier.EvidenceError, KeyError)):
                verifier.verify_report(value)


_CAPTURE = os.environ.get("LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE")
if _CAPTURE:
    class OrientationCaptureEvidenceTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            raw = Path(_CAPTURE).read_bytes()
            cls.report = verifier._json(raw)
            cls.source = cls.report["source"]["commit"]
            cls.image = cls.report["docker_identity"]["image_id"]
            cls.current = verifier.verify_report(cls.report, expected_source_sha=cls.source, expected_image=cls.image)

        def rejects(self, changed):
            with self.assertRaises((verifier.EvidenceError, ValueError, KeyError, TypeError)):
                verifier.verify_report(changed, expected_source_sha=self.source, expected_image=self.image)

        def test_current_report(self):
            self.assertEqual(self.current["status"], "PASS")
            self.assertEqual(self.current["orientation_revisions"], {name: 2 if name == "verified_feedback_chain" else 0 for name in verifier.CASE_IDS})
            self.assertFalse(self.current["execution_authorized"])
            self.assertEqual(self.current["containment_status"], "NOT_ESTABLISHED")

        def test_forged_receipt(self):
            changed = deepcopy(self.report)
            changed["endpoint_final_inventory"]["receipts"][0]["signature"] = "0" * 128
            self.rejects(changed)

        def test_raw_sql_revision(self):
            changed = deepcopy(self.report)
            changed["outcomes"]["verified_feedback_chain"]["orientation_after"]["tables"]["orientation_states"][0]["revision"] = 3
            self.rejects(changed)

        def test_missing_channels(self):
            changed = deepcopy(self.report)
            channels = changed["outcomes"]["verified_feedback_chain"]["supervisor_after"]["launch_boundary"]["contract"]["channels"]
            channels.pop("worker_network")
            self.rejects(changed)

        def test_pending_false_no_effect(self):
            changed = deepcopy(self.report)
            changed["outcomes"]["stop_after_begin"]["effect_external_state"]["pending_count"] = 0
            self.rejects(changed)

        def test_omitted_source(self):
            changed = deepcopy(self.report)
            changed["source_files_sha256"].pop("sdk/liminal_agent_control/external_agent_orientation_feedback.py")
            self.rejects(changed)
