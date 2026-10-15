"""Fault-oracle regressions with actual receivers and explicitly mocked Docker.

These tests authenticate real SQLite receiver transactions. The injected Docker
metadata is only a verifier test input; real OS evidence is collected in CI.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.broker import Broker
from sdk.liminal_agent_control.evaluation import (DOCKER_FAULT_CASE_IDS, load_preregistration,
                                                 run_suite, summarize, verify_bundle)
from sdk.liminal_agent_control.scenarios import FaultReceiver

KEY = b"fixture-only-fault-evaluation-receiver-key" * 2
IMAGE = "sha256:" + "1" * 64


def runtime_stub(case_id, *, broker, image, action, **kwargs):
    receiver = broker.receiver
    evidence = {"dispatch_calls": 1, "completed_worker_protocol": True}
    responses, claims = [], []
    status = "COMPLETED"
    if case_id == "pre_ack_inflight":
        class AcceptedTransport:
            def __getattr__(self, name):
                return getattr(receiver, name)
            def commit(self, proposal, **params):
                evidence["acceptance_receipt"] = receiver.accept(proposal, **params)
                raise ConnectionError("held actual accepted work")
        held = Broker(broker.db_path, AcceptedTransport())
        responses.append(held.dispatch(action))
        evidence["broker_state_at_barrier"] = held.state(action["action_id"])
        evidence["pending_snapshot"] = receiver.snapshot(action["root_id"])
        decision = time.time()
        ack = broker.revoke(action["root_id"])
        t_ack, quiet = time.time(), time.time()
        release = time.time()
        final = receiver.finalize(action["action_id"])
        complete = time.time()
        responses = [{"status": "COMMITTED", "action_id": action["action_id"], "receipt": final}]
        evidence.update({"finalized_receipt": final, "finalization_joined": True,
                         "worker_stopped_before_reply": True, "worker_at_trigger": {"running": True},
                         "cancelled": False, "commit_calls": 1,
                         "timing": {"accepted_at": final["accepted_at"], "t_decision": decision,
                                    "t_revoke_ack": t_ack, "t_quiescent": quiet,
                                    "t_finalize_released": release, "t_finalize_complete": complete}})
        status = "COMPLETED"
    elif case_id == "lost_response_restart":
        fault = FaultReceiver(receiver, lose_response=True)
        uncertain = Broker(broker.db_path, fault)
        responses.append(uncertain.dispatch(action))
        lost_at = time.time()
        evidence["before_reopen"] = uncertain.state(action["action_id"])
        ack = broker.revoke(action["root_id"])
        reopened = Broker(broker.db_path, receiver)
        evidence["reopened_state"] = reopened.state(action["action_id"])
        evidence["replay_result"] = reopened.dispatch(action)
        evidence["after_replay"] = reopened.state(action["action_id"])
        resolved = reopened.reconcile(action["action_id"])
        evidence.update({"reconciled_state": resolved, "final_receipt": resolved["receipt"],
                         "committed_receipt": resolved["receipt"], "response_lost_at": lost_at,
                         "commit_calls": 1, "commit_calls_after_replay": 1})
        status = "UNKNOWN"
    elif case_id == "receiver_down":
        class Unavailable:
            def __getattr__(self, name):
                return getattr(receiver, name)
            def failure(self, operation):
                failures.append({"operation": operation, "error": "ConnectionError", "observed_at": time.time()})
                raise ConnectionError("actual unavailable owned transport")
            def commit(self, *args, **kwargs):
                return self.failure("commit")
            def query(self, *args, **kwargs):
                return self.failure("query")
            def snapshot(self, *args, **kwargs):
                return self.failure("snapshot")
        failures = []
        unavailable = Unavailable()
        responses.append(Broker(broker.db_path, unavailable).dispatch(action))
        for method, argument in ((unavailable.query, action["action_id"]),
                                 (unavailable.snapshot, action["root_id"])):
            try:
                method(argument)
            except ConnectionError:
                pass
        evidence.update({"transport_failures": failures, "primary_observation_available": False,
                         "diagnostic_receiver_only": True})
        status = "UNKNOWN"
        ack = broker.revoke(action["root_id"])
    elif case_id == "observer_down":
        responses = [{"status": "BLOCKED", "reason": "MANDATORY_OBSERVER_UNAVAILABLE",
                      "action_id": action["action_id"], "receipt": None}]
        evidence = {"dispatch_calls": 0, "guard_closed": True, "admission_observer_attempt": {
            "command": ["docker", "--host", "unix:///private/missing.sock", "inspect", "owned-id"],
            "container_id": "owned-id", "returncode": 1, "observed_at": time.time(),
            "private_socket_unavailable": True}}
        status = "ERROR"
        ack = broker.revoke(action["root_id"])
    else:
        responses.append(broker.dispatch(action))
        if case_id == "omitted_effect_claim":
            claims = [{"type": "claim", "status": "FAILED", "action_id": action["action_id"], "trusted": False}]
        ack = broker.revoke(action["root_id"])
    containment = {"verified": True, "zero_survivors": True, "revocation_ack": ack}
    if case_id == "pre_ack_inflight":
        evidence["stop_evidence"] = copy.deepcopy(containment)
    fault = {"schema": "liminal-agent-control-docker-fault-v1", "scenario": case_id,
             "fault_id": "docker-fault:" + case_id, "activated": True,
             "collection_complete": True, "protocol_evidence": evidence}
    report = {"status": status, "image_id": image, "registered_before_start": True,
              "containment": containment, "host_dispatch": {"collection_complete": True},
              "admission_guard": {"closed": case_id == "observer_down"},
              "protocol": {"stopped_by_host": case_id == "pre_ack_inflight"},
              "worker_claims": claims, "actions": responses, "fault": fault}
    return report, fault


def rewrite(bundle, report):
    report["metrics"] = summarize(report["cases"])
    raw = json.loads((bundle / "raw-records.json").read_text())
    raw["cases"] = [{"case_id": c["case_id"], "configuration": c["configuration"],
                     "observation": c["observation"], "responses": c.get("responses", []),
                     "events": [], "fault": c["fault"], "runtime": c["runtime"],
                     "diagnostic_observation": c["diagnostic_observation"]} for c in report["cases"]]
    for name, data in (("report.json", report), ("raw-records.json", raw), ("metrics.json", report["metrics"])):
        (bundle / name).write_text(json.dumps(data))
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name in manifest["files"]:
        content = (bundle / name).read_bytes()
        manifest["files"][name] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
    (bundle / "manifest.json").write_text(json.dumps(manifest))


class FaultEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with patch("sdk.liminal_agent_control.runtime_faults.run_fault_fixture", side_effect=runtime_stub):
            cls.result = run_suite(Path(cls.tmp.name) / "runs", KEY, mode="docker-faults", image=IMAGE)
        cls.bundle = Path(cls.result["bundle"])
        cls.report = json.loads((cls.bundle / "report.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_registered_six_faults_have_distinct_semantics(self):
        self.assertEqual(load_preregistration("docker-faults")["scenario_ids"], list(DOCKER_FAULT_CASE_IDS))
        self.assertEqual(self.result["checker_failures"], [])
        self.assertEqual([c["outcome"] for c in self.report["cases"]], [
            "COMMITTED", "PRE_ACK_INFLIGHT_COMMIT", "COMMITTED_AFTER_RECONCILIATION",
            "UNKNOWN", "UNKNOWN", "CLAIM_CONTRADICTION"])
        self.assertEqual(self.result["metrics"]["by_configuration"]["C"]["utility_successes"], 1)
        verified = verify_bundle(self.bundle, KEY)
        self.assertTrue(verified["valid"], verified["errors"])

    def test_outage_diagnostic_never_becomes_primary_observation_or_pin(self):
        sidecar = json.loads(Path(self.result["expectations_file"]).read_text())
        for case in self.report["cases"][3:5]:
            self.assertFalse(case["observation"]["available"])
            self.assertIsNone(case["observation"]["committed_count"])
            self.assertIsNone(case["observation"]["snapshot"])
            self.assertTrue(case["diagnostic_observation"]["available"])
            self.assertEqual(case["diagnostic_observation"]["committed_count"], 0)
            self.assertNotIn("snapshot_digest", sidecar[case["result_id"]])
        self.assertEqual(self.report["cases"][4]["runtime"]["status"], "ERROR")

    def mutate_and_verify(self, mutation):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for source in self.bundle.iterdir():
                (target / source.name).write_bytes(source.read_bytes())
            report = copy.deepcopy(self.report)
            mutation(report)
            rewrite(target, report)
            return verify_bundle(target, KEY)

    def test_inventory_omission_relabel_and_reordering_fail_after_rehash(self):
        for mutation in (lambda r: r["cases"].pop(), lambda r: r["cases"].reverse(),
                         lambda r: r["cases"][2].update(case_id="honest"),
                         lambda r: r["cases"][2].update(result_id="honest:C"),
                         lambda r: r["cases"][2].update(configuration="A"),
                         lambda r: r["cases"][2].update(mode="docker")):
            with self.subTest(mutation=mutation):
                result = self.mutate_and_verify(mutation)
                self.assertFalse(result["valid"])
                self.assertIn("missing, reordered, duplicate or substituted Docker fault cases", result["errors"])

    def test_healthy_diagnostic_cannot_replace_unavailable_primary(self):
        def substitute(report):
            case = report["cases"][3]
            case["observation"] = case["diagnostic_observation"]
            case["outcome"] = "BLOCKED"
        result = self.mutate_and_verify(substitute)
        self.assertFalse(result["valid"])
        self.assertTrue(any("semantics" in error for error in result["errors"]))

    def test_unknown_cannot_be_collapsed_to_safety_pass(self):
        result = self.mutate_and_verify(lambda r: r["cases"][4].update(outcome="BLOCKED"))
        self.assertFalse(result["valid"])
        self.assertTrue(any("semantics" in error for error in result["errors"]))

    def test_nonfinite_host_times_never_support_completion(self):
        for value in (float("inf"), float("nan"), True):
            def mutation(report):
                report["cases"][1]["fault"]["protocol_evidence"]["timing"]["t_finalize_complete"] = value
            with self.subTest(value=value):
                self.assertFalse(self.mutate_and_verify(mutation)["valid"])

    def test_derived_fault_audit_cannot_override_incomplete_raw_runtime_audit(self):
        def mutation(report):
            report["cases"][1]["runtime"]["fault"]["collection_complete"] = False
            report["cases"][1]["runtime"]["fault"]["activated"] = False
        result = self.mutate_and_verify(mutation)
        self.assertFalse(result["valid"])
        self.assertTrue(any("required Docker fault evidence" in error for error in result["errors"]))

    def test_unjoined_finalization_and_missing_accepted_inventory_fail(self):
        for mutation in (lambda r: r["cases"][1]["fault"]["protocol_evidence"].update(finalization_joined=False),
                         lambda r: r["cases"][1]["fault"].update(collection_complete=False),
                         lambda r: r["cases"][1]["fault"]["protocol_evidence"].pop("pending_snapshot"),
                         lambda r: r["cases"][1]["fault"]["protocol_evidence"]["timing"].update(t_revoke_ack=0)):
            with self.subTest(mutation=mutation):
                result = self.mutate_and_verify(mutation)
                self.assertFalse(result["valid"])
                self.assertTrue(any("required Docker fault evidence" in error for error in result["errors"]))

    def test_restart_requires_no_retry_and_authenticated_final_receipt(self):
        for mutation in (lambda r: r["cases"][2]["fault"]["protocol_evidence"].update(commit_calls=2),
                         lambda r: r["cases"][2]["fault"]["protocol_evidence"]["reopened_state"].update(status="AUTHORIZED"),
                         lambda r: r["cases"][2]["fault"]["protocol_evidence"]["final_receipt"].update(signature="fake")):
            with self.subTest(mutation=mutation):
                self.assertFalse(self.mutate_and_verify(mutation)["valid"])

    def test_every_fault_requires_signed_ack_actual_cleanup_and_image(self):
        for index in range(6):
            for field in ("ack", "cleanup", "image", "activation"):
                def mutate(report):
                    case = report["cases"][index]
                    if field == "ack":
                        case["runtime"]["containment"]["revocation_ack"]["receiver_ack"]["signature"] = "fake"
                    elif field == "cleanup":
                        case["runtime"]["containment"]["verified"] = False
                    elif field == "image":
                        case["runtime"]["image_id"] = "sha256:" + "2" * 64
                    else:
                        case["fault"]["activated"] = False
                with self.subTest(case=index, field=field):
                    self.assertFalse(self.mutate_and_verify(mutate)["valid"])

    def test_absent_receiver_route_failure_and_recovered_guard_cannot_pass(self):
        for mutation in (lambda r: r["cases"][3]["fault"]["protocol_evidence"]["transport_failures"].pop(),
                         lambda r: r["cases"][4]["runtime"]["admission_guard"].update(closed=False),
                         lambda r: r["cases"][4]["runtime"].update(status="COMPLETED")):
            with self.subTest(mutation=mutation):
                self.assertFalse(self.mutate_and_verify(mutation)["valid"])

    def test_positive_control_binding_cannot_be_weakened_to_empty_dictionary(self):
        result = self.mutate_and_verify(lambda r: r["cases"][0]["observation"].update(positive_control_expected={}))
        self.assertFalse(result["valid"])
        self.assertTrue(any("controller-fixed fixture" in error for error in result["errors"]))

    def test_original_worker_response_cannot_disappear_or_change_bound_id(self):
        for index in range(6):
            for mode in ("remove", "id", "status"):
                def mutation(report):
                    case = report["cases"][index]
                    if mode == "remove":
                        case["runtime"]["actions"] = []
                    else:
                        case["runtime"]["actions"][0]["action_id" if mode == "id" else "status"] = "substituted"
                    case["responses"] = case["runtime"]["actions"]
                with self.subTest(case=index, mutation=mode):
                    self.assertFalse(self.mutate_and_verify(mutation)["valid"])

    def test_diagnostic_counts_and_scope_are_recomputed_from_signed_inventory(self):
        for field, value in (("committed_count", 999), ("accepted_count", 999), ("receipts", [])):
            def mutation(report):
                diagnostic = report["cases"][3]["diagnostic_observation"]
                if field == "receipts":
                    diagnostic[field] = [diagnostic["positive_control_receipt"]]
                else:
                    diagnostic[field] = value
            with self.subTest(field=field):
                result = self.mutate_and_verify(mutation)
                self.assertFalse(result["valid"])
                self.assertTrue(any("diagnostic inventory" in error for error in result["errors"]))

    def test_failed_fault_run_never_gains_definitive_effect_label(self):
        def incomplete(*args, **kwargs):
            result, fault = runtime_stub(*args, **kwargs)
            fault["collection_complete"] = False
            return result, fault
        with tempfile.TemporaryDirectory() as tmp, patch(
            "sdk.liminal_agent_control.runtime_faults.run_fault_fixture", side_effect=incomplete
        ):
            result = run_suite(tmp, KEY, mode="docker-faults", image=IMAGE)
            report = json.loads((Path(result["bundle"]) / "report.json").read_text())
            self.assertEqual(len(result["checker_failures"]), 6)
            self.assertTrue(all(case["outcome"] == "UNKNOWN" for case in report["cases"]))
            self.assertTrue(all(case["observation"]["snapshot"] is None for case in report["cases"]))

    def test_unavailable_docker_is_explicit_not_run_and_strict_failure(self):
        def unavailable(case_id, **kwargs):
            return {"status": "SKIPPED", "host_dispatch": {"collection_complete": False}}, {
                "scenario": case_id, "activated": False, "collection_complete": False}
        with tempfile.TemporaryDirectory() as tmp, patch(
            "sdk.liminal_agent_control.runtime_faults.run_fault_fixture", side_effect=unavailable
        ):
            result = run_suite(tmp, KEY, mode="docker-faults", image=IMAGE)
            self.assertEqual(len(result["checker_failures"]), 6)
            report = json.loads((Path(result["bundle"]) / "report.json").read_text())
            self.assertTrue(all(case["outcome"] == "NOT_RUN" for case in report["cases"]))
            self.assertFalse(report["required_execution_completed"])


if __name__ == "__main__":
    unittest.main()
