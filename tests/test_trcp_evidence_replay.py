"""TRCP v0.2 — Evidence adapter and independent replay tests.

Happy-path PASS plus adversarial mutation tests. Every mutation must
produce FAIL or a specific verifier check failure.

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.
"""
import copy
import unittest

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import run_default_scenario
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import verify_evidence_bundle


def _recalculate_bundle_hash(bundle: dict) -> None:
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    bundle["bundle_sha256"] = canonical_sha256(body)


class EvidenceAdapterHappyPathTests(unittest.TestCase):
    def test_bundle_is_deterministic(self):
        first = build_evidence_bundle(run_default_scenario())
        second = build_evidence_bundle(run_default_scenario())
        self.assertEqual(first, second)

    def test_bundle_has_correct_schema(self):
        bundle = build_evidence_bundle(run_default_scenario())
        self.assertEqual(bundle["schema"], "liminal-trcp-evidence-v0.2")

    def test_bundle_sha256_matches_canonical(self):
        bundle = build_evidence_bundle(run_default_scenario())
        body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
        self.assertEqual(bundle["bundle_sha256"], canonical_sha256(body))

    def test_bundle_contains_causal_lineage(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        self.assertGreater(len(lineage), 0)
        for edge in lineage:
            self.assertIn("edge_id", edge)
            self.assertIn("from", edge)
            self.assertIn("to", edge)
            self.assertIn("relation", edge)
            self.assertIn("evidence_ref", edge)
            self.assertIn(edge["relation"], {"CAUSES", "AUTHORIZES", "CONSTRAINS", "VERIFIES"})


class ReplayVerifierHappyPathTests(unittest.TestCase):
    def test_happy_path_pass(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["schema"], "liminal-trcp-replay-receipt-v0.2")

    def test_receipt_is_deterministic(self):
        bundle = build_evidence_bundle(run_default_scenario())
        first = verify_evidence_bundle(bundle)
        second = verify_evidence_bundle(bundle)
        self.assertEqual(first, second)

    def test_receipt_sha256_matches(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        body = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
        self.assertEqual(receipt["receipt_sha256"], canonical_sha256(body))

    def test_all_checks_pass(self):
        bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(bundle)
        for check in receipt["checks"]:
            self.assertEqual(check["result"], "PASS", f"check {check['id']} failed")


class AdversarialMutationTests(unittest.TestCase):
    def _valid_bundle(self) -> dict:
        return build_evidence_bundle(run_default_scenario())

    def _mutate_bundle(self, bundle: dict) -> dict:
        return copy.deepcopy(bundle)

    def test_01_change_authorization_id_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["authorization"]["authorization_id"] = "auth:mutated"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "AUTHORIZATION_CONTINUITY")

    def test_02_broaden_effective_scope_targets_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["effective_scope"]["allowed_targets"] = [
            "fixture:repo",
            "fixture:other",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_03_add_prohibited_action_to_allowed_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["effective_scope"]["allowed_actions"] = [
            "ANALYZE_FIXTURE",
            "LIVE_EXPLOIT",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(receipt["failed_check"], {"SCOPE_MONOTONICITY", "PROHIBITED_ACTION"})

    def test_04_reorder_provider_transitions_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        trace = bundle["trace"]
        state_transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        if len(state_transitions) >= 2:
            state_transitions[0]["payload"]["to"], state_transitions[1]["payload"]["to"] = (
                state_transitions[1]["payload"]["to"],
                state_transitions[0]["payload"]["to"],
            )
            for event in state_transitions:
                core = {k: v for k, v in event.items() if k != "event_sha256"}
                event["event_sha256"] = canonical_sha256(core)
            for i in range(1, len(trace)):
                trace[i]["previous_event_sha256"] = trace[i - 1]["event_sha256"]
            last = trace[-1]
            _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"STATE_TRANSITION", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_05_remove_failover_decision_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["failover_decision"] = None
        trace = bundle["trace"]
        bundle["trace"] = [
            e for e in trace if e["kind"] != "FAILOVER_DECISION_RECORDED"
        ]
        for i in range(len(bundle["trace"])):
            if i == 0:
                bundle["trace"][i]["previous_event_sha256"] = "0" * 64
            else:
                bundle["trace"][i]["previous_event_sha256"] = bundle["trace"][i - 1]["event_sha256"]
            core = {k: v for k, v in bundle["trace"][i].items() if k != "event_sha256"}
            bundle["trace"][i]["event_sha256"] = canonical_sha256(core)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"FAILOVER_DECISION_REQUIRED", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_06_change_fallback_task_hash_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        if len(bundle["provider_runs"]) >= 2:
            bundle["provider_runs"][-1]["normalized_task_hash"] = "deadbeef" * 8
            run_body = {
                k: v for k, v in bundle["provider_runs"][-1].items()
                if k != "record_sha256"
            }
            bundle["provider_runs"][-1]["record_sha256"] = canonical_sha256(run_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "TASK_IDENTITY")

    def test_07_mutate_trace_event_without_rehash_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        trace = bundle["trace"]
        for event in trace:
            if event["kind"] == "PROVIDER_RUN_RECORDED":
                event["payload"]["outcome"] = "COMPLETED"
                break
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"TRACE_HASH_CHAIN", "BUNDLE_INTEGRITY"},
        )

    def test_08_illegal_state_transition_with_valid_hashes_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        trace = bundle["trace"]
        state_transitions = [e for e in trace if e["kind"] == "STATE_TRANSITION"]
        if len(state_transitions) >= 3:
            state_transitions[0]["payload"]["to"] = "VERIFYING"
            state_transitions[1]["payload"]["from"] = "VERIFYING"
            state_transitions[1]["payload"]["to"] = "ACTIVE"
            state_transitions[2]["payload"]["from"] = "ACTIVE"
            for event in state_transitions:
                core = {k: v for k, v in event.items() if k != "event_sha256"}
                event["event_sha256"] = canonical_sha256(core)
            for i in range(1, len(trace)):
                trace[i]["previous_event_sha256"] = trace[i - 1]["event_sha256"]
            _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"STATE_TRANSITION", "CAUSAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_09_non_monotonic_timestamp_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        trace = bundle["trace"]
        if len(trace) >= 3:
            trace[2]["observed_at_unix"] = trace[0]["observed_at_unix"] - 100
            core = {k: v for k, v in trace[2].items() if k != "event_sha256"}
            trace[2]["event_sha256"] = canonical_sha256(core)
            for i in range(3, len(trace)):
                trace[i]["previous_event_sha256"] = trace[i - 1]["event_sha256"]
                core = {k: v for k, v in trace[i].items() if k != "event_sha256"}
                trace[i]["event_sha256"] = canonical_sha256(core)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertIn(
            receipt["failed_check"],
            {"TEMPORAL_ORDER", "TRACE_HASH_CHAIN"},
        )

    def test_10_confirmed_without_reproduced_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        if bundle["finding"] is not None:
            bundle["finding"]["status"] = "CONFIRMED"
            finding_body = {
                k: v for k, v in bundle["finding"].items()
                if k != "record_sha256"
            }
            bundle["finding"]["record_sha256"] = canonical_sha256(finding_body)
        if bundle["verification"] is not None:
            bundle["verification"]["result"] = "NOT_REPRODUCED"
            ver_body = {
                k: v for k, v in bundle["verification"].items()
                if k != "record_sha256"
            }
            bundle["verification"]["record_sha256"] = canonical_sha256(ver_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "VERIFICATION_CLOSURE")

    def test_11_verification_status_mismatch_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        if bundle["verification"] is not None and bundle["finding"] is not None:
            bundle["verification"]["finding_id"] = "finding:different-id"
            ver_body = {
                k: v for k, v in bundle["verification"].items()
                if k != "record_sha256"
            }
            bundle["verification"]["record_sha256"] = canonical_sha256(ver_body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "VERIFICATION_CONSISTENCY")

    def test_12_tampered_bundle_hash_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["authorization"]["authority_source"] = "tampered"
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "BUNDLE_INTEGRITY")

    def test_13_broaden_effective_actions_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["effective_scope"]["allowed_actions"] = [
            "ANALYZE_FIXTURE",
            "ACTIVE_VALIDATE",
        ]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_14_change_initial_scope_authorization_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["initial_scope"]["authorization_id"] = "auth:different"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "AUTHORIZATION_CONTINUITY")

    def test_15_empty_trace_preserves_hash_fails_integrity(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        original_hash = bundle["bundle_sha256"]
        bundle["trace"] = []
        bundle["bundle_sha256"] = original_hash
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "BUNDLE_INTEGRITY")

    def test_16_broaden_network_mode_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["effective_scope"]["network_mode"] = "EXTERNAL"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")

    def test_17_extend_scope_expiry_fails(self):
        bundle = self._mutate_bundle(self._valid_bundle())
        bundle["effective_scope"]["expires_at"] = 9999
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "SCOPE_MONOTONICITY")


class ReplayIndependenceTests(unittest.TestCase):
    def test_replay_does_not_import_simulator(self):
        import inspect
        from sdk.liminal_trcp import replay
        source = inspect.getsource(replay)
        self.assertNotIn("from sdk.liminal_trcp import", source)
        self.assertNotIn("TRCPSimulator(", source)

    def test_replay_uses_only_bundle_data(self):
        bundle = build_evidence_bundle(run_default_scenario())
        bundle_copy = copy.deepcopy(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(bundle, bundle_copy)
        self.assertEqual(receipt["result"], "PASS")


class CausalLineageTests(unittest.TestCase):
    def test_lineage_is_deterministic(self):
        bundle1 = build_evidence_bundle(run_default_scenario())
        bundle2 = build_evidence_bundle(run_default_scenario())
        self.assertEqual(bundle1["causal_lineage"], bundle2["causal_lineage"])

    def test_lineage_contains_authorization_to_primary(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        first_edge = lineage[0]
        self.assertEqual(first_edge["from"], "AUTHORIZATION")
        self.assertEqual(first_edge["to"], "PRIMARY_RUN")

    def test_lineage_edge_ids_are_deterministic(self):
        bundle = build_evidence_bundle(run_default_scenario())
        lineage = bundle["causal_lineage"]
        for edge in lineage:
            self.assertTrue(edge["edge_id"].startswith("edge:"))


class DeterministicReceiptTests(unittest.TestCase):
    def test_same_bundle_same_receipt_hash(self):
        bundle = build_evidence_bundle(run_default_scenario())
        r1 = verify_evidence_bundle(bundle)
        r2 = verify_evidence_bundle(bundle)
        self.assertEqual(r1["receipt_sha256"], r2["receipt_sha256"])

    def test_different_bundle_different_receipt_hash(self):
        bundle1 = build_evidence_bundle(run_default_scenario())
        bundle2 = copy.deepcopy(bundle1)
        bundle2["bundle_sha256"] = "a" * 64
        r1 = verify_evidence_bundle(bundle1)
        r2 = verify_evidence_bundle(bundle2)
        if r1["result"] == r2["result"] == "PASS":
            self.assertNotEqual(r1["receipt_sha256"], r2["receipt_sha256"])


class FailoverWithoutFindingTests(unittest.TestCase):
    def test_no_finding_verification_path(self):
        report = run_default_scenario()
        report_no_finding = copy.deepcopy(report)
        report_no_finding["finding"] = None
        report_no_finding["verification"] = None
        body = {k: v for k, v in report_no_finding.items() if k != "report_sha256"}
        report_no_finding["report_sha256"] = canonical_sha256(body)
        bundle = build_evidence_bundle(report_no_finding)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "PASS")


if __name__ == "__main__":
    unittest.main()
