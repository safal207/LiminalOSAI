"""TRCP v0.4 — External consumer adapter and replay contract tests.

Covers the non-escrow delegated-spending consumer:

- generic adapter normalization (deterministic, canonical)
- non-escrow fixture passing the existing binding verifier with zero
  special-case logic in replay.py
- deterministic workload/bundle/receipt hashes
- adversarial binding failures
- legacy TRCP evidence compatibility
- execution replay as an optional, separate concern

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.
"""

from __future__ import annotations

import copy
import re
import subprocess
import sys
import unittest
from pathlib import Path

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import run_default_scenario
from sdk.liminal_trcp.adapter import EXECUTION_REPLAY_NOT_RUN, run_external_consumer
from sdk.liminal_trcp.consumer import VALID_PATH, run_contract_consumer
from sdk.liminal_trcp.delegated_spending import (
    AUTHORITY_EXTERNAL_INPUT,
    CUMULATIVE_QUOTA,
    LIMIT_EXTERNAL_INPUT,
    PER_ACTION_LIMIT,
    QUOTA_EXTERNAL_INPUT,
    REJECTED_EXTERNAL_INPUT,
    TERMINAL_EXTERNAL_INPUT,
    VALID_EXTERNAL_INPUT,
    DelegatedSpendingAdapter,
    delegated_workload_result,
    normalize_delegated_workload,
)
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import (
    GENERIC_WORKLOAD_EVIDENCE_SCHEMA,
    WORKLOAD_EVIDENCE_SCHEMA,
    WORKLOAD_EVIDENCE_SCHEMAS,
    verify_evidence_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = ROOT / "scripts" / "replay_trcp_external_consumer.py"
GENERIC_BODY_FIELDS = (
    "schema",
    "consumer_type",
    "requested_operation",
    "actor",
    "input",
    "result",
)


def _recalculate_bundle_hash(bundle):
    body = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    bundle["bundle_sha256"] = canonical_sha256(body)


class DelegatedFixtureInvariantTests(unittest.TestCase):
    def test_valid_path_executes_without_violations(self):
        result = delegated_workload_result(VALID_EXTERNAL_INPUT)
        self.assertEqual(result["final_state"], "EXECUTED")
        self.assertEqual(result["spent"], 40)
        self.assertEqual(result["violations"], [])

    def test_rejected_action_causes_no_mutation(self):
        result = delegated_workload_result(REJECTED_EXTERNAL_INPUT)
        self.assertEqual(result["final_state"], "REJECTED")
        self.assertEqual(result["spent"], 0)
        self.assertEqual(result["violations"], [])

    def test_unauthorized_actor_violates_actor_authority(self):
        result = delegated_workload_result(AUTHORITY_EXTERNAL_INPUT)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["actor-authority"],
        )
        self.assertEqual(result["final_state"], "ACTIVE")

    def test_per_action_limit_violation(self):
        result = delegated_workload_result(LIMIT_EXTERNAL_INPUT)
        self.assertGreater(LIMIT_EXTERNAL_INPUT["operations"][0]["amount"], PER_ACTION_LIMIT)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["per-action-limit"],
        )

    def test_cumulative_quota_violation(self):
        result = delegated_workload_result(QUOTA_EXTERNAL_INPUT)
        self.assertGreater(result["spent"], CUMULATIVE_QUOTA)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["cumulative-quota"],
        )

    def test_terminal_exclusivity_and_rejected_no_mutation(self):
        result = delegated_workload_result(TERMINAL_EXTERNAL_INPUT)
        self.assertEqual(result["final_state"], "EXECUTED")
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["terminal-exclusivity", "rejected-action-no-mutation"],
        )

    def test_actor_schedule_length_mismatch_raises(self):
        bad_input = copy.deepcopy(VALID_EXTERNAL_INPUT)
        bad_input["actor_schedule"] = ["agent"]
        with self.assertRaises(ValueError):
            delegated_workload_result(bad_input)


class GenericAdapterNormalizationTests(unittest.TestCase):
    def test_normalize_is_deterministic(self):
        first = normalize_delegated_workload(VALID_EXTERNAL_INPUT)
        second = normalize_delegated_workload(VALID_EXTERNAL_INPUT)
        self.assertEqual(first, second)

    def test_normalized_body_uses_generic_schema(self):
        body = normalize_delegated_workload(VALID_EXTERNAL_INPUT)
        self.assertEqual(body["schema"], GENERIC_WORKLOAD_EVIDENCE_SCHEMA)
        self.assertEqual(set(GENERIC_BODY_FIELDS), set(body))
        self.assertEqual(body["consumer_type"], "delegated-spending")
        self.assertEqual(
            body["requested_operation"],
            ["request_action", "approve", "execute"],
        )
        self.assertEqual(body["actor"], ["agent", "approver", "agent"])

    def test_normalized_body_has_no_escrow_fields(self):
        body = normalize_delegated_workload(VALID_EXTERNAL_INPUT)
        self.assertNotIn("requested_path", body)
        self.assertNotIn("deposited_amount", body)
        self.assertNotIn("released_amount", body)
        self.assertNotIn("refunded_amount", body)

    def test_changed_external_input_changes_workload_body(self):
        changed = copy.deepcopy(VALID_EXTERNAL_INPUT)
        changed["operations"][0]["amount"] = 60
        self.assertNotEqual(
            normalize_delegated_workload(VALID_EXTERNAL_INPUT),
            normalize_delegated_workload(changed),
        )

    def test_evidence_workload_sha256_matches_canonical_body(self):
        adapter = DelegatedSpendingAdapter()
        body = adapter.normalize(VALID_EXTERNAL_INPUT)
        task = adapter.task(canonical_sha256(body))
        evidence = {
            **body,
            "task": task,
            "task_fixture": task["fixture"],
            "workload_sha256": canonical_sha256(body),
        }
        self.assertEqual(evidence["workload_sha256"], canonical_sha256(body))
        self.assertEqual(
            evidence["task_fixture"],
            f"delegated-spending-quota-v0.1@sha256:{evidence['workload_sha256']}",
        )


class ExternalConsumerPipelineTests(unittest.TestCase):
    def test_non_escrow_fixture_passes_binding_replay(self):
        outcome = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        binding = next(
            check for check in outcome["receipt"]["checks"]
            if check["id"] == "WORKLOAD_EVIDENCE_BINDING"
        )
        self.assertEqual(binding["result"], "PASS")
        self.assertIsNone(outcome["report"]["finding"])
        self.assertEqual(outcome["report"]["final_state"], "CLOSED")

    def test_violating_fixture_still_passes_binding_with_finding(self):
        outcome = run_external_consumer(
            DelegatedSpendingAdapter(),
            AUTHORITY_EXTERNAL_INPUT,
        )
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        finding = outcome["report"]["finding"]
        self.assertIsNotNone(finding)
        self.assertEqual(finding["finding_class"], "WORKLOAD_INVARIANT_VIOLATION")
        self.assertIn("actor-authority", finding["summary"])
        self.assertEqual(finding["status"], "CONFIRMED")

    def test_two_identical_runs_produce_same_hashes(self):
        first = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        second = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        self.assertEqual(
            first["workload_evidence"]["workload_sha256"],
            second["workload_evidence"]["workload_sha256"],
        )
        self.assertEqual(first["bundle"], second["bundle"])
        self.assertEqual(first["receipt"], second["receipt"])
        self.assertEqual(
            first["bundle"]["bundle_sha256"],
            second["bundle"]["bundle_sha256"],
        )
        self.assertEqual(
            first["receipt"]["receipt_sha256"],
            second["receipt"]["receipt_sha256"],
        )

    def test_changed_external_input_changes_all_hashes(self):
        changed = copy.deepcopy(VALID_EXTERNAL_INPUT)
        changed["operations"][0]["amount"] = 60
        original = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        altered = run_external_consumer(DelegatedSpendingAdapter(), changed)
        self.assertNotEqual(
            original["workload_evidence"]["workload_sha256"],
            altered["workload_evidence"]["workload_sha256"],
        )
        self.assertNotEqual(
            original["bundle"]["bundle_sha256"],
            altered["bundle"]["bundle_sha256"],
        )
        self.assertNotEqual(
            original["receipt"]["receipt_sha256"],
            altered["receipt"]["receipt_sha256"],
        )

    def test_replay_does_not_mutate_bundle(self):
        outcome = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        bundle_copy = copy.deepcopy(outcome["bundle"])
        verify_evidence_bundle(outcome["bundle"])
        self.assertEqual(outcome["bundle"], bundle_copy)

    def test_reproduction_mismatch_is_not_confirmed(self):
        class FlakyAdapter:
            consumer_type = "delegated-spending"

            def __init__(self):
                self._delegate = DelegatedSpendingAdapter()
                self.calls = 0

            def normalize(self, external_input):
                self.calls += 1
                body = normalize_delegated_workload(external_input)
                if self.calls == 2:
                    body = copy.deepcopy(body)
                    body["result"]["final_state"] = "ACTION_REQUESTED"
                return body

            def task(self, workload_sha256):
                return self._delegate.task(workload_sha256)

            def fixture(self, workload_sha256):
                return self._delegate.fixture(workload_sha256)

        outcome = run_external_consumer(FlakyAdapter(), AUTHORITY_EXTERNAL_INPUT)

        self.assertFalse(outcome["reproduction"]["matches_original"])
        self.assertEqual(outcome["report"]["verification"]["result"], "NOT_REPRODUCED")
        self.assertEqual(outcome["report"]["finding"]["status"], "NOT_REPRODUCED")
        self.assertEqual(outcome["report"]["final_state"], "CLOSED")
        self.assertEqual(outcome["receipt"]["result"], "PASS")


class BindingAdversarialTests(unittest.TestCase):
    def _valid_bundle(self):
        outcome = run_external_consumer(DelegatedSpendingAdapter(), VALID_EXTERNAL_INPUT)
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        return outcome["bundle"]

    def test_stripped_consumer_evidence_fails(self):
        bundle = self._valid_bundle()
        del bundle["consumer_evidence"]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_mismatched_provider_workload_hash_fails(self):
        bundle = self._valid_bundle()
        for run in bundle["provider_runs"]:
            run["provider_metadata"]["workload_sha256"] = "1" * 64
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_mutated_normalized_result_fails(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["result"]["final_state"] = "ACTION_REQUESTED"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_mutated_normalized_input_fails(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["input"]["operations"][0]["amount"] = 999
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_unrecognized_schema_fails(self):
        bundle = self._valid_bundle()
        bundle["consumer_evidence"]["schema"] = "generic-workload-evidence-v9.9"
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_missing_required_generic_field_fails(self):
        bundle = self._valid_bundle()
        del bundle["consumer_evidence"]["consumer_type"]
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")

    def test_stale_task_reference_fails(self):
        bundle = self._valid_bundle()
        evidence = bundle["consumer_evidence"]
        evidence["result"]["violations"] = [{"invariant_id": "forged", "violated": True}]
        body = {field: evidence[field] for field in GENERIC_BODY_FIELDS}
        evidence["workload_sha256"] = canonical_sha256(body)
        _recalculate_bundle_hash(bundle)
        receipt = verify_evidence_bundle(bundle)
        self.assertEqual(receipt["result"], "FAIL")
        self.assertEqual(receipt["failed_check"], "WORKLOAD_EVIDENCE_BINDING")


class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_trcp_evidence_remains_compatible(self):
        legacy_bundle = build_evidence_bundle(run_default_scenario())
        receipt = verify_evidence_bundle(legacy_bundle)
        self.assertEqual(receipt["result"], "PASS")
        binding = next(
            check for check in receipt["checks"]
            if check["id"] == "WORKLOAD_EVIDENCE_BINDING"
        )
        self.assertEqual(binding["result"], "SKIP")

    def test_legacy_escrow_consumer_remains_compatible(self):
        outcome = run_contract_consumer(VALID_PATH)
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertEqual(
            outcome["workload_evidence"]["schema"],
            "contract-workload-evidence-v0.1",
        )
        self.assertIn(WORKLOAD_EVIDENCE_SCHEMA, WORKLOAD_EVIDENCE_SCHEMAS)

    def test_generic_schema_is_registered_in_verifier(self):
        self.assertIn(GENERIC_WORKLOAD_EVIDENCE_SCHEMA, WORKLOAD_EVIDENCE_SCHEMAS)
        self.assertEqual(
            WORKLOAD_EVIDENCE_SCHEMAS[GENERIC_WORKLOAD_EVIDENCE_SCHEMA],
            GENERIC_BODY_FIELDS,
        )


class AdapterOutcomeAdaptivityTests(unittest.TestCase):
    def _base_adapter(self, primary_outcome: str):
        from sdk.liminal_trcp import MockProvider

        class OutcomeAdapter(DelegatedSpendingAdapter):
            def fixture(self, workload_sha256):
                fixture = super().fixture(workload_sha256)
                fixture["primary"] = MockProvider(
                    self.primary_provider_id,
                    "mock-model-a",
                    primary_outcome,
                    provider_metadata={"workload_sha256": workload_sha256},
                )
                return fixture

        return OutcomeAdapter()

    def test_primary_completion_without_failover_passes(self):
        outcome = run_external_consumer(
            self._base_adapter("COMPLETED"),
            VALID_EXTERNAL_INPUT,
        )
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertIsNone(outcome["bundle"]["failover_decision"])
        self.assertEqual(len(outcome["bundle"]["provider_runs"]), 1)
        self.assertEqual(outcome["report"]["final_state"], "CLOSED")
        self.assertIsNone(outcome["report"]["finding"])

    def test_aborted_primary_closes_without_verification(self):
        outcome = run_external_consumer(
            self._base_adapter("ABORTED_BY_OPERATOR"),
            VALID_EXTERNAL_INPUT,
        )
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertEqual(outcome["report"]["final_state"], "ABORTED")
        self.assertIsNone(outcome["bundle"]["failover_decision"])
        self.assertIsNone(outcome["report"]["verification"])

    def test_failing_primary_still_triggers_failover(self):
        outcome = run_external_consumer(
            self._base_adapter("ACCESS_RESTRICTED"),
            VALID_EXTERNAL_INPUT,
        )
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertIsNotNone(outcome["bundle"]["failover_decision"])
        self.assertEqual(len(outcome["bundle"]["provider_runs"]), 2)

    def test_scalar_normalized_result_is_supported(self):
        class ScalarAdapter:
            consumer_type = "delegated-spending"

            def __init__(self):
                self._delegate = DelegatedSpendingAdapter()

            def normalize(self, external_input):
                body = self._delegate.normalize(external_input)
                body["result"] = {"final_state": body["result"]["final_state"]}
                return body

            def task(self, workload_sha256):
                return self._delegate.task(workload_sha256)

            def fixture(self, workload_sha256):
                return self._delegate.fixture(workload_sha256)

        outcome = run_external_consumer(ScalarAdapter(), VALID_EXTERNAL_INPUT)
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertIsNone(outcome["report"]["finding"])

    def test_replay_hook_exception_is_isolated_from_binding(self):
        class ThrowingHookAdapter(DelegatedSpendingAdapter):
            def replay_execution(self, workload_body):
                raise RuntimeError("sandbox exploded")

        outcome = run_external_consumer(
            ThrowingHookAdapter(),
            VALID_EXTERNAL_INPUT,
            execution_replay=True,
        )
        self.assertEqual(outcome["execution_replay"]["status"], "FAIL")
        self.assertIn("sandbox exploded", outcome["execution_replay"]["error"])
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertNotIn("execution", outcome["receipt"])


class ExecutionReplaySeparationTests(unittest.TestCase):
    def test_execution_replay_optional_and_not_required_for_binding(self):
        outcome = run_external_consumer(
            DelegatedSpendingAdapter(),
            VALID_EXTERNAL_INPUT,
            execution_replay=False,
        )
        self.assertEqual(outcome["execution_replay"]["status"], EXECUTION_REPLAY_NOT_RUN)
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_execution_replay_passes_for_deterministic_fixture(self):
        outcome = run_external_consumer(
            DelegatedSpendingAdapter(),
            VALID_EXTERNAL_INPUT,
            execution_replay=True,
        )
        self.assertEqual(outcome["execution_replay"]["status"], "PASS")
        self.assertTrue(outcome["execution_replay"]["matches_binding_result"])
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_requested_replay_without_hook_reports_unsupported(self):
        class HooklessAdapter:
            consumer_type = "delegated-spending"

            def __init__(self):
                self._delegate = DelegatedSpendingAdapter()

            def normalize(self, external_input):
                return self._delegate.normalize(external_input)

            def task(self, workload_sha256):
                return self._delegate.task(workload_sha256)

            def fixture(self, workload_sha256):
                return self._delegate.fixture(workload_sha256)

        outcome = run_external_consumer(
            HooklessAdapter(),
            VALID_EXTERNAL_INPUT,
            execution_replay=True,
        )
        self.assertEqual(outcome["execution_replay"]["status"], "UNSUPPORTED")
        self.assertEqual(outcome["receipt"]["result"], "PASS")

    def test_execution_replay_mismatch_is_explicit_and_separate(self):
        class MismatchAdapter(DelegatedSpendingAdapter):
            def replay_execution(self, workload_body):
                result = super().replay_execution(workload_body)
                result["final_state"] = "ACTION_REQUESTED"
                return result

        outcome = run_external_consumer(
            MismatchAdapter(),
            VALID_EXTERNAL_INPUT,
            execution_replay=True,
        )
        self.assertEqual(outcome["execution_replay"]["status"], "FAIL")
        self.assertFalse(outcome["execution_replay"]["matches_binding_result"])
        self.assertEqual(
            outcome["execution_replay"]["result"]["final_state"],
            "ACTION_REQUESTED",
        )
        self.assertEqual(outcome["receipt"]["result"], "PASS")
        self.assertNotIn("execution", outcome["receipt"])


class ReplayGenericityTests(unittest.TestCase):
    def test_replay_verifier_surface_is_consumer_neutral(self):
        from sdk.liminal_trcp.replay import CHECK_FUNCTIONS, WORKLOAD_EVIDENCE_SCHEMAS

        for schema in WORKLOAD_EVIDENCE_SCHEMAS:
            self.assertIsInstance(schema, str)
            self.assertTrue(schema.endswith("-evidence-v0.1"))
            self.assertNotIn("escrow", schema.lower())
            self.assertNotIn("delegated", schema.lower())
        for check_id in CHECK_FUNCTIONS:
            self.assertNotIn("EXECUTION_REPLAY", check_id)
            self.assertNotIn("CONSUMER_", check_id)
            self.assertNotIn("DELEGATED", check_id)

    def test_replay_source_has_no_consumer_conditional(self):
        from sdk.liminal_trcp.replay import __file__ as replay_file

        source = Path(replay_file).read_text(encoding="utf-8")
        self.assertNotIn("external_consumer", source)
        self.assertNotIn("delegated_spending", source)

    def test_replay_registry_is_verifier_side_only(self):
        from sdk.liminal_trcp.replay import __file__ as replay_file

        source = Path(replay_file).read_text(encoding="utf-8")
        self.assertIn("WORKLOAD_EVIDENCE_SCHEMAS", source)
        self.assertIn("contract-workload-evidence-v0.1", source)
        self.assertIn("generic-workload-evidence-v0.1", source)


class MalformedInputTests(unittest.TestCase):
    def test_missing_amount_is_deterministic_violation(self):
        malformed = {
            "operations": [{"operation": "request_action"}],
            "actor_schedule": ["agent"],
        }
        result = delegated_workload_result(malformed)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["malformed-operation"],
        )
        self.assertEqual(result["final_state"], "ACTIVE")

    def test_invariant_reports_are_deduplicated(self):
        double_limit = {
            "operations": [
                {"operation": "request_action", "amount": 120},
                {"operation": "approve"},
                {"operation": "execute"},
                {"operation": "execute"},
            ],
            "actor_schedule": ["agent", "approver", "agent", "agent"],
        }
        result = delegated_workload_result(double_limit)
        self.assertEqual(
            [v["invariant_id"] for v in result["violations"]],
            ["per-action-limit", "cumulative-quota"],
        )


class CliExitCodeTests(unittest.TestCase):
    def _run_cli(self):
        return subprocess.run(
            [sys.executable, str(CLI_SCRIPT)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=60,
            check=False,
        )

    def test_cli_exit_code_zero_on_pass(self):
        result = self._run_cli()
        self.assertEqual(result.returncode, 0, "stderr: " + result.stderr)

    def test_cli_output_reports_binding_and_execution_replay(self):
        result = self._run_cli()
        self.assertEqual(result.returncode, 0, "stderr: " + result.stderr)
        stdout = result.stdout
        self.assertIn("External Consumer Adapter", stdout)
        self.assertIn("Binding replay: PASS", stdout)
        self.assertIn("Execution replay: PASS", stdout)
        self.assertIn("Execution replay: NOT_RUN", stdout)
        for field in ("workload_sha256", "bundle_sha256", "receipt_sha256"):
            self.assertIn(f"{field}: ", stdout)
        digests = re.findall(r"(?:workload|bundle|receipt)_sha256: ([0-9a-f]{64})", stdout)
        self.assertEqual(len(digests), 6 * 3)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", d) for d in digests))


if __name__ == "__main__":
    unittest.main()
