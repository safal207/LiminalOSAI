"""Third-party contract tests for the public TRCP Adapter SDK v0.1.

These tests intentionally import the integration surface only.  Core modules
are inspected as text where an architectural boundary must be enforced, never
used to construct a successful consumer integration.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import subprocess
import sys
import tempfile
import traceback
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import sdk.liminal_trcp.sdk as public_sdk
from sdk.liminal_trcp.sdk import (
    ADAPTER_SDK_VERSION,
    NORMALIZED_WORKLOAD_SCHEMA,
    AdapterContractError,
    BindingCheck,
    BindingReceipt,
    BindingVerificationError,
    ExecutionReplayResult,
    ExternalWorkloadResult,
    WorkloadNormalizationError,
    build_workload_evidence,
    normalize_workload,
    run_external_workload,
    verify_binding,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "trcp_external_consumer_reference" / "self_check.py"
REPLAY = ROOT / "sdk" / "liminal_trcp" / "replay.py"

PUBLIC_NAMES = {
    "ADAPTER_SDK_VERSION",
    "NORMALIZED_WORKLOAD_SCHEMA",
    "AdapterContractError",
    "BindingCheck",
    "BindingReceipt",
    "BindingVerificationError",
    "ExecutionReplayHook",
    "ExecutionReplayResult",
    "ExternalWorkloadAdapter",
    "ExternalWorkloadResult",
    "TRCPAdapterError",
    "WorkloadNormalizationError",
    "build_workload_evidence",
    "normalize_workload",
    "run_external_workload",
    "verify_binding",
}

REQUEST = {
    "actor": "order-service",
    "available": 5,
    "operation": "reserve",
    "order_id": "order-1001",
    "quantity": 2,
}


def _result(request: Mapping[str, Any]) -> dict[str, Any]:
    accepted = request["operation"] == "reserve" and (
        0 < request["quantity"] <= request["available"]
    )
    return {
        "accepted": accepted,
        "remaining": request["available"] - request["quantity"]
        if accepted
        else request["available"],
        "status": "RESERVED" if accepted else "REJECTED",
    }


class OrderAdapter:
    consumer_type = "example-order-system"

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        return normalize_workload(
            consumer_type=self.consumer_type,
            requested_operation=external_input["operation"],
            actor=external_input["actor"],
            input_data=external_input,
            result=_result(external_input),
        )


class ReplayOrderAdapter(OrderAdapter):
    def replay_execution(self, workload: Mapping[str, Any]) -> dict[str, Any]:
        return _result(workload["input"])


class PublicSurfaceTests(unittest.TestCase):
    def test_exact_public_all(self):
        self.assertEqual(PUBLIC_NAMES, set(public_sdk.__all__))
        self.assertEqual(ADAPTER_SDK_VERSION, "0.1")
        self.assertEqual(
            NORMALIZED_WORKLOAD_SCHEMA,
            "generic-workload-evidence-v0.1",
        )

    def test_public_result_is_typed_and_binding_passes(self):
        outcome = run_external_workload(OrderAdapter(), REQUEST)
        self.assertIsInstance(outcome, ExternalWorkloadResult)
        self.assertIsInstance(outcome.binding_receipt, BindingReceipt)
        self.assertTrue(
            all(isinstance(check, BindingCheck) for check in outcome.binding_receipt.checks)
        )
        self.assertIsInstance(outcome.execution_replay, ExecutionReplayResult)
        self.assertEqual(outcome.binding_receipt.result, "PASS")
        self.assertEqual(outcome.execution_replay.status, "NOT_RUN")
        self.assertRegex(outcome.workload_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(outcome.bundle_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(outcome.receipt_sha256, r"^[0-9a-f]{64}$")

    def test_external_adapter_needs_only_consumer_type_and_normalize(self):
        adapter = OrderAdapter()
        self.assertFalse(hasattr(adapter, "task"))
        self.assertFalse(hasattr(adapter, "fixture"))
        self.assertEqual(
            run_external_workload(adapter, REQUEST).binding_receipt.result,
            "PASS",
        )


class DeterminismAndBindingTests(unittest.TestCase):
    def test_identical_runs_have_identical_artifacts_and_hashes(self):
        first = run_external_workload(OrderAdapter(), REQUEST)
        second = run_external_workload(OrderAdapter(), copy.deepcopy(REQUEST))
        self.assertEqual(first.normalized_workload, second.normalized_workload)
        self.assertEqual(first.workload_evidence, second.workload_evidence)
        self.assertEqual(first.evidence_bundle, second.evidence_bundle)
        self.assertEqual(first.binding_receipt, second.binding_receipt)
        self.assertEqual(
            (first.workload_sha256, first.bundle_sha256, first.receipt_sha256),
            (second.workload_sha256, second.bundle_sha256, second.receipt_sha256),
        )

    def test_changed_request_changes_every_public_hash(self):
        changed = copy.deepcopy(REQUEST)
        changed["quantity"] = 3
        original = run_external_workload(OrderAdapter(), REQUEST)
        altered = run_external_workload(OrderAdapter(), changed)
        self.assertNotEqual(original.workload_sha256, altered.workload_sha256)
        self.assertNotEqual(original.bundle_sha256, altered.bundle_sha256)
        self.assertNotEqual(original.receipt_sha256, altered.receipt_sha256)

    def test_build_and_verify_helpers_are_public_and_tamper_evident(self):
        outcome = run_external_workload(OrderAdapter(), REQUEST)
        evidence = build_workload_evidence(outcome.normalized_workload)
        self.assertEqual(evidence, outcome.workload_evidence)
        self.assertEqual(verify_binding(outcome.evidence_bundle), outcome.binding_receipt)

        tampered = copy.deepcopy(outcome.evidence_bundle)
        tampered["consumer_evidence"]["input"]["quantity"] = 4
        receipt = verify_binding(tampered)
        self.assertEqual(receipt.result, "FAIL")
        self.assertEqual(receipt.failed_check, "BUNDLE_INTEGRITY")
        self.assertNotEqual(receipt.receipt_sha256, outcome.receipt_sha256)

    def test_identical_fresh_processes_have_identical_output(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        with tempfile.TemporaryDirectory() as temp_dir:
            commands = [sys.executable, str(EXAMPLE)]
            first = subprocess.run(
                commands,
                cwd=temp_dir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            second = subprocess.run(
                commands,
                cwd=temp_dir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(json.loads(first.stdout), json.loads(second.stdout))


class ExecutionReplaySeparationTests(unittest.TestCase):
    def test_not_run_and_unsupported_are_distinct(self):
        not_run = run_external_workload(OrderAdapter(), REQUEST)
        unsupported = run_external_workload(
            OrderAdapter(), REQUEST, execution_replay=True
        )
        self.assertEqual(not_run.execution_replay.status, "NOT_RUN")
        self.assertEqual(unsupported.execution_replay.status, "UNSUPPORTED")
        self.assertEqual(not_run.binding_receipt, unsupported.binding_receipt)

    def test_matching_hook_passes_without_changing_binding(self):
        no_replay = run_external_workload(ReplayOrderAdapter(), REQUEST)
        replayed = run_external_workload(
            ReplayOrderAdapter(), REQUEST, execution_replay=True
        )
        self.assertEqual(replayed.execution_replay.status, "PASS")
        self.assertTrue(replayed.execution_replay.matches_binding_result)
        self.assertEqual(no_replay.binding_receipt, replayed.binding_receipt)

    def test_mismatch_and_error_are_separate_from_binding(self):
        class MismatchAdapter(OrderAdapter):
            def replay_execution(self, workload):
                return {"status": "DIFFERENT"}

        class ErrorAdapter(OrderAdapter):
            def replay_execution(self, workload):
                raise RuntimeError("synthetic replay failure")

        baseline = run_external_workload(OrderAdapter(), REQUEST)
        mismatch = run_external_workload(
            MismatchAdapter(), REQUEST, execution_replay=True
        )
        errored = run_external_workload(ErrorAdapter(), REQUEST, execution_replay=True)
        self.assertEqual(mismatch.execution_replay.status, "MISMATCH")
        self.assertFalse(mismatch.execution_replay.matches_binding_result)
        self.assertEqual(errored.execution_replay.status, "ERROR")
        self.assertEqual(errored.execution_replay.error, "RuntimeError")
        self.assertNotIn("synthetic replay failure", errored.execution_replay.error or "")
        self.assertEqual(mismatch.binding_receipt, baseline.binding_receipt)
        self.assertEqual(errored.binding_receipt, baseline.binding_receipt)


class StrictContractTests(unittest.TestCase):
    def test_normalized_contract_has_exact_six_fields_and_detaches_input(self):
        source = {"nested": {"value": 1}}
        workload = normalize_workload(
            consumer_type="example-order-system",
            requested_operation="reserve",
            actor="order-service",
            input_data=source,
            result={"status": "RESERVED"},
        )
        source["nested"]["value"] = 2
        self.assertEqual(
            set(workload),
            {"schema", "consumer_type", "requested_operation", "actor", "input", "result"},
        )
        self.assertEqual(workload["input"]["nested"]["value"], 1)

    def test_non_json_and_non_finite_values_are_rejected(self):
        bad_values = ({"value": {1}}, {"value": b"bytes"}, {"value": float("nan")})
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    WorkloadNormalizationError, "JSON"
                ):
                    normalize_workload(
                        consumer_type="example-order-system",
                        requested_operation="reserve",
                        actor="order-service",
                        input_data=value,
                        result={},
                    )

    def test_non_string_keys_cycles_invalid_unicode_and_oversize_are_rejected(self):
        cyclic: dict[str, Any] = {}
        cyclic["self"] = cyclic
        invalid_values = (
            {1: "not-a-string-key"},
            cyclic,
            {"text": "\ud800"},
            {"payload": "x" * 900_001},
        )
        for value in invalid_values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(WorkloadNormalizationError):
                    normalize_workload(
                        consumer_type="example-order-system",
                        requested_operation="reserve",
                        actor="order-service",
                        input_data=value,
                        result={},
                    )

    def test_missing_extra_and_wrong_schema_fields_are_rejected(self):
        valid = OrderAdapter().normalize(REQUEST)
        variants = []
        missing = copy.deepcopy(valid)
        del missing["result"]
        variants.append(missing)
        extra = copy.deepcopy(valid)
        extra["unbound_metadata"] = True
        variants.append(extra)
        wrong_schema = copy.deepcopy(valid)
        wrong_schema["schema"] = "generic-workload-evidence-v9.9"
        variants.append(wrong_schema)

        for normalized in variants:
            class StaticAdapter:
                consumer_type = "example-order-system"

                def normalize(self, external_input, artifact=normalized):
                    return artifact

            with self.subTest(normalized=normalized):
                with self.assertRaises(WorkloadNormalizationError):
                    run_external_workload(StaticAdapter(), REQUEST)

    def test_adapter_consumer_type_must_be_valid_and_match_body(self):
        class MismatchedAdapter(OrderAdapter):
            consumer_type = "different-system"

            def normalize(self, external_input):
                body = super().normalize(external_input)
                body["consumer_type"] = "example-order-system"
                return body

        with self.assertRaisesRegex(AdapterContractError, "does not match"):
            run_external_workload(MismatchedAdapter(), REQUEST)
        for invalid in ("", "UPPERCASE", "x" * 65):
            with self.subTest(consumer_type=invalid):
                adapter = OrderAdapter()
                adapter.consumer_type = invalid
                with self.assertRaisesRegex(AdapterContractError, "consumer_type"):
                    run_external_workload(adapter, REQUEST)

    def test_non_mapping_contract_inputs_raise_public_errors(self):
        with self.assertRaisesRegex(WorkloadNormalizationError, "mapping"):
            normalize_workload(
                consumer_type="example-order-system",
                requested_operation="reserve",
                actor="order-service",
                input_data=[],  # type: ignore[arg-type]
                result={},
            )
        with self.assertRaisesRegex(AdapterContractError, "mapping"):
            run_external_workload(OrderAdapter(), [])  # type: ignore[arg-type]
        with self.assertRaisesRegex(BindingVerificationError, "mapping"):
            verify_binding([])  # type: ignore[arg-type]

    def test_external_normalize_is_called_once_and_snapshotted(self):
        class CountingAdapter(OrderAdapter):
            def __init__(self):
                self.calls = 0

            def normalize(self, external_input):
                self.calls += 1
                return super().normalize(external_input)

        adapter = CountingAdapter()
        outcome = run_external_workload(adapter, REQUEST)
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(outcome.binding_receipt.result, "PASS")

    def test_adapter_and_hook_exception_details_are_not_exposed(self):
        class SecretNormalizeAdapter(OrderAdapter):
            def normalize(self, external_input):
                raise RuntimeError("SECRET-NORMALIZE")

        class SecretHookAdapter(OrderAdapter):
            def replay_execution(self, workload):
                raise WorkloadNormalizationError("SECRET-HOOK")

        with self.assertRaises(WorkloadNormalizationError) as caught:
            run_external_workload(SecretNormalizeAdapter(), REQUEST)
        self.assertNotIn("SECRET-NORMALIZE", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        formatted = "".join(
            traceback.format_exception(
                type(caught.exception),
                caught.exception,
                caught.exception.__traceback__,
            )
        )
        self.assertNotIn("SECRET-NORMALIZE", formatted)
        replayed = run_external_workload(
            SecretHookAdapter(), REQUEST, execution_replay=True
        )
        self.assertEqual(replayed.execution_replay.status, "ERROR")
        self.assertNotIn("SECRET-HOOK", replayed.execution_replay.error or "")

class ReferenceIsolationTests(unittest.TestCase):
    def test_example_imports_liminal_symbols_only_from_public_sdk(self):
        tree = ast.parse(EXAMPLE.read_text(encoding="utf-8"), filename=str(EXAMPLE))
        liminal_imports: list[str] = []
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("sdk.liminal"):
                    liminal_imports.append(node.module)
                    imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                liminal_imports.extend(
                    alias.name for alias in node.names if alias.name.startswith("sdk.liminal")
                )
        self.assertEqual(liminal_imports, ["sdk.liminal_trcp.sdk"])
        self.assertEqual(
            imported_names,
            {"ADAPTER_SDK_VERSION", "normalize_workload", "run_external_workload"},
        )

    def test_example_has_no_core_or_private_symbol_references(self):
        source = EXAMPLE.read_text(encoding="utf-8")
        forbidden = (
            "adapter.py",
            "consumer.py",
            "delegated_spending",
            "MockProvider",
            "replay.py",
            "ScopeEnvelope",
            "TRCPSimulator",
            "AuthorizationRecord",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

    def test_replay_source_contains_no_reference_consumer_logic(self):
        source = REPLAY.read_text(encoding="utf-8").lower()
        for token in (
            "example-order-system",
            "order-1001",
            "execute_order",
            "trcp_external_consumer_reference",
        ):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
