"""Semantic mutation sensitivity tests for the public TRCP Adapter SDK.

These tests deliberately use only the public SDK surface. They distinguish
byte/evidence binding from business-rule sensitivity: a semantically different
producer can still create internally consistent evidence, while an independent
execution replay must expose a result mismatch for a discriminating vector.
"""

from __future__ import annotations

import copy
import unittest
from collections.abc import Mapping
from typing import Any

from sdk.liminal_trcp.sdk import normalize_workload, run_external_workload


MUTANTS = {
    "exclusive_upper_bound": {
        "vector": {
            "actor": "order-service",
            "available": 5,
            "operation": "reserve",
            "order_id": "boundary-1001",
            "quantity": 5,
        },
        "neutral": {
            "actor": "order-service",
            "available": 5,
            "operation": "reserve",
            "order_id": "neutral-1001",
            "quantity": 2,
        },
    },
    "accept_any_operation": {
        "vector": {
            "actor": "order-service",
            "available": 5,
            "operation": "inspect",
            "order_id": "operation-1001",
            "quantity": 1,
        },
        "neutral": {
            "actor": "order-service",
            "available": 5,
            "operation": "reserve",
            "order_id": "neutral-1002",
            "quantity": 2,
        },
    },
    "mutate_on_reject": {
        "vector": {
            "actor": "order-service",
            "available": 5,
            "operation": "reserve",
            "order_id": "reject-1001",
            "quantity": 6,
        },
        "neutral": {
            "actor": "order-service",
            "available": 5,
            "operation": "reserve",
            "order_id": "neutral-1003",
            "quantity": 2,
        },
    },
}


def _evaluate_order(
    request: Mapping[str, Any],
    *,
    mutant: str | None = None,
) -> dict[str, Any]:
    quantity = request["quantity"]
    available = request["available"]

    operation_allowed = request["operation"] == "reserve"
    if mutant == "accept_any_operation":
        operation_allowed = True

    capacity_allowed = 0 < quantity <= available
    if mutant == "exclusive_upper_bound":
        capacity_allowed = 0 < quantity < available

    accepted = operation_allowed and capacity_allowed
    remaining = available - quantity if accepted else available
    if mutant == "mutate_on_reject" and not accepted and quantity > 0:
        remaining = available - quantity

    return {
        "accepted": accepted,
        "remaining": remaining,
        "status": "RESERVED" if accepted else "REJECTED",
    }


class SemanticAdapter:
    consumer_type = "semantic-order-system"

    def __init__(self, mutant: str | None = None):
        self.mutant = mutant

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        return normalize_workload(
            consumer_type=self.consumer_type,
            requested_operation=external_input["operation"],
            actor=external_input["actor"],
            input_data=external_input,
            result=_evaluate_order(external_input, mutant=self.mutant),
        )


class ReplaySemanticAdapter(SemanticAdapter):
    def __init__(self, replay_mutant: str | None = None):
        super().__init__(mutant=None)
        self.replay_mutant = replay_mutant

    def replay_execution(
        self,
        normalized_workload: Mapping[str, Any],
    ) -> dict[str, Any]:
        return _evaluate_order(
            normalized_workload["input"],
            mutant=self.replay_mutant,
        )


class SemanticMutationTests(unittest.TestCase):
    def test_catalog_contains_at_least_three_material_mutants(self):
        self.assertGreaterEqual(len(MUTANTS), 3)
        self.assertEqual(
            set(MUTANTS),
            {
                "exclusive_upper_bound",
                "accept_any_operation",
                "mutate_on_reject",
            },
        )

    def test_each_mutant_moves_bound_result_and_receipt_identity(self):
        for mutant, cases in MUTANTS.items():
            request = cases["vector"]
            with self.subTest(mutant=mutant, vector=request["order_id"]):
                baseline = run_external_workload(SemanticAdapter(), request)
                changed = run_external_workload(SemanticAdapter(mutant), request)

                # Binding checks internal consistency, not business correctness.
                self.assertEqual(baseline.binding_receipt.result, "PASS")
                self.assertEqual(changed.binding_receipt.result, "PASS")

                # A material semantic change must be observable in the bound artifact.
                self.assertNotEqual(
                    baseline.normalized_workload["result"],
                    changed.normalized_workload["result"],
                    msg=f"surviving semantic mutant: {mutant}",
                )
                self.assertNotEqual(
                    baseline.workload_sha256,
                    changed.workload_sha256,
                    msg=f"workload identity did not move for mutant: {mutant}",
                )
                self.assertNotEqual(
                    baseline.bundle_sha256,
                    changed.bundle_sha256,
                    msg=f"bundle identity did not move for mutant: {mutant}",
                )
                self.assertNotEqual(
                    baseline.receipt_sha256,
                    changed.receipt_sha256,
                    msg=f"receipt identity did not move for mutant: {mutant}",
                )

    def test_each_mutant_is_killed_by_independent_execution_replay(self):
        for mutant, cases in MUTANTS.items():
            request = cases["vector"]
            with self.subTest(mutant=mutant, vector=request["order_id"]):
                baseline = run_external_workload(
                    ReplaySemanticAdapter(),
                    request,
                    execution_replay=True,
                )
                mutated_replay = run_external_workload(
                    ReplaySemanticAdapter(mutant),
                    request,
                    execution_replay=True,
                )

                self.assertEqual(baseline.binding_receipt.result, "PASS")
                self.assertEqual(baseline.execution_replay.status, "PASS")
                self.assertEqual(mutated_replay.binding_receipt.result, "PASS")
                self.assertEqual(
                    mutated_replay.execution_replay.status,
                    "MISMATCH",
                    msg=(
                        f"surviving semantic mutant: {mutant}; "
                        f"expected discriminating vector: {request['order_id']}"
                    ),
                )
                self.assertEqual(
                    baseline.binding_receipt,
                    mutated_replay.binding_receipt,
                    msg="execution replay must not rewrite binding receipt semantics",
                )

    def test_mutants_are_vector_specific_not_always_on_noise(self):
        for mutant, cases in MUTANTS.items():
            request = cases["neutral"]
            with self.subTest(mutant=mutant, vector=request["order_id"]):
                baseline = run_external_workload(SemanticAdapter(), request)
                changed = run_external_workload(SemanticAdapter(mutant), request)
                self.assertEqual(
                    baseline.normalized_workload["result"],
                    changed.normalized_workload["result"],
                )
                self.assertEqual(baseline.workload_sha256, changed.workload_sha256)
                self.assertEqual(baseline.bundle_sha256, changed.bundle_sha256)
                self.assertEqual(baseline.receipt_sha256, changed.receipt_sha256)

    def test_mutated_runs_remain_deterministic(self):
        for mutant, cases in MUTANTS.items():
            request = cases["vector"]
            with self.subTest(mutant=mutant, vector=request["order_id"]):
                first = run_external_workload(SemanticAdapter(mutant), request)
                second = run_external_workload(
                    SemanticAdapter(mutant),
                    copy.deepcopy(request),
                )
                self.assertEqual(first.normalized_workload, second.normalized_workload)
                self.assertEqual(first.evidence_bundle, second.evidence_bundle)
                self.assertEqual(first.binding_receipt, second.binding_receipt)
                self.assertEqual(
                    (
                        first.workload_sha256,
                        first.bundle_sha256,
                        first.receipt_sha256,
                    ),
                    (
                        second.workload_sha256,
                        second.bundle_sha256,
                        second.receipt_sha256,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
