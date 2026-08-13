#!/usr/bin/env python3
"""Public-API-only TRCP reference for a financial state-transition observation.

This example is deliberately synthetic and client-neutral. It does not call a
network, provider, wallet, payment API, or external business system. The
adapter binds a sanitized observation into a deterministic TRCP evidence bundle
and receipt. A binding PASS is not proof of live execution correctness.

Money is represented in integer minor units so the boundary case 10.01 is
encoded as 1001 rather than a floating-point value.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from sdk.liminal_trcp.sdk import (
    ADAPTER_SDK_VERSION,
    normalize_workload,
    run_external_workload,
)


def classify_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate explicit invariants over an already-recorded observation."""
    policy = observation["policy"]
    request = observation["request"]
    response = observation["observed_response"]
    pre_state = observation["pre_state"]
    post_state = observation["post_state"]

    amount_minor = request["amount_minor"]
    max_per_transaction_minor = policy["max_per_transaction_minor"]
    over_limit = amount_minor > max_per_transaction_minor
    observed_rejected = response["status"] == "REJECTED"
    state_unchanged = pre_state == post_state

    invariants = [
        {
            "invariant_id": "per-transaction-limit-enforced",
            "passed": (not over_limit) or observed_rejected,
        },
        {
            "invariant_id": "rejected-action-no-mutation",
            "passed": (not observed_rejected) or state_unchanged,
        },
    ]

    if over_limit:
        expected_outcome_class = "REJECTED_OVER_PER_TRANSACTION_LIMIT"
    else:
        expected_outcome_class = "WITHIN_PER_TRANSACTION_LIMIT"

    return {
        "classification": "PASS" if all(item["passed"] for item in invariants) else "FAIL",
        "expected_outcome_class": expected_outcome_class,
        "invariants": invariants,
        "observed_status": response["status"],
        "over_per_transaction_limit": over_limit,
        "state_unchanged": state_unchanged,
    }


class AgentFinancialTransitionAdapter:
    """Minimal external adapter: stable type identifier plus normalize()."""

    consumer_type = "agent-financial-transition"

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        observation = copy.deepcopy(dict(external_input))
        return normalize_workload(
            consumer_type=self.consumer_type,
            requested_operation=observation["request"]["operation"],
            actor=observation["actor"],
            input_data=observation,
            result=classify_observation(observation),
        )


SYNTHETIC_BOUNDARY_OBSERVATION: dict[str, Any] = {
    "actor": "synthetic-agent",
    "policy": {
        "daily_limit_minor": 2500,
        "max_per_transaction_minor": 1000,
        "require_approval_above_minor": 2000,
    },
    "request": {
        "operation": "spend",
        "amount_minor": 1001,
        "currency": "USD",
    },
    "pre_state": {
        "available_balance_minor": 5000,
        "spent_today_minor": 0,
    },
    "observed_response": {
        "status": "REJECTED",
        "reason_class": "PER_TRANSACTION_LIMIT",
    },
    "post_state": {
        "available_balance_minor": 5000,
        "spent_today_minor": 0,
    },
}


def main() -> int:
    outcome = run_external_workload(
        AgentFinancialTransitionAdapter(),
        SYNTHETIC_BOUNDARY_OBSERVATION,
    )
    print(
        json.dumps(
            {
                "adapter_sdk_version": ADAPTER_SDK_VERSION,
                "binding_result": outcome.binding_receipt.result,
                "bundle_sha256": outcome.bundle_sha256,
                "consumer_type": outcome.normalized_workload["consumer_type"],
                "execution_replay_status": outcome.execution_replay.status,
                "receipt_sha256": outcome.receipt_sha256,
                "semantic_classification": outcome.normalized_workload["result"]["classification"],
                "workload_sha256": outcome.workload_sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outcome.binding_receipt.result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
