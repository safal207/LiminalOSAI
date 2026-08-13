#!/usr/bin/env python3
"""Five-minute, public-API-only TRCP Adapter SDK integration.

The example deliberately behaves like code in a separate repository: every
Liminal symbol comes from ``sdk.liminal_trcp.sdk``.  The order system and its
optional execution replay hook remain consumer-owned.
"""

from __future__ import annotations

import argparse
import copy
import json
from collections.abc import Mapping
from typing import Any

from sdk.liminal_trcp.sdk import (
    ADAPTER_SDK_VERSION,
    normalize_workload,
    run_external_workload,
)


def execute_order(request: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic stand-in for an external order system."""
    quantity = request["quantity"]
    available = request["available"]
    accepted = request["operation"] == "reserve" and 0 < quantity <= available
    return {
        "accepted": accepted,
        "order_id": request["order_id"],
        "remaining": available - quantity if accepted else available,
        "reserved_quantity": quantity if accepted else 0,
        "status": "RESERVED" if accepted else "REJECTED",
    }


class ExampleOrderSystemAdapter:
    """Small external adapter: a type identifier plus normalization logic."""

    consumer_type = "example-order-system"

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        request = copy.deepcopy(dict(external_input))
        return normalize_workload(
            consumer_type=self.consumer_type,
            requested_operation=request["operation"],
            actor=request["actor"],
            input_data=request,
            result=execute_order(request),
        )

    def replay_execution(
        self,
        normalized_workload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Optional hook; binding verification does not depend on this."""
        return execute_order(normalized_workload["input"])


EXAMPLE_REQUEST: dict[str, Any] = {
    "actor": "order-service",
    "available": 5,
    "operation": "reserve",
    "order_id": "order-1001",
    "quantity": 2,
    "sku": "demo-widget",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execution-replay",
        action="store_true",
        help="also invoke the adapter's optional local execution replay hook",
    )
    args = parser.parse_args()

    outcome = run_external_workload(
        ExampleOrderSystemAdapter(),
        EXAMPLE_REQUEST,
        execution_replay=args.execution_replay,
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
                "workload_sha256": outcome.workload_sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if outcome.binding_receipt.result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
