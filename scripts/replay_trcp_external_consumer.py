#!/usr/bin/env python3
"""TRCP v0.4 — External consumer adapter replay CLI demo.

Runs the non-escrow delegated-spending consumer through the generic
provider-neutral pipeline:

    external workload -> normalize() -> workload evidence
    -> TRCP task/provider records -> evidence bundle
    -> independent binding verification -> deterministic receipt

Binding replay is always performed. Execution replay is the optional,
separate adapter hook: PASS when the re-run matches the binding result,
NOT_RUN when the hook is not exercised, and it never affects the binding
receipt.

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.

Exit codes:
  0 - binding replay PASS for every scenario
  1 - at least one binding replay FAIL
  2 - unexpected error
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_trcp.adapter import run_external_consumer  # noqa: E402
from sdk.liminal_trcp.delegated_spending import (  # noqa: E402
    AUTHORITY_EXTERNAL_INPUT,
    LIMIT_EXTERNAL_INPUT,
    QUOTA_EXTERNAL_INPUT,
    REJECTED_EXTERNAL_INPUT,
    TERMINAL_EXTERNAL_INPUT,
    VALID_EXTERNAL_INPUT,
    DelegatedSpendingAdapter,
)

SCENARIOS = (
    ("valid-approval", VALID_EXTERNAL_INPUT, True),
    ("rejected-action", REJECTED_EXTERNAL_INPUT, True),
    ("actor-authority", AUTHORITY_EXTERNAL_INPUT, False),
    ("per-action-limit", LIMIT_EXTERNAL_INPUT, True),
    ("cumulative-quota", QUOTA_EXTERNAL_INPUT, True),
    ("terminal-exclusivity", TERMINAL_EXTERNAL_INPUT, True),
)


def main() -> int:
    adapter = DelegatedSpendingAdapter()
    failed = False
    for name, external_input, with_execution_replay in SCENARIOS:
        outcome = run_external_consumer(
            adapter,
            external_input,
            execution_replay=with_execution_replay,
        )
        receipt = outcome["receipt"]
        replay = outcome["execution_replay"]
        print("External Consumer Adapter")
        print(f"  scenario: {name}")
        print(f"  consumer_type: {adapter.consumer_type}")
        print(f"  Binding replay: {receipt['result']}")
        print(f"  Execution replay: {replay['status']}")
        print(f"  workload_sha256: {outcome['workload_evidence']['workload_sha256']}")
        print(f"  bundle_sha256: {outcome['bundle']['bundle_sha256']}")
        print(f"  receipt_sha256: {receipt['receipt_sha256']}")
        if receipt["result"] != "PASS":
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
