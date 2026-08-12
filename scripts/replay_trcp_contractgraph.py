#!/usr/bin/env python3
"""CLI demo for the TRCP v0.3 local contract-state consumer pipeline.

Runs the escrow fixture through the full path:

    local fixture -> TRCP -> evidence bundle -> causal lineage -> independent replay

Exits 0 when every scenario replays PASS, 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_trcp.consumer import (
    DOUBLE_RELEASE_PATH,
    ILLEGAL_PATH,
    VALID_PATH,
    run_contract_consumer,
)

SCENARIOS = (
    ("valid", VALID_PATH),
    ("illegal-transition", ILLEGAL_PATH),
    ("double-release", DOUBLE_RELEASE_PATH),
)


def main() -> int:
    failed = False
    for name, path in SCENARIOS:
        outcome = run_contract_consumer(path)
        receipt = outcome["receipt"]
        workload = outcome["workload"]
        summary = {
            "scenario": name,
            "workload": {
                "final_state": workload["final_state"],
                "violations": [
                    {"invariant_id": v["invariant_id"], "violated": v["violated"]}
                    for v in workload["violations"]
                ],
            },
            "finding_id": (outcome["report"]["finding"] or {}).get("finding_id"),
            "receipt": {
                "result": receipt["result"],
                "failed_check": receipt.get("failed_check"),
            },
        }
        print(json.dumps(summary, sort_keys=True, indent=2))
        if receipt["result"] != "PASS":
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
