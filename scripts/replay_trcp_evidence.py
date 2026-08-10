#!/usr/bin/env python3
"""TRCP v0.2 — Evidence replay CLI.

Runs the default TRCP v0.2 scenario end-to-end:
TRCP simulator -> report -> evidence adapter -> replay verifier -> JSON receipt.

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.

Exit codes:
  0 - verification PASS
  1 - verification FAIL
  2 - unexpected error
"""
import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_trcp import run_default_scenario
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import verify_evidence_bundle


def main() -> int:
    try:
        report = run_default_scenario()
        bundle = build_evidence_bundle(report)
        receipt = verify_evidence_bundle(bundle)
        print(json.dumps(receipt, sort_keys=True, indent=2))
        if receipt["result"] != "PASS":
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
