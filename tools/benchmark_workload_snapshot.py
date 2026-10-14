#!/usr/bin/env python3
"""Reproducible, synthetic TRCP copy-cost probe; no network or model calls.

Run this same script with --repo pointing to each checkout. Timings describe
only this local workload; artifact hashes and copy counts are deterministic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from unittest.mock import patch

GIT_METADATA_TIMEOUT_SECONDS = 10.0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--rows", type=int, default=300)
    args = parser.parse_args()
    if min(args.samples, args.iterations, args.rows) < 1:
        parser.error("samples, iterations and rows must be positive")
    repo = args.repo.resolve()
    sys.path.insert(0, str(repo))
    from sdk.liminal_trcp import sdk
    sdk_filename = getattr(sdk, "__file__", None)
    if sdk_filename is None or not Path(sdk_filename).resolve().is_relative_to(repo):
        parser.error("imported TRCP SDK is outside --repo; use a fresh process for the target checkout")
    sdk_file = Path(sdk_filename).resolve()

    workload = sdk.normalize_workload(
        consumer_type="snapshot-benchmark", requested_operation=["inspect"],
        actor=["synthetic-worker"],
        input_data={"rows": [{"id": n, "text": "тест-" * 16, "tags": ["local", "synthetic"]} for n in range(args.rows)]},
        result={"accepted": True, "count": args.rows},
    )

    class Adapter:
        consumer_type = "snapshot-benchmark"

        def normalize(self, external_input):
            return workload

    functions = {
        "validate_snapshot": lambda: sdk._validated_normalized_workload(workload),
        "build_workload_evidence": lambda: sdk.build_workload_evidence(workload),
        "run_external_workload": lambda: sdk.run_external_workload(Adapter(), {}).evidence_bundle,
    }
    results = {}
    for name, operation in functions.items():
        artifact = operation()
        durations = []
        for _ in range(args.samples):
            start = time.perf_counter()
            for _ in range(args.iterations):
                operation()
            durations.append((time.perf_counter() - start) / args.iterations * 1000)
        encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        results[name] = {"median_ms": round(statistics.median(durations), 4), "samples_ms": [round(n, 4) for n in durations], "artifact_sha256": hashlib.sha256(encoded).hexdigest()}
    with patch.object(sdk, "_json_copy", wraps=sdk._json_copy) as copies:
        sdk._validated_normalized_workload(workload)
        copy_calls = copies.call_count
    try:
        source = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True,
            timeout=GIT_METADATA_TIMEOUT_SECONDS,
        ).strip()
        dirty = bool(subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain"], text=True,
            timeout=GIT_METADATA_TIMEOUT_SECONDS,
        ))
    except subprocess.TimeoutExpired:
        parser.error("Git metadata query timed out; no benchmark report was emitted")
    print(json.dumps({"source": source, "dirty": dirty, "sdk_file": str(sdk_file), "python": platform.python_version(), "platform": platform.platform(), "rows": args.rows, "samples": args.samples, "iterations": args.iterations, "json_copy_calls_per_validation": copy_calls, "results": results}, indent=2))


if __name__ == "__main__":
    main()
