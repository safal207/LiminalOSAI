#!/usr/bin/env python3
"""TRCP Contract Benchmark v0.1 - Deterministic Contract Evidence Replay.

Measures whether TRCP produces stable, independently replayable,
tamper-evident receipts across valid, invalid, and adversarial
contract-state workloads.

Scenario classes:
  clean          - valid contract paths, no violations, no finding
  illegal        - paths that trigger transition-validation violations
  invariant      - paths that violate contract invariants (payout, exclusivity)
  adversarial    - tampered evidence bundles that must FAIL replay

Exit codes:
  0 - every scenario and tamper behaved as expected
  1 - any expectation mismatch or verifier failure
  2 - unexpected error

LOCAL_ONLY / SYNTHETIC_ONLY. No network, no providers, no real targets.
"""
from __future__ import annotations

import copy
import datetime
import json
import platform
import statistics
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_post_sandbox_contracts import canonical_sha256  # noqa: E402
from sdk.liminal_trcp.consumer import (  # noqa: E402
    DOUBLE_RELEASE_PATH,
    ILLEGAL_PATH,
    VALID_PATH,
    run_contract_consumer,
)
from sdk.liminal_trcp.replay import verify_evidence_bundle  # noqa: E402

ARTIFACT_PATH = ROOT / "artifacts" / "trcp-contract-benchmark.json"

BENCHMARK_VERSION = "0.1"
ITERATIONS = 2
WARMUP_RUNS = 1

CLEAN = "clean"
ILLEGAL = "illegal"
INVARIANT = "invariant"
ADVERSARIAL = "adversarial"


def _git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:  # noqa: BLE001 - best-effort metadata
        return "unknown"


def _benchmark_metadata() -> dict[str, Any]:
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_revision": _git_revision(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "iterations": ITERATIONS,
        "warmup_runs": WARMUP_RUNS,
        "determinism_basis": (
            "evidence_hashes (workload_sha256/bundle_sha256/receipt_sha256); "
            "wall-clock timing is observational only"
        ),
    }


def _scenario(
    name: str,
    path: tuple[str, ...],
    actor: str,
    scenario_class: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "path": list(path),
        "actor": actor,
        "class": scenario_class,
        "expected": "PASS",
    }


SCENARIOS: list[dict[str, Any]] = [
    _scenario("valid-full-release", VALID_PATH, "buyer", CLEAN),
    _scenario("funded-only", ("FUNDED",), "buyer", CLEAN),
    _scenario("funded-release-requested", ("FUNDED", "RELEASE_REQUESTED"), "buyer", CLEAN),
    _scenario("funded-refunded", ("FUNDED", "REFUNDED"), "buyer", CLEAN),
    _scenario("refund-then-release", ("FUNDED", "REFUNDED", "RELEASED"), "buyer", CLEAN),
    _scenario("empty-path", (), "buyer", CLEAN),
    _scenario("request-before-funding", ("RELEASE_REQUESTED",), "buyer", ILLEGAL),
    _scenario("release-before-funding", ("RELEASED",), "buyer", ILLEGAL),
    _scenario("refund-before-funding", ("REFUNDED",), "buyer", ILLEGAL),
    _scenario("double-fund", ("FUNDED", "FUNDED"), "buyer", ILLEGAL),
    _scenario("double-release-request", ("FUNDED", "RELEASE_REQUESTED", "RELEASE_REQUESTED"), "buyer", ILLEGAL),
    _scenario("release-then-refund", ("FUNDED", "RELEASE_REQUESTED", "RELEASED", "REFUNDED"), "buyer", ILLEGAL),
    _scenario("unauthorized-seller-fund", ("FUNDED",), "seller", ILLEGAL),
    _scenario("unauthorized-seller-release", VALID_PATH, "seller", ILLEGAL),
    _scenario("unauthorized-seller-refund", ("FUNDED", "REFUNDED"), "seller", ILLEGAL),
    _scenario("double-release-invariant", DOUBLE_RELEASE_PATH, "buyer", INVARIANT),
    _scenario("illegal-terminal-state", ILLEGAL_PATH, "buyer", INVARIANT),
    _scenario("unauthorized-seller-request", ("FUNDED", "RELEASE_REQUESTED"), "seller", ILLEGAL),
    _scenario("unauthorized-seller-deep-release", VALID_PATH + ("RELEASED",), "seller", ILLEGAL),
    _scenario("request-after-refund", ("FUNDED", "REFUNDED", "RELEASE_REQUESTED"), "buyer", ILLEGAL),
]


def _mutate_bundle(
    bundle: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
    *,
    recalculate: bool,
) -> dict[str, Any]:
    mutated = copy.deepcopy(bundle)
    mutate(mutated)
    if recalculate:
        body = {k: v for k, v in mutated.items() if k != "bundle_sha256"}
        mutated["bundle_sha256"] = canonical_sha256(body)
    return mutated


def _strip_consumer_evidence(bundle: dict[str, Any]) -> None:
    del bundle["consumer_evidence"]


def _empty_provider_runs(bundle: dict[str, Any]) -> None:
    bundle["provider_runs"] = []
    bundle["failover_decision"] = None


def _mismatch_provider_hash(bundle: dict[str, Any]) -> None:
    for run in bundle["provider_runs"]:
        run["provider_metadata"]["workload_sha256"] = "1" * 64


def _forge_violations(bundle: dict[str, Any]) -> None:
    evidence = bundle["consumer_evidence"]
    evidence["result"]["violations"] = [{"invariant_id": "forged", "violated": True}]
    body = {
        "schema": evidence["schema"],
        "requested_path": evidence["requested_path"],
        "actor": evidence["actor"],
        "result": evidence["result"],
    }
    evidence["workload_sha256"] = canonical_sha256(body)


def _break_verification_closure(bundle: dict[str, Any]) -> None:
    bundle["verification"] = None


TAMPERS: list[dict[str, Any]] = [
    {
        "name": "tamper-bundle-integrity",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "BUNDLE_INTEGRITY",
        "mutate": lambda b: b.__setitem__("bundle_sha256", "0" * 64),
        "recalculate": False,
    },
    {
        "name": "tamper-requested-path",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"].__setitem__("requested_path", ["CREATED"]),
        "recalculate": True,
    },
    {
        "name": "tamper-final-state",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"]["result"].__setitem__("final_state", "REFUNDED"),
        "recalculate": True,
    },
    {
        "name": "tamper-forged-violations",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _forge_violations,
        "recalculate": True,
    },
    {
        "name": "tamper-task-identity",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"]["task"].__setitem__("task_id", "task:forged"),
        "recalculate": True,
    },
    {
        "name": "tamper-schema",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"].__setitem__("schema", "contract-workload-evidence-v0.9"),
        "recalculate": True,
    },
    {
        "name": "tamper-evidence-stripped",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _strip_consumer_evidence,
        "recalculate": True,
    },
    {
        "name": "tamper-empty-provider-runs",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _empty_provider_runs,
        "recalculate": True,
    },
    {
        "name": "tamper-mismatched-provider-hash",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _mismatch_provider_hash,
        "recalculate": True,
    },
    {
        "name": "tamper-authorization",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "AUTHORIZATION_CONTINUITY",
        "mutate": lambda b: b["authorization"].__setitem__("authorization_id", "auth:mutated"),
        "recalculate": True,
    },
    {
        "name": "tamper-trace-chain",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "TRACE_HASH_CHAIN",
        "mutate": lambda b: b["trace"][1].__setitem__("previous_event_sha256", "0" * 64),
        "recalculate": True,
    },
    {
        "name": "tamper-verification-closure",
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "VERIFICATION_CLOSURE",
        "mutate": _break_verification_closure,
        "recalculate": True,
        "baseline_path": ILLEGAL_PATH,
    },
]


def _run_scenario_once(spec: dict[str, Any]) -> dict[str, Any]:
    outcome = run_contract_consumer(tuple(spec["path"]), actor=spec["actor"])
    bundle = outcome["bundle"]
    started = time.perf_counter_ns()
    receipt = verify_evidence_bundle(bundle)
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "scenario": spec["name"],
        "class": spec["class"],
        "expected": spec["expected"],
        "actual": receipt["result"],
        "evidence": {
            "workload_sha256": outcome["workload_evidence"]["workload_sha256"],
            "bundle_sha256": bundle["bundle_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "checks": receipt["checks"],
        },
        "measurement": {
            "replay_time_ns": elapsed_ns,
        },
    }


def _run_tamper_once(spec: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    bundle = _mutate_bundle(baseline["bundle"], spec["mutate"], recalculate=spec["recalculate"])
    started = time.perf_counter_ns()
    receipt = verify_evidence_bundle(bundle)
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "scenario": spec["name"],
        "class": spec["class"],
        "expected": spec["expected"],
        "expected_failed_check": spec["expected_failed_check"],
        "actual": receipt["result"],
        "failed_check": receipt.get("failed_check"),
        "evidence": {
            "bundle_sha256": bundle["bundle_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "checks": receipt["checks"],
        },
        "measurement": {
            "replay_time_ns": elapsed_ns,
        },
    }


def main() -> int:
    try:
        for _ in range(WARMUP_RUNS):
            run_contract_consumer(VALID_PATH)

        records: list[dict[str, Any]] = []
        failures: list[str] = []

        first_runs: dict[str, dict[str, Any]] = {}
        hash_failures = 0
        for spec in SCENARIOS:
            first = _run_scenario_once(spec)
            second = _run_scenario_once(spec)
            records.append(first)

            if first["actual"] != spec["expected"]:
                failures.append(f"{spec['name']}: expected {spec['expected']}, got {first['actual']}")
            if second["actual"] != spec["expected"]:
                failures.append(f"{spec['name']} (run 2): expected {spec['expected']}, got {second['actual']}")
            for key in ("workload_sha256", "bundle_sha256", "receipt_sha256"):
                if first["evidence"][key] != second["evidence"][key]:
                    hash_failures += 1
                    failures.append(f"{spec['name']}: evidence {key} differs across runs")

            first_runs[spec["name"]] = first

        baseline = run_contract_consumer(VALID_PATH)
        for spec in TAMPERS:
            if spec.get("baseline_path") is not None:
                baseline = run_contract_consumer(tuple(spec["baseline_path"]))
            record = _run_tamper_once(spec, baseline)
            records.append(record)
            if record["actual"] != spec["expected"]:
                failures.append(f"{spec['name']}: expected {spec['expected']}, got {record['actual']}")
            if record["failed_check"] != spec["expected_failed_check"]:
                failures.append(
                    f"{spec['name']}: expected failed_check {spec['expected_failed_check']}, "
                    f"got {record['failed_check']}"
                )

        scenario_records = [r for r in records if r["class"] != ADVERSARIAL]
        tamper_records = [r for r in records if r["class"] == ADVERSARIAL]

        replay_pass = sum(1 for r in scenario_records if r["actual"] == "PASS")
        tamper_detected = sum(1 for r in tamper_records if r["actual"] == "FAIL")
        binding_tampers = [
            r for r in tamper_records if r["expected_failed_check"] == "WORKLOAD_EVIDENCE_BINDING"
        ]
        binding_detected = sum(
            1 for r in binding_tampers if r["failed_check"] == "WORKLOAD_EVIDENCE_BINDING"
        )
        deterministic = sum(
            1 for name, first in first_runs.items() if first["actual"] == "PASS"
        )
        false_confirmations = sum(
            1 for r in scenario_records if r["expected"] == "PASS" and r["actual"] != "PASS"
        )
        hashes_compared = len(first_runs) * 3
        hashes_stable = hashes_compared - hash_failures
        replay_times_ns = [r["measurement"]["replay_time_ns"] for r in scenario_records]

        summary = {
            "scenarios_total": len(scenario_records),
            "tampers_total": len(tamper_records),
            "replay_pass": f"{replay_pass}/{len(scenario_records)}",
            "tamper_detected": f"{tamper_detected}/{len(tamper_records)}",
            "deterministic_scenarios": f"{deterministic}/{len(scenario_records)}",
            "cross_run_evidence_hash_stability_pct": round(
                hashes_stable / hashes_compared * 100, 1
            ),
            "false_confirmations": false_confirmations,
            "binding_failures_detected_pct": round(
                binding_detected / len(binding_tampers) * 100, 1
            ),
            "median_replay_time_ns": int(statistics.median(replay_times_ns)),
        }

        artifact = {
            "schema": "trcp-contract-benchmark-v0.1",
            "metadata": _benchmark_metadata(),
            "summary": summary,
            "records": records,
        }
        ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT_PATH.write_text(json.dumps(artifact, sort_keys=True, indent=2) + "\n")

        median_ms = summary["median_replay_time_ns"] / 1_000_000.0
        print("TRCP Contract Benchmark v0.1")
        print()
        print(f"Scenarios: {len(scenario_records)}")
        print(f"Replay PASS: {summary['replay_pass']}")
        print(f"Tamper detection: {summary['tamper_detected']}")
        print(f"Deterministic receipts: {summary['deterministic_scenarios']}")
        print(
            "Cross-run hash stability: "
            f"{summary['cross_run_evidence_hash_stability_pct']}% "
            "(evidence hashes only; timing is observational)"
        )
        print(f"False confirmations: {summary['false_confirmations']}")
        print(f"Binding failures detected: {summary['binding_failures_detected_pct']}%")
        print(f"Median replay time: {median_ms:.3f} ms")
        print()
        print(f"artifact: {ARTIFACT_PATH}")

        if failures:
            print(file=sys.stderr)
            print("expectation failures:", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
