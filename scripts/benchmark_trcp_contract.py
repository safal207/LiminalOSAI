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
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
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
    steps: tuple[tuple[str, str], ...],
    scenario_class: str,
    *,
    expected_violations: list[str],
    expected_finding: bool,
) -> dict[str, Any]:
    return {
        "name": name,
        "steps": [list(step) for step in steps],
        "class": scenario_class,
        "expected": "PASS",
        "expected_violations": list(expected_violations),
        "expected_finding": expected_finding,
    }


B = "buyer"
S = "seller"

SCENARIOS: list[dict[str, Any]] = [
    _scenario(
        "valid-full-release",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASED", B)),
        CLEAN,
        expected_violations=[],
        expected_finding=False,
    ),
    _scenario(
        "funded-only",
        (("FUNDED", B),),
        CLEAN,
        expected_violations=[],
        expected_finding=False,
    ),
    _scenario(
        "funded-release-requested",
        (("FUNDED", B), ("RELEASE_REQUESTED", B)),
        CLEAN,
        expected_violations=[],
        expected_finding=False,
    ),
    _scenario(
        "funded-refunded",
        (("FUNDED", B), ("REFUNDED", B)),
        CLEAN,
        expected_violations=[],
        expected_finding=False,
    ),
    _scenario(
        "empty-path",
        (),
        CLEAN,
        expected_violations=[],
        expected_finding=False,
    ),
    _scenario(
        "request-before-funding",
        (("RELEASE_REQUESTED", B),),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "release-before-funding",
        (("RELEASED", B),),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "refund-before-funding",
        (("REFUNDED", B),),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "double-fund",
        (("FUNDED", B), ("FUNDED", B)),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "double-release-request",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASE_REQUESTED", B)),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "release-then-refund",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASED", B), ("REFUNDED", B)),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "request-after-refund",
        (("FUNDED", B), ("REFUNDED", B), ("RELEASE_REQUESTED", B)),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "request-then-release-before-funding",
        (("RELEASE_REQUESTED", B), ("RELEASED", B)),
        ILLEGAL,
        expected_violations=["transition-validation"],
        expected_finding=True,
    ),
    _scenario(
        "unauthorized-seller-fund",
        (("FUNDED", S),),
        ILLEGAL,
        expected_violations=["authorization"],
        expected_finding=True,
    ),
    _scenario(
        "unauthorized-seller-request",
        (("FUNDED", B), ("RELEASE_REQUESTED", S)),
        ILLEGAL,
        expected_violations=["authorization"],
        expected_finding=True,
    ),
    _scenario(
        "unauthorized-seller-release",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASED", S)),
        ILLEGAL,
        expected_violations=["authorization"],
        expected_finding=True,
    ),
    _scenario(
        "unauthorized-seller-refund",
        (("FUNDED", B), ("REFUNDED", S)),
        ILLEGAL,
        expected_violations=["authorization"],
        expected_finding=True,
    ),
    _scenario(
        "unauthorized-seller-deep-release",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASED", B), ("RELEASED", S)),
        ILLEGAL,
        expected_violations=["authorization"],
        expected_finding=True,
    ),
    _scenario(
        "refund-then-release",
        (("FUNDED", B), ("REFUNDED", B), ("RELEASED", B)),
        INVARIANT,
        expected_violations=["terminal-state-exclusivity"],
        expected_finding=True,
    ),
    _scenario(
        "double-release-invariant",
        (("FUNDED", B), ("RELEASE_REQUESTED", B), ("RELEASED", B), ("RELEASED", B)),
        INVARIANT,
        expected_violations=["payout-conservation"],
        expected_finding=True,
    ),
    _scenario(
        "double-release-refund",
        (("FUNDED", B), ("REFUNDED", B), ("RELEASED", B), ("RELEASED", B)),
        INVARIANT,
        expected_violations=["payout-conservation", "terminal-state-exclusivity"],
        expected_finding=True,
    ),
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


def _adversarial_name(base: str, kind: str | None = "tamper") -> str:
    """Combine a base name with an optional adversarial class suffix."""
    return base if kind is None else f"{kind}-{base}"


TAMPERS: list[dict[str, Any]] = [
    {
        "name": _adversarial_name("bundle-integrity"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "BUNDLE_INTEGRITY",
        "mutate": lambda b: b.__setitem__("bundle_sha256", "0" * 64),
        "recalculate": False,
    },
    {
        "name": _adversarial_name("requested-path"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"].__setitem__("requested_path", ["CREATED"]),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("final-state"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"]["result"].__setitem__("final_state", "REFUNDED"),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("forged-violations"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _forge_violations,
        "recalculate": True,
    },
    {
        "name": _adversarial_name("task-identity"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"]["task"].__setitem__("task_id", "task:forged"),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("schema"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": lambda b: b["consumer_evidence"].__setitem__("schema", "contract-workload-evidence-v0.9"),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("evidence-stripped"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _strip_consumer_evidence,
        "recalculate": True,
    },
    {
        "name": _adversarial_name("empty-provider-runs"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _empty_provider_runs,
        "recalculate": True,
    },
    {
        "name": _adversarial_name("mismatched-provider-hash"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "WORKLOAD_EVIDENCE_BINDING",
        "mutate": _mismatch_provider_hash,
        "recalculate": True,
    },
    {
        "name": _adversarial_name("authorization"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "AUTHORIZATION_CONTINUITY",
        "mutate": lambda b: b["authorization"].__setitem__("authorization_id", "auth:mutated"),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("trace-chain"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "TRACE_HASH_CHAIN",
        "mutate": lambda b: b["trace"][1].__setitem__("previous_event_sha256", "0" * 64),
        "recalculate": True,
    },
    {
        "name": _adversarial_name("verification-closure"),
        "class": ADVERSARIAL,
        "expected": "FAIL",
        "expected_failed_check": "VERIFICATION_CLOSURE",
        "mutate": _break_verification_closure,
        "recalculate": True,
        "baseline_path": ILLEGAL_PATH,
    },
]


def _run_scenario_once(spec: dict[str, Any]) -> dict[str, Any]:
    steps = [tuple(step) for step in spec["steps"]]
    path = tuple(step[0] for step in steps)
    actors = tuple(step[1] for step in steps)
    actor: str | tuple[str, ...] = actors[0] if len(set(actors)) == 1 else actors
    outcome = run_contract_consumer(path, actor=actor)
    bundle = outcome["bundle"]
    started = time.perf_counter_ns()
    receipt = verify_evidence_bundle(bundle)
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "scenario": spec["name"],
        "class": spec["class"],
        "expected": spec["expected"],
        "expected_violations": list(spec["expected_violations"]),
        "expected_finding": spec["expected_finding"],
        "actual": receipt["result"],
        "actual_violations": sorted(
            {v["invariant_id"] for v in outcome["workload"]["violations"]}
        ),
        "finding_present": outcome["report"]["finding"] is not None,
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

        hash_failures = 0
        for spec in SCENARIOS:
            first = _run_scenario_once(spec)
            second = _run_scenario_once(spec)
            first["second_evidence"] = {
                key: second["evidence"][key]
                for key in ("workload_sha256", "bundle_sha256", "receipt_sha256")
            }
            first["hash_equality"] = {
                key: first["evidence"][key] == second["evidence"][key]
                for key in ("workload_sha256", "bundle_sha256", "receipt_sha256")
            }
            first["deterministic"] = all(first["hash_equality"].values())
            records.append(first)

            if first["actual"] != spec["expected"]:
                failures.append(f"{spec['name']}: expected {spec['expected']}, got {first['actual']}")
            if first["actual_violations"] != first["expected_violations"]:
                failures.append(
                    f"{spec['name']}: expected violations {first['expected_violations']}, "
                    f"got {first['actual_violations']}"
                )
            if first["finding_present"] != spec["expected_finding"]:
                failures.append(
                    f"{spec['name']}: expected finding={spec['expected_finding']}, "
                    f"got finding={first['finding_present']}"
                )
            if second["actual"] != spec["expected"]:
                failures.append(f"{spec['name']} (run 2): expected {spec['expected']}, got {second['actual']}")
            for key in ("workload_sha256", "bundle_sha256", "receipt_sha256"):
                if first["evidence"][key] != second["evidence"][key]:
                    hash_failures += 1
                    failures.append(f"{spec['name']}: evidence {key} differs across runs")

        valid_baseline = run_contract_consumer(VALID_PATH)
        for spec in TAMPERS:
            if spec.get("baseline_path") is not None:
                baseline = run_contract_consumer(tuple(spec["baseline_path"]))
            else:
                baseline = valid_baseline
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
            1 for r in scenario_records if r["deterministic"] and r["actual"] == "PASS"
        )
        false_confirmations = sum(
            1 for r in records if r["expected"] == "FAIL" and r["actual"] == "PASS"
        )
        hashes_compared = len(scenario_records) * 3
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
        ARTIFACT_PATH.write_text(
            json.dumps(artifact, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

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
