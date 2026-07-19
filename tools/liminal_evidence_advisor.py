#!/usr/bin/env python3
"""Build a bounded LiminalOSAI advisory packet from normalized QA evidence.

This adapter is intentionally deterministic and advisory-only. It does not
execute a target, infer a security vulnerability, override the evidence-bound
product verdict, or grant execution/merge/submission authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

PIPELINE_STEPS = ("awareness", "introspect", "harmony", "gate")
AUTHORITY = {
    "mode": "advisory_only",
    "ownership": False,
    "approval": False,
    "execution": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge": False,
    "product_verdict_override": False,
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _pipeline_from_log(text: str) -> list[str]:
    lowered = text.lower()
    observed: list[str] = []
    for step in PIPELINE_STEPS:
        if re.search(rf"\b{re.escape(step)}\b", lowered):
            observed.append(step)
    return observed


def _classify(evidence: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]]:
    facts: list[str] = []
    probe = evidence.get("probe_summary")
    probe_map = probe if isinstance(probe, dict) else {}

    dns_baseline = evidence.get("dns_baseline_addresses")
    dns_garden = evidence.get("dns_garden_addresses")
    if isinstance(dns_baseline, list) and dns_baseline:
        facts.append("DNS resolved in the matching baseline namespace")
    if isinstance(dns_garden, list) and dns_garden:
        facts.append("DNS resolved inside Garden")

    events = evidence.get("garden_events")
    if isinstance(events, list):
        expected_events = {
            "RUN_CREATED",
            "SEED_LOADED",
            "NS_CREATED",
            "MOUNT_DONE",
            "CAPS_DROPPED",
            "SECCOMP_ENABLED",
            "PROCESS_START",
            "PROCESS_EXIT",
        }
        if expected_events.issubset(set(events)):
            facts.append("Garden emitted the complete required lifecycle")

    if evidence.get("safe_readonly_probe") is True:
        facts.append("The probe respected the read-only safety boundary")

    confirmed_defect = probe_map.get("confirmed_defect")
    live_confirmed = evidence.get("live_garden_probe_confirmed") is True
    probe_present = evidence.get("probe_present") is True

    if live_confirmed and probe_present and confirmed_defect is False:
        classification = "NO_DEFECT_OBSERVED"
        facts.append("The normalized probe reports no confirmed product defect")
        next_experiment = {
            "name": "preserve_negative_control_and_expand_only_with_new_hypothesis",
            "priority": "low",
            "change_product_scope": False,
            "disable_seccomp": False,
            "reason": "The exact bounded scenario completed without an inconsistent state.",
        }
    elif live_confirmed and probe_present and confirmed_defect is True:
        classification = "PRODUCT_SIGNAL_REQUIRES_LOTUS_ADJUDICATION"
        facts.append("The normalized probe contains a positive defect signal")
        next_experiment = {
            "name": "independent_exact_head_reproduction",
            "priority": "high",
            "change_product_scope": False,
            "disable_seccomp": False,
            "reason": "A positive signal must be reproduced and adjudicated outside the advisor.",
        }
    else:
        classification = "RUNTIME_OR_EVIDENCE_GAP"
        missing: list[str] = []
        if not probe_present:
            missing.append("probe_result")
        if not live_confirmed:
            missing.append("confirmed_live_garden_lifecycle")
        next_experiment = {
            "name": "isolate_first_missing_runtime_or_evidence_boundary",
            "priority": "high",
            "change_product_scope": False,
            "disable_seccomp": False,
            "missing": missing,
            "reason": "Product conclusions are blocked until execution and evidence boundaries are complete.",
        }

    return classification, facts, next_experiment


def build_packet(evidence_path: Path, runtime_log_path: Path, output_dir: Path) -> dict[str, Any]:
    evidence = _require_mapping(json.loads(evidence_path.read_text()), "evidence")
    runtime_text = runtime_log_path.read_text(errors="replace")
    observed_pipeline = _pipeline_from_log(runtime_text)
    classification, facts, next_experiment = _classify(evidence)

    packet = {
        "schema_version": "liminalos-evidence-advisory-v0.1",
        "adapter_kind": "deterministic_evidence_advisor",
        "evidence_ingested": True,
        "runtime_trace_ingested": True,
        "input_integrity": {
            "evidence_sha256": _sha256(evidence_path),
            "runtime_log_sha256": _sha256(runtime_log_path),
        },
        "liminal_runtime": {
            "expected_pipeline": list(PIPELINE_STEPS),
            "observed_pipeline": observed_pipeline,
            "pipeline_complete": list(PIPELINE_STEPS) == observed_pipeline,
        },
        "classification": classification,
        "confirmed_facts": facts,
        "next_experiment": next_experiment,
        "product_verdict_source": "normalized_evidence_not_liminalos",
        "authority": AUTHORITY,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    advice_path = output_dir / "liminalos-advice.json"
    next_path = output_dir / "liminalos-next-experiment.json"
    graph_path = output_dir / "liminalos-causal-graph.md"

    advice_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    next_path.write_text(json.dumps(next_experiment, indent=2, sort_keys=True) + "\n")

    graph_lines = [
        "# LiminalOSAI bounded causal advisory",
        "",
        "```text",
        "normalized QA evidence",
        "→ integrity verification",
        "→ Garden/DNS/probe fact extraction",
        f"→ advisory classification: {classification}",
        f"→ next experiment: {next_experiment['name']}",
        "→ Lotus/Pythia remains the adjudication boundary",
        "```",
        "",
        "The advisor is deterministic and advisory-only. It cannot override the normalized product verdict or authorize execution, submission, deployment, or merge.",
    ]
    graph_path.write_text("\n".join(graph_lines) + "\n")
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--runtime-log", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    packet = build_packet(args.evidence, args.runtime_log, args.output_dir)
    print(json.dumps(packet, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
