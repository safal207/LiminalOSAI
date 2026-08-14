#!/usr/bin/env python3
"""Export External Validation Graph state without transferring authority.

The export contract is deliberately negative: external review maturity is
portable evidence, but it cannot become a capability, execution permission, or
policy mutation authority. Even a fully VALIDATED graph with EEW=100 remains
EVIDENCE_ONLY and requires a separate authorization contract before action.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from validate_external_graph import load_graph, validate_graph

DEFAULT_GRAPH = Path("docs/external_validation_graph.v0.1.yaml")
EXPORT_SCHEMA = "external-validation-evidence-export/v0.1"
BOUNDARY_SCHEMA = "external-validation-export-boundary/v0.1"

REQUIRED_AUTHORITY_BOUNDARY: dict[str, Any] = {
    "schema_version": BOUNDARY_SCHEMA,
    "classification": "EVIDENCE_ONLY",
    "authorization_transfer": "NONE",
    "execution_authorized": False,
    "policy_mutation_authorized": False,
    "capability_granted": False,
    "durable_authority_granted": False,
    "requires_separate_authorization_contract": True,
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def validate_authority_boundary(graph: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    boundary = graph.get("export_contract")
    if not isinstance(boundary, dict):
        return ["export_contract must be an object"]

    for key, expected in REQUIRED_AUTHORITY_BOUNDARY.items():
        actual = boundary.get(key)
        if actual != expected:
            errors.append(
                f"export_contract.{key} must be {expected!r}, got {actual!r}"
            )

    rule = boundary.get("rule")
    if not isinstance(rule, str) or not rule.strip():
        errors.append("export_contract.rule must be a non-empty string")

    proofpath = graph.get("proofpath_mapping")
    if not isinstance(proofpath, dict):
        errors.append("proofpath_mapping must be an object")
    else:
        if proofpath.get("event_classification") != "EVIDENCE_ONLY":
            errors.append("proofpath_mapping.event_classification must be EVIDENCE_ONLY")
        if proofpath.get("authorization_transfer") != "NONE":
            errors.append("proofpath_mapping.authorization_transfer must be NONE")
        if proofpath.get("may_infer_authority") is not False:
            errors.append("proofpath_mapping.may_infer_authority must be false")

    cml = graph.get("cml_mapping")
    if not isinstance(cml, dict):
        errors.append("cml_mapping must be an object")
    else:
        if cml.get("memory_semantics") != "EVIDENCE_STATE_ONLY":
            errors.append("cml_mapping.memory_semantics must be EVIDENCE_STATE_ONLY")
        if cml.get("authorization_transfer") != "NONE":
            errors.append("cml_mapping.authorization_transfer must be NONE")
        if cml.get("may_influence_authorization_without_separate_contract") is not False:
            errors.append(
                "cml_mapping.may_influence_authorization_without_separate_contract must be false"
            )

    return errors


def build_export(graph: dict[str, Any]) -> dict[str, Any]:
    summary, graph_errors = validate_graph(graph)
    boundary_errors = validate_authority_boundary(graph)
    errors = graph_errors + boundary_errors
    if errors:
        raise ValueError("invalid external validation graph: " + "; ".join(errors))

    targets = []
    for target in sorted(graph["review_targets"], key=lambda item: item["id"]):
        targets.append(
            {
                "id": target["id"],
                "organization": target["organization"],
                "status": target["status"],
                "evidence_reference": target["evidence_reference"],
                "repository_commit_or_pr": target["repository_commit_or_pr"],
            }
        )

    body: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA,
        "source_graph_schema": graph["schema_version"],
        "claim_id": graph["claim"]["id"],
        "updated_at": graph["updated_at"],
        "review_maturity": {
            "score_id": graph["score"]["id"],
            "target_count": summary["target_count"],
            "weighted_sum": summary["weighted_sum"],
            "score_percent": summary["score_percent"],
            "validated_targets": summary["validated_targets"],
            "reproduced_targets": summary["reproduced_targets"],
        },
        "targets": targets,
        "authority_boundary": copy.deepcopy(graph["export_contract"]),
        "downstream": {
            "proofpath": {
                "classification": graph["proofpath_mapping"]["event_classification"],
                "authorization_transfer": graph["proofpath_mapping"]["authorization_transfer"],
                "may_infer_authority": graph["proofpath_mapping"]["may_infer_authority"],
            },
            "cml": {
                "state_key": graph["cml_mapping"]["state_key"],
                "memory_semantics": graph["cml_mapping"]["memory_semantics"],
                "authorization_transfer": graph["cml_mapping"]["authorization_transfer"],
                "may_influence_authorization_without_separate_contract": graph["cml_mapping"][
                    "may_influence_authorization_without_separate_contract"
                ],
            },
        },
    }
    exported = copy.deepcopy(body)
    exported["export_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return exported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        graph = load_graph(args.graph)
        exported = build_export(graph)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(exported, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
