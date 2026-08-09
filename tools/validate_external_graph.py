#!/usr/bin/env python3
"""Validate the External Validation Graph using only the Python standard library.

The canonical .yaml file is intentionally serialized as JSON-compatible YAML.
JSON is a valid YAML 1.2 subset, which lets this security gate avoid a runtime
package installation solely to parse the graph.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any


STATUS_ORDER = (
    "SENT",
    "ACKNOWLEDGED",
    "ROUTED",
    "TECHNICAL_FEEDBACK",
    "REPRODUCED",
    "VALIDATED",
)

DEFAULT_GRAPH = Path("docs/external_validation_graph.v0.1.yaml")
EXPECTED_SCHEMA = "external-validation-graph/v0.1"


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _mapping(value: Any) -> bool:
    return isinstance(value, dict)


def load_graph(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise ValueError(f"graph file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path} must remain JSON-compatible YAML; parse error: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError("graph root must be an object")
    return data


def validate_graph(graph: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []

    if graph.get("schema_version") != EXPECTED_SCHEMA:
        errors.append(
            f"schema_version must be {EXPECTED_SCHEMA!r}, got {graph.get('schema_version')!r}"
        )

    claim = graph.get("claim")
    if not _mapping(claim) or not _nonempty(claim.get("id")):
        errors.append("claim.id must be a non-empty string")
        claim_id = None
    else:
        claim_id = claim["id"]

    status_model = graph.get("status_model")
    if not _mapping(status_model):
        errors.append("status_model must be an object")
        status_model = {}

    weights: dict[str, float] = {}
    previous_weight = -1.0
    for status in STATUS_ORDER:
        entry = status_model.get(status)
        if not _mapping(entry):
            errors.append(f"status_model.{status} must be an object")
            continue
        weight = entry.get("weight")
        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            errors.append(f"status_model.{status}.weight must be numeric")
            continue
        weight = float(weight)
        if not 0.0 <= weight <= 1.0:
            errors.append(f"status_model.{status}.weight must be in [0, 1]")
        if weight <= previous_weight:
            errors.append("status weights must be strictly increasing in maturity order")
        previous_weight = weight
        weights[status] = weight
        if not _nonempty(entry.get("meaning")):
            errors.append(f"status_model.{status}.meaning must be non-empty")

    extra_statuses = set(status_model) - set(STATUS_ORDER)
    if extra_statuses:
        errors.append(f"unknown statuses in status_model: {sorted(extra_statuses)}")

    allowed_transitions = graph.get("allowed_transitions")
    if not isinstance(allowed_transitions, list) or not allowed_transitions:
        errors.append("allowed_transitions must be a non-empty list")
    else:
        seen_edges: set[tuple[str, str]] = set()
        for index, transition in enumerate(allowed_transitions):
            prefix = f"allowed_transitions[{index}]"
            if not _mapping(transition):
                errors.append(f"{prefix} must be an object")
                continue
            source = transition.get("from")
            target = transition.get("to")
            if source not in STATUS_ORDER:
                errors.append(f"{prefix}.from is not a known status: {source!r}")
            if target not in STATUS_ORDER:
                errors.append(f"{prefix}.to is not a known status: {target!r}")
            if source == target:
                errors.append(f"{prefix} cannot be a self-transition")
            if source in STATUS_ORDER and target in STATUS_ORDER:
                edge = (source, target)
                if edge in seen_edges:
                    errors.append(f"duplicate allowed transition: {source} -> {target}")
                seen_edges.add(edge)
            if not _nonempty(transition.get("evidence_required")):
                errors.append(f"{prefix}.evidence_required must be non-empty")

    targets = graph.get("review_targets")
    if not isinstance(targets, list) or not targets:
        errors.append("review_targets must be a non-empty list")
        targets = []

    required_target_fields = (
        "id",
        "claim_id",
        "organization",
        "target",
        "date_utc",
        "status",
        "evidence",
        "evidence_reference",
        "repository_commit_or_pr",
        "requested_falsification",
        "next_high_value_state",
    )

    seen_ids: set[str] = set()
    authoritative_weights: list[float] = []

    for index, target in enumerate(targets):
        prefix = f"review_targets[{index}]"
        if not _mapping(target):
            errors.append(f"{prefix} must be an object")
            continue

        for field in required_target_fields:
            if not _nonempty(target.get(field)):
                errors.append(f"{prefix}.{field} must be a non-empty string")

        target_id = target.get("id")
        if isinstance(target_id, str):
            if target_id in seen_ids:
                errors.append(f"duplicate review target id: {target_id}")
            seen_ids.add(target_id)

        if claim_id is not None and target.get("claim_id") != claim_id:
            errors.append(
                f"{prefix}.claim_id must match claim.id {claim_id!r}"
            )

        status = target.get("status")
        if status not in STATUS_ORDER:
            errors.append(f"{prefix}.status is not a known status: {status!r}")
            continue

        model_weight = weights.get(status)
        status_weight = target.get("status_weight")
        if model_weight is not None:
            authoritative_weights.append(model_weight)
            if not isinstance(status_weight, (int, float)) or isinstance(status_weight, bool):
                errors.append(f"{prefix}.status_weight must be numeric")
            elif not math.isclose(float(status_weight), model_weight, rel_tol=0.0, abs_tol=1e-12):
                errors.append(
                    f"{prefix}.status_weight {status_weight!r} does not match "
                    f"status_model.{status}.weight {model_weight!r}"
                )

        next_state = target.get("next_high_value_state")
        if next_state not in STATUS_ORDER:
            errors.append(f"{prefix}.next_high_value_state is unknown: {next_state!r}")

        repository_ref = target.get("repository_commit_or_pr")
        if _nonempty(repository_ref) and not repository_ref.startswith("https://github.com/"):
            errors.append(
                f"{prefix}.repository_commit_or_pr must be a GitHub URL"
            )

        status_rank = STATUS_ORDER.index(status)
        if status_rank >= STATUS_ORDER.index("TECHNICAL_FEEDBACK"):
            if not _nonempty(target.get("technical_feedback_reference")):
                errors.append(
                    f"{prefix} at {status} requires technical_feedback_reference"
                )

        if status_rank >= STATUS_ORDER.index("REPRODUCED"):
            reproduction = target.get("reproduction_evidence")
            if not _mapping(reproduction):
                errors.append(
                    f"{prefix} at {status} requires reproduction_evidence"
                )
            else:
                for field in ("external_reference", "repository_commit_or_pr"):
                    if not _nonempty(reproduction.get(field)):
                        errors.append(
                            f"{prefix}.reproduction_evidence.{field} must be non-empty"
                        )

        if status == "VALIDATED":
            validation = target.get("validation_evidence")
            if not _mapping(validation):
                errors.append(
                    f"{prefix} at VALIDATED requires validation_evidence"
                )
            else:
                for field in (
                    "external_reference",
                    "reproduction_reference",
                    "repository_commit_or_pr",
                ):
                    if not _nonempty(validation.get(field)):
                        errors.append(
                            f"{prefix}.validation_evidence.{field} must be non-empty"
                        )

    target_count = len(targets)
    weighted_sum = round(sum(authoritative_weights), 8)
    score_percent = round(100.0 * weighted_sum / target_count, 2) if target_count else 0.0

    score = graph.get("score")
    if not _mapping(score):
        errors.append("score must be an object")
    else:
        if score.get("target_count") != target_count:
            errors.append(
                f"score.target_count is stale: expected {target_count}, got {score.get('target_count')!r}"
            )
        stored_sum = score.get("weighted_sum")
        if not isinstance(stored_sum, (int, float)) or isinstance(stored_sum, bool):
            errors.append("score.weighted_sum must be numeric")
        elif not math.isclose(float(stored_sum), weighted_sum, rel_tol=0.0, abs_tol=1e-8):
            errors.append(
                f"score.weighted_sum is stale: expected {weighted_sum}, got {stored_sum!r}"
            )
        stored_percent = score.get("score_percent")
        if not isinstance(stored_percent, (int, float)) or isinstance(stored_percent, bool):
            errors.append("score.score_percent must be numeric")
        elif not math.isclose(float(stored_percent), score_percent, rel_tol=0.0, abs_tol=1e-2):
            errors.append(
                f"score.score_percent is stale: expected {score_percent}, got {stored_percent!r}"
            )

    summary = {
        "schema_version": graph.get("schema_version"),
        "claim_id": claim_id,
        "target_count": target_count,
        "weighted_sum": weighted_sum,
        "score_percent": score_percent,
        "validated_targets": sum(
            1 for target in targets if isinstance(target, dict) and target.get("status") == "VALIDATED"
        ),
        "reproduced_targets": sum(
            1 for target in targets if isinstance(target, dict) and target.get("status") == "REPRODUCED"
        ),
    }
    return summary, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)

    try:
        graph = load_graph(args.path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    summary, errors = validate_graph(graph)
    if errors:
        print("External Validation Graph: INVALID", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if args.json_output:
        print(json.dumps(summary, sort_keys=True))
    else:
        print("External Validation Graph: VALID")
        print(f"claim={summary['claim_id']}")
        print(f"targets={summary['target_count']}")
        print(f"weighted_sum={summary['weighted_sum']:.2f}")
        print(f"EEW={summary['score_percent']:.2f}/100")
        print(f"reproduced={summary['reproduced_targets']}")
        print(f"validated={summary['validated_targets']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
