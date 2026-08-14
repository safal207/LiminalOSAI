#!/usr/bin/env python3
"""Validate Review Event Envelope v0.1 using only the Python standard library."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "review-event-envelope/v0.1"
GRAPH_PATH = Path("docs/external_validation_graph.v0.1.yaml")
STATUS_ORDER = (
    "SENT",
    "ACKNOWLEDGED",
    "ROUTED",
    "TECHNICAL_FEEDBACK",
    "REPRODUCED",
    "VALIDATED",
)
EVENT_TO_STATUS = {
    "review.sent": "SENT",
    "review.acknowledged": "ACKNOWLEDGED",
    "review.routed": "ROUTED",
    "review.technical_feedback": "TECHNICAL_FEEDBACK",
    "review.reproduced": "REPRODUCED",
    "review.validated": "VALIDATED",
}


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"root must be an object: {path}")
    return data


def _valid_rfc3339(value: Any) -> bool:
    if not _nonempty(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return "T" in value


def validate_event(
    event: dict[str, Any], graph: dict[str, Any] | None = None
) -> list[str]:
    errors: list[str] = []

    if event.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")

    for field in ("event_id", "event_type", "occurred_at", "claim_id"):
        if not _nonempty(event.get(field)):
            errors.append(f"{field} must be a non-empty string")

    if not _valid_rfc3339(event.get("occurred_at")):
        errors.append("occurred_at must be an ISO/RFC3339 date-time")

    event_type = event.get("event_type")
    expected_status = EVENT_TO_STATUS.get(event_type)
    if expected_status is None:
        errors.append(f"unknown event_type: {event_type!r}")

    subject = event.get("subject")
    if not _mapping(subject):
        errors.append("subject must be an object")
        subject = {}
    for field in ("organization", "target_id"):
        if not _nonempty(subject.get(field)):
            errors.append(f"subject.{field} must be a non-empty string")

    transition = event.get("transition")
    if not _mapping(transition):
        errors.append("transition must be an object")
        transition = {}

    source = transition.get("from")
    target = transition.get("to")
    if source is not None and source not in STATUS_ORDER:
        errors.append(f"transition.from is unknown: {source!r}")
    if target not in STATUS_ORDER:
        errors.append(f"transition.to is unknown: {target!r}")
    if expected_status is not None and target != expected_status:
        errors.append(
            f"event_type {event_type!r} requires transition.to={expected_status!r}"
        )

    if target in STATUS_ORDER:
        target_rank = STATUS_ORDER.index(target)
        if target == "SENT":
            if source is not None:
                errors.append("review.sent must start with transition.from=null")
        elif source is None:
            errors.append(f"{event_type} requires a previous status")
        elif source in STATUS_ORDER and STATUS_ORDER.index(source) >= target_rank:
            errors.append("review transitions must move to a strictly stronger status")

    evidence = event.get("evidence")
    if not _mapping(evidence):
        errors.append("evidence must be an object")
        evidence = {}
    for field in ("kind", "reference", "summary"):
        if not _nonempty(evidence.get(field)):
            errors.append(f"evidence.{field} must be a non-empty string")
    if not isinstance(evidence.get("public"), bool):
        errors.append("evidence.public must be boolean")

    if target in STATUS_ORDER:
        target_rank = STATUS_ORDER.index(target)
        if target_rank >= STATUS_ORDER.index("TECHNICAL_FEEDBACK"):
            summary = evidence.get("summary")
            if not _nonempty(summary) or len(summary.strip()) < 40:
                errors.append(
                    "TECHNICAL_FEEDBACK or stronger requires a substantive evidence.summary"
                )
        if target_rank >= STATUS_ORDER.index("REPRODUCED"):
            for field in ("external_reproducer", "reproduction_reference"):
                if not _nonempty(evidence.get(field)):
                    errors.append(f"{target} requires evidence.{field}")
        if target == "VALIDATED" and not _nonempty(evidence.get("validation_reference")):
            errors.append("VALIDATED requires evidence.validation_reference")

    repository = event.get("repository")
    if not _mapping(repository):
        errors.append("repository must be an object")
        repository = {}
    if repository.get("repository") != "safal207/LiminalOSAI":
        errors.append("repository.repository must be 'safal207/LiminalOSAI'")
    if not isinstance(repository.get("pr"), int) or isinstance(repository.get("pr"), bool):
        errors.append("repository.pr must be an integer")
    commit = repository.get("commit")
    if commit is not None and not _nonempty(commit):
        errors.append("repository.commit must be null or a non-empty string")

    provenance = event.get("provenance")
    if not _mapping(provenance):
        errors.append("provenance must be an object")
        provenance = {}
    for field in ("recorded_by", "source"):
        if not _nonempty(provenance.get(field)):
            errors.append(f"provenance.{field} must be a non-empty string")

    if graph is not None:
        claim = graph.get("claim") if _mapping(graph.get("claim")) else {}
        if event.get("claim_id") != claim.get("id"):
            errors.append("event claim_id does not match canonical graph claim.id")

        target_id = subject.get("target_id")
        canonical_target = None
        for item in graph.get("review_targets", []):
            if isinstance(item, dict) and item.get("id") == target_id:
                canonical_target = item
                break
        if canonical_target is None:
            errors.append(f"subject.target_id not found in canonical graph: {target_id!r}")
        else:
            if subject.get("organization") != canonical_target.get("organization"):
                errors.append("subject.organization does not match canonical review target")
            current_status = canonical_target.get("status")
            if target in STATUS_ORDER and current_status in STATUS_ORDER:
                if STATUS_ORDER.index(target) > STATUS_ORDER.index(current_status):
                    errors.append(
                        "event transition exceeds the evidence state currently accepted by the canonical graph"
                    )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", nargs="+", type=Path)
    parser.add_argument("--graph", type=Path, default=GRAPH_PATH)
    args = parser.parse_args(argv)

    try:
        graph = _load_json(args.graph)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    failed = False
    for path in args.events:
        try:
            event = _load_json(path)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failed = True
            continue

        errors = validate_event(event, graph)
        if errors:
            failed = True
            print(f"Review Event Envelope: INVALID ({path})", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
        else:
            print(
                f"Review Event Envelope: VALID ({path}) "
                f"{event['event_type']} {event['subject']['target_id']}"
            )

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
