#!/usr/bin/env python3
"""Apply a Review Event Envelope to the External Validation Graph.

Fail-closed behavior:
- default mode is dry-run; the canonical graph is never written implicitly;
- candidate event structure/evidence is validated first;
- the event target must already exist in the canonical graph;
- a new transition must start from the target's exact current status;
- the transition edge must be explicitly allowed by the graph;
- stale/regressive events are rejected;
- replay of an already-applied event is an idempotent no-op only when its
  evidence reference is already represented by the canonical target;
- EEW is recomputed from the status model, never trusted from the event.

The graph file is JSON-compatible YAML, so this tool uses only the Python
standard library.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import sys
from pathlib import Path
from typing import Any

from validate_external_graph import load_graph, validate_graph
from validate_review_event import STATUS_ORDER, _load_json, validate_event


DEFAULT_GRAPH = Path("docs/external_validation_graph.v0.1.yaml")


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _find_target(graph: dict[str, Any], target_id: str) -> dict[str, Any] | None:
    for target in graph.get("review_targets", []):
        if isinstance(target, dict) and target.get("id") == target_id:
            return target
    return None


def _allowed_edges(graph: dict[str, Any]) -> set[tuple[str, str]]:
    edges: set[tuple[str, str]] = set()
    for transition in graph.get("allowed_transitions", []):
        if not isinstance(transition, dict):
            continue
        source = transition.get("from")
        target = transition.get("to")
        if source in STATUS_ORDER and target in STATUS_ORDER:
            edges.add((source, target))
    return edges


def _repository_reference(event: dict[str, Any]) -> str:
    repository = event["repository"]
    repo = repository["repository"]
    commit = repository.get("commit")
    if _nonempty(commit):
        return f"https://github.com/{repo}/commit/{commit}"
    return f"https://github.com/{repo}/pull/{repository['pr']}"


def _next_high_value_state(graph: dict[str, Any], current: str) -> str:
    candidates = [
        target
        for source, target in _allowed_edges(graph)
        if source == current and target in STATUS_ORDER
    ]
    if not candidates:
        return "VALIDATED"
    return max(candidates, key=STATUS_ORDER.index)


def _evidence_already_present(target: dict[str, Any], event: dict[str, Any]) -> bool:
    reference = event.get("evidence", {}).get("reference")
    if not _nonempty(reference):
        return False
    haystacks = (
        target.get("evidence_reference"),
        target.get("evidence"),
        target.get("technical_feedback_reference"),
    )
    return any(_nonempty(value) and reference in value for value in haystacks)


def _recompute_score(graph: dict[str, Any]) -> None:
    weights = {
        status: float(entry["weight"])
        for status, entry in graph["status_model"].items()
        if status in STATUS_ORDER and isinstance(entry, dict)
    }
    targets = graph["review_targets"]
    weighted_sum = round(sum(weights[target["status"]] for target in targets), 8)
    score_percent = round(100.0 * weighted_sum / len(targets), 2) if targets else 0.0

    graph["score"]["target_count"] = len(targets)
    graph["score"]["weighted_sum"] = weighted_sum
    graph["score"]["score_percent"] = score_percent

    technical = sum(
        1
        for target in targets
        if STATUS_ORDER.index(target["status"]) >= STATUS_ORDER.index("TECHNICAL_FEEDBACK")
    )
    reproduced = sum(
        1
        for target in targets
        if STATUS_ORDER.index(target["status"]) >= STATUS_ORDER.index("REPRODUCED")
    )
    validated = sum(1 for target in targets if target["status"] == "VALIDATED")
    graph["score"]["interpretation"] = (
        "External-review maturity only: "
        f"technical_feedback_or_stronger={technical}, "
        f"reproduced_or_stronger={reproduced}, validated={validated}. "
        "This is not a safety-confidence percentage, probability, or endorsement score."
    )


def apply_event(
    graph: dict[str, Any], event: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (new_graph, result). The input graph is never mutated."""

    structural_errors = validate_event(event, graph=None)
    if structural_errors:
        raise ValueError("invalid review event: " + "; ".join(structural_errors))

    candidate = copy.deepcopy(graph)

    claim = candidate.get("claim", {})
    if event.get("claim_id") != claim.get("id"):
        raise ValueError("event claim_id does not match canonical graph claim.id")

    subject = event["subject"]
    target = _find_target(candidate, subject["target_id"])
    if target is None:
        raise ValueError(
            f"review target does not exist in canonical graph: {subject['target_id']!r}"
        )
    if subject.get("organization") != target.get("organization"):
        raise ValueError("event organization does not match canonical review target")

    current_status = target["status"]
    source_status = event["transition"].get("from")
    new_status = event["transition"]["to"]

    current_rank = STATUS_ORDER.index(current_status)
    new_rank = STATUS_ORDER.index(new_status)

    if new_status == current_status:
        if not _evidence_already_present(target, event):
            raise ValueError(
                "same-state replay is not attributable to evidence already represented by the canonical target"
            )
        result = {
            "action": "noop",
            "reason": "already_applied",
            "event_id": event["event_id"],
            "target_id": target["id"],
            "current_status": current_status,
            "new_status": new_status,
            "score_percent": candidate["score"]["score_percent"],
        }
        return candidate, result

    if new_rank < current_rank:
        raise ValueError(
            f"stale/regressive event: canonical={current_status}, event.to={new_status}"
        )

    if source_status != current_status:
        raise ValueError(
            f"transition.from must equal canonical current status {current_status!r}, got {source_status!r}"
        )

    if (current_status, new_status) not in _allowed_edges(candidate):
        raise ValueError(
            f"transition is not allowed by canonical graph: {current_status} -> {new_status}"
        )

    event_evidence = event["evidence"]
    repo_reference = _repository_reference(event)

    target["date_utc"] = event["occurred_at"][:10]
    target["status"] = new_status
    target["status_weight"] = float(candidate["status_model"][new_status]["weight"])
    target["evidence"] = event_evidence["summary"]
    target["evidence_reference"] = event_evidence["reference"]
    target["repository_commit_or_pr"] = repo_reference
    target["next_high_value_state"] = _next_high_value_state(candidate, new_status)
    target["last_review_event"] = {
        "event_id": event["event_id"],
        "event_type": event["event_type"],
        "occurred_at": event["occurred_at"],
        "evidence_reference": event_evidence["reference"],
        "evidence_public": event_evidence["public"],
    }

    if new_rank >= STATUS_ORDER.index("TECHNICAL_FEEDBACK"):
        target["technical_feedback_reference"] = event_evidence["reference"]

    if new_rank >= STATUS_ORDER.index("REPRODUCED"):
        target["reproduction_evidence"] = {
            "external_reference": event_evidence["reproduction_reference"],
            "external_reproducer": event_evidence["external_reproducer"],
            "repository_commit_or_pr": repo_reference,
        }

    if new_status == "VALIDATED":
        target["validation_evidence"] = {
            "external_reference": event_evidence["validation_reference"],
            "reproduction_reference": event_evidence["reproduction_reference"],
            "repository_commit_or_pr": repo_reference,
        }

    candidate["updated_at"] = event["occurred_at"][:10]
    _recompute_score(candidate)

    summary, graph_errors = validate_graph(candidate)
    if graph_errors:
        raise ValueError(
            "candidate graph failed post-apply validation: " + "; ".join(graph_errors)
        )

    result = {
        "action": "apply",
        "event_id": event["event_id"],
        "target_id": target["id"],
        "previous_status": current_status,
        "new_status": new_status,
        "weighted_sum": summary["weighted_sum"],
        "score_percent": summary["score_percent"],
    }
    return candidate, result


def _serialized(graph: dict[str, Any]) -> str:
    return json.dumps(graph, indent=2, ensure_ascii=False) + "\n"


def _diff(before: dict[str, Any], after: dict[str, Any], graph_path: Path) -> str:
    return "".join(
        difflib.unified_diff(
            _serialized(before).splitlines(keepends=True),
            _serialized(after).splitlines(keepends=True),
            fromfile=str(graph_path),
            tofile=str(graph_path) + " (candidate)",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument(
        "--write",
        action="store_true",
        help="write the validated candidate graph; default is dry-run",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args(argv)

    try:
        graph = load_graph(args.graph)
        event = _load_json(args.event)
        candidate, result = apply_event(graph, event)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    changed = candidate != graph
    result["changed"] = changed
    result["mode"] = "write" if args.write else "dry-run"

    if args.write and changed:
        args.graph.write_text(_serialized(candidate), encoding="utf-8")
        result["written"] = True
    else:
        result["written"] = False

    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"Review Event Apply: {result['action'].upper()} "
            f"target={result['target_id']} status={result.get('previous_status', result.get('current_status'))}"
            f"->{result['new_status']} mode={result['mode']}"
        )
        if changed and not args.write:
            print(_diff(graph, candidate, args.graph), end="")
        elif args.write and changed:
            print(f"wrote validated graph: {args.graph}")
        elif not changed:
            print("canonical graph unchanged")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
