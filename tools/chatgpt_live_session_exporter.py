#!/usr/bin/env python3
"""Export an explicit live-session event log into the v0.2 conversation bundle.

The exporter is deterministic and fail-closed. It does not inspect hidden model
state, infer claims or authorization from prose, browse, execute tools, approve
delivery, or write model memory. It packages explicit events for the downstream
Conversation Normalizer and Liminal Adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "chatgpt-live-session-v0.3"
OUTPUT_SCHEMA = "chatgpt-conversation-bundle-v0.2"
MANIFEST_SCHEMA = "chatgpt-live-session-export-v0.3"

EVENT_TYPES = {
    "user_message",
    "assistant_draft",
    "claim",
    "source",
    "tool_event",
    "proposed_action",
    "contradiction",
    "user_authorization",
}
CLAIM_KINDS = {"fact", "reasoning", "recommendation", "uncertainty"}
FRESHNESS_VALUES = {"current", "stable", "unknown"}
SOURCE_KINDS = {"official", "repository", "tool", "user_provided", "web", "other"}
TOOL_STATUSES = {"success", "failure", "cancelled"}
TOOL_EFFECTS = {"read", "write", "none"}
AUTHORIZABLE_TYPES = {"tool_event", "proposed_action"}

AUTHORITY = {
    "mode": "export_only",
    "hidden_state_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "source_truth_verification": False,
    "execution": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array")
    return value


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _unit_interval(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number in [0, 1]")
    result = float(value)
    if not math.isfinite(result) or result < 0.0 or result > 1.0:
        raise ValueError(f"{name} must be a finite number in [0, 1]")
    return result


def _enum(value: Any, name: str, allowed: set[str]) -> str:
    item = _string(value, name)
    if item not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}")
    return item


def _string_list(value: Any, name: str) -> list[str]:
    result = [
        _string(item, f"{name}[{index}]")
        for index, item in enumerate(_list(value, name))
    ]
    if len(result) != len(set(result)):
        raise ValueError(f"{name} contains duplicates")
    return result


def _base_event(raw: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "id": _string(raw.get("id"), f"events[{index}].id"),
        "sequence": _integer(raw.get("sequence"), f"events[{index}].sequence"),
        "type": _enum(raw.get("type"), f"events[{index}].type", EVENT_TYPES),
    }


def validate_session(packet: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize the public v0.3 live-session contract."""
    if packet.get("schema_version") != INPUT_SCHEMA:
        raise ValueError(f"schema_version must be {INPUT_SCHEMA!r}")

    session_raw = _mapping(packet.get("session"), "session")
    capture_complete = _boolean(
        session_raw.get("capture_complete"), "session.capture_complete"
    )
    if not capture_complete:
        raise ValueError("session.capture_complete must be true for fail-closed export")

    session = {
        "id": _string(session_raw.get("id"), "session.id"),
        "request_event_id": _string(
            session_raw.get("request_event_id"), "session.request_event_id"
        ),
        "draft_event_id": _string(
            session_raw.get("draft_event_id"), "session.draft_event_id"
        ),
        "high_stakes": _boolean(
            session_raw.get("high_stakes"), "session.high_stakes"
        ),
        "requires_current_information": _boolean(
            session_raw.get("requires_current_information"),
            "session.requires_current_information",
        ),
        "capture_complete": capture_complete,
    }

    events: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(packet.get("events"), "events")):
        raw = _mapping(raw_value, f"events[{index}]")
        event = _base_event(raw, index)
        event_type = event["type"]

        if event_type == "user_message":
            event["text"] = _string(raw.get("text"), f"events[{index}].text")

        elif event_type == "assistant_draft":
            no_signal = _boolean(
                raw.get("no_signal"), f"events[{index}].no_signal"
            )
            response = _string(
                raw.get("response"), f"events[{index}].response", allow_empty=True
            )
            if not no_signal and not response.strip():
                raise ValueError(
                    f"events[{index}].response must not be empty unless no_signal is true"
                )
            event.update(
                {
                    "response": response,
                    "no_signal": no_signal,
                    "intent_alignment": _unit_interval(
                        raw.get("intent_alignment"),
                        f"events[{index}].intent_alignment",
                    ),
                }
            )

        elif event_type == "claim":
            event.update(
                {
                    "draft_event_id": _string(
                        raw.get("draft_event_id"),
                        f"events[{index}].draft_event_id",
                    ),
                    "text": _string(raw.get("text"), f"events[{index}].text"),
                    "kind": _enum(
                        raw.get("kind"), f"events[{index}].kind", CLAIM_KINDS
                    ),
                    "confidence": _unit_interval(
                        raw.get("confidence"), f"events[{index}].confidence"
                    ),
                    "requires_current_information": _boolean(
                        raw.get("requires_current_information"),
                        f"events[{index}].requires_current_information",
                    ),
                    "evidence_event_ids": _string_list(
                        raw.get("evidence_event_ids"),
                        f"events[{index}].evidence_event_ids",
                    ),
                }
            )

        elif event_type == "source":
            event.update(
                {
                    "handle": _string(
                        raw.get("handle"), f"events[{index}].handle"
                    ),
                    "verified": _boolean(
                        raw.get("verified"), f"events[{index}].verified"
                    ),
                    "freshness": _enum(
                        raw.get("freshness"),
                        f"events[{index}].freshness",
                        FRESHNESS_VALUES,
                    ),
                    "source_kind": _enum(
                        raw.get("source_kind"),
                        f"events[{index}].source_kind",
                        SOURCE_KINDS,
                    ),
                    "locator": _string(
                        raw.get("locator"), f"events[{index}].locator"
                    ),
                }
            )

        elif event_type == "tool_event":
            evidence_eligible = _boolean(
                raw.get("evidence_eligible"),
                f"events[{index}].evidence_eligible",
            )
            locator = _optional_string(
                raw.get("locator"), f"events[{index}].locator"
            )
            if evidence_eligible and locator is None:
                raise ValueError(
                    f"events[{index}].locator is required when evidence_eligible is true"
                )
            event.update(
                {
                    "tool": _string(raw.get("tool"), f"events[{index}].tool"),
                    "operation": _string(
                        raw.get("operation"), f"events[{index}].operation"
                    ),
                    "status": _enum(
                        raw.get("status"),
                        f"events[{index}].status",
                        TOOL_STATUSES,
                    ),
                    "effect": _enum(
                        raw.get("effect"),
                        f"events[{index}].effect",
                        TOOL_EFFECTS,
                    ),
                    "evidence_eligible": evidence_eligible,
                    "freshness": _enum(
                        raw.get("freshness"),
                        f"events[{index}].freshness",
                        FRESHNESS_VALUES,
                    ),
                    "locator": locator,
                    "reversible": _boolean(
                        raw.get("reversible"), f"events[{index}].reversible"
                    ),
                    "recovery_plan": _optional_string(
                        raw.get("recovery_plan"),
                        f"events[{index}].recovery_plan",
                    ),
                }
            )

        elif event_type == "proposed_action":
            event.update(
                {
                    "draft_event_id": _string(
                        raw.get("draft_event_id"),
                        f"events[{index}].draft_event_id",
                    ),
                    "description": _string(
                        raw.get("description"), f"events[{index}].description"
                    ),
                    "reversible": _boolean(
                        raw.get("reversible"), f"events[{index}].reversible"
                    ),
                    "recovery_plan": _optional_string(
                        raw.get("recovery_plan"),
                        f"events[{index}].recovery_plan",
                    ),
                }
            )

        elif event_type == "contradiction":
            event.update(
                {
                    "draft_event_id": _string(
                        raw.get("draft_event_id"),
                        f"events[{index}].draft_event_id",
                    ),
                    "text": _string(raw.get("text"), f"events[{index}].text"),
                }
            )

        elif event_type == "user_authorization":
            event.update(
                {
                    "text": _string(raw.get("text"), f"events[{index}].text"),
                    "authorized_event_ids": _string_list(
                        raw.get("authorized_event_ids"),
                        f"events[{index}].authorized_event_ids",
                    ),
                }
            )

        events.append(event)

    event_ids = [event["id"] for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event ids must be unique")
    sequences = [event["sequence"] for event in events]
    if len(sequences) != len(set(sequences)):
        raise ValueError("event sequences must be unique")

    events.sort(key=lambda item: (item["sequence"], item["id"]))
    by_id = {event["id"]: event for event in events}

    request_event = by_id.get(session["request_event_id"])
    if request_event is None or request_event["type"] != "user_message":
        raise ValueError("session.request_event_id must reference a user_message event")

    draft_event = by_id.get(session["draft_event_id"])
    if draft_event is None or draft_event["type"] != "assistant_draft":
        raise ValueError("session.draft_event_id must reference an assistant_draft event")

    draft_ids = {
        event["id"] for event in events if event["type"] == "assistant_draft"
    }
    for event in events:
        if event["type"] in {"claim", "proposed_action", "contradiction"}:
            if event["draft_event_id"] not in draft_ids:
                raise ValueError(
                    f"event {event['id']} references unknown assistant draft "
                    f"{event['draft_event_id']}"
                )

    source_handles = [
        event["handle"] for event in events if event["type"] == "source"
    ]
    if len(source_handles) != len(set(source_handles)):
        raise ValueError("source handles must be unique")

    tool_ids = {
        event["id"] for event in events if event["type"] == "tool_event"
    }
    overlap = sorted(set(source_handles) & tool_ids)
    if overlap:
        raise ValueError(
            "source handles and tool event ids must be globally unique: "
            + ", ".join(overlap)
        )

    authorization_edges: list[dict[str, str]] = []
    for authorization in [
        event for event in events if event["type"] == "user_authorization"
    ]:
        for target_id in authorization["authorized_event_ids"]:
            target = by_id.get(target_id)
            if target is None:
                raise ValueError(
                    f"authorization {authorization['id']} references unknown event {target_id}"
                )
            if target["type"] not in AUTHORIZABLE_TYPES:
                raise ValueError(
                    f"authorization target {target_id} must be a tool_event or proposed_action"
                )
            if authorization["sequence"] >= target["sequence"]:
                raise ValueError(
                    f"authorization {authorization['id']} must precede target {target_id}"
                )
            authorization_edges.append(
                {
                    "authorization_event_id": authorization["id"],
                    "target_event_id": target_id,
                }
            )

    return {
        "schema_version": INPUT_SCHEMA,
        "session": session,
        "events": events,
        "authorization_edges": authorization_edges,
    }


def export_session(
    packet: dict[str, Any], input_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Export a validated live session into a v0.2 conversation bundle."""
    normalized = validate_session(packet)
    session = normalized["session"]
    events = normalized["events"]
    by_id = {event["id"]: event for event in events}
    request_event = by_id[session["request_event_id"]]
    draft_event = by_id[session["draft_event_id"]]

    authorized_targets = {
        edge["target_event_id"] for edge in normalized["authorization_edges"]
    }
    selected_draft_id = draft_event["id"]

    claims = [
        event
        for event in events
        if event["type"] == "claim"
        and event["draft_event_id"] == selected_draft_id
    ]
    proposed_actions = [
        event
        for event in events
        if event["type"] == "proposed_action"
        and event["draft_event_id"] == selected_draft_id
    ]
    contradictions = [
        event
        for event in events
        if event["type"] == "contradiction"
        and event["draft_event_id"] == selected_draft_id
    ]
    sources = [event for event in events if event["type"] == "source"]
    tool_events = [event for event in events if event["type"] == "tool_event"]

    source_by_event_id = {event["id"]: event for event in sources}
    tool_by_event_id = {event["id"]: event for event in tool_events}
    unresolved_evidence_event_ids: set[str] = set()
    referenced_source_ids: set[str] = set()

    exported_claims: list[dict[str, Any]] = []
    for claim in claims:
        evidence_handles: list[str] = []
        for reference in claim["evidence_event_ids"]:
            if reference in source_by_event_id:
                source = source_by_event_id[reference]
                referenced_source_ids.add(reference)
                evidence_handles.append(source["handle"])
            elif reference in tool_by_event_id and tool_by_event_id[reference][
                "evidence_eligible"
            ]:
                evidence_handles.append(reference)
            else:
                unresolved_evidence_event_ids.add(reference)
                evidence_handles.append(f"unresolved:{reference}")
        exported_claims.append(
            {
                "id": claim["id"],
                "text": claim["text"],
                "kind": claim["kind"],
                "confidence": claim["confidence"],
                "requires_current_information": claim[
                    "requires_current_information"
                ],
                "evidence_handles": evidence_handles,
            }
        )

    bundle = {
        "schema_version": OUTPUT_SCHEMA,
        "request": {
            "id": session["id"],
            "text": request_event["text"],
            "high_stakes": session["high_stakes"],
            "requires_current_information": session[
                "requires_current_information"
            ],
        },
        "draft": {
            "response": draft_event["response"],
            "no_signal": draft_event["no_signal"],
            "intent_alignment": draft_event["intent_alignment"],
            "claims": exported_claims,
            "proposed_actions": [
                {
                    "id": event["id"],
                    "description": event["description"],
                    "reversible": event["reversible"],
                    "user_authorized": event["id"] in authorized_targets,
                    "recovery_plan": event["recovery_plan"],
                }
                for event in proposed_actions
            ],
            "contradictions": [event["text"] for event in contradictions],
        },
        "sources": [
            {
                "handle": event["handle"],
                "verified": event["verified"],
                "freshness": event["freshness"],
                "source_kind": event["source_kind"],
                "locator": event["locator"],
            }
            for event in sources
        ],
        "tool_events": [
            {
                "id": event["id"],
                "tool": event["tool"],
                "operation": event["operation"],
                "status": event["status"],
                "effect": event["effect"],
                "evidence_eligible": event["evidence_eligible"],
                "freshness": event["freshness"],
                "locator": event["locator"],
                "reversible": event["reversible"],
                "user_authorized": event["id"] in authorized_targets,
                "recovery_plan": event["recovery_plan"],
            }
            for event in tool_events
        ],
    }

    ignored_draft_bound_events = [
        event["id"]
        for event in events
        if event["type"] in {"claim", "proposed_action", "contradiction"}
        and event["draft_event_id"] != selected_draft_id
    ]
    unused_source_event_ids = sorted(
        event["id"] for event in sources if event["id"] not in referenced_source_ids
    )

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "exporter_kind": "deterministic_live_session_event_exporter",
        "session_id": session["id"],
        "selected_event_ids": {
            "request": request_event["id"],
            "draft": draft_event["id"],
        },
        "input_integrity": {"input_sha256": input_sha256},
        "output_integrity": {"bundle_sha256": _canonical_sha256(bundle)},
        "counts": {
            "events": len(events),
            "claims": len(exported_claims),
            "sources": len(sources),
            "tool_events": len(tool_events),
            "proposed_actions": len(proposed_actions),
            "contradictions": len(contradictions),
            "authorization_edges": len(normalized["authorization_edges"]),
        },
        "authorization_edges": normalized["authorization_edges"],
        "unresolved_evidence_event_ids": sorted(
            unresolved_evidence_event_ids
        ),
        "unused_source_event_ids": unused_source_event_ids,
        "ignored_draft_bound_event_ids": ignored_draft_bound_events,
        "warnings": [
            f"unresolved_evidence_event:{event_id}"
            for event_id in sorted(unresolved_evidence_event_ids)
        ],
        "authority": AUTHORITY,
    }
    return bundle, manifest


def _graph(manifest: dict[str, Any]) -> str:
    unresolved = manifest["unresolved_evidence_event_ids"]
    authorization_count = manifest["counts"]["authorization_edges"]
    return "\n".join(
        [
            "# Live Session Export Trace",
            "",
            f"- session: `{manifest['session_id']}`",
            f"- request event: `{manifest['selected_event_ids']['request']}`",
            f"- draft event: `{manifest['selected_event_ids']['draft']}`",
            f"- claims: `{manifest['counts']['claims']}`",
            f"- tool events: `{manifest['counts']['tool_events']}`",
            f"- authorization edges: `{authorization_count}`",
            "- unresolved evidence events: "
            + (", ".join(f"`{item}`" for item in unresolved) if unresolved else "none"),
            "",
            "```text",
            "explicit live-session events",
            "→ selected request + selected draft",
            "→ claims / sources / tool events / explicit authorization edges",
            "→ chatgpt-conversation-bundle-v0.2",
            "→ Conversation Normalizer",
            "→ Liminal Adapter",
            "```",
            "",
        ]
    )


def write_export(
    bundle: dict[str, Any], manifest: dict[str, Any], output_dir: Path
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "chatgpt-conversation-bundle.json"
    manifest_path = output_dir / "live-session-export.json"
    graph_path = output_dir / "live-session-export-graph.md"

    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    graph_path.write_text(_graph(manifest))
    return {
        "bundle": str(bundle_path),
        "manifest": str(manifest_path),
        "graph": str(graph_path),
    }


def build_export(input_path: Path, output_dir: Path) -> tuple[dict[str, Any], dict[str, str]]:
    packet = json.loads(input_path.read_text())
    bundle, manifest = export_session(packet, _sha256(input_path))
    paths = write_export(bundle, manifest, output_dir)
    return manifest, paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export explicit live-session events into a conversation bundle."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        manifest, paths = build_export(args.input, args.output_dir)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"live-session export failed: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "schema_version": manifest["schema_version"],
                "session_id": manifest["session_id"],
                "unresolved_evidence_event_ids": manifest[
                    "unresolved_evidence_event_ids"
                ],
                "outputs": paths,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
