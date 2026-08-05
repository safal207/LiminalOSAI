#!/usr/bin/env python3
"""Normalize a bounded conversation bundle into ChatGPT Liminal Adapter input.

The normalizer is deterministic and fail-closed. It does not infer claims from
raw prose, browse, verify source truth, execute tools, approve delivery, or
write model memory. It converts explicit request, draft, source, and tool-event
records into the adapter's v0.1 JSON contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "chatgpt-conversation-bundle-v0.2"
MANIFEST_SCHEMA = "chatgpt-conversation-normalization-v0.2"
ADAPTER_SCHEMA = "chatgpt-liminal-input-v0.1"
CLAIM_KINDS = {"fact", "reasoning", "recommendation", "uncertainty"}
FRESHNESS_VALUES = {"current", "stable", "unknown"}
SOURCE_KINDS = {"official", "repository", "tool", "user_provided", "web", "other"}
TOOL_STATUSES = {"success", "failure", "cancelled"}
TOOL_EFFECTS = {"read", "write", "none"}

AUTHORITY = {
    "mode": "normalization_only",
    "claim_inference": False,
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


def _unit_interval(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number in [0, 1]")
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or number > 1.0:
        raise ValueError(f"{name} must be a finite number in [0, 1]")
    return number


def _enum(value: Any, name: str, allowed: set[str]) -> str:
    item = _string(value, name)
    if item not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}")
    return item


def _string_list(value: Any, name: str) -> list[str]:
    result: list[str] = []
    for index, item in enumerate(_list(value, name)):
        result.append(_string(item, f"{name}[{index}]"))
    if len(result) != len(set(result)):
        raise ValueError(f"{name} contains duplicates")
    return result


def _require_unique(items: list[dict[str, Any]], field: str, name: str) -> None:
    seen: set[str] = set()
    for item in items:
        value = item[field]
        if value in seen:
            raise ValueError(f"duplicate {name} {field}: {value}")
        seen.add(value)


def validate_bundle(packet: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize the public v0.2 conversation bundle."""
    if packet.get("schema_version") != INPUT_SCHEMA:
        raise ValueError(f"schema_version must be {INPUT_SCHEMA!r}")

    request_raw = _mapping(packet.get("request"), "request")
    request = {
        "id": _string(request_raw.get("id"), "request.id"),
        "text": _string(request_raw.get("text"), "request.text"),
        "high_stakes": _boolean(request_raw.get("high_stakes"), "request.high_stakes"),
        "requires_current_information": _boolean(
            request_raw.get("requires_current_information"),
            "request.requires_current_information",
        ),
    }

    draft_raw = _mapping(packet.get("draft"), "draft")
    no_signal = _boolean(draft_raw.get("no_signal"), "draft.no_signal")
    response = _string(draft_raw.get("response"), "draft.response", allow_empty=True)
    if not no_signal and not response.strip():
        raise ValueError("draft.response must not be empty unless draft.no_signal is true")

    claims: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(draft_raw.get("claims"), "draft.claims")):
        raw = _mapping(raw_value, f"draft.claims[{index}]")
        claims.append(
            {
                "id": _string(raw.get("id"), f"draft.claims[{index}].id"),
                "text": _string(raw.get("text"), f"draft.claims[{index}].text"),
                "kind": _enum(
                    raw.get("kind"), f"draft.claims[{index}].kind", CLAIM_KINDS
                ),
                "confidence": _unit_interval(
                    raw.get("confidence"), f"draft.claims[{index}].confidence"
                ),
                "requires_current_information": _boolean(
                    raw.get("requires_current_information"),
                    f"draft.claims[{index}].requires_current_information",
                ),
                "evidence_handles": _string_list(
                    raw.get("evidence_handles"),
                    f"draft.claims[{index}].evidence_handles",
                ),
            }
        )
    _require_unique(claims, "id", "claim")

    proposed_actions: list[dict[str, Any]] = []
    for index, raw_value in enumerate(
        _list(draft_raw.get("proposed_actions"), "draft.proposed_actions")
    ):
        raw = _mapping(raw_value, f"draft.proposed_actions[{index}]")
        proposed_actions.append(
            {
                "id": _string(raw.get("id"), f"draft.proposed_actions[{index}].id"),
                "description": _string(
                    raw.get("description"),
                    f"draft.proposed_actions[{index}].description",
                ),
                "reversible": _boolean(
                    raw.get("reversible"),
                    f"draft.proposed_actions[{index}].reversible",
                ),
                "user_authorized": _boolean(
                    raw.get("user_authorized"),
                    f"draft.proposed_actions[{index}].user_authorized",
                ),
                "recovery_plan": _optional_string(
                    raw.get("recovery_plan"),
                    f"draft.proposed_actions[{index}].recovery_plan",
                ),
            }
        )
    _require_unique(proposed_actions, "id", "proposed action")

    sources: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(packet.get("sources"), "sources")):
        raw = _mapping(raw_value, f"sources[{index}]")
        sources.append(
            {
                "handle": _string(raw.get("handle"), f"sources[{index}].handle"),
                "verified": _boolean(raw.get("verified"), f"sources[{index}].verified"),
                "freshness": _enum(
                    raw.get("freshness"),
                    f"sources[{index}].freshness",
                    FRESHNESS_VALUES,
                ),
                "source_kind": _enum(
                    raw.get("source_kind"),
                    f"sources[{index}].source_kind",
                    SOURCE_KINDS,
                ),
                "locator": _string(raw.get("locator"), f"sources[{index}].locator"),
            }
        )
    _require_unique(sources, "handle", "source")

    tool_events: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(packet.get("tool_events"), "tool_events")):
        raw = _mapping(raw_value, f"tool_events[{index}]")
        evidence_eligible = _boolean(
            raw.get("evidence_eligible"), f"tool_events[{index}].evidence_eligible"
        )
        locator = _optional_string(raw.get("locator"), f"tool_events[{index}].locator")
        if evidence_eligible and locator is None:
            raise ValueError(
                f"tool_events[{index}].locator is required when evidence_eligible is true"
            )
        tool_events.append(
            {
                "id": _string(raw.get("id"), f"tool_events[{index}].id"),
                "tool": _string(raw.get("tool"), f"tool_events[{index}].tool"),
                "operation": _string(
                    raw.get("operation"), f"tool_events[{index}].operation"
                ),
                "status": _enum(
                    raw.get("status"), f"tool_events[{index}].status", TOOL_STATUSES
                ),
                "effect": _enum(
                    raw.get("effect"), f"tool_events[{index}].effect", TOOL_EFFECTS
                ),
                "evidence_eligible": evidence_eligible,
                "freshness": _enum(
                    raw.get("freshness"),
                    f"tool_events[{index}].freshness",
                    FRESHNESS_VALUES,
                ),
                "locator": locator,
                "reversible": _boolean(
                    raw.get("reversible"), f"tool_events[{index}].reversible"
                ),
                "user_authorized": _boolean(
                    raw.get("user_authorized"),
                    f"tool_events[{index}].user_authorized",
                ),
                "recovery_plan": _optional_string(
                    raw.get("recovery_plan"),
                    f"tool_events[{index}].recovery_plan",
                ),
            }
        )
    _require_unique(tool_events, "id", "tool event")

    source_handles = {item["handle"] for item in sources}
    event_ids = {item["id"] for item in tool_events}
    overlap = sorted(source_handles & event_ids)
    if overlap:
        raise ValueError(
            "source handles and tool event ids must be globally unique: " + ", ".join(overlap)
        )

    action_ids = {item["id"] for item in proposed_actions}
    successful_write_ids = {
        item["id"]
        for item in tool_events
        if item["effect"] == "write" and item["status"] == "success"
    }
    overlap_actions = sorted(action_ids & successful_write_ids)
    if overlap_actions:
        raise ValueError(
            "proposed action ids and successful write event ids must be unique: "
            + ", ".join(overlap_actions)
        )

    return {
        "schema_version": INPUT_SCHEMA,
        "request": request,
        "draft": {
            "response": response,
            "no_signal": no_signal,
            "intent_alignment": _unit_interval(
                draft_raw.get("intent_alignment"), "draft.intent_alignment"
            ),
            "claims": claims,
            "proposed_actions": proposed_actions,
            "contradictions": _string_list(
                draft_raw.get("contradictions"), "draft.contradictions"
            ),
        },
        "sources": sources,
        "tool_events": tool_events,
    }


def normalize_bundle(packet: dict[str, Any], input_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert a validated conversation bundle into adapter input and a manifest."""
    normalized = validate_bundle(packet)
    request = normalized["request"]
    draft = normalized["draft"]
    sources = normalized["sources"]
    tool_events = normalized["tool_events"]

    evidence: list[dict[str, Any]] = []
    reference_map: dict[str, str] = {}
    warnings: list[str] = []

    for source in sources:
        evidence_id = f"source:{source['handle']}"
        reference_map[source["handle"]] = evidence_id
        evidence.append(
            {
                "id": evidence_id,
                "verified": source["verified"],
                "freshness": source["freshness"],
                "source_kind": source["source_kind"],
                "locator": source["locator"],
            }
        )

    for event in tool_events:
        if event["evidence_eligible"]:
            evidence_id = f"tool:{event['id']}"
            reference_map[event["id"]] = evidence_id
            evidence.append(
                {
                    "id": evidence_id,
                    "verified": event["status"] == "success",
                    "freshness": event["freshness"],
                    "source_kind": "tool",
                    "locator": event["locator"],
                }
            )
            if event["status"] != "success":
                warnings.append(
                    f"tool_event_not_verified:{event['id']}:{event['status']}"
                )

    claims: list[dict[str, Any]] = []
    unresolved_handles: set[str] = set()
    for claim in draft["claims"]:
        refs: list[str] = []
        for handle in claim["evidence_handles"]:
            resolved = reference_map.get(handle)
            if resolved is None:
                unresolved_handles.add(handle)
                refs.append(f"missing:{handle}")
            else:
                refs.append(resolved)
        claims.append(
            {
                "id": claim["id"],
                "text": claim["text"],
                "kind": claim["kind"],
                "confidence": claim["confidence"],
                "requires_current_information": claim[
                    "requires_current_information"
                ],
                "evidence_refs": refs,
            }
        )

    for handle in sorted(unresolved_handles):
        warnings.append(f"unresolved_evidence_handle:{handle}")

    actions: list[dict[str, Any]] = []
    for action in draft["proposed_actions"]:
        actions.append(
            {
                "id": action["id"],
                "description": action["description"],
                "mode": "proposed",
                "reversible": action["reversible"],
                "user_authorized": action["user_authorized"],
                "recovery_plan": action["recovery_plan"],
            }
        )

    ignored_tool_events: list[str] = []
    for event in tool_events:
        if event["effect"] == "write" and event["status"] == "success":
            actions.append(
                {
                    "id": event["id"],
                    "description": f"{event['tool']}:{event['operation']}",
                    "mode": "performed",
                    "reversible": event["reversible"],
                    "user_authorized": event["user_authorized"],
                    "recovery_plan": event["recovery_plan"],
                }
            )
        elif event["effect"] == "write":
            ignored_tool_events.append(event["id"])
            warnings.append(
                f"write_event_not_performed:{event['id']}:{event['status']}"
            )

    adapter_packet = {
        "schema_version": ADAPTER_SCHEMA,
        "request": {
            "id": request["id"],
            "intent": request["text"],
            "high_stakes": request["high_stakes"],
            "requires_current_information": request["requires_current_information"],
        },
        "draft": {
            "response": draft["response"],
            "no_signal": draft["no_signal"],
            "intent_alignment": draft["intent_alignment"],
            "claims": claims,
            "actions": actions,
            "contradictions": draft["contradictions"],
        },
        "evidence": evidence,
    }

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "normalizer_kind": "deterministic_conversation_bundle_normalizer",
        "input_integrity": {"input_sha256": input_sha256},
        "output_integrity": {
            "adapter_packet_canonical_sha256": _canonical_sha256(adapter_packet)
        },
        "counts": {
            "claims": len(claims),
            "sources": len(sources),
            "tool_events": len(tool_events),
            "evidence_items": len(evidence),
            "actions": len(actions),
        },
        "unresolved_evidence_handles": sorted(unresolved_handles),
        "ignored_write_events": sorted(ignored_tool_events),
        "warnings": sorted(set(warnings)),
        "authority": AUTHORITY,
    }
    return adapter_packet, manifest


def build_packet(input_path: Path, output_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    packet = _mapping(json.loads(input_path.read_text()), "conversation bundle")
    adapter_packet, manifest = normalize_bundle(packet, _sha256(input_path))

    output_dir.mkdir(parents=True, exist_ok=True)
    adapter_path = output_dir / "chatgpt-liminal-input.json"
    manifest_path = output_dir / "conversation-normalization.json"
    graph_path = output_dir / "conversation-normalization-graph.md"

    adapter_path.write_text(json.dumps(adapter_packet, indent=2, sort_keys=True) + "\n")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    graph_path.write_text(
        "# ChatGPT conversation normalization v0.2\n\n"
        "```text\n"
        "explicit request + draft + sources + tool events\n"
        "→ schema validation\n"
        "→ source/tool evidence ID resolution\n"
        "→ successful write events become performed actions\n"
        "→ unresolved handles remain missing evidence\n"
        "→ chatgpt-liminal-input-v0.1\n"
        "→ ChatGPT Liminal Adapter decision\n"
        "```\n\n"
        "The normalizer is deterministic and normalization-only. It does not infer "
        "claims from prose, verify source truth, execute tools, approve delivery, or "
        "write model memory.\n"
    )
    return adapter_packet, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        adapter_packet, manifest = build_packet(args.input, args.output_dir)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"conversation normalizer error: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {"adapter_packet": adapter_packet, "normalization": manifest},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
