#!/usr/bin/env python3
"""Deterministically gate a normalized ChatGPT draft against explicit evidence.

The adapter does not generate a replacement answer, infer hidden intent, browse,
execute actions, approve delivery, or modify model weights. It checks a bounded
packet and returns one of: ALLOW, REVISE, VERIFY, or NO_SIGNAL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "chatgpt-liminal-input-v0.1"
OUTPUT_SCHEMA = "chatgpt-liminal-advice-v0.1"
DECISIONS = ("ALLOW", "REVISE", "VERIFY", "NO_SIGNAL")
CLAIM_KINDS = {"fact", "reasoning", "recommendation", "uncertainty"}
FRESHNESS_VALUES = {"current", "stable", "unknown"}
SOURCE_KINDS = {"official", "repository", "tool", "user_provided", "web", "other"}
ACTION_MODES = {"proposed", "performed"}
INTENT_ALIGNMENT_MIN = 0.65
UNSUPPORTED_CONFIDENCE_MAX = 0.90

AUTHORITY = {
    "mode": "advisory_only",
    "ownership": False,
    "approval": False,
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


def _string_list(value: Any, name: str) -> list[str]:
    values = _list(value, name)
    result: list[str] = []
    for index, item in enumerate(values):
        result.append(_string(item, f"{name}[{index}]"))
    return result


def _require_unique_ids(items: list[dict[str, Any]], name: str) -> None:
    seen: set[str] = set()
    for item in items:
        item_id = item["id"]
        if item_id in seen:
            raise ValueError(f"duplicate {name} id: {item_id}")
        seen.add(item_id)


def validate_input(packet: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize the public v0.1 input contract."""
    if packet.get("schema_version") != INPUT_SCHEMA:
        raise ValueError(f"schema_version must be {INPUT_SCHEMA!r}")

    request_raw = _mapping(packet.get("request"), "request")
    request = {
        "id": _string(request_raw.get("id"), "request.id"),
        "intent": _string(request_raw.get("intent"), "request.intent"),
        "high_stakes": _boolean(request_raw.get("high_stakes"), "request.high_stakes"),
        "requires_current_information": _boolean(
            request_raw.get("requires_current_information"),
            "request.requires_current_information",
        ),
    }

    evidence: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(packet.get("evidence"), "evidence")):
        raw = _mapping(raw_value, f"evidence[{index}]")
        freshness = _string(raw.get("freshness"), f"evidence[{index}].freshness")
        if freshness not in FRESHNESS_VALUES:
            raise ValueError(
                f"evidence[{index}].freshness must be one of {sorted(FRESHNESS_VALUES)}"
            )
        source_kind = _string(raw.get("source_kind"), f"evidence[{index}].source_kind")
        if source_kind not in SOURCE_KINDS:
            raise ValueError(
                f"evidence[{index}].source_kind must be one of {sorted(SOURCE_KINDS)}"
            )
        evidence.append(
            {
                "id": _string(raw.get("id"), f"evidence[{index}].id"),
                "verified": _boolean(raw.get("verified"), f"evidence[{index}].verified"),
                "freshness": freshness,
                "source_kind": source_kind,
                "locator": _string(raw.get("locator"), f"evidence[{index}].locator"),
            }
        )
    _require_unique_ids(evidence, "evidence")

    draft_raw = _mapping(packet.get("draft"), "draft")
    no_signal = _boolean(draft_raw.get("no_signal"), "draft.no_signal")
    response = _string(draft_raw.get("response"), "draft.response", allow_empty=True)
    if not no_signal and not response.strip():
        raise ValueError("draft.response must not be empty unless draft.no_signal is true")

    claims: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(draft_raw.get("claims"), "draft.claims")):
        raw = _mapping(raw_value, f"draft.claims[{index}]")
        kind = _string(raw.get("kind"), f"draft.claims[{index}].kind")
        if kind not in CLAIM_KINDS:
            raise ValueError(
                f"draft.claims[{index}].kind must be one of {sorted(CLAIM_KINDS)}"
            )
        refs = _string_list(
            raw.get("evidence_refs"), f"draft.claims[{index}].evidence_refs"
        )
        if len(refs) != len(set(refs)):
            raise ValueError(f"draft.claims[{index}].evidence_refs contains duplicates")
        claims.append(
            {
                "id": _string(raw.get("id"), f"draft.claims[{index}].id"),
                "text": _string(raw.get("text"), f"draft.claims[{index}].text"),
                "kind": kind,
                "confidence": _unit_interval(
                    raw.get("confidence"), f"draft.claims[{index}].confidence"
                ),
                "requires_current_information": _boolean(
                    raw.get("requires_current_information"),
                    f"draft.claims[{index}].requires_current_information",
                ),
                "evidence_refs": refs,
            }
        )
    _require_unique_ids(claims, "claim")

    actions: list[dict[str, Any]] = []
    for index, raw_value in enumerate(_list(draft_raw.get("actions"), "draft.actions")):
        raw = _mapping(raw_value, f"draft.actions[{index}]")
        mode = _string(raw.get("mode"), f"draft.actions[{index}].mode")
        if mode not in ACTION_MODES:
            raise ValueError(
                f"draft.actions[{index}].mode must be one of {sorted(ACTION_MODES)}"
            )
        recovery_raw = raw.get("recovery_plan")
        recovery_plan = None
        if recovery_raw is not None:
            recovery_plan = _string(
                recovery_raw, f"draft.actions[{index}].recovery_plan"
            )
        actions.append(
            {
                "id": _string(raw.get("id"), f"draft.actions[{index}].id"),
                "description": _string(
                    raw.get("description"), f"draft.actions[{index}].description"
                ),
                "mode": mode,
                "reversible": _boolean(
                    raw.get("reversible"), f"draft.actions[{index}].reversible"
                ),
                "user_authorized": _boolean(
                    raw.get("user_authorized"),
                    f"draft.actions[{index}].user_authorized",
                ),
                "recovery_plan": recovery_plan,
            }
        )
    _require_unique_ids(actions, "action")

    contradictions = _string_list(
        draft_raw.get("contradictions"), "draft.contradictions"
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
            "actions": actions,
            "contradictions": contradictions,
        },
        "evidence": evidence,
    }


def _next_step(decision: str) -> dict[str, Any]:
    if decision == "ALLOW":
        return {
            "name": "deliver_with_evidence_packet",
            "requires_external_verification": False,
            "reason": "The normalized draft passed the bounded response checks.",
        }
    if decision == "VERIFY":
        return {
            "name": "verify_missing_or_stale_evidence",
            "requires_external_verification": True,
            "reason": "One or more claims need verified or current evidence before delivery.",
        }
    if decision == "REVISE":
        return {
            "name": "revise_draft_before_delivery",
            "requires_external_verification": False,
            "reason": "The draft conflicts with intent, confidence, or action-boundary rules.",
        }
    return {
        "name": "return_explicit_no_signal",
        "requires_external_verification": False,
        "reason": "The packet intentionally declines to manufacture an unsupported answer.",
    }


def evaluate_packet(packet: dict[str, Any], input_sha256: str) -> dict[str, Any]:
    """Evaluate a validated packet without generating or executing anything."""
    normalized = validate_input(packet)
    request = normalized["request"]
    draft = normalized["draft"]
    evidence_by_id = {item["id"]: item for item in normalized["evidence"]}

    revision_reasons: list[str] = []
    verification_reasons: list[str] = []
    blocked_claims: list[str] = []
    missing_evidence: list[str] = []
    action_findings: list[str] = []

    if draft["intent_alignment"] < INTENT_ALIGNMENT_MIN:
        revision_reasons.append(
            f"intent_alignment_below_{INTENT_ALIGNMENT_MIN:.2f}"
        )

    for contradiction in draft["contradictions"]:
        revision_reasons.append(f"declared_contradiction:{contradiction}")

    if draft["no_signal"]:
        if draft["response"].strip() or draft["claims"] or draft["actions"]:
            revision_reasons.append("no_signal_packet_contains_response_claims_or_actions")
    else:
        if request["high_stakes"] and not draft["claims"]:
            verification_reasons.append("high_stakes_response_has_no_normalized_claims")
        if request["requires_current_information"] and not any(
            claim["kind"] == "fact" for claim in draft["claims"]
        ):
            verification_reasons.append("current_information_request_has_no_fact_claim")

    current_information_verified = True
    for claim in draft["claims"]:
        refs = claim["evidence_refs"]
        resolved = [evidence_by_id[ref] for ref in refs if ref in evidence_by_id]
        missing_refs = [ref for ref in refs if ref not in evidence_by_id]
        verified = [item for item in resolved if item["verified"]]

        requires_evidence = claim["kind"] == "fact" or (
            claim["kind"] == "recommendation" and request["high_stakes"]
        )
        requires_current = claim["requires_current_information"] or (
            request["requires_current_information"] and claim["kind"] == "fact"
        )

        claim_issues: list[str] = []
        if requires_evidence and not refs:
            claim_issues.append("no_evidence_references")
        if missing_refs:
            claim_issues.append("unknown_evidence_references")
            missing_evidence.extend(missing_refs)
        if requires_evidence and refs and not verified:
            claim_issues.append("no_verified_evidence")
        if any(not item["verified"] for item in resolved):
            claim_issues.append("contains_unverified_evidence")
        if requires_current and not any(
            item["verified"] and item["freshness"] == "current"
            for item in resolved
        ):
            claim_issues.append("missing_verified_current_evidence")
            current_information_verified = False

        if (
            claim["kind"] in {"reasoning", "uncertainty"}
            and not verified
            and claim["confidence"] > UNSUPPORTED_CONFIDENCE_MAX
        ):
            revision_reasons.append(
                f"overconfident_unsupported_claim:{claim['id']}"
            )
            blocked_claims.append(claim["id"])

        for issue in claim_issues:
            verification_reasons.append(f"claim:{claim['id']}:{issue}")
            blocked_claims.append(claim["id"])

    action_boundary_respected = True
    for action in draft["actions"]:
        if action["mode"] == "performed" and not action["user_authorized"]:
            finding = f"action:{action['id']}:performed_without_user_authorization"
            revision_reasons.append(finding)
            action_findings.append(finding)
            action_boundary_respected = False
        if (
            action["mode"] == "performed"
            and not action["reversible"]
            and not action["recovery_plan"]
        ):
            finding = f"action:{action['id']}:irreversible_without_recovery_plan"
            revision_reasons.append(finding)
            action_findings.append(finding)
            action_boundary_respected = False
        if (
            action["mode"] == "proposed"
            and request["high_stakes"]
            and not action["reversible"]
            and not action["recovery_plan"]
        ):
            finding = f"action:{action['id']}:high_stakes_proposal_without_recovery_plan"
            revision_reasons.append(finding)
            action_findings.append(finding)
            action_boundary_respected = False

    if revision_reasons:
        decision = "REVISE"
        reasons = revision_reasons + verification_reasons
    elif verification_reasons:
        decision = "VERIFY"
        reasons = verification_reasons
    elif draft["no_signal"]:
        decision = "NO_SIGNAL"
        reasons = ["explicit_no_signal_without_claims_or_actions"]
    else:
        decision = "ALLOW"
        reasons = ["bounded_response_contract_satisfied"]

    assert decision in DECISIONS
    blocked_claims = sorted(set(blocked_claims))
    missing_evidence = sorted(set(missing_evidence))

    return {
        "schema_version": OUTPUT_SCHEMA,
        "adapter_kind": "deterministic_chatgpt_response_gate",
        "decision": decision,
        "request_id": request["id"],
        "input_integrity": {"input_sha256": input_sha256},
        "checks": {
            "intent_aligned": draft["intent_alignment"] >= INTENT_ALIGNMENT_MIN,
            "contradictions_absent": not draft["contradictions"],
            "claim_evidence_complete": not verification_reasons,
            "current_information_verified": current_information_verified,
            "action_boundary_respected": action_boundary_respected,
            "explicit_no_signal": draft["no_signal"],
        },
        "counts": {
            "claims": len(draft["claims"]),
            "evidence": len(normalized["evidence"]),
            "actions": len(draft["actions"]),
        },
        "reasons": reasons,
        "blocked_claims": blocked_claims,
        "missing_evidence": missing_evidence,
        "action_findings": action_findings,
        "next_step": _next_step(decision),
        "authority": AUTHORITY,
    }


def build_packet(input_path: Path, output_dir: Path) -> dict[str, Any]:
    raw = _mapping(json.loads(input_path.read_text()), "input")
    packet = evaluate_packet(raw, _sha256(input_path))

    output_dir.mkdir(parents=True, exist_ok=True)
    advice_path = output_dir / "chatgpt-liminal-advice.json"
    next_path = output_dir / "chatgpt-liminal-next-step.json"
    graph_path = output_dir / "chatgpt-liminal-causal-graph.md"

    advice_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    next_path.write_text(json.dumps(packet["next_step"], indent=2, sort_keys=True) + "\n")
    graph_path.write_text(
        "\n".join(
            [
                "# ChatGPT Liminal Adapter v0.1",
                "",
                "```text",
                "normalized user request",
                "→ normalized draft claims and actions",
                "→ evidence reference and freshness checks",
                "→ intent / contradiction / action-boundary checks",
                f"→ decision: {packet['decision']}",
                f"→ next step: {packet['next_step']['name']}",
                "→ human/tool authority remains external",
                "```",
                "",
                "This adapter is deterministic and advisory-only. It does not browse, execute, approve, deliver, deploy, merge, or modify model weights.",
            ]
        )
        + "\n"
    )
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        packet = build_packet(args.input, args.output_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"chatgpt_liminal_adapter: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(packet, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
