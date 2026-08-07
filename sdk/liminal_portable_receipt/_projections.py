"""Evidence-only projections from Portable Action Receipt v1.2."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ._contracts import (
    AUTHORITY,
    PortableActionReceipt,
    ReceiptError,
    canonical_sha256,
)

PROOFPATH_SCHEMA = "org.proofpath.authorization-record.v0.1"
PROOFPATH_PROFILE = "org.proofpath.authorization-export.v0.1"
PROOFPATH_ACTION_PROFILE = "org.liminal.trustworthy-transition.action-identity.v0.1"
PROOFPATH_BINDING_PROFILE = "org.liminal.trustworthy-transition.binding.v0.1"
CML_SCHEMA = "cml-memory-pack-v1"
LIMINALDB_PROFILE = "org.liminaldb.trustworthy-transition-ledger.v0.1"
RINSE_SUPERSESSION_SCHEMA = "liminal-rinse-supersession-fixture-v1.2"


def _receipt(value: PortableActionReceipt | Mapping[str, Any]) -> PortableActionReceipt:
    return value if isinstance(value, PortableActionReceipt) else PortableActionReceipt.from_document(dict(value))


def _sha_ref(value: str) -> str:
    return f"sha256:{value}"


def _rfc3339(unix_seconds: int, *, milliseconds: bool = False) -> str:
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    if milliseconds:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def project_proofpath_authorization_records(
    receipt: PortableActionReceipt | Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Project original write authorizations without turning outcome into authority."""
    value = _receipt(receipt)
    claims = value.claims
    result: list[dict[str, Any]] = []
    for action in claims.actions:
        if action.effect != "write":
            continue
        if not action.authorization_event_ids:
            raise ReceiptError("cannot project a write without explicit authorization evidence")
        action_identity = canonical_sha256(
            {
                "transaction_id": claims.transaction_id,
                "step_id": action.step_id,
                "call_id": action.call_id,
                "action": action.action,
                "request_sha256": action.request_sha256,
            }
        )
        binding = canonical_sha256(
            {
                "repository_full_name": claims.repository_full_name,
                "plan_sha256": claims.plan_sha256,
                "policy_sha256": claims.policy_sha256,
                "approval_ledger_head_sha256": claims.approval_ledger_head_sha256,
                "action_evidence_sha256": action.evidence_sha256,
            }
        )
        evidence_refs = sorted(
            {
                _sha_ref(value.receipt_sha256),
                _sha_ref(claims.governance_capsule_sha256),
                _sha_ref(claims.identity_bundle_sha256),
                _sha_ref(action.evidence_sha256),
                *(_sha_ref(item) for item in action.authorization_event_sha256s),
            }
        )
        result.append(
            {
                "schema": PROOFPATH_SCHEMA,
                "profile": PROOFPATH_PROFILE,
                "transition_id": f"{claims.transaction_id}:{action.step_id}",
                "subject_id": claims.subject_id,
                "action_identity_profile": PROOFPATH_ACTION_PROFILE,
                "action_identity_digest": _sha_ref(action_identity),
                "binding_profile": PROOFPATH_BINDING_PROFILE,
                "binding_digest": _sha_ref(binding),
                "decision": "ACCEPT",
                "reason_codes": [
                    "policy_allow",
                    "approval_ready",
                    "explicit_write_authorization",
                ],
                "issued_at": _rfc3339(claims.issued_at_unix),
                "expires_at": None,
                "consumption_state": "CONSUMED",
                "continuation_state": "RESOLVED",
                "current_state": "CONSUMED",
                "policy_ref": _sha_ref(claims.policy_sha256),
                "proofpath_evidence_refs": evidence_refs,
                "claim_boundary": (
                    "Pre-execution authorization projection only. CONSUMED means the "
                    "recorded authorization was used by the observed transaction; this "
                    "record does not itself prove execution and grants no fresh authority."
                ),
            }
        )
    return result


def _cml_pack_id(document: Mapping[str, Any]) -> str:
    value = dict(document)
    value.pop("pack_id", None)
    graph = dict(value["graph"])
    graph["nodes"] = sorted(graph["nodes"], key=lambda item: item["id"])
    graph["edges"] = sorted(graph["edges"], key=lambda item: item["id"])
    value["graph"] = graph
    value["evidence"] = sorted(value["evidence"], key=lambda item: item["id"])
    value["redactions"] = sorted(value["redactions"], key=lambda item: (item["path"], item["reason"]))
    return canonical_sha256(value)


def project_cml_memory_pack(
    receipt: PortableActionReceipt | Mapping[str, Any],
    *,
    source_commit: str | None = None,
    visibility: str = "partner",
) -> dict[str, Any]:
    """Create a bounded CML Memory Pack v1 advisory projection."""
    value = _receipt(receipt)
    claims = value.claims
    commit = source_commit or claims.source_head_oid
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ReceiptError("CML projection requires an exact lowercase 40-character Git source commit")
    if visibility not in {"private", "team", "partner", "public"}:
        raise ReceiptError("CML visibility is invalid")
    situation_id = f"situation:{claims.receipt_id}"
    action_id = f"action:{claims.transaction_id}"
    outcome_id = f"outcome:{claims.transaction_id}"
    evidence_id = "receipt-evidence"
    outcome_status = "verified" if claims.terminal_status == "completed" else "failed"
    document = {
        "schema_version": CML_SCHEMA,
        "pack_id": "",
        "manifest": {
            "project": "LiminalOSAI",
            "source_repository": claims.repository_full_name,
            "source_commit": commit,
            "created_at": _rfc3339(claims.issued_at_unix, milliseconds=True),
            "visibility": visibility,
            "license": "CC0-1.0",
            "contains_private_data": False,
            "merge_authority": False,
            "execution_authority": False,
            "description": "Advisory causal-memory projection of a verified portable action receipt.",
        },
        "graph": {
            "nodes": [
                {
                    "id": situation_id,
                    "kind": "situation",
                    "label": "Identity-bound governed transaction was requested",
                    "status": "observed",
                    "confidence": 100,
                    "attributes": {
                        "receipt_sha256": value.receipt_sha256,
                        "intent_sha256": claims.intent_sha256,
                        "policy_sha256": claims.policy_sha256,
                    },
                },
                {
                    "id": action_id,
                    "kind": "action",
                    "label": "Bounded GitHub transaction executed under recorded authority",
                    "status": "tested" if claims.terminal_status == "completed" else "failed",
                    "confidence": 100,
                    "attributes": {
                        "actions_root_sha256": claims.actions_root_sha256,
                        "transaction_journal_final_sha256": claims.transaction_journal_final_sha256,
                        "authority_effect": "none",
                    },
                },
                {
                    "id": outcome_id,
                    "kind": "outcome",
                    "label": f"Transaction reached terminal state {claims.terminal_status}",
                    "status": outcome_status,
                    "confidence": 100,
                    "attributes": {
                        "terminal_status": claims.terminal_status,
                        "ci_exact_head_verified": claims.ci_gate.exact_head_verified,
                        "fresh_authorization": False,
                    },
                },
            ],
            "edges": [
                {
                    "id": "edge:situation-action",
                    "source": situation_id,
                    "target": action_id,
                    "relation": "leads_to",
                    "strength": 100,
                    "evidence_ids": [evidence_id],
                },
                {
                    "id": "edge:action-outcome",
                    "source": action_id,
                    "target": outcome_id,
                    "relation": "leads_to",
                    "strength": 100,
                    "evidence_ids": [evidence_id],
                },
            ],
            "selected_path": [situation_id, action_id, outcome_id],
        },
        "evidence": [
            {
                "id": evidence_id,
                "kind": "document",
                "digest": value.receipt_sha256,
                "locator": _sha_ref(value.receipt_sha256),
                "description": "Portable Action Receipt v1.2 root; verify independently before relying on it.",
            }
        ],
        "redactions": [
            {"path": "raw_user_intent", "reason": "Only intent SHA-256 is exported."},
            {"path": "raw_tool_arguments", "reason": "Only argument digests and safe bindings are exported."},
            {"path": "raw_connector_responses", "reason": "Only response and normalized payload digests are exported."},
        ],
    }
    document["pack_id"] = _cml_pack_id(document)
    return document


def _execution_state(actions: Iterable[Any]) -> str:
    actions = tuple(actions)
    if any(item.runtime_status == "failure" for item in actions):
        return "OBSERVED_ERRORED"
    if any(item.runtime_status == "cancelled" for item in actions):
        return "OBSERVED_BLOCKED"
    if actions:
        return "OBSERVED_EXECUTED"
    return "NOT_OBSERVED"


def project_liminaldb_event_inputs(
    receipt: PortableActionReceipt | Mapping[str, Any],
) -> dict[str, Any]:
    """Project the receipt into LiminalDB Trustworthy-Transition v0.1 inputs."""
    value = _receipt(receipt)
    claims = value.claims
    transition_id = claims.transaction_id
    subject_id = claims.subject_id
    proofpath = project_proofpath_authorization_records(value)
    authorization_ref = _sha_ref(
        canonical_sha256(
            {
                "policy_sha256": claims.policy_sha256,
                "approval_ledger_head_sha256": claims.approval_ledger_head_sha256,
                "identity_bundle_sha256": claims.identity_bundle_sha256,
                "proofpath_records": proofpath,
            }
        )
    )
    captured_at_ms = claims.issued_at_unix * 1000
    empty_links = {
        "authorization_ref": None,
        "observation_refs": [],
        "response_integrity_ref": None,
        "causal_audit_ref": None,
        "previous_continuity_ref": None,
    }
    events: list[dict[str, Any]] = [
        {
            "transition_id": transition_id,
            "subject_id": subject_id,
            "kind": "authorization",
            "record_ref": authorization_ref,
            "payload_digest": _sha_ref(canonical_sha256(proofpath)),
            "links": empty_links,
            "dimensions": {
                "authority": "VALID",
                "execution": "NOT_OBSERVED",
                "response_integrity": "NOT_EVALUATED",
                "causal_validity": "NOT_EVALUATED",
                "continuity_posture": "NOT_EVALUATED",
            },
            "side_effect_committed": None,
            "captured_at_ms": captured_at_ms,
        }
    ]
    observation_refs: list[str] = []
    for index, action in enumerate(claims.actions, start=1):
        record_ref = _sha_ref(action.evidence_sha256)
        observation_refs.append(record_ref)
        execution = (
            "OBSERVED_EXECUTED"
            if action.runtime_status == "success"
            else "OBSERVED_BLOCKED"
            if action.runtime_status == "cancelled"
            else "OBSERVED_ERRORED"
        )
        events.append(
            {
                "transition_id": transition_id,
                "subject_id": subject_id,
                "kind": "observation",
                "record_ref": record_ref,
                "payload_digest": _sha_ref(action.evidence_sha256),
                "links": {
                    "authorization_ref": authorization_ref,
                    "observation_refs": [],
                    "response_integrity_ref": None,
                    "causal_audit_ref": None,
                    "previous_continuity_ref": None,
                },
                "dimensions": {
                    "authority": "CONSUMED" if action.effect == "write" else "VALID",
                    "execution": execution,
                    "response_integrity": "NOT_EVALUATED",
                    "causal_validity": "NOT_EVALUATED",
                    "continuity_posture": "REPORT_ONLY",
                },
                "side_effect_committed": action.effect == "write" and action.runtime_status == "success",
                "captured_at_ms": captured_at_ms + index,
            }
        )
    response_ref = _sha_ref(
        canonical_sha256(
            {
                "receipt_sha256": value.receipt_sha256,
                "payload_sha256": value.payload_sha256,
                "actions_root_sha256": claims.actions_root_sha256,
            }
        )
    )
    execution = _execution_state(claims.actions)
    events.append(
        {
            "transition_id": transition_id,
            "subject_id": subject_id,
            "kind": "response_integrity",
            "record_ref": response_ref,
            "payload_digest": _sha_ref(value.payload_sha256),
            "links": {
                "authorization_ref": authorization_ref,
                "observation_refs": sorted(observation_refs),
                "response_integrity_ref": None,
                "causal_audit_ref": None,
                "previous_continuity_ref": None,
            },
            "dimensions": {
                "authority": "CONSUMED" if any(item.effect == "write" for item in claims.actions) else "VALID",
                "execution": execution,
                "response_integrity": "VERIFIED",
                "causal_validity": "NOT_EVALUATED",
                "continuity_posture": "REPORT_ONLY",
            },
            "side_effect_committed": any(item.effect == "write" and item.runtime_status == "success" for item in claims.actions),
            "captured_at_ms": captured_at_ms + len(claims.actions) + 1,
        }
    )
    continuity_ref = _sha_ref(
        canonical_sha256(
            {
                "authorization_ref": authorization_ref,
                "observation_refs": sorted(observation_refs),
                "response_integrity_ref": response_ref,
                "receipt_sha256": value.receipt_sha256,
            }
        )
    )
    events.append(
        {
            "transition_id": transition_id,
            "subject_id": subject_id,
            "kind": "continuity_snapshot",
            "record_ref": continuity_ref,
            "payload_digest": _sha_ref(claims.final_engine_evidence_sha256),
            "links": {
                "authorization_ref": authorization_ref,
                "observation_refs": sorted(observation_refs),
                "response_integrity_ref": response_ref,
                "causal_audit_ref": None,
                "previous_continuity_ref": None,
            },
            "dimensions": {
                "authority": "CONSUMED" if any(item.effect == "write" for item in claims.actions) else "VALID",
                "execution": execution,
                "response_integrity": "VERIFIED",
                "causal_validity": "NOT_EVALUATED",
                "continuity_posture": "REPORT_ONLY",
            },
            "side_effect_committed": any(item.effect == "write" and item.runtime_status == "success" for item in claims.actions),
            "captured_at_ms": captured_at_ms + len(claims.actions) + 2,
        }
    )
    return {
        "profile": LIMINALDB_PROFILE,
        "source_receipt_sha256": value.receipt_sha256,
        "event_inputs": events,
        "projection_boundary": {
            "durability_only": True,
            "authority_effect": "none",
            "reinterpretation": False,
        },
    }


def project_rinse_trace_event(
    receipt: PortableActionReceipt | Mapping[str, Any],
) -> dict[str, Any]:
    """Create a minimal immutable RINSE source trace without raw payloads."""
    value = _receipt(receipt)
    claims = value.claims
    return {
        "id": f"receipt:{value.receipt_sha256}",
        "ts": _rfc3339(claims.issued_at_unix),
        "actor": "system",
        "kind": "observation",
        "text": (
            f"Portable action receipt {value.receipt_sha256[:16]} records transaction "
            f"{claims.transaction_id} in terminal state {claims.terminal_status}. "
            "Interpretation remains advisory and grants no authority."
        ),
        "context": {
            "receipt_sha256": value.receipt_sha256,
            "intent_sha256": claims.intent_sha256,
            "actions_root_sha256": claims.actions_root_sha256,
            "final_engine_evidence_sha256": claims.final_engine_evidence_sha256,
            "source_receipt_immutable": True,
            "authority_effect": "none",
        },
    }


def build_rinse_supersession_fixture(
    receipt: PortableActionReceipt | Mapping[str, Any],
) -> dict[str, Any]:
    """Demonstrate reversible interpretation while preserving the receipt root."""
    value = _receipt(receipt)
    trace = project_rinse_trace_event(value)
    trace_id = trace["id"]
    produced = _rfc3339(value.claims.issued_at_unix)
    later = _rfc3339(value.claims.issued_at_unix + 1)
    interpretations = [
        {
            "id": f"rinse-{value.receipt_sha256[:16]}-v1",
            "source_trace_ids": [trace_id],
            "emotions": [],
            "signals": ["portable_action_receipt", f"terminal_{value.claims.terminal_status}"],
            "causal_links": [],
            "insight": "Initial interpretation: independently verify the receipt before using it as operational evidence.",
            "clarity": 1.0,
            "next_step": "Review trust stores and receipt verification output.",
            "produced_at": produced,
        },
        {
            "id": f"rinse-{value.receipt_sha256[:16]}-v2",
            "source_trace_ids": [trace_id],
            "emotions": [],
            "signals": ["portable_action_receipt", "superseding_interpretation"],
            "causal_links": [],
            "insight": "Superseding interpretation: operational meaning may change after review, but the source receipt remains immutable.",
            "clarity": 1.0,
            "next_step": "Use the later interpretation only as advisory context; never as authorization.",
            "produced_at": later,
        },
    ]
    return {
        "schema_version": RINSE_SUPERSESSION_SCHEMA,
        "source_receipt_sha256": value.receipt_sha256,
        "source_trace": trace,
        "interpretations": interpretations,
        "supersession": {
            "superseded_interpretation_id": interpretations[0]["id"],
            "current_interpretation_id": interpretations[1]["id"],
            "source_receipt_preserved": True,
            "authority_effect": "none",
        },
        "authority": AUTHORITY,
    }
