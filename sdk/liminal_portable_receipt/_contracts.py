"""Strict contracts for Portable Action Receipt v1.2."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

RECEIPT_SCHEMA = "liminal-portable-action-receipt-v1.2"
VERIFICATION_SCHEMA = "liminal-portable-action-receipt-verification-v1.2"
ALGORITHM = "ed25519-openssl-v1"
DOMAIN_SEPARATOR = b"LIMINAL-PORTABLE-ACTION-RECEIPT-V1.2\x00"
REDACTION_PROFILE = "liminal-digest-only-redaction-v1.2"
ZERO_SHA256 = "0" * 64

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40,64}$")
IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

SAFE_BINDING_KEYS = frozenset(
    {
        "repository_full_name",
        "repo_full_name",
        "commit_sha",
        "expected_head_sha",
        "branch_name",
        "base_ref",
        "base",
        "head",
        "pr_number",
        "path",
        "ref",
    }
)
SAFE_EXPECTATION_KEYS = frozenset({"state", "status", "merged"})
TERMINAL_STATUSES = frozenset({"completed", "halted", "aborted"})
RUNTIME_STATUSES = frozenset({"success", "failure", "cancelled"})

AUTHORITY = {
    "mode": "portable_observation_only",
    "fresh_authorization": False,
    "replay_authorization": False,
    "automatic_write_authorization": False,
    "execution_authority": False,
    "merge_authority": False,
    "deployment_authority": False,
    "rollback_authority": False,
    "delivery_authority": False,
    "identity_inference": False,
    "claim_inference": False,
    "memory_authority": False,
    "persistence_authority": False,
    "interpretation_authority": False,
}


class ReceiptError(ValueError):
    """Raised when portable receipt evidence violates the v1.2 contract."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ReceiptError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{name} must be a JSON object")
    return dict(value)


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReceiptError(f"{name} must be a JSON array")
    return list(value)


def exact_keys(raw: Mapping[str, Any], required: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required)
    if missing:
        raise ReceiptError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise ReceiptError(f"{name} contains unsupported keys: {', '.join(extra)}")


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ReceiptError(f"{name} must be a non-empty trimmed string")
    if "\x00" in value:
        raise ReceiptError(f"{name} must not contain NUL")
    return value


def identifier(value: Any, name: str) -> str:
    item = string(value, name)
    if not IDENT_RE.fullmatch(item):
        raise ReceiptError(f"{name} contains unsupported characters")
    return item


def repository(value: Any, name: str) -> str:
    item = string(value, name)
    if not REPO_RE.fullmatch(item):
        raise ReceiptError(f"{name} must use owner/name form")
    return item


def sha256(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not SHA256_RE.fullmatch(item):
        raise ReceiptError(f"{name} must be a lowercase 64-character SHA-256")
    return item


def optional_sha256(value: Any, name: str) -> str | None:
    return None if value is None else sha256(value, name)


def git_oid(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not GIT_OID_RE.fullmatch(item):
        raise ReceiptError(f"{name} must be a lowercase 40-64 character Git object id")
    return item


def unix_time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReceiptError(f"{name} must be a non-negative integer Unix timestamp")
    return value


def boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ReceiptError(f"{name} must be a boolean")
    return value


def normalized_identifiers(value: Any, name: str) -> tuple[str, ...]:
    items = tuple(identifier(item, f"{name}[{index}]") for index, item in enumerate(array(value, name)))
    if len(items) != len(set(items)):
        raise ReceiptError(f"{name} contains duplicates")
    return tuple(sorted(items))


def safe_scalar(value: Any, name: str) -> Any:
    if value is None or type(value) is bool or isinstance(value, int):
        return value
    if isinstance(value, str):
        item = string(value, name)
        if len(item.encode("utf-8")) > 1024:
            raise ReceiptError(f"{name} exceeds 1024 UTF-8 bytes")
        return item
    raise ReceiptError(f"{name} must be a safe scalar")


def safe_map(value: Any, name: str, allowed: frozenset[str]) -> dict[str, Any]:
    raw = mapping(value, name)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ReceiptError(f"{name} contains unsafe keys: {', '.join(unknown)}")
    return {key: safe_scalar(raw[key], f"{name}.{key}") for key in sorted(raw)}


@dataclass(frozen=True)
class ActionEvidence:
    step_id: str
    call_id: str
    action: str
    effect: str
    request_sha256: str
    resolved_arguments_sha256: str
    runtime_status: str
    locator_sha256: str | None
    connected_receipt_sha256: str | None
    raw_response_sha256: str | None
    normalized_payload_sha256: str | None
    authorization_event_ids: tuple[str, ...]
    authorization_event_sha256s: tuple[str, ...]
    recorder_event_id: str | None
    recorder_head_sha256: str | None
    host_trace_head_sha256: str | None
    expectations_met: bool
    reconciled: bool
    safe_bindings: Mapping[str, Any]
    safe_expectations: Mapping[str, Any]
    evidence_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "call_id": self.call_id,
            "action": self.action,
            "effect": self.effect,
            "request_sha256": self.request_sha256,
            "resolved_arguments_sha256": self.resolved_arguments_sha256,
            "runtime_status": self.runtime_status,
            "locator_sha256": self.locator_sha256,
            "connected_receipt_sha256": self.connected_receipt_sha256,
            "raw_response_sha256": self.raw_response_sha256,
            "normalized_payload_sha256": self.normalized_payload_sha256,
            "authorization_event_ids": list(self.authorization_event_ids),
            "authorization_event_sha256s": list(self.authorization_event_sha256s),
            "recorder_event_id": self.recorder_event_id,
            "recorder_head_sha256": self.recorder_head_sha256,
            "host_trace_head_sha256": self.host_trace_head_sha256,
            "expectations_met": self.expectations_met,
            "reconciled": self.reconciled,
            "safe_bindings": dict(self.safe_bindings),
            "safe_expectations": dict(self.safe_expectations),
        }

    def payload(self) -> dict[str, Any]:
        return {**self.body(), "evidence_sha256": self.evidence_sha256}

    @classmethod
    def build(cls, **kwargs: Any) -> "ActionEvidence":
        body = {**kwargs}
        body["evidence_sha256"] = canonical_sha256(body)
        return cls.from_value(body)

    @classmethod
    def from_value(cls, value: Any) -> "ActionEvidence":
        raw = mapping(value, "action_evidence")
        required = {
            "step_id", "call_id", "action", "effect", "request_sha256",
            "resolved_arguments_sha256", "runtime_status", "locator_sha256",
            "connected_receipt_sha256", "raw_response_sha256",
            "normalized_payload_sha256", "authorization_event_ids",
            "authorization_event_sha256s", "recorder_event_id",
            "recorder_head_sha256", "host_trace_head_sha256",
            "expectations_met", "reconciled", "safe_bindings",
            "safe_expectations", "evidence_sha256",
        }
        exact_keys(raw, required, "action_evidence")
        effect = string(raw["effect"], "action_evidence.effect")
        if effect not in {"read", "write"}:
            raise ReceiptError("action_evidence.effect must be read or write")
        runtime_status = string(raw["runtime_status"], "action_evidence.runtime_status")
        if runtime_status not in RUNTIME_STATUSES:
            raise ReceiptError("action_evidence.runtime_status is invalid")
        auth_ids = normalized_identifiers(raw["authorization_event_ids"], "action_evidence.authorization_event_ids")
        auth_hashes = tuple(
            sorted(sha256(item, f"action_evidence.authorization_event_sha256s[{index}]") for index, item in enumerate(array(raw["authorization_event_sha256s"], "action_evidence.authorization_event_sha256s")))
        )
        if len(auth_ids) != len(auth_hashes):
            raise ReceiptError("authorization event ids and digests must have equal length")
        if effect == "write" and not auth_ids:
            raise ReceiptError("write action evidence requires explicit authorization evidence")
        recorder_event = raw["recorder_event_id"]
        if recorder_event is not None:
            recorder_event = identifier(recorder_event, "action_evidence.recorder_event_id")
        item = cls(
            step_id=identifier(raw["step_id"], "action_evidence.step_id"),
            call_id=identifier(raw["call_id"], "action_evidence.call_id"),
            action=identifier(raw["action"], "action_evidence.action"),
            effect=effect,
            request_sha256=sha256(raw["request_sha256"], "action_evidence.request_sha256"),
            resolved_arguments_sha256=sha256(raw["resolved_arguments_sha256"], "action_evidence.resolved_arguments_sha256"),
            runtime_status=runtime_status,
            locator_sha256=optional_sha256(raw["locator_sha256"], "action_evidence.locator_sha256"),
            connected_receipt_sha256=optional_sha256(raw["connected_receipt_sha256"], "action_evidence.connected_receipt_sha256"),
            raw_response_sha256=optional_sha256(raw["raw_response_sha256"], "action_evidence.raw_response_sha256"),
            normalized_payload_sha256=optional_sha256(raw["normalized_payload_sha256"], "action_evidence.normalized_payload_sha256"),
            authorization_event_ids=auth_ids,
            authorization_event_sha256s=auth_hashes,
            recorder_event_id=recorder_event,
            recorder_head_sha256=optional_sha256(raw["recorder_head_sha256"], "action_evidence.recorder_head_sha256"),
            host_trace_head_sha256=optional_sha256(raw["host_trace_head_sha256"], "action_evidence.host_trace_head_sha256"),
            expectations_met=boolean(raw["expectations_met"], "action_evidence.expectations_met"),
            reconciled=boolean(raw["reconciled"], "action_evidence.reconciled"),
            safe_bindings=safe_map(raw["safe_bindings"], "action_evidence.safe_bindings", SAFE_BINDING_KEYS),
            safe_expectations=safe_map(raw["safe_expectations"], "action_evidence.safe_expectations", SAFE_EXPECTATION_KEYS),
            evidence_sha256=sha256(raw["evidence_sha256"], "action_evidence.evidence_sha256"),
        )
        if canonical_sha256(item.body()) != item.evidence_sha256:
            raise ReceiptError("action_evidence.evidence_sha256 mismatch")
        return item


@dataclass(frozen=True)
class CIGateEvidence:
    observed: bool
    checked_commit_oid: str | None
    state: str
    merge_expected_head_oid: str | None
    exact_head_verified: bool
    evidence_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "observed": self.observed,
            "checked_commit_oid": self.checked_commit_oid,
            "state": self.state,
            "merge_expected_head_oid": self.merge_expected_head_oid,
            "exact_head_verified": self.exact_head_verified,
        }

    def payload(self) -> dict[str, Any]:
        return {**self.body(), "evidence_sha256": self.evidence_sha256}

    @classmethod
    def build(cls, *, observed: bool, checked_commit_oid: str | None, state: str, merge_expected_head_oid: str | None, exact_head_verified: bool) -> "CIGateEvidence":
        body = {
            "observed": observed,
            "checked_commit_oid": checked_commit_oid,
            "state": state,
            "merge_expected_head_oid": merge_expected_head_oid,
            "exact_head_verified": exact_head_verified,
        }
        return cls.from_value({**body, "evidence_sha256": canonical_sha256(body)})

    @classmethod
    def from_value(cls, value: Any) -> "CIGateEvidence":
        raw = mapping(value, "ci_gate")
        exact_keys(raw, {"observed", "checked_commit_oid", "state", "merge_expected_head_oid", "exact_head_verified", "evidence_sha256"}, "ci_gate")
        observed = boolean(raw["observed"], "ci_gate.observed")
        state = string(raw["state"], "ci_gate.state")
        if state not in {"success", "failure", "pending", "not_observed"}:
            raise ReceiptError("ci_gate.state is invalid")
        checked = None if raw["checked_commit_oid"] is None else git_oid(raw["checked_commit_oid"], "ci_gate.checked_commit_oid")
        merged = None if raw["merge_expected_head_oid"] is None else git_oid(raw["merge_expected_head_oid"], "ci_gate.merge_expected_head_oid")
        exact = boolean(raw["exact_head_verified"], "ci_gate.exact_head_verified")
        if not observed and (state != "not_observed" or checked is not None or merged is not None or exact):
            raise ReceiptError("unobserved ci_gate must contain no positive CI claim")
        if exact and (state != "success" or checked is None or checked != merged):
            raise ReceiptError("exact_head_verified requires a successful check of the exact merge head")
        item = cls(observed, checked, state, merged, exact, sha256(raw["evidence_sha256"], "ci_gate.evidence_sha256"))
        if canonical_sha256(item.body()) != item.evidence_sha256:
            raise ReceiptError("ci_gate.evidence_sha256 mismatch")
        return item


@dataclass(frozen=True)
class RecoveryEvidence:
    status: str
    completed_step_ids: tuple[str, ...]
    pending_step_ids: tuple[str, ...]
    failed_step_ids: tuple[str, ...]
    manual_recovery_required: bool
    automatic_rollback: bool
    automatic_pending_write_replay: bool
    report_sha256: str
    evidence_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "completed_step_ids": list(self.completed_step_ids),
            "pending_step_ids": list(self.pending_step_ids),
            "failed_step_ids": list(self.failed_step_ids),
            "manual_recovery_required": self.manual_recovery_required,
            "automatic_rollback": self.automatic_rollback,
            "automatic_pending_write_replay": self.automatic_pending_write_replay,
            "report_sha256": self.report_sha256,
        }

    def payload(self) -> dict[str, Any]:
        return {**self.body(), "evidence_sha256": self.evidence_sha256}

    @classmethod
    def build(cls, report: Mapping[str, Any]) -> "RecoveryEvidence":
        raw = mapping(dict(report), "recovery_report")
        body = {
            "status": raw.get("status"),
            "completed_step_ids": sorted(str(item.get("step_id")) for item in raw.get("completed_steps", [])),
            "pending_step_ids": sorted(raw.get("pending_step_ids", [])),
            "failed_step_ids": sorted(raw.get("failed_step_ids", [])),
            "manual_recovery_required": raw.get("manual_recovery_required"),
            "automatic_rollback": raw.get("automatic_rollback"),
            "automatic_pending_write_replay": raw.get("automatic_pending_write_replay"),
            "report_sha256": canonical_sha256(raw),
        }
        return cls.from_value({**body, "evidence_sha256": canonical_sha256(body)})

    @classmethod
    def from_value(cls, value: Any) -> "RecoveryEvidence":
        raw = mapping(value, "recovery")
        exact_keys(raw, {"status", "completed_step_ids", "pending_step_ids", "failed_step_ids", "manual_recovery_required", "automatic_rollback", "automatic_pending_write_replay", "report_sha256", "evidence_sha256"}, "recovery")
        status = string(raw["status"], "recovery.status")
        if status not in TERMINAL_STATUSES:
            raise ReceiptError("recovery.status must be terminal")
        item = cls(
            status=status,
            completed_step_ids=normalized_identifiers(raw["completed_step_ids"], "recovery.completed_step_ids"),
            pending_step_ids=normalized_identifiers(raw["pending_step_ids"], "recovery.pending_step_ids"),
            failed_step_ids=normalized_identifiers(raw["failed_step_ids"], "recovery.failed_step_ids"),
            manual_recovery_required=boolean(raw["manual_recovery_required"], "recovery.manual_recovery_required"),
            automatic_rollback=boolean(raw["automatic_rollback"], "recovery.automatic_rollback"),
            automatic_pending_write_replay=boolean(raw["automatic_pending_write_replay"], "recovery.automatic_pending_write_replay"),
            report_sha256=sha256(raw["report_sha256"], "recovery.report_sha256"),
            evidence_sha256=sha256(raw["evidence_sha256"], "recovery.evidence_sha256"),
        )
        if item.automatic_rollback or item.automatic_pending_write_replay:
            raise ReceiptError("portable receipt may not claim automatic recovery authority")
        if canonical_sha256(item.body()) != item.evidence_sha256:
            raise ReceiptError("recovery.evidence_sha256 mismatch")
        return item


@dataclass(frozen=True)
class BoundaryEvidence:
    profile_id: str
    status: str
    root_sha256: str

    def payload(self) -> dict[str, Any]:
        return {"profile_id": self.profile_id, "status": self.status, "root_sha256": self.root_sha256}

    @classmethod
    def pending(cls, profile_id: str) -> "BoundaryEvidence":
        return cls(identifier(profile_id, "boundary.profile_id"), "not_implemented", ZERO_SHA256)

    @classmethod
    def from_value(cls, value: Any, name: str) -> "BoundaryEvidence":
        raw = mapping(value, name)
        exact_keys(raw, {"profile_id", "status", "root_sha256"}, name)
        status = string(raw["status"], f"{name}.status")
        if status not in {"not_implemented", "observed"}:
            raise ReceiptError(f"{name}.status is invalid")
        root = sha256(raw["root_sha256"], f"{name}.root_sha256")
        if status == "not_implemented" and root != ZERO_SHA256:
            raise ReceiptError(f"{name} not_implemented root must be zero")
        if status == "observed" and root == ZERO_SHA256:
            raise ReceiptError(f"{name} observed root must be non-zero")
        return cls(identifier(raw["profile_id"], f"{name}.profile_id"), status, root)


@dataclass(frozen=True)
class ReceiptClaims:
    receipt_id: str
    issuer_id: str
    subject_id: str
    tenant_id: str
    organization_id: str
    roles: tuple[str, ...]
    session_sha256: str
    key_id: str
    algorithm: str
    audience: str
    issued_at_unix: int
    execution_verified_at_unix: int
    intent_id: str
    intent_sha256: str
    transaction_id: str
    repository_full_name: str
    source_head_oid: str
    result_head_oid: str
    policy_id: str
    policy_sha256: str
    snapshot_sha256: str
    plan_sha256: str
    approval_ledger_head_sha256: str
    transaction_journal_anchor_sha256: str
    transaction_journal_final_sha256: str
    capsule_engine_evidence_sha256: str
    final_engine_evidence_sha256: str
    governance_capsule_sha256: str
    identity_assertion_sha256: str
    kms_attestation_sha256: str
    identity_bundle_sha256: str
    identity_verification_sha256: str
    actions: tuple[ActionEvidence, ...]
    actions_root_sha256: str
    ci_gate: CIGateEvidence
    recovery: RecoveryEvidence
    capability: BoundaryEvidence
    containment: BoundaryEvidence
    terminal_status: str

    def payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "organization_id": self.organization_id,
            "roles": list(self.roles),
            "session_sha256": self.session_sha256,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "audience": self.audience,
            "issued_at_unix": self.issued_at_unix,
            "execution_verified_at_unix": self.execution_verified_at_unix,
            "intent_id": self.intent_id,
            "intent_sha256": self.intent_sha256,
            "transaction_id": self.transaction_id,
            "repository_full_name": self.repository_full_name,
            "source_head_oid": self.source_head_oid,
            "result_head_oid": self.result_head_oid,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "plan_sha256": self.plan_sha256,
            "approval_ledger_head_sha256": self.approval_ledger_head_sha256,
            "transaction_journal_anchor_sha256": self.transaction_journal_anchor_sha256,
            "transaction_journal_final_sha256": self.transaction_journal_final_sha256,
            "capsule_engine_evidence_sha256": self.capsule_engine_evidence_sha256,
            "final_engine_evidence_sha256": self.final_engine_evidence_sha256,
            "governance_capsule_sha256": self.governance_capsule_sha256,
            "identity_assertion_sha256": self.identity_assertion_sha256,
            "kms_attestation_sha256": self.kms_attestation_sha256,
            "identity_bundle_sha256": self.identity_bundle_sha256,
            "identity_verification_sha256": self.identity_verification_sha256,
            "actions": [item.payload() for item in self.actions],
            "actions_root_sha256": self.actions_root_sha256,
            "ci_gate": self.ci_gate.payload(),
            "recovery": self.recovery.payload(),
            "capability": self.capability.payload(),
            "containment": self.containment.payload(),
            "terminal_status": self.terminal_status,
            "redaction_profile": REDACTION_PROFILE,
            "authority": AUTHORITY,
        }

    @classmethod
    def from_value(cls, value: Any) -> "ReceiptClaims":
        raw = mapping(value, "receipt.claims")
        required = {
            "receipt_id", "issuer_id", "subject_id", "tenant_id", "organization_id", "roles", "session_sha256",
            "key_id", "algorithm", "audience", "issued_at_unix", "execution_verified_at_unix",
            "intent_id", "intent_sha256", "transaction_id", "repository_full_name", "source_head_oid", "result_head_oid",
            "policy_id", "policy_sha256", "snapshot_sha256", "plan_sha256", "approval_ledger_head_sha256",
            "transaction_journal_anchor_sha256", "transaction_journal_final_sha256", "capsule_engine_evidence_sha256",
            "final_engine_evidence_sha256", "governance_capsule_sha256", "identity_assertion_sha256", "kms_attestation_sha256",
            "identity_bundle_sha256", "identity_verification_sha256", "actions", "actions_root_sha256", "ci_gate", "recovery",
            "capability", "containment", "terminal_status", "redaction_profile", "authority",
        }
        exact_keys(raw, required, "receipt.claims")
        if raw["authority"] != AUTHORITY:
            raise ReceiptError("receipt.claims.authority must remain fixed")
        if raw["redaction_profile"] != REDACTION_PROFILE:
            raise ReceiptError("receipt.claims.redaction_profile mismatch")
        if raw["algorithm"] != ALGORITHM:
            raise ReceiptError(f"receipt.claims.algorithm must be {ALGORITHM}")
        issued = unix_time(raw["issued_at_unix"], "receipt.claims.issued_at_unix")
        verified = unix_time(raw["execution_verified_at_unix"], "receipt.claims.execution_verified_at_unix")
        if verified > issued:
            raise ReceiptError("execution_verified_at_unix must not be after receipt issuance")
        terminal = string(raw["terminal_status"], "receipt.claims.terminal_status")
        if terminal not in TERMINAL_STATUSES:
            raise ReceiptError("receipt terminal_status must be terminal")
        actions = tuple(ActionEvidence.from_value(item) for item in array(raw["actions"], "receipt.claims.actions"))
        if len({item.step_id for item in actions}) != len(actions) or len({item.call_id for item in actions}) != len(actions):
            raise ReceiptError("receipt actions contain duplicate step_id or call_id")
        actions_root = sha256(raw["actions_root_sha256"], "receipt.claims.actions_root_sha256")
        if actions_root != canonical_sha256([item.payload() for item in actions]):
            raise ReceiptError("receipt claims actions_root_sha256 mismatch")
        recovery = RecoveryEvidence.from_value(raw["recovery"])
        if recovery.status != terminal:
            raise ReceiptError("recovery status must match terminal_status")
        item = cls(
            receipt_id=identifier(raw["receipt_id"], "receipt.claims.receipt_id"),
            issuer_id=identifier(raw["issuer_id"], "receipt.claims.issuer_id"),
            subject_id=identifier(raw["subject_id"], "receipt.claims.subject_id"),
            tenant_id=identifier(raw["tenant_id"], "receipt.claims.tenant_id"),
            organization_id=identifier(raw["organization_id"], "receipt.claims.organization_id"),
            roles=normalized_identifiers(raw["roles"], "receipt.claims.roles"),
            session_sha256=sha256(raw["session_sha256"], "receipt.claims.session_sha256"),
            key_id=identifier(raw["key_id"], "receipt.claims.key_id"),
            algorithm=ALGORITHM,
            audience=identifier(raw["audience"], "receipt.claims.audience"),
            issued_at_unix=issued,
            execution_verified_at_unix=verified,
            intent_id=identifier(raw["intent_id"], "receipt.claims.intent_id"),
            intent_sha256=sha256(raw["intent_sha256"], "receipt.claims.intent_sha256"),
            transaction_id=identifier(raw["transaction_id"], "receipt.claims.transaction_id"),
            repository_full_name=repository(raw["repository_full_name"], "receipt.claims.repository_full_name"),
            source_head_oid=git_oid(raw["source_head_oid"], "receipt.claims.source_head_oid"),
            result_head_oid=git_oid(raw["result_head_oid"], "receipt.claims.result_head_oid"),
            policy_id=identifier(raw["policy_id"], "receipt.claims.policy_id"),
            policy_sha256=sha256(raw["policy_sha256"], "receipt.claims.policy_sha256"),
            snapshot_sha256=sha256(raw["snapshot_sha256"], "receipt.claims.snapshot_sha256"),
            plan_sha256=sha256(raw["plan_sha256"], "receipt.claims.plan_sha256"),
            approval_ledger_head_sha256=sha256(raw["approval_ledger_head_sha256"], "receipt.claims.approval_ledger_head_sha256"),
            transaction_journal_anchor_sha256=sha256(raw["transaction_journal_anchor_sha256"], "receipt.claims.transaction_journal_anchor_sha256"),
            transaction_journal_final_sha256=sha256(raw["transaction_journal_final_sha256"], "receipt.claims.transaction_journal_final_sha256"),
            capsule_engine_evidence_sha256=sha256(raw["capsule_engine_evidence_sha256"], "receipt.claims.capsule_engine_evidence_sha256"),
            final_engine_evidence_sha256=sha256(raw["final_engine_evidence_sha256"], "receipt.claims.final_engine_evidence_sha256"),
            governance_capsule_sha256=sha256(raw["governance_capsule_sha256"], "receipt.claims.governance_capsule_sha256"),
            identity_assertion_sha256=sha256(raw["identity_assertion_sha256"], "receipt.claims.identity_assertion_sha256"),
            kms_attestation_sha256=sha256(raw["kms_attestation_sha256"], "receipt.claims.kms_attestation_sha256"),
            identity_bundle_sha256=sha256(raw["identity_bundle_sha256"], "receipt.claims.identity_bundle_sha256"),
            identity_verification_sha256=sha256(raw["identity_verification_sha256"], "receipt.claims.identity_verification_sha256"),
            actions=actions,
            actions_root_sha256=actions_root,
            ci_gate=CIGateEvidence.from_value(raw["ci_gate"]),
            recovery=recovery,
            capability=BoundaryEvidence.from_value(raw["capability"], "receipt.claims.capability"),
            containment=BoundaryEvidence.from_value(raw["containment"], "receipt.claims.containment"),
            terminal_status=terminal,
        )
        if terminal == "completed" and (item.recovery.pending_step_ids or item.recovery.failed_step_ids):
            raise ReceiptError("completed receipt cannot retain pending or failed steps")
        return item


@dataclass(frozen=True)
class PortableActionReceipt:
    claims: ReceiptClaims
    governance_capsule: Mapping[str, Any]
    identity_bundle: Mapping[str, Any]
    payload_sha256: str
    signature_b64url: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": RECEIPT_SCHEMA,
            "claims": self.claims.payload(),
            "governance_capsule": dict(self.governance_capsule),
            "identity_bundle": dict(self.identity_bundle),
        }

    @property
    def signed_message(self) -> bytes:
        return DOMAIN_SEPARATOR + canonical_json(self.unsigned_payload()).encode("utf-8")

    def as_document(self) -> dict[str, Any]:
        return {
            **self.unsigned_payload(),
            "payload_sha256": self.payload_sha256,
            "signature_b64url": self.signature_b64url,
        }

    @property
    def receipt_sha256(self) -> str:
        return canonical_sha256(self.as_document())

    @classmethod
    def from_document(cls, value: Any) -> "PortableActionReceipt":
        raw = mapping(value, "receipt")
        exact_keys(raw, {"schema_version", "claims", "governance_capsule", "identity_bundle", "payload_sha256", "signature_b64url"}, "receipt")
        if raw["schema_version"] != RECEIPT_SCHEMA:
            raise ReceiptError(f"receipt.schema_version must be {RECEIPT_SCHEMA}")
        claims = ReceiptClaims.from_value(raw["claims"])
        capsule = mapping(raw["governance_capsule"], "receipt.governance_capsule")
        bundle = mapping(raw["identity_bundle"], "receipt.identity_bundle")
        item = cls(
            claims=claims,
            governance_capsule=capsule,
            identity_bundle=bundle,
            payload_sha256=sha256(raw["payload_sha256"], "receipt.payload_sha256"),
            signature_b64url=string(raw["signature_b64url"], "receipt.signature_b64url"),
        )
        if not B64URL_RE.fullmatch(item.signature_b64url):
            raise ReceiptError("receipt.signature_b64url is not unpadded base64url")
        if canonical_sha256(item.unsigned_payload()) != item.payload_sha256:
            raise ReceiptError("receipt.payload_sha256 mismatch")
        return item
