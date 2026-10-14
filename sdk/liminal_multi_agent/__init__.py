"""Deterministic multi-agent delegation governance for LiminalOS v1.2.

Grant identities are single admission: replaying an admission cannot reset a
use budget, change a delegation edge, or reactivate revoked authority. Budgets
remain per grant; this reference profile does not pool sibling consumption.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import threading
from typing import Any, Iterable, Mapping

from sdk.liminal_causal_escalation import TrajectoryEvent, analyze_trajectory
from sdk.liminal_post_sandbox_contracts import (
    CAPABILITY_TYPES,
    ContractError,
    canonical_sha256,
    validate_scope,
)

SCHEMA = "liminal-multi-agent-governance-v0.1"
AUTHORITY = {
    "mode": "delegation_governance_only",
    "autonomous_agent_spawn": False,
    "execution": False,
    "credential_access": False,
    "deployment": False,
    "payments": False,
    "automatic_release": False,
}


class MultiAgentError(ValueError):
    pass


def _identifier(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value) > 192
    ):
        raise MultiAgentError(f"{name} must be a non-empty trimmed identifier")
    return value


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise MultiAgentError(f"{name} must be an integer >= {minimum}")
    return value


def _scope(capability_type: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MultiAgentError("scope must be a mapping")
    try:
        # The contract normalizer creates fresh nested lists as well as checking
        # their types. Caller-owned JSON cannot subsequently widen a live grant.
        return validate_scope(capability_type, dict(value))
    except (ContractError, TypeError, ValueError) as exc:
        raise MultiAgentError(str(exc)) from exc


@dataclass(frozen=True)
class Grant:
    capability_id: str
    subject_id: str
    capability_type: str
    scope: Mapping[str, Any]
    issued_at_unix: int
    expires_at_unix: int
    max_uses: int
    parent_capability_id: str | None
    policy_sha256: str
    status: str = "active"
    use_count: int = 0


@dataclass(frozen=True)
class DelegationReceipt:
    parent_capability_id: str
    child_capability_id: str
    parent_subject_id: str
    child_subject_id: str
    policy_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "parent_capability_id": self.parent_capability_id,
            "child_capability_id": self.child_capability_id,
            "parent_subject_id": self.parent_subject_id,
            "child_subject_id": self.child_subject_id,
            "policy_sha256": self.policy_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "authority": dict(AUTHORITY),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class MultiAgentGovernance:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._grants: dict[str, Grant] = {}
        self._children: dict[str, set[str]] = {}
        self._receipts: list[DelegationReceipt] = []

    def admit_root(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        with self._lock:
            _integer(at_unix, "at_unix")
            grant = self._parse(document)
            if grant.parent_capability_id is not None:
                raise MultiAgentError("root capability must not have a parent")
            self._require_new_id(grant.capability_id)
            if not (grant.issued_at_unix <= at_unix < grant.expires_at_unix):
                raise MultiAgentError("root outside validity window")
            self._grants[grant.capability_id] = grant
            self._children[grant.capability_id] = set()
            return {
                "decision": "ALLOW",
                "capability_id": grant.capability_id,
                "reason_codes": ["root_admitted"],
            }

    def delegate(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        with self._lock:
            _integer(at_unix, "at_unix")
            child = self._parse(document)
            if child.parent_capability_id is None:
                raise MultiAgentError("delegated capability requires parent")
            parent = self._grants.get(child.parent_capability_id)
            if parent is None or parent.status != "active":
                raise MultiAgentError("delegation parent is not active")
            if child.capability_id == parent.capability_id:
                raise MultiAgentError("self-delegation is forbidden")
            if child.subject_id == parent.subject_id:
                raise MultiAgentError("delegation must cross subjects")
            self._require_new_id(child.capability_id)
            if child.capability_type != parent.capability_type or child.policy_sha256 != parent.policy_sha256:
                raise MultiAgentError("child authority differs from parent")
            if (
                child.issued_at_unix < parent.issued_at_unix
                or child.expires_at_unix > parent.expires_at_unix
                or child.max_uses > parent.max_uses
            ):
                raise MultiAgentError("child validity or use bounds exceed parent")
            if not _scope_contains(parent.scope, child.scope):
                raise MultiAgentError("child scope exceeds parent")
            if not (parent.issued_at_unix <= at_unix < parent.expires_at_unix):
                raise MultiAgentError("parent outside validity window")
            if not (child.issued_at_unix <= at_unix < child.expires_at_unix):
                raise MultiAgentError("child outside validity window")

            # An unseen ID attached to one existing parent cannot form a cycle.
            self._grants[child.capability_id] = child
            self._children[parent.capability_id].add(child.capability_id)
            self._children[child.capability_id] = set()
            provisional = DelegationReceipt(
                parent.capability_id,
                child.capability_id,
                parent.subject_id,
                child.subject_id,
                child.policy_sha256,
                "ALLOW",
                ("monotonic_narrowing", "delegation_admitted"),
                "",
            )
            receipt = replace(provisional, receipt_sha256=canonical_sha256(provisional.body()))
            self._receipts.append(receipt)
            return receipt.as_document()

    def authorize(
        self, *, subject_id: str, capability_id: str,
        requested_scope: Mapping[str, Any], at_unix: int,
    ) -> dict[str, Any]:
        with self._lock:
            _integer(at_unix, "at_unix")
            _identifier(subject_id, "subject_id")
            _identifier(capability_id, "capability_id")
            grant = self._grants.get(capability_id)
            blocked = {"decision": "BLOCK", "reason_codes": ["default_deny"]}
            if (
                grant is None
                or grant.status != "active"
                or grant.subject_id != subject_id
                or not (grant.issued_at_unix <= at_unix < grant.expires_at_unix)
                or grant.use_count >= grant.max_uses
            ):
                return blocked
            try:
                scope = _scope(grant.capability_type, requested_scope)
            except MultiAgentError:
                return blocked
            if not _scope_contains(grant.scope, scope):
                return blocked
            self._grants[capability_id] = replace(grant, use_count=grant.use_count + 1)
            return {"decision": "ALLOW", "reason_codes": ["delegated_scope_match"]}

    def revoke_tree(self, capability_id: str, *, at_unix: int) -> tuple[dict[str, Any], ...]:
        with self._lock:
            _integer(at_unix, "at_unix")
            _identifier(capability_id, "capability_id")
            if capability_id not in self._grants:
                raise MultiAgentError("unknown capability")
            receipts = []
            for current_id in reversed(self._descendants(capability_id)):
                self._grants[current_id] = replace(self._grants[current_id], status="revoked")
                receipts.append({
                    "capability_id": current_id,
                    "decision": "ALLOW",
                    "reason_codes": ["ancestor_revoke"],
                })
            return tuple(receipts)

    def analyze_collective(self, events: Iterable[TrajectoryEvent]) -> dict[str, Any]:
        ordered = tuple(events)
        subjects = tuple(sorted({event.subject_id for event in ordered}))
        if len(subjects) < 2:
            raise MultiAgentError("collective analysis requires at least two subjects")
        body = {
            "schema": "liminal-multi-agent-collective-decision-v0.1",
            "subjects": list(subjects),
            "event_count": len(ordered),
            "phase3": analyze_trajectory(ordered),
            "authority": dict(AUTHORITY),
        }
        return {**body, "receipt_sha256": canonical_sha256(body)}

    @staticmethod
    def _parse(document: Mapping[str, Any]) -> Grant:
        required = {
            "capability_id", "subject_id", "capability_type", "scope",
            "issued_at_unix", "expires_at_unix", "max_uses",
            "parent_capability_id", "policy_sha256",
        }
        if not isinstance(document, Mapping) or set(document) != required:
            raise MultiAgentError("grant schema mismatch")
        capability_type = document["capability_type"]
        if not isinstance(capability_type, str) or capability_type not in CAPABILITY_TYPES:
            raise MultiAgentError("unsupported capability_type")
        issued = _integer(document["issued_at_unix"], "issued_at_unix")
        expires = _integer(document["expires_at_unix"], "expires_at_unix")
        if issued >= expires:
            raise MultiAgentError("grant validity window is invalid")
        parent = document["parent_capability_id"]
        if parent is not None:
            parent = _identifier(parent, "parent_capability_id")
        policy = document["policy_sha256"]
        if not isinstance(policy, str) or len(policy) != 64 or any(ch not in "0123456789abcdef" for ch in policy):
            raise MultiAgentError("policy_sha256 must be a lowercase SHA-256 digest")
        return Grant(
            capability_id=_identifier(document["capability_id"], "capability_id"),
            subject_id=_identifier(document["subject_id"], "subject_id"),
            capability_type=capability_type,
            scope=_scope(capability_type, document["scope"]),
            issued_at_unix=issued,
            expires_at_unix=expires,
            max_uses=_integer(document["max_uses"], "max_uses", minimum=1),
            parent_capability_id=parent,
            policy_sha256=policy,
        )

    def _require_new_id(self, capability_id: str) -> None:
        if capability_id in self._grants:
            raise MultiAgentError("capability_id already admitted")

    def _descendants(self, root: str) -> list[str]:
        result: list[str] = []
        stack = [root]
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                raise MultiAgentError("delegation cycle detected")
            seen.add(current)
            result.append(current)
            stack.extend(sorted(self._children.get(current, ()), reverse=True))
        return result


def _scope_contains(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    for key, value in child.items():
        if key not in parent:
            return False
        parent_value = parent[key]
        if isinstance(value, list):
            if not isinstance(parent_value, list) or not set(value).issubset(set(parent_value)):
                return False
        elif value != parent_value:
            return False
    return True


__all__ = ["AUTHORITY", "DelegationReceipt", "Grant", "MultiAgentError", "MultiAgentGovernance", "SCHEMA"]
