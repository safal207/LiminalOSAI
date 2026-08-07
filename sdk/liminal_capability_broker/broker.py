"""Defensive capability lifecycle enforcement.

The broker decides whether an action is within an admitted capability contract.
It never executes the action itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from sdk.liminal_post_sandbox_contracts import (
    CAPABILITY_TYPES,
    CapabilityContract,
    CausalRuntimeEvent,
    ContractError,
    canonical_sha256,
    validate_scope,
)

ZERO_SHA256 = "0" * 64
DECISION_SCHEMA = "liminal-capability-decision-receipt-v0.1"

BROKER_AUTHORITY = {
    "mode": "capability_lifecycle_enforcement_only",
    "capability_admission": True,
    "capability_grant": True,
    "capability_use_decision": True,
    "capability_revoke": True,
    "capability_expire": True,
    "execution": False,
    "network_mediation": False,
    "credential_material_access": False,
    "process_control": False,
    "containment_execution": False,
    "automatic_github_write_authorization": False,
    "merge": False,
    "deployment": False,
    "rollback": False,
}


class BrokerError(ValueError):
    pass


@dataclass(frozen=True)
class CapabilityDecisionReceipt:
    decision_id: str
    capability_id: str | None
    subject_id: str
    capability_type: str
    policy_sha256: str
    action_sha256: str
    requested_scope: Mapping[str, Any]
    decision: str
    reason_codes: tuple[str, ...]
    at_unix: int
    use_count_before: int
    use_count_after: int
    causal_event_sha256: str
    broker_head_sha256: str
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": DECISION_SCHEMA,
            "decision_id": self.decision_id,
            "capability_id": self.capability_id,
            "subject_id": self.subject_id,
            "capability_type": self.capability_type,
            "policy_sha256": self.policy_sha256,
            "action_sha256": self.action_sha256,
            "requested_scope": dict(self.requested_scope),
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "use_count_before": self.use_count_before,
            "use_count_after": self.use_count_after,
            "causal_event_sha256": self.causal_event_sha256,
            "broker_head_sha256": self.broker_head_sha256,
            "authority": BROKER_AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _State:
    contract: CapabilityContract
    status: str = "active"
    use_count: int = 0
    revoked_at_unix: int | None = None
    expired_at_unix: int | None = None


class CapabilityBroker:
    def __init__(self, broker_id: str = "broker:default") -> None:
        if not isinstance(broker_id, str) or not broker_id.strip():
            raise BrokerError("broker_id must be non-empty")
        self.broker_id = broker_id
        self._states: dict[str, _State] = {}
        self._events: list[CausalRuntimeEvent] = []
        self._receipts: list[CapabilityDecisionReceipt] = []
        self._head = ZERO_SHA256

    @property
    def head_sha256(self) -> str:
        return self._head

    def admit(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        self._check_time(at_unix)
        contract = CapabilityContract.from_document(dict(document))
        existing = self._states.get(contract.capability_id)
        if existing:
            if existing.contract.contract_sha256 != contract.contract_sha256:
                raise BrokerError("duplicate capability_id with different contract")
            return self._lifecycle(existing, "grant", "ALLOW", ("already_admitted",), at_unix)
        if at_unix < contract.issued_at_unix or at_unix >= contract.expires_at_unix:
            raise BrokerError("capability is outside admissible time window")
        self._validate_parent(contract)
        state = _State(contract=contract)
        self._states[contract.capability_id] = state
        return self._lifecycle(state, "grant", "ALLOW", ("capability_admitted",), at_unix)

    def authorize(
        self,
        *,
        subject_id: str,
        capability_type: str,
        policy_sha256: str,
        requested_scope: Mapping[str, Any],
        action: Mapping[str, Any],
        at_unix: int,
        recorder_event_id: str | None = None,
        recorder_entry_sha256: str | None = None,
    ) -> dict[str, Any]:
        self._check_time(at_unix)
        if capability_type not in CAPABILITY_TYPES:
            raise BrokerError("unsupported capability_type")
        try:
            scope = validate_scope(capability_type, dict(requested_scope))
        except ContractError as exc:
            raise BrokerError(str(exc)) from exc
        action_sha = canonical_sha256(dict(action))
        candidates = sorted(
            (s for s in self._states.values() if s.contract.subject_id == subject_id and s.contract.capability_type == capability_type),
            key=lambda s: s.contract.capability_id,
        )
        reasons: set[str] = set()
        for state in candidates:
            bad = self._ineligible(state, policy_sha256, scope, at_unix)
            if bad:
                reasons.update(bad)
                continue
            before = state.use_count
            state.use_count += 1
            event = self._event(
                event_type="use", subject_id=subject_id, capability_id=state.contract.capability_id,
                capability_type=capability_type, decision="ALLOW", at_unix=at_unix,
                input_sha=action_sha, output_sha=state.contract.contract_sha256,
                reasons=("capability_scope_match", "policy_match", "use_committed"),
                recorder_event_id=recorder_event_id, recorder_entry_sha256=recorder_entry_sha256,
            )
            return self._receipt(
                capability_id=state.contract.capability_id, subject_id=subject_id,
                capability_type=capability_type, policy_sha=policy_sha256, action_sha=action_sha,
                scope=scope, decision="ALLOW",
                reasons=("capability_scope_match", "policy_match", "use_committed"), at_unix=at_unix,
                before=before, after=state.use_count, event=event,
            )
        deny_reasons = tuple(sorted(reasons or {"default_deny", "no_matching_capability"}))
        event = self._event(
            event_type="deny", subject_id=subject_id, capability_id="capability:none",
            capability_type=capability_type, decision="BLOCK", at_unix=at_unix,
            input_sha=action_sha, output_sha=None, reasons=deny_reasons,
            recorder_event_id=recorder_event_id, recorder_entry_sha256=recorder_entry_sha256,
        )
        return self._receipt(
            capability_id=None, subject_id=subject_id, capability_type=capability_type,
            policy_sha=policy_sha256, action_sha=action_sha, scope=scope, decision="BLOCK",
            reasons=deny_reasons, at_unix=at_unix, before=0, after=0, event=event,
        )

    def revoke(self, capability_id: str, *, at_unix: int) -> dict[str, Any]:
        self._check_time(at_unix)
        state = self._require(capability_id)
        if state.status != "active":
            return self._lifecycle(state, "revoke", "BLOCK", (f"already_{state.status}",), at_unix)
        state.status = "revoked"
        state.revoked_at_unix = at_unix
        return self._lifecycle(state, "revoke", "ALLOW", ("explicit_revoke",), at_unix)

    def expire_due(self, *, at_unix: int) -> tuple[dict[str, Any], ...]:
        self._check_time(at_unix)
        out: list[dict[str, Any]] = []
        for capability_id in sorted(self._states):
            state = self._states[capability_id]
            if state.status == "active" and at_unix >= state.contract.expires_at_unix:
                state.status = "expired"
                state.expired_at_unix = at_unix
                out.append(self._lifecycle(state, "expire", "ALLOW", ("ttl_expired",), at_unix))
        return tuple(out)

    def state_document(self) -> dict[str, Any]:
        caps = []
        for capability_id in sorted(self._states):
            state = self._states[capability_id]
            caps.append({
                "capability_id": capability_id,
                "contract_sha256": state.contract.contract_sha256,
                "status": state.status,
                "use_count": state.use_count,
                "max_uses": state.contract.max_uses,
                "expires_at_unix": state.contract.expires_at_unix,
            })
        body = {
            "schema": "liminal-capability-broker-state-v0.1",
            "broker_id": self.broker_id,
            "head_sha256": self._head,
            "event_count": len(self._events),
            "receipt_count": len(self._receipts),
            "capabilities": caps,
            "authority": BROKER_AUTHORITY,
        }
        return {**body, "state_sha256": canonical_sha256(body)}

    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(event.as_document() for event in self._events)

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(receipt.as_document() for receipt in self._receipts)

    def _ineligible(self, state: _State, policy_sha: str, scope: Mapping[str, Any], at_unix: int) -> tuple[str, ...]:
        c = state.contract
        reasons: list[str] = []
        if state.status != "active":
            reasons.append(state.status)
        if at_unix < c.not_before_unix:
            reasons.append("not_yet_valid")
        if at_unix >= c.expires_at_unix:
            reasons.append("expired")
        if c.policy_sha256 != policy_sha:
            reasons.append("policy_mismatch")
        if state.use_count >= c.max_uses:
            reasons.append("use_exhausted")
        if not _scope_contains(c.capability_type, c.scope, scope):
            reasons.append("scope_mismatch")
        return tuple(sorted(set(reasons)))

    def _validate_parent(self, child: CapabilityContract) -> None:
        if child.parent_capability_id is None:
            return
        parent_state = self._states.get(child.parent_capability_id)
        if parent_state is None or parent_state.status != "active":
            raise BrokerError("delegation parent is not active")
        parent = parent_state.contract
        if not parent.delegable:
            raise BrokerError("parent is not delegable")
        if child.capability_type != parent.capability_type:
            raise BrokerError("child capability_type exceeds parent")
        if child.policy_sha256 != parent.policy_sha256:
            raise BrokerError("child policy differs from parent")
        if child.expires_at_unix > parent.expires_at_unix or child.max_uses > parent.max_uses:
            raise BrokerError("child validity or use bounds exceed parent")
        if not _scope_contains(child.capability_type, parent.scope, child.scope):
            raise BrokerError("child scope exceeds parent")

    def _lifecycle(self, state: _State, event_type: str, decision: str, reasons: tuple[str, ...], at_unix: int) -> dict[str, Any]:
        event = self._event(
            event_type=event_type, subject_id=state.contract.subject_id,
            capability_id=state.contract.capability_id, capability_type=state.contract.capability_type,
            decision=decision, at_unix=at_unix, input_sha=state.contract.contract_sha256,
            output_sha=None, reasons=reasons, recorder_event_id=None, recorder_entry_sha256=None,
        )
        return self._receipt(
            capability_id=state.contract.capability_id, subject_id=state.contract.subject_id,
            capability_type=state.contract.capability_type, policy_sha=state.contract.policy_sha256,
            action_sha=state.contract.contract_sha256, scope=state.contract.scope, decision=decision,
            reasons=reasons, at_unix=at_unix, before=state.use_count, after=state.use_count, event=event,
        )

    def _event(self, *, event_type: str, subject_id: str, capability_id: str, capability_type: str,
               decision: str, at_unix: int, input_sha: str, output_sha: str | None,
               reasons: tuple[str, ...], recorder_event_id: str | None,
               recorder_entry_sha256: str | None) -> CausalRuntimeEvent:
        event = CausalRuntimeEvent.build(
            event_id=f"broker-event:{len(self._events)+1}", event_type=event_type,
            subject_id=subject_id, capability_id=capability_id,
            recorder_event_id=recorder_event_id, recorder_entry_sha256=recorder_entry_sha256,
            effect=_effect_for(capability_type), decision=decision, observed_at_unix=at_unix,
            previous_causal_event_sha256=self._head, input_sha256=input_sha,
            output_sha256=output_sha, reason_codes=list(reasons),
        )
        self._events.append(event)
        self._head = event.event_sha256
        return event

    def _receipt(self, *, capability_id: str | None, subject_id: str, capability_type: str,
                 policy_sha: str, action_sha: str, scope: Mapping[str, Any], decision: str,
                 reasons: tuple[str, ...], at_unix: int, before: int, after: int,
                 event: CausalRuntimeEvent) -> dict[str, Any]:
        base = CapabilityDecisionReceipt(
            decision_id=f"broker-decision:{len(self._receipts)+1}", capability_id=capability_id,
            subject_id=subject_id, capability_type=capability_type, policy_sha256=policy_sha,
            action_sha256=action_sha, requested_scope=dict(scope), decision=decision,
            reason_codes=tuple(sorted(set(reasons))), at_unix=at_unix,
            use_count_before=before, use_count_after=after,
            causal_event_sha256=event.event_sha256, broker_head_sha256=self._head,
            receipt_sha256="",
        )
        receipt = CapabilityDecisionReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()

    def _require(self, capability_id: str) -> _State:
        if capability_id not in self._states:
            raise BrokerError("unknown capability_id")
        return self._states[capability_id]

    @staticmethod
    def _check_time(at_unix: int) -> None:
        if isinstance(at_unix, bool) or not isinstance(at_unix, int) or at_unix < 0:
            raise BrokerError("at_unix must be a non-negative integer")


def _scope_contains(capability_type: str, granted: Mapping[str, Any], requested: Mapping[str, Any]) -> bool:
    if capability_type in {"repository.read", "repository.write"} and granted.get("repository") != requested.get("repository"):
        return False
    for key, requested_value in requested.items():
        if key not in granted:
            return False
        granted_value = granted[key]
        if isinstance(requested_value, list):
            if not isinstance(granted_value, list) or not set(requested_value).issubset(set(granted_value)):
                return False
        elif key == "max_children":
            if not isinstance(granted_value, int) or requested_value > granted_value:
                return False
        elif granted_value != requested_value:
            return False
    return True


def _effect_for(capability_type: str) -> str:
    if capability_type == "repository.read":
        return "read"
    if capability_type in {"repository.write", "filesystem.write_outside_workspace"}:
        return "write"
    if capability_type in {"process.execute", "package.install", "process.spawn_child"}:
        return "execute"
    if capability_type in {"network.open", "network.connect_domain"}:
        return "network"
    if capability_type == "credential.access":
        return "secret"
    return "config"
