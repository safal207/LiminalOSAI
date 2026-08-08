"""Epoch-bound capability contracts for LiminalOS.

This layer binds an existing Phase-0 CapabilityContract to the exact trusted
runtime epoch and runtime-state digest in which the capability is valid. It
does not grant or execute effects. The existing CapabilityBroker remains the
lifecycle/scope authority; this wrapper removes stale or unbound authority
before delegating admission/use decisions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from sdk.liminal_capability_broker import BrokerError, CapabilityBroker
from sdk.liminal_post_sandbox_contracts import (
    CapabilityContract,
    ContractError,
    canonical_sha256,
)

CONTRACT_SCHEMA = "liminal-epoch-bound-capability-contract-v0.1"
DECISION_SCHEMA = "liminal-epoch-bound-capability-decision-v0.1"
STATE_SCHEMA = "liminal-epoch-bound-capability-broker-state-v0.1"
ZERO_SHA256 = "0" * 64

AUTHORITY = {
    "mode": "runtime_epoch_capability_restriction",
    "base_capability_schema_preserved": True,
    "trusted_runtime_state_required": True,
    "admission_epoch_check": True,
    "use_epoch_check": True,
    "stale_authority_revocation": True,
    "unbound_authority_revocation": True,
    "new_effect_grant": False,
    "runtime_mutation": False,
    "process_execution": False,
    "network_access": False,
    "credential_access": False,
    "kernel_enforcement": False,
}


class EpochBindingError(ValueError):
    pass


class RuntimeEpochProvider(Protocol):
    def state_document(self) -> Mapping[str, Any]: ...


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise EpochBindingError(f"{name} must be lowercase SHA-256")
    return value


def _time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EpochBindingError(f"{name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class TrustedRuntimeSnapshot:
    epoch: int
    state_sha256: str
    tainted: bool
    snapshot_sha256: str

    @classmethod
    def from_provider(cls, provider: RuntimeEpochProvider) -> "TrustedRuntimeSnapshot":
        raw = dict(provider.state_document())
        epoch = _time(raw.get("epoch"), "runtime epoch")
        state = _sha(raw.get("state_sha256"), "runtime state_sha256")
        tainted = raw.get("tainted")
        if type(tainted) is not bool:
            raise EpochBindingError("runtime tainted flag must be boolean")
        body = {"epoch": epoch, "state_sha256": state, "tainted": tainted}
        return cls(epoch=epoch, state_sha256=state, tainted=tainted, snapshot_sha256=canonical_sha256(body))


@dataclass(frozen=True)
class EpochBoundCapabilityContract:
    base_capability: Mapping[str, Any]
    runtime_epoch: int
    runtime_state_sha256: str
    binding_sha256: str

    @classmethod
    def build(
        cls,
        *,
        base_capability: Mapping[str, Any],
        runtime_epoch: int,
        runtime_state_sha256: str,
    ) -> "EpochBoundCapabilityContract":
        base = CapabilityContract.from_document(dict(base_capability))
        epoch = _time(runtime_epoch, "runtime_epoch")
        state = _sha(runtime_state_sha256, "runtime_state_sha256")
        body = {
            "schema": CONTRACT_SCHEMA,
            "base_capability": base.as_document(),
            "runtime_epoch": epoch,
            "runtime_state_sha256": state,
            "authority": AUTHORITY,
        }
        return cls(
            base_capability=base.as_document(),
            runtime_epoch=epoch,
            runtime_state_sha256=state,
            binding_sha256=canonical_sha256(body),
        )

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "EpochBoundCapabilityContract":
        raw = dict(value)
        expected = {
            "schema", "base_capability", "runtime_epoch", "runtime_state_sha256",
            "authority", "binding_sha256",
        }
        if set(raw) != expected:
            raise EpochBindingError("epoch-bound capability contract keys mismatch")
        if raw.get("schema") != CONTRACT_SCHEMA or raw.get("authority") != AUTHORITY:
            raise EpochBindingError("epoch-bound capability schema or authority mismatch")
        try:
            base = CapabilityContract.from_document(dict(raw["base_capability"]))
        except (ContractError, TypeError, ValueError) as exc:
            raise EpochBindingError(str(exc)) from exc
        item = cls(
            base_capability=base.as_document(),
            runtime_epoch=_time(raw["runtime_epoch"], "runtime_epoch"),
            runtime_state_sha256=_sha(raw["runtime_state_sha256"], "runtime_state_sha256"),
            binding_sha256=_sha(raw["binding_sha256"], "binding_sha256"),
        )
        if canonical_sha256(item.body()) != item.binding_sha256:
            raise EpochBindingError("epoch-bound capability binding_sha256 mismatch")
        return item

    @property
    def base(self) -> CapabilityContract:
        return CapabilityContract.from_document(dict(self.base_capability))

    def body(self) -> dict[str, Any]:
        return {
            "schema": CONTRACT_SCHEMA,
            "base_capability": dict(self.base_capability),
            "runtime_epoch": self.runtime_epoch,
            "runtime_state_sha256": self.runtime_state_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "binding_sha256": self.binding_sha256}


@dataclass(frozen=True)
class EpochBoundDecisionReceipt:
    decision_id: str
    capability_id: str | None
    subject_id: str
    capability_type: str
    bound_contract_sha256: str
    base_contract_sha256: str
    runtime_epoch_bound: int
    runtime_epoch_observed: int
    runtime_state_sha256_bound: str
    runtime_state_sha256_observed: str
    runtime_snapshot_sha256: str
    delegate_receipt_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": DECISION_SCHEMA,
            "decision_id": self.decision_id,
            "capability_id": self.capability_id,
            "subject_id": self.subject_id,
            "capability_type": self.capability_type,
            "bound_contract_sha256": self.bound_contract_sha256,
            "base_contract_sha256": self.base_contract_sha256,
            "runtime_epoch_bound": self.runtime_epoch_bound,
            "runtime_epoch_observed": self.runtime_epoch_observed,
            "runtime_state_sha256_bound": self.runtime_state_sha256_bound,
            "runtime_state_sha256_observed": self.runtime_state_sha256_observed,
            "runtime_snapshot_sha256": self.runtime_snapshot_sha256,
            "delegate_receipt_sha256": self.delegate_receipt_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class EpochBoundCapabilityBroker:
    """Drop-in capability broker surface with runtime-epoch restriction."""

    def __init__(
        self,
        *,
        runtime_provider: RuntimeEpochProvider,
        delegate: CapabilityBroker | None = None,
        broker_id: str = "broker:epoch-bound",
    ) -> None:
        self.runtime_provider = runtime_provider
        self.delegate = delegate or CapabilityBroker(broker_id)
        self.broker_id = broker_id
        self._bindings: dict[str, EpochBoundCapabilityContract] = {}
        self._receipts: list[EpochBoundDecisionReceipt] = []
        self._head = ZERO_SHA256

    @property
    def head_sha256(self) -> str:
        return canonical_sha256({
            "delegate_head_sha256": self.delegate.head_sha256,
            "epoch_binding_head_sha256": self._head,
        })

    def admit(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        _time(at_unix, "at_unix")
        bound = EpochBoundCapabilityContract.from_document(document)
        base = bound.base
        existing = self._bindings.get(base.capability_id)
        if existing is not None and existing.binding_sha256 != bound.binding_sha256:
            raise EpochBindingError("duplicate capability_id with different runtime binding")

        snapshot = TrustedRuntimeSnapshot.from_provider(self.runtime_provider)
        if snapshot.tainted:
            return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                decision="BLOCK", reasons=("runtime_state_tainted",),
                                at_unix=at_unix, capability_id=None)
        mismatch = self._binding_mismatch(bound, snapshot)
        if mismatch:
            return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                decision="BLOCK", reasons=mismatch, at_unix=at_unix, capability_id=None)

        if base.parent_capability_id is not None:
            parent = self._bindings.get(base.parent_capability_id)
            if parent is None:
                return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                    decision="BLOCK", reasons=("delegation_parent_not_epoch_bound",),
                                    at_unix=at_unix, capability_id=None)
            if parent.runtime_epoch != bound.runtime_epoch or parent.runtime_state_sha256 != bound.runtime_state_sha256:
                return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                    decision="BLOCK", reasons=("delegation_runtime_binding_mismatch",),
                                    at_unix=at_unix, capability_id=None)

        try:
            delegate_receipt = self.delegate.admit(base.as_document(), at_unix=at_unix)
        except BrokerError as exc:
            return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                decision="BLOCK", reasons=("delegate_admission_error", type(exc).__name__),
                                at_unix=at_unix, capability_id=None)
        if delegate_receipt.get("decision") != "ALLOW":
            return self._finish(bound=bound, snapshot=snapshot,
                                delegate_receipt_sha=_sha(delegate_receipt["receipt_sha256"], "delegate receipt"),
                                decision="BLOCK",
                                reasons=tuple(delegate_receipt.get("reason_codes", ())) + ("delegate_admission_blocked",),
                                at_unix=at_unix, capability_id=None)
        self._bindings[base.capability_id] = bound
        return self._finish(bound=bound, snapshot=snapshot,
                            delegate_receipt_sha=_sha(delegate_receipt["receipt_sha256"], "delegate receipt"),
                            decision="ALLOW", reasons=("epoch_binding_match", "base_capability_admitted"),
                            at_unix=at_unix, capability_id=base.capability_id)

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
        _time(at_unix, "at_unix")
        snapshot = TrustedRuntimeSnapshot.from_provider(self.runtime_provider)
        revoked_reasons = self._reconcile(snapshot, at_unix=at_unix)
        candidates = sorted(
            (bound for bound in self._bindings.values()
             if bound.base.subject_id == subject_id
             and bound.base.capability_type == capability_type
             and bound.runtime_epoch == snapshot.epoch
             and bound.runtime_state_sha256 == snapshot.state_sha256),
            key=lambda item: item.base.capability_id,
        )
        representative = candidates[0] if candidates else None

        if snapshot.tainted:
            return self._finish_generic(representative=representative, subject_id=subject_id,
                                        capability_type=capability_type, policy_sha256=policy_sha256,
                                        snapshot=snapshot, delegate_receipt_sha=ZERO_SHA256,
                                        decision="BLOCK", reasons=tuple(revoked_reasons) + ("runtime_state_tainted",),
                                        at_unix=at_unix)

        bound_action = {
            **dict(action),
            "trusted_runtime_epoch": snapshot.epoch,
            "trusted_runtime_state_sha256": snapshot.state_sha256,
            "trusted_runtime_snapshot_sha256": snapshot.snapshot_sha256,
        }
        delegate_receipt = self.delegate.authorize(
            subject_id=subject_id, capability_type=capability_type, policy_sha256=policy_sha256,
            requested_scope=requested_scope, action=bound_action, at_unix=at_unix,
            recorder_event_id=recorder_event_id, recorder_entry_sha256=recorder_entry_sha256,
        )
        delegate_sha = _sha(delegate_receipt["receipt_sha256"], "delegate receipt")
        capability_id = delegate_receipt.get("capability_id")

        if delegate_receipt.get("decision") == "ALLOW":
            bound = self._bindings.get(capability_id)
            if bound is None:
                if capability_id:
                    self.delegate.revoke(capability_id, at_unix=at_unix)
                return self._finish_generic(representative=representative, subject_id=subject_id,
                                            capability_type=capability_type, policy_sha256=policy_sha256,
                                            snapshot=snapshot, delegate_receipt_sha=delegate_sha,
                                            decision="BLOCK",
                                            reasons=tuple(revoked_reasons) + ("delegate_returned_unbound_authority",),
                                            at_unix=at_unix)
            mismatch = self._binding_mismatch(bound, snapshot)
            if mismatch:
                self.delegate.revoke(capability_id, at_unix=at_unix)
                return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=delegate_sha,
                                    decision="BLOCK",
                                    reasons=tuple(revoked_reasons) + mismatch + ("stale_authority_revoked",),
                                    at_unix=at_unix, capability_id=None)
            return self._finish(bound=bound, snapshot=snapshot, delegate_receipt_sha=delegate_sha,
                                decision="ALLOW",
                                reasons=tuple(revoked_reasons) + ("epoch_binding_match",) + tuple(delegate_receipt.get("reason_codes", ())),
                                at_unix=at_unix, capability_id=capability_id)

        return self._finish_generic(representative=representative, subject_id=subject_id,
                                    capability_type=capability_type, policy_sha256=policy_sha256,
                                    snapshot=snapshot, delegate_receipt_sha=delegate_sha,
                                    decision="BLOCK",
                                    reasons=tuple(revoked_reasons) + tuple(delegate_receipt.get("reason_codes", ())),
                                    at_unix=at_unix)

    def revoke(self, capability_id: str, *, at_unix: int) -> dict[str, Any]:
        return self.delegate.revoke(capability_id, at_unix=at_unix)

    def expire_due(self, *, at_unix: int) -> tuple[dict[str, Any], ...]:
        return self.delegate.expire_due(at_unix=at_unix)

    def state_document(self) -> dict[str, Any]:
        snapshot = TrustedRuntimeSnapshot.from_provider(self.runtime_provider)
        delegate_state = self.delegate.state_document()
        capabilities = []
        for item in delegate_state.get("capabilities", []):
            cap = dict(item)
            bound = self._bindings.get(cap["capability_id"])
            cap["epoch_bound"] = bound is not None
            cap["runtime_epoch"] = bound.runtime_epoch if bound else None
            cap["runtime_state_sha256"] = bound.runtime_state_sha256 if bound else ZERO_SHA256
            cap["bound_contract_sha256"] = bound.binding_sha256 if bound else ZERO_SHA256
            capabilities.append(cap)
        body = {
            "schema": STATE_SCHEMA,
            "broker_id": self.broker_id,
            "runtime_epoch": snapshot.epoch,
            "runtime_state_sha256": snapshot.state_sha256,
            "runtime_tainted": snapshot.tainted,
            "runtime_snapshot_sha256": snapshot.snapshot_sha256,
            "delegate_head_sha256": self.delegate.head_sha256,
            "epoch_binding_head_sha256": self._head,
            "capabilities": capabilities,
            "authority": AUTHORITY,
        }
        return {**body, "state_sha256": canonical_sha256(body)}

    def events(self) -> tuple[dict[str, Any], ...]:
        return self.delegate.events()

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def delegate_receipts(self) -> tuple[dict[str, Any], ...]:
        return self.delegate.receipts()

    def _binding_mismatch(self, bound: EpochBoundCapabilityContract,
                          snapshot: TrustedRuntimeSnapshot) -> tuple[str, ...]:
        reasons: list[str] = []
        if bound.runtime_epoch != snapshot.epoch:
            reasons.append("stale_runtime_epoch")
        if bound.runtime_state_sha256 != snapshot.state_sha256:
            reasons.append("stale_runtime_state")
        return tuple(reasons)

    def _reconcile(self, snapshot: TrustedRuntimeSnapshot, *, at_unix: int) -> tuple[str, ...]:
        reasons: set[str] = set()
        state_items = list(self.delegate.state_document().get("capabilities", []))
        statuses = {item["capability_id"]: item.get("status") for item in state_items}
        for item in state_items:
            if item.get("status") != "active":
                continue
            cap_id = item["capability_id"]
            bound = self._bindings.get(cap_id)
            if bound is None:
                result = self.delegate.revoke(cap_id, at_unix=at_unix)
                if result.get("decision") == "ALLOW":
                    reasons.add("unbound_authority_revoked")
                    statuses[cap_id] = "revoked"
                continue
            parent_id = bound.base.parent_capability_id
            if parent_id is not None and statuses.get(parent_id) != "active":
                result = self.delegate.revoke(cap_id, at_unix=at_unix)
                if result.get("decision") == "ALLOW":
                    reasons.add("delegation_parent_inactive")
                    reasons.add("stale_authority_revoked")
                    statuses[cap_id] = "revoked"
                continue
            mismatch = self._binding_mismatch(bound, snapshot)
            if snapshot.tainted or mismatch:
                result = self.delegate.revoke(cap_id, at_unix=at_unix)
                if result.get("decision") == "ALLOW":
                    reasons.add("stale_authority_revoked")
                    reasons.update(mismatch)
                    statuses[cap_id] = "revoked"
        return tuple(sorted(reasons))

    def _finish(self, *, bound: EpochBoundCapabilityContract, snapshot: TrustedRuntimeSnapshot,
                delegate_receipt_sha: str, decision: str, reasons: tuple[str, ...],
                at_unix: int, capability_id: str | None) -> dict[str, Any]:
        base = bound.base
        return self._receipt(capability_id=capability_id, subject_id=base.subject_id,
                             capability_type=base.capability_type, bound_contract_sha=bound.binding_sha256,
                             base_contract_sha=base.contract_sha256, runtime_epoch_bound=bound.runtime_epoch,
                             runtime_state_bound=bound.runtime_state_sha256, snapshot=snapshot,
                             delegate_receipt_sha=delegate_receipt_sha, decision=decision,
                             reasons=reasons, at_unix=at_unix)

    def _finish_generic(self, *, representative: EpochBoundCapabilityContract | None,
                        subject_id: str, capability_type: str, policy_sha256: str,
                        snapshot: TrustedRuntimeSnapshot, delegate_receipt_sha: str,
                        decision: str, reasons: tuple[str, ...], at_unix: int) -> dict[str, Any]:
        _sha(policy_sha256, "policy_sha256")
        if representative is None:
            bound_sha = ZERO_SHA256
            base_sha = ZERO_SHA256
            epoch_bound = snapshot.epoch
            state_bound = snapshot.state_sha256
        else:
            bound_sha = representative.binding_sha256
            base_sha = representative.base.contract_sha256
            epoch_bound = representative.runtime_epoch
            state_bound = representative.runtime_state_sha256
        return self._receipt(capability_id=None, subject_id=subject_id, capability_type=capability_type,
                             bound_contract_sha=bound_sha, base_contract_sha=base_sha,
                             runtime_epoch_bound=epoch_bound, runtime_state_bound=state_bound,
                             snapshot=snapshot, delegate_receipt_sha=delegate_receipt_sha,
                             decision=decision, reasons=reasons or ("default_deny",), at_unix=at_unix)

    def _receipt(self, *, capability_id: str | None, subject_id: str, capability_type: str,
                 bound_contract_sha: str, base_contract_sha: str, runtime_epoch_bound: int,
                 runtime_state_bound: str, snapshot: TrustedRuntimeSnapshot,
                 delegate_receipt_sha: str, decision: str, reasons: tuple[str, ...],
                 at_unix: int) -> dict[str, Any]:
        if decision not in {"ALLOW", "BLOCK"}:
            raise EpochBindingError("epoch-bound broker decision must be ALLOW or BLOCK")
        item = EpochBoundDecisionReceipt(
            decision_id=f"epoch-bound-decision:{len(self._receipts)+1}",
            capability_id=capability_id,
            subject_id=subject_id,
            capability_type=capability_type,
            bound_contract_sha256=_sha(bound_contract_sha, "bound_contract_sha256"),
            base_contract_sha256=_sha(base_contract_sha, "base_contract_sha256"),
            runtime_epoch_bound=_time(runtime_epoch_bound, "runtime_epoch_bound"),
            runtime_epoch_observed=snapshot.epoch,
            runtime_state_sha256_bound=_sha(runtime_state_bound, "runtime_state_sha256_bound"),
            runtime_state_sha256_observed=snapshot.state_sha256,
            runtime_snapshot_sha256=snapshot.snapshot_sha256,
            delegate_receipt_sha256=_sha(delegate_receipt_sha, "delegate_receipt_sha256"),
            decision=decision,
            reason_codes=tuple(sorted(set(reasons))),
            at_unix=_time(at_unix, "at_unix"),
            receipt_sha256="",
        )
        receipt = EpochBoundDecisionReceipt(**{**item.__dict__, "receipt_sha256": canonical_sha256(item.body())})
        self._receipts.append(receipt)
        self._head = receipt.receipt_sha256
        return receipt.as_document()


def verify_contract(document: Mapping[str, Any]) -> dict[str, Any]:
    return EpochBoundCapabilityContract.from_document(document).as_document()


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != DECISION_SCHEMA or raw.get("authority") != AUTHORITY:
        raise EpochBindingError("epoch-bound decision schema or authority mismatch")
    expected = {
        "schema", "decision_id", "capability_id", "subject_id", "capability_type",
        "bound_contract_sha256", "base_contract_sha256", "runtime_epoch_bound",
        "runtime_epoch_observed", "runtime_state_sha256_bound", "runtime_state_sha256_observed",
        "runtime_snapshot_sha256", "delegate_receipt_sha256", "decision", "reason_codes",
        "at_unix", "authority",
    }
    if set(raw) != expected:
        raise EpochBindingError("epoch-bound decision keys mismatch")
    for key in ("bound_contract_sha256", "base_contract_sha256", "runtime_state_sha256_bound",
                "runtime_state_sha256_observed", "runtime_snapshot_sha256", "delegate_receipt_sha256"):
        _sha(raw[key], key)
    _time(raw["runtime_epoch_bound"], "runtime_epoch_bound")
    _time(raw["runtime_epoch_observed"], "runtime_epoch_observed")
    _time(raw["at_unix"], "at_unix")
    if raw["decision"] not in {"ALLOW", "BLOCK"}:
        raise EpochBindingError("invalid epoch-bound decision")
    if not isinstance(raw["reason_codes"], list) or not all(isinstance(x, str) and x for x in raw["reason_codes"]):
        raise EpochBindingError("reason_codes must be strings")
    digest = _sha(digest, "receipt_sha256")
    if canonical_sha256(raw) != digest:
        raise EpochBindingError("epoch-bound decision receipt digest mismatch")
    return {**raw, "receipt_sha256": digest}
