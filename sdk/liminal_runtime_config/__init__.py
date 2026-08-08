"""Bound runtime-configuration governance for LiminalOS.

A runtime configuration mutation is admitted only when an immutable plan is
bound to the exact trusted pre-state and runtime epoch. Successful or
unverifiable admitted mutation invalidates authority from the previous epoch.
The model-facing layer never receives raw environment/configuration values.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from sdk.liminal_post_sandbox_contracts import canonical_sha256, validate_scope
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

SCHEMA = "liminal-bound-runtime-config-receipt-v0.1"
PLAN_SCHEMA = "liminal-bound-runtime-config-plan-v0.1"
STATE_SCHEMA = "liminal-runtime-state-evidence-v0.1"
ZERO_SHA256 = "0" * 64

AUTHORITY = {
    "mode": "bound_runtime_configuration_governance",
    "runtime_mediation_required": True,
    "trusted_state_observation": True,
    "exact_before_state_binding": True,
    "monotonic_runtime_epoch": True,
    "old_epoch_authority_revocation": True,
    "digest_only_receipts": True,
    "raw_environment_access": False,
    "secret_material_export": False,
    "shell_execution": False,
    "direct_filesystem_mutation": False,
    "direct_network_reconfiguration": False,
    "kernel_or_runtime_escape_resistance": False,
}


class RuntimeConfigError(ValueError):
    pass


class RuntimeConfigBackend(Protocol):
    def observe(self) -> Mapping[str, Any]: ...
    def apply(self, plan: "RuntimeConfigPlan") -> None: ...


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeConfigError(f"{name} must be lowercase SHA-256")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value or len(value) > 192:
        raise RuntimeConfigError(f"{name} must be a bounded non-empty string")
    return value


@dataclass(frozen=True)
class RuntimeStateEvidence:
    host_binding_sha256: str
    state_sha256: str
    evidence_sha256: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, expected_host_binding_sha256: str) -> "RuntimeStateEvidence":
        raw = dict(value)
        expected = {"schema", "host_binding_sha256", "state_sha256", "evidence_sha256"}
        if set(raw) != expected or raw.get("schema") != STATE_SCHEMA:
            raise RuntimeConfigError("runtime state evidence schema mismatch")
        host = _sha(raw["host_binding_sha256"], "host_binding_sha256")
        if host != expected_host_binding_sha256:
            raise RuntimeConfigError("runtime state host binding mismatch")
        state = _sha(raw["state_sha256"], "state_sha256")
        body = {"schema": STATE_SCHEMA, "host_binding_sha256": host, "state_sha256": state}
        evidence = _sha(raw["evidence_sha256"], "evidence_sha256")
        if evidence != canonical_sha256(body):
            raise RuntimeConfigError("runtime state evidence digest mismatch")
        return cls(host, state, evidence)


@dataclass(frozen=True)
class RuntimeConfigPlan:
    operation_id: str
    setting_keys: tuple[str, ...]
    before_state_sha256: str
    after_state_sha256: str
    change_set_sha256: str
    host_binding_sha256: str
    epoch_before: int

    @classmethod
    def build(
        cls,
        *,
        operation_id: str,
        setting_keys: Sequence[str],
        before_state_sha256: str,
        after_state_sha256: str,
        change_set_sha256: str,
        host_binding_sha256: str,
        epoch_before: int,
    ) -> "RuntimeConfigPlan":
        scope = validate_scope("runtime.configure", {"setting_keys": list(setting_keys)})
        item = cls(
            operation_id=_text(operation_id, "operation_id"),
            setting_keys=tuple(scope["setting_keys"]),
            before_state_sha256=_sha(before_state_sha256, "before_state_sha256"),
            after_state_sha256=_sha(after_state_sha256, "after_state_sha256"),
            change_set_sha256=_sha(change_set_sha256, "change_set_sha256"),
            host_binding_sha256=_sha(host_binding_sha256, "host_binding_sha256"),
            epoch_before=epoch_before,
        )
        item.validate()
        return item

    def validate(self) -> None:
        _text(self.operation_id, "operation_id")
        validate_scope("runtime.configure", {"setting_keys": list(self.setting_keys)})
        for value, name in (
            (self.before_state_sha256, "before_state_sha256"),
            (self.after_state_sha256, "after_state_sha256"),
            (self.change_set_sha256, "change_set_sha256"),
            (self.host_binding_sha256, "host_binding_sha256"),
        ):
            _sha(value, name)
        if self.before_state_sha256 == self.after_state_sha256:
            raise RuntimeConfigError("runtime configuration plan must change state")
        if isinstance(self.epoch_before, bool) or not isinstance(self.epoch_before, int) or self.epoch_before < 0:
            raise RuntimeConfigError("epoch_before must be a non-negative integer")

    def body(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema": PLAN_SCHEMA,
            "operation_id": self.operation_id,
            "setting_keys": list(self.setting_keys),
            "before_state_sha256": self.before_state_sha256,
            "after_state_sha256": self.after_state_sha256,
            "change_set_sha256": self.change_set_sha256,
            "host_binding_sha256": self.host_binding_sha256,
            "epoch_before": self.epoch_before,
        }

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self.body())

    @property
    def payload_sha256(self) -> str:
        return canonical_sha256({"runtime_config_plan_sha256": self.plan_sha256})


@dataclass(frozen=True)
class RuntimeConfigReceipt:
    operation_id: str
    plan_sha256: str
    before_state_sha256: str
    after_state_sha256: str
    epoch_before: int
    epoch_after: int
    mediation_receipt_sha256: str
    host_evidence_sha256: str
    revoked_authority_count: int
    revoked_authority_set_sha256: str
    decision: str
    outcome: str
    reason_codes: tuple[str, ...]
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "operation_id": self.operation_id,
            "plan_sha256": self.plan_sha256,
            "before_state_sha256": self.before_state_sha256,
            "after_state_sha256": self.after_state_sha256,
            "epoch_before": self.epoch_before,
            "epoch_after": self.epoch_after,
            "mediation_receipt_sha256": self.mediation_receipt_sha256,
            "host_evidence_sha256": self.host_evidence_sha256,
            "revoked_authority_count": self.revoked_authority_count,
            "revoked_authority_set_sha256": self.revoked_authority_set_sha256,
            "decision": self.decision,
            "outcome": self.outcome,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class BoundRuntimeConfigBroker:
    def __init__(self, *, mediator: RuntimeMediator, backend: RuntimeConfigBackend, host_binding_sha256: str) -> None:
        self.mediator = mediator
        self.backend = backend
        self.host_binding_sha256 = _sha(host_binding_sha256, "host_binding_sha256")
        initial = self._observe()
        self._state_sha256 = initial.state_sha256
        self._epoch = 0
        self._tainted = False
        self._seen_plans: set[str] = set()
        self._receipts: list[RuntimeConfigReceipt] = []

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def state_sha256(self) -> str:
        return self._state_sha256

    @property
    def tainted(self) -> bool:
        return self._tainted

    def state_document(self) -> dict[str, Any]:
        body = {
            "schema": "liminal-bound-runtime-config-state-v0.1",
            "epoch": self._epoch,
            "state_sha256": self._state_sha256,
            "tainted": self._tainted,
            "seen_plan_count": len(self._seen_plans),
            "authority": AUTHORITY,
        }
        return {**body, "state_document_sha256": canonical_sha256(body)}

    def execute(self, *, operation: RuntimeOperation, plan: RuntimeConfigPlan) -> dict[str, Any]:
        operation.validate()
        plan.validate()
        before_epoch = self._epoch
        before_state = self._state_sha256

        if operation.kind != "runtime.configure":
            raise RuntimeConfigError("bound runtime configuration only accepts runtime.configure")
        if operation.operation_id != plan.operation_id:
            raise RuntimeConfigError("operation_id does not match runtime configuration plan")
        scope = operation.normalized_scope()
        if tuple(scope.get("setting_keys", ())) != plan.setting_keys:
            raise RuntimeConfigError("runtime configuration setting scope must exactly match plan")
        if operation.payload_sha256 != plan.payload_sha256:
            raise RuntimeConfigError("runtime payload is not bound to the configuration plan")
        if plan.host_binding_sha256 != self.host_binding_sha256:
            return self._finish(operation, plan, before_state, before_state, before_epoch, before_epoch, ZERO_SHA256, ZERO_SHA256, (), "BLOCK", "NOT_EXECUTED", ("host_binding_mismatch",))
        if self._tainted:
            return self._finish(operation, plan, before_state, before_state, before_epoch, before_epoch, ZERO_SHA256, ZERO_SHA256, (), "BLOCK", "NOT_EXECUTED", ("runtime_state_unverified",))
        if plan.plan_sha256 in self._seen_plans:
            return self._finish(operation, plan, before_state, before_state, before_epoch, before_epoch, ZERO_SHA256, ZERO_SHA256, (), "BLOCK", "NOT_EXECUTED", ("plan_replay",))
        if plan.epoch_before != self._epoch:
            return self._finish(operation, plan, before_state, before_state, before_epoch, before_epoch, ZERO_SHA256, ZERO_SHA256, (), "BLOCK", "NOT_EXECUTED", ("stale_runtime_epoch",))

        trusted_before = self._observe()
        if trusted_before.state_sha256 != self._state_sha256 or plan.before_state_sha256 != trusted_before.state_sha256:
            self._state_sha256 = trusted_before.state_sha256
            return self._finish(operation, plan, before_state, trusted_before.state_sha256, before_epoch, before_epoch, ZERO_SHA256, trusted_before.evidence_sha256, (), "BLOCK", "NOT_EXECUTED", ("stale_before_state",))

        captured: dict[str, RuntimeStateEvidence] = {}

        def executor(_: RuntimeOperation) -> ExecutionObservation:
            self.backend.apply(plan)
            after = self._observe()
            captured["after"] = after
            return ExecutionObservation.success({
                "runtime_config_plan_sha256": plan.plan_sha256,
                "after_state_sha256": after.state_sha256,
                "host_evidence_sha256": after.evidence_sha256,
            })

        mediation = self.mediator.mediate(operation, executor)
        if mediation["admission_decision"] != "ALLOW":
            return self._finish(operation, plan, before_state, before_state, before_epoch, before_epoch, mediation["receipt_sha256"], ZERO_SHA256, (), "BLOCK", "NOT_EXECUTED", tuple(mediation["reason_codes"]))

        self._seen_plans.add(plan.plan_sha256)
        after = captured.get("after")
        if mediation["execution_outcome"] == "SUCCEEDED" and after is not None:
            if after.state_sha256 == plan.after_state_sha256:
                revoked = self._advance_epoch(after.state_sha256, operation.at_unix)
                return self._finish(operation, plan, before_state, after.state_sha256, before_epoch, self._epoch, mediation["receipt_sha256"], after.evidence_sha256, revoked, "ALLOW", "SUCCEEDED", ("exact_state_transition", "runtime_epoch_advanced", "old_epoch_authority_revoked"))
            revoked = self._advance_epoch(after.state_sha256, operation.at_unix)
            self._tainted = True
            return self._finish(operation, plan, before_state, after.state_sha256, before_epoch, self._epoch, mediation["receipt_sha256"], after.evidence_sha256, revoked, "BLOCK", "FAILED_CLOSED", ("after_state_mismatch", "runtime_epoch_advanced", "old_epoch_authority_revoked", "runtime_state_tainted"))

        # An admitted host mutation that did not produce a verified success is
        # treated as potentially partial. Try one trusted re-observation, but
        # revoke all old authority regardless: we cannot safely preserve it.
        evidence_sha = ZERO_SHA256
        observed_state = ZERO_SHA256
        try:
            uncertain = self._observe()
            observed_state = uncertain.state_sha256
            evidence_sha = uncertain.evidence_sha256
        except Exception:
            pass
        revoked = self._advance_epoch(observed_state, operation.at_unix)
        self._tainted = True
        return self._finish(operation, plan, before_state, observed_state, before_epoch, self._epoch, mediation["receipt_sha256"], evidence_sha, revoked, "BLOCK", "FAILED_CLOSED", ("host_mutation_unverified", "runtime_epoch_advanced", "old_epoch_authority_revoked", "runtime_state_tainted"))

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def _observe(self) -> RuntimeStateEvidence:
        return RuntimeStateEvidence.from_mapping(self.backend.observe(), expected_host_binding_sha256=self.host_binding_sha256)

    def _advance_epoch(self, state_sha256: str, at_unix: int) -> tuple[str, ...]:
        _sha(state_sha256, "state_sha256")
        self._epoch += 1
        self._state_sha256 = state_sha256
        revoked: list[str] = []
        for item in self.mediator.broker.state_document().get("capabilities", []):
            if item.get("status") != "active":
                continue
            cap_id = item["capability_id"]
            result = self.mediator.broker.revoke(cap_id, at_unix=at_unix)
            if result.get("decision") == "ALLOW":
                revoked.append(cap_id)
        return tuple(sorted(revoked))

    def _finish(
        self,
        operation: RuntimeOperation,
        plan: RuntimeConfigPlan,
        before_state: str,
        after_state: str,
        epoch_before: int,
        epoch_after: int,
        mediation_sha: str,
        host_evidence_sha: str,
        revoked: tuple[str, ...],
        decision: str,
        outcome: str,
        reasons: tuple[str, ...],
    ) -> dict[str, Any]:
        revoked_root = canonical_sha256(list(revoked))
        base = RuntimeConfigReceipt(
            operation_id=operation.operation_id,
            plan_sha256=plan.plan_sha256,
            before_state_sha256=before_state,
            after_state_sha256=after_state,
            epoch_before=epoch_before,
            epoch_after=epoch_after,
            mediation_receipt_sha256=mediation_sha,
            host_evidence_sha256=host_evidence_sha,
            revoked_authority_count=len(revoked),
            revoked_authority_set_sha256=revoked_root,
            decision=decision,
            outcome=outcome,
            reason_codes=tuple(sorted(set(reasons))),
            receipt_sha256="",
        )
        receipt = RuntimeConfigReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != SCHEMA or raw.get("authority") != AUTHORITY:
        raise RuntimeConfigError("runtime configuration receipt schema or authority mismatch")
    for key in (
        "plan_sha256", "before_state_sha256", "after_state_sha256",
        "mediation_receipt_sha256", "host_evidence_sha256", "revoked_authority_set_sha256",
    ):
        _sha(raw.get(key), key)
    if raw.get("decision") not in {"ALLOW", "BLOCK"}:
        raise RuntimeConfigError("unsupported runtime configuration decision")
    if raw.get("outcome") not in {"SUCCEEDED", "NOT_EXECUTED", "FAILED_CLOSED"}:
        raise RuntimeConfigError("unsupported runtime configuration outcome")
    for key in ("epoch_before", "epoch_after", "revoked_authority_count"):
        if isinstance(raw.get(key), bool) or not isinstance(raw.get(key), int) or raw[key] < 0:
            raise RuntimeConfigError(f"invalid {key}")
    if raw["epoch_after"] < raw["epoch_before"]:
        raise RuntimeConfigError("runtime epoch cannot move backwards")
    if digest != canonical_sha256(raw):
        raise RuntimeConfigError("runtime configuration receipt digest mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY", "BoundRuntimeConfigBroker", "PLAN_SCHEMA", "RuntimeConfigBackend",
    "RuntimeConfigError", "RuntimeConfigPlan", "RuntimeConfigReceipt", "RuntimeStateEvidence",
    "SCHEMA", "STATE_SCHEMA", "ZERO_SHA256", "verify_receipt",
]
