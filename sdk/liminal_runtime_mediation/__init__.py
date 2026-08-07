"""Reference runtime mediation layer for LiminalOS v1.3.

This package is a host-integrated admission path, not an OS sandbox. It never
opens sockets, starts subprocesses, mutates files, installs packages or reads
credential material directly. Sensitive effects happen only inside injected
host callbacks after capability admission.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_escalation import TrajectoryEvent
from sdk.liminal_egress_gateway import EgressBlocked, EgressGateway, GatewayRequest
from sdk.liminal_post_sandbox_contracts import ContractError, canonical_sha256, validate_scope

SCHEMA = "liminal-runtime-mediation-receipt-v0.1"
ZERO_SHA256 = "0" * 64

OPERATION_TO_CAPABILITY = {
    "process.execute": "process.execute",
    "process.spawn_child": "process.spawn_child",
    "package.install": "package.install",
    "filesystem.write_outside_workspace": "filesystem.write_outside_workspace",
    "credential.access": "credential.access",
    "runtime.configure": "runtime.configure",
}

# Phase 3 currently has no dedicated filesystem-outside-workspace event kind.
# Until that schema evolves, the projection uses the existing generic write
# signal and preserves the exact runtime kind in the event metadata digest.
PHASE3_KIND = {
    **{kind: kind for kind in OPERATION_TO_CAPABILITY if kind != "filesystem.write_outside_workspace"},
    "filesystem.write_outside_workspace": "repository.write",
}

AUTHORITY = {
    "mode": "host_integrated_runtime_mediation",
    "capability_admission": True,
    "host_callback_dispatch": True,
    "network_via_egress_gateway": True,
    "direct_subprocess_execution": False,
    "direct_socket_creation": False,
    "direct_filesystem_mutation": False,
    "direct_package_installation": False,
    "credential_material_export": False,
    "os_kernel_enforcement": False,
    "seccomp_ebpf_apparmor_enforcement": False,
    "deployment": False,
    "automatic_release": False,
}


class MediationError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeOperation:
    operation_id: str
    subject_id: str
    policy_sha256: str
    kind: str
    scope: Mapping[str, Any]
    payload_sha256: str
    at_unix: int
    privilege_level_before: int = 0
    privilege_level_after: int = 0

    def normalized_scope(self) -> dict[str, Any]:
        if self.kind not in OPERATION_TO_CAPABILITY:
            raise MediationError("unsupported runtime operation kind")
        try:
            return validate_scope(OPERATION_TO_CAPABILITY[self.kind], dict(self.scope))
        except ContractError as exc:
            raise MediationError(str(exc)) from exc

    def validate(self) -> None:
        for value, name in ((self.operation_id, "operation_id"), (self.subject_id, "subject_id")):
            if not isinstance(value, str) or not value.strip():
                raise MediationError(f"{name} must be non-empty")
        _sha(self.policy_sha256, "policy_sha256")
        _sha(self.payload_sha256, "payload_sha256")
        if not isinstance(self.at_unix, int) or isinstance(self.at_unix, bool) or self.at_unix < 0:
            raise MediationError("at_unix must be non-negative")
        for value, name in ((self.privilege_level_before, "privilege_level_before"), (self.privilege_level_after, "privilege_level_after")):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                raise MediationError(f"{name} must be between 0 and 10")
        self.normalized_scope()


@dataclass(frozen=True)
class ExecutionObservation:
    outcome: str
    result_sha256: str

    @classmethod
    def success(cls, safe_metadata: Mapping[str, Any]) -> "ExecutionObservation":
        return cls("SUCCEEDED", canonical_sha256(dict(safe_metadata)))

    def validate(self) -> None:
        if self.outcome != "SUCCEEDED":
            raise MediationError("host observation outcome must be SUCCEEDED")
        _sha(self.result_sha256, "result_sha256")


@dataclass(frozen=True)
class RuntimeMediationReceipt:
    operation_id: str
    subject_id: str
    runtime_kind: str
    policy_sha256: str
    scope_sha256: str
    payload_sha256: str
    capability_receipt_sha256: str
    admission_decision: str
    execution_outcome: str
    result_sha256: str
    reason_codes: tuple[str, ...]
    trajectory_event_sha256: str
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "operation_id": self.operation_id,
            "subject_id": self.subject_id,
            "runtime_kind": self.runtime_kind,
            "policy_sha256": self.policy_sha256,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "admission_decision": self.admission_decision,
            "execution_outcome": self.execution_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "trajectory_event_sha256": self.trajectory_event_sha256,
            "at_unix": self.at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


Executor = Callable[[RuntimeOperation], ExecutionObservation]


class RuntimeMediator:
    def __init__(self, *, broker: CapabilityBroker, egress_gateway: EgressGateway | None = None) -> None:
        self.broker = broker
        self.egress_gateway = egress_gateway
        self._contained = False
        self._containment_evidence_sha256 = ZERO_SHA256
        self._receipts: list[RuntimeMediationReceipt] = []
        self._events: list[TrajectoryEvent] = []
        self._event_head = ZERO_SHA256

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        self._containment_evidence_sha256 = _sha(incident_receipt_sha256, "incident_receipt_sha256")
        self._contained = True

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        # The Phase 4 component remains responsible for verifying human release.
        # This hook only consumes a verified external receipt digest.
        self._containment_evidence_sha256 = _sha(human_release_receipt_sha256, "human_release_receipt_sha256")
        self._contained = False

    def mediate(self, operation: RuntimeOperation, executor: Executor) -> dict[str, Any]:
        operation.validate()
        scope = operation.normalized_scope()
        scope_sha = canonical_sha256(scope)
        if self._contained:
            return self._finish(
                operation=operation, capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=("containment_active",), capability_id=None, scope_sha=scope_sha,
            )

        capability = self.broker.authorize(
            subject_id=operation.subject_id,
            capability_type=OPERATION_TO_CAPABILITY[operation.kind],
            policy_sha256=operation.policy_sha256,
            requested_scope=scope,
            action={
                "operation_id": operation.operation_id,
                "runtime_kind": operation.kind,
                "scope_sha256": scope_sha,
                "payload_sha256": operation.payload_sha256,
            },
            at_unix=operation.at_unix,
        )
        if capability["decision"] != "ALLOW":
            return self._finish(
                operation=operation, capability_receipt_sha=capability["receipt_sha256"],
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=tuple(capability["reason_codes"]), capability_id=None, scope_sha=scope_sha,
            )

        try:
            observation = executor(operation)
            if not isinstance(observation, ExecutionObservation):
                raise MediationError("executor must return ExecutionObservation")
            observation.validate()
        except Exception as exc:
            # Error messages are intentionally excluded because they may contain
            # command lines, paths, tokens or other host-sensitive material.
            return self._finish(
                operation=operation, capability_receipt_sha=capability["receipt_sha256"],
                admission="ALLOW", outcome="FAILED",
                result_sha=canonical_sha256({"error_type": type(exc).__name__}),
                reasons=("executor_failed",), capability_id=capability.get("capability_id"), scope_sha=scope_sha,
            )

        return self._finish(
            operation=operation, capability_receipt_sha=capability["receipt_sha256"],
            admission="ALLOW", outcome="SUCCEEDED", result_sha=observation.result_sha256,
            reasons=("capability_admitted", "host_executor_succeeded"),
            capability_id=capability.get("capability_id"), scope_sha=scope_sha,
        )

    def mediate_network(self, request: GatewayRequest) -> dict[str, Any]:
        if self.egress_gateway is None:
            raise MediationError("network mediation requires EgressGateway")
        if self._contained:
            operation = RuntimeOperation(
                operation_id=request.call_id, subject_id=request.subject_id,
                policy_sha256=request.policy_sha256, kind="runtime.configure",
                scope={"setting_keys": ["egress_blocked_by_containment"]},
                payload_sha256=request.body_sha256, at_unix=request.at_unix,
            )
            return self._finish(
                operation=operation, capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK", outcome="NOT_EXECUTED", result_sha=ZERO_SHA256,
                reasons=("containment_active", "network_blocked"), capability_id=None,
                scope_sha=canonical_sha256({"network_request_sha256": canonical_sha256({"call_id": request.call_id, "url_sha256": canonical_sha256(request.url)})}),
                event_kind_override="network.connect_domain",
            )
        try:
            network = self.egress_gateway.execute(request)
        except EgressBlocked as exc:
            operation = RuntimeOperation(
                operation_id=request.call_id, subject_id=request.subject_id,
                policy_sha256=request.policy_sha256, kind="runtime.configure",
                scope={"setting_keys": ["egress_gateway_block"]},
                payload_sha256=request.body_sha256, at_unix=request.at_unix,
            )
            return self._finish(
                operation=operation, capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK", outcome="NOT_EXECUTED",
                result_sha=canonical_sha256({"error_type": type(exc).__name__}),
                reasons=("egress_gateway_blocked",), capability_id=None,
                scope_sha=canonical_sha256({"network_request_sha256": canonical_sha256({"call_id": request.call_id, "url_sha256": canonical_sha256(request.url)})}),
                event_kind_override="network.connect_domain",
            )
        operation = RuntimeOperation(
            operation_id=request.call_id, subject_id=request.subject_id,
            policy_sha256=request.policy_sha256, kind="runtime.configure",
            scope={"setting_keys": ["egress_gateway_success"]},
            payload_sha256=request.body_sha256, at_unix=request.at_unix,
        )
        return self._finish(
            operation=operation,
            capability_receipt_sha=network["capability_receipt_sha256"],
            admission="ALLOW", outcome="SUCCEEDED",
            result_sha=network["receipt_sha256"],
            reasons=("egress_gateway_mediated",), capability_id=None,
            scope_sha=canonical_sha256({"network_receipt_sha256": network["receipt_sha256"]}),
            event_kind_override="network.connect_domain",
        )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def trajectory_events(self) -> tuple[TrajectoryEvent, ...]:
        return tuple(self._events)

    def _finish(self, *, operation: RuntimeOperation, capability_receipt_sha: str,
                admission: str, outcome: str, result_sha: str, reasons: tuple[str, ...],
                capability_id: str | None, scope_sha: str, event_kind_override: str | None = None) -> dict[str, Any]:
        event_kind = event_kind_override or PHASE3_KIND[operation.kind]
        event_decision = "ALLOW" if admission == "ALLOW" and outcome == "SUCCEEDED" else "BLOCK"
        event = TrajectoryEvent.build(
            event_id=f"runtime-event:{len(self._events)+1}", sequence=len(self._events)+1,
            observed_at_unix=operation.at_unix, kind=event_kind, decision=event_decision,
            subject_id=operation.subject_id, capability_id=capability_id,
            privilege_level_before=operation.privilege_level_before,
            privilege_level_after=operation.privilege_level_after if event_decision == "ALLOW" else operation.privilege_level_before,
            metadata={
                "operation_id": operation.operation_id,
                "runtime_kind": operation.kind if event_kind_override is None else event_kind_override,
                "payload_sha256": operation.payload_sha256,
                "scope_sha256": scope_sha,
                "outcome": outcome,
                "containment_evidence_sha256": self._containment_evidence_sha256,
            },
            previous_event_sha256=self._event_head,
        )
        self._events.append(event)
        self._event_head = event.event_sha256
        base = RuntimeMediationReceipt(
            operation_id=operation.operation_id, subject_id=operation.subject_id,
            runtime_kind=event_kind_override or operation.kind, policy_sha256=operation.policy_sha256,
            scope_sha256=scope_sha, payload_sha256=operation.payload_sha256,
            capability_receipt_sha256=capability_receipt_sha,
            admission_decision=admission, execution_outcome=outcome,
            result_sha256=result_sha, reason_codes=tuple(sorted(set(reasons))),
            trajectory_event_sha256=event.event_sha256, at_unix=operation.at_unix,
            receipt_sha256="",
        )
        receipt = RuntimeMediationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    receipt_sha = raw.pop("receipt_sha256", None)
    if raw.get("schema") != SCHEMA or raw.get("authority") != AUTHORITY:
        raise MediationError("receipt schema or authority boundary mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise MediationError("runtime mediation receipt digest mismatch")
    return dict(document)


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise MediationError(f"{name} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "AUTHORITY", "ExecutionObservation", "MediationError", "OPERATION_TO_CAPABILITY",
    "RuntimeMediationReceipt", "RuntimeMediator", "RuntimeOperation", "SCHEMA", "verify_receipt",
]
