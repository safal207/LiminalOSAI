"""Epoch-bound one-time effect commit leases for LiminalOS.

This layer closes the mediated-host TOCTOU window between an ALLOW decision and
its trusted host callback. It never grants authority. A lease is bound to the
exact capability decision, operation, runtime world, execution-session evidence
and trusted host, then consumed exactly once under a shared runtime commit
fence immediately before the effect callback.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping, Protocol

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_config import BoundRuntimeConfigBroker
from sdk.liminal_runtime_mediation import (
    ExecutionObservation,
    MediationError,
    OPERATION_TO_CAPABILITY,
    RuntimeMediator,
    RuntimeOperation,
)

LEASE_SCHEMA = "liminal-epoch-bound-effect-lease-v0.1"
COMMIT_SCHEMA = "liminal-epoch-bound-effect-commit-receipt-v0.1"
SESSION_SCHEMA = "liminal-trusted-execution-session-v0.1"
ZERO_SHA256 = "0" * 64
MAX_LEASE_TTL_SECONDS = 30

AUTHORITY = {
    "mode": "epoch_bound_effect_commit_only",
    "capability_grant": False,
    "runtime_mutation": False,
    "effect_commit": True,
    "one_time_lease": True,
    "trusted_runtime_recheck": True,
    "trusted_session_recheck": True,
    "shared_runtime_commit_fence": True,
    "containment_gate": True,
    "raw_runtime_values": False,
    "raw_session_identity": False,
    "secret_material_access": False,
    "network_authority": False,
    "kernel_enforcement": False,
}


class EffectCommitError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RuntimeWorldProvider(Protocol):
    def state_document(self) -> Mapping[str, Any]: ...


class ExecutionSessionProvider(Protocol):
    def session_document(self, operation_id: str) -> Mapping[str, Any]: ...


class RuntimeCommitFence:
    """Trusted in-process serialization point for runtime mutation/effect commit.

    This is not a kernel lock. It is effective only when every governed runtime
    mutation and committed effect uses the same fence instance.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self._lock:
            yield


class FencedBoundRuntimeConfigBroker(BoundRuntimeConfigBroker):
    """BoundRuntimeConfigBroker serialized by the shared commit fence."""

    def __init__(self, *, commit_fence: RuntimeCommitFence, **kwargs: Any) -> None:
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise EffectCommitError("invalid_runtime_commit_fence")
        self.commit_fence = commit_fence
        super().__init__(**kwargs)

    def execute(self, *, operation: RuntimeOperation, plan: Any) -> dict[str, Any]:
        with self.commit_fence.hold():
            return super().execute(operation=operation, plan=plan)


@dataclass(frozen=True)
class TrustedRuntimeWorld:
    epoch: int
    state_sha256: str
    tainted: bool
    snapshot_sha256: str

    @classmethod
    def observe(cls, provider: RuntimeWorldProvider) -> "TrustedRuntimeWorld":
        raw = dict(provider.state_document())
        epoch = raw.get("epoch", raw.get("runtime_epoch"))
        state = raw.get("state_sha256", raw.get("runtime_state_sha256"))
        tainted = raw.get("tainted", raw.get("runtime_tainted"))
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise EffectCommitError("invalid_runtime_epoch")
        _sha(state, "runtime_state_sha256")
        if type(tainted) is not bool:
            raise EffectCommitError("invalid_runtime_taint_state")
        body = {"epoch": epoch, "state_sha256": state, "tainted": tainted}
        return cls(epoch, state, tainted, canonical_sha256(body))


@dataclass(frozen=True)
class TrustedExecutionSession:
    operation_id_sha256: str
    session_sha256: str
    host_binding_sha256: str
    active: bool
    evidence_sha256: str

    @classmethod
    def observe(
        cls,
        provider: ExecutionSessionProvider,
        *,
        operation_id: str,
        expected_host_binding_sha256: str,
    ) -> "TrustedExecutionSession":
        raw = dict(provider.session_document(operation_id))
        expected = {
            "schema", "operation_id_sha256", "session_sha256",
            "host_binding_sha256", "active", "evidence_sha256",
        }
        if set(raw) != expected or raw.get("schema") != SESSION_SCHEMA:
            raise EffectCommitError("execution_session_schema_mismatch")
        operation_sha = _sha(raw["operation_id_sha256"], "operation_id_sha256")
        if operation_sha != canonical_sha256(operation_id):
            raise EffectCommitError("execution_session_operation_mismatch")
        session_sha = _sha(raw["session_sha256"], "session_sha256")
        host_sha = _sha(raw["host_binding_sha256"], "host_binding_sha256")
        if host_sha != expected_host_binding_sha256:
            raise EffectCommitError("execution_session_host_mismatch")
        active = raw["active"]
        if type(active) is not bool:
            raise EffectCommitError("execution_session_active_invalid")
        body = {
            "schema": SESSION_SCHEMA,
            "operation_id_sha256": operation_sha,
            "session_sha256": session_sha,
            "host_binding_sha256": host_sha,
            "active": active,
        }
        evidence = _sha(raw["evidence_sha256"], "evidence_sha256")
        if evidence != canonical_sha256(body):
            raise EffectCommitError("execution_session_evidence_mismatch")
        return cls(operation_sha, session_sha, host_sha, active, evidence)


@dataclass(frozen=True)
class EffectCommitAuthorizationReceipt:
    operation_id: str
    lease_id_sha256: str
    capability_id: str
    capability_receipt_sha256: str
    bound_contract_sha256: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    runtime_epoch: int
    runtime_state_sha256: str
    runtime_snapshot_sha256: str
    execution_session_sha256: str
    execution_session_evidence_sha256: str
    host_binding_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": LEASE_SCHEMA,
            "operation_id": self.operation_id,
            "lease_id_sha256": self.lease_id_sha256,
            "capability_id": self.capability_id,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "bound_contract_sha256": self.bound_contract_sha256,
            "runtime_kind": self.runtime_kind,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "runtime_epoch": self.runtime_epoch,
            "runtime_state_sha256": self.runtime_state_sha256,
            "runtime_snapshot_sha256": self.runtime_snapshot_sha256,
            "execution_session_sha256": self.execution_session_sha256,
            "execution_session_evidence_sha256": self.execution_session_evidence_sha256,
            "host_binding_sha256": self.host_binding_sha256,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class EffectCommitReceipt:
    operation_id: str
    authorization_receipt_sha256: str
    lease_id_sha256: str
    runtime_epoch: int
    runtime_state_sha256: str
    runtime_snapshot_sha256: str
    execution_session_sha256: str
    execution_session_evidence_sha256: str
    capability_receipt_sha256: str
    committed_at_unix: int
    effect_outcome: str
    result_sha256: str
    reason_codes: tuple[str, ...]
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": COMMIT_SCHEMA,
            "operation_id": self.operation_id,
            "authorization_receipt_sha256": self.authorization_receipt_sha256,
            "lease_id_sha256": self.lease_id_sha256,
            "runtime_epoch": self.runtime_epoch,
            "runtime_state_sha256": self.runtime_state_sha256,
            "runtime_snapshot_sha256": self.runtime_snapshot_sha256,
            "execution_session_sha256": self.execution_session_sha256,
            "execution_session_evidence_sha256": self.execution_session_evidence_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "committed_at_unix": self.committed_at_unix,
            "effect_outcome": self.effect_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _Lease:
    lease_id: str
    operation: RuntimeOperation
    capability_id: str
    capability_receipt_sha256: str
    bound_contract_sha256: str
    scope_sha256: str
    runtime_world: TrustedRuntimeWorld
    session: TrustedExecutionSession
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


class EffectCommitBroker:
    def __init__(
        self,
        *,
        runtime_provider: RuntimeWorldProvider,
        session_provider: ExecutionSessionProvider,
        capability_broker: Any,
        host_binding_sha256: str,
        adapter_token_sha256: str,
        commit_fence: RuntimeCommitFence,
        lease_ttl_seconds: int = 10,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.runtime_provider = runtime_provider
        self.session_provider = session_provider
        self.capability_broker = capability_broker
        self.host_binding_sha256 = _sha(host_binding_sha256, "host_binding_sha256")
        self.adapter_token_sha256 = _sha(adapter_token_sha256, "adapter_token_sha256")
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise EffectCommitError("invalid_runtime_commit_fence")
        if isinstance(lease_ttl_seconds, bool) or not isinstance(lease_ttl_seconds, int) or not 1 <= lease_ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise EffectCommitError("invalid_lease_ttl_seconds")
        self.commit_fence = commit_fence
        self.lease_ttl_seconds = lease_ttl_seconds
        self.clock = clock or (lambda: int(time.time()))
        self._leases: dict[str, _Lease] = {}
        self._authorizations: list[EffectCommitAuthorizationReceipt] = []
        self._commits: list[EffectCommitReceipt] = []
        self._contained = False
        self._lock = threading.RLock()

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        _sha(incident_receipt_sha256, "incident_receipt_sha256")
        with self._lock:
            self._contained = True

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        _sha(human_release_receipt_sha256, "human_release_receipt_sha256")
        with self._lock:
            self._contained = False

    def issue_for_trusted_adapter(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        operation.validate()
        capability = dict(capability_decision)
        if capability.get("decision") != "ALLOW":
            raise EffectCommitError("capability_decision_not_allow")
        capability_id = capability.get("capability_id")
        if not isinstance(capability_id, str) or not capability_id:
            raise EffectCommitError("capability_id_missing")
        capability_receipt_sha = _sha(capability.get("receipt_sha256"), "capability_receipt_sha256")
        bound_contract_sha = _sha(capability.get("bound_contract_sha256", ZERO_SHA256), "bound_contract_sha256")
        if bound_contract_sha == ZERO_SHA256:
            raise EffectCommitError("capability_decision_not_epoch_bound")

        with self._lock:
            if self._contained:
                raise EffectCommitError("containment_active")
            now = self._now()
            world = TrustedRuntimeWorld.observe(self.runtime_provider)
            if world.tainted:
                raise EffectCommitError("runtime_state_tainted")
            session = TrustedExecutionSession.observe(
                self.session_provider,
                operation_id=operation.operation_id,
                expected_host_binding_sha256=self.host_binding_sha256,
            )
            if not session.active:
                raise EffectCommitError("execution_session_inactive")
            if not self._capability_active(capability_id, world):
                raise EffectCommitError("source_capability_inactive_or_stale")
            scope_sha = canonical_sha256(operation.normalized_scope())
            lease_id = f"effect-lease:{len(self._leases)+1}:{canonical_sha256({'operation': operation.operation_id, 'capability': capability_receipt_sha, 'world': world.snapshot_sha256, 'session': session.session_sha256})[:20]}"
            expires = now + self.lease_ttl_seconds
            provisional = EffectCommitAuthorizationReceipt(
                operation_id=operation.operation_id,
                lease_id_sha256=canonical_sha256(lease_id),
                capability_id=capability_id,
                capability_receipt_sha256=capability_receipt_sha,
                bound_contract_sha256=bound_contract_sha,
                runtime_kind=operation.kind,
                scope_sha256=scope_sha,
                payload_sha256=operation.payload_sha256,
                runtime_epoch=world.epoch,
                runtime_state_sha256=world.state_sha256,
                runtime_snapshot_sha256=world.snapshot_sha256,
                execution_session_sha256=session.session_sha256,
                execution_session_evidence_sha256=session.evidence_sha256,
                host_binding_sha256=self.host_binding_sha256,
                issued_at_unix=now,
                expires_at_unix=expires,
                receipt_sha256="",
            )
            receipt = EffectCommitAuthorizationReceipt(**{
                **provisional.__dict__,
                "receipt_sha256": canonical_sha256(provisional.body()),
            })
            self._authorizations.append(receipt)
            self._leases[lease_id] = _Lease(
                lease_id=lease_id,
                operation=operation,
                capability_id=capability_id,
                capability_receipt_sha256=capability_receipt_sha,
                bound_contract_sha256=bound_contract_sha,
                scope_sha256=scope_sha,
                runtime_world=world,
                session=session,
                authorization_receipt_sha256=receipt.receipt_sha256,
                issued_at_unix=now,
                expires_at_unix=expires,
            )
            return lease_id, receipt.as_document()

    def consume_for_trusted_adapter(
        self,
        lease_id: str,
        *,
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        if not isinstance(adapter_token, str) or not adapter_token:
            raise EffectCommitError("adapter_auth_failed")
        supplied = hashlib.sha256(adapter_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(supplied, self.adapter_token_sha256):
            raise EffectCommitError("adapter_auth_failed")
        return self._commit(lease_id, executor)

    def commit_authorized_effect(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        """Trusted RuntimeMediator integration path; opaque lease never leaves host code."""
        lease_id, _ = self.issue_for_trusted_adapter(
            operation=operation,
            capability_decision=capability_decision,
        )
        return self._commit(lease_id, executor)

    def authorization_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._authorizations)

    def commit_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._commits)

    def state_document(self) -> dict[str, Any]:
        with self._lock:
            body = {
                "schema": "liminal-effect-commit-state-v0.1",
                "lease_count": len(self._leases),
                "consumed_count": sum(1 for item in self._leases.values() if item.consumed),
                "contained": self._contained,
                "authorization_count": len(self._authorizations),
                "commit_count": len(self._commits),
                "authority": AUTHORITY,
            }
            return {**body, "state_sha256": canonical_sha256(body)}

    def _commit(
        self,
        lease_id: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        with self.commit_fence.hold():
            with self._lock:
                now = self._now()
                if self._contained:
                    raise EffectCommitError("containment_active")
                lease = self._leases.get(lease_id)
                if lease is None:
                    raise EffectCommitError("unknown_lease")
                if lease.consumed:
                    raise EffectCommitError("lease_replayed")
                if now < lease.issued_at_unix:
                    raise EffectCommitError("clock_regression")
                if now > lease.expires_at_unix:
                    raise EffectCommitError("lease_expired")

                world = TrustedRuntimeWorld.observe(self.runtime_provider)
                if world.tainted:
                    raise EffectCommitError("runtime_state_tainted")
                if world.epoch != lease.runtime_world.epoch:
                    raise EffectCommitError("stale_runtime_epoch")
                if world.state_sha256 != lease.runtime_world.state_sha256:
                    raise EffectCommitError("stale_runtime_state")

                session = TrustedExecutionSession.observe(
                    self.session_provider,
                    operation_id=lease.operation.operation_id,
                    expected_host_binding_sha256=self.host_binding_sha256,
                )
                if not session.active:
                    raise EffectCommitError("execution_session_inactive")
                if session.session_sha256 != lease.session.session_sha256:
                    raise EffectCommitError("execution_session_changed")
                if not self._capability_active(lease.capability_id, world):
                    raise EffectCommitError("source_capability_inactive_or_stale")

                # One-time lease is burned before the callback. A failed callback
                # can never be retried with the same authority token.
                lease.consumed = True
                try:
                    observation = executor(lease.operation)
                    if not isinstance(observation, ExecutionObservation):
                        raise EffectCommitError("executor_observation_invalid")
                    observation.validate()
                except Exception as exc:
                    self._append_commit(
                        lease=lease,
                        world=world,
                        session=session,
                        committed_at_unix=now,
                        outcome="FAILED",
                        result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                        reasons=("lease_consumed", "effect_callback_failed"),
                    )
                    if isinstance(exc, EffectCommitError):
                        raise
                    raise EffectCommitError("effect_callback_failed") from exc

                self._append_commit(
                    lease=lease,
                    world=world,
                    session=session,
                    committed_at_unix=now,
                    outcome="SUCCEEDED",
                    result_sha256=observation.result_sha256,
                    reasons=("runtime_world_rechecked", "execution_session_rechecked", "source_capability_active", "lease_consumed", "effect_committed_under_fence"),
                )
                return observation

    def _append_commit(
        self,
        *,
        lease: _Lease,
        world: TrustedRuntimeWorld,
        session: TrustedExecutionSession,
        committed_at_unix: int,
        outcome: str,
        result_sha256: str,
        reasons: tuple[str, ...],
    ) -> None:
        provisional = EffectCommitReceipt(
            operation_id=lease.operation.operation_id,
            authorization_receipt_sha256=lease.authorization_receipt_sha256,
            lease_id_sha256=canonical_sha256(lease.lease_id),
            runtime_epoch=world.epoch,
            runtime_state_sha256=world.state_sha256,
            runtime_snapshot_sha256=world.snapshot_sha256,
            execution_session_sha256=session.session_sha256,
            execution_session_evidence_sha256=session.evidence_sha256,
            capability_receipt_sha256=lease.capability_receipt_sha256,
            committed_at_unix=committed_at_unix,
            effect_outcome=outcome,
            result_sha256=_sha(result_sha256, "result_sha256"),
            reason_codes=tuple(sorted(set(reasons))),
            receipt_sha256="",
        )
        receipt = EffectCommitReceipt(**{
            **provisional.__dict__,
            "receipt_sha256": canonical_sha256(provisional.body()),
        })
        self._commits.append(receipt)

    def _capability_active(self, capability_id: str, world: TrustedRuntimeWorld) -> bool:
        try:
            state = dict(self.capability_broker.state_document())
        except Exception:
            return False
        for item in state.get("capabilities", []):
            if item.get("capability_id") != capability_id:
                continue
            if item.get("status") != "active":
                return False
            if item.get("epoch_bound") is not True:
                return False
            if item.get("runtime_epoch") != world.epoch:
                return False
            if item.get("runtime_state_sha256") != world.state_sha256:
                return False
            return True
        return False

    def _now(self) -> int:
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EffectCommitError("invalid_trusted_clock")
        return value


class EpochBoundEffectRuntimeMediator(RuntimeMediator):
    """Opt-in RuntimeMediator path that commits effects through one-time leases."""

    def __init__(self, *, effect_commit_broker: EffectCommitBroker, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.effect_commit_broker = effect_commit_broker

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        super().enter_containment(incident_receipt_sha256=incident_receipt_sha256)
        self.effect_commit_broker.enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        self.effect_commit_broker.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)
        super().exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def mediate(self, operation: RuntimeOperation, executor: Callable[[RuntimeOperation], ExecutionObservation]) -> dict[str, Any]:
        operation.validate()
        scope = operation.normalized_scope()
        scope_sha = canonical_sha256(scope)
        if self._contained:
            return self._finish(
                operation=operation,
                capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK",
                outcome="NOT_EXECUTED",
                result_sha=ZERO_SHA256,
                reasons=("containment_active", "effect_commit_blocked"),
                capability_id=None,
                scope_sha=scope_sha,
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
                operation=operation,
                capability_receipt_sha=capability["receipt_sha256"],
                admission="BLOCK",
                outcome="NOT_EXECUTED",
                result_sha=ZERO_SHA256,
                reasons=tuple(capability["reason_codes"]),
                capability_id=None,
                scope_sha=scope_sha,
            )

        try:
            observation = self.effect_commit_broker.commit_authorized_effect(
                operation=operation,
                capability_decision=capability,
                executor=executor,
            )
        except Exception as exc:
            return self._finish(
                operation=operation,
                capability_receipt_sha=capability["receipt_sha256"],
                admission="ALLOW",
                outcome="FAILED",
                result_sha=canonical_sha256({"error_type": type(exc).__name__}),
                reasons=("effect_commit_failed",),
                capability_id=capability.get("capability_id"),
                scope_sha=scope_sha,
            )

        return self._finish(
            operation=operation,
            capability_receipt_sha=capability["receipt_sha256"],
            admission="ALLOW",
            outcome="SUCCEEDED",
            result_sha=observation.result_sha256,
            reasons=("capability_admitted", "effect_commit_lease_consumed", "host_executor_succeeded"),
            capability_id=capability.get("capability_id"),
            scope_sha=scope_sha,
        )


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != LEASE_SCHEMA or raw.get("authority") != AUTHORITY:
        raise EffectCommitError("lease_receipt_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise EffectCommitError("lease_receipt_digest_mismatch")
    return dict(document)


def verify_commit_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != COMMIT_SCHEMA or raw.get("authority") != AUTHORITY:
        raise EffectCommitError("commit_receipt_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise EffectCommitError("commit_receipt_digest_mismatch")
    return dict(document)


def build_session_document(
    *,
    operation_id: str,
    session_sha256: str,
    host_binding_sha256: str,
    active: bool,
) -> dict[str, Any]:
    _sha(session_sha256, "session_sha256")
    _sha(host_binding_sha256, "host_binding_sha256")
    if type(active) is not bool:
        raise EffectCommitError("execution_session_active_invalid")
    body = {
        "schema": SESSION_SCHEMA,
        "operation_id_sha256": canonical_sha256(operation_id),
        "session_sha256": session_sha256,
        "host_binding_sha256": host_binding_sha256,
        "active": active,
    }
    return {**body, "evidence_sha256": canonical_sha256(body)}


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise EffectCommitError(f"invalid_{name}")
    return value


__all__ = [
    "AUTHORITY", "COMMIT_SCHEMA", "EffectCommitAuthorizationReceipt", "EffectCommitBroker",
    "EffectCommitError", "EffectCommitReceipt", "EpochBoundEffectRuntimeMediator",
    "ExecutionSessionProvider", "FencedBoundRuntimeConfigBroker", "LEASE_SCHEMA",
    "MAX_LEASE_TTL_SECONDS", "RuntimeCommitFence", "RuntimeWorldProvider", "SESSION_SCHEMA",
    "TrustedExecutionSession", "TrustedRuntimeWorld", "build_session_document",
    "verify_authorization_receipt", "verify_commit_receipt",
]
