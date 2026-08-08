"""Objective-bound composition for LiminalOS effect commits.

This module composes the Objective Integrity Guard with the existing epoch-bound
EffectCommitBroker without changing either v0.1 schema.  An outer one-time lease
binds an exact objective ALLOW decision and observation head to the existing
runtime/session-bound inner lease. Trusted objective observations and the final
host effect share the same RuntimeCommitFence, closing the mediated-host TOCTOU
window between method-integrity approval and physical effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sdk.liminal_effect_commit import (
    EffectCommitBroker,
    EffectCommitError,
    RuntimeCommitFence,
    ZERO_SHA256,
    verify_authorization_receipt as verify_inner_authorization_receipt,
)
from sdk.liminal_objective_integrity import (
    ObjectiveIntegrityGuard,
    verify_decision,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import (
    ExecutionObservation,
    OPERATION_TO_CAPABILITY,
    RuntimeMediator,
    RuntimeOperation,
)

LEASE_SCHEMA = "liminal-objective-bound-effect-lease-v0.1"
COMMIT_SCHEMA = "liminal-objective-bound-effect-commit-v0.1"
STATE_SCHEMA = "liminal-objective-bound-effect-state-v0.1"

AUTHORITY = {
    "mode": "objective_bound_effect_commit_composition",
    "objective_head_binding": True,
    "objective_policy_binding": True,
    "objective_state_recheck": True,
    "shared_objective_runtime_fence": True,
    "one_time_outer_lease": True,
    "inner_epoch_effect_lease_required": True,
    "capability_grant": False,
    "objective_policy_mutation": False,
    "trusted_observation_fabrication": False,
    "runtime_mutation": False,
    "network_authority": False,
    "credential_authority": False,
    "hidden_answer_access": False,
    "evaluator_state_access": False,
    "kernel_enforcement": False,
}


class ObjectiveEffectCommitError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(value: Any, name: str, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ObjectiveEffectCommitError(f"invalid_{name}")
    if not allow_zero and value == ZERO_SHA256:
        raise ObjectiveEffectCommitError(f"zero_{name}")
    return value


def _time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ObjectiveEffectCommitError(f"invalid_{name}")
    return value


class FencedObjectiveIntegrityGuard(ObjectiveIntegrityGuard):
    """Objective Integrity Guard whose mutable/read state shares RuntimeCommitFence.

    The security claim applies only when trusted observation ingestion,
    containment transitions, objective decisions and effect commits all use the
    same fence instance. This class does not make the fence a kernel boundary.
    """

    def __init__(self, *, commit_fence: RuntimeCommitFence, **kwargs: Any) -> None:
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise ObjectiveEffectCommitError("invalid_runtime_commit_fence")
        self.commit_fence = commit_fence
        super().__init__(**kwargs)

    def ingest_observation(self, document: Mapping[str, Any]) -> dict[str, Any]:
        with self.commit_fence.hold():
            return super().ingest_observation(document)

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            super().enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            super().exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def evaluate_action(self, action: Any) -> dict[str, Any]:
        with self.commit_fence.hold():
            return super().evaluate_action(action)

    def verify_completion(self, **kwargs: Any) -> dict[str, Any]:
        with self.commit_fence.hold():
            return super().verify_completion(**kwargs)

    def state_document(self) -> dict[str, Any]:
        with self.commit_fence.hold():
            return super().state_document()


@dataclass(frozen=True)
class ObjectiveEffectAuthorizationReceipt:
    operation_id: str
    outer_lease_id_sha256: str
    objective_id: str
    method_policy_sha256: str
    objective_decision_receipt_sha256: str
    objective_observation_head_sha256: str
    objective_state_sha256: str
    objective_decision: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    capability_receipt_sha256: str
    inner_authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": LEASE_SCHEMA,
            "operation_id": self.operation_id,
            "outer_lease_id_sha256": self.outer_lease_id_sha256,
            "objective_id": self.objective_id,
            "method_policy_sha256": self.method_policy_sha256,
            "objective_decision_receipt_sha256": self.objective_decision_receipt_sha256,
            "objective_observation_head_sha256": self.objective_observation_head_sha256,
            "objective_state_sha256": self.objective_state_sha256,
            "objective_decision": self.objective_decision,
            "runtime_kind": self.runtime_kind,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "inner_authorization_receipt_sha256": self.inner_authorization_receipt_sha256,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class ObjectiveEffectCommitReceipt:
    operation_id: str
    authorization_receipt_sha256: str
    outer_lease_id_sha256: str
    objective_id: str
    method_policy_sha256: str
    objective_observation_head_sha256: str
    objective_state_sha256: str
    inner_authorization_receipt_sha256: str
    inner_commit_receipt_sha256: str
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
            "outer_lease_id_sha256": self.outer_lease_id_sha256,
            "objective_id": self.objective_id,
            "method_policy_sha256": self.method_policy_sha256,
            "objective_observation_head_sha256": self.objective_observation_head_sha256,
            "objective_state_sha256": self.objective_state_sha256,
            "inner_authorization_receipt_sha256": self.inner_authorization_receipt_sha256,
            "inner_commit_receipt_sha256": self.inner_commit_receipt_sha256,
            "committed_at_unix": self.committed_at_unix,
            "effect_outcome": self.effect_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _ObjectiveLease:
    outer_lease_id: str
    inner_lease_id: str
    operation: RuntimeOperation
    objective_id: str
    method_policy_sha256: str
    objective_decision_receipt_sha256: str
    observation_head_sha256: str
    objective_state_sha256: str
    capability_receipt_sha256: str
    inner_authorization_receipt_sha256: str
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


class ObjectiveBoundEffectCommitBroker:
    """One-time objective binding around the existing epoch-bound effect broker."""

    def __init__(
        self,
        *,
        guard: FencedObjectiveIntegrityGuard,
        delegate: EffectCommitBroker,
        commit_fence: RuntimeCommitFence,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(guard, FencedObjectiveIntegrityGuard):
            raise ObjectiveEffectCommitError("fenced_objective_guard_required")
        if not isinstance(delegate, EffectCommitBroker):
            raise ObjectiveEffectCommitError("effect_commit_delegate_required")
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise ObjectiveEffectCommitError("invalid_runtime_commit_fence")
        if guard.commit_fence is not commit_fence or delegate.commit_fence is not commit_fence:
            raise ObjectiveEffectCommitError("shared_commit_fence_required")
        self.guard = guard
        self.delegate = delegate
        self.commit_fence = commit_fence
        self.clock = clock or delegate.clock
        self._leases: dict[str, _ObjectiveLease] = {}
        self._authorizations: list[ObjectiveEffectAuthorizationReceipt] = []
        self._commits: list[ObjectiveEffectCommitReceipt] = []

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            self.guard.enter_containment(incident_receipt_sha256=incident_receipt_sha256)
            self.delegate.enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            self.delegate.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)
            self.guard.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def issue_for_trusted_adapter(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        objective_decision: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        operation.validate()
        with self.commit_fence.hold():
            decision = verify_decision(dict(objective_decision))
            state = self.guard.state_document()
            self._verify_objective_allow(operation=operation, decision=decision, state=state)
            capability_sha = _sha(capability_decision.get("receipt_sha256"), "capability_receipt_sha256")
            inner_lease_id, inner_auth = self.delegate.issue_for_trusted_adapter(
                operation=operation,
                capability_decision=capability_decision,
            )
            verify_inner_authorization_receipt(inner_auth)
            issued = _time(inner_auth["issued_at_unix"], "issued_at_unix")
            expires = _time(inner_auth["expires_at_unix"], "expires_at_unix")
            outer_lease_id = (
                f"objective-effect-lease:{len(self._leases)+1}:"
                f"{canonical_sha256({'objective': decision['receipt_sha256'], 'inner': inner_auth['receipt_sha256'], 'operation': operation.operation_id})[:20]}"
            )
            provisional = ObjectiveEffectAuthorizationReceipt(
                operation_id=operation.operation_id,
                outer_lease_id_sha256=canonical_sha256(outer_lease_id),
                objective_id=state["objective_id"],
                method_policy_sha256=state["method_policy_sha256"],
                objective_decision_receipt_sha256=decision["receipt_sha256"],
                objective_observation_head_sha256=state["observation_head_sha256"],
                objective_state_sha256=state["state_sha256"],
                objective_decision="ALLOW",
                runtime_kind=operation.kind,
                scope_sha256=canonical_sha256(operation.normalized_scope()),
                payload_sha256=operation.payload_sha256,
                capability_receipt_sha256=capability_sha,
                inner_authorization_receipt_sha256=inner_auth["receipt_sha256"],
                issued_at_unix=issued,
                expires_at_unix=expires,
                receipt_sha256="",
            )
            receipt = ObjectiveEffectAuthorizationReceipt(**{
                **provisional.__dict__,
                "receipt_sha256": canonical_sha256(provisional.body()),
            })
            self._authorizations.append(receipt)
            self._leases[outer_lease_id] = _ObjectiveLease(
                outer_lease_id=outer_lease_id,
                inner_lease_id=inner_lease_id,
                operation=operation,
                objective_id=state["objective_id"],
                method_policy_sha256=state["method_policy_sha256"],
                objective_decision_receipt_sha256=decision["receipt_sha256"],
                observation_head_sha256=state["observation_head_sha256"],
                objective_state_sha256=state["state_sha256"],
                capability_receipt_sha256=capability_sha,
                inner_authorization_receipt_sha256=inner_auth["receipt_sha256"],
                authorization_receipt_sha256=receipt.receipt_sha256,
                issued_at_unix=issued,
                expires_at_unix=expires,
            )
            return outer_lease_id, receipt.as_document()

    def consume_for_trusted_adapter(
        self,
        outer_lease_id: str,
        *,
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        with self.commit_fence.hold():
            lease = self._require_live_lease(outer_lease_id)
            now = self._now()
            if now < lease.issued_at_unix:
                return self._invalidate_and_raise(lease, now, "clock_regression")
            if now > lease.expires_at_unix:
                return self._invalidate_and_raise(lease, now, "lease_expired")
            state = self.guard.state_document()
            mismatch = self._objective_mismatch(lease, state)
            if mismatch is not None:
                return self._invalidate_and_raise(lease, now, mismatch, state=state)

            # Burn the outer objective lease before entering the inner effect
            # callback. Even callback failure cannot restore this authority.
            lease.consumed = True
            before_commits = len(self.delegate.commit_receipts())
            try:
                observation = self.delegate.consume_for_trusted_adapter(
                    lease.inner_lease_id,
                    adapter_token=adapter_token,
                    executor=executor,
                )
            except Exception as exc:
                inner_sha = self._latest_inner_commit(before_commits)
                self._append_commit(
                    lease=lease,
                    state=state,
                    committed_at_unix=now,
                    outcome="FAILED",
                    result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                    inner_commit_sha256=inner_sha,
                    reasons=("outer_lease_consumed", "inner_effect_commit_failed"),
                )
                if isinstance(exc, ObjectiveEffectCommitError):
                    raise
                raise ObjectiveEffectCommitError("inner_effect_commit_failed") from exc

            inner_sha = self._latest_inner_commit(before_commits)
            self._append_commit(
                lease=lease,
                state=state,
                committed_at_unix=now,
                outcome="SUCCEEDED",
                result_sha256=observation.result_sha256,
                inner_commit_sha256=inner_sha,
                reasons=(
                    "objective_policy_rechecked",
                    "objective_head_rechecked",
                    "objective_decision_floor_allow",
                    "outer_lease_consumed",
                    "inner_epoch_effect_committed",
                    "effect_committed_under_shared_fence",
                ),
            )
            return observation

    def commit_authorized_effect(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        objective_decision: Mapping[str, Any],
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        outer_lease_id, _ = self.issue_for_trusted_adapter(
            operation=operation,
            capability_decision=capability_decision,
            objective_decision=objective_decision,
        )
        return self.consume_for_trusted_adapter(
            outer_lease_id,
            adapter_token=adapter_token,
            executor=executor,
        )

    def authorization_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._authorizations)

    def commit_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._commits)

    def state_document(self) -> dict[str, Any]:
        with self.commit_fence.hold():
            objective_state = self.guard.state_document()
            body = {
                "schema": STATE_SCHEMA,
                "objective_id": objective_state["objective_id"],
                "method_policy_sha256": objective_state["method_policy_sha256"],
                "objective_observation_head_sha256": objective_state["observation_head_sha256"],
                "objective_decision_floor": objective_state["decision_floor"],
                "lease_count": len(self._leases),
                "consumed_count": sum(1 for item in self._leases.values() if item.consumed),
                "authorization_count": len(self._authorizations),
                "commit_count": len(self._commits),
                "authority": AUTHORITY,
            }
            return {**body, "state_sha256": canonical_sha256(body)}

    def _verify_objective_allow(
        self,
        *,
        operation: RuntimeOperation,
        decision: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> None:
        if decision.get("decision") != "ALLOW":
            raise ObjectiveEffectCommitError("objective_decision_not_allow")
        if state.get("decision_floor") != "ALLOW" or state.get("contained") is not False:
            raise ObjectiveEffectCommitError("objective_state_not_allow")
        if decision.get("objective_id") != state.get("objective_id"):
            raise ObjectiveEffectCommitError("objective_id_mismatch")
        if decision.get("method_policy_sha256") != state.get("method_policy_sha256"):
            raise ObjectiveEffectCommitError("objective_policy_mismatch")
        if decision.get("observation_head_sha256") != state.get("observation_head_sha256"):
            raise ObjectiveEffectCommitError("stale_objective_observation_head")
        if operation.policy_sha256 != self.guard.policy.governance_policy_sha256:
            raise ObjectiveEffectCommitError("governance_policy_mismatch")
        expected = {
            "action_id_sha256": canonical_sha256(operation.operation_id),
            "subject_id_sha256": canonical_sha256(operation.subject_id),
            "runtime_kind": operation.kind,
            "scope_sha256": canonical_sha256(operation.normalized_scope()),
            "payload_sha256": operation.payload_sha256,
        }
        for key, value in expected.items():
            if decision.get(key) != value:
                raise ObjectiveEffectCommitError("objective_decision_action_mismatch")

    def _objective_mismatch(self, lease: _ObjectiveLease, state: Mapping[str, Any]) -> str | None:
        if state.get("objective_id") != lease.objective_id:
            return "objective_id_changed"
        if state.get("method_policy_sha256") != lease.method_policy_sha256:
            return "objective_policy_changed"
        if state.get("contained") is not False:
            return "objective_containment_active"
        if state.get("decision_floor") != "ALLOW":
            return "objective_decision_floor_changed"
        if state.get("observation_head_sha256") != lease.observation_head_sha256:
            return "stale_objective_observation_head"
        if state.get("state_sha256") != lease.objective_state_sha256:
            return "objective_state_changed"
        return None

    def _require_live_lease(self, outer_lease_id: str) -> _ObjectiveLease:
        if not isinstance(outer_lease_id, str) or not outer_lease_id:
            raise ObjectiveEffectCommitError("unknown_outer_lease")
        lease = self._leases.get(outer_lease_id)
        if lease is None:
            raise ObjectiveEffectCommitError("unknown_outer_lease")
        if lease.consumed:
            raise ObjectiveEffectCommitError("outer_lease_replayed")
        return lease

    def _invalidate_and_raise(
        self,
        lease: _ObjectiveLease,
        now: int,
        reason: str,
        *,
        state: Mapping[str, Any] | None = None,
    ) -> ExecutionObservation:
        lease.consumed = True
        current = dict(state or self.guard.state_document())
        self._append_commit(
            lease=lease,
            state=current,
            committed_at_unix=now,
            outcome="NOT_EXECUTED",
            result_sha256=ZERO_SHA256,
            inner_commit_sha256=ZERO_SHA256,
            reasons=("outer_lease_consumed", reason),
        )
        raise ObjectiveEffectCommitError(reason)

    def _latest_inner_commit(self, before_count: int) -> str:
        commits = self.delegate.commit_receipts()
        if len(commits) <= before_count:
            return ZERO_SHA256
        return _sha(commits[-1]["receipt_sha256"], "inner_commit_receipt_sha256")

    def _append_commit(
        self,
        *,
        lease: _ObjectiveLease,
        state: Mapping[str, Any],
        committed_at_unix: int,
        outcome: str,
        result_sha256: str,
        inner_commit_sha256: str,
        reasons: tuple[str, ...],
    ) -> None:
        provisional = ObjectiveEffectCommitReceipt(
            operation_id=lease.operation.operation_id,
            authorization_receipt_sha256=lease.authorization_receipt_sha256,
            outer_lease_id_sha256=canonical_sha256(lease.outer_lease_id),
            objective_id=lease.objective_id,
            method_policy_sha256=lease.method_policy_sha256,
            objective_observation_head_sha256=_sha(
                state.get("observation_head_sha256", lease.observation_head_sha256),
                "objective_observation_head_sha256",
            ),
            objective_state_sha256=_sha(
                state.get("state_sha256", lease.objective_state_sha256),
                "objective_state_sha256",
            ),
            inner_authorization_receipt_sha256=lease.inner_authorization_receipt_sha256,
            inner_commit_receipt_sha256=_sha(inner_commit_sha256, "inner_commit_receipt_sha256"),
            committed_at_unix=_time(committed_at_unix, "committed_at_unix"),
            effect_outcome=outcome,
            result_sha256=_sha(result_sha256, "result_sha256"),
            reason_codes=tuple(sorted(set(reasons))),
            receipt_sha256="",
        )
        receipt = ObjectiveEffectCommitReceipt(**{
            **provisional.__dict__,
            "receipt_sha256": canonical_sha256(provisional.body()),
        })
        self._commits.append(receipt)

    def _now(self) -> int:
        return _time(self.clock(), "trusted_clock")


class ObjectiveBoundEffectRuntimeMediator(RuntimeMediator):
    """Opt-in full path: objective gate → capability → objective-bound effect."""

    def __init__(
        self,
        *,
        objective_effect_broker: ObjectiveBoundEffectCommitBroker,
        adapter_token: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not isinstance(objective_effect_broker, ObjectiveBoundEffectCommitBroker):
            raise ObjectiveEffectCommitError("objective_effect_broker_required")
        if not isinstance(adapter_token, str) or not adapter_token:
            raise ObjectiveEffectCommitError("adapter_token_required")
        self.objective_effect_broker = objective_effect_broker
        self.guard = objective_effect_broker.guard
        self.adapter_token = adapter_token

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        super().enter_containment(incident_receipt_sha256=incident_receipt_sha256)
        self.objective_effect_broker.enter_containment(
            incident_receipt_sha256=incident_receipt_sha256
        )

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        self.objective_effect_broker.exit_containment(
            human_release_receipt_sha256=human_release_receipt_sha256
        )
        super().exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def mediate(
        self,
        operation: RuntimeOperation,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> dict[str, Any]:
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
                reasons=("containment_active", "objective_bound_effect_blocked"),
                capability_id=None,
                scope_sha=scope_sha,
            )

        gate = self.guard.evaluate_operation(operation)
        if gate["decision"] != "ALLOW":
            return self._finish(
                operation=operation,
                capability_receipt_sha=ZERO_SHA256,
                admission="BLOCK",
                outcome="NOT_EXECUTED",
                result_sha=ZERO_SHA256,
                reasons=("objective_integrity_gate_blocked", f"objective_decision:{gate['decision']}"),
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
                "objective_decision_receipt_sha256": gate["receipt_sha256"],
                "objective_observation_head_sha256": gate["observation_head_sha256"],
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
            observation = self.objective_effect_broker.commit_authorized_effect(
                operation=operation,
                capability_decision=capability,
                objective_decision=gate,
                adapter_token=self.adapter_token,
                executor=executor,
            )
        except Exception as exc:
            return self._finish(
                operation=operation,
                capability_receipt_sha=capability["receipt_sha256"],
                admission="ALLOW",
                outcome="FAILED",
                result_sha=canonical_sha256({"error_type": type(exc).__name__}),
                reasons=("objective_bound_effect_commit_failed",),
                capability_id=capability.get("capability_id"),
                scope_sha=scope_sha,
            )

        return self._finish(
            operation=operation,
            capability_receipt_sha=capability["receipt_sha256"],
            admission="ALLOW",
            outcome="SUCCEEDED",
            result_sha=observation.result_sha256,
            reasons=(
                "objective_integrity_allow",
                "capability_admitted",
                "objective_bound_effect_lease_consumed",
                "host_executor_succeeded",
            ),
            capability_id=capability.get("capability_id"),
            scope_sha=scope_sha,
        )


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != LEASE_SCHEMA or raw.get("authority") != AUTHORITY:
        raise ObjectiveEffectCommitError("authorization_receipt_schema_mismatch")
    if raw.get("objective_decision") != "ALLOW":
        raise ObjectiveEffectCommitError("authorization_receipt_not_allow")
    if digest != canonical_sha256(raw):
        raise ObjectiveEffectCommitError("authorization_receipt_digest_mismatch")
    return dict(document)


def verify_commit_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != COMMIT_SCHEMA or raw.get("authority") != AUTHORITY:
        raise ObjectiveEffectCommitError("commit_receipt_schema_mismatch")
    if raw.get("effect_outcome") not in {"SUCCEEDED", "FAILED", "NOT_EXECUTED"}:
        raise ObjectiveEffectCommitError("commit_receipt_outcome_invalid")
    if digest != canonical_sha256(raw):
        raise ObjectiveEffectCommitError("commit_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY",
    "COMMIT_SCHEMA",
    "FencedObjectiveIntegrityGuard",
    "LEASE_SCHEMA",
    "ObjectiveBoundEffectCommitBroker",
    "ObjectiveBoundEffectRuntimeMediator",
    "ObjectiveEffectAuthorizationReceipt",
    "ObjectiveEffectCommitError",
    "ObjectiveEffectCommitReceipt",
    "STATE_SCHEMA",
    "verify_authorization_receipt",
    "verify_commit_receipt",
]
