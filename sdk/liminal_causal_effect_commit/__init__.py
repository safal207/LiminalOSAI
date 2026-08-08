"""Causal / trajectory-bound effect commit composition for LiminalOS.

This layer composes the deterministic Phase-3 causal escalation detector with
Objective-Bound Effect Commit. It does not change either existing schema. A
one-time outer lease binds the exact verified causal head and a deterministic
projection of the proposed effect. The same RuntimeCommitFence serializes
trajectory advancement and physical effect commit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sdk.liminal_causal_escalation import (
    AUTHORITY as CAUSAL_AUTHORITY,
    EVENT_KINDS,
    EscalationError,
    TrajectoryEvent,
    analyze_trajectory,
)
from sdk.liminal_effect_commit import RuntimeCommitFence, ZERO_SHA256
from sdk.liminal_objective_effect_commit import (
    ObjectiveBoundEffectCommitBroker,
    ObjectiveEffectCommitError,
    verify_authorization_receipt as verify_objective_authorization_receipt,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import (
    ExecutionObservation,
    OPERATION_TO_CAPABILITY,
    PHASE3_KIND,
    RuntimeMediator,
    RuntimeOperation,
)

LEDGER_SCHEMA = "liminal-fenced-trajectory-risk-ledger-v0.1"
LEASE_SCHEMA = "liminal-causal-bound-effect-lease-v0.1"
COMMIT_SCHEMA = "liminal-causal-bound-effect-commit-v0.1"
STATE_SCHEMA = "liminal-causal-bound-effect-state-v0.1"

AUTHORITY = {
    "mode": "causal_trajectory_bound_effect_commit_composition",
    "trajectory_head_binding": True,
    "projected_trajectory_gate": True,
    "shared_causal_effect_fence": True,
    "one_time_causal_lease": True,
    "objective_bound_inner_effect_required": True,
    "append_committed_event_on_success": True,
    "trusted_event_verification_required": True,
    "capability_grant": False,
    "causal_evidence_fabrication": False,
    "runtime_mutation": False,
    "network_authority": False,
    "credential_authority": False,
    "containment_execution": False,
    "kernel_enforcement": False,
}

EventVerifier = Callable[[Mapping[str, Any]], bool]


class CausalEffectCommitError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(value: Any, name: str, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise CausalEffectCommitError(f"invalid_{name}")
    if not allow_zero and value == ZERO_SHA256:
        raise CausalEffectCommitError(f"zero_{name}")
    return value


def _time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CausalEffectCommitError(f"invalid_{name}")
    return value


def _parse_event(document: Mapping[str, Any]) -> TrajectoryEvent:
    raw = dict(document)
    expected = {
        "event_id", "sequence", "observed_at_unix", "kind", "decision",
        "subject_id", "capability_id", "privilege_level_before",
        "privilege_level_after", "metadata_sha256", "previous_event_sha256",
        "event_sha256",
    }
    if set(raw) != expected:
        raise CausalEffectCommitError("trajectory_event_keys_mismatch")
    try:
        item = TrajectoryEvent(**raw)
    except (TypeError, ValueError) as exc:
        raise CausalEffectCommitError("trajectory_event_invalid") from exc
    if canonical_sha256(item.body()) != item.event_sha256:
        raise CausalEffectCommitError("trajectory_event_digest_mismatch")
    return item


def build_effect_trajectory_event(
    *,
    operation: RuntimeOperation,
    capability_decision: Mapping[str, Any],
    sequence: int,
    previous_event_sha256: str,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build the exact digest-only proposal that a trusted host may attest.

    Privilege levels come from the already-normalized RuntimeOperation, matching
    the existing RuntimeMediator Phase-3 projection semantics. The broker still
    requires an injected verifier before accepting this event as trusted.
    """
    operation.validate()
    capability_id = capability_decision.get("capability_id")
    capability_receipt = _sha(
        capability_decision.get("receipt_sha256"), "capability_receipt_sha256", allow_zero=False
    )
    if capability_decision.get("decision") != "ALLOW" or not isinstance(capability_id, str) or not capability_id:
        raise CausalEffectCommitError("capability_decision_not_allow")
    scope_sha = canonical_sha256(operation.normalized_scope())
    metadata = {
        "operation_id_sha256": canonical_sha256(operation.operation_id),
        "runtime_kind": operation.kind,
        "scope_sha256": scope_sha,
        "payload_sha256": operation.payload_sha256,
        "capability_receipt_sha256": capability_receipt,
    }
    event = TrajectoryEvent.build(
        event_id=event_id or f"effect-proposal:{operation.operation_id}",
        sequence=sequence,
        observed_at_unix=operation.at_unix,
        kind=PHASE3_KIND[operation.kind],
        decision="ALLOW",
        subject_id=operation.subject_id,
        capability_id=capability_id,
        privilege_level_before=operation.privilege_level_before,
        privilege_level_after=operation.privilege_level_after,
        metadata=metadata,
        previous_event_sha256=_sha(previous_event_sha256, "previous_event_sha256"),
    )
    return event.body() | {"event_sha256": event.event_sha256}


class FencedTrajectoryRiskLedger:
    """Append-only verified Phase-3 trajectory state under RuntimeCommitFence."""

    def __init__(
        self,
        *,
        commit_fence: RuntimeCommitFence,
        verify_event: EventVerifier,
    ) -> None:
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise CausalEffectCommitError("invalid_runtime_commit_fence")
        if not callable(verify_event):
            raise CausalEffectCommitError("trusted_event_verifier_required")
        self.commit_fence = commit_fence
        self._verify_event = verify_event
        self._events: list[TrajectoryEvent] = []
        self._event_ids: set[str] = set()

    @property
    def head_sha256(self) -> str:
        with self.commit_fence.hold():
            return self._events[-1].event_sha256 if self._events else ZERO_SHA256

    @property
    def event_count(self) -> int:
        with self.commit_fence.hold():
            return len(self._events)

    def events(self) -> tuple[dict[str, Any], ...]:
        with self.commit_fence.hold():
            return tuple(event.body() | {"event_sha256": event.event_sha256} for event in self._events)

    def append_verified_event(self, document: Mapping[str, Any]) -> dict[str, Any]:
        with self.commit_fence.hold():
            event = self._verified_event(document)
            if event.event_id in self._event_ids:
                raise CausalEffectCommitError("trajectory_event_replay")
            decision = self._analyze(self._events + [event])
            self._events.append(event)
            self._event_ids.add(event.event_id)
            return {
                "event_sha256": event.event_sha256,
                "trajectory_head_sha256": event.event_sha256,
                "trajectory_decision": decision["decision"],
                "trajectory_decision_receipt_sha256": decision["receipt_sha256"],
                "risk_score": decision["risk_score"],
            }

    def project_verified_event(self, document: Mapping[str, Any]) -> dict[str, Any]:
        with self.commit_fence.hold():
            event = self._verified_event(document)
            if event.event_id in self._event_ids:
                raise CausalEffectCommitError("trajectory_event_replay")
            decision = self._analyze(self._events + [event])
            body = {
                "schema": "liminal-trajectory-projection-v0.1",
                "trajectory_head_sha256": self._events[-1].event_sha256 if self._events else ZERO_SHA256,
                "event_count_before": len(self._events),
                "proposed_event_sha256": event.event_sha256,
                "projected_graph_sha256": decision["graph_sha256"],
                "projected_decision_receipt_sha256": decision["receipt_sha256"],
                "projected_decision": decision["decision"],
                "projected_risk_score": decision["risk_score"],
                "authority": AUTHORITY,
            }
            return {**body, "projection_sha256": canonical_sha256(body)}

    def state_document(self) -> dict[str, Any]:
        with self.commit_fence.hold():
            decision = self._analyze(self._events)
            head = self._events[-1].event_sha256 if self._events else ZERO_SHA256
            body = {
                "schema": LEDGER_SCHEMA,
                "event_count": len(self._events),
                "trajectory_head_sha256": head,
                "graph_sha256": decision["graph_sha256"],
                "decision_receipt_sha256": decision["receipt_sha256"],
                "decision": decision["decision"],
                "risk_score": decision["risk_score"],
                "matched_rules": list(decision["matched_rules"]),
                "causal_authority_sha256": canonical_sha256(CAUSAL_AUTHORITY),
                "authority": AUTHORITY,
            }
            return {**body, "state_sha256": canonical_sha256(body)}

    def _verified_event(self, document: Mapping[str, Any]) -> TrajectoryEvent:
        event = _parse_event(document)
        try:
            verified = self._verify_event(dict(document))
        except Exception as exc:
            raise CausalEffectCommitError("trusted_event_verification_failed") from exc
        if verified is not True:
            raise CausalEffectCommitError("trusted_event_verification_failed")
        return event

    @staticmethod
    def _analyze(events: list[TrajectoryEvent]) -> dict[str, Any]:
        try:
            return analyze_trajectory(events)
        except EscalationError as exc:
            raise CausalEffectCommitError("trajectory_chain_invalid") from exc


@dataclass(frozen=True)
class CausalEffectAuthorizationReceipt:
    operation_id: str
    causal_lease_id_sha256: str
    trajectory_head_sha256: str
    trajectory_graph_sha256: str
    trajectory_decision_receipt_sha256: str
    trajectory_state_sha256: str
    trajectory_decision: str
    projected_event_sha256: str
    projected_graph_sha256: str
    projected_decision_receipt_sha256: str
    projected_decision: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    capability_receipt_sha256: str
    objective_authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": LEASE_SCHEMA,
            "operation_id": self.operation_id,
            "causal_lease_id_sha256": self.causal_lease_id_sha256,
            "trajectory_head_sha256": self.trajectory_head_sha256,
            "trajectory_graph_sha256": self.trajectory_graph_sha256,
            "trajectory_decision_receipt_sha256": self.trajectory_decision_receipt_sha256,
            "trajectory_state_sha256": self.trajectory_state_sha256,
            "trajectory_decision": self.trajectory_decision,
            "projected_event_sha256": self.projected_event_sha256,
            "projected_graph_sha256": self.projected_graph_sha256,
            "projected_decision_receipt_sha256": self.projected_decision_receipt_sha256,
            "projected_decision": self.projected_decision,
            "runtime_kind": self.runtime_kind,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "objective_authorization_receipt_sha256": self.objective_authorization_receipt_sha256,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class CausalEffectCommitReceipt:
    operation_id: str
    authorization_receipt_sha256: str
    causal_lease_id_sha256: str
    trajectory_head_before_sha256: str
    projected_event_sha256: str
    trajectory_head_after_sha256: str
    objective_authorization_receipt_sha256: str
    objective_commit_receipt_sha256: str
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
            "causal_lease_id_sha256": self.causal_lease_id_sha256,
            "trajectory_head_before_sha256": self.trajectory_head_before_sha256,
            "projected_event_sha256": self.projected_event_sha256,
            "trajectory_head_after_sha256": self.trajectory_head_after_sha256,
            "objective_authorization_receipt_sha256": self.objective_authorization_receipt_sha256,
            "objective_commit_receipt_sha256": self.objective_commit_receipt_sha256,
            "committed_at_unix": self.committed_at_unix,
            "effect_outcome": self.effect_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _CausalLease:
    causal_lease_id: str
    objective_lease_id: str
    operation: RuntimeOperation
    proposal: dict[str, Any]
    trajectory_head_sha256: str
    trajectory_graph_sha256: str
    trajectory_decision_receipt_sha256: str
    trajectory_state_sha256: str
    projected_graph_sha256: str
    projected_decision_receipt_sha256: str
    capability_receipt_sha256: str
    objective_authorization_receipt_sha256: str
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


class CausalBoundEffectCommitBroker:
    """One-time causal binding around ObjectiveBoundEffectCommitBroker."""

    def __init__(
        self,
        *,
        ledger: FencedTrajectoryRiskLedger,
        delegate: ObjectiveBoundEffectCommitBroker,
        commit_fence: RuntimeCommitFence,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(ledger, FencedTrajectoryRiskLedger):
            raise CausalEffectCommitError("fenced_trajectory_ledger_required")
        if not isinstance(delegate, ObjectiveBoundEffectCommitBroker):
            raise CausalEffectCommitError("objective_bound_effect_delegate_required")
        if not isinstance(commit_fence, RuntimeCommitFence):
            raise CausalEffectCommitError("invalid_runtime_commit_fence")
        if ledger.commit_fence is not commit_fence or delegate.commit_fence is not commit_fence:
            raise CausalEffectCommitError("shared_commit_fence_required")
        self.ledger = ledger
        self.delegate = delegate
        self.commit_fence = commit_fence
        self.clock = clock or delegate.clock
        self._leases: dict[str, _CausalLease] = {}
        self._authorizations: list[CausalEffectAuthorizationReceipt] = []
        self._commits: list[CausalEffectCommitReceipt] = []

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            self.delegate.enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        with self.commit_fence.hold():
            self.delegate.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def issue_for_trusted_adapter(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        objective_decision: Mapping[str, Any],
        proposed_event: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        operation.validate()
        with self.commit_fence.hold():
            state = self.ledger.state_document()
            if state["decision"] != "ALLOW":
                raise CausalEffectCommitError("trajectory_state_not_allow")
            proposal = dict(proposed_event)
            event = _parse_event(proposal)
            self._verify_proposal_binding(
                operation=operation,
                capability_decision=capability_decision,
                event=event,
                state=state,
            )
            projection = self.ledger.project_verified_event(proposal)
            if projection["projected_decision"] != "ALLOW":
                raise CausalEffectCommitError("projected_trajectory_not_allow")

            objective_lease_id, objective_auth = self.delegate.issue_for_trusted_adapter(
                operation=operation,
                capability_decision=capability_decision,
                objective_decision=objective_decision,
            )
            verify_objective_authorization_receipt(objective_auth)
            issued = _time(objective_auth["issued_at_unix"], "issued_at_unix")
            expires = _time(objective_auth["expires_at_unix"], "expires_at_unix")
            capability_sha = _sha(
                capability_decision.get("receipt_sha256"), "capability_receipt_sha256", allow_zero=False
            )
            causal_lease_id = (
                f"causal-effect-lease:{len(self._leases)+1}:"
                f"{canonical_sha256({'head': state['trajectory_head_sha256'], 'projection': projection['projection_sha256'], 'inner': objective_auth['receipt_sha256']})[:20]}"
            )
            provisional = CausalEffectAuthorizationReceipt(
                operation_id=operation.operation_id,
                causal_lease_id_sha256=canonical_sha256(causal_lease_id),
                trajectory_head_sha256=state["trajectory_head_sha256"],
                trajectory_graph_sha256=state["graph_sha256"],
                trajectory_decision_receipt_sha256=state["decision_receipt_sha256"],
                trajectory_state_sha256=state["state_sha256"],
                trajectory_decision="ALLOW",
                projected_event_sha256=event.event_sha256,
                projected_graph_sha256=projection["projected_graph_sha256"],
                projected_decision_receipt_sha256=projection["projected_decision_receipt_sha256"],
                projected_decision="ALLOW",
                runtime_kind=operation.kind,
                scope_sha256=canonical_sha256(operation.normalized_scope()),
                payload_sha256=operation.payload_sha256,
                capability_receipt_sha256=capability_sha,
                objective_authorization_receipt_sha256=objective_auth["receipt_sha256"],
                issued_at_unix=issued,
                expires_at_unix=expires,
                receipt_sha256="",
            )
            receipt = CausalEffectAuthorizationReceipt(**{
                **provisional.__dict__, "receipt_sha256": canonical_sha256(provisional.body())
            })
            self._authorizations.append(receipt)
            self._leases[causal_lease_id] = _CausalLease(
                causal_lease_id=causal_lease_id,
                objective_lease_id=objective_lease_id,
                operation=operation,
                proposal=proposal,
                trajectory_head_sha256=state["trajectory_head_sha256"],
                trajectory_graph_sha256=state["graph_sha256"],
                trajectory_decision_receipt_sha256=state["decision_receipt_sha256"],
                trajectory_state_sha256=state["state_sha256"],
                projected_graph_sha256=projection["projected_graph_sha256"],
                projected_decision_receipt_sha256=projection["projected_decision_receipt_sha256"],
                capability_receipt_sha256=capability_sha,
                objective_authorization_receipt_sha256=objective_auth["receipt_sha256"],
                authorization_receipt_sha256=receipt.receipt_sha256,
                issued_at_unix=issued,
                expires_at_unix=expires,
            )
            return causal_lease_id, receipt.as_document()

    def consume_for_trusted_adapter(
        self,
        causal_lease_id: str,
        *,
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        with self.commit_fence.hold():
            lease = self._require_live_lease(causal_lease_id)
            now = self._now()
            if now < lease.issued_at_unix:
                return self._invalidate_and_raise(lease, now, "clock_regression")
            if now > lease.expires_at_unix:
                return self._invalidate_and_raise(lease, now, "lease_expired")

            state = self.ledger.state_document()
            mismatch = self._trajectory_mismatch(lease, state)
            if mismatch is not None:
                return self._invalidate_and_raise(lease, now, mismatch, state=state)
            projection = self.ledger.project_verified_event(lease.proposal)
            if projection["projected_decision"] != "ALLOW":
                return self._invalidate_and_raise(lease, now, "projected_trajectory_not_allow", state=state)
            if projection["projected_graph_sha256"] != lease.projected_graph_sha256:
                return self._invalidate_and_raise(lease, now, "projected_graph_changed", state=state)
            if projection["projected_decision_receipt_sha256"] != lease.projected_decision_receipt_sha256:
                return self._invalidate_and_raise(lease, now, "projected_decision_changed", state=state)

            lease.consumed = True
            before_commits = len(self.delegate.commit_receipts())
            try:
                observation = self.delegate.consume_for_trusted_adapter(
                    lease.objective_lease_id,
                    adapter_token=adapter_token,
                    executor=executor,
                )
            except Exception as exc:
                self._append_commit(
                    lease=lease,
                    head_after=state["trajectory_head_sha256"],
                    objective_commit_sha256=self._latest_objective_commit(before_commits),
                    committed_at_unix=now,
                    outcome="FAILED",
                    result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                    reasons=("causal_lease_consumed", "objective_bound_effect_failed"),
                )
                raise CausalEffectCommitError("objective_bound_effect_failed") from exc

            try:
                appended = self.ledger.append_verified_event(lease.proposal)
            except Exception as exc:
                self._append_commit(
                    lease=lease,
                    head_after=state["trajectory_head_sha256"],
                    objective_commit_sha256=self._latest_objective_commit(before_commits),
                    committed_at_unix=now,
                    outcome="EFFECT_SUCCEEDED_EVIDENCE_FAILED",
                    result_sha256=observation.result_sha256,
                    reasons=("causal_lease_consumed", "effect_succeeded", "trajectory_append_failed"),
                )
                raise CausalEffectCommitError("trajectory_append_failed_after_effect") from exc

            self._append_commit(
                lease=lease,
                head_after=appended["trajectory_head_sha256"],
                objective_commit_sha256=self._latest_objective_commit(before_commits),
                committed_at_unix=now,
                outcome="SUCCEEDED",
                result_sha256=observation.result_sha256,
                reasons=(
                    "trajectory_head_rechecked",
                    "trajectory_state_allow",
                    "projected_trajectory_allow",
                    "causal_lease_consumed",
                    "objective_runtime_effect_committed",
                    "committed_event_appended",
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
        proposed_event: Mapping[str, Any],
        adapter_token: str,
        executor: Callable[[RuntimeOperation], ExecutionObservation],
    ) -> ExecutionObservation:
        lease_id, _ = self.issue_for_trusted_adapter(
            operation=operation,
            capability_decision=capability_decision,
            objective_decision=objective_decision,
            proposed_event=proposed_event,
        )
        return self.consume_for_trusted_adapter(
            lease_id, adapter_token=adapter_token, executor=executor
        )

    def authorization_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._authorizations)

    def commit_receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._commits)

    def state_document(self) -> dict[str, Any]:
        with self.commit_fence.hold():
            trajectory = self.ledger.state_document()
            body = {
                "schema": STATE_SCHEMA,
                "trajectory_head_sha256": trajectory["trajectory_head_sha256"],
                "trajectory_decision": trajectory["decision"],
                "trajectory_risk_score": trajectory["risk_score"],
                "lease_count": len(self._leases),
                "consumed_count": sum(1 for item in self._leases.values() if item.consumed),
                "authorization_count": len(self._authorizations),
                "commit_count": len(self._commits),
                "authority": AUTHORITY,
            }
            return {**body, "state_sha256": canonical_sha256(body)}

    def _verify_proposal_binding(
        self,
        *,
        operation: RuntimeOperation,
        capability_decision: Mapping[str, Any],
        event: TrajectoryEvent,
        state: Mapping[str, Any],
    ) -> None:
        capability_id = capability_decision.get("capability_id")
        capability_receipt = _sha(
            capability_decision.get("receipt_sha256"), "capability_receipt_sha256", allow_zero=False
        )
        if capability_decision.get("decision") != "ALLOW" or not isinstance(capability_id, str) or not capability_id:
            raise CausalEffectCommitError("capability_decision_not_allow")
        if event.sequence != state["event_count"] + 1:
            raise CausalEffectCommitError("proposal_sequence_mismatch")
        if event.previous_event_sha256 != state["trajectory_head_sha256"]:
            raise CausalEffectCommitError("proposal_head_mismatch")
        if event.kind != PHASE3_KIND[operation.kind] or event.kind not in EVENT_KINDS:
            raise CausalEffectCommitError("proposal_kind_mismatch")
        if event.decision != "ALLOW":
            raise CausalEffectCommitError("proposal_decision_not_allow")
        if event.subject_id != operation.subject_id or event.capability_id != capability_id:
            raise CausalEffectCommitError("proposal_authority_binding_mismatch")
        if event.observed_at_unix != operation.at_unix:
            raise CausalEffectCommitError("proposal_time_mismatch")
        if event.privilege_level_before != operation.privilege_level_before or event.privilege_level_after != operation.privilege_level_after:
            raise CausalEffectCommitError("proposal_privilege_binding_mismatch")
        expected_metadata_sha = canonical_sha256({
            "operation_id_sha256": canonical_sha256(operation.operation_id),
            "runtime_kind": operation.kind,
            "scope_sha256": canonical_sha256(operation.normalized_scope()),
            "payload_sha256": operation.payload_sha256,
            "capability_receipt_sha256": capability_receipt,
        })
        if event.metadata_sha256 != expected_metadata_sha:
            raise CausalEffectCommitError("proposal_action_binding_mismatch")

    @staticmethod
    def _trajectory_mismatch(lease: _CausalLease, state: Mapping[str, Any]) -> str | None:
        if state.get("decision") != "ALLOW":
            return "trajectory_state_not_allow"
        if state.get("trajectory_head_sha256") != lease.trajectory_head_sha256:
            return "stale_trajectory_head"
        if state.get("graph_sha256") != lease.trajectory_graph_sha256:
            return "trajectory_graph_changed"
        if state.get("decision_receipt_sha256") != lease.trajectory_decision_receipt_sha256:
            return "trajectory_decision_changed"
        if state.get("state_sha256") != lease.trajectory_state_sha256:
            return "trajectory_state_changed"
        return None

    def _require_live_lease(self, causal_lease_id: str) -> _CausalLease:
        if not isinstance(causal_lease_id, str) or not causal_lease_id:
            raise CausalEffectCommitError("unknown_causal_lease")
        lease = self._leases.get(causal_lease_id)
        if lease is None:
            raise CausalEffectCommitError("unknown_causal_lease")
        if lease.consumed:
            raise CausalEffectCommitError("causal_lease_replayed")
        return lease

    def _invalidate_and_raise(
        self,
        lease: _CausalLease,
        now: int,
        reason: str,
        *,
        state: Mapping[str, Any] | None = None,
    ) -> ExecutionObservation:
        lease.consumed = True
        current = dict(state or self.ledger.state_document())
        self._append_commit(
            lease=lease,
            head_after=current["trajectory_head_sha256"],
            objective_commit_sha256=ZERO_SHA256,
            committed_at_unix=now,
            outcome="NOT_EXECUTED",
            result_sha256=ZERO_SHA256,
            reasons=("causal_lease_consumed", reason),
        )
        raise CausalEffectCommitError(reason)

    def _latest_objective_commit(self, before_count: int) -> str:
        commits = self.delegate.commit_receipts()
        if len(commits) <= before_count:
            return ZERO_SHA256
        return _sha(commits[-1]["receipt_sha256"], "objective_commit_receipt_sha256")

    def _append_commit(
        self,
        *,
        lease: _CausalLease,
        head_after: str,
        objective_commit_sha256: str,
        committed_at_unix: int,
        outcome: str,
        result_sha256: str,
        reasons: tuple[str, ...],
    ) -> None:
        provisional = CausalEffectCommitReceipt(
            operation_id=lease.operation.operation_id,
            authorization_receipt_sha256=lease.authorization_receipt_sha256,
            causal_lease_id_sha256=canonical_sha256(lease.causal_lease_id),
            trajectory_head_before_sha256=lease.trajectory_head_sha256,
            projected_event_sha256=_sha(lease.proposal["event_sha256"], "projected_event_sha256"),
            trajectory_head_after_sha256=_sha(head_after, "trajectory_head_after_sha256"),
            objective_authorization_receipt_sha256=lease.objective_authorization_receipt_sha256,
            objective_commit_receipt_sha256=_sha(objective_commit_sha256, "objective_commit_receipt_sha256"),
            committed_at_unix=_time(committed_at_unix, "committed_at_unix"),
            effect_outcome=outcome,
            result_sha256=_sha(result_sha256, "result_sha256"),
            reason_codes=tuple(sorted(set(reasons))),
            receipt_sha256="",
        )
        receipt = CausalEffectCommitReceipt(**{
            **provisional.__dict__, "receipt_sha256": canonical_sha256(provisional.body())
        })
        self._commits.append(receipt)

    def _now(self) -> int:
        return _time(self.clock(), "trusted_clock")


ProposalFactory = Callable[[RuntimeOperation, Mapping[str, Any], FencedTrajectoryRiskLedger], Mapping[str, Any]]


class CausalBoundEffectRuntimeMediator(RuntimeMediator):
    """Opt-in full path: objective → capability → causal/objective/runtime effect."""

    def __init__(
        self,
        *,
        causal_effect_broker: CausalBoundEffectCommitBroker,
        adapter_token: str,
        proposal_factory: ProposalFactory,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not isinstance(causal_effect_broker, CausalBoundEffectCommitBroker):
            raise CausalEffectCommitError("causal_effect_broker_required")
        if not isinstance(adapter_token, str) or not adapter_token:
            raise CausalEffectCommitError("adapter_token_required")
        if not callable(proposal_factory):
            raise CausalEffectCommitError("trusted_proposal_factory_required")
        self.causal_effect_broker = causal_effect_broker
        self.objective_effect_broker = causal_effect_broker.delegate
        self.guard = self.objective_effect_broker.guard
        self.adapter_token = adapter_token
        self.proposal_factory = proposal_factory

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        super().enter_containment(incident_receipt_sha256=incident_receipt_sha256)
        self.causal_effect_broker.enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        self.causal_effect_broker.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)
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
                reasons=("containment_active", "causal_bound_effect_blocked"),
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
            proposal = dict(self.proposal_factory(operation, capability, self.causal_effect_broker.ledger))
            observation = self.causal_effect_broker.commit_authorized_effect(
                operation=operation,
                capability_decision=capability,
                objective_decision=gate,
                proposed_event=proposal,
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
                reasons=("causal_bound_effect_commit_failed",),
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
                "causal_projection_allow",
                "causal_bound_effect_lease_consumed",
                "host_executor_succeeded",
            ),
            capability_id=capability.get("capability_id"),
            scope_sha=scope_sha,
        )


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != LEASE_SCHEMA or raw.get("authority") != AUTHORITY:
        raise CausalEffectCommitError("authorization_receipt_schema_mismatch")
    if raw.get("trajectory_decision") != "ALLOW" or raw.get("projected_decision") != "ALLOW":
        raise CausalEffectCommitError("authorization_receipt_not_allow")
    if digest != canonical_sha256(raw):
        raise CausalEffectCommitError("authorization_receipt_digest_mismatch")
    return dict(document)


def verify_commit_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != COMMIT_SCHEMA or raw.get("authority") != AUTHORITY:
        raise CausalEffectCommitError("commit_receipt_schema_mismatch")
    if raw.get("effect_outcome") not in {"SUCCEEDED", "FAILED", "NOT_EXECUTED", "EFFECT_SUCCEEDED_EVIDENCE_FAILED"}:
        raise CausalEffectCommitError("commit_receipt_outcome_invalid")
    if digest != canonical_sha256(raw):
        raise CausalEffectCommitError("commit_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY",
    "COMMIT_SCHEMA",
    "CausalBoundEffectCommitBroker",
    "CausalBoundEffectRuntimeMediator",
    "CausalEffectAuthorizationReceipt",
    "CausalEffectCommitError",
    "CausalEffectCommitReceipt",
    "FencedTrajectoryRiskLedger",
    "LEDGER_SCHEMA",
    "LEASE_SCHEMA",
    "STATE_SCHEMA",
    "build_effect_trajectory_event",
    "verify_authorization_receipt",
    "verify_commit_receipt",
]
