"""Local-only deterministic Trusted Research Continuity Protocol simulator.

This module is intentionally non-networked and non-operational. It models
authorization, scope, provider failover, verification, and evidence lineage
using fixed mock providers and synthetic fixtures only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-trcp-simulator-v0.1"
REPORT_SCHEMA = "liminal-trcp-simulator-report-v0.1"

FAILOVER_OUTCOMES = frozenset({
    "REFUSED",
    "ACCESS_RESTRICTED",
    "RATE_LIMITED",
    "PROVIDER_ERROR",
    "TIMEOUT",
})
PROVIDER_OUTCOMES = FAILOVER_OUTCOMES | frozenset({"COMPLETED", "ABORTED_BY_OPERATOR"})
FINDING_STATUSES = frozenset({
    "UNVERIFIED",
    "REPRODUCED",
    "NOT_REPRODUCED",
    "DISPUTED",
    "NEEDS_HUMAN_REVIEW",
    "CONFIRMED",
    "REMEDIATED",
})

AUTHORITY = {
    "mode": "local_deterministic_simulation_only",
    "external_network": False,
    "live_targets": False,
    "credential_access": False,
    "exploit_execution": False,
    "provider_api_calls": False,
    "automatic_disclosure": False,
}


class TRCPError(ValueError):
    """Raised when a TRCP invariant would be violated."""


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    subject_id: str
    asset_id: str
    valid_from: int
    valid_until: int
    allowed_activity_classes: tuple[str, ...]
    authority_source: str = "synthetic-fixture"
    owner_or_authorizer: str = "fixture-owner"
    proof_reference: str = "fixture://authorization"
    created_at: int = 900

    def validate(self, now_unix: int) -> None:
        if not self.authorization_id or not self.subject_id or not self.asset_id:
            raise TRCPError("authorization identity fields must be non-empty")
        if self.valid_from > self.valid_until:
            raise TRCPError("authorization validity window is inverted")
        if not (self.valid_from <= now_unix <= self.valid_until):
            raise TRCPError("authorization is not currently valid")
        if not self.allowed_activity_classes:
            raise TRCPError("authorization must allow at least one activity class")

    def as_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "subject_id": self.subject_id,
            "asset_id": self.asset_id,
            "authority_source": self.authority_source,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "allowed_activity_classes": list(self.allowed_activity_classes),
            "owner_or_authorizer": self.owner_or_authorizer,
            "proof_reference": self.proof_reference,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ScopeEnvelope:
    scope_id: str
    authorization_id: str
    allowed_targets: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_environments: tuple[str, ...] = ("LOCAL_FIXTURE",)
    prohibited_actions: tuple[str, ...] = (
        "LIVE_EXPLOIT",
        "CREDENTIAL_ACCESS",
        "PUBLIC_TARGET_SCAN",
    )
    data_handling_class: str = "SYNTHETIC_ONLY"
    network_mode: str = "LOCAL_ONLY"
    expires_at: int = 2000

    def validate(self, authorization: AuthorizationRecord, now_unix: int) -> None:
        if self.authorization_id != authorization.authorization_id:
            raise TRCPError("scope authorization_id does not match authorization")
        if authorization.asset_id not in self.allowed_targets:
            raise TRCPError("authorized asset is not inside scope")
        if self.network_mode != "LOCAL_ONLY":
            raise TRCPError("initial TRCP simulator requires LOCAL_ONLY network mode")
        if now_unix > self.expires_at:
            raise TRCPError("scope has expired")
        if not self.allowed_actions:
            raise TRCPError("scope must allow at least one action")

    def is_equal_or_narrower_than(self, parent: "ScopeEnvelope") -> bool:
        return (
            self.authorization_id == parent.authorization_id
            and set(self.allowed_targets).issubset(parent.allowed_targets)
            and set(self.allowed_actions).issubset(parent.allowed_actions)
            and set(self.allowed_environments).issubset(parent.allowed_environments)
            and set(parent.prohibited_actions).issubset(self.prohibited_actions)
            and self.data_handling_class == parent.data_handling_class
            and self.network_mode == parent.network_mode == "LOCAL_ONLY"
            and self.expires_at <= parent.expires_at
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "authorization_id": self.authorization_id,
            "allowed_targets": list(self.allowed_targets),
            "allowed_environments": list(self.allowed_environments),
            "allowed_actions": list(self.allowed_actions),
            "prohibited_actions": list(self.prohibited_actions),
            "rate_limits": {"fixture_runs": 8},
            "compute_limits": {"synthetic_steps": 32},
            "data_handling_class": self.data_handling_class,
            "network_mode": self.network_mode,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class MockProvider:
    provider_id: str
    model_id: str
    outcome: str
    synthetic_finding: Mapping[str, Any] | None = None
    provider_metadata: Mapping[str, Any] | None = None

    def run(self, normalized_task_hash: str) -> dict[str, Any]:
        if self.outcome not in PROVIDER_OUTCOMES:
            raise TRCPError("unsupported mock provider outcome")
        body: dict[str, Any] = {
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "outcome": self.outcome,
            "normalized_task_hash": normalized_task_hash,
            "synthetic_finding": dict(self.synthetic_finding or {}),
            "provider_metadata": dict(self.provider_metadata or {}),
        }
        return {**body, "provider_output_sha256": canonical_sha256(body)}


class TRCPSimulator:
    """Stateful local-only protocol simulator with hash-chained trace events."""

    def __init__(
        self,
        authorization: AuthorizationRecord,
        scope: ScopeEnvelope,
        *,
        now_unix: int = 1000,
    ) -> None:
        self.authorization = authorization
        self.scope = scope
        self.now_unix = now_unix
        self.state = "NEW"
        self.trace: list[dict[str, Any]] = []
        self.provider_runs: list[dict[str, Any]] = []
        self.failover_record: dict[str, Any] | None = None
        self.finding: dict[str, Any] | None = None
        self.verification: dict[str, Any] | None = None
        self._append("SIMULATOR_CREATED", {"state": self.state})

    def _append(self, kind: str, payload: Mapping[str, Any]) -> None:
        previous = self.trace[-1]["event_sha256"] if self.trace else "0" * 64
        core = {
            "sequence": len(self.trace) + 1,
            "observed_at_unix": 1000 + len(self.trace),
            "kind": kind,
            "state": self.state,
            "payload": dict(payload),
            "previous_event_sha256": previous,
        }
        self.trace.append({**core, "event_sha256": canonical_sha256(core)})

    def _transition(self, new_state: str, reason: str) -> None:
        previous = self.state
        self.state = new_state
        self._append("STATE_TRANSITION", {"from": previous, "to": new_state, "reason": reason})

    def advance_time(self, now_unix: int) -> None:
        if now_unix < self.now_unix:
            raise TRCPError("simulator clock cannot move backward")
        self.now_unix = now_unix
        self._append("CLOCK_ADVANCED", {"now_unix": now_unix})

    def authorize(self) -> None:
        if self.state != "NEW":
            raise TRCPError("authorize is only valid from NEW")
        self.authorization.validate(self.now_unix)
        self.scope.validate(self.authorization, self.now_unix)
        self._transition("AUTHORIZED", "authorization_and_scope_valid")

    def _validate_task(self, task: Mapping[str, Any], scope: ScopeEnvelope | None = None) -> str:
        active_scope = scope or self.scope
        required = {"task_id", "asset_id", "activity_class", "action", "fixture"}
        if set(task) != required:
            raise TRCPError("task must contain exactly task_id, asset_id, activity_class, action, fixture")
        if task["asset_id"] != self.authorization.asset_id:
            raise TRCPError("task asset is outside authorization")
        if task["asset_id"] not in active_scope.allowed_targets:
            raise TRCPError("task asset is outside scope")
        if task["activity_class"] not in self.authorization.allowed_activity_classes:
            raise TRCPError("task activity class is outside authorization")
        if task["action"] not in active_scope.allowed_actions:
            raise TRCPError("task action is outside scope")
        if active_scope.network_mode != "LOCAL_ONLY":
            raise TRCPError("task would leave local-only simulator")
        return canonical_sha256(dict(task))

    def _provider_run_record(
        self,
        provider: MockProvider,
        normalized_task_hash: str,
        output: Mapping[str, Any],
    ) -> dict[str, Any]:
        run_body = {
            "run_id": f"run:{len(self.provider_runs) + 1}",
            "scope_id": self.scope.scope_id,
            "provider_id": provider.provider_id,
            "model_id": provider.model_id,
            "started_at": 1100 + len(self.provider_runs) * 10,
            "ended_at": 1101 + len(self.provider_runs) * 10,
            "normalized_task_hash": normalized_task_hash,
            "provider_request_reference": f"mock://{provider.provider_id}/{len(self.provider_runs) + 1}",
            "outcome": output["outcome"],
            "output_artifact_reference": f"sha256:{output['provider_output_sha256']}",
        }
        return {**run_body, "record_sha256": canonical_sha256(run_body)}

    def execute_primary(self, task: Mapping[str, Any], provider: MockProvider) -> dict[str, Any]:
        if self.state != "AUTHORIZED":
            raise TRCPError("primary execution requires AUTHORIZED state")
        self.authorization.validate(self.now_unix)
        normalized_task_hash = self._validate_task(task)
        self._transition("ACTIVE", "primary_provider_started")
        output = provider.run(normalized_task_hash)
        run = self._provider_run_record(provider, normalized_task_hash, output)
        self.provider_runs.append(run)
        self._append("PROVIDER_RUN_RECORDED", run)
        if output["outcome"] in FAILOVER_OUTCOMES:
            self._transition("DEGRADED", output["outcome"])
            self._transition("FAILOVER_PENDING", "provider_continuity_required")
        elif output["outcome"] == "COMPLETED":
            self._capture_finding(output, run["run_id"])
            self._transition("VERIFYING", "primary_provider_completed")
        else:
            self._transition("ABORTED", output["outcome"])
        return output

    def record_failover(
        self,
        fallback: MockProvider,
        *,
        fallback_scope: ScopeEnvelope | None = None,
    ) -> dict[str, Any]:
        if self.state != "FAILOVER_PENDING":
            raise TRCPError("failover decision requires FAILOVER_PENDING state")
        self.authorization.validate(self.now_unix)
        candidate = fallback_scope or self.scope
        candidate.validate(self.authorization, self.now_unix)
        if not candidate.is_equal_or_narrower_than(self.scope):
            raise TRCPError("fallback scope would broaden permissions")
        permission_delta = "UNCHANGED" if candidate.as_dict() == self.scope.as_dict() else "NARROWER"
        previous_run_id = self.provider_runs[-1]["run_id"]
        body = {
            "failover_id": f"failover:{len(self.provider_runs)}",
            "previous_run_id": previous_run_id,
            "scope_id": candidate.scope_id,
            "reason": self.provider_runs[-1]["outcome"],
            "scope_revalidated": True,
            "new_provider_id": fallback.provider_id,
            "new_model_id": fallback.model_id,
            "permission_delta": permission_delta,
            "human_approval_required": False,
            "human_approval_reference": None,
            "created_at": 1200,
        }
        self.failover_record = {**body, "record_sha256": canonical_sha256(body)}
        self._append("FAILOVER_DECISION_RECORDED", self.failover_record)
        return self.failover_record

    def execute_fallback(self, task: Mapping[str, Any], provider: MockProvider) -> dict[str, Any]:
        if self.state != "FAILOVER_PENDING":
            raise TRCPError("fallback execution requires FAILOVER_PENDING state")
        if self.failover_record is None:
            raise TRCPError("fallback execution requires FailoverDecisionRecord")
        if (
            provider.provider_id != self.failover_record["new_provider_id"]
            or provider.model_id != self.failover_record["new_model_id"]
        ):
            raise TRCPError("fallback provider does not match FailoverDecisionRecord")
        self.authorization.validate(self.now_unix)
        normalized_task_hash = self._validate_task(task)
        if normalized_task_hash != self.provider_runs[-1]["normalized_task_hash"]:
            raise TRCPError("fallback must execute the same normalized task")
        self._transition("ACTIVE_ON_FALLBACK", "recorded_failover_started")
        output = provider.run(normalized_task_hash)
        run = self._provider_run_record(provider, normalized_task_hash, output)
        self.provider_runs.append(run)
        self._append("PROVIDER_RUN_RECORDED", run)
        if output["outcome"] != "COMPLETED":
            self._transition("ABORTED", f"fallback_{output['outcome'].lower()}")
            return output
        self._capture_finding(output, run["run_id"])
        self._transition("VERIFYING", "fallback_provider_completed")
        return output

    def _capture_finding(self, output: Mapping[str, Any], run_id: str) -> None:
        raw = dict(output.get("synthetic_finding") or {})
        if not raw:
            return
        allowed = {
            "finding_class",
            "location_reference",
            "summary",
            "severity_claim",
            "confidence_claim",
        }
        normalized = {key: raw[key] for key in sorted(allowed) if key in raw}
        required = allowed - {"confidence_claim"}
        if not required.issubset(normalized):
            raise TRCPError("synthetic finding is missing required normalized fields")
        body = {
            "finding_id": f"finding:{canonical_sha256(normalized)[:16]}",
            "source_run_ids": [run_id],
            "asset_id": self.authorization.asset_id,
            **normalized,
            "evidence_references": [f"sha256:{output['provider_output_sha256']}"],
            "status": "UNVERIFIED",
            "created_at": 1300,
        }
        self.finding = {**body, "record_sha256": canonical_sha256(body)}
        self._append("FINDING_RECORDED", self.finding)

    def verify(self, *, reproduced: bool) -> dict[str, Any]:
        if self.state != "VERIFYING":
            raise TRCPError("verification requires VERIFYING state")
        if self.finding is None:
            self._transition("CLOSED", "no_finding_to_verify")
            return {}
        result = "REPRODUCED" if reproduced else "NOT_REPRODUCED"
        body = {
            "verification_id": "verification:1",
            "finding_id": self.finding["finding_id"],
            "method": "DETERMINISTIC_FIXTURE",
            "verifier_type": "LOCAL_SIMULATOR",
            "verifier_reference": "fixture://trcp-verifier-v1",
            "result": result,
            "evidence_references": [
                f"sha256:{canonical_sha256({'fixture': 'trcp-verifier-v1', 'result': result})}"
            ],
            "performed_at": 1400,
        }
        self.verification = {**body, "record_sha256": canonical_sha256(body)}
        finding_body = {key: value for key, value in self.finding.items() if key != "record_sha256"}
        finding_body["status"] = result
        self.finding = {**finding_body, "record_sha256": canonical_sha256(finding_body)}
        self._append("VERIFICATION_RECORDED", self.verification)
        self._append("FINDING_STATUS_UPDATED", {"finding_id": self.finding["finding_id"], "status": result})
        return self.verification

    def confirm_finding(self) -> None:
        if self.finding is None:
            raise TRCPError("no finding exists")
        if self.verification is None or self.verification["result"] != "REPRODUCED":
            raise TRCPError("finding cannot become CONFIRMED without reproduced verification")
        body = {key: value for key, value in self.finding.items() if key != "record_sha256"}
        body["status"] = "CONFIRMED"
        self.finding = {**body, "record_sha256": canonical_sha256(body)}
        self._append("FINDING_STATUS_UPDATED", {"finding_id": self.finding["finding_id"], "status": "CONFIRMED"})
        self._transition("CLOSED", "verified_finding_confirmed")

    def report(self) -> dict[str, Any]:
        body = {
            "schema": REPORT_SCHEMA,
            "protocol_schema": SCHEMA,
            "final_state": self.state,
            "authorization": self.authorization.as_dict(),
            "scope": self.scope.as_dict(),
            "provider_runs": list(self.provider_runs),
            "failover_record": self.failover_record,
            "finding": self.finding,
            "verification": self.verification,
            "trace": list(self.trace),
            "authority": AUTHORITY,
        }
        return {**body, "report_sha256": canonical_sha256(body)}


def default_fixture() -> dict[str, Any]:
    authorization = AuthorizationRecord(
        authorization_id="auth:trcp-demo",
        subject_id="researcher:fixture",
        asset_id="fixture:repo",
        valid_from=900,
        valid_until=2000,
        allowed_activity_classes=("STATIC_ANALYSIS",),
    )
    scope = ScopeEnvelope(
        scope_id="scope:trcp-demo",
        authorization_id=authorization.authorization_id,
        allowed_targets=("fixture:repo",),
        allowed_actions=("ANALYZE_FIXTURE",),
    )
    task = {
        "task_id": "task:2",
        "asset_id": "fixture:repo",
        "activity_class": "STATIC_ANALYSIS",
        "action": "ANALYZE_FIXTURE",
        "fixture": "synthetic-safe-fixture-v1",
    }
    primary = MockProvider("provider:A", "mock-model-a", "ACCESS_RESTRICTED")
    fallback = MockProvider(
        "provider:B",
        "mock-model-b",
        "COMPLETED",
        synthetic_finding={
            "finding_class": "SYNTHETIC_BOUNDARY_CHECK",
            "location_reference": "fixture://sample#L1",
            "summary": "Synthetic fixture matches expected marker",
            "severity_claim": "LOW",
            "confidence_claim": "FIXTURE",
        },
    )
    return {
        "authorization": authorization,
        "scope": scope,
        "task": task,
        "primary": primary,
        "fallback": fallback,
    }


def run_default_scenario() -> dict[str, Any]:
    fixture = default_fixture()
    simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
    simulator.authorize()
    simulator.execute_primary(fixture["task"], fixture["primary"])
    simulator.record_failover(fixture["fallback"])
    simulator.execute_fallback(fixture["task"], fixture["fallback"])
    simulator.verify(reproduced=True)
    simulator.confirm_finding()
    return simulator.report()


__all__ = [
    "AUTHORITY",
    "AuthorizationRecord",
    "FAILOVER_OUTCOMES",
    "FINDING_STATUSES",
    "MockProvider",
    "REPORT_SCHEMA",
    "SCHEMA",
    "ScopeEnvelope",
    "TRCPError",
    "TRCPSimulator",
    "default_fixture",
    "run_default_scenario",
]
