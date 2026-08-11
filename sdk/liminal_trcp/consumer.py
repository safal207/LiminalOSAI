"""TRCP v0.3 local contract-state consumer fixture and adapter boundary.

The left block of the pipeline is a deterministic, local-only escrow state
machine mirroring the ``escrow.yaml`` scenario owned by the external
``ContractGraph-QA`` project (states CREATED/FUNDED/RELEASE_REQUESTED/
RELEASED/REFUNDED; buyer/seller actors; payout-conservation and
terminal-state-exclusivity invariants).

The adapter turns a workload run into TRCP evidence: the state machine is
exercised as a provider-capable consumer, its result becomes the TRCP
finding, and the whole run flows through the existing
``build_evidence_bundle`` / ``verify_evidence_bundle`` pipeline.

The adapter boundary is explicit: replacing the fixture state machine with
the real ContractGraph-QA engine only requires changing the left block
without touching the TRCP path.

No blockchain, network, credential, or real-target interaction exists here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import (
    AuthorizationRecord,
    MockProvider,
    ScopeEnvelope,
    TRCPSimulator,
)
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import verify_evidence_bundle

NOT_STARTED = "CREATED"
FLOW_STATES = ("CREATED", "FUNDED", "RELEASE_REQUESTED", "RELEASED", "REFUNDED")

CONTRACT_ASSET = "fixture:escrow-contract"
CONTRACT_ACTIVITY = "CONTRACT_STATE_ANALYSIS"
CONTRACT_ACTION = "ANALYZE_CONTRACT_STATE"
CONTRACT_FIXTURE = "escrow-causal-temporal-v0.1"
WORKLOAD_EVIDENCE_SCHEMA = "contract-workload-evidence-v0.1"

VALID_PATH = ("FUNDED", "RELEASE_REQUESTED", "RELEASED")
ILLEGAL_PATH = ("FUNDED", "REFUNDED", "RELEASED")
DOUBLE_RELEASE_PATH = ("FUNDED", "RELEASE_REQUESTED", "RELEASED", "RELEASED")

DEPOSIT_AMOUNT = 100
RELEASE_AMOUNT = 60
REFUND_AMOUNT = 40


class IllegalTransition(ValueError):
    """Raised when the workload attempts a state transition the contract forbids."""


class AuthorizationViolation(IllegalTransition):
    """Raised when an actor is not authorized for a contract action."""


@dataclass(frozen=True)
class ContractState:
    state: str
    released_amount: int
    refunded_amount: int

    def invariant_report(self) -> list[dict[str, Any]]:
        report: list[dict[str, Any]] = []
        if self.released_amount + self.refunded_amount > DEPOSIT_AMOUNT:
            report.append(
                {
                    "invariant_id": "payout-conservation",
                    "expression": "releasedAmount + refundedAmount <= depositedAmount",
                    "violated": True,
                }
            )
        if (self.state == "RELEASED" and self.refunded_amount != 0) or (
            self.state == "REFUNDED" and self.released_amount != 0
        ):
            report.append(
                {
                    "invariant_id": "terminal-state-exclusivity",
                    "expression": (
                        "(state != RELEASED || refundedAmount == 0)"
                        " && (state != REFUNDED || releasedAmount == 0)"
                    ),
                    "violated": True,
                }
            )
        return report


@dataclass
class EscrowFixture:
    """Deterministic local escrow state machine (worker for the TRCP consumer)."""

    state: str = NOT_STARTED
    released_amount: int = 0
    refunded_amount: int = 0
    steps: list[dict[str, Any]] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)

    def _record(self, action: str, actor: str, effect: str, pre_state: str) -> None:
        step = {
            "action": action,
            "actor": actor,
            "pre_state": pre_state,
            "post_state": self.state,
            "effect": effect,
        }
        self.steps.append(step)
        self.violations.extend(self._check_invariants())

    def _check_invariants(self) -> list[dict[str, Any]]:
        contract = ContractState(self.state, self.released_amount, self.refunded_amount)
        return contract.invariant_report()

    def fund(self, actor: str = "buyer") -> None:
        if self.state != "CREATED":
            raise IllegalTransition(f"fund is only valid from CREATED (current: {self.state})")
        if actor != "buyer":
            raise AuthorizationViolation("only the buyer may fund the escrow")
        pre_state = self.state
        self.state = "FUNDED"
        self._record("fund", actor, "escrow funded by buyer", pre_state)

    def release_request(self, actor: str = "buyer") -> None:
        if self.state != "FUNDED":
            raise IllegalTransition(
                f"release_request is only valid from FUNDED (current: {self.state})"
            )
        if actor != "buyer":
            raise AuthorizationViolation("only the buyer may request release of the escrow")
        pre_state = self.state
        self.state = "RELEASE_REQUESTED"
        self._record("release_request", actor, "buyer requested release", pre_state)

    def release(self, actor: str = "buyer") -> None:
        if self.state not in ("RELEASE_REQUESTED", "REFUNDED", "RELEASED"):
            raise IllegalTransition(
                f"release is only valid after funding (current: {self.state})"
            )
        if actor != "buyer":
            raise AuthorizationViolation("only the buyer may release the escrow")
        pre_state = self.state
        self.state = "RELEASED"
        self.released_amount += RELEASE_AMOUNT
        self._record("release", actor, "escrow released to seller", pre_state)

    def refund(self, actor: str = "buyer") -> None:
        if self.state != "FUNDED":
            raise IllegalTransition(
                f"refund is only valid from FUNDED (current: {self.state})"
            )
        if actor != "buyer":
            raise AuthorizationViolation("only the buyer may refund the escrow")
        pre_state = self.state
        self.state = "REFUNDED"
        self.refunded_amount += REFUND_AMOUNT
        self._record("refund", actor, "escrow refunded to buyer", pre_state)

    def run_path(self, path: tuple[str, ...], actor: str = "buyer") -> "EscrowFixture":
        for expected_state in path:
            action = {
                "FUNDED": "fund",
                "RELEASE_REQUESTED": "release_request",
                "RELEASED": "release",
                "REFUNDED": "refund",
            }[expected_state]
            getattr(self, action)(actor)
        return self

    def summary(self) -> dict[str, Any]:
        return {
            "contract": "Escrow",
            "network": "local-fixture",
            "path": list(self.steps),
            "violations": list(self.violations),
            "final_state": self.state,
        }


def workload_result(path: tuple[str, ...], actor: str = "buyer") -> dict[str, Any]:
    """Run the local state machine and return a deterministic workload result."""
    fixture = EscrowFixture()
    try:
        fixture.run_path(path, actor)
    except AuthorizationViolation as exc:
        fixture.violations.append(
            {
                "invariant_id": "authorization",
                "expression": "contract action requires the authorized buyer actor",
                "violated": True,
                "detail": str(exc),
            }
        )
    except IllegalTransition as exc:
        fixture.violations.append(
            {
                "invariant_id": "transition-validation",
                "expression": "requested action must be valid from the current contract state",
                "violated": True,
                "detail": str(exc),
            }
        )
    return fixture.summary()


def _workload_evidence(
    path: tuple[str, ...],
    actor: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": WORKLOAD_EVIDENCE_SCHEMA,
        "requested_path": list(path),
        "actor": actor,
        "result": result,
    }
    return {**body, "workload_sha256": canonical_sha256(body)}


def _synthetic_finding(result: dict[str, Any]) -> dict[str, Any] | None:
    if not result["violations"]:
        return None
    first = result["violations"][0]
    return {
        "finding_class": "CONTRACT_INVARIANT_VIOLATION",
        "location_reference": "fixture://esem.sol#L1",
        "summary": f"{first['invariant_id']} violated: {first['expression']}",
        "severity_claim": "HIGH",
        "confidence_claim": "DETERMINISTIC",
    }


def _task(workload_sha256: str | None = None) -> dict[str, Any]:
    fixture_reference = CONTRACT_FIXTURE
    if workload_sha256:
        fixture_reference = f"{CONTRACT_FIXTURE}@sha256:{workload_sha256}"
    return {
        "task_id": "task:contract-state",
        "asset_id": CONTRACT_ASSET,
        "activity_class": CONTRACT_ACTIVITY,
        "action": CONTRACT_ACTION,
        "fixture": fixture_reference,
    }


def contract_fixture(workload_sha256: str | None = None) -> dict[str, Any]:
    authorization = AuthorizationRecord(
        authorization_id="auth:contractgraph-demo",
        subject_id="researcher:contractgraph",
        asset_id=CONTRACT_ASSET,
        valid_from=900,
        valid_until=2000,
        allowed_activity_classes=(CONTRACT_ACTIVITY,),
    )
    scope = ScopeEnvelope(
        scope_id="scope:contractgraph-demo",
        authorization_id=authorization.authorization_id,
        allowed_targets=(CONTRACT_ASSET,),
        allowed_actions=(CONTRACT_ACTION,),
    )
    provider_metadata = (
        {"workload_sha256": workload_sha256} if workload_sha256 is not None else None
    )
    primary = MockProvider(
        "provider:cgqa-primary",
        "mock-model-a",
        "ACCESS_RESTRICTED",
        provider_metadata=provider_metadata,
    )
    return {
        "authorization": authorization,
        "scope": scope,
        "task": _task(workload_sha256),
        "primary": primary,
    }


def run_contract_consumer(
    path: tuple[str, ...],
    actor: str = "buyer",
) -> dict[str, Any]:
    """Full pipeline: local fixture -> TRCP -> evidence bundle -> replay receipt."""
    result = workload_result(path, actor)
    workload_evidence = _workload_evidence(path, actor, result)

    reproduction_result = workload_result(path, actor)
    reproduction_evidence = _workload_evidence(path, actor, reproduction_result)
    reproduced = (
        workload_evidence["workload_sha256"]
        == reproduction_evidence["workload_sha256"]
    )

    fixture = contract_fixture(workload_evidence["workload_sha256"])
    authorization: AuthorizationRecord = fixture["authorization"]
    scope: ScopeEnvelope = fixture["scope"]
    task: dict[str, Any] = fixture["task"]
    primary: MockProvider = fixture["primary"]

    fallback = MockProvider(
        "provider:cgqa-fallback",
        "mock-model-b",
        "COMPLETED",
        synthetic_finding=_synthetic_finding(result),
        provider_metadata={"workload_sha256": workload_evidence["workload_sha256"]},
    )

    simulator = TRCPSimulator(authorization, scope)
    simulator.authorize()
    simulator.execute_primary(task, primary)
    simulator.record_failover(fallback)
    simulator.execute_fallback(task, fallback)
    simulator.verify(reproduced=reproduced)
    if simulator.finding is not None and reproduced:
        simulator.confirm_finding()

    report = simulator.report()
    bundle = build_evidence_bundle(report)
    receipt = verify_evidence_bundle(bundle)

    return {
        "workload": result,
        "workload_evidence": workload_evidence,
        "reproduction": {
            "result": reproduction_result,
            "workload_sha256": reproduction_evidence["workload_sha256"],
            "matches_original": reproduced,
        },
        "report": report,
        "bundle": bundle,
        "receipt": receipt,
    }


__all__ = [
    "CONTRACT_ACTION",
    "CONTRACT_ACTIVITY",
    "CONTRACT_ASSET",
    "CONTRACT_FIXTURE",
    "DEPOSIT_AMOUNT",
    "DOUBLE_RELEASE_PATH",
    "FLOW_STATES",
    "ILLEGAL_PATH",
    "NOT_STARTED",
    "REFUND_AMOUNT",
    "RELEASE_AMOUNT",
    "VALID_PATH",
    "WORKLOAD_EVIDENCE_SCHEMA",
    "AuthorizationViolation",
    "ContractState",
    "EscrowFixture",
    "IllegalTransition",
    "contract_fixture",
    "run_contract_consumer",
    "workload_result",
]
