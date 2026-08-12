"""TRCP v0.4 — Non-escrow external consumer fixture: delegated spending / quota.

Deterministic synthetic consumer that models an AI-agent spending control
(close to real agent controls without repeating the escrow consumer):

    ACTIVE -> ACTION_REQUESTED -> APPROVED -> EXECUTED
    ACTION_REQUESTED -> REJECTED (terminal)

Invariants the workload must satisfy:

- actor authority: every operation requires its authorized actor
- per-action limit: a single executed action never exceeds the per-action cap
- cumulative quota: total spent never exceeds the delegated quota
- terminal exclusivity: EXECUTED and REJECTED are mutually exclusive
- rejected action -> no mutation: a rejected action never changes spending

Like the escrow fixture, the machine records what the workload attempts and
the invariant report flags what the attempt violated. The adapter
(``DelegatedSpendingAdapter``) implements the provider-neutral
``ExternalWorkloadAdapter`` contract from ``sdk.liminal_trcp.adapter``:
``normalize`` produces the canonical workload body, ``task``/``fixture``
build the TRCP records, and ``replay_execution`` is the optional execution
replay hook (re-runs the workload from its normalized input).

No blockchain, network, credential, or real-target interaction exists here.
LOCAL_ONLY / SYNTHETIC_ONLY.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Mapping

from sdk.liminal_trcp import AuthorizationRecord, MockProvider, ScopeEnvelope
from sdk.liminal_trcp.adapter import run_external_consumer
from sdk.liminal_trcp.replay import GENERIC_WORKLOAD_EVIDENCE_SCHEMA

CONSUMER_TYPE = "delegated-spending"
CONSUMER_FIXTURE = "delegated-spending-quota-v0.1"
CONSUMER_ASSET = "fixture:delegated-spending"
CONSUMER_ACTIVITY = "DELEGATED_ACTION_GOVERNANCE"
CONSUMER_ACTION = "GOVERN_DELEGATED_SPENDING"

AGENT_ACTOR = "agent"
APPROVER_ACTOR = "approver"

PER_ACTION_LIMIT = 100
CUMULATIVE_QUOTA = 150

VALID_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 40},
        {"operation": "approve"},
        {"operation": "execute"},
    ],
    "actor_schedule": ["agent", "approver", "agent"],
}
REJECTED_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 40},
        {"operation": "reject"},
    ],
    "actor_schedule": ["agent", "approver"],
}
AUTHORITY_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 40},
    ],
    "actor_schedule": ["approver"],
}
LIMIT_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 120},
        {"operation": "approve"},
        {"operation": "execute"},
    ],
    "actor_schedule": ["agent", "approver", "agent"],
}
QUOTA_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 100},
        {"operation": "approve"},
        {"operation": "execute"},
        {"operation": "execute"},
    ],
    "actor_schedule": ["agent", "approver", "agent", "agent"],
}
TERMINAL_EXTERNAL_INPUT: dict[str, Any] = {
    "operations": [
        {"operation": "request_action", "amount": 40},
        {"operation": "reject"},
        {"operation": "execute"},
    ],
    "actor_schedule": ["agent", "approver", "agent"],
}


class DelegatedSpendingViolation(ValueError):
    """Raised when the workload attempts an operation the machine forbids."""


class AuthorityViolation(DelegatedSpendingViolation):
    """Raised when an actor is not authorized for a delegated operation."""


class IllegalOperation(DelegatedSpendingViolation):
    """Raised when an operation is not valid from the current state."""


@dataclass
class DelegatedSpendingFixture:
    """Deterministic delegated-spending state machine (worker for the adapter)."""

    state: str = "ACTIVE"
    spent: int = 0
    requested_amount: int = 0
    rejected: bool = False
    last_executed_amount: int | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)

    def _record(self, operation: str, actor: str, effect: str, pre_state: str) -> None:
        step = {
            "operation": operation,
            "actor": actor,
            "pre_state": pre_state,
            "post_state": self.state,
            "effect": effect,
        }
        self.steps.append(step)
        recorded_ids = {v["invariant_id"] for v in self.violations}
        self.violations.extend(
            report
            for report in self._check_invariants()
            if report["invariant_id"] not in recorded_ids
        )

    def _check_invariants(self) -> list[dict[str, Any]]:
        report: list[dict[str, Any]] = []
        if self.last_executed_amount is not None and self.last_executed_amount > PER_ACTION_LIMIT:
            report.append(
                {
                    "invariant_id": "per-action-limit",
                    "expression": "executedAmount <= perActionLimit",
                    "violated": True,
                }
            )
        if self.spent > CUMULATIVE_QUOTA:
            report.append(
                {
                    "invariant_id": "cumulative-quota",
                    "expression": "spent <= cumulativeQuota",
                    "violated": True,
                }
            )
        if (self.state == "EXECUTED" and self.rejected) or (
            self.state == "REJECTED" and self.spent > 0
        ):
            report.append(
                {
                    "invariant_id": "terminal-exclusivity",
                    "expression": "EXECUTED and REJECTED are mutually exclusive terminal states",
                    "violated": True,
                }
            )
        if self.rejected and self.spent > 0:
            report.append(
                {
                    "invariant_id": "rejected-action-no-mutation",
                    "expression": "a rejected action must not mutate spending",
                    "violated": True,
                }
            )
        return report

    def request_action(self, actor: str, amount: int) -> None:
        if self.state != "ACTIVE":
            raise IllegalOperation(
                f"request_action is only valid from ACTIVE (current: {self.state})"
            )
        if actor != AGENT_ACTOR:
            raise AuthorityViolation("only the delegated agent may request an action")
        pre_state = self.state
        self.state = "ACTION_REQUESTED"
        self.requested_amount = amount
        self._record("request_action", actor, f"action requested for {amount}", pre_state)

    def approve(self, actor: str) -> None:
        if self.state != "ACTION_REQUESTED":
            raise IllegalOperation(
                f"approve is only valid from ACTION_REQUESTED (current: {self.state})"
            )
        if actor != APPROVER_ACTOR:
            raise AuthorityViolation("only the controller may approve an action")
        pre_state = self.state
        self.state = "APPROVED"
        self._record("approve", actor, "action approved", pre_state)

    def reject(self, actor: str) -> None:
        if self.state != "ACTION_REQUESTED":
            raise IllegalOperation(
                f"reject is only valid from ACTION_REQUESTED (current: {self.state})"
            )
        if actor != APPROVER_ACTOR:
            raise AuthorityViolation("only the controller may reject an action")
        pre_state = self.state
        self.state = "REJECTED"
        self.rejected = True
        self._record("reject", actor, "action rejected (no mutation)", pre_state)

    def execute(self, actor: str) -> None:
        if self.state not in ("APPROVED", "REJECTED", "EXECUTED"):
            raise IllegalOperation(
                f"execute is only valid after approval (current: {self.state})"
            )
        if actor != AGENT_ACTOR:
            raise AuthorityViolation("only the delegated agent may execute an action")
        pre_state = self.state
        self.state = "EXECUTED"
        self.spent += self.requested_amount
        self.last_executed_amount = self.requested_amount
        self._record("execute", actor, f"executed action for {self.requested_amount}", pre_state)

    def summary(self) -> dict[str, Any]:
        return {
            "consumer": CONSUMER_TYPE,
            "final_state": self.state,
            "spent": self.spent,
            "steps": list(self.steps),
            "violations": list(self.violations),
        }


def delegated_workload_result(external_input: Mapping[str, Any]) -> dict[str, Any]:
    """Run the delegated-spending state machine and return the workload result.

    ``actor_schedule`` is either a single actor applied to every operation or
    a per-operation schedule of the same length as ``operations``.
    """
    fixture = DelegatedSpendingFixture()
    operations = external_input["operations"]
    schedule = external_input.get("actor_schedule", AGENT_ACTOR)
    if isinstance(schedule, str):
        schedule = [schedule] * len(operations)
    if len(schedule) != len(operations):
        raise ValueError("actor_schedule length must match operations length")

    for operation, actor in zip(operations, schedule, strict=True):
        name = operation["operation"]
        try:
            if name == "request_action":
                fixture.request_action(actor, operation["amount"])
            elif name == "approve":
                fixture.approve(actor)
            elif name == "reject":
                fixture.reject(actor)
            elif name == "execute":
                fixture.execute(actor)
            else:
                fixture.violations.append(
                    {
                        "invariant_id": "unknown-operation",
                        "expression": (
                            "operation must be one of request_action/approve/reject/execute"
                        ),
                        "violated": True,
                        "detail": f"unknown operation: {name}",
                    }
                )
        except AuthorityViolation as exc:
            fixture.violations.append(
                {
                    "invariant_id": "actor-authority",
                    "expression": "each delegated operation requires its authorized actor",
                    "violated": True,
                    "detail": str(exc),
                }
            )
        except IllegalOperation as exc:
            fixture.violations.append(
                {
                    "invariant_id": "transition-validation",
                    "expression": "operation must be valid from the current machine state",
                    "violated": True,
                    "detail": str(exc),
                }
            )
        except KeyError as exc:
            fixture.violations.append(
                {
                    "invariant_id": "malformed-operation",
                    "expression": "each operation must carry its required fields",
                    "violated": True,
                    "detail": f"missing field: {exc}",
                }
            )
    return fixture.summary()


def normalize_delegated_workload(external_input: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize external input into the canonical generic workload body."""
    result = delegated_workload_result(external_input)
    return {
        "schema": GENERIC_WORKLOAD_EVIDENCE_SCHEMA,
        "consumer_type": CONSUMER_TYPE,
        "requested_operation": [op["operation"] for op in external_input["operations"]],
        "actor": external_input.get("actor_schedule", AGENT_ACTOR),
        "input": copy.deepcopy(dict(external_input)),
        "result": result,
    }


@dataclass(frozen=True)
class DelegatedSpendingAdapter:
    """TRCP v0.4 adapter for the delegated-spending external consumer."""

    consumer_type: str = CONSUMER_TYPE
    fixture_name: str = CONSUMER_FIXTURE
    asset_id: str = CONSUMER_ASSET
    activity_class: str = CONSUMER_ACTIVITY
    action: str = CONSUMER_ACTION
    primary_provider_id: str = "provider:delegated-primary"

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        return normalize_delegated_workload(external_input)

    def task(self, workload_sha256: str) -> dict[str, Any]:
        return {
            "task_id": "task:delegated-spending",
            "asset_id": self.asset_id,
            "activity_class": self.activity_class,
            "action": self.action,
            "fixture": f"{self.fixture_name}@sha256:{workload_sha256}",
        }

    def fixture(self, workload_sha256: str) -> dict[str, Any]:
        authorization = AuthorizationRecord(
            authorization_id="auth:delegated-spending-demo",
            subject_id="researcher:delegated-spending",
            asset_id=self.asset_id,
            valid_from=900,
            valid_until=2000,
            allowed_activity_classes=(self.activity_class,),
        )
        scope = ScopeEnvelope(
            scope_id="scope:delegated-spending-demo",
            authorization_id=authorization.authorization_id,
            allowed_targets=(self.asset_id,),
            allowed_actions=(self.action,),
        )
        primary = MockProvider(
            self.primary_provider_id,
            "mock-model-a",
            "ACCESS_RESTRICTED",
            provider_metadata={"workload_sha256": workload_sha256},
        )
        return {
            "authorization": authorization,
            "scope": scope,
            "task": self.task(workload_sha256),
            "primary": primary,
        }

    def replay_execution(self, workload_body: Mapping[str, Any]) -> dict[str, Any]:
        """Optional execution replay hook: re-run from the normalized input."""
        return delegated_workload_result(workload_body["input"])


__all__ = [
    "AGENT_ACTOR",
    "APPROVER_ACTOR",
    "AUTHORITY_EXTERNAL_INPUT",
    "AuthorityViolation",
    "CONSUMER_ACTION",
    "CONSUMER_ACTIVITY",
    "CONSUMER_ASSET",
    "CONSUMER_FIXTURE",
    "CONSUMER_TYPE",
    "CUMULATIVE_QUOTA",
    "DelegatedSpendingAdapter",
    "DelegatedSpendingFixture",
    "DelegatedSpendingViolation",
    "IllegalOperation",
    "LIMIT_EXTERNAL_INPUT",
    "PER_ACTION_LIMIT",
    "QUOTA_EXTERNAL_INPUT",
    "REJECTED_EXTERNAL_INPUT",
    "TERMINAL_EXTERNAL_INPUT",
    "VALID_EXTERNAL_INPUT",
    "delegated_workload_result",
    "normalize_delegated_workload",
    "run_external_consumer",
]
