"""Deterministic composed-risk analysis for LiminalOS Phase 3.

The detector analyzes verified event trajectories and recommends a decision. It
never grants capabilities, executes actions, reads secret values, or performs
containment itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-causal-escalation-decision-v0.1"
AUTHORITY = {
    "mode": "trajectory_analysis_only",
    "capability_grant": False,
    "execution": False,
    "network_mediation": False,
    "credential_access": False,
    "process_control": False,
    "containment_execution": False,
    "human_release": False,
}

EVENT_KINDS = frozenset({
    "package.install",
    "network.connect_domain",
    "credential.access",
    "process.spawn_child",
    "process.execute",
    "runtime.configure",
    "repository.write",
    "capability.grant",
    "capability.revoke",
})

RULES = {
    "R-CRED-EGRESS": {"weight": 35, "requires": ("network.connect_domain", "credential.access")},
    "R-PACKAGE-EGRESS": {"weight": 20, "requires": ("package.install", "network.connect_domain")},
    "R-CRED-CHILD": {"weight": 30, "requires": ("credential.access", "process.spawn_child")},
    "R-PACKAGE-CRED-CHILD": {"weight": 45, "requires": ("package.install", "credential.access", "process.spawn_child")},
    "R-RUNTIME-CRED": {"weight": 25, "requires": ("runtime.configure", "credential.access")},
    "R-NEW-EGRESS-CHILD": {"weight": 25, "requires": ("network.connect_domain", "process.spawn_child")},
}

THRESHOLDS = {
    "ALLOW": 0,
    "REVISE": 20,
    "BLOCK": 50,
    "CONTAIN": 80,
}

class EscalationError(ValueError):
    pass


@dataclass(frozen=True)
class TrajectoryEvent:
    event_id: str
    sequence: int
    observed_at_unix: int
    kind: str
    decision: str
    subject_id: str
    capability_id: str | None
    privilege_level_before: int
    privilege_level_after: int
    metadata_sha256: str
    previous_event_sha256: str
    event_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "observed_at_unix": self.observed_at_unix,
            "kind": self.kind,
            "decision": self.decision,
            "subject_id": self.subject_id,
            "capability_id": self.capability_id,
            "privilege_level_before": self.privilege_level_before,
            "privilege_level_after": self.privilege_level_after,
            "metadata_sha256": self.metadata_sha256,
            "previous_event_sha256": self.previous_event_sha256,
        }

    @classmethod
    def build(cls, *, event_id: str, sequence: int, observed_at_unix: int, kind: str,
              decision: str, subject_id: str, capability_id: str | None,
              privilege_level_before: int, privilege_level_after: int,
              metadata: Mapping[str, Any], previous_event_sha256: str) -> "TrajectoryEvent":
        if not isinstance(event_id, str) or not event_id.strip():
            raise EscalationError("event_id must be non-empty")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise EscalationError("sequence must be >= 1")
        if not isinstance(observed_at_unix, int) or isinstance(observed_at_unix, bool) or observed_at_unix < 0:
            raise EscalationError("observed_at_unix must be non-negative")
        if kind not in EVENT_KINDS:
            raise EscalationError("unsupported event kind")
        if decision not in {"ALLOW", "BLOCK", "REVISE", "CONTAIN"}:
            raise EscalationError("unsupported decision")
        if not isinstance(subject_id, str) or not subject_id.strip():
            raise EscalationError("subject_id must be non-empty")
        for value, name in ((privilege_level_before, "privilege_level_before"), (privilege_level_after, "privilege_level_after")):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                raise EscalationError(f"{name} must be between 0 and 10")
        if len(previous_event_sha256) != 64:
            raise EscalationError("previous_event_sha256 must be a SHA-256 digest")
        base = cls(
            event_id=event_id,
            sequence=sequence,
            observed_at_unix=observed_at_unix,
            kind=kind,
            decision=decision,
            subject_id=subject_id,
            capability_id=capability_id,
            privilege_level_before=privilege_level_before,
            privilege_level_after=privilege_level_after,
            metadata_sha256=canonical_sha256(dict(metadata)),
            previous_event_sha256=previous_event_sha256,
            event_sha256="",
        )
        return cls(**{**base.__dict__, "event_sha256": canonical_sha256(base.body())})


@dataclass(frozen=True)
class EscalationDecision:
    decision: str
    risk_score: int
    matched_rules: tuple[str, ...]
    contributing_event_ids: tuple[str, ...]
    privilege_delta: int
    capability_delta: int
    explanation: str
    graph_sha256: str
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "matched_rules": list(self.matched_rules),
            "contributing_event_ids": list(self.contributing_event_ids),
            "privilege_delta": self.privilege_delta,
            "capability_delta": self.capability_delta,
            "explanation": self.explanation,
            "graph_sha256": self.graph_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


def analyze_trajectory(events: Iterable[TrajectoryEvent]) -> dict[str, Any]:
    ordered = tuple(events)
    _verify_chain(ordered)
    allowed = tuple(event for event in ordered if event.decision == "ALLOW")
    kinds = tuple(event.kind for event in allowed)
    matched: list[str] = []
    contributors: set[str] = set()
    risk = 0
    for rule_id, rule in sorted(RULES.items()):
        required = rule["requires"]
        if _ordered_subsequence(kinds, required):
            matched.append(rule_id)
            risk += int(rule["weight"])
            contributors.update(_contributors_for(allowed, required))

    privilege_delta = 0 if not ordered else ordered[-1].privilege_level_after - ordered[0].privilege_level_before
    if privilege_delta > 0:
        risk += min(25, privilege_delta * 5)
    active_caps: set[str] = set()
    max_caps = 0
    for event in allowed:
        if event.kind == "capability.grant" and event.capability_id:
            active_caps.add(event.capability_id)
        elif event.kind == "capability.revoke" and event.capability_id:
            active_caps.discard(event.capability_id)
        max_caps = max(max_caps, len(active_caps))
    capability_delta = max_caps
    if capability_delta > 1:
        risk += min(20, (capability_delta - 1) * 5)
    risk = min(100, risk)
    decision = _decision_for(risk)
    graph_sha = canonical_sha256([event.body() | {"event_sha256": event.event_sha256} for event in ordered])
    explanation = _explain(decision, risk, matched, tuple(sorted(contributors)), privilege_delta, capability_delta)
    base = EscalationDecision(
        decision=decision,
        risk_score=risk,
        matched_rules=tuple(matched),
        contributing_event_ids=tuple(sorted(contributors)),
        privilege_delta=privilege_delta,
        capability_delta=capability_delta,
        explanation=explanation,
        graph_sha256=graph_sha,
        receipt_sha256="",
    )
    receipt = EscalationDecision(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
    return receipt.as_document()


def replay(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    parsed: list[TrajectoryEvent] = []
    for raw in events:
        event = TrajectoryEvent(**dict(raw))
        if canonical_sha256(event.body()) != event.event_sha256:
            raise EscalationError("event digest mismatch")
        parsed.append(event)
    return analyze_trajectory(parsed)


def _verify_chain(events: tuple[TrajectoryEvent, ...]) -> None:
    previous = "0" * 64
    last_time = -1
    for index, event in enumerate(events, start=1):
        if event.sequence != index:
            raise EscalationError("event sequence is disconnected")
        if event.previous_event_sha256 != previous:
            raise EscalationError("causal hash chain is disconnected")
        if event.observed_at_unix < last_time:
            raise EscalationError("event time moved backwards")
        if canonical_sha256(event.body()) != event.event_sha256:
            raise EscalationError("event digest mismatch")
        previous = event.event_sha256
        last_time = event.observed_at_unix


def _ordered_subsequence(values: tuple[str, ...], required: tuple[str, ...]) -> bool:
    cursor = 0
    for value in values:
        if value == required[cursor]:
            cursor += 1
            if cursor == len(required):
                return True
    return False


def _contributors_for(events: tuple[TrajectoryEvent, ...], required: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    cursor = 0
    for event in events:
        if event.kind == required[cursor]:
            out.append(event.event_id)
            cursor += 1
            if cursor == len(required):
                break
    return tuple(out)


def _decision_for(score: int) -> str:
    if score >= THRESHOLDS["CONTAIN"]:
        return "CONTAIN"
    if score >= THRESHOLDS["BLOCK"]:
        return "BLOCK"
    if score >= THRESHOLDS["REVISE"]:
        return "REVISE"
    return "ALLOW"


def _explain(decision: str, score: int, rules: list[str], event_ids: tuple[str, ...], privilege_delta: int, capability_delta: int) -> str:
    parts = [f"trajectory risk={score}/100 → {decision}"]
    if rules:
        parts.append("matched rules: " + ", ".join(rules))
    if event_ids:
        parts.append("contributing events: " + ", ".join(event_ids))
    if privilege_delta:
        parts.append(f"privilege delta: {privilege_delta:+d}")
    if capability_delta:
        parts.append(f"peak active capability count: {capability_delta}")
    return "; ".join(parts)

__all__ = [
    "AUTHORITY",
    "EVENT_KINDS",
    "RULES",
    "SCHEMA",
    "THRESHOLDS",
    "EscalationDecision",
    "EscalationError",
    "TrajectoryEvent",
    "analyze_trajectory",
    "replay",
]
