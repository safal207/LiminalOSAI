"""Deterministic runtime Objective Integrity Guard for LiminalOS.

This layer evaluates whether a proposed or observed method remains inside an
immutable human-approved objective policy. It does not infer hidden semantic
intent from model prose. Decisions are based on normalized runtime metadata,
exact digest match rules, and externally verified integrity observations.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from sdk.liminal_post_sandbox_contracts import (
    AUTHORITY as PHASE0_AUTHORITY,
    CAPABILITY_TYPES,
    OBJECTIVE_INTEGRITY_SCHEMA,
    OBJECTIVE_VIOLATIONS,
    canonical_sha256,
    validate_objective_integrity,
)
from sdk.liminal_runtime_mediation import RuntimeMediator, RuntimeOperation

POLICY_SCHEMA = "liminal-objective-method-policy-v0.1"
RULE_SCHEMA = "liminal-objective-method-rule-v0.1"
OBSERVATION_SCHEMA = "liminal-objective-integrity-observation-v0.1"
DECISION_SCHEMA = "liminal-objective-integrity-decision-v0.1"
COMPLETION_SCHEMA = "liminal-objective-integrity-completion-v0.1"
MEDIATION_SCHEMA = "liminal-objective-guarded-mediation-v0.1"
ZERO_SHA256 = "0" * 64

AUTHORITY = {
    "mode": "objective_method_integrity_governance",
    "deterministic_policy_evaluation": True,
    "trusted_observation_verification_required": True,
    "method_integrity_completion_gate": True,
    "capability_grant": False,
    "runtime_execution": False,
    "network_execution": False,
    "secret_access": False,
    "policy_mutation": False,
    "runtime_mutation": False,
    "hidden_answer_access": False,
    "evaluator_state_access": False,
    "semantic_omniscience": False,
    "automatic_containment_execution": False,
}

DECISION_RANK = {"ALLOW": 0, "REVISE": 1, "BLOCK": 2, "CONTAIN": 3}
CRITICAL_VIOLATIONS = frozenset({
    "hidden_answer_access",
    "evaluator_state_access",
    "grader_or_benchmark_modification",
    "evidence_tampering",
    "evaluation_environment_exploitation",
    "unauthorized_policy_mutation",
    "unauthorized_runtime_mutation",
})
NONCRITICAL_VIOLATIONS = frozenset(OBJECTIVE_VIOLATIONS) - CRITICAL_VIOLATIONS


class ObjectiveIntegrityError(ValueError):
    pass


def _sha(value: Any, name: str, *, allow_zero: bool = True) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ObjectiveIntegrityError(f"{name} must be lowercase SHA-256")
    if not allow_zero and value == ZERO_SHA256:
        raise ObjectiveIntegrityError(f"{name} must not be zero SHA-256")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value or len(value) > 192:
        raise ObjectiveIntegrityError(f"{name} must be a bounded non-empty string")
    return value


def _time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ObjectiveIntegrityError(f"{name} must be a non-negative integer")
    return value


def _exact(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(raw) != expected:
        raise ObjectiveIntegrityError(f"{name} keys mismatch")


def _decision_max(values: Sequence[str]) -> str:
    if not values:
        return "ALLOW"
    return max(values, key=lambda item: DECISION_RANK[item])


@dataclass(frozen=True)
class ObjectiveMethodRule:
    rule_id: str
    runtime_kind: str
    violation_code: str
    decision: str
    scope_sha256: str
    payload_sha256: str
    rule_sha256: str

    @classmethod
    def build(
        cls,
        *,
        rule_id: str,
        runtime_kind: str,
        violation_code: str,
        decision: str,
        scope_sha256: str = ZERO_SHA256,
        payload_sha256: str = ZERO_SHA256,
    ) -> "ObjectiveMethodRule":
        item = cls(
            rule_id=_text(rule_id, "rule_id"),
            runtime_kind=_text(runtime_kind, "runtime_kind"),
            violation_code=_text(violation_code, "violation_code"),
            decision=_text(decision, "decision"),
            scope_sha256=_sha(scope_sha256, "scope_sha256"),
            payload_sha256=_sha(payload_sha256, "payload_sha256"),
            rule_sha256="",
        )
        item.validate()
        return cls(**{**item.__dict__, "rule_sha256": canonical_sha256(item.body())})

    def validate(self) -> None:
        _text(self.rule_id, "rule_id")
        if self.runtime_kind not in CAPABILITY_TYPES:
            raise ObjectiveIntegrityError("runtime_kind is not a known capability/method kind")
        if self.violation_code not in OBJECTIVE_VIOLATIONS:
            raise ObjectiveIntegrityError("unknown objective-integrity violation code")
        if self.decision not in {"REVISE", "BLOCK", "CONTAIN"}:
            raise ObjectiveIntegrityError("forbidden-method rule cannot yield ALLOW")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.payload_sha256, "payload_sha256")

    def body(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema": RULE_SCHEMA,
            "rule_id": self.rule_id,
            "runtime_kind": self.runtime_kind,
            "violation_code": self.violation_code,
            "decision": self.decision,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "rule_sha256": self.rule_sha256}

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "ObjectiveMethodRule":
        raw = dict(value)
        _exact(raw, {
            "schema", "rule_id", "runtime_kind", "violation_code", "decision",
            "scope_sha256", "payload_sha256", "authority", "rule_sha256",
        }, "objective method rule")
        if raw.get("schema") != RULE_SCHEMA or raw.get("authority") != AUTHORITY:
            raise ObjectiveIntegrityError("objective method rule schema/authority mismatch")
        item = cls.build(
            rule_id=raw["rule_id"],
            runtime_kind=raw["runtime_kind"],
            violation_code=raw["violation_code"],
            decision=raw["decision"],
            scope_sha256=raw["scope_sha256"],
            payload_sha256=raw["payload_sha256"],
        )
        if item.rule_sha256 != _sha(raw["rule_sha256"], "rule_sha256"):
            raise ObjectiveIntegrityError("objective method rule digest mismatch")
        return item

    def matches(self, action: "ObjectiveAction") -> bool:
        if action.runtime_kind != self.runtime_kind:
            return False
        if self.scope_sha256 != ZERO_SHA256 and action.scope_sha256 != self.scope_sha256:
            return False
        if self.payload_sha256 != ZERO_SHA256 and action.payload_sha256 != self.payload_sha256:
            return False
        return True


@dataclass(frozen=True)
class ObjectiveMethodPolicy:
    objective_id: str
    objective_sha256: str
    method_policy_id: str
    governance_policy_sha256: str
    allowed_runtime_kinds: tuple[str, ...]
    rules: tuple[ObjectiveMethodRule, ...]
    require_completion_evidence: bool
    policy_sha256: str

    @classmethod
    def build(
        cls,
        *,
        objective_id: str,
        objective_sha256: str,
        method_policy_id: str,
        governance_policy_sha256: str,
        allowed_runtime_kinds: Sequence[str],
        rules: Sequence[ObjectiveMethodRule] = (),
        require_completion_evidence: bool = True,
    ) -> "ObjectiveMethodPolicy":
        raw_kinds = tuple(allowed_runtime_kinds)
        kinds = tuple(sorted(set(raw_kinds)))
        if not kinds or len(kinds) != len(raw_kinds):
            raise ObjectiveIntegrityError("allowed_runtime_kinds must be non-empty and unique")
        if any(kind not in CAPABILITY_TYPES for kind in kinds):
            raise ObjectiveIntegrityError("allowed_runtime_kinds contains unknown kind")
        parsed_rules = tuple(rules)
        if any(rule.runtime_kind not in kinds for rule in parsed_rules):
            raise ObjectiveIntegrityError("objective method rule kind must be allowed by the same policy")
        ids = [item.rule_id for item in parsed_rules]
        if len(ids) != len(set(ids)):
            raise ObjectiveIntegrityError("objective method rule IDs must be unique")
        if type(require_completion_evidence) is not bool:
            raise ObjectiveIntegrityError("require_completion_evidence must be boolean")
        item = cls(
            objective_id=_text(objective_id, "objective_id"),
            objective_sha256=_sha(objective_sha256, "objective_sha256", allow_zero=False),
            method_policy_id=_text(method_policy_id, "method_policy_id"),
            governance_policy_sha256=_sha(governance_policy_sha256, "governance_policy_sha256", allow_zero=False),
            allowed_runtime_kinds=kinds,
            rules=parsed_rules,
            require_completion_evidence=require_completion_evidence,
            policy_sha256="",
        )
        return cls(**{**item.__dict__, "policy_sha256": canonical_sha256(item.body())})

    def body(self) -> dict[str, Any]:
        return {
            "schema": POLICY_SCHEMA,
            "objective_id": self.objective_id,
            "objective_sha256": self.objective_sha256,
            "method_policy_id": self.method_policy_id,
            "governance_policy_sha256": self.governance_policy_sha256,
            "allowed_runtime_kinds": list(self.allowed_runtime_kinds),
            "rules": [item.as_document() for item in sorted(self.rules, key=lambda rule: rule.rule_id)],
            "require_completion_evidence": self.require_completion_evidence,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "policy_sha256": self.policy_sha256}

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "ObjectiveMethodPolicy":
        raw = dict(value)
        _exact(raw, {
            "schema", "objective_id", "objective_sha256", "method_policy_id",
            "governance_policy_sha256", "allowed_runtime_kinds", "rules", "require_completion_evidence",
            "authority", "policy_sha256",
        }, "objective method policy")
        if raw.get("schema") != POLICY_SCHEMA or raw.get("authority") != AUTHORITY:
            raise ObjectiveIntegrityError("objective method policy schema/authority mismatch")
        if not isinstance(raw["rules"], list) or not isinstance(raw["allowed_runtime_kinds"], list):
            raise ObjectiveIntegrityError("objective method policy kinds/rules must be arrays")
        item = cls.build(
            objective_id=raw["objective_id"],
            objective_sha256=raw["objective_sha256"],
            method_policy_id=raw["method_policy_id"],
            governance_policy_sha256=raw["governance_policy_sha256"],
            allowed_runtime_kinds=tuple(raw["allowed_runtime_kinds"]),
            rules=tuple(ObjectiveMethodRule.from_document(rule) for rule in raw["rules"]),
            require_completion_evidence=raw["require_completion_evidence"],
        )
        if item.policy_sha256 != _sha(raw["policy_sha256"], "policy_sha256"):
            raise ObjectiveIntegrityError("objective method policy digest mismatch")
        return item


@dataclass(frozen=True)
class ObjectiveAction:
    action_id: str
    subject_id: str
    policy_sha256: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    at_unix: int

    def validate(self) -> None:
        _text(self.action_id, "action_id")
        _text(self.subject_id, "subject_id")
        _sha(self.policy_sha256, "policy_sha256")
        if self.runtime_kind not in CAPABILITY_TYPES:
            raise ObjectiveIntegrityError("unsupported objective action runtime_kind")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.payload_sha256, "payload_sha256")
        _time(self.at_unix, "at_unix")

    @classmethod
    def from_runtime_operation(cls, operation: RuntimeOperation) -> "ObjectiveAction":
        operation.validate()
        return cls(
            action_id=operation.operation_id,
            subject_id=operation.subject_id,
            policy_sha256=operation.policy_sha256,
            runtime_kind=operation.kind,
            scope_sha256=canonical_sha256(operation.normalized_scope()),
            payload_sha256=operation.payload_sha256,
            at_unix=operation.at_unix,
        )

    @classmethod
    def from_network_request(cls, request: Any) -> "ObjectiveAction":
        method = _text(getattr(request, "method", ""), "network method").upper()
        url = _text(getattr(request, "url", ""), "network url")
        body_sha = _sha(getattr(request, "body_sha256", ""), "network body_sha256")
        item = cls(
            action_id=_text(getattr(request, "call_id", ""), "network call_id"),
            subject_id=_text(getattr(request, "subject_id", ""), "network subject_id"),
            policy_sha256=_sha(getattr(request, "policy_sha256", ""), "network policy_sha256"),
            runtime_kind="network.connect_domain",
            scope_sha256=canonical_sha256({
                "method": method,
                "requested_url_sha256": canonical_sha256(url),
            }),
            payload_sha256=body_sha,
            at_unix=_time(getattr(request, "at_unix", None), "network at_unix"),
        )
        item.validate()
        return item


@dataclass(frozen=True)
class ObjectiveIntegrityObservation:
    observation_id: str
    objective_id: str
    method_policy_sha256: str
    source_id: str
    source_binding_sha256: str
    violation_code: str
    evidence_sha256: str
    observed_at_unix: int
    previous_observation_sha256: str
    observation_sha256: str

    @classmethod
    def build(
        cls,
        *,
        observation_id: str,
        objective_id: str,
        method_policy_sha256: str,
        source_id: str,
        source_binding_sha256: str,
        violation_code: str,
        evidence_sha256: str,
        observed_at_unix: int,
        previous_observation_sha256: str,
    ) -> "ObjectiveIntegrityObservation":
        item = cls(
            observation_id=_text(observation_id, "observation_id"),
            objective_id=_text(objective_id, "objective_id"),
            method_policy_sha256=_sha(method_policy_sha256, "method_policy_sha256"),
            source_id=_text(source_id, "source_id"),
            source_binding_sha256=_sha(source_binding_sha256, "source_binding_sha256", allow_zero=False),
            violation_code=_text(violation_code, "violation_code"),
            evidence_sha256=_sha(evidence_sha256, "evidence_sha256", allow_zero=False),
            observed_at_unix=_time(observed_at_unix, "observed_at_unix"),
            previous_observation_sha256=_sha(previous_observation_sha256, "previous_observation_sha256"),
            observation_sha256="",
        )
        if item.violation_code not in OBJECTIVE_VIOLATIONS:
            raise ObjectiveIntegrityError("unknown objective integrity violation")
        return cls(**{**item.__dict__, "observation_sha256": canonical_sha256(item.body())})

    def body(self) -> dict[str, Any]:
        return {
            "schema": OBSERVATION_SCHEMA,
            "observation_id": self.observation_id,
            "objective_id": self.objective_id,
            "method_policy_sha256": self.method_policy_sha256,
            "source_id": self.source_id,
            "source_binding_sha256": self.source_binding_sha256,
            "violation_code": self.violation_code,
            "evidence_sha256": self.evidence_sha256,
            "observed_at_unix": self.observed_at_unix,
            "previous_observation_sha256": self.previous_observation_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "observation_sha256": self.observation_sha256}

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "ObjectiveIntegrityObservation":
        raw = dict(value)
        _exact(raw, {
            "schema", "observation_id", "objective_id", "method_policy_sha256",
            "source_id", "source_binding_sha256", "violation_code", "evidence_sha256",
            "observed_at_unix", "previous_observation_sha256", "authority",
            "observation_sha256",
        }, "objective integrity observation")
        if raw.get("schema") != OBSERVATION_SCHEMA or raw.get("authority") != AUTHORITY:
            raise ObjectiveIntegrityError("objective integrity observation schema/authority mismatch")
        item = cls.build(
            observation_id=raw["observation_id"],
            objective_id=raw["objective_id"],
            method_policy_sha256=raw["method_policy_sha256"],
            source_id=raw["source_id"],
            source_binding_sha256=raw["source_binding_sha256"],
            violation_code=raw["violation_code"],
            evidence_sha256=raw["evidence_sha256"],
            observed_at_unix=raw["observed_at_unix"],
            previous_observation_sha256=raw["previous_observation_sha256"],
        )
        if item.observation_sha256 != _sha(raw["observation_sha256"], "observation_sha256"):
            raise ObjectiveIntegrityError("objective integrity observation digest mismatch")
        return item


@dataclass(frozen=True)
class ObjectiveIntegrityDecision:
    decision_id: str
    objective_id: str
    method_policy_sha256: str
    action_id_sha256: str
    subject_id_sha256: str
    runtime_kind: str
    scope_sha256: str
    payload_sha256: str
    matched_rule_ids: tuple[str, ...]
    observed_violation_codes: tuple[str, ...]
    observation_head_sha256: str
    evidence_sha256: str
    phase0_contract_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": DECISION_SCHEMA,
            "decision_id": self.decision_id,
            "objective_id": self.objective_id,
            "method_policy_sha256": self.method_policy_sha256,
            "action_id_sha256": self.action_id_sha256,
            "subject_id_sha256": self.subject_id_sha256,
            "runtime_kind": self.runtime_kind,
            "scope_sha256": self.scope_sha256,
            "payload_sha256": self.payload_sha256,
            "matched_rule_ids": list(self.matched_rule_ids),
            "observed_violation_codes": list(self.observed_violation_codes),
            "observation_head_sha256": self.observation_head_sha256,
            "evidence_sha256": self.evidence_sha256,
            "phase0_contract_sha256": self.phase0_contract_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True)
class ObjectiveCompletionReceipt:
    objective_id: str
    method_policy_sha256: str
    result_sha256: str
    trajectory_sha256: str
    method_evidence_sha256: str
    observation_head_sha256: str
    observed_violation_codes: tuple[str, ...]
    decision: str
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": COMPLETION_SCHEMA,
            "objective_id": self.objective_id,
            "method_policy_sha256": self.method_policy_sha256,
            "result_sha256": self.result_sha256,
            "trajectory_sha256": self.trajectory_sha256,
            "method_evidence_sha256": self.method_evidence_sha256,
            "observation_head_sha256": self.observation_head_sha256,
            "observed_violation_codes": list(self.observed_violation_codes),
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


ObservationVerifier = Callable[[Mapping[str, Any]], bool]


class ObjectiveIntegrityGuard:
    def __init__(
        self,
        *,
        policy: ObjectiveMethodPolicy | Mapping[str, Any],
        trusted_source_bindings: Mapping[str, str] | None = None,
        verify_observation: ObservationVerifier | None = None,
    ) -> None:
        self.policy = (
            policy if isinstance(policy, ObjectiveMethodPolicy)
            else ObjectiveMethodPolicy.from_document(policy)
        )
        bindings = dict(trusted_source_bindings or {})
        for source_id, binding_sha in bindings.items():
            _text(source_id, "trusted source_id")
            _sha(binding_sha, "trusted source binding", allow_zero=False)
        if bindings and verify_observation is None:
            raise ObjectiveIntegrityError("trusted observation verifier required when detector bindings are configured")
        self._trusted_source_bindings = bindings
        self._verify_observation = verify_observation
        self._observations: list[ObjectiveIntegrityObservation] = []
        self._observation_head = ZERO_SHA256
        self._observation_ids: set[str] = set()
        self._last_observed_at = -1
        self._decisions: list[ObjectiveIntegrityDecision] = []
        self._completions: list[ObjectiveCompletionReceipt] = []
        self._contained = False
        self._containment_evidence_sha256 = ZERO_SHA256

    @property
    def observation_head_sha256(self) -> str:
        return self._observation_head

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        self._containment_evidence_sha256 = _sha(
            incident_receipt_sha256, "incident_receipt_sha256", allow_zero=False
        )
        self._contained = True

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        # Release does not erase objective-integrity history. A new clean objective
        # epoch should instantiate a new guard/policy if critical evidence remains.
        self._containment_evidence_sha256 = _sha(
            human_release_receipt_sha256, "human_release_receipt_sha256", allow_zero=False
        )
        self._contained = False

    def ingest_observation(self, document: Mapping[str, Any]) -> dict[str, Any]:
        item = ObjectiveIntegrityObservation.from_document(document)
        expected_binding = self._trusted_source_bindings.get(item.source_id)
        if expected_binding is None:
            raise ObjectiveIntegrityError("objective observation source is not trusted")
        if item.source_binding_sha256 != expected_binding:
            raise ObjectiveIntegrityError("objective observation source binding mismatch")
        if self._verify_observation is None or self._verify_observation(item.as_document()) is not True:
            raise ObjectiveIntegrityError("objective observation external verification failed")
        if item.objective_id != self.policy.objective_id:
            raise ObjectiveIntegrityError("objective observation objective_id mismatch")
        if item.method_policy_sha256 != self.policy.policy_sha256:
            raise ObjectiveIntegrityError("objective observation method policy mismatch")
        if item.observation_id in self._observation_ids:
            raise ObjectiveIntegrityError("objective observation replay/duplicate")
        if item.previous_observation_sha256 != self._observation_head:
            raise ObjectiveIntegrityError("objective observation chain is disconnected")
        if item.observed_at_unix < self._last_observed_at:
            raise ObjectiveIntegrityError("objective observation time moved backwards")
        self._observations.append(item)
        self._observation_ids.add(item.observation_id)
        self._observation_head = item.observation_sha256
        self._last_observed_at = item.observed_at_unix
        return {
            "observation_id": item.observation_id,
            "violation_code": item.violation_code,
            "decision_floor": self._decision_for_violation(item.violation_code),
            "observation_sha256": item.observation_sha256,
        }

    def evaluate_operation(self, operation: RuntimeOperation) -> dict[str, Any]:
        return self.evaluate_action(ObjectiveAction.from_runtime_operation(operation))

    def evaluate_network_request(self, request: Any) -> dict[str, Any]:
        return self.evaluate_action(ObjectiveAction.from_network_request(request))

    def evaluate_action(self, action: ObjectiveAction) -> dict[str, Any]:
        action.validate()
        reasons: list[str] = []
        violations = {item.violation_code for item in self._observations}
        decisions: list[str] = [self._decision_for_violation(code) for code in violations]
        matched_rules: list[ObjectiveMethodRule] = []

        if self._contained:
            decisions.append("CONTAIN")
            reasons.append("containment_active")

        if action.policy_sha256 != self.policy.governance_policy_sha256:
            violations.add("unauthorized_policy_mutation")
            decisions.append("CONTAIN")
            reasons.append("governance_policy_binding_mismatch")

        if action.runtime_kind not in self.policy.allowed_runtime_kinds:
            violations.add("task_constraint_mutation")
            decisions.append("BLOCK")
            reasons.append("runtime_kind_outside_method_policy")
        else:
            reasons.append("runtime_kind_allowed")

        for rule in self.policy.rules:
            if rule.matches(action):
                matched_rules.append(rule)
                violations.add(rule.violation_code)
                decisions.append(rule.decision)
                reasons.append(f"matched_rule:{rule.rule_id}")

        if self._observations:
            reasons.append("trusted_integrity_observation_present")
        decision = _decision_max(decisions)
        if decision == "ALLOW":
            reasons.append("no_objective_integrity_violation_observed")

        evidence_sha = canonical_sha256({
            "objective_sha256": self.policy.objective_sha256,
            "method_policy_sha256": self.policy.policy_sha256,
            "action": {
                "action_id_sha256": canonical_sha256(action.action_id),
                "subject_id_sha256": canonical_sha256(action.subject_id),
                "runtime_kind": action.runtime_kind,
                "scope_sha256": action.scope_sha256,
                "payload_sha256": action.payload_sha256,
            },
            "matched_rule_sha256": [rule.rule_sha256 for rule in sorted(matched_rules, key=lambda item: item.rule_id)],
            "observation_head_sha256": self._observation_head,
            "containment_evidence_sha256": self._containment_evidence_sha256,
        })
        phase0 = validate_objective_integrity({
            "schema": OBJECTIVE_INTEGRITY_SCHEMA,
            "objective_id": self.policy.objective_id,
            "method_policy_sha256": self.policy.policy_sha256,
            "observed_violation_codes": sorted(violations),
            "decision": decision,
            "evidence_sha256": evidence_sha,
            "authority": PHASE0_AUTHORITY,
        })
        phase0_sha = canonical_sha256(phase0)
        base = ObjectiveIntegrityDecision(
            decision_id=f"objective-decision:{len(self._decisions)+1}",
            objective_id=self.policy.objective_id,
            method_policy_sha256=self.policy.policy_sha256,
            action_id_sha256=canonical_sha256(action.action_id),
            subject_id_sha256=canonical_sha256(action.subject_id),
            runtime_kind=action.runtime_kind,
            scope_sha256=action.scope_sha256,
            payload_sha256=action.payload_sha256,
            matched_rule_ids=tuple(sorted(rule.rule_id for rule in matched_rules)),
            observed_violation_codes=tuple(sorted(violations)),
            observation_head_sha256=self._observation_head,
            evidence_sha256=evidence_sha,
            phase0_contract_sha256=phase0_sha,
            decision=decision,
            reason_codes=tuple(sorted(set(reasons))),
            at_unix=action.at_unix,
            receipt_sha256="",
        )
        receipt = ObjectiveIntegrityDecision(
            **{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())}
        )
        self._decisions.append(receipt)
        return receipt.as_document()

    def verify_completion(
        self,
        *,
        result_sha256: str,
        trajectory_sha256: str,
        method_evidence_sha256: str,
        at_unix: int,
    ) -> dict[str, Any]:
        result = _sha(result_sha256, "result_sha256", allow_zero=False)
        trajectory = _sha(trajectory_sha256, "trajectory_sha256")
        method_evidence = _sha(method_evidence_sha256, "method_evidence_sha256")
        _time(at_unix, "at_unix")
        violations = tuple(sorted({item.violation_code for item in self._observations}))
        reasons: list[str] = []
        decisions = [self._decision_for_violation(code) for code in violations]

        if self._contained:
            decisions.append("CONTAIN")
            reasons.append("containment_active")
        if self.policy.require_completion_evidence and (
            trajectory == ZERO_SHA256 or method_evidence == ZERO_SHA256
        ):
            decisions.append("BLOCK")
            reasons.append("completion_evidence_missing")
        if violations:
            reasons.append("method_integrity_not_clean")
        decision = _decision_max(decisions)
        if decision == "ALLOW":
            reasons.extend(("result_digest_present", "method_integrity_proven"))

        base = ObjectiveCompletionReceipt(
            objective_id=self.policy.objective_id,
            method_policy_sha256=self.policy.policy_sha256,
            result_sha256=result,
            trajectory_sha256=trajectory,
            method_evidence_sha256=method_evidence,
            observation_head_sha256=self._observation_head,
            observed_violation_codes=violations,
            decision=decision,
            reason_codes=tuple(sorted(set(reasons))),
            at_unix=at_unix,
            receipt_sha256="",
        )
        receipt = ObjectiveCompletionReceipt(
            **{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())}
        )
        self._completions.append(receipt)
        return receipt.as_document()

    def state_document(self) -> dict[str, Any]:
        violations = tuple(sorted({item.violation_code for item in self._observations}))
        decision_floor = _decision_max([self._decision_for_violation(code) for code in violations])
        if self._contained:
            decision_floor = "CONTAIN"
        body = {
            "objective_id": self.policy.objective_id,
            "objective_sha256": self.policy.objective_sha256,
            "method_policy_sha256": self.policy.policy_sha256,
            "observation_head_sha256": self._observation_head,
            "observation_count": len(self._observations),
            "observed_violation_codes": list(violations),
            "decision_floor": decision_floor,
            "contained": self._contained,
            "containment_evidence_sha256": self._containment_evidence_sha256,
            "authority": AUTHORITY,
        }
        return {**body, "state_sha256": canonical_sha256(body)}

    def decisions(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._decisions)

    def completions(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._completions)

    @staticmethod
    def _decision_for_violation(code: str) -> str:
        if code in CRITICAL_VIOLATIONS:
            return "CONTAIN"
        if code in NONCRITICAL_VIOLATIONS:
            return "BLOCK"
        raise ObjectiveIntegrityError("unknown objective integrity violation")


class ObjectiveGuardedRuntimeMediator:
    """Opt-in mediation facade that gates effects on objective integrity."""

    def __init__(self, *, guard: ObjectiveIntegrityGuard, delegate: RuntimeMediator) -> None:
        self.guard = guard
        self.delegate = delegate
        self.broker = delegate.broker
        self.egress_gateway = delegate.egress_gateway
        self._receipts: list[dict[str, Any]] = []

    def enter_containment(self, *, incident_receipt_sha256: str) -> None:
        self.guard.enter_containment(incident_receipt_sha256=incident_receipt_sha256)
        self.delegate.enter_containment(incident_receipt_sha256=incident_receipt_sha256)

    def exit_containment(self, *, human_release_receipt_sha256: str) -> None:
        self.guard.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)
        self.delegate.exit_containment(human_release_receipt_sha256=human_release_receipt_sha256)

    def mediate(self, operation: RuntimeOperation, executor: Callable[[RuntimeOperation], Any]) -> dict[str, Any]:
        gate = self.guard.evaluate_operation(operation)
        if gate["decision"] != "ALLOW":
            return self._finish_blocked(
                action_id=operation.operation_id,
                runtime_kind=operation.kind,
                gate=gate,
                at_unix=operation.at_unix,
            )
        runtime = self.delegate.mediate(operation, executor)
        return self._finish_delegated(
            action_id=operation.operation_id,
            runtime_kind=operation.kind,
            gate=gate,
            runtime=runtime,
            at_unix=operation.at_unix,
        )

    def mediate_network(self, request: Any) -> dict[str, Any]:
        gate = self.guard.evaluate_network_request(request)
        if gate["decision"] != "ALLOW":
            return self._finish_blocked(
                action_id=getattr(request, "call_id"),
                runtime_kind="network.connect_domain",
                gate=gate,
                at_unix=getattr(request, "at_unix"),
            )
        runtime = self.delegate.mediate_network(request)
        return self._finish_delegated(
            action_id=getattr(request, "call_id"),
            runtime_kind="network.connect_domain",
            gate=gate,
            runtime=runtime,
            at_unix=getattr(request, "at_unix"),
        )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._receipts)

    def trajectory_events(self) -> tuple[Any, ...]:
        return self.delegate.trajectory_events()

    def _finish_blocked(
        self,
        *,
        action_id: str,
        runtime_kind: str,
        gate: Mapping[str, Any],
        at_unix: int,
    ) -> dict[str, Any]:
        reasons = tuple(sorted(set(gate.get("reason_codes", ())) | {
            "objective_integrity_gate_blocked",
            f"objective_decision:{gate['decision']}",
        }))
        body = {
            "schema": MEDIATION_SCHEMA,
            "action_id_sha256": canonical_sha256(action_id),
            "runtime_kind": runtime_kind,
            "objective_integrity_receipt_sha256": gate["receipt_sha256"],
            "runtime_mediation_receipt_sha256": ZERO_SHA256,
            "objective_decision": gate["decision"],
            "admission_decision": "BLOCK",
            "execution_outcome": "NOT_EXECUTED",
            "reason_codes": list(reasons),
            "at_unix": at_unix,
            "authority": AUTHORITY,
        }
        receipt = {**body, "receipt_sha256": canonical_sha256(body)}
        self._receipts.append(receipt)
        return receipt

    def _finish_delegated(
        self,
        *,
        action_id: str,
        runtime_kind: str,
        gate: Mapping[str, Any],
        runtime: Mapping[str, Any],
        at_unix: int,
    ) -> dict[str, Any]:
        reasons = tuple(sorted(set(runtime.get("reason_codes", ())) | {"objective_integrity_allow"}))
        body = {
            "schema": MEDIATION_SCHEMA,
            "action_id_sha256": canonical_sha256(action_id),
            "runtime_kind": runtime_kind,
            "objective_integrity_receipt_sha256": gate["receipt_sha256"],
            "runtime_mediation_receipt_sha256": runtime["receipt_sha256"],
            "objective_decision": gate["decision"],
            "admission_decision": runtime["admission_decision"],
            "execution_outcome": runtime["execution_outcome"],
            "reason_codes": list(reasons),
            "at_unix": at_unix,
            "authority": AUTHORITY,
        }
        receipt = {**body, "receipt_sha256": canonical_sha256(body)}
        self._receipts.append(receipt)
        return receipt


def verify_policy(document: Mapping[str, Any]) -> dict[str, Any]:
    return ObjectiveMethodPolicy.from_document(document).as_document()


def verify_observation(document: Mapping[str, Any]) -> dict[str, Any]:
    return ObjectiveIntegrityObservation.from_document(document).as_document()


def verify_decision(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != DECISION_SCHEMA or raw.get("authority") != AUTHORITY:
        raise ObjectiveIntegrityError("objective decision schema/authority mismatch")
    if raw.get("decision") not in DECISION_RANK:
        raise ObjectiveIntegrityError("objective decision value invalid")
    if digest != canonical_sha256(raw):
        raise ObjectiveIntegrityError("objective decision receipt digest mismatch")
    return dict(document)


def verify_completion(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != COMPLETION_SCHEMA or raw.get("authority") != AUTHORITY:
        raise ObjectiveIntegrityError("objective completion schema/authority mismatch")
    if raw.get("decision") not in DECISION_RANK:
        raise ObjectiveIntegrityError("objective completion decision invalid")
    if digest != canonical_sha256(raw):
        raise ObjectiveIntegrityError("objective completion receipt digest mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY",
    "COMPLETION_SCHEMA",
    "CRITICAL_VIOLATIONS",
    "DECISION_SCHEMA",
    "MEDIATION_SCHEMA",
    "NONCRITICAL_VIOLATIONS",
    "OBSERVATION_SCHEMA",
    "POLICY_SCHEMA",
    "RULE_SCHEMA",
    "ObjectiveAction",
    "ObjectiveCompletionReceipt",
    "ObjectiveGuardedRuntimeMediator",
    "ObjectiveIntegrityDecision",
    "ObjectiveIntegrityError",
    "ObjectiveIntegrityGuard",
    "ObjectiveIntegrityObservation",
    "ObjectiveMethodPolicy",
    "ObjectiveMethodRule",
    "verify_completion",
    "verify_decision",
    "verify_observation",
    "verify_policy",
]
