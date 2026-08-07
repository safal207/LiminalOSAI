"""Phase 0 contracts for LiminalOS post-sandbox governance.

This package defines capability, causal-event, evidence, objective-integrity and
containment contracts only. It does not grant capabilities, mediate syscalls or
network traffic, freeze processes, inject credentials, or execute tools.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

CONTRACT_VERSION = "0.1"
CAPABILITY_SCHEMA = "liminal-capability-contract-v0.1"
CAUSAL_EVENT_SCHEMA = "liminal-causal-runtime-event-v0.1"
EVIDENCE_SCHEMA = "liminal-runtime-evidence-requirement-v0.1"
CONTAINMENT_SCHEMA = "liminal-containment-transition-v0.1"
OBJECTIVE_INTEGRITY_SCHEMA = "liminal-objective-integrity-contract-v0.1"

CAPABILITY_TYPES = frozenset({
    "repository.read",
    "repository.write",
    "process.execute",
    "package.install",
    "network.open",
    "network.connect_domain",
    "credential.access",
    "filesystem.write_outside_workspace",
    "process.spawn_child",
    "runtime.configure",
})

CAPABILITY_EVENTS = frozenset({"grant", "use", "deny", "revoke", "expire"})
EFFECTS = frozenset({"read", "write", "execute", "network", "secret", "config"})
DECISIONS = frozenset({"ALLOW", "REVISE", "BLOCK", "CONTAIN"})
CONTAINMENT_STATES = frozenset({
    "IDLE", "DETECT", "FREEZE", "REVOKE", "SEAL", "SNAPSHOT", "REVIEW", "RELEASED"
})
CONTAINMENT_TRANSITIONS = frozenset({
    ("IDLE", "DETECT"),
    ("DETECT", "FREEZE"),
    ("FREEZE", "REVOKE"),
    ("REVOKE", "SEAL"),
    ("SEAL", "SNAPSHOT"),
    ("SNAPSHOT", "REVIEW"),
    ("REVIEW", "RELEASED"),
})
OBJECTIVE_VIOLATIONS = frozenset({
    "hidden_answer_access",
    "evaluator_state_access",
    "grader_or_benchmark_modification",
    "result_fabrication",
    "evidence_tampering",
    "task_constraint_mutation",
    "evaluation_environment_exploitation",
    "unauthorized_policy_mutation",
    "unauthorized_runtime_mutation",
})

AUTHORITY = {
    "mode": "contract_definition_only",
    "capability_grant": False,
    "capability_use": False,
    "execution": False,
    "network_mediation": False,
    "credential_access": False,
    "process_control": False,
    "containment_execution": False,
    "human_release": False,
    "policy_mutation": False,
}

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")


class ContractError(ValueError):
    """Raised when a Phase 0 contract is malformed or semantically unsafe."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be a JSON object")
    return dict(value)


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value:
        raise ContractError(f"{name} must be a non-empty trimmed string without NUL")
    return value


def _identifier(value: Any, name: str) -> str:
    item = _string(value, name)
    if not _IDENT.fullmatch(item):
        raise ContractError(f"{name} contains unsupported characters")
    return item


def _sha(value: Any, name: str) -> str:
    item = _string(value, name).lower()
    if not _SHA.fullmatch(item):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")
    return item


def _time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{name} must be a non-negative Unix timestamp")
    return value


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{name} must be boolean")
    return value


def _int(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{name} must be an integer >= {minimum}")
    return value


def _exact(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    missing = sorted(expected - set(raw))
    extra = sorted(set(raw) - expected)
    if missing:
        raise ContractError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise ContractError(f"{name} contains unsupported keys: {', '.join(extra)}")


def _sorted_unique_strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{name} must be an array")
    result = tuple(sorted(_identifier(item, f"{name}[]") for item in value))
    if len(result) != len(set(result)):
        raise ContractError(f"{name} contains duplicates")
    return result


def validate_scope(capability_type: str, value: Any) -> dict[str, Any]:
    raw = _mapping(value, "scope")
    allowed_by_type = {
        "repository.read": {"repository", "refs", "paths"},
        "repository.write": {"repository", "refs", "paths"},
        "process.execute": {"executables", "working_directory", "argument_profile"},
        "package.install": {"registries", "packages"},
        "network.open": {"protocols"},
        "network.connect_domain": {"domains", "protocols", "ports"},
        "credential.access": {"credential_ids", "purpose"},
        "filesystem.write_outside_workspace": {"paths"},
        "process.spawn_child": {"executables", "max_children"},
        "runtime.configure": {"setting_keys"},
    }
    allowed = allowed_by_type[capability_type]
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ContractError("scope contains unsupported keys: " + ", ".join(unknown))
    if not raw:
        raise ContractError("scope must not be empty")
    result: dict[str, Any] = {}
    for key, item in raw.items():
        if key == "repository":
            repo = _string(item, "scope.repository")
            if not _REPO.fullmatch(repo):
                raise ContractError("scope.repository must use owner/name form")
            result[key] = repo
        elif key == "domains":
            if not isinstance(item, list) or not item:
                raise ContractError("scope.domains must be a non-empty array")
            domains = tuple(sorted(_string(domain, "scope.domains[]").lower() for domain in item))
            if len(domains) != len(set(domains)) or any(not _DOMAIN.fullmatch(domain) for domain in domains):
                raise ContractError("scope.domains must contain unique DNS names")
            result[key] = list(domains)
        elif key in {"ports"}:
            if not isinstance(item, list) or not item:
                raise ContractError("scope.ports must be a non-empty array")
            ports = sorted(item)
            if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
                raise ContractError("scope.ports must contain valid TCP/UDP ports")
            if len(ports) != len(set(ports)):
                raise ContractError("scope.ports contains duplicates")
            result[key] = ports
        elif key == "max_children":
            result[key] = _int(item, "scope.max_children", minimum=1)
        elif isinstance(item, list):
            if not item:
                raise ContractError(f"scope.{key} must not be empty")
            values = [_string(v, f"scope.{key}[]") for v in item]
            if len(values) != len(set(values)):
                raise ContractError(f"scope.{key} contains duplicates")
            result[key] = sorted(values)
        else:
            result[key] = _string(item, f"scope.{key}")
    return {key: result[key] for key in sorted(result)}


@dataclass(frozen=True)
class CapabilityContract:
    capability_id: str
    capability_type: str
    subject_id: str
    issuer_id: str
    scope: Mapping[str, Any]
    issued_at_unix: int
    not_before_unix: int
    expires_at_unix: int
    max_uses: int
    delegable: bool
    parent_capability_id: str | None
    policy_sha256: str
    contract_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": CAPABILITY_SCHEMA,
            "capability_id": self.capability_id,
            "capability_type": self.capability_type,
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "scope": dict(self.scope),
            "issued_at_unix": self.issued_at_unix,
            "not_before_unix": self.not_before_unix,
            "expires_at_unix": self.expires_at_unix,
            "max_uses": self.max_uses,
            "delegable": self.delegable,
            "parent_capability_id": self.parent_capability_id,
            "policy_sha256": self.policy_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "contract_sha256": self.contract_sha256}

    @classmethod
    def build(cls, **kwargs: Any) -> "CapabilityContract":
        provisional = {"schema": CAPABILITY_SCHEMA, **kwargs, "authority": AUTHORITY}
        return cls.from_document({**provisional, "contract_sha256": canonical_sha256(provisional)})

    @classmethod
    def from_document(cls, value: Any) -> "CapabilityContract":
        raw = _mapping(value, "capability")
        expected = {
            "schema", "capability_id", "capability_type", "subject_id", "issuer_id", "scope",
            "issued_at_unix", "not_before_unix", "expires_at_unix", "max_uses", "delegable",
            "parent_capability_id", "policy_sha256", "authority", "contract_sha256",
        }
        _exact(raw, expected, "capability")
        if raw["schema"] != CAPABILITY_SCHEMA or raw["authority"] != AUTHORITY:
            raise ContractError("capability schema or authority boundary mismatch")
        capability_type = _string(raw["capability_type"], "capability_type")
        if capability_type not in CAPABILITY_TYPES:
            raise ContractError("unsupported capability_type")
        issued = _time(raw["issued_at_unix"], "issued_at_unix")
        not_before = _time(raw["not_before_unix"], "not_before_unix")
        expires = _time(raw["expires_at_unix"], "expires_at_unix")
        if not (issued <= not_before < expires):
            raise ContractError("capability validity window is invalid")
        max_uses = _int(raw["max_uses"], "max_uses", minimum=1)
        if max_uses > 1000:
            raise ContractError("max_uses exceeds Phase 0 bounded contract limit")
        delegable = _bool(raw["delegable"], "delegable")
        parent = raw["parent_capability_id"]
        if parent is not None:
            parent = _identifier(parent, "parent_capability_id")
        if delegable and parent is None:
            raise ContractError("delegable capabilities require explicit parent_capability_id")
        item = cls(
            capability_id=_identifier(raw["capability_id"], "capability_id"),
            capability_type=capability_type,
            subject_id=_identifier(raw["subject_id"], "subject_id"),
            issuer_id=_identifier(raw["issuer_id"], "issuer_id"),
            scope=validate_scope(capability_type, raw["scope"]),
            issued_at_unix=issued,
            not_before_unix=not_before,
            expires_at_unix=expires,
            max_uses=max_uses,
            delegable=delegable,
            parent_capability_id=parent,
            policy_sha256=_sha(raw["policy_sha256"], "policy_sha256"),
            contract_sha256=_sha(raw["contract_sha256"], "contract_sha256"),
        )
        if canonical_sha256(item.body()) != item.contract_sha256:
            raise ContractError("capability contract_sha256 mismatch")
        return item


@dataclass(frozen=True)
class CausalRuntimeEvent:
    event_id: str
    event_type: str
    subject_id: str
    capability_id: str | None
    recorder_event_id: str | None
    recorder_entry_sha256: str | None
    effect: str
    decision: str
    observed_at_unix: int
    previous_causal_event_sha256: str
    input_sha256: str
    output_sha256: str | None
    reason_codes: tuple[str, ...]
    event_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": CAUSAL_EVENT_SCHEMA,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "capability_id": self.capability_id,
            "recorder_event_id": self.recorder_event_id,
            "recorder_entry_sha256": self.recorder_entry_sha256,
            "effect": self.effect,
            "decision": self.decision,
            "observed_at_unix": self.observed_at_unix,
            "previous_causal_event_sha256": self.previous_causal_event_sha256,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "reason_codes": list(self.reason_codes),
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "event_sha256": self.event_sha256}

    @classmethod
    def build(cls, **kwargs: Any) -> "CausalRuntimeEvent":
        body = {"schema": CAUSAL_EVENT_SCHEMA, **kwargs, "authority": AUTHORITY}
        return cls.from_document({**body, "event_sha256": canonical_sha256(body)})

    @classmethod
    def from_document(cls, value: Any) -> "CausalRuntimeEvent":
        raw = _mapping(value, "causal_event")
        expected = {
            "schema", "event_id", "event_type", "subject_id", "capability_id",
            "recorder_event_id", "recorder_entry_sha256", "effect", "decision",
            "observed_at_unix", "previous_causal_event_sha256", "input_sha256",
            "output_sha256", "reason_codes", "authority", "event_sha256",
        }
        _exact(raw, expected, "causal_event")
        if raw["schema"] != CAUSAL_EVENT_SCHEMA or raw["authority"] != AUTHORITY:
            raise ContractError("causal-event schema or authority boundary mismatch")
        event_type = _string(raw["event_type"], "event_type")
        if event_type not in CAPABILITY_EVENTS | {"runtime_action", "objective_violation", "containment_transition"}:
            raise ContractError("unsupported causal event_type")
        effect = _string(raw["effect"], "effect")
        if effect not in EFFECTS:
            raise ContractError("unsupported effect")
        decision = _string(raw["decision"], "decision")
        if decision not in DECISIONS:
            raise ContractError("unsupported decision")
        capability_id = None if raw["capability_id"] is None else _identifier(raw["capability_id"], "capability_id")
        if event_type in {"grant", "use", "deny", "revoke", "expire"} and capability_id is None:
            raise ContractError("capability lifecycle event requires capability_id")
        recorder_id = None if raw["recorder_event_id"] is None else _identifier(raw["recorder_event_id"], "recorder_event_id")
        recorder_hash = None if raw["recorder_entry_sha256"] is None else _sha(raw["recorder_entry_sha256"], "recorder_entry_sha256")
        if (recorder_id is None) != (recorder_hash is None):
            raise ContractError("recorder_event_id and recorder_entry_sha256 must appear together")
        reasons = _sorted_unique_strings(raw["reason_codes"], "reason_codes")
        if not reasons:
            raise ContractError("reason_codes must not be empty")
        output_hash = None if raw["output_sha256"] is None else _sha(raw["output_sha256"], "output_sha256")
        item = cls(
            event_id=_identifier(raw["event_id"], "event_id"), event_type=event_type,
            subject_id=_identifier(raw["subject_id"], "subject_id"), capability_id=capability_id,
            recorder_event_id=recorder_id, recorder_entry_sha256=recorder_hash, effect=effect,
            decision=decision, observed_at_unix=_time(raw["observed_at_unix"], "observed_at_unix"),
            previous_causal_event_sha256=_sha(raw["previous_causal_event_sha256"], "previous_causal_event_sha256"),
            input_sha256=_sha(raw["input_sha256"], "input_sha256"), output_sha256=output_hash,
            reason_codes=reasons, event_sha256=_sha(raw["event_sha256"], "event_sha256"),
        )
        if canonical_sha256(item.body()) != item.event_sha256:
            raise ContractError("causal event_sha256 mismatch")
        return item


@dataclass(frozen=True)
class RuntimeEvidenceRequirement:
    action_class: str
    required_roots: tuple[str, ...]
    require_capability: bool
    require_recorder_link: bool
    require_result_digest: bool
    fail_closed_on_missing: bool
    requirement_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "action_class": self.action_class,
            "required_roots": list(self.required_roots),
            "require_capability": self.require_capability,
            "require_recorder_link": self.require_recorder_link,
            "require_result_digest": self.require_result_digest,
            "fail_closed_on_missing": self.fail_closed_on_missing,
            "authority": AUTHORITY,
        }

    @classmethod
    def build(cls, *, action_class: str, required_roots: list[str], require_capability: bool = True,
              require_recorder_link: bool = True, require_result_digest: bool = True,
              fail_closed_on_missing: bool = True) -> "RuntimeEvidenceRequirement":
        body = {
            "schema": EVIDENCE_SCHEMA,
            "action_class": _identifier(action_class, "action_class"),
            "required_roots": sorted(required_roots),
            "require_capability": require_capability,
            "require_recorder_link": require_recorder_link,
            "require_result_digest": require_result_digest,
            "fail_closed_on_missing": fail_closed_on_missing,
            "authority": AUTHORITY,
        }
        return cls.from_document({**body, "requirement_sha256": canonical_sha256(body)})

    @classmethod
    def from_document(cls, value: Any) -> "RuntimeEvidenceRequirement":
        raw = _mapping(value, "evidence_requirement")
        expected = {"schema", "action_class", "required_roots", "require_capability", "require_recorder_link",
                    "require_result_digest", "fail_closed_on_missing", "authority", "requirement_sha256"}
        _exact(raw, expected, "evidence_requirement")
        if raw["schema"] != EVIDENCE_SCHEMA or raw["authority"] != AUTHORITY:
            raise ContractError("evidence schema or authority boundary mismatch")
        roots = _sorted_unique_strings(raw["required_roots"], "required_roots")
        if not roots:
            raise ContractError("required_roots must not be empty")
        item = cls(
            action_class=_identifier(raw["action_class"], "action_class"), required_roots=roots,
            require_capability=_bool(raw["require_capability"], "require_capability"),
            require_recorder_link=_bool(raw["require_recorder_link"], "require_recorder_link"),
            require_result_digest=_bool(raw["require_result_digest"], "require_result_digest"),
            fail_closed_on_missing=_bool(raw["fail_closed_on_missing"], "fail_closed_on_missing"),
            requirement_sha256=_sha(raw["requirement_sha256"], "requirement_sha256"),
        )
        if not item.fail_closed_on_missing:
            raise ContractError("Phase 0 sensitive runtime evidence must fail closed")
        if canonical_sha256(item.body()) != item.requirement_sha256:
            raise ContractError("evidence requirement_sha256 mismatch")
        return item

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "requirement_sha256": self.requirement_sha256}


def validate_containment_transition(value: Any) -> dict[str, Any]:
    raw = _mapping(value, "containment_transition")
    expected = {"schema", "incident_id", "from_state", "to_state", "reason_codes", "evidence_sha256", "at_unix", "human_release_id", "authority"}
    _exact(raw, expected, "containment_transition")
    if raw["schema"] != CONTAINMENT_SCHEMA or raw["authority"] != AUTHORITY:
        raise ContractError("containment schema or authority boundary mismatch")
    before = _string(raw["from_state"], "from_state")
    after = _string(raw["to_state"], "to_state")
    if before not in CONTAINMENT_STATES or after not in CONTAINMENT_STATES or (before, after) not in CONTAINMENT_TRANSITIONS:
        raise ContractError("illegal containment transition")
    reasons = _sorted_unique_strings(raw["reason_codes"], "reason_codes")
    if not reasons:
        raise ContractError("containment reason_codes must not be empty")
    release_id = raw["human_release_id"]
    if after == "RELEASED":
        if release_id is None:
            raise ContractError("RELEASED requires explicit human_release_id")
        release_id = _identifier(release_id, "human_release_id")
    elif release_id is not None:
        raise ContractError("human_release_id is allowed only for RELEASED")
    return {
        "schema": CONTAINMENT_SCHEMA,
        "incident_id": _identifier(raw["incident_id"], "incident_id"),
        "from_state": before,
        "to_state": after,
        "reason_codes": list(reasons),
        "evidence_sha256": _sha(raw["evidence_sha256"], "evidence_sha256"),
        "at_unix": _time(raw["at_unix"], "at_unix"),
        "human_release_id": release_id,
        "authority": AUTHORITY,
    }


def validate_objective_integrity(value: Any) -> dict[str, Any]:
    raw = _mapping(value, "objective_integrity")
    expected = {"schema", "objective_id", "method_policy_sha256", "observed_violation_codes", "decision", "evidence_sha256", "authority"}
    _exact(raw, expected, "objective_integrity")
    if raw["schema"] != OBJECTIVE_INTEGRITY_SCHEMA or raw["authority"] != AUTHORITY:
        raise ContractError("objective-integrity schema or authority boundary mismatch")
    violations = _sorted_unique_strings(raw["observed_violation_codes"], "observed_violation_codes")
    unknown = sorted(set(violations) - OBJECTIVE_VIOLATIONS)
    if unknown:
        raise ContractError("unknown objective-integrity violation: " + ", ".join(unknown))
    decision = _string(raw["decision"], "decision")
    if decision not in DECISIONS:
        raise ContractError("unsupported objective-integrity decision")
    if violations and decision == "ALLOW":
        raise ContractError("observed objective-integrity violations cannot yield ALLOW")
    return {
        "schema": OBJECTIVE_INTEGRITY_SCHEMA,
        "objective_id": _identifier(raw["objective_id"], "objective_id"),
        "method_policy_sha256": _sha(raw["method_policy_sha256"], "method_policy_sha256"),
        "observed_violation_codes": list(violations),
        "decision": decision,
        "evidence_sha256": _sha(raw["evidence_sha256"], "evidence_sha256"),
        "authority": AUTHORITY,
    }


def default_evidence_requirements() -> tuple[RuntimeEvidenceRequirement, ...]:
    roots = ["policy_sha256", "capability_sha256", "input_sha256", "recorder_entry_sha256"]
    return tuple(
        RuntimeEvidenceRequirement.build(
            action_class=capability_type.replace(".", ":"),
            required_roots=roots + (["result_sha256"] if capability_type != "network.open" else ["network_receipt_sha256"]),
        )
        for capability_type in sorted(CAPABILITY_TYPES)
    )


__all__ = [
    "AUTHORITY", "CAPABILITY_EVENTS", "CAPABILITY_SCHEMA", "CAPABILITY_TYPES",
    "CAUSAL_EVENT_SCHEMA", "CONTAINMENT_SCHEMA", "CONTAINMENT_STATES", "CONTAINMENT_TRANSITIONS",
    "CONTRACT_VERSION", "DECISIONS", "EFFECTS", "EVIDENCE_SCHEMA", "OBJECTIVE_INTEGRITY_SCHEMA",
    "OBJECTIVE_VIOLATIONS", "CapabilityContract", "CausalRuntimeEvent", "ContractError",
    "RuntimeEvidenceRequirement", "canonical_json", "canonical_sha256", "default_evidence_requirements",
    "validate_containment_transition", "validate_objective_integrity", "validate_scope",
]
