"""Contracts for GitHub Transaction Policy & Approval Engine v0.9."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from sdk.liminal_github_bridge import OPERATION_POLICIES
from sdk.liminal_github_transaction import TransactionPlan

POLICY_SCHEMA = "chatgpt-github-transaction-policy-v0.9"
SNAPSHOT_SCHEMA = "chatgpt-github-policy-snapshot-v0.9"
ENGINE_SCHEMA = "chatgpt-github-transaction-policy-engine-v0.9"
APPROVAL_LEDGER_SCHEMA = "chatgpt-github-approval-ledger-v0.9"
MAX_APPROVALS_PER_ROLE = 8
RISK_LEVELS = ("low", "moderate", "high", "critical")
APPROVAL_SCOPES = ("none", "transaction", "step")

IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

AUTHORITY = {
    "mode": "github_transaction_policy_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "identity_verification": False,
    "signature_verification": False,
    "source_truth_verification": False,
    "github_execution_ownership": False,
    "connector_discovery": False,
    "arbitrary_tool_dispatch": False,
    "credential_access": False,
    "tool_result_fabrication": False,
    "automatic_step_authorization": False,
    "automatic_pending_write_replay": False,
    "automatic_rollback": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge_authority": False,
    "force_push_authority": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class PolicyError(ValueError):
    """Raised when a policy, snapshot, or approval violates v0.9."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{name} must be a non-empty string")
    if "\x00" in value:
        raise PolicyError(f"{name} must not contain NUL")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{name} must be a boolean")
    return value


def nonnegative_integer(value: Any, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError(f"{name} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise PolicyError(f"{name} must be <= {maximum}")
    return value


def positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError(f"{name} must be a positive integer")
    return value


def exact_keys(raw: Mapping[str, Any], required: set[str], optional: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        raise PolicyError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise PolicyError(f"{name} contains unsupported keys: {', '.join(extra)}")


def identifier(value: Any, name: str) -> str:
    item = string(value, name)
    if not IDENT_RE.fullmatch(item):
        raise PolicyError(f"{name} contains unsupported characters")
    return item


def repository_name(value: Any, name: str = "repository_full_name") -> str:
    item = string(value, name)
    if not REPO_RE.fullmatch(item):
        raise PolicyError(f"{name} must use owner/name form")
    return item


def sha256(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not SHA256_RE.fullmatch(item):
        raise PolicyError(f"{name} must be a 64-character SHA-256")
    return item


def enum(value: Any, name: str, allowed: tuple[str, ...]) -> str:
    item = string(value, name)
    if item not in allowed:
        raise PolicyError(f"{name} must be one of {list(allowed)}")
    return item


def role_counts(value: Any, name: str) -> dict[str, int]:
    raw = mapping(value, name)
    result: dict[str, int] = {}
    for role, count in raw.items():
        normalized = identifier(role, f"{name}.role")
        result[normalized] = nonnegative_integer(
            count, f"{name}.{normalized}", maximum=MAX_APPROVALS_PER_ROLE
        )
    return {key: count for key, count in sorted(result.items()) if count > 0}


@dataclass(frozen=True)
class ActionRule:
    action: str
    allowed: bool
    risk_level: str
    approval_scope: str
    required_role_counts: dict[str, int]
    require_distinct_principals: bool
    require_recovery_plan: bool
    max_occurrences: int

    def payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "allowed": self.allowed,
            "risk_level": self.risk_level,
            "approval_scope": self.approval_scope,
            "required_role_counts": dict(self.required_role_counts),
            "require_distinct_principals": self.require_distinct_principals,
            "require_recovery_plan": self.require_recovery_plan,
            "max_occurrences": self.max_occurrences,
        }

    @property
    def rule_sha256(self) -> str:
        return canonical_sha256(self.payload())

    @classmethod
    def from_value(cls, value: Any, *, index: int) -> "ActionRule":
        raw = mapping(value, f"rules[{index}]")
        exact_keys(
            raw,
            {
                "action", "allowed", "risk_level", "approval_scope",
                "required_role_counts", "require_distinct_principals",
                "require_recovery_plan", "max_occurrences",
            },
            set(),
            f"rules[{index}]",
        )
        action = string(raw["action"], f"rules[{index}].action")
        if action not in OPERATION_POLICIES:
            raise PolicyError(f"rules[{index}].action is unsupported: {action}")
        counts = role_counts(raw["required_role_counts"], f"rules[{index}].required_role_counts")
        scope = enum(raw["approval_scope"], f"rules[{index}].approval_scope", APPROVAL_SCOPES)
        if counts and scope == "none":
            raise PolicyError(f"rules[{index}] approvals require transaction or step scope")
        if not counts and scope != "none":
            raise PolicyError(f"rules[{index}] approval_scope must be none when no roles are required")
        return cls(
            action=action,
            allowed=boolean(raw["allowed"], f"rules[{index}].allowed"),
            risk_level=enum(raw["risk_level"], f"rules[{index}].risk_level", RISK_LEVELS),
            approval_scope=scope,
            required_role_counts=counts,
            require_distinct_principals=boolean(raw["require_distinct_principals"], f"rules[{index}].require_distinct_principals"),
            require_recovery_plan=boolean(raw["require_recovery_plan"], f"rules[{index}].require_recovery_plan"),
            max_occurrences=positive_integer(raw["max_occurrences"], f"rules[{index}].max_occurrences"),
        )


def default_rule_documents() -> list[dict[str, Any]]:
    reads = {"get_repo", "fetch_file", "fetch_pr", "compare_commits", "get_commit_combined_status", "list_pr_changed_filenames"}
    moderate = {"create_branch", "create_blob", "create_tree", "create_commit"}
    high = {"create_file", "update_file", "delete_file", "update_ref", "create_pull_request"}
    critical = {"merge_pull_request"}
    expected = reads | moderate | high | critical
    if expected != set(OPERATION_POLICIES):
        raise PolicyError("v0.9 default policy diverges from the GitHub operation catalog")
    documents: list[dict[str, Any]] = []
    for action in OPERATION_POLICIES:
        if action in reads:
            risk, scope, roles = "low", "none", {}
        elif action in moderate:
            risk, scope, roles = "moderate", "transaction", {"operator": 1}
        elif action in high:
            risk, scope, roles = "high", "step", {"reviewer": 1}
        else:
            risk, scope, roles = "critical", "step", {"release_manager": 1, "reviewer": 1}
        documents.append({
            "action": action,
            "allowed": True,
            "risk_level": risk,
            "approval_scope": scope,
            "required_role_counts": roles,
            "require_distinct_principals": True,
            "require_recovery_plan": OPERATION_POLICIES[action].effect == "write",
            "max_occurrences": 64,
        })
    return documents


@dataclass(frozen=True)
class TransactionPolicy:
    policy_id: str
    allowed_repositories: tuple[str, ...]
    max_steps: int
    max_write_steps: int
    max_critical_steps: int
    rules: tuple[ActionRule, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "allowed_repositories": list(self.allowed_repositories),
            "max_steps": self.max_steps,
            "max_write_steps": self.max_write_steps,
            "max_critical_steps": self.max_critical_steps,
            "rules": [rule.payload() for rule in self.rules],
            "authority": AUTHORITY,
        }

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "policy_sha256": self.policy_sha256}

    @property
    def rule_map(self) -> dict[str, ActionRule]:
        return {rule.action: rule for rule in self.rules}

    @classmethod
    def build(cls, *, policy_id: str, allowed_repositories: list[str], rules: list[dict[str, Any]] | None = None, max_steps: int = 64, max_write_steps: int = 32, max_critical_steps: int = 1) -> "TransactionPolicy":
        repositories = tuple(sorted(repository_name(item, "allowed_repositories[]") for item in allowed_repositories))
        if not repositories:
            raise PolicyError("allowed_repositories must not be empty")
        if len(repositories) != len(set(repositories)):
            raise PolicyError("allowed_repositories contains duplicates")
        rule_values = rules if rules is not None else default_rule_documents()
        normalized = tuple(ActionRule.from_value(value, index=index) for index, value in enumerate(rule_values))
        actions = [rule.action for rule in normalized]
        if len(actions) != len(set(actions)):
            raise PolicyError("policy contains duplicate action rules")
        return cls(
            policy_id=identifier(policy_id, "policy_id"),
            allowed_repositories=repositories,
            max_steps=positive_integer(max_steps, "max_steps"),
            max_write_steps=nonnegative_integer(max_write_steps, "max_write_steps"),
            max_critical_steps=nonnegative_integer(max_critical_steps, "max_critical_steps"),
            rules=tuple(sorted(normalized, key=lambda rule: rule.action)),
        )

    @classmethod
    def from_document(cls, value: Any) -> "TransactionPolicy":
        raw = mapping(value, "transaction_policy")
        exact_keys(raw, {"schema_version", "policy_id", "allowed_repositories", "max_steps", "max_write_steps", "max_critical_steps", "rules", "authority", "policy_sha256"}, set(), "transaction_policy")
        if raw["schema_version"] != POLICY_SCHEMA:
            raise PolicyError(f"transaction_policy.schema_version must be {POLICY_SCHEMA}")
        if raw["authority"] != AUTHORITY:
            raise PolicyError("transaction_policy.authority must remain fixed")
        policy = cls.build(
            policy_id=raw["policy_id"],
            allowed_repositories=array(raw["allowed_repositories"], "transaction_policy.allowed_repositories"),
            rules=array(raw["rules"], "transaction_policy.rules"),
            max_steps=raw["max_steps"],
            max_write_steps=raw["max_write_steps"],
            max_critical_steps=raw["max_critical_steps"],
        )
        if raw["policy_sha256"] != policy.policy_sha256:
            raise PolicyError("transaction_policy.policy_sha256 mismatch")
        return policy


@dataclass(frozen=True)
class ApprovalRequirement:
    requirement_id: str
    scope: str
    scope_id: str
    action: str
    risk_level: str
    required_role_counts: dict[str, int]
    require_distinct_principals: bool
    rule_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "scope": self.scope,
            "scope_id": self.scope_id,
            "action": self.action,
            "risk_level": self.risk_level,
            "required_role_counts": dict(self.required_role_counts),
            "require_distinct_principals": self.require_distinct_principals,
            "rule_sha256": self.rule_sha256,
        }

    @classmethod
    def from_value(cls, value: Any, *, index: int) -> "ApprovalRequirement":
        raw = mapping(value, f"requirements[{index}]")
        exact_keys(raw, {"requirement_id", "scope", "scope_id", "action", "risk_level", "required_role_counts", "require_distinct_principals", "rule_sha256"}, set(), f"requirements[{index}]")
        action = string(raw["action"], f"requirements[{index}].action")
        if action not in OPERATION_POLICIES:
            raise PolicyError(f"requirements[{index}].action is unsupported")
        counts = role_counts(raw["required_role_counts"], f"requirements[{index}].required_role_counts")
        if not counts:
            raise PolicyError(f"requirements[{index}] must require at least one role")
        return cls(
            requirement_id=identifier(raw["requirement_id"], f"requirements[{index}].requirement_id"),
            scope=enum(raw["scope"], f"requirements[{index}].scope", ("transaction", "step")),
            scope_id=identifier(raw["scope_id"], f"requirements[{index}].scope_id"),
            action=action,
            risk_level=enum(raw["risk_level"], f"requirements[{index}].risk_level", RISK_LEVELS),
            required_role_counts=counts,
            require_distinct_principals=boolean(raw["require_distinct_principals"], f"requirements[{index}].require_distinct_principals"),
            rule_sha256=sha256(raw["rule_sha256"], f"requirements[{index}].rule_sha256"),
        )


@dataclass(frozen=True)
class PolicySnapshot:
    policy_id: str
    policy_sha256: str
    transaction_id: str
    plan_sha256: str
    repository_full_name: str
    decision: str
    denied_reasons: tuple[str, ...]
    risk_summary: dict[str, int]
    requirements: tuple[ApprovalRequirement, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": SNAPSHOT_SCHEMA,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "transaction_id": self.transaction_id,
            "plan_sha256": self.plan_sha256,
            "repository_full_name": self.repository_full_name,
            "decision": self.decision,
            "denied_reasons": list(self.denied_reasons),
            "risk_summary": dict(self.risk_summary),
            "requirements": [requirement.payload() for requirement in self.requirements],
            "authority": AUTHORITY,
        }

    @property
    def snapshot_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "snapshot_sha256": self.snapshot_sha256}

    @property
    def requirement_map(self) -> dict[str, ApprovalRequirement]:
        return {item.requirement_id: item for item in self.requirements}

    @classmethod
    def evaluate(cls, policy: TransactionPolicy, plan: TransactionPlan) -> "PolicySnapshot":
        denied: list[str] = []
        if plan.repository_full_name not in policy.allowed_repositories:
            denied.append(f"repository_not_allowed:{plan.repository_full_name}")
        if len(plan.steps) > policy.max_steps:
            denied.append(f"step_limit_exceeded:{len(plan.steps)}>{policy.max_steps}")
        risk_summary = {risk: 0 for risk in RISK_LEVELS}
        rules = policy.rule_map
        occurrences: dict[str, int] = {}
        requirements: list[ApprovalRequirement] = []
        transaction_requirement_keys: set[str] = set()
        write_steps = 0
        critical_steps = 0
        for step in plan.steps:
            rule = rules.get(step.action)
            if rule is None:
                denied.append(f"unruled_action:{step.action}")
                continue
            occurrences[step.action] = occurrences.get(step.action, 0) + 1
            risk_summary[rule.risk_level] += 1
            if step.effect == "write":
                write_steps += 1
            if rule.risk_level == "critical":
                critical_steps += 1
            if not rule.allowed:
                denied.append(f"action_denied:{step.step_id}:{step.action}")
            if occurrences[step.action] > rule.max_occurrences:
                denied.append(f"action_occurrence_limit:{step.action}:{occurrences[step.action]}>{rule.max_occurrences}")
            if rule.require_recovery_plan and step.effect == "write" and not step.recovery_plan:
                denied.append(f"missing_recovery_plan:{step.step_id}:{step.action}")
            if rule.required_role_counts:
                if rule.approval_scope == "step":
                    requirement_id = f"step:{step.step_id}:{step.action}"
                    scope_id = step.step_id
                else:
                    requirement_id = f"transaction:{step.action}"
                    scope_id = plan.transaction_id
                    if requirement_id in transaction_requirement_keys:
                        continue
                    transaction_requirement_keys.add(requirement_id)
                requirements.append(ApprovalRequirement(
                    requirement_id=requirement_id,
                    scope=rule.approval_scope,
                    scope_id=scope_id,
                    action=step.action,
                    risk_level=rule.risk_level,
                    required_role_counts=dict(rule.required_role_counts),
                    require_distinct_principals=rule.require_distinct_principals,
                    rule_sha256=rule.rule_sha256,
                ))
        if write_steps > policy.max_write_steps:
            denied.append(f"write_step_limit_exceeded:{write_steps}>{policy.max_write_steps}")
        if critical_steps > policy.max_critical_steps:
            denied.append(f"critical_step_limit_exceeded:{critical_steps}>{policy.max_critical_steps}")
        denied = sorted(set(denied))
        return cls(
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            transaction_id=plan.transaction_id,
            plan_sha256=plan.plan_sha256,
            repository_full_name=plan.repository_full_name,
            decision="deny" if denied else "allow",
            denied_reasons=tuple(denied),
            risk_summary=risk_summary,
            requirements=tuple(requirements),
        )

    @classmethod
    def from_document(cls, value: Any) -> "PolicySnapshot":
        raw = mapping(value, "policy_snapshot")
        exact_keys(raw, {"schema_version", "policy_id", "policy_sha256", "transaction_id", "plan_sha256", "repository_full_name", "decision", "denied_reasons", "risk_summary", "requirements", "authority", "snapshot_sha256"}, set(), "policy_snapshot")
        if raw["schema_version"] != SNAPSHOT_SCHEMA:
            raise PolicyError(f"policy_snapshot.schema_version must be {SNAPSHOT_SCHEMA}")
        if raw["authority"] != AUTHORITY:
            raise PolicyError("policy_snapshot.authority must remain fixed")
        denied_values = array(raw["denied_reasons"], "policy_snapshot.denied_reasons")
        denied = tuple(sorted(string(item, "policy_snapshot.denied_reasons[]") for item in denied_values))
        if len(denied) != len(set(denied)):
            raise PolicyError("policy_snapshot.denied_reasons contains duplicates")
        risk_raw = mapping(raw["risk_summary"], "policy_snapshot.risk_summary")
        if set(risk_raw) != set(RISK_LEVELS):
            raise PolicyError("policy_snapshot.risk_summary must contain every risk level")
        risk_summary = {risk: nonnegative_integer(risk_raw[risk], f"policy_snapshot.risk_summary.{risk}") for risk in RISK_LEVELS}
        requirements = tuple(ApprovalRequirement.from_value(value, index=index) for index, value in enumerate(array(raw["requirements"], "policy_snapshot.requirements")))
        ids = [item.requirement_id for item in requirements]
        if len(ids) != len(set(ids)):
            raise PolicyError("policy_snapshot contains duplicate requirement IDs")
        snapshot = cls(
            policy_id=identifier(raw["policy_id"], "policy_snapshot.policy_id"),
            policy_sha256=sha256(raw["policy_sha256"], "policy_snapshot.policy_sha256"),
            transaction_id=identifier(raw["transaction_id"], "policy_snapshot.transaction_id"),
            plan_sha256=sha256(raw["plan_sha256"], "policy_snapshot.plan_sha256"),
            repository_full_name=repository_name(raw["repository_full_name"], "policy_snapshot.repository_full_name"),
            decision=enum(raw["decision"], "policy_snapshot.decision", ("allow", "deny")),
            denied_reasons=denied,
            risk_summary=risk_summary,
            requirements=requirements,
        )
        if (snapshot.decision == "deny") != bool(snapshot.denied_reasons):
            raise PolicyError("policy_snapshot decision and denied_reasons disagree")
        if raw["snapshot_sha256"] != snapshot.snapshot_sha256:
            raise PolicyError("policy_snapshot.snapshot_sha256 mismatch")
        return snapshot
