"""Contracts for GitHub Transaction Orchestrator v0.8."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from sdk.liminal_github_bridge import OPERATION_POLICIES

PLAN_SCHEMA = "chatgpt-github-transaction-plan-v0.8"
JOURNAL_SCHEMA = "chatgpt-github-transaction-journal-v0.8"
ORCHESTRATOR_SCHEMA = "chatgpt-github-transaction-orchestrator-v0.8"
ZERO_HASH = "0" * 64
MAX_STEPS = 64
REFERENCE_KEY = "$checkpoint"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")

AUTHORITY = {
    "mode": "github_transaction_orchestrator_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "source_truth_verification": False,
    "github_execution_ownership": False,
    "connector_discovery": False,
    "arbitrary_tool_dispatch": False,
    "credential_access": False,
    "tool_result_fabrication": False,
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


class TransactionError(ValueError):
    """Raised when a transaction plan or checkpoint violates v0.8."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError) as exc:
        raise TransactionError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransactionError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise TransactionError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TransactionError(f"{name} must be a non-empty string")
    if "\x00" in value:
        raise TransactionError(f"{name} must not contain NUL")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TransactionError(f"{name} must be a boolean")
    return value


def exact_keys(
    raw: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    name: str,
) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        raise TransactionError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise TransactionError(f"{name} contains unsupported keys: {', '.join(extra)}")


def identifier(value: Any, name: str) -> str:
    item = string(value, name)
    if not IDENT_RE.fullmatch(item):
        raise TransactionError(f"{name} contains unsupported characters")
    return item


def repository_name(value: Any, name: str = "repository_full_name") -> str:
    item = string(value, name)
    if not REPO_RE.fullmatch(item):
        raise TransactionError(f"{name} must use owner/name form")
    return item


def sha256(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not SHA256_RE.fullmatch(item):
        raise TransactionError(f"{name} must be a 64-character SHA-256")
    return item


def output_path(value: Any, name: str) -> str:
    item = string(value, name)
    if not PATH_RE.fullmatch(item):
        raise TransactionError(f"{name} must be a dotted output path")
    return item


def scalar(value: Any, name: str) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        canonical_json(value)
        return value
    raise TransactionError(f"{name} must be a JSON scalar")


def _reference(value: Any, name: str) -> tuple[str, str] | None:
    if not isinstance(value, dict) or REFERENCE_KEY not in value:
        return None
    exact_keys(value, {REFERENCE_KEY}, set(), name)
    token = string(value[REFERENCE_KEY], f"{name}.{REFERENCE_KEY}")
    if "." not in token:
        raise TransactionError(
            f"{name}.{REFERENCE_KEY} must use step-id.export-name form"
        )
    step_id, export_name = token.rsplit(".", 1)
    return identifier(step_id, f"{name}.step_id"), identifier(
        export_name, f"{name}.export_name"
    )


def iter_references(value: Any, name: str = "value") -> list[tuple[str, str]]:
    ref = _reference(value, name)
    if ref is not None:
        return [ref]
    if isinstance(value, dict):
        result: list[tuple[str, str]] = []
        for key, item in value.items():
            string(key, f"{name}.key")
            result.extend(iter_references(item, f"{name}.{key}"))
        return result
    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            result.extend(iter_references(item, f"{name}[{index}]"))
        return result
    canonical_json(value)
    return []


def checkpoint_reference(step_id: str, export_name: str) -> dict[str, str]:
    return {REFERENCE_KEY: f"{step_id}.{export_name}"}


@dataclass(frozen=True)
class TransactionStep:
    step_id: str
    call_id: str
    action: str
    arguments: dict[str, Any]
    exports: dict[str, str]
    expect: dict[str, Any]
    gate_step_ids: tuple[str, ...] = ()

    @property
    def effect(self) -> str:
        return OPERATION_POLICIES[self.action].effect

    @property
    def reversible(self) -> bool:
        return OPERATION_POLICIES[self.action].reversible

    @property
    def recovery_plan(self) -> str | None:
        return OPERATION_POLICIES[self.action].recovery_plan

    def payload(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "call_id": self.call_id,
            "action": self.action,
            "arguments": self.arguments,
            "exports": self.exports,
            "expect": self.expect,
            "gate_step_ids": list(self.gate_step_ids),
        }

    @classmethod
    def from_value(
        cls,
        value: Any,
        *,
        index: int,
        repository_full_name: str,
        prior_steps: dict[str, "TransactionStep"],
        known_exports: dict[str, set[str]],
    ) -> "TransactionStep":
        raw = mapping(value, f"steps[{index}]")
        exact_keys(
            raw,
            {"step_id", "call_id", "action", "arguments", "exports", "expect"},
            {"gate_step_ids"},
            f"steps[{index}]",
        )
        step_id = identifier(raw["step_id"], f"steps[{index}].step_id")
        call_id = identifier(raw["call_id"], f"steps[{index}].call_id")
        action = string(raw["action"], f"steps[{index}].action")
        if action not in OPERATION_POLICIES:
            raise TransactionError(f"steps[{index}].action is unsupported: {action}")
        arguments = mapping(raw["arguments"], f"steps[{index}].arguments")
        canonical_json(arguments)

        repo_key = (
            "repository_full_name"
            if "repository_full_name" in arguments
            else "repo_full_name"
            if "repo_full_name" in arguments
            else None
        )
        if repo_key is None:
            raise TransactionError(
                f"steps[{index}].arguments must contain a literal repository name"
            )
        repo_value = arguments[repo_key]
        if isinstance(repo_value, dict):
            raise TransactionError(
                f"steps[{index}].arguments.{repo_key} must not be a checkpoint reference"
            )
        repo = repository_name(repo_value, f"steps[{index}].arguments.{repo_key}")
        if repo != repository_full_name:
            raise TransactionError(
                f"steps[{index}] targets {repo}, outside transaction repository "
                f"{repository_full_name}"
            )

        for referenced_step, export_name in iter_references(
            arguments, f"steps[{index}].arguments"
        ):
            if referenced_step not in prior_steps:
                raise TransactionError(
                    f"steps[{index}] references non-prior step: {referenced_step}"
                )
            if export_name not in known_exports.get(referenced_step, set()):
                raise TransactionError(
                    f"steps[{index}] references unknown export "
                    f"{referenced_step}.{export_name}"
                )

        exports_raw = mapping(raw["exports"], f"steps[{index}].exports")
        exports: dict[str, str] = {}
        for key, path in exports_raw.items():
            export_name = identifier(key, f"steps[{index}].exports.key")
            exports[export_name] = output_path(
                path, f"steps[{index}].exports.{export_name}"
            )

        expect_raw = mapping(raw["expect"], f"steps[{index}].expect")
        expect: dict[str, Any] = {}
        for path, expected in expect_raw.items():
            normalized_path = output_path(path, f"steps[{index}].expect.path")
            expect[normalized_path] = scalar(
                expected, f"steps[{index}].expect.{normalized_path}"
            )

        gate_values = raw.get("gate_step_ids", [])
        gates = tuple(
            identifier(item, f"steps[{index}].gate_step_ids[{gate_index}]")
            for gate_index, item in enumerate(
                array(gate_values, f"steps[{index}].gate_step_ids")
            )
        )
        if len(gates) != len(set(gates)):
            raise TransactionError(f"steps[{index}].gate_step_ids contains duplicates")
        for gate in gates:
            if gate not in prior_steps:
                raise TransactionError(
                    f"steps[{index}] gate must reference a prior step: {gate}"
                )

        if action == "merge_pull_request":
            if not gates:
                raise TransactionError(
                    "merge_pull_request requires at least one successful prior gate"
                )
            expected_head = arguments.get("expected_head_sha")
            if _reference(expected_head, f"steps[{index}].arguments.expected_head_sha") is None:
                raise TransactionError(
                    "merge_pull_request.expected_head_sha must come from a checkpoint"
                )
            ci_gates = [
                prior_steps[gate]
                for gate in gates
                if prior_steps[gate].action == "get_commit_combined_status"
                and prior_steps[gate].expect.get("state") == "success"
            ]
            if not ci_gates:
                raise TransactionError(
                    "merge_pull_request requires a prior CI gate expecting state=success"
                )

        return cls(
            step_id=step_id,
            call_id=call_id,
            action=action,
            arguments=dict(arguments),
            exports=exports,
            expect=expect,
            gate_step_ids=gates,
        )


@dataclass(frozen=True)
class TransactionPlan:
    transaction_id: str
    runtime_config_path: str
    runtime_config_sha256: str
    repository_full_name: str
    steps: tuple[TransactionStep, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": PLAN_SCHEMA,
            "transaction_id": self.transaction_id,
            "runtime_config_path": self.runtime_config_path,
            "runtime_config_sha256": self.runtime_config_sha256,
            "repository_full_name": self.repository_full_name,
            "steps": [step.payload() for step in self.steps],
            "authority": AUTHORITY,
        }

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "plan_sha256": self.plan_sha256}

    @classmethod
    def from_document(cls, value: Any) -> "TransactionPlan":
        raw = mapping(value, "transaction_plan")
        exact_keys(
            raw,
            {
                "schema_version",
                "transaction_id",
                "runtime_config_path",
                "runtime_config_sha256",
                "repository_full_name",
                "steps",
                "authority",
                "plan_sha256",
            },
            set(),
            "transaction_plan",
        )
        if raw["schema_version"] != PLAN_SCHEMA:
            raise TransactionError(
                f"transaction_plan.schema_version must be {PLAN_SCHEMA}"
            )
        if raw["authority"] != AUTHORITY:
            raise TransactionError("transaction_plan.authority must remain fixed")
        transaction_id = identifier(
            raw["transaction_id"], "transaction_plan.transaction_id"
        )
        runtime_path = string(
            raw["runtime_config_path"], "transaction_plan.runtime_config_path"
        )
        runtime_sha = sha256(
            raw["runtime_config_sha256"],
            "transaction_plan.runtime_config_sha256",
        )
        repository = repository_name(
            raw["repository_full_name"],
            "transaction_plan.repository_full_name",
        )
        step_values = array(raw["steps"], "transaction_plan.steps")
        if not step_values or len(step_values) > MAX_STEPS:
            raise TransactionError(
                f"transaction_plan.steps must contain 1..{MAX_STEPS} steps"
            )
        prior: dict[str, TransactionStep] = {}
        known_exports: dict[str, set[str]] = {}
        steps: list[TransactionStep] = []
        call_ids: set[str] = set()
        for index, step_value in enumerate(step_values):
            step = TransactionStep.from_value(
                step_value,
                index=index,
                repository_full_name=repository,
                prior_steps=prior,
                known_exports=known_exports,
            )
            if step.step_id in prior:
                raise TransactionError(
                    f"transaction_plan contains duplicate step_id: {step.step_id}"
                )
            if step.call_id in call_ids:
                raise TransactionError(
                    f"transaction_plan contains duplicate call_id: {step.call_id}"
                )
            prior[step.step_id] = step
            known_exports[step.step_id] = set(step.exports)
            call_ids.add(step.call_id)
            steps.append(step)
        plan = cls(
            transaction_id=transaction_id,
            runtime_config_path=runtime_path,
            runtime_config_sha256=runtime_sha,
            repository_full_name=repository,
            steps=tuple(steps),
        )
        if raw["plan_sha256"] != plan.plan_sha256:
            raise TransactionError("transaction_plan.plan_sha256 mismatch")
        return plan

    @classmethod
    def build(
        cls,
        *,
        transaction_id: str,
        runtime_config_path: str,
        runtime_config_sha256: str,
        repository_full_name: str,
        steps: list[dict[str, Any]],
    ) -> "TransactionPlan":
        payload = {
            "schema_version": PLAN_SCHEMA,
            "transaction_id": transaction_id,
            "runtime_config_path": runtime_config_path,
            "runtime_config_sha256": runtime_config_sha256,
            "repository_full_name": repository_full_name,
            "steps": steps,
            "authority": AUTHORITY,
        }
        return cls.from_document(
            {**payload, "plan_sha256": canonical_sha256(payload)}
        )
