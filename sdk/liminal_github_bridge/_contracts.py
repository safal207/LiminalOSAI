"""Core contracts for the GitHub Agent Bridge v0.6."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

BRIDGE_SCHEMA = "chatgpt-github-agent-bridge-v0.6"
CONFIG_SCHEMA = "chatgpt-github-agent-bridge-config-v0.6"
RESULT_STATUSES = {"success", "failure", "cancelled"}
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
INVALID_REF_CHARS = set(" ~^:?*[\\")

AUTHORITY = {
    "mode": "github_bridge_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "source_truth_verification": False,
    "github_execution_ownership": False,
    "tool_result_fabrication": False,
    "credential_access": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge_authority": False,
    "force_push_authority": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class GitHubBridgeError(ValueError):
    """Raised when a GitHub operation violates the v0.6 contract."""


class GitHubExecutor(Protocol):
    def __call__(self, action: str, arguments: dict[str, Any]) -> Any: ...


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise GitHubBridgeError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubBridgeError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise GitHubBridgeError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise GitHubBridgeError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise GitHubBridgeError(f"{name} must not be empty")
    if "\x00" in value:
        raise GitHubBridgeError(f"{name} must not contain NUL")
    return value


def optional_string(value: Any, name: str) -> str | None:
    return None if value is None else string(value, name)


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise GitHubBridgeError(f"{name} must be a boolean")
    return value


def positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubBridgeError(f"{name} must be a positive integer")
    return value


def enum(value: Any, name: str, allowed: set[str]) -> str:
    item = string(value, name)
    if item not in allowed:
        raise GitHubBridgeError(f"{name} must be one of {sorted(allowed)}")
    return item


def exact_keys(raw: Mapping[str, Any], required: set[str], optional: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        raise GitHubBridgeError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise GitHubBridgeError(f"{name} contains unsupported keys: {', '.join(extra)}")


def repository_name(value: Any, name: str = "repository_full_name") -> str:
    repo = string(value, name)
    if not REPO_RE.fullmatch(repo):
        raise GitHubBridgeError(f"{name} must use owner/name form")
    return repo


def git_sha(value: Any, name: str) -> str:
    sha = string(value, name)
    if not SHA_RE.fullmatch(sha):
        raise GitHubBridgeError(f"{name} must be a 40-character Git SHA")
    return sha.lower()


def repository_path(value: Any, name: str = "path") -> str:
    path = string(value, name)
    if path.startswith("/") or path.endswith("/"):
        raise GitHubBridgeError(f"{name} must be repository-relative")
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise GitHubBridgeError(f"{name} contains an unsafe path segment")
    return path


def git_ref(value: Any, name: str) -> str:
    ref = string(value, name)
    if ref.startswith(("/", "-")) or ref.endswith(("/", ".")):
        raise GitHubBridgeError(f"{name} is not a valid Git ref")
    if ".." in ref or "@{" in ref or "//" in ref:
        raise GitHubBridgeError(f"{name} is not a valid Git ref")
    if any(ch in INVALID_REF_CHARS or ord(ch) < 32 for ch in ref):
        raise GitHubBridgeError(f"{name} is not a valid Git ref")
    if any(part.startswith(".") or part.endswith(".lock") for part in ref.split("/")):
        raise GitHubBridgeError(f"{name} is not a valid Git ref")
    return ref


def string_list(value: Any, name: str, *, allow_empty: bool = True) -> list[str]:
    result = [string(item, f"{name}[{i}]") for i, item in enumerate(array(value, name))]
    if len(result) != len(set(result)):
        raise GitHubBridgeError(f"{name} contains duplicates")
    if not allow_empty and not result:
        raise GitHubBridgeError(f"{name} must not be empty")
    return result


@dataclass(frozen=True)
class GitHubBridgeConfig:
    host_trace_path: str
    allowed_repositories: tuple[str, ...]
    protected_branches: tuple[str, ...]
    max_request_bytes: int

    def normalized(self) -> "GitHubBridgeConfig":
        allowed = tuple(sorted(repository_name(x, "config.allowed_repositories[]") for x in self.allowed_repositories))
        protected = tuple(sorted(git_ref(x, "config.protected_branches[]") for x in self.protected_branches))
        if not allowed:
            raise GitHubBridgeError("config.allowed_repositories must not be empty")
        if len(allowed) != len(set(allowed)) or len(protected) != len(set(protected)):
            raise GitHubBridgeError("config lists contain duplicates")
        return GitHubBridgeConfig(
            host_trace_path=string(self.host_trace_path, "config.host_trace_path"),
            allowed_repositories=allowed,
            protected_branches=protected,
            max_request_bytes=positive_integer(self.max_request_bytes, "config.max_request_bytes"),
        )

    def payload(self) -> dict[str, Any]:
        value = self.normalized()
        return {
            "schema_version": CONFIG_SCHEMA,
            "host_trace_path": value.host_trace_path,
            "allowed_repositories": list(value.allowed_repositories),
            "protected_branches": list(value.protected_branches),
            "max_request_bytes": value.max_request_bytes,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        payload = self.payload()
        return {**payload, "config_sha256": canonical_sha256(payload)}

    @classmethod
    def from_document(cls, value: Any) -> "GitHubBridgeConfig":
        raw = mapping(value, "bridge_config")
        exact_keys(raw, {
            "schema_version", "host_trace_path", "allowed_repositories",
            "protected_branches", "max_request_bytes", "authority", "config_sha256",
        }, set(), "bridge_config")
        if raw["schema_version"] != CONFIG_SCHEMA:
            raise GitHubBridgeError(f"bridge_config.schema_version must be {CONFIG_SCHEMA}")
        if raw["authority"] != AUTHORITY:
            raise GitHubBridgeError("bridge_config.authority must remain fixed")
        payload = {key: raw[key] for key in raw if key != "config_sha256"}
        if raw["config_sha256"] != canonical_sha256(payload):
            raise GitHubBridgeError("bridge_config.config_sha256 mismatch")
        return cls(
            host_trace_path=raw["host_trace_path"],
            allowed_repositories=tuple(string_list(raw["allowed_repositories"], "bridge_config.allowed_repositories", allow_empty=False)),
            protected_branches=tuple(string_list(raw["protected_branches"], "bridge_config.protected_branches")),
            max_request_bytes=raw["max_request_bytes"],
        ).normalized()


@dataclass(frozen=True)
class GitHubOperation:
    call_id: str
    action: str
    arguments: dict[str, Any]

    def normalized(self, config: GitHubBridgeConfig) -> "NormalizedGitHubOperation":
        from ._operations import OPERATION_POLICIES, enforce_protected_ref_policy, operation_summary

        call_id = string(self.call_id, "operation.call_id")
        action = string(self.action, "operation.action")
        policy = OPERATION_POLICIES.get(action)
        if policy is None:
            raise GitHubBridgeError(f"unsupported GitHub action: {action}")
        raw = mapping(self.arguments, "operation.arguments")
        exact_keys(raw, set(policy.required), set(policy.optional), f"arguments[{action}]")
        arguments = policy.validator(dict(raw))
        repo = repository_name(arguments.get("repository_full_name", arguments.get("repo_full_name")))
        if repo not in config.allowed_repositories:
            raise GitHubBridgeError(f"repository is outside the configured allowlist: {repo}")
        enforce_protected_ref_policy(action, arguments, config)
        request_bytes = len(canonical_json(arguments).encode("utf-8"))
        if request_bytes > config.max_request_bytes:
            raise GitHubBridgeError(
                f"operation request exceeds max_request_bytes ({request_bytes} > {config.max_request_bytes})"
            )
        digest = canonical_sha256({"call_id": call_id, "action": action, "arguments": arguments})
        return NormalizedGitHubOperation(
            call_id, action, arguments, repo, policy.effect, policy.reversible,
            policy.recovery_plan, digest, operation_summary(action, arguments, digest),
        )


@dataclass(frozen=True)
class NormalizedGitHubOperation:
    call_id: str
    action: str
    arguments: dict[str, Any]
    repository_full_name: str
    effect: str
    reversible: bool
    recovery_plan: str | None
    request_sha256: str
    operation_summary: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class GitHubExecutorResult:
    status: str
    locator: str
    payload: Any

    @classmethod
    def success(cls, *, locator: str, payload: Any) -> "GitHubExecutorResult":
        return cls("success", locator, payload)

    @classmethod
    def failure(cls, *, locator: str, payload: Any) -> "GitHubExecutorResult":
        return cls("failure", locator, payload)

    @classmethod
    def cancelled(cls, *, locator: str, payload: Any = None) -> "GitHubExecutorResult":
        return cls("cancelled", locator, payload)

    @classmethod
    def from_value(cls, value: Any) -> "GitHubExecutorResult":
        if isinstance(value, cls):
            result = value
        else:
            raw = mapping(value, "executor_result")
            exact_keys(raw, {"status", "locator", "payload"}, set(), "executor_result")
            result = cls(raw["status"], raw["locator"], raw["payload"])
        canonical_json(result.payload)
        return cls(
            enum(result.status, "executor_result.status", RESULT_STATUSES),
            string(result.locator, "executor_result.locator"),
            result.payload,
        )

    @property
    def payload_sha256(self) -> str:
        return canonical_sha256(self.payload)


@dataclass(frozen=True)
class GitHubExecutionReceipt:
    schema_version: str
    call_id: str
    action: str
    repository_full_name: str
    request_sha256: str
    status: str
    locator: str
    payload_sha256: str
    recorder_event_id: str
    recorder_head_sha256: str
    host_trace_head_sha256: str
    authority: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)
