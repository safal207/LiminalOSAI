"""Contracts for Connected GitHub Runtime Harness v0.7."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

RUNTIME_SCHEMA = "chatgpt-connected-github-runtime-v0.7"
CONFIG_SCHEMA = "chatgpt-connected-github-runtime-config-v0.7"

AUTHORITY = {
    "mode": "connected_github_runtime_only",
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
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge_authority": False,
    "force_push_authority": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class GitHubRuntimeError(ValueError):
    """Raised when the connected runtime violates the v0.7 contract."""


class ConnectorInvoker(Protocol):
    """One fixed host bridge to an already connected GitHub connector."""

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> Any: ...


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise GitHubRuntimeError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubRuntimeError(f"{name} must be a JSON object")
    return value


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GitHubRuntimeError(f"{name} must be a non-empty string")
    if "\x00" in value:
        raise GitHubRuntimeError(f"{name} must not contain NUL")
    return value


def positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubRuntimeError(f"{name} must be a positive integer")
    return value


def exact_keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        raise GitHubRuntimeError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise GitHubRuntimeError(f"{name} contains unsupported keys: {', '.join(extra)}")


@dataclass(frozen=True)
class GitHubRuntimeConfig:
    bridge_config_path: str
    connector_name: str
    max_response_bytes: int
    supported_actions: tuple[str, ...]
    registry_sha256: str

    def normalized(self, expected_actions: tuple[str, ...], expected_registry_sha: str) -> "GitHubRuntimeConfig":
        bridge_path = string(self.bridge_config_path, "runtime_config.bridge_config_path")
        connector_name = string(self.connector_name, "runtime_config.connector_name")
        if connector_name != "GitHub":
            raise GitHubRuntimeError("runtime_config.connector_name must be 'GitHub'")
        max_bytes = positive_integer(self.max_response_bytes, "runtime_config.max_response_bytes")
        actions = tuple(self.supported_actions)
        if actions != expected_actions:
            raise GitHubRuntimeError("runtime_config.supported_actions must match the fixed v0.7 registry")
        if self.registry_sha256 != expected_registry_sha:
            raise GitHubRuntimeError("runtime_config.registry_sha256 mismatch")
        return GitHubRuntimeConfig(
            bridge_config_path=bridge_path,
            connector_name=connector_name,
            max_response_bytes=max_bytes,
            supported_actions=actions,
            registry_sha256=expected_registry_sha,
        )

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": CONFIG_SCHEMA,
            "bridge_config_path": self.bridge_config_path,
            "connector_name": self.connector_name,
            "max_response_bytes": self.max_response_bytes,
            "supported_actions": list(self.supported_actions),
            "registry_sha256": self.registry_sha256,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        payload = self.payload()
        return {**payload, "config_sha256": canonical_sha256(payload)}

    @classmethod
    def from_document(
        cls,
        value: Any,
        *,
        expected_actions: tuple[str, ...],
        expected_registry_sha: str,
    ) -> "GitHubRuntimeConfig":
        raw = mapping(value, "runtime_config")
        expected = {
            "schema_version",
            "bridge_config_path",
            "connector_name",
            "max_response_bytes",
            "supported_actions",
            "registry_sha256",
            "authority",
            "config_sha256",
        }
        exact_keys(raw, expected, "runtime_config")
        if raw["schema_version"] != CONFIG_SCHEMA:
            raise GitHubRuntimeError(f"runtime_config.schema_version must be {CONFIG_SCHEMA}")
        if raw["authority"] != AUTHORITY:
            raise GitHubRuntimeError("runtime_config.authority must remain fixed")
        payload = {key: raw[key] for key in raw if key != "config_sha256"}
        if raw["config_sha256"] != canonical_sha256(payload):
            raise GitHubRuntimeError("runtime_config.config_sha256 mismatch")
        actions_raw = raw["supported_actions"]
        if not isinstance(actions_raw, list) or not all(isinstance(x, str) for x in actions_raw):
            raise GitHubRuntimeError("runtime_config.supported_actions must be a string array")
        return cls(
            bridge_config_path=raw["bridge_config_path"],
            connector_name=raw["connector_name"],
            max_response_bytes=raw["max_response_bytes"],
            supported_actions=tuple(actions_raw),
            registry_sha256=raw["registry_sha256"],
        ).normalized(expected_actions, expected_registry_sha)


@dataclass(frozen=True)
class ConnectedGitHubReceipt:
    schema_version: str
    call_id: str
    action: str
    connector_name: str
    connector_tool: str
    request_sha256: str
    raw_response_sha256: str
    normalized_payload_sha256: str
    status: str
    locator: str
    bridge_receipt_sha256: str
    recorder_event_id: str
    recorder_head_sha256: str
    host_trace_head_sha256: str
    authority: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)
