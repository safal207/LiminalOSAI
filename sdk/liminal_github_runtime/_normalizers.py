"""Fixed GitHub connector registry and response normalizers for v0.7."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from sdk.liminal_github_bridge import GitHubExecutorResult

from ._contracts import GitHubRuntimeError, canonical_json, canonical_sha256, mapping, string

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

_ACTION_BINDINGS = {
    "get_repo": "get_repo",
    "fetch_file": "fetch_file",
    "fetch_pr": "fetch_pr",
    "compare_commits": "compare_commits",
    "get_commit_combined_status": "get_commit_combined_status",
    "list_pr_changed_filenames": "list_pr_changed_filenames",
    "create_branch": "create_branch",
    "create_file": "create_file",
    "update_file": "update_file",
    "delete_file": "delete_file",
    "create_blob": "create_blob",
    "create_tree": "create_tree",
    "create_commit": "create_commit",
    "update_ref": "update_ref",
    "create_pull_request": "create_pull_request",
    "merge_pull_request": "merge_pull_request",
}
ACTION_BINDINGS = MappingProxyType(_ACTION_BINDINGS)
SUPPORTED_ACTIONS = tuple(_ACTION_BINDINGS)
REGISTRY_SHA256 = canonical_sha256(_ACTION_BINDINGS)

READ_ACTIONS = {
    "get_repo",
    "fetch_file",
    "fetch_pr",
    "compare_commits",
    "get_commit_combined_status",
    "list_pr_changed_filenames",
}


@dataclass(frozen=True)
class NormalizedConnectorResponse:
    executor_result: GitHubExecutorResult
    raw_response_sha256: str
    normalized_payload_sha256: str


def connector_tool_for(action: str) -> str:
    try:
        return ACTION_BINDINGS[action]
    except KeyError as exc:
        raise GitHubRuntimeError(f"action is outside the fixed connector registry: {action}") from exc


def _sha(value: Any, name: str) -> str:
    text = string(value, name)
    if not SHA_RE.fullmatch(text):
        raise GitHubRuntimeError(f"{name} must be a 40-character Git SHA")
    return text.lower()


def _unwrap(raw: Any) -> tuple[Any, Any | None]:
    if isinstance(raw, dict) and "error" in raw:
        error = raw["error"]
        if error is not None:
            return raw, error
        if "result" in raw:
            return raw["result"], None
    return raw, None


def _walk_locator(value: Any) -> str | None:
    preferred = ("display_url", "html_url", "url", "resource_uri", "locator")
    if isinstance(value, dict):
        for key in preferred:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        for key in ("result", "structuredContent", "content"):
            if key in value:
                candidate = _walk_locator(value[key])
                if candidate:
                    return candidate
    return None


def _repo(arguments: dict[str, Any]) -> str:
    return arguments.get("repository_full_name", arguments.get("repo_full_name", "unknown/unknown"))


def _fallback_locator(action: str, arguments: dict[str, Any], payload: Any, request_sha: str) -> str:
    repo = _repo(arguments)
    if action == "create_branch" and isinstance(payload, dict) and isinstance(payload.get("branch"), str):
        return f"github://{repo}/branch/{payload['branch']}"
    if action in {"create_file", "update_file", "delete_file", "create_commit"} and isinstance(payload, dict):
        sha = payload.get("commit_sha", payload.get("sha"))
        if isinstance(sha, str) and SHA_RE.fullmatch(sha):
            return f"github://{repo}/commit/{sha.lower()}"
    if action in {"create_blob", "create_tree"} and isinstance(payload, dict):
        sha = payload.get("sha")
        if isinstance(sha, str) and SHA_RE.fullmatch(sha):
            return f"github://{repo}/{action.removeprefix('create_')}/{sha.lower()}"
    if action == "create_pull_request" and isinstance(payload, dict) and isinstance(payload.get("number"), int):
        return f"github://{repo}/pull/{payload['number']}"
    if action == "merge_pull_request" and isinstance(payload, dict) and isinstance(payload.get("sha"), str):
        return f"github://{repo}/commit/{payload['sha'].lower()}"
    return f"github://connector/{action}/{request_sha}"


def _normalize_success_payload(action: str, payload: Any) -> Any:
    if action in READ_ACTIONS:
        canonical_json(payload)
        return payload
    item = mapping(payload, f"connector_response[{action}]")
    if action == "create_branch":
        string(item.get("branch"), "connector_response.branch")
        if item.get("sha") is not None:
            _sha(item["sha"], "connector_response.sha")
    elif action in {"create_file", "update_file", "delete_file"}:
        _sha(item.get("commit_sha"), "connector_response.commit_sha")
    elif action in {"create_blob", "create_tree", "create_commit"}:
        _sha(item.get("sha"), "connector_response.sha")
    elif action == "update_ref":
        has_sha = item.get("sha") is not None
        succeeded = item.get("success") is True or item.get("updated") is True
        if not has_sha and not succeeded:
            raise GitHubRuntimeError("update_ref response requires sha, success=true, or updated=true")
        if has_sha:
            _sha(item["sha"], "connector_response.sha")
    elif action == "create_pull_request":
        has_url = isinstance(item.get("url"), str) and bool(item["url"].strip())
        has_number = isinstance(item.get("number"), int) and not isinstance(item["number"], bool) and item["number"] > 0
        if not has_url and not has_number:
            raise GitHubRuntimeError("create_pull_request response requires url or positive number")
    elif action == "merge_pull_request":
        if item.get("merged") is not True:
            raise GitHubRuntimeError("merge_pull_request success response must contain merged=true")
        _sha(item.get("sha"), "connector_response.sha")
    else:
        raise GitHubRuntimeError(f"no response normalizer for action: {action}")
    canonical_json(item)
    return item


def normalize_connector_response(
    *,
    action: str,
    arguments: dict[str, Any],
    request_sha256: str,
    raw_response: Any,
    max_response_bytes: int,
) -> NormalizedConnectorResponse:
    raw_json = canonical_json(raw_response)
    raw_size = len(raw_json.encode("utf-8"))
    if raw_size > max_response_bytes:
        raise GitHubRuntimeError(
            f"connector response exceeds max_response_bytes ({raw_size} > {max_response_bytes})"
        )
    raw_sha = canonical_sha256(raw_response)
    payload, connector_error = _unwrap(raw_response)
    if connector_error is not None:
        locator = _walk_locator(raw_response) or f"github://connector/{action}/error/{raw_sha}"
        result = GitHubExecutorResult.failure(locator=locator, payload=raw_response)
        return NormalizedConnectorResponse(result, raw_sha, result.payload_sha256)

    if action == "merge_pull_request" and isinstance(payload, dict) and payload.get("merged") is False:
        locator = _walk_locator(payload) or f"github://connector/{action}/not-merged/{raw_sha}"
        result = GitHubExecutorResult.failure(locator=locator, payload=payload)
        return NormalizedConnectorResponse(result, raw_sha, result.payload_sha256)

    normalized_payload = _normalize_success_payload(action, payload)
    locator = _walk_locator(raw_response) or _fallback_locator(
        action, arguments, normalized_payload, request_sha256
    )
    result = GitHubExecutorResult.success(locator=locator, payload=normalized_payload)
    return NormalizedConnectorResponse(result, raw_sha, result.payload_sha256)
