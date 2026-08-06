"""Exact GitHub connector action schemas for v0.6."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ._contracts import (
    GitHubBridgeConfig, GitHubBridgeError, array, boolean, enum, exact_keys,
    git_ref, git_sha, mapping, optional_string, positive_integer,
    repository_name, repository_path, string,
)


@dataclass(frozen=True)
class OperationPolicy:
    effect: str
    required: frozenset[str]
    optional: frozenset[str]
    reversible: bool
    recovery_plan: str | None
    validator: Callable[[dict[str, Any]], dict[str, Any]]


def get_repo(raw: dict[str, Any]) -> dict[str, Any]:
    return {"repository_full_name": repository_name(raw["repository_full_name"])}


def fetch_file(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "path": repository_path(raw["path"]),
    }
    if "ref" in raw:
        result["ref"] = optional_string(raw["ref"], "arguments.ref")
    if "encoding" in raw:
        result["encoding"] = enum(raw["encoding"], "arguments.encoding", {"utf-8", "base64"})
    return result


def pr_read(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_full_name": repository_name(raw["repo_full_name"], "arguments.repo_full_name"),
        "pr_number": positive_integer(raw["pr_number"], "arguments.pr_number"),
    }


def compare_commits(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_full_name": repository_name(raw["repo_full_name"], "arguments.repo_full_name"),
        "base": git_ref(raw["base"], "arguments.base"),
        "head": git_ref(raw["head"], "arguments.head"),
    }


def commit_status(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_full_name": repository_name(raw["repo_full_name"], "arguments.repo_full_name"),
        "commit_sha": git_sha(raw["commit_sha"], "arguments.commit_sha"),
    }


def create_branch(raw: dict[str, Any]) -> dict[str, Any]:
    has_sha = "sha" in raw and raw["sha"] is not None
    has_base = "base_ref" in raw and raw["base_ref"] is not None
    if has_sha == has_base:
        raise GitHubBridgeError("create_branch requires exactly one of sha or base_ref")
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "branch_name": git_ref(raw["branch_name"], "arguments.branch_name"),
    }
    result["sha" if has_sha else "base_ref"] = (
        git_sha(raw["sha"], "arguments.sha") if has_sha
        else git_ref(raw["base_ref"], "arguments.base_ref")
    )
    return result


def create_file(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "path": repository_path(raw["path"]),
        "content": string(raw["content"], "arguments.content", allow_empty=True),
        "message": string(raw["message"], "arguments.message"),
        "branch": git_ref(raw["branch"], "arguments.branch"),
    }


def update_file(raw: dict[str, Any]) -> dict[str, Any]:
    result = create_file(raw)
    result["sha"] = git_sha(raw["sha"], "arguments.sha")
    return result


def delete_file(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "path": repository_path(raw["path"]),
        "message": string(raw["message"], "arguments.message"),
        "sha": git_sha(raw["sha"], "arguments.sha"),
        "branch": git_ref(raw["branch"], "arguments.branch"),
    }


def create_blob(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "content": string(raw["content"], "arguments.content", allow_empty=True),
    }
    if "encoding" in raw:
        result["encoding"] = enum(raw["encoding"], "arguments.encoding", {"utf-8", "base64"})
    return result


def create_tree(raw: dict[str, Any]) -> dict[str, Any]:
    elements = array(raw["tree_elements"], "arguments.tree_elements")
    if not elements:
        raise GitHubBridgeError("arguments.tree_elements must not be empty")
    normalized = []
    for i, element in enumerate(elements):
        item = mapping(element, f"arguments.tree_elements[{i}]")
        exact_keys(item, {"path", "mode", "type"}, {"sha", "content"}, f"tree_elements[{i}]")
        if ("sha" in item) == ("content" in item):
            raise GitHubBridgeError(f"tree_elements[{i}] requires exactly one of sha or content")
        value = {
            "path": repository_path(item["path"], f"tree_elements[{i}].path"),
            "mode": enum(item["mode"], f"tree_elements[{i}].mode", {"100644", "100755", "040000", "160000", "120000"}),
            "type": enum(item["type"], f"tree_elements[{i}].type", {"blob", "tree", "commit"}),
        }
        if "sha" in item:
            value["sha"] = None if item["sha"] is None else git_sha(item["sha"], f"tree_elements[{i}].sha")
        else:
            value["content"] = string(item["content"], f"tree_elements[{i}].content", allow_empty=True)
        normalized.append(value)
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "tree_elements": normalized,
    }
    if "base_tree_sha" in raw:
        result["base_tree_sha"] = optional_string(raw["base_tree_sha"], "arguments.base_tree_sha")
        if result["base_tree_sha"] is not None:
            result["base_tree_sha"] = git_sha(result["base_tree_sha"], "arguments.base_tree_sha")
    return result


def create_commit(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "message": string(raw["message"], "arguments.message"),
        "tree_sha": git_sha(raw["tree_sha"], "arguments.tree_sha"),
        "parent_sha": git_sha(raw["parent_sha"], "arguments.parent_sha"),
    }
    if "additional_parent_shas" in raw:
        result["additional_parent_shas"] = [
            git_sha(x, f"arguments.additional_parent_shas[{i}]")
            for i, x in enumerate(array(raw["additional_parent_shas"], "arguments.additional_parent_shas"))
        ]
    return result


def update_ref(raw: dict[str, Any]) -> dict[str, Any]:
    if boolean(raw.get("force", False), "arguments.force"):
        raise GitHubBridgeError("force ref updates are not supported by v0.6")
    return {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "branch_name": git_ref(raw["branch_name"], "arguments.branch_name"),
        "sha": git_sha(raw["sha"], "arguments.sha"),
        "force": False,
    }


def create_pr(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "title": string(raw["title"], "arguments.title"),
        "head": git_ref(raw["head"], "arguments.head"),
        "base": git_ref(raw["base"], "arguments.base"),
    }
    if "body" in raw:
        result["body"] = optional_string(raw["body"], "arguments.body")
    if "draft" in raw:
        result["draft"] = boolean(raw["draft"], "arguments.draft")
    if "maintainer_can_modify" in raw:
        result["maintainer_can_modify"] = boolean(raw["maintainer_can_modify"], "arguments.maintainer_can_modify")
    return result


def merge_pr(raw: dict[str, Any]) -> dict[str, Any]:
    result = {
        "repository_full_name": repository_name(raw["repository_full_name"]),
        "pr_number": positive_integer(raw["pr_number"], "arguments.pr_number"),
        "expected_head_sha": git_sha(raw["expected_head_sha"], "arguments.expected_head_sha"),
    }
    if "merge_method" in raw:
        result["merge_method"] = enum(raw["merge_method"], "arguments.merge_method", {"merge", "squash", "rebase"})
    if "commit_title" in raw:
        result["commit_title"] = optional_string(raw["commit_title"], "arguments.commit_title")
    if "commit_message" in raw:
        result["commit_message"] = optional_string(raw["commit_message"], "arguments.commit_message")
    return result


R, O, W = frozenset, frozenset(), "write"
OPERATION_POLICIES = {
    "get_repo": OperationPolicy("read", R({"repository_full_name"}), O, True, None, get_repo),
    "fetch_file": OperationPolicy("read", R({"repository_full_name", "path"}), R({"ref", "encoding"}), True, None, fetch_file),
    "fetch_pr": OperationPolicy("read", R({"repo_full_name", "pr_number"}), O, True, None, pr_read),
    "compare_commits": OperationPolicy("read", R({"repo_full_name", "base", "head"}), O, True, None, compare_commits),
    "get_commit_combined_status": OperationPolicy("read", R({"repo_full_name", "commit_sha"}), O, True, None, commit_status),
    "list_pr_changed_filenames": OperationPolicy("read", R({"repo_full_name", "pr_number"}), O, True, None, pr_read),
    "create_branch": OperationPolicy(W, R({"repository_full_name", "branch_name"}), R({"sha", "base_ref"}), True, "Delete the created branch", create_branch),
    "create_file": OperationPolicy(W, R({"repository_full_name", "path", "content", "message", "branch"}), O, True, "Delete the created file in a follow-up commit", create_file),
    "update_file": OperationPolicy(W, R({"repository_full_name", "path", "content", "message", "sha", "branch"}), O, True, "Revert the update commit", update_file),
    "delete_file": OperationPolicy(W, R({"repository_full_name", "path", "message", "sha", "branch"}), O, True, "Restore the file from its parent commit", delete_file),
    "create_blob": OperationPolicy(W, R({"repository_full_name", "content"}), R({"encoding"}), True, "Leave the blob unreferenced", create_blob),
    "create_tree": OperationPolicy(W, R({"repository_full_name", "tree_elements"}), R({"base_tree_sha"}), True, "Leave the tree unreferenced", create_tree),
    "create_commit": OperationPolicy(W, R({"repository_full_name", "message", "tree_sha", "parent_sha"}), R({"additional_parent_shas"}), True, "Leave the commit unreferenced or move the branch back", create_commit),
    "update_ref": OperationPolicy(W, R({"repository_full_name", "branch_name", "sha"}), R({"force"}), True, "Move the branch back with separate authorization", update_ref),
    "create_pull_request": OperationPolicy(W, R({"repository_full_name", "title", "head", "base"}), R({"body", "draft", "maintainer_can_modify"}), True, "Close the pull request", create_pr),
    "merge_pull_request": OperationPolicy(W, R({"repository_full_name", "pr_number", "expected_head_sha"}), R({"merge_method", "commit_title", "commit_message"}), False, "Create and review a revert pull request", merge_pr),
}


def enforce_protected_ref_policy(action: str, arguments: dict[str, Any], config: GitHubBridgeConfig) -> None:
    branch = None
    if action in {"create_file", "update_file", "delete_file"}:
        branch = arguments.get("branch")
    elif action in {"create_branch", "update_ref"}:
        branch = arguments.get("branch_name")
    if branch in config.protected_branches:
        raise GitHubBridgeError(f"direct write to protected branch is blocked by v0.6: {branch}")


def operation_summary(action: str, arguments: dict[str, Any], digest: str) -> str:
    repo = arguments.get("repository_full_name", arguments.get("repo_full_name"))
    target = ""
    if "path" in arguments:
        target = f" path={arguments['path']}"
    elif "branch_name" in arguments:
        target = f" branch={arguments['branch_name']}"
    elif "pr_number" in arguments:
        target = f" pr={arguments['pr_number']}"
    elif action == "create_pull_request":
        target = f" head={arguments['head']} base={arguments['base']}"
    return f"GitHub.{action} repo={repo}{target} request_sha256={digest}"
