"""Shared primitives for the host integration adapter."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

HOST_TRACE_SCHEMA = "chatgpt-host-tool-trace-v0.5"
ZERO_HASH = "0" * 64
TOOL_EFFECTS = {"read", "write", "none"}
TOOL_STATUSES = {"success", "failure", "cancelled"}
FRESHNESS_VALUES = {"current", "stable", "unknown"}

AUTHORITY = {
    "mode": "host_integration_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "source_truth_verification": False,
    "tool_result_fabrication": False,
    "tool_execution_ownership": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class HostAdapterError(ValueError):
    """Raised when a host trace or tool lifecycle violates v0.5."""


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HostAdapterError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise HostAdapterError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise HostAdapterError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise HostAdapterError(f"{name} must not be empty")
    return value


def optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return string(value, name)


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise HostAdapterError(f"{name} must be a boolean")
    return value


def enum(value: Any, name: str, allowed: set[str]) -> str:
    item = string(value, name)
    if item not in allowed:
        raise HostAdapterError(f"{name} must be one of {sorted(allowed)}")
    return item


def exact_keys(raw: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        raise HostAdapterError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise HostAdapterError(f"{name} contains unsupported keys: {', '.join(extra)}")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise HostAdapterError(f"host trace lock already exists: {lock_path}") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        yield
    finally:
        lock_path.unlink(missing_ok=True)


@dataclass(frozen=True)
class ToolCallSpec:
    """Metadata known before one visible tool call starts."""

    call_id: str
    tool: str
    operation: str
    effect: str
    evidence_eligible: bool
    freshness: str
    reversible: bool
    recovery_plan: str | None

    def normalized(self) -> "ToolCallSpec":
        return ToolCallSpec(
            call_id=string(self.call_id, "tool_call.call_id"),
            tool=string(self.tool, "tool_call.tool"),
            operation=string(self.operation, "tool_call.operation"),
            effect=enum(self.effect, "tool_call.effect", TOOL_EFFECTS),
            evidence_eligible=boolean(
                self.evidence_eligible, "tool_call.evidence_eligible"
            ),
            freshness=enum(self.freshness, "tool_call.freshness", FRESHNESS_VALUES),
            reversible=boolean(self.reversible, "tool_call.reversible"),
            recovery_plan=optional_string(
                self.recovery_plan, "tool_call.recovery_plan"
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        value = self.normalized()
        return {
            "call_id": value.call_id,
            "tool": value.tool,
            "operation": value.operation,
            "effect": value.effect,
            "evidence_eligible": value.evidence_eligible,
            "freshness": value.freshness,
            "reversible": value.reversible,
            "recovery_plan": value.recovery_plan,
        }
