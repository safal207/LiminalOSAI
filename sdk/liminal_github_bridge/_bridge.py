"""GitHub-specific typed execution bridge built on HostIntegrationAdapter v0.5."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sdk.liminal_host_adapter import HostAdapterError, HostIntegrationAdapter, ToolCallSpec

from ._contracts import (
    AUTHORITY,
    BRIDGE_SCHEMA,
    GitHubBridgeConfig,
    GitHubBridgeError,
    GitHubExecutionReceipt,
    GitHubExecutor,
    GitHubExecutorResult,
    GitHubOperation,
    NormalizedGitHubOperation,
    canonical_sha256,
)


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


class GitHubAgentBridge:
    """Validates exact GitHub actions and wraps host-owned execution in v0.5."""

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)

    @classmethod
    def create(
        cls,
        config_path: str | Path,
        *,
        host_trace_path: str | Path,
        recorder_path: str | Path,
        session_id: str,
        high_stakes: bool,
        requires_current_information: bool,
        allowed_repositories: list[str],
        protected_branches: list[str] | None = None,
        max_request_bytes: int = 1_048_576,
    ) -> "GitHubAgentBridge":
        config_file = Path(config_path)
        if config_file.exists():
            raise GitHubBridgeError(f"bridge config already exists: {config_file}")
        config = GitHubBridgeConfig(
            host_trace_path=str(host_trace_path),
            allowed_repositories=tuple(allowed_repositories),
            protected_branches=tuple(protected_branches or ["main", "master"]),
            max_request_bytes=max_request_bytes,
        ).normalized()
        HostIntegrationAdapter.create(
            host_trace_path,
            recorder_path=recorder_path,
            session_id=session_id,
            high_stakes=high_stakes,
            requires_current_information=requires_current_information,
        )
        _atomic_write_json(config_file, config.as_document())
        return cls(config_file)

    @property
    def config(self) -> GitHubBridgeConfig:
        try:
            value = json.loads(self.config_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise GitHubBridgeError(f"bridge config does not exist: {self.config_path}") from exc
        except json.JSONDecodeError as exc:
            raise GitHubBridgeError(f"bridge config is not valid JSON: {exc}") from exc
        return GitHubBridgeConfig.from_document(value)

    @property
    def host(self) -> HostIntegrationAdapter:
        return HostIntegrationAdapter(self.config.host_trace_path)

    def validate_operation(self, operation: GitHubOperation) -> NormalizedGitHubOperation:
        return operation.normalized(self.config)

    def authorize_operation(
        self, *, event_id: str, text: str, operation: GitHubOperation
    ) -> dict[str, Any]:
        normalized = self.validate_operation(operation)
        return self.host.record_authorization(
            event_id=event_id,
            text=text,
            authorized_event_ids=[normalized.call_id],
        )

    def execute(
        self, operation: GitHubOperation, executor: GitHubExecutor
    ) -> GitHubExecutionReceipt:
        normalized = self.validate_operation(operation)
        spec = ToolCallSpec(
            call_id=normalized.call_id,
            tool="GitHub",
            operation=normalized.operation_summary,
            effect=normalized.effect,
            evidence_eligible=True,
            freshness="current",
            reversible=normalized.reversible,
            recovery_plan=normalized.recovery_plan,
        )
        event: dict[str, Any]
        try:
            with self.host.tool_call(spec) as call:
                raw_result = executor(
                    normalized.action,
                    copy.deepcopy(normalized.arguments),
                )
                result = GitHubExecutorResult.from_value(raw_result)
                if result.status == "success":
                    event = call.succeed(locator=result.locator)
                elif result.status == "failure":
                    event = call.fail(locator=result.locator)
                else:
                    event = call.cancel(locator=result.locator)
            verification = self.host.verify()
        except HostAdapterError as exc:
            raise GitHubBridgeError(f"host adapter rejected GitHub operation: {exc}") from exc
        return GitHubExecutionReceipt(
            schema_version=BRIDGE_SCHEMA,
            call_id=normalized.call_id,
            action=normalized.action,
            repository_full_name=normalized.repository_full_name,
            request_sha256=normalized.request_sha256,
            status=result.status,
            locator=result.locator,
            payload_sha256=result.payload_sha256,
            recorder_event_id=event["id"],
            recorder_head_sha256=verification["recorder_head_sha256"],
            host_trace_head_sha256=verification["trace_head_sha256"],
            authority=AUTHORITY,
        )

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        config = self.config
        host_summary = self.host.verify(allow_pending=allow_pending)
        return {
            "schema_version": BRIDGE_SCHEMA,
            "config_sha256": canonical_sha256(config.payload()),
            "allowed_repositories": list(config.allowed_repositories),
            "protected_branches": list(config.protected_branches),
            "max_request_bytes": config.max_request_bytes,
            "host": host_summary,
            "authority": AUTHORITY,
        }

    def append_visible_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.host.append_visible_event(payload)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_claim(**kwargs)

    def record_source(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_source(**kwargs)

    def record_authorization(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_authorization(**kwargs)

    def record_proposed_action(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_proposed_action(**kwargs)

    def record_contradiction(self, **kwargs: Any) -> dict[str, Any]:
        return self.host.record_contradiction(**kwargs)

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        self.verify()
        return self.host.seal(
            request_event_id=request_event_id,
            draft_event_id=draft_event_id,
        )

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self.verify()
        return self.host.export_live_session(output_path)


__all__ = ["GitHubAgentBridge"]
