"""Connected GitHub runtime harness built on GitHubAgentBridge v0.6."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sdk.liminal_github_bridge import (
    GitHubAgentBridge,
    GitHubBridgeError,
    GitHubOperation,
    OPERATION_POLICIES,
)

from ._contracts import (
    AUTHORITY,
    RUNTIME_SCHEMA,
    ConnectedGitHubReceipt,
    ConnectorInvoker,
    GitHubRuntimeConfig,
    GitHubRuntimeError,
    canonical_sha256,
)
from ._normalizers import (
    REGISTRY_SHA256,
    SUPPORTED_ACTIONS,
    connector_tool_for,
    normalize_connector_response,
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


def _verify_bridge_registry() -> None:
    if set(OPERATION_POLICIES) != set(SUPPORTED_ACTIONS):
        raise GitHubRuntimeError("v0.6 operation catalog diverges from the fixed v0.7 registry")


class ConnectorNamespaceInvoker:
    """Dispatches fixed registry names to methods on one connected namespace object."""

    def __init__(self, namespace: Any):
        self.namespace = namespace

    def preflight(self, tool_name: str) -> None:
        if tool_name not in SUPPORTED_ACTIONS:
            raise GitHubRuntimeError(f"tool is outside the fixed registry: {tool_name}")
        method = getattr(self.namespace, tool_name, None)
        if not callable(method):
            raise GitHubRuntimeError(f"connected GitHub namespace lacks callable tool: {tool_name}")

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        self.preflight(tool_name)
        method = getattr(self.namespace, tool_name)
        return method(**copy.deepcopy(arguments))


class ConnectedGitHubRuntime:
    """Fixed dispatcher from validated v0.6 operations to a connected GitHub namespace."""

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)

    @classmethod
    def create(
        cls,
        config_path: str | Path,
        *,
        bridge_config_path: str | Path,
        max_response_bytes: int = 4_194_304,
    ) -> "ConnectedGitHubRuntime":
        _verify_bridge_registry()
        path = Path(config_path)
        if path.exists():
            raise GitHubRuntimeError(f"runtime config already exists: {path}")
        bridge = GitHubAgentBridge(bridge_config_path)
        bridge.verify(allow_pending=True)
        config = GitHubRuntimeConfig(
            bridge_config_path=str(bridge_config_path),
            connector_name="GitHub",
            max_response_bytes=max_response_bytes,
            supported_actions=SUPPORTED_ACTIONS,
            registry_sha256=REGISTRY_SHA256,
        ).normalized(SUPPORTED_ACTIONS, REGISTRY_SHA256)
        _atomic_write_json(path, config.as_document())
        return cls(path)

    @property
    def config(self) -> GitHubRuntimeConfig:
        _verify_bridge_registry()
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise GitHubRuntimeError(f"runtime config does not exist: {self.config_path}") from exc
        except json.JSONDecodeError as exc:
            raise GitHubRuntimeError(f"runtime config is not valid JSON: {exc}") from exc
        return GitHubRuntimeConfig.from_document(
            raw,
            expected_actions=SUPPORTED_ACTIONS,
            expected_registry_sha=REGISTRY_SHA256,
        )

    @property
    def bridge(self) -> GitHubAgentBridge:
        return GitHubAgentBridge(self.config.bridge_config_path)

    @staticmethod
    def _coerce_invoker(connector: Any) -> ConnectorInvoker:
        invoke = getattr(connector, "invoke", None)
        if callable(invoke):
            return connector
        raise GitHubRuntimeError(
            "connector must expose invoke(tool_name, arguments); "
            "wrap a method namespace with ConnectorNamespaceInvoker"
        )

    @staticmethod
    def _preflight_invoker(invoker: ConnectorInvoker, tool_name: str) -> None:
        preflight = getattr(invoker, "preflight", None)
        if callable(preflight):
            preflight(tool_name)

    def execute(
        self,
        operation: GitHubOperation,
        connector: ConnectorInvoker | ConnectorNamespaceInvoker,
    ) -> ConnectedGitHubReceipt:
        config = self.config
        normalized = self.bridge.validate_operation(operation)
        connector_tool = connector_tool_for(normalized.action)
        invoker = self._coerce_invoker(connector)
        self._preflight_invoker(invoker, connector_tool)
        captured: dict[str, Any] = {}

        def fixed_executor(action: str, arguments: dict[str, Any]) -> Any:
            if action != normalized.action:
                raise GitHubRuntimeError("bridge action changed during connected dispatch")
            if arguments != normalized.arguments:
                raise GitHubRuntimeError("bridge arguments changed during connected dispatch")
            raw_response = invoker.invoke(connector_tool, copy.deepcopy(arguments))
            result = normalize_connector_response(
                action=action,
                arguments=arguments,
                request_sha256=normalized.request_sha256,
                raw_response=raw_response,
                max_response_bytes=config.max_response_bytes,
            )
            captured["normalized"] = result
            return result.executor_result

        try:
            bridge_receipt = self.bridge.execute(operation, fixed_executor)
        except GitHubBridgeError as exc:
            raise GitHubRuntimeError(f"GitHub bridge rejected connected dispatch: {exc}") from exc
        result = captured.get("normalized")
        if result is None:
            raise GitHubRuntimeError("connector returned without a normalized response")
        bridge_document = bridge_receipt.as_dict()
        return ConnectedGitHubReceipt(
            schema_version=RUNTIME_SCHEMA,
            call_id=bridge_receipt.call_id,
            action=bridge_receipt.action,
            connector_name=config.connector_name,
            connector_tool=connector_tool,
            request_sha256=bridge_receipt.request_sha256,
            raw_response_sha256=result.raw_response_sha256,
            normalized_payload_sha256=result.normalized_payload_sha256,
            status=bridge_receipt.status,
            locator=bridge_receipt.locator,
            bridge_receipt_sha256=canonical_sha256(bridge_document),
            recorder_event_id=bridge_receipt.recorder_event_id,
            recorder_head_sha256=bridge_receipt.recorder_head_sha256,
            host_trace_head_sha256=bridge_receipt.host_trace_head_sha256,
            authority=AUTHORITY,
        )

    dispatch = execute

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        config = self.config
        bridge_summary = self.bridge.verify(allow_pending=allow_pending)
        return {
            "schema_version": RUNTIME_SCHEMA,
            "config_sha256": canonical_sha256(config.payload()),
            "connector_name": config.connector_name,
            "supported_actions": list(config.supported_actions),
            "registry_sha256": config.registry_sha256,
            "max_response_bytes": config.max_response_bytes,
            "bridge": bridge_summary,
            "authority": AUTHORITY,
        }

    def authorize_operation(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.authorize_operation(**kwargs)

    def append_visible_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.bridge.append_visible_event(payload)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_claim(**kwargs)

    def record_source(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_source(**kwargs)

    def record_authorization(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_authorization(**kwargs)

    def record_proposed_action(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_proposed_action(**kwargs)

    def record_contradiction(self, **kwargs: Any) -> dict[str, Any]:
        return self.bridge.record_contradiction(**kwargs)

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        self.verify()
        return self.bridge.seal(
            request_event_id=request_event_id,
            draft_event_id=draft_event_id,
        )

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self.verify()
        return self.bridge.export_live_session(output_path)


__all__ = ["ConnectedGitHubRuntime", "ConnectorNamespaceInvoker"]
