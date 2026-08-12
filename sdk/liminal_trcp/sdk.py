"""Stable public integration surface for the TRCP Adapter SDK v0.1.

External consumers should import from this module only.  The lower-level
``adapter``, ``evidence``, ``replay``, and simulator modules remain internal
implementation details of this facade.

The SDK is deliberately local and synthetic.  It creates deterministic TRCP
records, binds a normalized workload to an evidence bundle, and returns a
typed receipt.  Optional execution replay is reported separately and can
never change the binding receipt.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from sdk.liminal_trcp import AuthorizationRecord as _AuthorizationRecord
from sdk.liminal_trcp import MockProvider as _MockProvider
from sdk.liminal_trcp import ScopeEnvelope as _ScopeEnvelope
from sdk.liminal_trcp.adapter import (
    build_workload_evidence as _build_internal_workload_evidence,
)
from sdk.liminal_trcp.adapter import run_external_consumer as _run_external_consumer
from sdk.liminal_trcp.replay import (
    GENERIC_WORKLOAD_EVIDENCE_SCHEMA as _GENERIC_WORKLOAD_EVIDENCE_SCHEMA,
)
from sdk.liminal_trcp.replay import verify_evidence_bundle as _verify_evidence_bundle

ADAPTER_SDK_VERSION = "0.1"
NORMALIZED_WORKLOAD_SCHEMA = _GENERIC_WORKLOAD_EVIDENCE_SCHEMA

_NORMALIZED_FIELDS = frozenset(
    {
        "schema",
        "consumer_type",
        "requested_operation",
        "actor",
        "input",
        "result",
    }
)
_CONSUMER_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 900_000


class TRCPAdapterError(ValueError):
    """Base class for stable public Adapter SDK errors."""


class AdapterContractError(TRCPAdapterError):
    """Raised when an adapter does not implement the public contract."""


class WorkloadNormalizationError(TRCPAdapterError):
    """Raised when a normalized workload is invalid or non-deterministic."""


class BindingVerificationError(TRCPAdapterError):
    """Raised when a binding receipt cannot be produced or decoded."""


@runtime_checkable
class ExternalWorkloadAdapter(Protocol):
    """Minimal structural contract implemented by an external consumer.

    No inheritance is required.  ``normalize`` must return the versioned
    normalized workload mapping produced by :func:`normalize_workload`.
    """

    consumer_type: str

    def normalize(self, external_input: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class ExecutionReplayHook(Protocol):
    """Optional execution replay implemented in addition to the adapter."""

    def replay_execution(self, workload: Mapping[str, Any]) -> Any: ...


@dataclass(frozen=True)
class BindingCheck:
    """One deterministic verifier check in a binding receipt."""

    id: str
    result: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        body = {"id": self.id, "result": self.result}
        if self.detail:
            body["detail"] = self.detail
        return body


@dataclass(frozen=True)
class BindingReceipt:
    """Typed, deterministic result of evidence binding verification."""

    schema: str
    result: str
    source_bundle_sha256: str
    checks: tuple[BindingCheck, ...]
    receipt_sha256: str
    failed_check: str | None = None
    failure_detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema": self.schema,
            "result": self.result,
            "source_bundle_sha256": self.source_bundle_sha256,
            "checks": [check.as_dict() for check in self.checks],
        }
        if self.failed_check is not None:
            body["failed_check"] = self.failed_check
        if self.failure_detail:
            body["failure_detail"] = self.failure_detail
        body["receipt_sha256"] = self.receipt_sha256
        return body


@dataclass(frozen=True)
class ExecutionReplayResult:
    """Optional execution replay outcome, separate from binding proof."""

    status: str
    matches_binding_result: bool | None = None
    result: Any = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"status": self.status}
        if self.matches_binding_result is not None:
            body["matches_binding_result"] = self.matches_binding_result
        if self.result is not None:
            body["result"] = copy.deepcopy(self.result)
        if self.error is not None:
            body["error"] = self.error
        return body


@dataclass(frozen=True)
class ExternalWorkloadResult:
    """Complete public result of an external workload integration run."""

    normalized_workload: dict[str, Any]
    workload_evidence: dict[str, Any]
    evidence_bundle: dict[str, Any]
    binding_receipt: BindingReceipt
    execution_replay: ExecutionReplayResult
    report: dict[str, Any]
    _workload_sha256: str
    _bundle_sha256: str

    @property
    def workload_sha256(self) -> str:
        return self._workload_sha256

    @property
    def bundle_sha256(self) -> str:
        return self._bundle_sha256

    @property
    def receipt_sha256(self) -> str:
        return self.binding_receipt.receipt_sha256


def _json_copy(value: Any, name: str) -> Any:
    """Return JSON primitives only and reject NaN/Infinity/custom objects."""
    _validate_json_tree(value, name, seen=set())
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        try:
            encoded_bytes = encoded.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise WorkloadNormalizationError(
                f"{name} must not contain invalid Unicode surrogates"
            ) from exc
        if len(encoded_bytes) > _MAX_JSON_BYTES:
            raise WorkloadNormalizationError(
                f"{name} exceeds the {_MAX_JSON_BYTES:,}-byte Adapter SDK limit"
            )
        return json.loads(encoded)
    except WorkloadNormalizationError:
        raise
    except (TypeError, ValueError) as exc:
        raise WorkloadNormalizationError(f"{name} must be canonical JSON data: {exc}") from exc


def _validate_json_tree(
    value: Any,
    name: str,
    *,
    seen: set[int],
    _depth: int = 0,
) -> None:
    if _depth > 64:
        raise WorkloadNormalizationError(f"{name} exceeds the maximum JSON depth of 64")
    if value is None or isinstance(value, (str, bool, int, float)):
        return
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise WorkloadNormalizationError(f"{name} must not contain a reference cycle")
        seen.add(identity)
        try:
            for key, child in value.items():
                if not isinstance(key, str):
                    raise WorkloadNormalizationError(
                        f"{name} must use string JSON object keys"
                    )
                _validate_json_tree(child, name, seen=seen, _depth=_depth + 1)
        finally:
            seen.remove(identity)
        return
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            raise WorkloadNormalizationError(f"{name} must not contain a reference cycle")
        seen.add(identity)
        try:
            for child in value:
                _validate_json_tree(child, name, seen=seen, _depth=_depth + 1)
        finally:
            seen.remove(identity)
        return
    raise WorkloadNormalizationError(
        f"{name} contains unsupported JSON value: {type(value).__name__}"
    )


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _consumer_type(value: Any) -> str:
    if not isinstance(value, str) or not _CONSUMER_TYPE_PATTERN.fullmatch(value):
        raise AdapterContractError(
            "consumer_type must match ^[a-z0-9][a-z0-9._-]{0,63}$"
        )
    return value


def _string_or_string_list(value: Any, name: str) -> str | list[str]:
    if isinstance(value, str):
        if not value or value != value.strip():
            raise WorkloadNormalizationError(f"{name} must be a non-empty trimmed string")
        return value
    if isinstance(value, (list, tuple)) and value:
        items = list(value)
        if any(
            not isinstance(item, str) or not item or item != item.strip()
            for item in items
        ):
            raise WorkloadNormalizationError(
                f"{name} must contain only non-empty trimmed strings"
            )
        return items
    raise WorkloadNormalizationError(f"{name} must be a string or non-empty string list")


def normalize_workload(
    *,
    consumer_type: str,
    requested_operation: str | list[str] | tuple[str, ...],
    actor: str | list[str] | tuple[str, ...],
    input_data: Mapping[str, Any],
    result: Any,
) -> dict[str, Any]:
    """Build a strict ``generic-workload-evidence-v0.1`` artifact.

    The six fields returned here are the exact workload hash closure.  Extra
    fields are intentionally rejected when an adapter returns its artifact,
    so no unbound metadata can look as if it were covered by the receipt.
    """
    normalized_consumer_type = _consumer_type(consumer_type)
    if not isinstance(input_data, Mapping):
        raise WorkloadNormalizationError("input_data must be a mapping")
    body = {
        "schema": NORMALIZED_WORKLOAD_SCHEMA,
        "consumer_type": normalized_consumer_type,
        "requested_operation": _string_or_string_list(
            requested_operation, "requested_operation"
        ),
        "actor": _string_or_string_list(actor, "actor"),
        "input": _json_copy(dict(input_data), "input_data"),
        "result": _json_copy(result, "result"),
    }
    return body


def _validated_normalized_workload(
    workload: Mapping[str, Any],
    *,
    expected_consumer_type: str | None = None,
) -> dict[str, Any]:
    if not isinstance(workload, Mapping):
        raise WorkloadNormalizationError("adapter normalize() must return a mapping")
    copied = _json_copy(dict(workload), "normalized workload")
    fields = frozenset(copied)
    if fields != _NORMALIZED_FIELDS:
        missing = sorted(_NORMALIZED_FIELDS - fields)
        extra = sorted(fields - _NORMALIZED_FIELDS)
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("extra: " + ", ".join(extra))
        raise WorkloadNormalizationError(
            "normalized workload must contain exactly the v0.1 fields ("
            + "; ".join(details)
            + ")"
        )
    if copied["schema"] != NORMALIZED_WORKLOAD_SCHEMA:
        raise WorkloadNormalizationError(
            f"normalized workload schema must be {NORMALIZED_WORKLOAD_SCHEMA!r}"
        )
    normalized_consumer_type = _consumer_type(copied["consumer_type"])
    if (
        expected_consumer_type is not None
        and normalized_consumer_type != expected_consumer_type
    ):
        raise AdapterContractError(
            "normalized workload consumer_type does not match adapter.consumer_type"
        )
    # Rebuild through the constructor so all field validation stays centralized.
    return normalize_workload(
        consumer_type=normalized_consumer_type,
        requested_operation=copied["requested_operation"],
        actor=copied["actor"],
        input_data=copied["input"],
        result=copied["result"],
    )


def _task(consumer_type: str, workload_sha256: str) -> dict[str, Any]:
    if not _SHA256_PATTERN.fullmatch(workload_sha256):
        raise AdapterContractError("workload_sha256 must be 64 lowercase hex characters")
    return {
        "task_id": f"task:trcp-sdk:{consumer_type}",
        "asset_id": f"fixture:trcp-sdk:{consumer_type}",
        "activity_class": "EXTERNAL_WORKLOAD_VALIDATION",
        "action": "VERIFY_SYNTHETIC_WORKLOAD",
        "fixture": (
            f"trcp-adapter-sdk-{ADAPTER_SDK_VERSION}:{consumer_type}"
            f"@sha256:{workload_sha256}"
        ),
    }


def build_workload_evidence(
    normalized_workload: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a validated normalized workload to its deterministic SDK task."""
    workload = _validated_normalized_workload(normalized_workload)
    workload_sha256 = _canonical_sha256(workload)
    task = _task(workload["consumer_type"], workload_sha256)
    return _build_internal_workload_evidence(workload, task)


def _binding_receipt(raw_receipt: Mapping[str, Any]) -> BindingReceipt:
    try:
        copied = _json_copy(dict(raw_receipt), "binding receipt")
        checks = tuple(
            BindingCheck(
                id=check["id"],
                result=check["result"],
                detail=check.get("detail", ""),
            )
            for check in copied["checks"]
        )
        receipt = BindingReceipt(
            schema=copied["schema"],
            result=copied["result"],
            source_bundle_sha256=copied["source_bundle_sha256"],
            checks=checks,
            receipt_sha256=copied["receipt_sha256"],
            failed_check=copied.get("failed_check"),
            failure_detail=copied.get("failure_detail"),
        )
    except (KeyError, TypeError, WorkloadNormalizationError) as exc:
        raise BindingVerificationError(f"invalid binding receipt: {exc}") from exc
    if receipt.result not in {"PASS", "FAIL"}:
        raise BindingVerificationError("binding receipt result must be PASS or FAIL")
    if not _SHA256_PATTERN.fullmatch(receipt.receipt_sha256):
        raise BindingVerificationError("binding receipt has an invalid receipt_sha256")
    if receipt.receipt_sha256 != _receipt_sha256(receipt.as_dict()):
        raise BindingVerificationError("binding receipt receipt_sha256 is inconsistent")
    return receipt


def _receipt_sha256(receipt: Mapping[str, Any]) -> str:
    """Hash the receipt body without exposing core canonicalization helpers."""
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return _canonical_sha256(body)


def verify_binding(evidence_bundle: Mapping[str, Any]) -> BindingReceipt:
    """Verify a bundle without importing the replay implementation directly."""
    if not isinstance(evidence_bundle, Mapping):
        raise BindingVerificationError("evidence_bundle must be a mapping")
    try:
        bundle = _json_copy(dict(evidence_bundle), "evidence bundle")
    except WorkloadNormalizationError as exc:
        raise BindingVerificationError(str(exc)) from exc
    try:
        raw_receipt = _verify_evidence_bundle(bundle)
    except Exception as exc:  # noqa: BLE001 - stable public error boundary
        raise BindingVerificationError(f"binding verifier failed: {exc}") from exc
    return _binding_receipt(raw_receipt)


class _DefaultAdapter:
    def __init__(self, external_adapter: ExternalWorkloadAdapter) -> None:
        self._external_adapter = external_adapter
        self.consumer_type = _consumer_type(
            getattr(external_adapter, "consumer_type", None)
        )
        if not callable(getattr(external_adapter, "normalize", None)):
            raise AdapterContractError("adapter must provide callable normalize(external_input)")
        self._expected_normalization: dict[str, Any] | None = None

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]:
        if self._expected_normalization is not None:
            return copy.deepcopy(self._expected_normalization)
        callback_error_type: str | None = None
        try:
            normalized = self._external_adapter.normalize(copy.deepcopy(dict(external_input)))
        except Exception as exc:  # noqa: BLE001 - stable public error boundary
            callback_error_type = type(exc).__name__
        if callback_error_type is not None:
            raise WorkloadNormalizationError(
                f"adapter normalize() failed ({callback_error_type})"
            ) from None
        workload = _validated_normalized_workload(
            normalized,
            expected_consumer_type=self.consumer_type,
        )
        return workload

    def lock_normalization(self, workload: Mapping[str, Any]) -> None:
        self._expected_normalization = copy.deepcopy(dict(workload))

    def task(self, workload_sha256: str) -> dict[str, Any]:
        return _task(self.consumer_type, workload_sha256)

    def fixture(self, workload_sha256: str) -> dict[str, Any]:
        task = self.task(workload_sha256)
        authorization = _AuthorizationRecord(
            authorization_id=f"auth:trcp-sdk:{self.consumer_type}",
            subject_id=f"external-consumer:{self.consumer_type}",
            asset_id=task["asset_id"],
            valid_from=900,
            valid_until=2000,
            allowed_activity_classes=(task["activity_class"],),
            authority_source="trcp-adapter-sdk",
            proof_reference="fixture://trcp-adapter-sdk/authorization",
        )
        scope = _ScopeEnvelope(
            scope_id=f"scope:trcp-sdk:{self.consumer_type}",
            authorization_id=authorization.authorization_id,
            allowed_targets=(task["asset_id"],),
            allowed_actions=(task["action"],),
        )
        primary = _MockProvider(
            "provider:trcp-sdk-primary",
            "synthetic-adapter-v0.1",
            "COMPLETED",
            provider_metadata={"workload_sha256": workload_sha256},
        )
        return {
            "authorization": authorization,
            "scope": scope,
            "task": task,
            "primary": primary,
        }


class _DefaultAdapterWithReplay(_DefaultAdapter):
    def replay_execution(self, workload: Mapping[str, Any]) -> Any:
        hook = getattr(self._external_adapter, "replay_execution")
        try:
            result = hook(copy.deepcopy(dict(workload)))
            return _json_copy(result, "execution replay result")
        except Exception as exc:  # noqa: BLE001 - isolated execution boundary
            raise RuntimeError(type(exc).__name__) from exc


def _execution_replay_result(raw: Mapping[str, Any]) -> ExecutionReplayResult:
    status = raw.get("status")
    if status in {"NOT_RUN", "UNSUPPORTED", "PASS"}:
        public_status = status
    elif status == "FAIL" and "error" in raw:
        public_status = "ERROR"
    elif status == "FAIL":
        public_status = "MISMATCH"
    else:
        raise BindingVerificationError(f"unknown execution replay status: {status!r}")
    return ExecutionReplayResult(
        status=public_status,
        matches_binding_result=raw.get("matches_binding_result"),
        result=copy.deepcopy(raw.get("result")),
        error=raw.get("error"),
    )


def run_external_workload(
    adapter: ExternalWorkloadAdapter,
    external_input: Mapping[str, Any],
    *,
    execution_replay: bool = False,
) -> ExternalWorkloadResult:
    """Run an external adapter and return deterministic, typed TRCP results."""
    if not isinstance(external_input, Mapping):
        raise AdapterContractError("external_input must be a mapping")
    canonical_input = _json_copy(dict(external_input), "external_input")
    has_replay_hook = callable(getattr(adapter, "replay_execution", None))
    wrapped: _DefaultAdapter
    if has_replay_hook:
        wrapped = _DefaultAdapterWithReplay(adapter)
    else:
        wrapped = _DefaultAdapter(adapter)

    # Snapshot exactly one public-boundary normalization.  The internal v0.4
    # compatibility pipeline asks twice; both calls receive this immutable
    # snapshot so normalization is never mislabeled as execution replay.
    first_normalization = wrapped.normalize(canonical_input)
    wrapped.lock_normalization(first_normalization)
    try:
        raw = _run_external_consumer(
            wrapped,
            canonical_input,
            execution_replay=execution_replay,
        )
    except TRCPAdapterError:
        raise
    except Exception as exc:  # noqa: BLE001 - stable public error boundary
        raise TRCPAdapterError(f"TRCP external workload run failed: {exc}") from exc

    receipt = verify_binding(raw["bundle"])
    if receipt.as_dict() != raw["receipt"]:
        raise BindingVerificationError("binding verifier returned inconsistent receipts")
    return ExternalWorkloadResult(
        normalized_workload=copy.deepcopy(raw["workload_body"]),
        workload_evidence=copy.deepcopy(raw["workload_evidence"]),
        evidence_bundle=copy.deepcopy(raw["bundle"]),
        binding_receipt=receipt,
        execution_replay=_execution_replay_result(raw["execution_replay"]),
        report=copy.deepcopy(raw["report"]),
        _workload_sha256=str(raw["workload_evidence"]["workload_sha256"]),
        _bundle_sha256=str(raw["bundle"]["bundle_sha256"]),
    )


__all__ = [
    "ADAPTER_SDK_VERSION",
    "NORMALIZED_WORKLOAD_SCHEMA",
    "AdapterContractError",
    "BindingCheck",
    "BindingReceipt",
    "BindingVerificationError",
    "ExecutionReplayHook",
    "ExecutionReplayResult",
    "ExternalWorkloadAdapter",
    "ExternalWorkloadResult",
    "TRCPAdapterError",
    "WorkloadNormalizationError",
    "build_workload_evidence",
    "normalize_workload",
    "run_external_workload",
    "verify_binding",
]
