"""Digest-bound file mutation governance for LiminalOS.

The model-facing broker never mutates the filesystem. It admits an exact replace
operation against immutable host-provisioned logical roots, then issues a short-
lived one-time lease for a trusted POSIX adapter.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import canonical_sha256

AUTH_SCHEMA = "liminal-file-mutation-authorization-receipt-v0.1"
BINDING_SCHEMA = "liminal-file-root-binding-v0.1"
ZERO_SHA256 = "0" * 64
MAX_LEASE_TTL_SECONDS = 30
MAX_CONTENT_BYTES = 8 * 1024 * 1024

_AUTHORITY_ITEMS = (
    ("mode", "file_mutation_governance_only"),
    ("binding_registration", False),
    ("filesystem_access", False),
    ("file_create", False),
    ("file_delete", False),
    ("file_rename", False),
    ("existing_file_replace_admission", True),
    ("opaque_lease_issue", True),
    ("trusted_adapter_authentication", True),
    ("network_authority", False),
    ("process_authority", False),
    ("deployment", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,95}$")


class FileMutationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _authority_document() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


def _ident(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value:
        raise FileMutationError(f"invalid_{name}")
    if not _IDENT.fullmatch(value):
        raise FileMutationError(f"invalid_{name}")
    return value


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise FileMutationError(f"invalid_{name}")
    return value


def _positive_int(value: int, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise FileMutationError(f"invalid_{name}")
    if maximum is not None and value > maximum:
        raise FileMutationError(f"invalid_{name}")
    return value


def normalize_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise FileMutationError("invalid_relative_path")
    if value.startswith("/") or "\\" in value or "//" in value:
        raise FileMutationError("invalid_relative_path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise FileMutationError("invalid_relative_path")
    if len(parts) > 64 or len(value.encode("utf-8")) > 1024:
        raise FileMutationError("invalid_relative_path")
    for part in parts:
        if len(part.encode("utf-8")) > 255:
            raise FileMutationError("invalid_relative_path")
    return "/".join(parts)


def _adapter_digest(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise FileMutationError("invalid_adapter_token")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FileRootBinding:
    root_id: str
    logical_prefix: str
    max_content_bytes: int
    binding_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": BINDING_SCHEMA,
            "root_id": self.root_id,
            "logical_prefix": self.logical_prefix,
            "max_content_bytes": self.max_content_bytes,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "binding_sha256": self.binding_sha256}

    @classmethod
    def build(cls, *, root_id: str, logical_prefix: str, max_content_bytes: int = MAX_CONTENT_BYTES) -> "FileRootBinding":
        root_id = _ident(root_id, "root_id")
        if not isinstance(logical_prefix, str) or not _PREFIX.fullmatch(logical_prefix):
            raise FileMutationError("invalid_logical_prefix")
        max_content_bytes = _positive_int(max_content_bytes, "max_content_bytes", maximum=MAX_CONTENT_BYTES)
        item = cls(root_id=root_id, logical_prefix=logical_prefix, max_content_bytes=max_content_bytes, binding_sha256="")
        return cls(**{**item.__dict__, "binding_sha256": canonical_sha256(item.body())})

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "FileRootBinding":
        raw = dict(document)
        expected = {"schema", "root_id", "logical_prefix", "max_content_bytes", "authority", "binding_sha256"}
        if set(raw) != expected or raw.get("schema") != BINDING_SCHEMA or raw.get("authority") != _authority_document():
            raise FileMutationError("binding_schema_mismatch")
        item = cls.build(
            root_id=raw["root_id"],
            logical_prefix=raw["logical_prefix"],
            max_content_bytes=raw["max_content_bytes"],
        )
        if item.binding_sha256 != _sha(raw["binding_sha256"], "binding_sha256"):
            raise FileMutationError("binding_digest_mismatch")
        return item


@dataclass(frozen=True)
class FileMutationRequest:
    call_id: str
    subject_id: str
    policy_sha256: str
    root_id: str
    relative_path: str
    expected_before_sha256: str
    desired_content_sha256: str
    content_length: int

    def normalized(self) -> "FileMutationRequest":
        return FileMutationRequest(
            call_id=_ident(self.call_id, "call_id"),
            subject_id=_ident(self.subject_id, "subject_id"),
            policy_sha256=_sha(self.policy_sha256, "policy_sha256"),
            root_id=_ident(self.root_id, "root_id"),
            relative_path=normalize_relative_path(self.relative_path),
            expected_before_sha256=_sha(self.expected_before_sha256, "expected_before_sha256"),
            desired_content_sha256=_sha(self.desired_content_sha256, "desired_content_sha256"),
            content_length=_positive_int(self.content_length, "content_length", maximum=MAX_CONTENT_BYTES),
        )

    def body(self) -> dict[str, Any]:
        r = self.normalized()
        return {
            "call_id": r.call_id,
            "subject_id": r.subject_id,
            "policy_sha256": r.policy_sha256,
            "root_id": r.root_id,
            "relative_path_sha256": canonical_sha256(r.relative_path),
            "expected_before_sha256": r.expected_before_sha256,
            "desired_content_sha256": r.desired_content_sha256,
            "content_length": r.content_length,
            "operation": "replace_existing_regular_file",
        }


@dataclass(frozen=True)
class FileMutationAuthorizationReceipt:
    authorization_id: str
    call_id: str
    subject_id: str
    request_sha256: str
    binding_sha256: str
    logical_path_sha256: str
    expected_before_sha256: str
    desired_content_sha256: str
    content_length: int
    capability_receipt_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    lease_id: str | None
    lease_expires_at_unix: int | None
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": AUTH_SCHEMA,
            "authorization_id": self.authorization_id,
            "call_id": self.call_id,
            "subject_id": self.subject_id,
            "request_sha256": self.request_sha256,
            "binding_sha256": self.binding_sha256,
            "logical_path_sha256": self.logical_path_sha256,
            "expected_before_sha256": self.expected_before_sha256,
            "desired_content_sha256": self.desired_content_sha256,
            "content_length": self.content_length,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "lease_id": self.lease_id,
            "lease_expires_at_unix": self.lease_expires_at_unix,
            "at_unix": self.at_unix,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _Lease:
    lease_id: str
    request: FileMutationRequest
    binding: FileRootBinding
    logical_path: str
    capability_id: str
    capability_receipt_sha256: str
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


@dataclass(frozen=True)
class TrustedFileMutationReference:
    lease_id: str
    root_id: str
    relative_path: str
    expected_before_sha256: str
    desired_content_sha256: str
    content_length: int
    binding_sha256: str
    authorization_receipt_sha256: str


Clock = Callable[[], int]


class FileMutationBroker:
    def __init__(
        self,
        *,
        capability_broker: CapabilityBroker,
        bindings: Iterable[Mapping[str, Any]],
        adapter_token_sha256: str,
        lease_ttl_seconds: int = 10,
        clock: Clock | None = None,
    ) -> None:
        self.capability_broker = capability_broker
        self.lease_ttl_seconds = _positive_int(lease_ttl_seconds, "lease_ttl_seconds", maximum=MAX_LEASE_TTL_SECONDS)
        self._adapter_token_sha256 = _sha(adapter_token_sha256, "adapter_token_sha256")
        self._clock = clock or (lambda: int(time.time()))
        parsed = [FileRootBinding.from_document(item) for item in bindings]
        if not parsed:
            raise FileMutationError("bindings_required")
        by_id: dict[str, FileRootBinding] = {}
        for item in parsed:
            if item.root_id in by_id:
                raise FileMutationError("duplicate_root_id")
            by_id[item.root_id] = item
        self._bindings = MappingProxyType(by_id)
        self._leases: dict[str, _Lease] = {}
        self._seen_call_ids: set[str] = set()
        self._receipts: list[FileMutationAuthorizationReceipt] = []
        self._contained = False
        self._lock = threading.RLock()

    def enter_containment(self, incident_receipt_sha256: str) -> None:
        _sha(incident_receipt_sha256, "incident_receipt_sha256")
        with self._lock:
            self._contained = True

    def exit_containment(self, human_release_receipt_sha256: str) -> None:
        _sha(human_release_receipt_sha256, "human_release_receipt_sha256")
        with self._lock:
            self._contained = False

    def authorize(self, request: FileMutationRequest) -> dict[str, Any]:
        req = request.normalized()
        with self._lock:
            now = self._now()
            request_sha = canonical_sha256(req.body())
            binding = self._bindings.get(req.root_id)
            logical_path = f"{binding.logical_prefix}/{req.relative_path}" if binding else ""
            logical_path_sha = canonical_sha256(logical_path) if logical_path else ZERO_SHA256
            if req.call_id in self._seen_call_ids:
                return self._receipt(req, request_sha, ZERO_SHA256, logical_path_sha, ZERO_SHA256, "BLOCK", ("replayed_call_id",), None, None, now)
            self._seen_call_ids.add(req.call_id)
            if self._contained:
                return self._receipt(req, request_sha, ZERO_SHA256, logical_path_sha, ZERO_SHA256, "BLOCK", ("containment_active",), None, None, now)
            if binding is None:
                return self._receipt(req, request_sha, ZERO_SHA256, ZERO_SHA256, ZERO_SHA256, "BLOCK", ("unknown_root_binding",), None, None, now)
            if req.content_length > binding.max_content_bytes:
                return self._receipt(req, request_sha, binding.binding_sha256, logical_path_sha, ZERO_SHA256, "BLOCK", ("content_length_exceeds_binding",), None, None, now)
            capability = self.capability_broker.authorize(
                subject_id=req.subject_id,
                capability_type="filesystem.write_outside_workspace",
                policy_sha256=req.policy_sha256,
                requested_scope={"paths": [logical_path]},
                action={
                    "operation": "replace_existing_regular_file",
                    "call_id": req.call_id,
                    "request_sha256": request_sha,
                    "binding_sha256": binding.binding_sha256,
                    "logical_path_sha256": logical_path_sha,
                    "expected_before_sha256": req.expected_before_sha256,
                    "desired_content_sha256": req.desired_content_sha256,
                    "content_length": req.content_length,
                },
                at_unix=now,
            )
            if capability["decision"] != "ALLOW":
                return self._receipt(
                    req, request_sha, binding.binding_sha256, logical_path_sha,
                    capability["receipt_sha256"], "BLOCK", tuple(capability["reason_codes"]), None, None, now,
                )
            lease_id = f"file-lease:{len(self._leases)+1}:{canonical_sha256({'call': req.call_id, 'path': logical_path_sha})[:16]}"
            expires = now + self.lease_ttl_seconds
            receipt = self._receipt(
                req, request_sha, binding.binding_sha256, logical_path_sha,
                capability["receipt_sha256"], "ALLOW",
                ("root_binding_match", "file_capability_admitted", "opaque_lease_issued"),
                lease_id, expires, now,
            )
            self._leases[lease_id] = _Lease(
                lease_id=lease_id,
                request=req,
                binding=binding,
                logical_path=logical_path,
                capability_id=capability["capability_id"],
                capability_receipt_sha256=capability["receipt_sha256"],
                authorization_receipt_sha256=receipt["receipt_sha256"],
                issued_at_unix=now,
                expires_at_unix=expires,
            )
            return receipt

    def consume_for_trusted_adapter(self, lease_id: str, *, adapter_token: str) -> TrustedFileMutationReference:
        with self._lock:
            supplied = _adapter_digest(adapter_token)
            if not hmac.compare_digest(supplied, self._adapter_token_sha256):
                raise FileMutationError("adapter_auth_failed")
            now = self._now()
            if self._contained:
                raise FileMutationError("containment_active")
            lease = self._leases.get(lease_id)
            if lease is None:
                raise FileMutationError("unknown_lease")
            if lease.consumed:
                raise FileMutationError("lease_replayed")
            if now > lease.expires_at_unix:
                raise FileMutationError("lease_expired")
            if now < lease.issued_at_unix:
                raise FileMutationError("clock_regression")
            if not self._capability_still_active(lease.capability_id, now):
                raise FileMutationError("source_capability_inactive")
            lease.consumed = True
            return TrustedFileMutationReference(
                lease_id=lease.lease_id,
                root_id=lease.request.root_id,
                relative_path=lease.request.relative_path,
                expected_before_sha256=lease.request.expected_before_sha256,
                desired_content_sha256=lease.request.desired_content_sha256,
                content_length=lease.request.content_length,
                binding_sha256=lease.binding.binding_sha256,
                authorization_receipt_sha256=lease.authorization_receipt_sha256,
            )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(item.as_document() for item in self._receipts)

    def _capability_still_active(self, capability_id: str, now: int) -> bool:
        state = self.capability_broker.state_document()
        for item in state["capabilities"]:
            if item["capability_id"] == capability_id:
                return item["status"] == "active" and now < item["expires_at_unix"]
        return False

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise FileMutationError("invalid_host_clock")
        return value

    def _receipt(
        self,
        req: FileMutationRequest,
        request_sha: str,
        binding_sha: str,
        logical_path_sha: str,
        capability_receipt_sha: str,
        decision: str,
        reasons: tuple[str, ...],
        lease_id: str | None,
        lease_expires: int | None,
        now: int,
    ) -> dict[str, Any]:
        base = FileMutationAuthorizationReceipt(
            authorization_id=f"file-auth:{len(self._receipts)+1}",
            call_id=req.call_id,
            subject_id=req.subject_id,
            request_sha256=request_sha,
            binding_sha256=binding_sha,
            logical_path_sha256=logical_path_sha,
            expected_before_sha256=req.expected_before_sha256,
            desired_content_sha256=req.desired_content_sha256,
            content_length=req.content_length,
            capability_receipt_sha256=capability_receipt_sha,
            decision=decision,
            reason_codes=tuple(sorted(set(reasons))),
            lease_id=lease_id,
            lease_expires_at_unix=lease_expires,
            at_unix=now,
            receipt_sha256="",
        )
        receipt = FileMutationAuthorizationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    expected = {
        "schema", "authorization_id", "call_id", "subject_id", "request_sha256", "binding_sha256",
        "logical_path_sha256", "expected_before_sha256", "desired_content_sha256", "content_length",
        "capability_receipt_sha256", "decision", "reason_codes", "lease_id", "lease_expires_at_unix",
        "at_unix", "authority", "receipt_sha256",
    }
    if set(raw) != expected:
        raise FileMutationError("authorization_receipt_schema_mismatch")
    receipt_sha = raw.pop("receipt_sha256")
    if raw.get("schema") != AUTH_SCHEMA or raw.get("authority") != _authority_document():
        raise FileMutationError("authorization_receipt_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise FileMutationError("authorization_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY", "AUTH_SCHEMA", "BINDING_SCHEMA", "FileMutationAuthorizationReceipt",
    "FileMutationBroker", "FileMutationError", "FileMutationRequest", "FileRootBinding",
    "MAX_CONTENT_BYTES", "MAX_LEASE_TTL_SECONDS", "TrustedFileMutationReference",
    "normalize_relative_path", "verify_authorization_receipt",
]
