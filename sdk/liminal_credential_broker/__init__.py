"""Bound credential-use governance for LiminalOS.

The model-facing broker never reads or returns secret material. A host creates
it with an immutable set of exact credential bindings and a trusted-adapter
token before exposing the broker to model-facing code. Authorization uses a
host-controlled clock and produces short-lived, one-time opaque leases.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import canonical_sha256

AUTH_SCHEMA = "liminal-credential-authorization-receipt-v0.1"
BINDING_SCHEMA = "liminal-credential-binding-v0.1"
ZERO_SHA256 = "0" * 64
MAX_LEASE_TTL_SECONDS = 30

_AUTHORITY_ITEMS = (
    ("mode", "credential_use_governance_only"),
    ("immutable_host_bindings", True),
    ("credential_capability_admission", True),
    ("opaque_lease_issue", True),
    ("lease_consumption", True),
    ("trusted_clock", True),
    ("atomic_state_transitions", True),
    ("secret_provider_access", False),
    ("secret_material_export", False),
    ("network_authority", False),
    ("process_authority", False),
    ("deployment", False),
    ("automatic_release", False),
)
# Public read-only metadata for inspection. Trust decisions never hash/compare
# this object; documents receive a fresh plain dict from _authority_doc().
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_HEADER = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")

_AUTH_RECEIPT_KEYS = frozenset({
    "schema", "authorization_id", "call_id", "subject_id", "credential_ref_sha256",
    "request_sha256", "binding_sha256", "capability_receipt_sha256", "decision",
    "reason_codes", "lease_id", "lease_expires_at_unix", "request_declared_at_unix",
    "decision_at_unix", "authority", "receipt_sha256",
})

Clock = Callable[[], int]


class CredentialError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _authority_doc() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


@dataclass(frozen=True)
class CredentialBinding:
    binding_id: str
    credential_id: str
    purpose: str
    protocol: str
    domain: str
    port: int
    injection_target: str
    binding_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": BINDING_SCHEMA,
            "binding_id": self.binding_id,
            "credential_id": self.credential_id,
            "purpose": self.purpose,
            "protocol": self.protocol,
            "domain": self.domain,
            "port": self.port,
            "injection_target": self.injection_target,
            "authority": _authority_doc(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "binding_sha256": self.binding_sha256}

    @classmethod
    def build(
        cls,
        *,
        binding_id: str,
        credential_id: str,
        purpose: str,
        protocol: str,
        domain: str,
        port: int,
        injection_target: str,
    ) -> "CredentialBinding":
        item = cls(
            binding_id=_ident(binding_id, "binding_id"),
            credential_id=_ident(credential_id, "credential_id"),
            purpose=_ident(purpose, "purpose"),
            protocol=_protocol(protocol),
            domain=_domain(domain),
            port=_port(port),
            injection_target=_target(injection_target),
            binding_sha256="",
        )
        return cls(**{**item.__dict__, "binding_sha256": canonical_sha256(item.body())})

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "CredentialBinding":
        raw = dict(document)
        expected = {
            "schema", "binding_id", "credential_id", "purpose", "protocol", "domain",
            "port", "injection_target", "authority", "binding_sha256",
        }
        if set(raw) != expected or raw.get("schema") != BINDING_SCHEMA or raw.get("authority") != _authority_doc():
            raise CredentialError("binding_schema_mismatch")
        item = cls(
            binding_id=_ident(raw["binding_id"], "binding_id"),
            credential_id=_ident(raw["credential_id"], "credential_id"),
            purpose=_ident(raw["purpose"], "purpose"),
            protocol=_protocol(raw["protocol"]),
            domain=_domain(raw["domain"]),
            port=_port(raw["port"]),
            injection_target=_target(raw["injection_target"]),
            binding_sha256=_sha(raw["binding_sha256"], "binding_sha256"),
        )
        if canonical_sha256(item.body()) != item.binding_sha256:
            raise CredentialError("binding_digest_mismatch")
        return item


@dataclass(frozen=True)
class CredentialUseRequest:
    call_id: str
    subject_id: str
    policy_sha256: str
    credential_id: str
    purpose: str
    protocol: str
    domain: str
    port: int
    injection_target: str
    at_unix: int

    def normalized(self) -> "CredentialUseRequest":
        return CredentialUseRequest(
            call_id=_ident(self.call_id, "call_id"),
            subject_id=_ident(self.subject_id, "subject_id"),
            policy_sha256=_sha(self.policy_sha256, "policy_sha256"),
            credential_id=_ident(self.credential_id, "credential_id"),
            purpose=_ident(self.purpose, "purpose"),
            protocol=_protocol(self.protocol),
            domain=_domain(self.domain),
            port=_port(self.port),
            injection_target=_target(self.injection_target),
            at_unix=_time(self.at_unix),
        )

    def body(self) -> dict[str, Any]:
        r = self.normalized()
        # at_unix is requester-declared evidence only. It is never used for TTL,
        # capability expiry, revocation, or lease-consumption decisions.
        return {
            "call_id": r.call_id,
            "subject_id": r.subject_id,
            "policy_sha256": r.policy_sha256,
            "credential_id": r.credential_id,
            "purpose": r.purpose,
            "protocol": r.protocol,
            "domain": r.domain,
            "port": r.port,
            "injection_target": r.injection_target,
            "at_unix": r.at_unix,
        }


@dataclass(frozen=True)
class CredentialAuthorizationReceipt:
    authorization_id: str
    call_id: str
    subject_id: str
    credential_ref_sha256: str
    request_sha256: str
    binding_sha256: str
    capability_receipt_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    lease_id: str | None
    lease_expires_at_unix: int | None
    request_declared_at_unix: int
    decision_at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": AUTH_SCHEMA,
            "authorization_id": self.authorization_id,
            "call_id": self.call_id,
            "subject_id": self.subject_id,
            "credential_ref_sha256": self.credential_ref_sha256,
            "request_sha256": self.request_sha256,
            "binding_sha256": self.binding_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "lease_id": self.lease_id,
            "lease_expires_at_unix": self.lease_expires_at_unix,
            "request_declared_at_unix": self.request_declared_at_unix,
            "decision_at_unix": self.decision_at_unix,
            "authority": _authority_doc(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _Lease:
    lease_id: str
    request: CredentialUseRequest
    binding: CredentialBinding
    capability_id: str
    authorization_receipt_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    consumed: bool = False


@dataclass(frozen=True)
class TrustedCredentialReference:
    lease_id: str
    credential_id: str
    purpose: str
    protocol: str
    domain: str
    port: int
    injection_target: str
    authorization_receipt_sha256: str
    binding_sha256: str


class CredentialBroker:
    """Host-configured, then model-facing credential-use broker.

    Bindings and the adapter authentication secret are supplied once at
    construction. There is intentionally no public post-construction binding
    registration method.
    """

    def __init__(
        self,
        *,
        capability_broker: CapabilityBroker,
        bindings: Sequence[Mapping[str, Any]],
        adapter_token: str,
        lease_ttl_seconds: int = 10,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(capability_broker, CapabilityBroker):
            raise CredentialError("invalid_capability_broker")
        if isinstance(lease_ttl_seconds, bool) or not isinstance(lease_ttl_seconds, int) or not 1 <= lease_ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise CredentialError("invalid_lease_ttl")
        if not isinstance(adapter_token, str) or len(adapter_token) < 32 or "\x00" in adapter_token:
            raise CredentialError("invalid_adapter_token")
        if clock is not None and not callable(clock):
            raise CredentialError("invalid_clock")

        binding_map: dict[str, CredentialBinding] = {}
        for document in bindings:
            binding = CredentialBinding.from_document(document)
            existing = binding_map.get(binding.binding_id)
            if existing and existing.binding_sha256 != binding.binding_sha256:
                raise CredentialError("duplicate_binding_id")
            binding_map[binding.binding_id] = binding
        if not binding_map:
            raise CredentialError("bindings_required")

        self._capability_broker = capability_broker
        self._bindings = MappingProxyType(binding_map)
        self._adapter_token_sha256 = hashlib.sha256(adapter_token.encode("utf-8")).hexdigest()
        self._lease_ttl_seconds = lease_ttl_seconds
        self._clock = clock or (lambda: int(time.time()))
        self._lock = threading.RLock()
        self._leases: dict[str, _Lease] = {}
        self._seen_call_ids: set[str] = set()
        self._receipts: list[CredentialAuthorizationReceipt] = []
        self._contained = False
        self._containment_evidence_sha256 = ZERO_SHA256

    def enter_containment(self, incident_receipt_sha256: str) -> None:
        with self._lock:
            self._containment_evidence_sha256 = _sha(incident_receipt_sha256, "incident_receipt_sha256")
            self._contained = True

    def exit_containment(self, human_release_receipt_sha256: str) -> None:
        with self._lock:
            self._containment_evidence_sha256 = _sha(human_release_receipt_sha256, "human_release_receipt_sha256")
            self._contained = False

    def authorize(self, request: CredentialUseRequest) -> dict[str, Any]:
        req = request.normalized()
        request_sha = canonical_sha256(req.body())
        credential_ref_sha = canonical_sha256({"credential_id": req.credential_id})
        with self._lock:
            now = self._now()
            if req.call_id in self._seen_call_ids:
                return self._receipt(
                    req=req, decision_at=now, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                    binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                    decision="BLOCK", reasons=("replayed_call_id",), lease_id=None, lease_expires=None,
                )
            self._seen_call_ids.add(req.call_id)
            if self._contained:
                return self._receipt(
                    req=req, decision_at=now, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                    binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                    decision="BLOCK", reasons=("containment_active",), lease_id=None, lease_expires=None,
                )
            binding = self._match_binding(req)
            if binding is None:
                return self._receipt(
                    req=req, decision_at=now, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                    binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                    decision="BLOCK", reasons=("binding_mismatch",), lease_id=None, lease_expires=None,
                )
            capability = self._capability_broker.authorize(
                subject_id=req.subject_id,
                capability_type="credential.access",
                policy_sha256=req.policy_sha256,
                requested_scope={"credential_ids": [req.credential_id], "purpose": req.purpose},
                action={
                    "operation": "credential_use",
                    "call_id": req.call_id,
                    "request_sha256": request_sha,
                    "binding_sha256": binding.binding_sha256,
                    "destination_sha256": canonical_sha256({
                        "protocol": req.protocol, "domain": req.domain, "port": req.port,
                    }),
                    "injection_target_sha256": canonical_sha256(req.injection_target),
                },
                at_unix=now,
            )
            if capability["decision"] != "ALLOW":
                return self._receipt(
                    req=req, decision_at=now, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                    binding_sha=binding.binding_sha256,
                    capability_receipt_sha=capability["receipt_sha256"], decision="BLOCK",
                    reasons=tuple(capability["reason_codes"]), lease_id=None, lease_expires=None,
                )
            lease_id = f"credential-lease:{len(self._leases)+1}:{canonical_sha256({'call_id': req.call_id, 'binding': binding.binding_sha256, 'decision_at': now})[:16]}"
            expires = now + self._lease_ttl_seconds
            authorization = self._receipt(
                req=req, decision_at=now, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                binding_sha=binding.binding_sha256,
                capability_receipt_sha=capability["receipt_sha256"], decision="ALLOW",
                reasons=("binding_match", "credential_capability_admitted", "opaque_lease_issued"),
                lease_id=lease_id, lease_expires=expires,
            )
            self._leases[lease_id] = _Lease(
                lease_id=lease_id, request=req, binding=binding,
                capability_id=capability["capability_id"],
                authorization_receipt_sha256=authorization["receipt_sha256"],
                issued_at_unix=now, expires_at_unix=expires,
            )
            return authorization

    def consume_for_trusted_adapter(self, lease_id: str, *, adapter_token: str) -> TrustedCredentialReference:
        # Authenticate the host adapter before examining or mutating lease state.
        if not self._adapter_authenticated(adapter_token):
            raise CredentialError("trusted_adapter_auth_failed")
        with self._lock:
            now = self._now()
            if self._contained:
                raise CredentialError("containment_active")
            lease = self._leases.get(lease_id)
            if lease is None:
                raise CredentialError("unknown_lease")
            if lease.consumed:
                raise CredentialError("lease_replayed")
            if now >= lease.expires_at_unix:
                raise CredentialError("lease_expired")
            if now < lease.issued_at_unix:
                raise CredentialError("trusted_clock_regression")
            if not self._capability_still_active(lease.capability_id, now):
                raise CredentialError("source_capability_inactive")
            # Consume before secret resolution. Provider/sink failures never reactivate it.
            lease.consumed = True
            return TrustedCredentialReference(
                lease_id=lease.lease_id,
                credential_id=lease.request.credential_id,
                purpose=lease.request.purpose,
                protocol=lease.request.protocol,
                domain=lease.request.domain,
                port=lease.request.port,
                injection_target=lease.request.injection_target,
                authorization_receipt_sha256=lease.authorization_receipt_sha256,
                binding_sha256=lease.binding.binding_sha256,
            )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(r.as_document() for r in self._receipts)

    def _match_binding(self, req: CredentialUseRequest) -> CredentialBinding | None:
        matches = [
            binding for binding in self._bindings.values()
            if binding.credential_id == req.credential_id
            and binding.purpose == req.purpose
            and binding.protocol == req.protocol
            and binding.domain == req.domain
            and binding.port == req.port
            and binding.injection_target == req.injection_target
        ]
        return matches[0] if len(matches) == 1 else None

    def _capability_still_active(self, capability_id: str, at_unix: int) -> bool:
        state = self._capability_broker.state_document()
        for item in state["capabilities"]:
            if item["capability_id"] == capability_id:
                return item["status"] == "active" and at_unix < item["expires_at_unix"]
        return False

    def _adapter_authenticated(self, adapter_token: Any) -> bool:
        if not isinstance(adapter_token, str):
            return False
        candidate = hashlib.sha256(adapter_token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate, self._adapter_token_sha256)

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CredentialError("trusted_clock_invalid")
        return value

    def _receipt(
        self,
        *,
        req: CredentialUseRequest,
        decision_at: int,
        credential_ref_sha: str,
        request_sha: str,
        binding_sha: str,
        capability_receipt_sha: str,
        decision: str,
        reasons: tuple[str, ...],
        lease_id: str | None,
        lease_expires: int | None,
    ) -> dict[str, Any]:
        base = CredentialAuthorizationReceipt(
            authorization_id=f"credential-auth:{len(self._receipts)+1}",
            call_id=req.call_id,
            subject_id=req.subject_id,
            credential_ref_sha256=credential_ref_sha,
            request_sha256=request_sha,
            binding_sha256=binding_sha,
            capability_receipt_sha256=capability_receipt_sha,
            decision=decision,
            reason_codes=tuple(sorted(set(reasons))),
            lease_id=lease_id,
            lease_expires_at_unix=lease_expires,
            request_declared_at_unix=req.at_unix,
            decision_at_unix=decision_at,
            receipt_sha256="",
        )
        receipt = CredentialAuthorizationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw_full = dict(document)
    if set(raw_full) != _AUTH_RECEIPT_KEYS:
        raise CredentialError("authorization_schema_mismatch")
    raw = dict(raw_full)
    receipt_sha = raw.pop("receipt_sha256")
    if raw.get("schema") != AUTH_SCHEMA or raw.get("authority") != _authority_doc():
        raise CredentialError("authorization_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise CredentialError("authorization_digest_mismatch")
    return raw_full


def _ident(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENT.fullmatch(value):
        raise CredentialError(f"invalid_{name}")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise CredentialError(f"invalid_{name}")
    return value


def _protocol(value: Any) -> str:
    if not isinstance(value, str) or value.lower() != "https":
        raise CredentialError("credential_destination_requires_https")
    return "https"


def _domain(value: Any) -> str:
    if not isinstance(value, str):
        raise CredentialError("invalid_domain")
    domain = value.lower()
    if "*" in domain or not _DOMAIN.fullmatch(domain):
        raise CredentialError("invalid_domain")
    return domain


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise CredentialError("invalid_port")
    return value


def _target(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("http_header:"):
        raise CredentialError("invalid_injection_target")
    header = value.split(":", 1)[1]
    if not _HEADER.fullmatch(header):
        raise CredentialError("invalid_injection_target")
    return "http_header:" + header.lower()


def _time(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CredentialError("invalid_time")
    return value


__all__ = [
    "AUTHORITY", "AUTH_SCHEMA", "BINDING_SCHEMA", "CredentialAuthorizationReceipt",
    "CredentialBinding", "CredentialBroker", "CredentialError", "CredentialUseRequest",
    "MAX_LEASE_TTL_SECONDS", "TrustedCredentialReference", "verify_authorization_receipt",
]
