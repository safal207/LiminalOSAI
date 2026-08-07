"""Bound credential-use governance for LiminalOS.

The model-facing broker never reads or returns secret material. It combines an
existing ``credential.access`` capability with a host-provisioned exact binding
for purpose, destination and injection target, then issues a short-lived opaque
lease. Secret resolution happens only in a trusted adapter outside this SDK.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import canonical_sha256

AUTH_SCHEMA = "liminal-credential-authorization-receipt-v0.1"
BINDING_SCHEMA = "liminal-credential-binding-v0.1"
ZERO_SHA256 = "0" * 64
MAX_LEASE_TTL_SECONDS = 30

AUTHORITY = {
    "mode": "credential_use_governance_only",
    "binding_registration": True,
    "credential_capability_admission": True,
    "opaque_lease_issue": True,
    "lease_consumption": True,
    "secret_provider_access": False,
    "secret_material_export": False,
    "network_authority": False,
    "process_authority": False,
    "deployment": False,
    "automatic_release": False,
}

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
_HEADER = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class CredentialError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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
            "authority": AUTHORITY,
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
        if set(raw) != expected or raw.get("schema") != BINDING_SCHEMA or raw.get("authority") != AUTHORITY:
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
    at_unix: int
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
            "at_unix": self.at_unix,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


@dataclass
class _Lease:
    lease_id: str
    request: CredentialUseRequest
    binding: CredentialBinding
    capability_id: str
    capability_receipt_sha256: str
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
    def __init__(self, *, capability_broker: CapabilityBroker, lease_ttl_seconds: int = 10) -> None:
        if isinstance(lease_ttl_seconds, bool) or not isinstance(lease_ttl_seconds, int) or not 1 <= lease_ttl_seconds <= MAX_LEASE_TTL_SECONDS:
            raise CredentialError("invalid_lease_ttl")
        self.capability_broker = capability_broker
        self.lease_ttl_seconds = lease_ttl_seconds
        self._bindings: dict[str, CredentialBinding] = {}
        self._leases: dict[str, _Lease] = {}
        self._seen_call_ids: set[str] = set()
        self._receipts: list[CredentialAuthorizationReceipt] = []
        self._contained = False
        self._containment_evidence_sha256 = ZERO_SHA256

    def register_binding(self, document: Mapping[str, Any]) -> dict[str, Any]:
        binding = CredentialBinding.from_document(document)
        existing = self._bindings.get(binding.binding_id)
        if existing and existing.binding_sha256 != binding.binding_sha256:
            raise CredentialError("duplicate_binding_id")
        self._bindings[binding.binding_id] = binding
        return binding.as_document()

    def enter_containment(self, incident_receipt_sha256: str) -> None:
        self._containment_evidence_sha256 = _sha(incident_receipt_sha256, "incident_receipt_sha256")
        self._contained = True

    def exit_containment(self, human_release_receipt_sha256: str) -> None:
        self._containment_evidence_sha256 = _sha(human_release_receipt_sha256, "human_release_receipt_sha256")
        self._contained = False

    def authorize(self, request: CredentialUseRequest) -> dict[str, Any]:
        req = request.normalized()
        request_sha = canonical_sha256(req.body())
        credential_ref_sha = canonical_sha256({"credential_id": req.credential_id})
        if req.call_id in self._seen_call_ids:
            return self._receipt(
                req=req, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                decision="BLOCK", reasons=("replayed_call_id",), lease_id=None, lease_expires=None,
            )
        self._seen_call_ids.add(req.call_id)
        if self._contained:
            return self._receipt(
                req=req, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                decision="BLOCK", reasons=("containment_active",), lease_id=None, lease_expires=None,
            )
        binding = self._match_binding(req)
        if binding is None:
            return self._receipt(
                req=req, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                binding_sha=ZERO_SHA256, capability_receipt_sha=ZERO_SHA256,
                decision="BLOCK", reasons=("binding_mismatch",), lease_id=None, lease_expires=None,
            )
        capability = self.capability_broker.authorize(
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
            at_unix=req.at_unix,
        )
        if capability["decision"] != "ALLOW":
            return self._receipt(
                req=req, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
                binding_sha=binding.binding_sha256,
                capability_receipt_sha=capability["receipt_sha256"], decision="BLOCK",
                reasons=tuple(capability["reason_codes"]), lease_id=None, lease_expires=None,
            )
        lease_id = f"credential-lease:{len(self._leases)+1}:{canonical_sha256({'call_id': req.call_id, 'binding': binding.binding_sha256})[:16]}"
        expires = req.at_unix + self.lease_ttl_seconds
        base = self._receipt(
            req=req, credential_ref_sha=credential_ref_sha, request_sha=request_sha,
            binding_sha=binding.binding_sha256,
            capability_receipt_sha=capability["receipt_sha256"], decision="ALLOW",
            reasons=("binding_match", "credential_capability_admitted", "opaque_lease_issued"),
            lease_id=lease_id, lease_expires=expires,
        )
        self._leases[lease_id] = _Lease(
            lease_id=lease_id, request=req, binding=binding,
            capability_id=capability["capability_id"], capability_receipt_sha256=capability["receipt_sha256"],
            authorization_receipt_sha256=base["receipt_sha256"], issued_at_unix=req.at_unix,
            expires_at_unix=expires,
        )
        return base

    def consume_for_trusted_adapter(self, lease_id: str, *, at_unix: int) -> TrustedCredentialReference:
        _time(at_unix)
        if self._contained:
            raise CredentialError("containment_active")
        lease = self._leases.get(lease_id)
        if lease is None:
            raise CredentialError("unknown_lease")
        if lease.consumed:
            raise CredentialError("lease_replayed")
        if at_unix > lease.expires_at_unix:
            raise CredentialError("lease_expired")
        if at_unix < lease.issued_at_unix:
            raise CredentialError("lease_time_regression")
        if not self._capability_still_active(lease.capability_id, at_unix):
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
        if len(matches) != 1:
            return None
        return matches[0]

    def _capability_still_active(self, capability_id: str, at_unix: int) -> bool:
        state = self.capability_broker.state_document()
        for item in state["capabilities"]:
            if item["capability_id"] == capability_id:
                return item["status"] == "active" and at_unix < item["expires_at_unix"]
        return False

    def _receipt(
        self,
        *,
        req: CredentialUseRequest,
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
            at_unix=req.at_unix,
            receipt_sha256="",
        )
        receipt = CredentialAuthorizationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_authorization_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    receipt_sha = raw.pop("receipt_sha256", None)
    if raw.get("schema") != AUTH_SCHEMA or raw.get("authority") != AUTHORITY:
        raise CredentialError("authorization_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise CredentialError("authorization_digest_mismatch")
    return dict(document)


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
