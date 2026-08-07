"""Trusted credential injection boundary for LiminalOS.

This adapter is intentionally outside the model-facing SDK. It is the only
component in this MVP that may receive raw credential material from a trusted
provider. The value is passed directly to a trusted sink and is never returned
in receipts or governance documents.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from sdk.liminal_credential_broker import CredentialBroker, CredentialError, CredentialUseRequest
from sdk.liminal_post_sandbox_contracts import canonical_sha256

INJECTION_SCHEMA = "liminal-credential-injection-receipt-v0.1"
ZERO_SHA256 = "0" * 64

_AUTHORITY_ITEMS = (
    ("mode", "trusted_secret_injection_boundary"),
    ("secret_provider_access", True),
    ("secret_injection", True),
    ("adapter_authentication", True),
    ("secret_material_export", False),
    ("raw_secret_receipt_storage", False),
    ("network_authority", False),
    ("credential_discovery", False),
    ("deployment", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_INJECTION_RECEIPT_KEYS = frozenset({
    "schema", "call_id", "subject_id", "credential_ref_sha256", "request_sha256",
    "binding_sha256", "capability_receipt_sha256", "authorization_receipt_sha256",
    "lease_ref_sha256", "destination_sha256", "injection_target_sha256", "decision",
    "injection_outcome", "result_sha256", "reason_codes", "at_unix", "authority",
    "receipt_sha256",
})


class CredentialInjectionError(RuntimeError):
    pass


def _authority_doc() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


@dataclass(frozen=True)
class InjectionContext:
    call_id: str
    subject_id: str
    purpose: str
    protocol: str
    domain: str
    port: int
    injection_target: str
    authorization_receipt_sha256: str
    binding_sha256: str


@dataclass(frozen=True)
class InjectionObservation:
    outcome: str
    result_sha256: str

    @classmethod
    def success(cls, safe_metadata: Mapping[str, Any]) -> "InjectionObservation":
        return cls(outcome="SUCCEEDED", result_sha256=canonical_sha256(dict(safe_metadata)))

    def validate(self) -> None:
        if self.outcome != "SUCCEEDED":
            raise CredentialInjectionError("invalid_observation_outcome")
        if not isinstance(self.result_sha256, str) or len(self.result_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.result_sha256):
            raise CredentialInjectionError("invalid_observation_digest")


@dataclass(frozen=True)
class CredentialInjectionReceipt:
    call_id: str
    subject_id: str
    credential_ref_sha256: str
    request_sha256: str
    binding_sha256: str
    capability_receipt_sha256: str
    authorization_receipt_sha256: str
    lease_ref_sha256: str
    destination_sha256: str
    injection_target_sha256: str
    decision: str
    injection_outcome: str
    result_sha256: str
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": INJECTION_SCHEMA,
            "call_id": self.call_id,
            "subject_id": self.subject_id,
            "credential_ref_sha256": self.credential_ref_sha256,
            "request_sha256": self.request_sha256,
            "binding_sha256": self.binding_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "authorization_receipt_sha256": self.authorization_receipt_sha256,
            "lease_ref_sha256": self.lease_ref_sha256,
            "destination_sha256": self.destination_sha256,
            "injection_target_sha256": self.injection_target_sha256,
            "decision": self.decision,
            "injection_outcome": self.injection_outcome,
            "result_sha256": self.result_sha256,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": _authority_doc(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


SecretProvider = Callable[[str], str]
InjectionSink = Callable[[InjectionContext, str], InjectionObservation]


class CredentialInjector:
    def __init__(
        self,
        *,
        broker: CredentialBroker,
        adapter_token: str,
        secret_provider: SecretProvider,
        sink: InjectionSink,
    ) -> None:
        if not isinstance(adapter_token, str) or len(adapter_token) < 32 or "\x00" in adapter_token:
            raise CredentialInjectionError("invalid_adapter_token")
        self.broker = broker
        self._adapter_token = adapter_token
        self.secret_provider = secret_provider
        self.sink = sink
        self._receipts: list[CredentialInjectionReceipt] = []

    def execute(self, request: CredentialUseRequest) -> dict[str, Any]:
        req = request.normalized()
        authorization = self.broker.authorize(req)
        common = {
            "call_id": req.call_id,
            "subject_id": req.subject_id,
            "credential_ref_sha256": authorization["credential_ref_sha256"],
            "request_sha256": authorization["request_sha256"],
            "binding_sha256": authorization["binding_sha256"],
            "capability_receipt_sha256": authorization["capability_receipt_sha256"],
            "authorization_receipt_sha256": authorization["receipt_sha256"],
            "destination_sha256": canonical_sha256({"protocol": req.protocol, "domain": req.domain, "port": req.port}),
            "injection_target_sha256": canonical_sha256(req.injection_target),
            "at_unix": authorization["decision_at_unix"],
        }
        if authorization["decision"] != "ALLOW":
            return self._receipt(
                **common,
                lease_ref_sha256=ZERO_SHA256,
                decision="BLOCK",
                injection_outcome="NOT_INJECTED",
                result_sha256=ZERO_SHA256,
                reason_codes=tuple(authorization["reason_codes"]),
            )

        lease_id = authorization["lease_id"]
        lease_ref_sha = canonical_sha256({"lease_id": lease_id})
        try:
            trusted = self.broker.consume_for_trusted_adapter(lease_id, adapter_token=self._adapter_token)
        except CredentialError as exc:
            return self._receipt(
                **common,
                lease_ref_sha256=lease_ref_sha,
                decision="BLOCK",
                injection_outcome="NOT_INJECTED",
                result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                reason_codes=(exc.code,),
            )

        context = InjectionContext(
            call_id=req.call_id,
            subject_id=req.subject_id,
            purpose=trusted.purpose,
            protocol=trusted.protocol,
            domain=trusted.domain,
            port=trusted.port,
            injection_target=trusted.injection_target,
            authorization_receipt_sha256=trusted.authorization_receipt_sha256,
            binding_sha256=trusted.binding_sha256,
        )

        secret: str | None = None
        try:
            secret = self.secret_provider(trusted.credential_id)
            if not isinstance(secret, str) or not secret:
                raise CredentialInjectionError("provider_returned_invalid_secret")
            observation = self.sink(context, secret)
            if not isinstance(observation, InjectionObservation):
                raise CredentialInjectionError("sink_must_return_observation")
            observation.validate()
        except Exception as exc:
            # Exception text is excluded because providers/sinks may include secret
            # material in error messages. The lease remains consumed.
            return self._receipt(
                **common,
                lease_ref_sha256=lease_ref_sha,
                decision="ALLOW",
                injection_outcome="FAILED",
                result_sha256=canonical_sha256({"error_type": type(exc).__name__}),
                reason_codes=("trusted_injection_failed",),
            )
        finally:
            # Python cannot guarantee physical memory zeroization. We still drop
            # the application-level reference immediately after the sink returns.
            secret = None

        return self._receipt(
            **common,
            lease_ref_sha256=lease_ref_sha,
            decision="ALLOW",
            injection_outcome="SUCCEEDED",
            result_sha256=observation.result_sha256,
            reason_codes=("credential_injected_at_trusted_boundary", "lease_consumed"),
        )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def _receipt(self, **kwargs: Any) -> dict[str, Any]:
        base = CredentialInjectionReceipt(receipt_sha256="", **kwargs)
        receipt = CredentialInjectionReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_injection_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw_full = dict(document)
    if set(raw_full) != _INJECTION_RECEIPT_KEYS:
        raise CredentialInjectionError("injection_schema_mismatch")
    raw = dict(raw_full)
    receipt_sha = raw.pop("receipt_sha256")
    if raw.get("schema") != INJECTION_SCHEMA or raw.get("authority") != _authority_doc():
        raise CredentialInjectionError("injection_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise CredentialInjectionError("injection_digest_mismatch")
    return raw_full


__all__ = [
    "AUTHORITY", "CredentialInjectionError", "CredentialInjectionReceipt", "CredentialInjector",
    "INJECTION_SCHEMA", "InjectionContext", "InjectionObservation", "verify_injection_receipt",
]
