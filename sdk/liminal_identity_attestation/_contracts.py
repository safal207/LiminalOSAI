"""Provider-neutral identity and KMS attestation contracts for v1.1."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

IDENTITY_ASSERTION_SCHEMA = "liminal-idp-identity-assertion-v1.1"
KMS_ATTESTATION_SCHEMA = "liminal-kms-key-attestation-v1.1"
IDENTITY_BUNDLE_SCHEMA = "liminal-governance-identity-bundle-v1.1"
IDENTITY_TRUST_STORE_SCHEMA = "liminal-identity-trust-store-v1.1"
IDENTITY_VERIFICATION_SCHEMA = "liminal-identity-verification-receipt-v1.1"
ALGORITHM = "ed25519-openssl-v1"
IDP_DOMAIN_SEPARATOR = b"LIMINAL-IDP-IDENTITY-ASSERTION-V1.1\x00"
KMS_DOMAIN_SEPARATOR = b"LIMINAL-KMS-KEY-ATTESTATION-V1.1\x00"
MAX_ASSERTION_TTL_SECONDS = 3600
MAX_ATTESTATION_TTL_SECONDS = 3600
DEFAULT_CLOCK_SKEW_SECONDS = 120

IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
URI_RE = re.compile(r"^https://[^\s\x00]{1,512}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

AUTHORITY = {
    "mode": "identity_and_key_attestation_only",
    "live_user_authentication": False,
    "external_idp_session_ownership": False,
    "bearer_token_storage": False,
    "cookie_storage": False,
    "private_key_storage": False,
    "kms_invocation_ownership": False,
    "identity_inference": False,
    "role_inference": False,
    "authorization_inference": False,
    "automatic_write_authorization": False,
    "github_execution_ownership": False,
    "automatic_merge": False,
    "automatic_deployment": False,
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "hidden_memory_write": False,
}


class AttestationError(ValueError):
    """Raised when an identity attestation violates v1.1."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError) as exc:
        raise AttestationError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def exact_keys(
    raw: Mapping[str, Any], required: set[str], optional: set[str], name: str
) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        raise AttestationError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise AttestationError(f"{name} contains unsupported keys: {', '.join(extra)}")


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise AttestationError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationError(f"{name} must be a non-empty string")
    if "\x00" in value:
        raise AttestationError(f"{name} must not contain NUL")
    return value


def identifier(value: Any, name: str) -> str:
    item = string(value, name)
    if not IDENT_RE.fullmatch(item):
        raise AttestationError(f"{name} contains unsupported characters")
    return item


def issuer_uri(value: Any, name: str) -> str:
    item = string(value, name)
    if not URI_RE.fullmatch(item):
        raise AttestationError(f"{name} must be an https issuer URI")
    return item.rstrip("/")


def repository(value: Any, name: str) -> str:
    item = string(value, name)
    if not REPO_RE.fullmatch(item):
        raise AttestationError(f"{name} must use owner/name form")
    return item


def sha256(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not SHA256_RE.fullmatch(item):
        raise AttestationError(f"{name} must be a 64-character SHA-256")
    return item


def unix_time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AttestationError(f"{name} must be a non-negative integer Unix timestamp")
    return value


def nullable_unix_time(value: Any, name: str) -> int | None:
    return None if value is None else unix_time(value, name)


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise AttestationError(f"{name} must be a boolean")
    return value


def positive_int(value: Any, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AttestationError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise AttestationError(f"{name} exceeds maximum {maximum}")
    return value


def normalized_identifiers(value: Any, name: str) -> tuple[str, ...]:
    result = tuple(
        identifier(item, f"{name}[{index}]")
        for index, item in enumerate(array(value, name))
    )
    if len(result) != len(set(result)):
        raise AttestationError(f"{name} contains duplicates")
    return tuple(sorted(result))


def normalized_repositories(value: Any, name: str) -> tuple[str, ...]:
    result = tuple(
        repository(item, f"{name}[{index}]")
        for index, item in enumerate(array(value, name))
    )
    if len(result) != len(set(result)):
        raise AttestationError(f"{name} contains duplicates")
    return tuple(sorted(result))


def _validate_window(
    issued: int, not_before: int, expires: int, maximum: int, name: str
) -> None:
    if not (issued <= not_before < expires):
        raise AttestationError(
            f"{name} time order must be issued_at <= not_before < expires_at"
        )
    if expires - issued > maximum:
        raise AttestationError(f"{name} TTL exceeds maximum {maximum}")


@dataclass(frozen=True)
class IdentityAssertionClaims:
    assertion_id: str
    issuer: str
    key_id: str
    subject_id: str
    tenant_id: str
    organization_id: str
    audience: str
    repository_full_name: str
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    auth_methods: tuple[str, ...]
    service_account: bool
    session_sha256: str
    capsule_nonce: str
    issued_at_unix: int
    not_before_unix: int
    expires_at_unix: int
    identity_status: str

    def payload(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "organization_id": self.organization_id,
            "audience": self.audience,
            "repository_full_name": self.repository_full_name,
            "roles": list(self.roles),
            "groups": list(self.groups),
            "auth_methods": list(self.auth_methods),
            "service_account": self.service_account,
            "session_sha256": self.session_sha256,
            "capsule_nonce": self.capsule_nonce,
            "issued_at_unix": self.issued_at_unix,
            "not_before_unix": self.not_before_unix,
            "expires_at_unix": self.expires_at_unix,
            "identity_status": self.identity_status,
            "authority": AUTHORITY,
        }

    @classmethod
    def from_value(cls, value: Any) -> "IdentityAssertionClaims":
        raw = mapping(value, "identity_assertion.claims")
        exact_keys(
            raw,
            {
                "assertion_id", "issuer", "key_id", "subject_id", "tenant_id",
                "organization_id", "audience", "repository_full_name", "roles",
                "groups", "auth_methods", "service_account", "session_sha256",
                "capsule_nonce", "issued_at_unix", "not_before_unix",
                "expires_at_unix", "identity_status", "authority",
            },
            set(),
            "identity_assertion.claims",
        )
        if raw["authority"] != AUTHORITY:
            raise AttestationError("identity_assertion.claims.authority must remain fixed")
        issued = unix_time(raw["issued_at_unix"], "identity_assertion.claims.issued_at_unix")
        not_before = unix_time(raw["not_before_unix"], "identity_assertion.claims.not_before_unix")
        expires = unix_time(raw["expires_at_unix"], "identity_assertion.claims.expires_at_unix")
        _validate_window(
            issued, not_before, expires, MAX_ASSERTION_TTL_SECONDS,
            "identity assertion",
        )
        status = identifier(raw["identity_status"], "identity_assertion.claims.identity_status")
        if status != "active":
            raise AttestationError("identity assertion identity_status must be active")
        return cls(
            assertion_id=identifier(raw["assertion_id"], "identity_assertion.claims.assertion_id"),
            issuer=issuer_uri(raw["issuer"], "identity_assertion.claims.issuer"),
            key_id=identifier(raw["key_id"], "identity_assertion.claims.key_id"),
            subject_id=identifier(raw["subject_id"], "identity_assertion.claims.subject_id"),
            tenant_id=identifier(raw["tenant_id"], "identity_assertion.claims.tenant_id"),
            organization_id=identifier(raw["organization_id"], "identity_assertion.claims.organization_id"),
            audience=identifier(raw["audience"], "identity_assertion.claims.audience"),
            repository_full_name=repository(
                raw["repository_full_name"],
                "identity_assertion.claims.repository_full_name",
            ),
            roles=normalized_identifiers(raw["roles"], "identity_assertion.claims.roles"),
            groups=normalized_identifiers(raw["groups"], "identity_assertion.claims.groups"),
            auth_methods=normalized_identifiers(
                raw["auth_methods"], "identity_assertion.claims.auth_methods"
            ),
            service_account=boolean(
                raw["service_account"], "identity_assertion.claims.service_account"
            ),
            session_sha256=sha256(
                raw["session_sha256"], "identity_assertion.claims.session_sha256"
            ),
            capsule_nonce=identifier(
                raw["capsule_nonce"], "identity_assertion.claims.capsule_nonce"
            ),
            issued_at_unix=issued,
            not_before_unix=not_before,
            expires_at_unix=expires,
            identity_status=status,
        )


@dataclass(frozen=True)
class SignedIdentityAssertion:
    claims: IdentityAssertionClaims
    payload_sha256: str
    signature_b64url: str

    @property
    def signed_message(self) -> bytes:
        return IDP_DOMAIN_SEPARATOR + canonical_json(self.claims.payload()).encode("utf-8")

    def as_document(self) -> dict[str, Any]:
        return {
            "schema_version": IDENTITY_ASSERTION_SCHEMA,
            "claims": self.claims.payload(),
            "payload_sha256": self.payload_sha256,
            "signature_b64url": self.signature_b64url,
        }

    @property
    def assertion_sha256(self) -> str:
        return canonical_sha256(self.as_document())

    @classmethod
    def from_document(cls, value: Any) -> "SignedIdentityAssertion":
        raw = mapping(value, "identity_assertion")
        exact_keys(
            raw,
            {"schema_version", "claims", "payload_sha256", "signature_b64url"},
            set(),
            "identity_assertion",
        )
        if raw["schema_version"] != IDENTITY_ASSERTION_SCHEMA:
            raise AttestationError(
                f"identity_assertion.schema_version must be {IDENTITY_ASSERTION_SCHEMA}"
            )
        claims = IdentityAssertionClaims.from_value(raw["claims"])
        payload_hash = sha256(raw["payload_sha256"], "identity_assertion.payload_sha256")
        if payload_hash != canonical_sha256(claims.payload()):
            raise AttestationError("identity_assertion.payload_sha256 mismatch")
        signature = string(raw["signature_b64url"], "identity_assertion.signature_b64url")
        if not B64URL_RE.fullmatch(signature):
            raise AttestationError(
                "identity_assertion.signature_b64url is not unpadded base64url"
            )
        return cls(claims=claims, payload_sha256=payload_hash, signature_b64url=signature)


@dataclass(frozen=True)
class KmsOperationClaims:
    receipt_id: str
    provider_id: str
    attestation_key_id: str
    tenant_id: str
    subject_id: str
    key_resource_id: str
    key_version_id: str
    governance_key_id: str
    algorithm: str
    public_key_sha256: str
    operation: str
    hardware_protection: str
    key_status: str
    repository_full_name: str
    capsule_nonce: str
    capsule_payload_sha256: str
    capsule_signature_sha256: str
    issued_at_unix: int
    not_before_unix: int
    expires_at_unix: int

    def payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "provider_id": self.provider_id,
            "attestation_key_id": self.attestation_key_id,
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "key_resource_id": self.key_resource_id,
            "key_version_id": self.key_version_id,
            "governance_key_id": self.governance_key_id,
            "algorithm": self.algorithm,
            "public_key_sha256": self.public_key_sha256,
            "operation": self.operation,
            "hardware_protection": self.hardware_protection,
            "key_status": self.key_status,
            "repository_full_name": self.repository_full_name,
            "capsule_nonce": self.capsule_nonce,
            "capsule_payload_sha256": self.capsule_payload_sha256,
            "capsule_signature_sha256": self.capsule_signature_sha256,
            "issued_at_unix": self.issued_at_unix,
            "not_before_unix": self.not_before_unix,
            "expires_at_unix": self.expires_at_unix,
            "authority": AUTHORITY,
        }

    @classmethod
    def from_value(cls, value: Any) -> "KmsOperationClaims":
        raw = mapping(value, "kms_attestation.claims")
        exact_keys(
            raw,
            {
                "receipt_id", "provider_id", "attestation_key_id", "tenant_id",
                "subject_id", "key_resource_id", "key_version_id",
                "governance_key_id", "algorithm", "public_key_sha256",
                "operation", "hardware_protection", "key_status",
                "repository_full_name", "capsule_nonce",
                "capsule_payload_sha256", "capsule_signature_sha256",
                "issued_at_unix", "not_before_unix", "expires_at_unix",
                "authority",
            },
            set(),
            "kms_attestation.claims",
        )
        if raw["authority"] != AUTHORITY:
            raise AttestationError("kms_attestation.claims.authority must remain fixed")
        issued = unix_time(raw["issued_at_unix"], "kms_attestation.claims.issued_at_unix")
        not_before = unix_time(raw["not_before_unix"], "kms_attestation.claims.not_before_unix")
        expires = unix_time(raw["expires_at_unix"], "kms_attestation.claims.expires_at_unix")
        _validate_window(
            issued, not_before, expires, MAX_ATTESTATION_TTL_SECONDS,
            "KMS attestation",
        )
        operation = identifier(raw["operation"], "kms_attestation.claims.operation")
        if operation != "sign":
            raise AttestationError("KMS attestation operation must be sign")
        algorithm = identifier(raw["algorithm"], "kms_attestation.claims.algorithm")
        if algorithm != ALGORITHM:
            raise AttestationError(f"KMS attestation algorithm must be {ALGORITHM}")
        hardware = identifier(
            raw["hardware_protection"], "kms_attestation.claims.hardware_protection"
        )
        if hardware not in {"hsm", "cloud-hsm", "software", "unknown"}:
            raise AttestationError("unsupported KMS hardware_protection")
        status = identifier(raw["key_status"], "kms_attestation.claims.key_status")
        if status != "active":
            raise AttestationError("KMS attestation key_status must be active")
        return cls(
            receipt_id=identifier(raw["receipt_id"], "kms_attestation.claims.receipt_id"),
            provider_id=identifier(raw["provider_id"], "kms_attestation.claims.provider_id"),
            attestation_key_id=identifier(
                raw["attestation_key_id"], "kms_attestation.claims.attestation_key_id"
            ),
            tenant_id=identifier(raw["tenant_id"], "kms_attestation.claims.tenant_id"),
            subject_id=identifier(raw["subject_id"], "kms_attestation.claims.subject_id"),
            key_resource_id=identifier(
                raw["key_resource_id"], "kms_attestation.claims.key_resource_id"
            ),
            key_version_id=identifier(
                raw["key_version_id"], "kms_attestation.claims.key_version_id"
            ),
            governance_key_id=identifier(
                raw["governance_key_id"], "kms_attestation.claims.governance_key_id"
            ),
            algorithm=algorithm,
            public_key_sha256=sha256(
                raw["public_key_sha256"], "kms_attestation.claims.public_key_sha256"
            ),
            operation=operation,
            hardware_protection=hardware,
            key_status=status,
            repository_full_name=repository(
                raw["repository_full_name"],
                "kms_attestation.claims.repository_full_name",
            ),
            capsule_nonce=identifier(
                raw["capsule_nonce"], "kms_attestation.claims.capsule_nonce"
            ),
            capsule_payload_sha256=sha256(
                raw["capsule_payload_sha256"],
                "kms_attestation.claims.capsule_payload_sha256",
            ),
            capsule_signature_sha256=sha256(
                raw["capsule_signature_sha256"],
                "kms_attestation.claims.capsule_signature_sha256",
            ),
            issued_at_unix=issued,
            not_before_unix=not_before,
            expires_at_unix=expires,
        )


@dataclass(frozen=True)
class SignedKmsAttestation:
    claims: KmsOperationClaims
    payload_sha256: str
    signature_b64url: str

    @property
    def signed_message(self) -> bytes:
        return KMS_DOMAIN_SEPARATOR + canonical_json(self.claims.payload()).encode("utf-8")

    def as_document(self) -> dict[str, Any]:
        return {
            "schema_version": KMS_ATTESTATION_SCHEMA,
            "claims": self.claims.payload(),
            "payload_sha256": self.payload_sha256,
            "signature_b64url": self.signature_b64url,
        }

    @property
    def attestation_sha256(self) -> str:
        return canonical_sha256(self.as_document())

    @classmethod
    def from_document(cls, value: Any) -> "SignedKmsAttestation":
        raw = mapping(value, "kms_attestation")
        exact_keys(
            raw,
            {"schema_version", "claims", "payload_sha256", "signature_b64url"},
            set(),
            "kms_attestation",
        )
        if raw["schema_version"] != KMS_ATTESTATION_SCHEMA:
            raise AttestationError(
                f"kms_attestation.schema_version must be {KMS_ATTESTATION_SCHEMA}"
            )
        claims = KmsOperationClaims.from_value(raw["claims"])
        payload_hash = sha256(raw["payload_sha256"], "kms_attestation.payload_sha256")
        if payload_hash != canonical_sha256(claims.payload()):
            raise AttestationError("kms_attestation.payload_sha256 mismatch")
        signature = string(raw["signature_b64url"], "kms_attestation.signature_b64url")
        if not B64URL_RE.fullmatch(signature):
            raise AttestationError(
                "kms_attestation.signature_b64url is not unpadded base64url"
            )
        return cls(claims=claims, payload_sha256=payload_hash, signature_b64url=signature)


@dataclass(frozen=True)
class TrustedIdpKey:
    issuer: str
    key_id: str
    public_key_pem: str
    public_key_sha256: str
    valid_from_unix: int
    valid_until_unix: int
    revoked_at_unix: int | None
    allowed_audiences: tuple[str, ...]
    allowed_tenants: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "public_key_sha256": self.public_key_sha256,
            "valid_from_unix": self.valid_from_unix,
            "valid_until_unix": self.valid_until_unix,
            "revoked_at_unix": self.revoked_at_unix,
            "allowed_audiences": list(self.allowed_audiences),
            "allowed_tenants": list(self.allowed_tenants),
        }

    @classmethod
    def from_value(cls, value: Any, *, index: int) -> "TrustedIdpKey":
        name = f"identity_trust_store.idp_keys[{index}]"
        raw = mapping(value, name)
        exact_keys(
            raw,
            {
                "issuer", "key_id", "public_key_pem", "public_key_sha256",
                "valid_from_unix", "valid_until_unix", "revoked_at_unix",
                "allowed_audiences", "allowed_tenants",
            },
            set(),
            name,
        )
        public_key = string(raw["public_key_pem"], f"{name}.public_key_pem")
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----\n"):
            raise AttestationError(f"{name}.public_key_pem must be a PEM public key")
        public_hash = sha256(raw["public_key_sha256"], f"{name}.public_key_sha256")
        if hashlib.sha256(public_key.encode("utf-8")).hexdigest() != public_hash:
            raise AttestationError(f"{name}.public_key_sha256 mismatch")
        valid_from = unix_time(raw["valid_from_unix"], f"{name}.valid_from_unix")
        valid_until = unix_time(raw["valid_until_unix"], f"{name}.valid_until_unix")
        if valid_until <= valid_from:
            raise AttestationError(f"{name}.valid_until_unix must be after valid_from")
        return cls(
            issuer=issuer_uri(raw["issuer"], f"{name}.issuer"),
            key_id=identifier(raw["key_id"], f"{name}.key_id"),
            public_key_pem=public_key,
            public_key_sha256=public_hash,
            valid_from_unix=valid_from,
            valid_until_unix=valid_until,
            revoked_at_unix=nullable_unix_time(raw["revoked_at_unix"], f"{name}.revoked_at_unix"),
            allowed_audiences=normalized_identifiers(
                raw["allowed_audiences"], f"{name}.allowed_audiences"
            ),
            allowed_tenants=normalized_identifiers(
                raw["allowed_tenants"], f"{name}.allowed_tenants"
            ),
        )


@dataclass(frozen=True)
class TrustedKmsAttestationKey:
    provider_id: str
    attestation_key_id: str
    public_key_pem: str
    public_key_sha256: str
    valid_from_unix: int
    valid_until_unix: int
    revoked_at_unix: int | None
    allowed_tenants: tuple[str, ...]
    allowed_repositories: tuple[str, ...]
    allowed_hardware_protection: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "attestation_key_id": self.attestation_key_id,
            "public_key_pem": self.public_key_pem,
            "public_key_sha256": self.public_key_sha256,
            "valid_from_unix": self.valid_from_unix,
            "valid_until_unix": self.valid_until_unix,
            "revoked_at_unix": self.revoked_at_unix,
            "allowed_tenants": list(self.allowed_tenants),
            "allowed_repositories": list(self.allowed_repositories),
            "allowed_hardware_protection": list(self.allowed_hardware_protection),
        }

    @classmethod
    def from_value(cls, value: Any, *, index: int) -> "TrustedKmsAttestationKey":
        name = f"identity_trust_store.kms_keys[{index}]"
        raw = mapping(value, name)
        exact_keys(
            raw,
            {
                "provider_id", "attestation_key_id", "public_key_pem",
                "public_key_sha256", "valid_from_unix", "valid_until_unix",
                "revoked_at_unix", "allowed_tenants", "allowed_repositories",
                "allowed_hardware_protection",
            },
            set(),
            name,
        )
        public_key = string(raw["public_key_pem"], f"{name}.public_key_pem")
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----\n"):
            raise AttestationError(f"{name}.public_key_pem must be a PEM public key")
        public_hash = sha256(raw["public_key_sha256"], f"{name}.public_key_sha256")
        if hashlib.sha256(public_key.encode("utf-8")).hexdigest() != public_hash:
            raise AttestationError(f"{name}.public_key_sha256 mismatch")
        valid_from = unix_time(raw["valid_from_unix"], f"{name}.valid_from_unix")
        valid_until = unix_time(raw["valid_until_unix"], f"{name}.valid_until_unix")
        if valid_until <= valid_from:
            raise AttestationError(f"{name}.valid_until_unix must be after valid_from")
        hardware = normalized_identifiers(
            raw["allowed_hardware_protection"],
            f"{name}.allowed_hardware_protection",
        )
        if not set(hardware).issubset({"hsm", "cloud-hsm", "software", "unknown"}):
            raise AttestationError(f"{name}.allowed_hardware_protection is invalid")
        return cls(
            provider_id=identifier(raw["provider_id"], f"{name}.provider_id"),
            attestation_key_id=identifier(
                raw["attestation_key_id"], f"{name}.attestation_key_id"
            ),
            public_key_pem=public_key,
            public_key_sha256=public_hash,
            valid_from_unix=valid_from,
            valid_until_unix=valid_until,
            revoked_at_unix=nullable_unix_time(raw["revoked_at_unix"], f"{name}.revoked_at_unix"),
            allowed_tenants=normalized_identifiers(raw["allowed_tenants"], f"{name}.allowed_tenants"),
            allowed_repositories=normalized_repositories(
                raw["allowed_repositories"], f"{name}.allowed_repositories"
            ),
            allowed_hardware_protection=hardware,
        )


@dataclass(frozen=True)
class IdentityTrustStore:
    trust_store_id: str
    max_assertion_ttl_seconds: int
    max_attestation_ttl_seconds: int
    max_clock_skew_seconds: int
    required_roles: tuple[str, ...]
    require_mfa: bool
    idp_keys: tuple[TrustedIdpKey, ...]
    kms_keys: tuple[TrustedKmsAttestationKey, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": IDENTITY_TRUST_STORE_SCHEMA,
            "trust_store_id": self.trust_store_id,
            "max_assertion_ttl_seconds": self.max_assertion_ttl_seconds,
            "max_attestation_ttl_seconds": self.max_attestation_ttl_seconds,
            "max_clock_skew_seconds": self.max_clock_skew_seconds,
            "required_roles": list(self.required_roles),
            "require_mfa": self.require_mfa,
            "idp_keys": [key.payload() for key in self.idp_keys],
            "kms_keys": [key.payload() for key in self.kms_keys],
            "authority": AUTHORITY,
        }

    @property
    def trust_store_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "trust_store_sha256": self.trust_store_sha256}

    @property
    def idp_key_map(self) -> dict[tuple[str, str], TrustedIdpKey]:
        return {(key.issuer, key.key_id): key for key in self.idp_keys}

    @property
    def kms_key_map(self) -> dict[tuple[str, str], TrustedKmsAttestationKey]:
        return {
            (key.provider_id, key.attestation_key_id): key for key in self.kms_keys
        }

    @classmethod
    def build(
        cls,
        *,
        trust_store_id: str,
        idp_keys: list[dict[str, Any]],
        kms_keys: list[dict[str, Any]],
        required_roles: list[str] | None = None,
        require_mfa: bool = True,
        max_assertion_ttl_seconds: int = MAX_ASSERTION_TTL_SECONDS,
        max_attestation_ttl_seconds: int = MAX_ATTESTATION_TTL_SECONDS,
        max_clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> "IdentityTrustStore":
        skew = unix_time(max_clock_skew_seconds, "max_clock_skew_seconds")
        if skew > 3600:
            raise AttestationError("max_clock_skew_seconds exceeds 3600")
        store = cls(
            trust_store_id=identifier(trust_store_id, "trust_store_id"),
            max_assertion_ttl_seconds=positive_int(
                max_assertion_ttl_seconds,
                "max_assertion_ttl_seconds",
                maximum=MAX_ASSERTION_TTL_SECONDS,
            ),
            max_attestation_ttl_seconds=positive_int(
                max_attestation_ttl_seconds,
                "max_attestation_ttl_seconds",
                maximum=MAX_ATTESTATION_TTL_SECONDS,
            ),
            max_clock_skew_seconds=skew,
            required_roles=normalized_identifiers(
                required_roles or [], "required_roles"
            ),
            require_mfa=boolean(require_mfa, "require_mfa"),
            idp_keys=tuple(
                TrustedIdpKey.from_value(item, index=index)
                for index, item in enumerate(idp_keys)
            ),
            kms_keys=tuple(
                TrustedKmsAttestationKey.from_value(item, index=index)
                for index, item in enumerate(kms_keys)
            ),
        )
        if not store.idp_keys or not store.kms_keys:
            raise AttestationError("identity trust store requires IdP and KMS keys")
        return cls.from_document(store.as_document())

    @classmethod
    def from_document(cls, value: Any) -> "IdentityTrustStore":
        raw = mapping(value, "identity_trust_store")
        exact_keys(
            raw,
            {
                "schema_version", "trust_store_id",
                "max_assertion_ttl_seconds", "max_attestation_ttl_seconds",
                "max_clock_skew_seconds", "required_roles", "require_mfa",
                "idp_keys", "kms_keys", "authority", "trust_store_sha256",
            },
            set(),
            "identity_trust_store",
        )
        if raw["schema_version"] != IDENTITY_TRUST_STORE_SCHEMA:
            raise AttestationError(
                f"identity_trust_store.schema_version must be {IDENTITY_TRUST_STORE_SCHEMA}"
            )
        if raw["authority"] != AUTHORITY:
            raise AttestationError("identity_trust_store.authority must remain fixed")
        skew = unix_time(raw["max_clock_skew_seconds"], "identity_trust_store.max_clock_skew_seconds")
        if skew > 3600:
            raise AttestationError("identity_trust_store.max_clock_skew_seconds exceeds 3600")
        idp_keys = tuple(
            TrustedIdpKey.from_value(item, index=index)
            for index, item in enumerate(array(raw["idp_keys"], "identity_trust_store.idp_keys"))
        )
        kms_keys = tuple(
            TrustedKmsAttestationKey.from_value(item, index=index)
            for index, item in enumerate(array(raw["kms_keys"], "identity_trust_store.kms_keys"))
        )
        if not idp_keys or not kms_keys:
            raise AttestationError("identity trust store requires IdP and KMS keys")
        if len({(key.issuer, key.key_id) for key in idp_keys}) != len(idp_keys):
            raise AttestationError("identity trust store contains duplicate IdP keys")
        if len({(key.provider_id, key.attestation_key_id) for key in kms_keys}) != len(kms_keys):
            raise AttestationError("identity trust store contains duplicate KMS keys")
        store = cls(
            trust_store_id=identifier(raw["trust_store_id"], "identity_trust_store.trust_store_id"),
            max_assertion_ttl_seconds=positive_int(
                raw["max_assertion_ttl_seconds"],
                "identity_trust_store.max_assertion_ttl_seconds",
                maximum=MAX_ASSERTION_TTL_SECONDS,
            ),
            max_attestation_ttl_seconds=positive_int(
                raw["max_attestation_ttl_seconds"],
                "identity_trust_store.max_attestation_ttl_seconds",
                maximum=MAX_ATTESTATION_TTL_SECONDS,
            ),
            max_clock_skew_seconds=skew,
            required_roles=normalized_identifiers(
                raw["required_roles"], "identity_trust_store.required_roles"
            ),
            require_mfa=boolean(raw["require_mfa"], "identity_trust_store.require_mfa"),
            idp_keys=idp_keys,
            kms_keys=kms_keys,
        )
        if raw["trust_store_sha256"] != store.trust_store_sha256:
            raise AttestationError("identity_trust_store.trust_store_sha256 mismatch")
        return store


@dataclass(frozen=True)
class IdentityAttestationBundle:
    identity_assertion: SignedIdentityAssertion
    kms_attestation: SignedKmsAttestation
    capsule_sha256: str
    capsule_payload_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": IDENTITY_BUNDLE_SCHEMA,
            "identity_assertion": self.identity_assertion.as_document(),
            "kms_attestation": self.kms_attestation.as_document(),
            "capsule_sha256": self.capsule_sha256,
            "capsule_payload_sha256": self.capsule_payload_sha256,
            "authority": AUTHORITY,
        }

    @property
    def bundle_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "bundle_sha256": self.bundle_sha256}

    @classmethod
    def build(
        cls,
        *,
        identity_assertion: SignedIdentityAssertion,
        kms_attestation: SignedKmsAttestation,
        capsule_sha256: str,
        capsule_payload_sha256: str,
    ) -> "IdentityAttestationBundle":
        return cls.from_document(
            cls(
                identity_assertion=identity_assertion,
                kms_attestation=kms_attestation,
                capsule_sha256=sha256(capsule_sha256, "capsule_sha256"),
                capsule_payload_sha256=sha256(
                    capsule_payload_sha256, "capsule_payload_sha256"
                ),
            ).as_document()
        )

    @classmethod
    def from_document(cls, value: Any) -> "IdentityAttestationBundle":
        raw = mapping(value, "identity_bundle")
        exact_keys(
            raw,
            {
                "schema_version", "identity_assertion", "kms_attestation",
                "capsule_sha256", "capsule_payload_sha256", "authority",
                "bundle_sha256",
            },
            set(),
            "identity_bundle",
        )
        if raw["schema_version"] != IDENTITY_BUNDLE_SCHEMA:
            raise AttestationError(
                f"identity_bundle.schema_version must be {IDENTITY_BUNDLE_SCHEMA}"
            )
        if raw["authority"] != AUTHORITY:
            raise AttestationError("identity_bundle.authority must remain fixed")
        bundle = cls(
            identity_assertion=SignedIdentityAssertion.from_document(
                raw["identity_assertion"]
            ),
            kms_attestation=SignedKmsAttestation.from_document(
                raw["kms_attestation"]
            ),
            capsule_sha256=sha256(raw["capsule_sha256"], "identity_bundle.capsule_sha256"),
            capsule_payload_sha256=sha256(
                raw["capsule_payload_sha256"],
                "identity_bundle.capsule_payload_sha256",
            ),
        )
        if raw["bundle_sha256"] != bundle.bundle_sha256:
            raise AttestationError("identity_bundle.bundle_sha256 mismatch")
        return bundle
