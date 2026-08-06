"""Contracts for Signed Governance Capsule v1.0."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

CAPSULE_SCHEMA = "chatgpt-signed-governance-capsule-v1.0"
TRUST_STORE_SCHEMA = "chatgpt-governance-trust-store-v1.0"
VERIFICATION_SCHEMA = "chatgpt-governance-capsule-verification-v1.0"
ALGORITHM = "ed25519-openssl-v1"
DOMAIN_SEPARATOR = b"LIMINAL-GOVERNANCE-CAPSULE-V1\x00"
MAX_CAPSULE_TTL_SECONDS = 86_400
DEFAULT_CLOCK_SKEW_SECONDS = 120

IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

AUTHORITY = {
    "mode": "signed_governance_capsule_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "identity_inference": False,
    "external_idp_verification": False,
    "private_key_storage": False,
    "key_custody": False,
    "github_execution_ownership": False,
    "automatic_write_authorization": False,
    "automatic_merge": False,
    "automatic_rollback": False,
    "delivery": False,
    "deployment": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class CapsuleError(ValueError):
    """Raised when a governance capsule violates v1.0."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError) as exc:
        raise CapsuleError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def exact_keys(
    raw: Mapping[str, Any], required: set[str], optional: set[str], name: str
) -> None:
    actual = set(raw)
    missing = sorted(required - actual)
    extra = sorted(actual - required - optional)
    if missing:
        raise CapsuleError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise CapsuleError(f"{name} contains unsupported keys: {', '.join(extra)}")


def mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CapsuleError(f"{name} must be a JSON object")
    return value


def array(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CapsuleError(f"{name} must be a JSON array")
    return value


def string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapsuleError(f"{name} must be a non-empty string")
    if "\x00" in value:
        raise CapsuleError(f"{name} must not contain NUL")
    return value


def identifier(value: Any, name: str) -> str:
    item = string(value, name)
    if not IDENT_RE.fullmatch(item):
        raise CapsuleError(f"{name} contains unsupported characters")
    return item


def repository(value: Any, name: str) -> str:
    item = string(value, name)
    if not REPO_RE.fullmatch(item):
        raise CapsuleError(f"{name} must use owner/name form")
    return item


def sha256(value: Any, name: str) -> str:
    item = string(value, name).lower()
    if not SHA256_RE.fullmatch(item):
        raise CapsuleError(f"{name} must be a 64-character SHA-256")
    return item


def unix_time(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CapsuleError(f"{name} must be a non-negative integer Unix timestamp")
    return value


def positive_int(value: Any, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CapsuleError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise CapsuleError(f"{name} exceeds maximum {maximum}")
    return value


def nullable_unix_time(value: Any, name: str) -> int | None:
    return None if value is None else unix_time(value, name)


def normalized_strings(value: Any, name: str, *, repositories: bool = False) -> tuple[str, ...]:
    items = array(value, name)
    normalized = tuple(
        repository(item, f"{name}[{index}]")
        if repositories
        else identifier(item, f"{name}[{index}]")
        for index, item in enumerate(items)
    )
    if len(normalized) != len(set(normalized)):
        raise CapsuleError(f"{name} contains duplicates")
    return normalized


@dataclass(frozen=True)
class GovernanceSubject:
    policy_id: str
    transaction_id: str
    repository_full_name: str
    policy_sha256: str
    snapshot_sha256: str
    plan_sha256: str
    approval_ledger_head_sha256: str
    transaction_journal_anchor_sha256: str
    engine_evidence_sha256: str
    decision: str
    approval_status: str

    def payload(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "transaction_id": self.transaction_id,
            "repository_full_name": self.repository_full_name,
            "policy_sha256": self.policy_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "plan_sha256": self.plan_sha256,
            "approval_ledger_head_sha256": self.approval_ledger_head_sha256,
            "transaction_journal_anchor_sha256": self.transaction_journal_anchor_sha256,
            "engine_evidence_sha256": self.engine_evidence_sha256,
            "decision": self.decision,
            "approval_status": self.approval_status,
        }

    @classmethod
    def from_value(cls, value: Any) -> "GovernanceSubject":
        raw = mapping(value, "capsule.claims.subject")
        exact_keys(
            raw,
            {
                "policy_id", "transaction_id", "repository_full_name",
                "policy_sha256", "snapshot_sha256", "plan_sha256",
                "approval_ledger_head_sha256",
                "transaction_journal_anchor_sha256",
                "engine_evidence_sha256", "decision", "approval_status",
            },
            set(),
            "capsule.claims.subject",
        )
        decision = string(raw["decision"], "capsule.claims.subject.decision")
        approval_status = string(
            raw["approval_status"], "capsule.claims.subject.approval_status"
        )
        if decision != "allow":
            raise CapsuleError("capsule subject decision must be allow")
        if approval_status != "ready":
            raise CapsuleError("capsule subject approval_status must be ready")
        subject = cls(
            policy_id=identifier(raw["policy_id"], "capsule.claims.subject.policy_id"),
            transaction_id=identifier(
                raw["transaction_id"], "capsule.claims.subject.transaction_id"
            ),
            repository_full_name=repository(
                raw["repository_full_name"],
                "capsule.claims.subject.repository_full_name",
            ),
            policy_sha256=sha256(
                raw["policy_sha256"], "capsule.claims.subject.policy_sha256"
            ),
            snapshot_sha256=sha256(
                raw["snapshot_sha256"], "capsule.claims.subject.snapshot_sha256"
            ),
            plan_sha256=sha256(
                raw["plan_sha256"], "capsule.claims.subject.plan_sha256"
            ),
            approval_ledger_head_sha256=sha256(
                raw["approval_ledger_head_sha256"],
                "capsule.claims.subject.approval_ledger_head_sha256",
            ),
            transaction_journal_anchor_sha256=sha256(
                raw["transaction_journal_anchor_sha256"],
                "capsule.claims.subject.transaction_journal_anchor_sha256",
            ),
            engine_evidence_sha256=sha256(
                raw["engine_evidence_sha256"],
                "capsule.claims.subject.engine_evidence_sha256",
            ),
            decision=decision,
            approval_status=approval_status,
        )
        evidence = {
            "policy_sha256": subject.policy_sha256,
            "snapshot_sha256": subject.snapshot_sha256,
            "plan_sha256": subject.plan_sha256,
            "approval_ledger_head_sha256": subject.approval_ledger_head_sha256,
            "transaction_journal_head_sha256": subject.transaction_journal_anchor_sha256,
        }
        if canonical_sha256(evidence) != subject.engine_evidence_sha256:
            raise CapsuleError("capsule subject engine_evidence_sha256 mismatch")
        return subject


@dataclass(frozen=True)
class CapsuleClaims:
    capsule_id: str
    issuer_id: str
    subject_id: str
    key_id: str
    algorithm: str
    audience: str
    issued_at_unix: int
    not_before_unix: int
    expires_at_unix: int
    nonce: str
    subject: GovernanceSubject

    def payload(self) -> dict[str, Any]:
        return {
            "capsule_id": self.capsule_id,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "audience": self.audience,
            "issued_at_unix": self.issued_at_unix,
            "not_before_unix": self.not_before_unix,
            "expires_at_unix": self.expires_at_unix,
            "nonce": self.nonce,
            "subject": self.subject.payload(),
            "authority": AUTHORITY,
        }

    @classmethod
    def from_value(cls, value: Any) -> "CapsuleClaims":
        raw = mapping(value, "capsule.claims")
        exact_keys(
            raw,
            {
                "capsule_id", "issuer_id", "subject_id", "key_id", "algorithm",
                "audience", "issued_at_unix", "not_before_unix",
                "expires_at_unix", "nonce", "subject", "authority",
            },
            set(),
            "capsule.claims",
        )
        if raw["authority"] != AUTHORITY:
            raise CapsuleError("capsule.claims.authority must remain fixed")
        algorithm = string(raw["algorithm"], "capsule.claims.algorithm")
        if algorithm != ALGORITHM:
            raise CapsuleError(f"capsule.claims.algorithm must be {ALGORITHM}")
        issued = unix_time(raw["issued_at_unix"], "capsule.claims.issued_at_unix")
        not_before = unix_time(
            raw["not_before_unix"], "capsule.claims.not_before_unix"
        )
        expires = unix_time(raw["expires_at_unix"], "capsule.claims.expires_at_unix")
        if not (issued <= not_before < expires):
            raise CapsuleError(
                "capsule time order must be issued_at <= not_before < expires_at"
            )
        if expires - issued > MAX_CAPSULE_TTL_SECONDS:
            raise CapsuleError(
                f"capsule TTL exceeds hard maximum {MAX_CAPSULE_TTL_SECONDS}"
            )
        return cls(
            capsule_id=identifier(raw["capsule_id"], "capsule.claims.capsule_id"),
            issuer_id=identifier(raw["issuer_id"], "capsule.claims.issuer_id"),
            subject_id=identifier(raw["subject_id"], "capsule.claims.subject_id"),
            key_id=identifier(raw["key_id"], "capsule.claims.key_id"),
            algorithm=algorithm,
            audience=identifier(raw["audience"], "capsule.claims.audience"),
            issued_at_unix=issued,
            not_before_unix=not_before,
            expires_at_unix=expires,
            nonce=identifier(raw["nonce"], "capsule.claims.nonce"),
            subject=GovernanceSubject.from_value(raw["subject"]),
        )


@dataclass(frozen=True)
class SignedGovernanceCapsule:
    claims: CapsuleClaims
    payload_sha256: str
    signature_b64url: str

    @property
    def signed_message(self) -> bytes:
        return DOMAIN_SEPARATOR + canonical_json(self.claims.payload()).encode("utf-8")

    def as_document(self) -> dict[str, Any]:
        return {
            "schema_version": CAPSULE_SCHEMA,
            "claims": self.claims.payload(),
            "payload_sha256": self.payload_sha256,
            "signature_b64url": self.signature_b64url,
        }

    @property
    def capsule_sha256(self) -> str:
        return canonical_sha256(self.as_document())

    @classmethod
    def from_document(cls, value: Any) -> "SignedGovernanceCapsule":
        raw = mapping(value, "capsule")
        exact_keys(
            raw,
            {"schema_version", "claims", "payload_sha256", "signature_b64url"},
            set(),
            "capsule",
        )
        if raw["schema_version"] != CAPSULE_SCHEMA:
            raise CapsuleError(f"capsule.schema_version must be {CAPSULE_SCHEMA}")
        claims = CapsuleClaims.from_value(raw["claims"])
        payload_hash = sha256(raw["payload_sha256"], "capsule.payload_sha256")
        expected = canonical_sha256(claims.payload())
        if payload_hash != expected:
            raise CapsuleError("capsule.payload_sha256 mismatch")
        signature = string(raw["signature_b64url"], "capsule.signature_b64url")
        if not B64URL_RE.fullmatch(signature):
            raise CapsuleError("capsule.signature_b64url is not unpadded base64url")
        return cls(claims=claims, payload_sha256=payload_hash, signature_b64url=signature)


@dataclass(frozen=True)
class TrustedKey:
    issuer_id: str
    key_id: str
    algorithm: str
    public_key_pem: str
    public_key_sha256: str
    valid_from_unix: int
    valid_until_unix: int
    revoked_at_unix: int | None
    allowed_audiences: tuple[str, ...]
    allowed_repositories: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_pem": self.public_key_pem,
            "public_key_sha256": self.public_key_sha256,
            "valid_from_unix": self.valid_from_unix,
            "valid_until_unix": self.valid_until_unix,
            "revoked_at_unix": self.revoked_at_unix,
            "allowed_audiences": list(self.allowed_audiences),
            "allowed_repositories": list(self.allowed_repositories),
        }

    @classmethod
    def from_value(cls, value: Any, *, index: int) -> "TrustedKey":
        raw = mapping(value, f"trust_store.keys[{index}]")
        exact_keys(
            raw,
            {
                "issuer_id", "key_id", "algorithm", "public_key_pem",
                "public_key_sha256", "valid_from_unix", "valid_until_unix",
                "revoked_at_unix", "allowed_audiences", "allowed_repositories",
            },
            set(),
            f"trust_store.keys[{index}]",
        )
        algorithm = string(raw["algorithm"], f"trust_store.keys[{index}].algorithm")
        if algorithm != ALGORITHM:
            raise CapsuleError(
                f"trust_store.keys[{index}].algorithm must be {ALGORITHM}"
            )
        public_key = string(
            raw["public_key_pem"], f"trust_store.keys[{index}].public_key_pem"
        )
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----\n"):
            raise CapsuleError(
                f"trust_store.keys[{index}].public_key_pem must be a PEM public key"
            )
        public_hash = sha256(
            raw["public_key_sha256"],
            f"trust_store.keys[{index}].public_key_sha256",
        )
        actual_hash = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
        if public_hash != actual_hash:
            raise CapsuleError(
                f"trust_store.keys[{index}].public_key_sha256 mismatch"
            )
        valid_from = unix_time(
            raw["valid_from_unix"], f"trust_store.keys[{index}].valid_from_unix"
        )
        valid_until = unix_time(
            raw["valid_until_unix"], f"trust_store.keys[{index}].valid_until_unix"
        )
        if valid_until <= valid_from:
            raise CapsuleError(
                f"trust_store.keys[{index}] valid_until must be after valid_from"
            )
        revoked = nullable_unix_time(
            raw["revoked_at_unix"], f"trust_store.keys[{index}].revoked_at_unix"
        )
        return cls(
            issuer_id=identifier(
                raw["issuer_id"], f"trust_store.keys[{index}].issuer_id"
            ),
            key_id=identifier(raw["key_id"], f"trust_store.keys[{index}].key_id"),
            algorithm=algorithm,
            public_key_pem=public_key,
            public_key_sha256=public_hash,
            valid_from_unix=valid_from,
            valid_until_unix=valid_until,
            revoked_at_unix=revoked,
            allowed_audiences=normalized_strings(
                raw["allowed_audiences"],
                f"trust_store.keys[{index}].allowed_audiences",
            ),
            allowed_repositories=normalized_strings(
                raw["allowed_repositories"],
                f"trust_store.keys[{index}].allowed_repositories",
                repositories=True,
            ),
        )


@dataclass(frozen=True)
class GovernanceTrustStore:
    trust_store_id: str
    max_ttl_seconds: int
    max_clock_skew_seconds: int
    keys: tuple[TrustedKey, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": TRUST_STORE_SCHEMA,
            "trust_store_id": self.trust_store_id,
            "max_ttl_seconds": self.max_ttl_seconds,
            "max_clock_skew_seconds": self.max_clock_skew_seconds,
            "keys": [key.payload() for key in self.keys],
            "authority": AUTHORITY,
        }

    @property
    def trust_store_sha256(self) -> str:
        return canonical_sha256(self.payload())

    def as_document(self) -> dict[str, Any]:
        return {**self.payload(), "trust_store_sha256": self.trust_store_sha256}

    @property
    def key_map(self) -> dict[tuple[str, str], TrustedKey]:
        return {(key.issuer_id, key.key_id): key for key in self.keys}

    @classmethod
    def build(
        cls,
        *,
        trust_store_id: str,
        keys: list[dict[str, Any]],
        max_ttl_seconds: int = MAX_CAPSULE_TTL_SECONDS,
        max_clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> "GovernanceTrustStore":
        document = {
            "schema_version": TRUST_STORE_SCHEMA,
            "trust_store_id": trust_store_id,
            "max_ttl_seconds": max_ttl_seconds,
            "max_clock_skew_seconds": max_clock_skew_seconds,
            "keys": keys,
            "authority": AUTHORITY,
        }
        return cls.from_document(
            {**document, "trust_store_sha256": canonical_sha256(document)}
        )

    @classmethod
    def from_document(cls, value: Any) -> "GovernanceTrustStore":
        raw = mapping(value, "trust_store")
        exact_keys(
            raw,
            {
                "schema_version", "trust_store_id", "max_ttl_seconds",
                "max_clock_skew_seconds", "keys", "authority",
                "trust_store_sha256",
            },
            set(),
            "trust_store",
        )
        if raw["schema_version"] != TRUST_STORE_SCHEMA:
            raise CapsuleError(
                f"trust_store.schema_version must be {TRUST_STORE_SCHEMA}"
            )
        if raw["authority"] != AUTHORITY:
            raise CapsuleError("trust_store.authority must remain fixed")
        ttl = positive_int(
            raw["max_ttl_seconds"],
            "trust_store.max_ttl_seconds",
            maximum=MAX_CAPSULE_TTL_SECONDS,
        )
        skew = unix_time(
            raw["max_clock_skew_seconds"], "trust_store.max_clock_skew_seconds"
        )
        if skew > 3600:
            raise CapsuleError("trust_store.max_clock_skew_seconds exceeds 3600")
        keys = tuple(
            TrustedKey.from_value(item, index=index)
            for index, item in enumerate(array(raw["keys"], "trust_store.keys"))
        )
        if not keys:
            raise CapsuleError("trust_store.keys must not be empty")
        identities = [(key.issuer_id, key.key_id) for key in keys]
        if len(identities) != len(set(identities)):
            raise CapsuleError("trust_store contains duplicate issuer_id/key_id")
        store = cls(
            trust_store_id=identifier(
                raw["trust_store_id"], "trust_store.trust_store_id"
            ),
            max_ttl_seconds=ttl,
            max_clock_skew_seconds=skew,
            keys=keys,
        )
        expected = store.trust_store_sha256
        if raw["trust_store_sha256"] != expected:
            raise CapsuleError("trust_store.trust_store_sha256 mismatch")
        return store
