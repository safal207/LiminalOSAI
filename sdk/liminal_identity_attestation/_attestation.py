"""Issue fixture attestations and verify identity-bound governance bundles."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

from sdk.liminal_governance_capsule import (
    CapsuleError,
    GovernanceTrustStore,
    SignedGovernanceCapsule,
    base64url_decode,
    base64url_encode,
    load_capsule,
    load_trust_store,
    sign_ed25519,
    verify_capsule,
    verify_capsule_against_engine,
    verify_ed25519,
)

from ._contracts import (
    ALGORITHM,
    AUTHORITY,
    IDENTITY_VERIFICATION_SCHEMA,
    AttestationError,
    IdentityAssertionClaims,
    IdentityAttestationBundle,
    IdentityTrustStore,
    KmsOperationClaims,
    SignedIdentityAssertion,
    SignedKmsAttestation,
    canonical_sha256,
    identifier,
    sha256,
    unix_time,
)


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _read_json(path: Path, name: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AttestationError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AttestationError(f"{name} is not valid JSON: {exc}") from exc


def _read_private_key(path: str | Path) -> bytes:
    target = Path(path)
    try:
        value = target.read_bytes()
    except FileNotFoundError as exc:
        raise AttestationError(f"private key does not exist: {target}") from exc
    if not value.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
        raise AttestationError("private key must be an unencrypted PKCS#8 PEM key")
    return value


def _write_new(path: str | Path | None, document: dict[str, Any], name: str) -> None:
    if path is None:
        return
    target = Path(path)
    if target.exists():
        raise AttestationError(f"{name} already exists: {target}")
    _atomic_write_json(target, document)


def issue_fixture_identity_assertion(
    *,
    private_key_path: str | Path,
    assertion_id: str,
    issuer: str,
    key_id: str,
    subject_id: str,
    tenant_id: str,
    organization_id: str,
    audience: str,
    repository_full_name: str,
    roles: Iterable[str],
    groups: Iterable[str],
    auth_methods: Iterable[str],
    service_account: bool,
    session_sha256: str,
    capsule_nonce: str,
    issued_at_unix: int,
    not_before_unix: int,
    expires_at_unix: int,
    identity_status: str = "active",
    output_path: str | Path | None = None,
) -> SignedIdentityAssertion:
    """Fixture signer only; a production host must adapt verified IdP evidence."""
    claims = IdentityAssertionClaims.from_value(
        {
            "assertion_id": assertion_id,
            "issuer": issuer,
            "key_id": key_id,
            "subject_id": subject_id,
            "tenant_id": tenant_id,
            "organization_id": organization_id,
            "audience": audience,
            "repository_full_name": repository_full_name,
            "roles": list(roles),
            "groups": list(groups),
            "auth_methods": list(auth_methods),
            "service_account": service_account,
            "session_sha256": session_sha256,
            "capsule_nonce": capsule_nonce,
            "issued_at_unix": issued_at_unix,
            "not_before_unix": not_before_unix,
            "expires_at_unix": expires_at_unix,
            "identity_status": identity_status,
            "authority": AUTHORITY,
        }
    )
    payload_hash = canonical_sha256(claims.payload())
    unsigned = SignedIdentityAssertion(claims, payload_hash, "AA")
    signature = sign_ed25519(_read_private_key(private_key_path), unsigned.signed_message)
    result = SignedIdentityAssertion.from_document(
        SignedIdentityAssertion(
            claims, payload_hash, base64url_encode(signature)
        ).as_document()
    )
    _write_new(output_path, result.as_document(), "identity assertion")
    return result


def issue_fixture_kms_attestation(
    *,
    private_key_path: str | Path,
    receipt_id: str,
    provider_id: str,
    attestation_key_id: str,
    tenant_id: str,
    subject_id: str,
    key_resource_id: str,
    key_version_id: str,
    governance_key_id: str,
    public_key_sha256: str,
    hardware_protection: str,
    repository_full_name: str,
    capsule_nonce: str,
    capsule_payload_sha256: str,
    capsule_signature_sha256: str,
    issued_at_unix: int,
    not_before_unix: int,
    expires_at_unix: int,
    key_status: str = "active",
    output_path: str | Path | None = None,
) -> SignedKmsAttestation:
    """Mock provider receipt; production signing remains owned by KMS/HSM host code."""
    claims = KmsOperationClaims.from_value(
        {
            "receipt_id": receipt_id,
            "provider_id": provider_id,
            "attestation_key_id": attestation_key_id,
            "tenant_id": tenant_id,
            "subject_id": subject_id,
            "key_resource_id": key_resource_id,
            "key_version_id": key_version_id,
            "governance_key_id": governance_key_id,
            "algorithm": ALGORITHM,
            "public_key_sha256": public_key_sha256,
            "operation": "sign",
            "hardware_protection": hardware_protection,
            "key_status": key_status,
            "repository_full_name": repository_full_name,
            "capsule_nonce": capsule_nonce,
            "capsule_payload_sha256": capsule_payload_sha256,
            "capsule_signature_sha256": capsule_signature_sha256,
            "issued_at_unix": issued_at_unix,
            "not_before_unix": not_before_unix,
            "expires_at_unix": expires_at_unix,
            "authority": AUTHORITY,
        }
    )
    payload_hash = canonical_sha256(claims.payload())
    unsigned = SignedKmsAttestation(claims, payload_hash, "AA")
    signature = sign_ed25519(_read_private_key(private_key_path), unsigned.signed_message)
    result = SignedKmsAttestation.from_document(
        SignedKmsAttestation(
            claims, payload_hash, base64url_encode(signature)
        ).as_document()
    )
    _write_new(output_path, result.as_document(), "KMS attestation")
    return result


def load_identity_assertion(path: str | Path) -> SignedIdentityAssertion:
    return SignedIdentityAssertion.from_document(
        _read_json(Path(path), "identity assertion")
    )


def load_kms_attestation(path: str | Path) -> SignedKmsAttestation:
    return SignedKmsAttestation.from_document(
        _read_json(Path(path), "KMS attestation")
    )


def load_identity_bundle(path: str | Path) -> IdentityAttestationBundle:
    return IdentityAttestationBundle.from_document(
        _read_json(Path(path), "identity attestation bundle")
    )


def load_identity_trust_store(path: str | Path) -> IdentityTrustStore:
    return IdentityTrustStore.from_document(
        _read_json(Path(path), "identity trust store")
    )


def write_identity_bundle(
    bundle: IdentityAttestationBundle, output_path: str | Path
) -> None:
    _write_new(output_path, bundle.as_document(), "identity attestation bundle")


class IdentityReplayGuard:
    """Host-owned, in-memory replay guard for authorization-time consumption."""

    def __init__(self) -> None:
        self._consumed: set[tuple[str, str, str, str]] = set()

    def consume(self, bundle: IdentityAttestationBundle) -> None:
        claims = bundle.identity_assertion.claims
        key = (
            claims.issuer,
            claims.subject_id,
            claims.capsule_nonce,
            claims.session_sha256,
        )
        if key in self._consumed:
            raise AttestationError("identity assertion replay detected")
        self._consumed.add(key)


def _verify_signature(public_key_pem: str, message: bytes, encoded: str, name: str) -> None:
    try:
        signature = base64url_decode(encoded)
    except CapsuleError as exc:
        raise AttestationError(f"{name} signature encoding is invalid") from exc
    if len(signature) != 64:
        raise AttestationError(f"{name} Ed25519 signature must contain 64 bytes")
    if not verify_ed25519(public_key_pem.encode("utf-8"), message, signature):
        raise AttestationError(f"{name} signature verification failed")


def _verify_time_and_key(
    *,
    issued: int,
    not_before: int,
    expires: int,
    maximum_ttl: int,
    now: int,
    skew: int,
    key_valid_from: int,
    key_valid_until: int,
    key_revoked_at: int | None,
    name: str,
) -> None:
    if expires - issued > maximum_ttl:
        raise AttestationError(f"{name} TTL exceeds trust-store maximum")
    if now + skew < not_before:
        raise AttestationError(f"{name} is not yet valid")
    if now - skew > expires:
        raise AttestationError(f"{name} has expired")
    if issued < key_valid_from:
        raise AttestationError(f"{name} was issued before trusted key validity")
    if issued > key_valid_until:
        raise AttestationError(f"{name} was issued after trusted key validity")
    if now - skew > key_valid_until:
        raise AttestationError(f"{name} trusted key validity has ended")
    if key_revoked_at is not None and now >= key_revoked_at:
        raise AttestationError(f"{name} trusted key is revoked")


def verify_identity_bundle(
    bundle: IdentityAttestationBundle | dict[str, Any],
    identity_trust_store: IdentityTrustStore | dict[str, Any],
    capsule: SignedGovernanceCapsule | dict[str, Any],
    governance_trust_store: GovernanceTrustStore | dict[str, Any],
    *,
    at_unix: int | None = None,
    expected_session_sha256: str | None = None,
    expected_tenant_id: str | None = None,
    expected_organization_id: str | None = None,
    expected_roles: Iterable[str] | None = None,
    replay_guard: IdentityReplayGuard | None = None,
    consume_replay: bool = False,
) -> dict[str, Any]:
    bundle_value = (
        bundle
        if isinstance(bundle, IdentityAttestationBundle)
        else IdentityAttestationBundle.from_document(bundle)
    )
    identity_store = (
        identity_trust_store
        if isinstance(identity_trust_store, IdentityTrustStore)
        else IdentityTrustStore.from_document(identity_trust_store)
    )
    capsule_value = (
        capsule
        if isinstance(capsule, SignedGovernanceCapsule)
        else SignedGovernanceCapsule.from_document(capsule)
    )
    governance_store = (
        governance_trust_store
        if isinstance(governance_trust_store, GovernanceTrustStore)
        else GovernanceTrustStore.from_document(governance_trust_store)
    )
    identity = bundle_value.identity_assertion.claims
    kms = bundle_value.kms_attestation.claims
    now = unix_time(int(time.time()) if at_unix is None else at_unix, "at_unix")

    try:
        capsule_verification = verify_capsule(
            capsule_value,
            governance_store,
            at_unix=now,
            expected_audience=identity.audience,
            expected_repository=identity.repository_full_name,
        )
    except CapsuleError as exc:
        raise AttestationError(f"governance capsule verification failed: {exc}") from exc

    if bundle_value.capsule_sha256 != capsule_value.capsule_sha256:
        raise AttestationError("identity bundle capsule_sha256 mismatch")
    if bundle_value.capsule_payload_sha256 != capsule_value.payload_sha256:
        raise AttestationError("identity bundle capsule_payload_sha256 mismatch")

    idp_key = identity_store.idp_key_map.get((identity.issuer, identity.key_id))
    if idp_key is None:
        raise AttestationError("identity assertion issuer/key is not trusted")
    if identity.audience not in idp_key.allowed_audiences:
        raise AttestationError("identity assertion audience is not permitted")
    if identity.tenant_id not in idp_key.allowed_tenants:
        raise AttestationError("identity assertion tenant is not permitted")
    _verify_time_and_key(
        issued=identity.issued_at_unix,
        not_before=identity.not_before_unix,
        expires=identity.expires_at_unix,
        maximum_ttl=identity_store.max_assertion_ttl_seconds,
        now=now,
        skew=identity_store.max_clock_skew_seconds,
        key_valid_from=idp_key.valid_from_unix,
        key_valid_until=idp_key.valid_until_unix,
        key_revoked_at=idp_key.revoked_at_unix,
        name="identity assertion",
    )
    _verify_signature(
        idp_key.public_key_pem,
        bundle_value.identity_assertion.signed_message,
        bundle_value.identity_assertion.signature_b64url,
        "identity assertion",
    )

    kms_key = identity_store.kms_key_map.get(
        (kms.provider_id, kms.attestation_key_id)
    )
    if kms_key is None:
        raise AttestationError("KMS provider/attestation key is not trusted")
    if kms.tenant_id not in kms_key.allowed_tenants:
        raise AttestationError("KMS attestation tenant is not permitted")
    if kms.repository_full_name not in kms_key.allowed_repositories:
        raise AttestationError("KMS attestation repository is not permitted")
    if kms.hardware_protection not in kms_key.allowed_hardware_protection:
        raise AttestationError("KMS hardware protection is not permitted")
    _verify_time_and_key(
        issued=kms.issued_at_unix,
        not_before=kms.not_before_unix,
        expires=kms.expires_at_unix,
        maximum_ttl=identity_store.max_attestation_ttl_seconds,
        now=now,
        skew=identity_store.max_clock_skew_seconds,
        key_valid_from=kms_key.valid_from_unix,
        key_valid_until=kms_key.valid_until_unix,
        key_revoked_at=kms_key.revoked_at_unix,
        name="KMS attestation",
    )
    _verify_signature(
        kms_key.public_key_pem,
        bundle_value.kms_attestation.signed_message,
        bundle_value.kms_attestation.signature_b64url,
        "KMS attestation",
    )

    capsule_claims = capsule_value.claims
    common_checks = {
        "identity subject": (identity.subject_id, capsule_claims.subject_id),
        "identity audience": (identity.audience, capsule_claims.audience),
        "identity repository": (
            identity.repository_full_name,
            capsule_claims.subject.repository_full_name,
        ),
        "identity nonce": (identity.capsule_nonce, capsule_claims.nonce),
        "KMS subject": (kms.subject_id, capsule_claims.subject_id),
        "KMS repository": (
            kms.repository_full_name,
            capsule_claims.subject.repository_full_name,
        ),
        "KMS nonce": (kms.capsule_nonce, capsule_claims.nonce),
        "KMS governance key": (kms.governance_key_id, capsule_claims.key_id),
        "KMS capsule payload": (
            kms.capsule_payload_sha256,
            capsule_value.payload_sha256,
        ),
        "IdP/KMS tenant": (identity.tenant_id, kms.tenant_id),
        "IdP/KMS subject": (identity.subject_id, kms.subject_id),
    }
    for name, (actual, expected) in common_checks.items():
        if actual != expected:
            raise AttestationError(f"{name} mismatch")

    try:
        capsule_signature = base64url_decode(capsule_value.signature_b64url)
    except CapsuleError as exc:
        raise AttestationError("capsule signature encoding is invalid") from exc
    if kms.capsule_signature_sha256 != hashlib.sha256(capsule_signature).hexdigest():
        raise AttestationError("KMS capsule signature digest mismatch")

    governance_key = governance_store.key_map.get(
        (capsule_claims.issuer_id, capsule_claims.key_id)
    )
    if governance_key is None:
        raise AttestationError("governance capsule key is not trusted")
    if kms.public_key_sha256 != governance_key.public_key_sha256:
        raise AttestationError("KMS public key fingerprint does not match capsule key")

    if expected_session_sha256 is not None and identity.session_sha256 != sha256(
        expected_session_sha256, "expected_session_sha256"
    ):
        raise AttestationError("identity assertion session mismatch")
    if expected_tenant_id is not None and identity.tenant_id != identifier(
        expected_tenant_id, "expected_tenant_id"
    ):
        raise AttestationError("identity assertion tenant mismatch")
    if expected_organization_id is not None and identity.organization_id != identifier(
        expected_organization_id, "expected_organization_id"
    ):
        raise AttestationError("identity assertion organization mismatch")

    required_roles = set(identity_store.required_roles)
    required_roles.update(identifier(role, "expected_roles[]") for role in (expected_roles or []))
    missing_roles = sorted(required_roles - set(identity.roles))
    if missing_roles:
        raise AttestationError(
            "identity assertion missing required roles: " + ", ".join(missing_roles)
        )
    if identity_store.require_mfa and "mfa" not in identity.auth_methods:
        raise AttestationError("identity assertion does not explicitly prove mfa")

    if consume_replay:
        if replay_guard is None:
            raise AttestationError("consume_replay requires a replay guard")
        replay_guard.consume(bundle_value)

    return {
        "schema_version": IDENTITY_VERIFICATION_SCHEMA,
        "status": "valid",
        "verified_at_unix": now,
        "subject_id": identity.subject_id,
        "tenant_id": identity.tenant_id,
        "organization_id": identity.organization_id,
        "service_account": identity.service_account,
        "roles": list(identity.roles),
        "groups": list(identity.groups),
        "auth_methods": list(identity.auth_methods),
        "issuer": identity.issuer,
        "idp_key_id": identity.key_id,
        "kms_provider_id": kms.provider_id,
        "kms_key_resource_id": kms.key_resource_id,
        "kms_key_version_id": kms.key_version_id,
        "hardware_protection": kms.hardware_protection,
        "repository_full_name": identity.repository_full_name,
        "session_sha256": identity.session_sha256,
        "identity_assertion_sha256": bundle_value.identity_assertion.assertion_sha256,
        "kms_attestation_sha256": bundle_value.kms_attestation.attestation_sha256,
        "bundle_sha256": bundle_value.bundle_sha256,
        "identity_trust_store_sha256": identity_store.trust_store_sha256,
        "capsule_verification": capsule_verification,
        "replay_consumed": consume_replay,
        "authority": AUTHORITY,
    }


def verify_identity_bundle_against_engine(
    bundle: IdentityAttestationBundle | dict[str, Any],
    identity_trust_store: IdentityTrustStore | dict[str, Any],
    capsule: SignedGovernanceCapsule | dict[str, Any],
    governance_trust_store: GovernanceTrustStore | dict[str, Any],
    engine: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    result = verify_identity_bundle(
        bundle,
        identity_trust_store,
        capsule,
        governance_trust_store,
        **kwargs,
    )
    at_unix = kwargs.get("at_unix")
    try:
        engine_verification = verify_capsule_against_engine(
            capsule,
            governance_trust_store,
            engine,
            at_unix=at_unix,
            expected_audience=result["capsule_verification"]["audience"],
        )
    except CapsuleError as exc:
        raise AttestationError(f"identity-bound capsule no longer matches engine: {exc}") from exc
    return {**result, "engine_verification": engine_verification}


class IdentityAttestedGovernanceSession:
    """Place identity and KMS verification above GovernanceCapsuleSession."""

    def __init__(
        self,
        governance_session: Any,
        *,
        identity_bundle_path: str | Path,
        identity_trust_store_path: str | Path,
        expected_session_sha256: str,
        expected_tenant_id: str,
        expected_organization_id: str,
        expected_roles: Iterable[str],
        replay_guard: IdentityReplayGuard | None = None,
    ):
        self.governance_session = governance_session
        self.identity_bundle_path = Path(identity_bundle_path)
        self.identity_trust_store_path = Path(identity_trust_store_path)
        self.expected_session_sha256 = sha256(
            expected_session_sha256, "expected_session_sha256"
        )
        self.expected_tenant_id = identifier(expected_tenant_id, "expected_tenant_id")
        self.expected_organization_id = identifier(
            expected_organization_id, "expected_organization_id"
        )
        self.expected_roles = tuple(
            sorted(identifier(role, "expected_roles[]") for role in expected_roles)
        )
        self.replay_guard = replay_guard or IdentityReplayGuard()
        self._activated = False

    def verify(self, *, consume_replay: bool = False) -> dict[str, Any]:
        session = self.governance_session
        return verify_identity_bundle_against_engine(
            load_identity_bundle(self.identity_bundle_path),
            load_identity_trust_store(self.identity_trust_store_path),
            load_capsule(session.capsule_path),
            load_trust_store(session.trust_store_path),
            session.engine,
            at_unix=session.clock(),
            expected_session_sha256=self.expected_session_sha256,
            expected_tenant_id=self.expected_tenant_id,
            expected_organization_id=self.expected_organization_id,
            expected_roles=self.expected_roles,
            replay_guard=self.replay_guard,
            consume_replay=consume_replay,
        )

    def activate(self) -> dict[str, Any]:
        verification = self.verify(consume_replay=True)
        self._activated = True
        return verification

    def _gate(self) -> dict[str, Any]:
        if not self._activated:
            return self.activate()
        return self.verify()

    def prepare_next(self) -> dict[str, Any]:
        identity = self._gate()
        result = self.governance_session.prepare_next()
        return {**result, "identity_attestation": identity}

    def authorize_step(self, **kwargs: Any) -> dict[str, Any]:
        self._gate()
        return self.governance_session.authorize_step(**kwargs)

    def run_next(self, connector: Any) -> dict[str, Any]:
        self._gate()
        return self.governance_session.run_next(connector)

    def run(self, connector: Any) -> dict[str, Any]:
        self._gate()
        return self.governance_session.run(connector)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.governance_session.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.governance_session.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.governance_session.record_claim(**kwargs)

    def seal(self, **kwargs: Any) -> dict[str, Any]:
        self._gate()
        return self.governance_session.seal(**kwargs)

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self._gate()
        return self.governance_session.export_live_session(output_path)
