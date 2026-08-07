#!/usr/bin/env python3
"""Generate and verify a complete v1.1 identity-bound governance fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from sdk.liminal_governance_capsule import (
    ALGORITHM as GOVERNANCE_ALGORITHM,
    CapsuleClaims,
    GovernanceSubject,
    GovernanceTrustStore,
    SignedGovernanceCapsule,
    base64url_decode,
    base64url_encode,
    generate_ed25519_keypair,
    sign_ed25519,
)
from sdk.liminal_identity_attestation import (
    AUTHORITY,
    IdentityAttestationBundle,
    IdentityReplayGuard,
    IdentityTrustStore,
    canonical_sha256,
    issue_fixture_identity_assertion,
    issue_fixture_kms_attestation,
    verify_identity_bundle,
)

NOW = 2_000_000_000
REPOSITORY = "safal207/LiminalOSAI"
AUDIENCE = "liminal-github-pilot"
SUBJECT = "user:alex"
TENANT = "tenant:liminal"
ORGANIZATION = "org:liminal"
SESSION_SHA = hashlib.sha256(b"visible-session-v1.1").hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)


def build(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    governance_private, governance_public = generate_ed25519_keypair()
    idp_private, idp_public = generate_ed25519_keypair()
    kms_private, kms_public = generate_ed25519_keypair()

    evidence = {
        "policy_sha256": "a" * 64,
        "snapshot_sha256": "b" * 64,
        "plan_sha256": "c" * 64,
        "approval_ledger_head_sha256": "d" * 64,
        "transaction_journal_head_sha256": "e" * 64,
    }
    subject = GovernanceSubject.from_value(
        {
            "policy_id": "policy:v1.1",
            "transaction_id": "transaction:v1.1",
            "repository_full_name": REPOSITORY,
            "policy_sha256": evidence["policy_sha256"],
            "snapshot_sha256": evidence["snapshot_sha256"],
            "plan_sha256": evidence["plan_sha256"],
            "approval_ledger_head_sha256": evidence[
                "approval_ledger_head_sha256"
            ],
            "transaction_journal_anchor_sha256": evidence[
                "transaction_journal_head_sha256"
            ],
            "engine_evidence_sha256": canonical_sha256(evidence),
            "decision": "allow",
            "approval_status": "ready",
        }
    )
    claims = CapsuleClaims(
        capsule_id="capsule:v1.1:self-check",
        issuer_id="issuer:liminal-governance",
        subject_id=SUBJECT,
        key_id="governance-key:v1",
        algorithm=GOVERNANCE_ALGORITHM,
        audience=AUDIENCE,
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        nonce="nonce:v1.1:self-check",
        subject=subject,
    )
    payload_hash = canonical_sha256(claims.payload())
    unsigned = SignedGovernanceCapsule(claims, payload_hash, "AA")
    capsule = SignedGovernanceCapsule.from_document(
        SignedGovernanceCapsule(
            claims,
            payload_hash,
            base64url_encode(sign_ed25519(governance_private, unsigned.signed_message)),
        ).as_document()
    )
    governance_store = GovernanceTrustStore.build(
        trust_store_id="governance-trust:v1.1:self-check",
        keys=[
            {
                "issuer_id": claims.issuer_id,
                "key_id": claims.key_id,
                "algorithm": GOVERNANCE_ALGORITHM,
                "public_key_pem": governance_public.decode("utf-8"),
                "public_key_sha256": hashlib.sha256(governance_public).hexdigest(),
                "valid_from_unix": NOW - 100,
                "valid_until_unix": NOW + 3600,
                "revoked_at_unix": None,
                "allowed_audiences": [AUDIENCE],
                "allowed_repositories": [REPOSITORY],
            }
        ],
        max_ttl_seconds=1200,
        max_clock_skew_seconds=0,
    )

    with tempfile.TemporaryDirectory(prefix="liminal-v11-self-check-") as temporary:
        root = Path(temporary)
        idp_private_path = root / "idp-private.pem"
        kms_private_path = root / "kms-private.pem"
        write_private(idp_private_path, idp_private)
        write_private(kms_private_path, kms_private)
        identity = issue_fixture_identity_assertion(
            private_key_path=idp_private_path,
            assertion_id="idp-assertion:v1.1:self-check",
            issuer="https://idp.example.test",
            key_id="idp-signing-key:v1",
            subject_id=SUBJECT,
            tenant_id=TENANT,
            organization_id=ORGANIZATION,
            audience=AUDIENCE,
            repository_full_name=REPOSITORY,
            roles=["governance-approver", "repository-maintainer"],
            groups=["engineering"],
            auth_methods=["mfa", "webauthn"],
            service_account=False,
            session_sha256=SESSION_SHA,
            capsule_nonce=claims.nonce,
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 300,
        )
        kms = issue_fixture_kms_attestation(
            private_key_path=kms_private_path,
            receipt_id="kms-receipt:v1.1:self-check",
            provider_id="mock-kms",
            attestation_key_id="mock-kms-attestation:v1",
            tenant_id=TENANT,
            subject_id=SUBJECT,
            key_resource_id="kms://liminal/governance-key",
            key_version_id="version:1",
            governance_key_id=claims.key_id,
            public_key_sha256=hashlib.sha256(governance_public).hexdigest(),
            hardware_protection="hsm",
            repository_full_name=REPOSITORY,
            capsule_nonce=claims.nonce,
            capsule_payload_sha256=capsule.payload_sha256,
            capsule_signature_sha256=hashlib.sha256(
                base64url_decode(capsule.signature_b64url)
            ).hexdigest(),
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 300,
        )

    identity_store = IdentityTrustStore.build(
        trust_store_id="identity-trust:v1.1:self-check",
        required_roles=["governance-approver"],
        require_mfa=True,
        max_assertion_ttl_seconds=600,
        max_attestation_ttl_seconds=600,
        max_clock_skew_seconds=0,
        idp_keys=[
            {
                "issuer": "https://idp.example.test",
                "key_id": "idp-signing-key:v1",
                "public_key_pem": idp_public.decode("utf-8"),
                "public_key_sha256": hashlib.sha256(idp_public).hexdigest(),
                "valid_from_unix": NOW - 100,
                "valid_until_unix": NOW + 3600,
                "revoked_at_unix": None,
                "allowed_audiences": [AUDIENCE],
                "allowed_tenants": [TENANT],
            }
        ],
        kms_keys=[
            {
                "provider_id": "mock-kms",
                "attestation_key_id": "mock-kms-attestation:v1",
                "public_key_pem": kms_public.decode("utf-8"),
                "public_key_sha256": hashlib.sha256(kms_public).hexdigest(),
                "valid_from_unix": NOW - 100,
                "valid_until_unix": NOW + 3600,
                "revoked_at_unix": None,
                "allowed_tenants": [TENANT],
                "allowed_repositories": [REPOSITORY],
                "allowed_hardware_protection": ["hsm"],
            }
        ],
    )
    bundle = IdentityAttestationBundle.build(
        identity_assertion=identity,
        kms_attestation=kms,
        capsule_sha256=capsule.capsule_sha256,
        capsule_payload_sha256=capsule.payload_sha256,
    )
    replay_guard = IdentityReplayGuard()
    verification = verify_identity_bundle(
        bundle,
        identity_store,
        capsule,
        governance_store,
        at_unix=NOW + 10,
        expected_session_sha256=SESSION_SHA,
        expected_tenant_id=TENANT,
        expected_organization_id=ORGANIZATION,
        expected_roles=["repository-maintainer"],
        replay_guard=replay_guard,
        consume_replay=True,
    )
    assert verification["status"] == "valid"
    assert verification["authority"] == AUTHORITY
    assert verification["replay_consumed"] is True

    write_json(output_dir / "governance-capsule.json", capsule.as_document())
    write_json(output_dir / "governance-trust-store.json", governance_store.as_document())
    write_json(output_dir / "identity-assertion.json", identity.as_document())
    write_json(output_dir / "kms-attestation.json", kms.as_document())
    write_json(output_dir / "identity-trust-store.json", identity_store.as_document())
    write_json(output_dir / "identity-bundle.json", bundle.as_document())
    write_json(output_dir / "identity-verification.json", verification)
    return verification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = build(Path(args.output_dir))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
