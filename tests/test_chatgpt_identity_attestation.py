from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
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
    AttestationError,
    IdentityAttestationBundle,
    IdentityReplayGuard,
    IdentityTrustStore,
    SignedIdentityAssertion,
    SignedKmsAttestation,
    canonical_sha256,
    issue_fixture_identity_assertion,
    issue_fixture_kms_attestation,
    verify_identity_bundle,
)

NOW = 2_000_000_000
REPO = "safal207/LiminalOSAI"
AUDIENCE = "liminal-github-pilot"
SUBJECT = "user:alex"
TENANT = "tenant:liminal"
ORG = "org:liminal"
SESSION_SHA = hashlib.sha256(b"session-v1.1").hexdigest()


class IdentityAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.governance_private, cls.governance_public = generate_ed25519_keypair()
        cls.idp_private, cls.idp_public = generate_ed25519_keypair()
        cls.kms_private, cls.kms_public = generate_ed25519_keypair()
        cls.idp_private_path = cls.root / "idp-private.pem"
        cls.kms_private_path = cls.root / "kms-private.pem"
        for path, content in (
            (cls.idp_private_path, cls.idp_private),
            (cls.kms_private_path, cls.kms_private),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def capsule(
        self,
        *,
        subject_id: str = SUBJECT,
        audience: str = AUDIENCE,
        repository: str = REPO,
        nonce: str = "nonce:v1.1",
        expires_at: int = NOW + 600,
    ) -> SignedGovernanceCapsule:
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
                "repository_full_name": repository,
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
            capsule_id="capsule:v1.1:test",
            issuer_id="issuer:governance",
            subject_id=subject_id,
            key_id="governance-key:v1",
            algorithm=GOVERNANCE_ALGORITHM,
            audience=audience,
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=expires_at,
            nonce=nonce,
            subject=subject,
        )
        payload_hash = canonical_sha256(claims.payload())
        unsigned = SignedGovernanceCapsule(claims, payload_hash, "AA")
        return SignedGovernanceCapsule.from_document(
            SignedGovernanceCapsule(
                claims,
                payload_hash,
                base64url_encode(
                    sign_ed25519(self.governance_private, unsigned.signed_message)
                ),
            ).as_document()
        )

    def governance_store(self, capsule: SignedGovernanceCapsule) -> GovernanceTrustStore:
        return GovernanceTrustStore.build(
            trust_store_id="governance-trust:test",
            keys=[
                {
                    "issuer_id": capsule.claims.issuer_id,
                    "key_id": capsule.claims.key_id,
                    "algorithm": GOVERNANCE_ALGORITHM,
                    "public_key_pem": self.governance_public.decode(),
                    "public_key_sha256": hashlib.sha256(
                        self.governance_public
                    ).hexdigest(),
                    "valid_from_unix": NOW - 100,
                    "valid_until_unix": NOW + 3600,
                    "revoked_at_unix": None,
                    "allowed_audiences": [capsule.claims.audience],
                    "allowed_repositories": [
                        capsule.claims.subject.repository_full_name
                    ],
                }
            ],
            max_ttl_seconds=1200,
            max_clock_skew_seconds=0,
        )

    def identity(
        self,
        capsule: SignedGovernanceCapsule,
        **overrides,
    ):
        values = {
            "assertion_id": "assertion:test",
            "issuer": "https://idp.example.test",
            "key_id": "idp-key:v1",
            "subject_id": capsule.claims.subject_id,
            "tenant_id": TENANT,
            "organization_id": ORG,
            "audience": capsule.claims.audience,
            "repository_full_name": capsule.claims.subject.repository_full_name,
            "roles": ["governance-approver", "repository-maintainer"],
            "groups": ["engineering"],
            "auth_methods": ["mfa", "webauthn"],
            "service_account": False,
            "session_sha256": SESSION_SHA,
            "capsule_nonce": capsule.claims.nonce,
            "issued_at_unix": NOW,
            "not_before_unix": NOW,
            "expires_at_unix": NOW + 300,
            "identity_status": "active",
        }
        values.update(overrides)
        return issue_fixture_identity_assertion(
            private_key_path=self.idp_private_path, **values
        )

    def kms(self, capsule: SignedGovernanceCapsule, **overrides):
        values = {
            "receipt_id": "kms-receipt:test",
            "provider_id": "mock-kms",
            "attestation_key_id": "kms-attestation-key:v1",
            "tenant_id": TENANT,
            "subject_id": capsule.claims.subject_id,
            "key_resource_id": "kms://liminal/governance-key",
            "key_version_id": "version:1",
            "governance_key_id": capsule.claims.key_id,
            "public_key_sha256": hashlib.sha256(
                self.governance_public
            ).hexdigest(),
            "hardware_protection": "hsm",
            "repository_full_name": capsule.claims.subject.repository_full_name,
            "capsule_nonce": capsule.claims.nonce,
            "capsule_payload_sha256": capsule.payload_sha256,
            "capsule_signature_sha256": hashlib.sha256(
                base64url_decode(capsule.signature_b64url)
            ).hexdigest(),
            "issued_at_unix": NOW,
            "not_before_unix": NOW,
            "expires_at_unix": NOW + 300,
            "key_status": "active",
        }
        values.update(overrides)
        return issue_fixture_kms_attestation(
            private_key_path=self.kms_private_path, **values
        )

    def identity_store(
        self,
        *,
        idp_revoked_at=None,
        kms_revoked_at=None,
        required_roles=None,
        require_mfa=True,
        idp_audiences=None,
        idp_tenants=None,
        kms_tenants=None,
        kms_repositories=None,
        hardware=None,
    ) -> IdentityTrustStore:
        return IdentityTrustStore.build(
            trust_store_id="identity-trust:test",
            required_roles=required_roles or ["governance-approver"],
            require_mfa=require_mfa,
            max_assertion_ttl_seconds=600,
            max_attestation_ttl_seconds=600,
            max_clock_skew_seconds=0,
            idp_keys=[
                {
                    "issuer": "https://idp.example.test",
                    "key_id": "idp-key:v1",
                    "public_key_pem": self.idp_public.decode(),
                    "public_key_sha256": hashlib.sha256(self.idp_public).hexdigest(),
                    "valid_from_unix": NOW - 100,
                    "valid_until_unix": NOW + 3600,
                    "revoked_at_unix": idp_revoked_at,
                    "allowed_audiences": idp_audiences or [AUDIENCE],
                    "allowed_tenants": idp_tenants or [TENANT],
                }
            ],
            kms_keys=[
                {
                    "provider_id": "mock-kms",
                    "attestation_key_id": "kms-attestation-key:v1",
                    "public_key_pem": self.kms_public.decode(),
                    "public_key_sha256": hashlib.sha256(self.kms_public).hexdigest(),
                    "valid_from_unix": NOW - 100,
                    "valid_until_unix": NOW + 3600,
                    "revoked_at_unix": kms_revoked_at,
                    "allowed_tenants": kms_tenants or [TENANT],
                    "allowed_repositories": kms_repositories or [REPO],
                    "allowed_hardware_protection": hardware or ["hsm"],
                }
            ],
        )

    def bundle(self, capsule, identity=None, kms=None):
        return IdentityAttestationBundle.build(
            identity_assertion=identity or self.identity(capsule),
            kms_attestation=kms or self.kms(capsule),
            capsule_sha256=capsule.capsule_sha256,
            capsule_payload_sha256=capsule.payload_sha256,
        )

    def verify(self, capsule, bundle=None, store=None, **kwargs):
        return verify_identity_bundle(
            bundle or self.bundle(capsule),
            store or self.identity_store(),
            capsule,
            self.governance_store(capsule),
            at_unix=kwargs.pop("at_unix", NOW + 10),
            expected_session_sha256=kwargs.pop(
                "expected_session_sha256", SESSION_SHA
            ),
            expected_tenant_id=kwargs.pop("expected_tenant_id", TENANT),
            expected_organization_id=kwargs.pop("expected_organization_id", ORG),
            expected_roles=kwargs.pop("expected_roles", ["repository-maintainer"]),
            **kwargs,
        )

    def test_valid_identity_kms_capsule_chain(self) -> None:
        result = self.verify(self.capsule())
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["authority"], AUTHORITY)

    def test_wrong_subject_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "identity subject mismatch"):
            self.verify(capsule, self.bundle(capsule, identity=self.identity(capsule, subject_id="user:mallory")))

    def test_unknown_issuer_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "not trusted"):
            self.verify(capsule, self.bundle(capsule, identity=self.identity(capsule, issuer="https://evil.example.test")))

    def test_wrong_audience_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "capsule verification failed"):
            self.verify(capsule, self.bundle(capsule, identity=self.identity(capsule, audience="other-audience")))

    def test_wrong_repository_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "capsule verification failed"):
            self.verify(capsule, self.bundle(capsule, identity=self.identity(capsule, repository_full_name="other/repo")))

    def test_wrong_nonce_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "identity nonce mismatch"):
            self.verify(capsule, self.bundle(capsule, identity=self.identity(capsule, capsule_nonce="nonce:other")))

    def test_missing_role_fails(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule, roles=["repository-maintainer"])
        with self.assertRaisesRegex(AttestationError, "missing required roles"):
            self.verify(capsule, self.bundle(capsule, identity=identity))

    def test_missing_mfa_fails(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule, auth_methods=["password"])
        with self.assertRaisesRegex(AttestationError, "explicitly prove mfa"):
            self.verify(capsule, self.bundle(capsule, identity=identity))

    def test_expired_assertion_fails(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule, expires_at_unix=NOW + 20)
        with self.assertRaisesRegex(AttestationError, "identity assertion has expired"):
            self.verify(capsule, self.bundle(capsule, identity=identity), at_unix=NOW + 21)

    def test_not_yet_valid_assertion_fails(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule, not_before_unix=NOW + 20)
        with self.assertRaisesRegex(AttestationError, "not yet valid"):
            self.verify(capsule, self.bundle(capsule, identity=identity), at_unix=NOW + 10)

    def test_revoked_idp_key_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "identity assertion trusted key is revoked"):
            self.verify(capsule, store=self.identity_store(idp_revoked_at=NOW + 1))

    def test_revoked_kms_key_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "KMS attestation trusted key is revoked"):
            self.verify(capsule, store=self.identity_store(kms_revoked_at=NOW + 1))

    def test_wrong_kms_public_key_fingerprint_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, public_key_sha256="f" * 64)
        with self.assertRaisesRegex(AttestationError, "fingerprint"):
            self.verify(capsule, self.bundle(capsule, kms=kms))

    def test_wrong_kms_governance_key_id_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, governance_key_id="governance-key:other")
        with self.assertRaisesRegex(AttestationError, "KMS governance key mismatch"):
            self.verify(capsule, self.bundle(capsule, kms=kms))

    def test_wrong_capsule_signature_digest_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, capsule_signature_sha256="f" * 64)
        with self.assertRaisesRegex(AttestationError, "signature digest mismatch"):
            self.verify(capsule, self.bundle(capsule, kms=kms))

    def test_kms_subject_substitution_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, subject_id="user:mallory")
        with self.assertRaisesRegex(AttestationError, "KMS subject mismatch"):
            self.verify(capsule, self.bundle(capsule, kms=kms))

    def test_cross_tenant_substitution_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, tenant_id="tenant:other")
        store = self.identity_store(kms_tenants=[TENANT, "tenant:other"])
        with self.assertRaisesRegex(AttestationError, "IdP/KMS tenant mismatch"):
            self.verify(capsule, self.bundle(capsule, kms=kms), store=store)

    def test_hardware_policy_fails_closed(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule, hardware_protection="software")
        with self.assertRaisesRegex(AttestationError, "hardware protection"):
            self.verify(capsule, self.bundle(capsule, kms=kms))

    def test_identity_signature_tampering_fails(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule)
        replacement = "A" if identity.signature_b64url[-1] != "A" else "B"
        tampered = SignedIdentityAssertion(
            identity.claims,
            identity.payload_sha256,
            identity.signature_b64url[:-1] + replacement,
        )
        with self.assertRaisesRegex(AttestationError, "identity assertion signature"):
            self.verify(capsule, self.bundle(capsule, identity=tampered))

    def test_kms_signature_tampering_fails(self) -> None:
        capsule = self.capsule()
        kms = self.kms(capsule)
        replacement = "A" if kms.signature_b64url[-1] != "A" else "B"
        tampered = SignedKmsAttestation(
            kms.claims, kms.payload_sha256, kms.signature_b64url[:-1] + replacement
        )
        with self.assertRaisesRegex(AttestationError, "KMS attestation signature"):
            self.verify(capsule, self.bundle(capsule, kms=tampered))

    def test_bundle_hash_tampering_fails(self) -> None:
        document = self.bundle(self.capsule()).as_document()
        document["capsule_sha256"] = "f" * 64
        with self.assertRaisesRegex(AttestationError, "bundle_sha256 mismatch"):
            IdentityAttestationBundle.from_document(document)

    def test_trust_store_hash_tampering_fails(self) -> None:
        document = self.identity_store().as_document()
        document["required_roles"] = []
        with self.assertRaisesRegex(AttestationError, "trust_store_sha256 mismatch"):
            IdentityTrustStore.from_document(document)

    def test_replay_guard_rejects_second_consumption(self) -> None:
        capsule = self.capsule()
        bundle = self.bundle(capsule)
        guard = IdentityReplayGuard()
        self.verify(capsule, bundle, replay_guard=guard, consume_replay=True)
        with self.assertRaisesRegex(AttestationError, "replay detected"):
            self.verify(capsule, bundle, replay_guard=guard, consume_replay=True)

    def test_session_binding_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "session mismatch"):
            self.verify(capsule, expected_session_sha256="f" * 64)

    def test_tenant_binding_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "tenant mismatch"):
            self.verify(capsule, expected_tenant_id="tenant:other")

    def test_organization_binding_fails(self) -> None:
        capsule = self.capsule()
        with self.assertRaisesRegex(AttestationError, "organization mismatch"):
            self.verify(capsule, expected_organization_id="org:other")

    def test_service_account_is_explicit_not_inferred(self) -> None:
        capsule = self.capsule()
        identity = self.identity(capsule, service_account=True)
        result = self.verify(capsule, self.bundle(capsule, identity=identity))
        self.assertIs(result["service_account"], True)

    def test_inactive_identity_rejected_at_contract_boundary(self) -> None:
        with self.assertRaisesRegex(AttestationError, "identity_status must be active"):
            self.identity(self.capsule(), identity_status="disabled")

    def test_inactive_kms_key_rejected_at_contract_boundary(self) -> None:
        with self.assertRaisesRegex(AttestationError, "key_status must be active"):
            self.kms(self.capsule(), key_status="disabled")

    def test_assertion_ttl_hard_limit(self) -> None:
        with self.assertRaisesRegex(AttestationError, "TTL exceeds maximum"):
            self.identity(self.capsule(), expires_at_unix=NOW + 3601)

    def test_evidence_contains_no_private_keys_or_tokens(self) -> None:
        capsule = self.capsule()
        result = self.verify(capsule)
        serialized = json.dumps(
            {
                "bundle": self.bundle(capsule).as_document(),
                "store": self.identity_store().as_document(),
                "verification": result,
            }
        )
        self.assertNotIn("BEGIN PRIVATE KEY", serialized)
        self.assertNotIn("secret-token-value", serialized)
        self.assertFalse(result["authority"]["automatic_write_authorization"])
        self.assertFalse(result["authority"]["kms_invocation_ownership"])


if __name__ == "__main__":
    unittest.main()
