#!/usr/bin/env python3
"""Generate and verify a complete Portable Action Receipt v1.2 fixture."""

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
    IdentityAttestationBundle,
    IdentityTrustStore,
    canonical_sha256,
    issue_fixture_identity_assertion,
    issue_fixture_kms_attestation,
)
from sdk.liminal_portable_receipt import (
    ActionEvidence,
    ProjectionLedger,
    RecoveryEvidence,
    build_rinse_supersession_fixture,
    issue_portable_receipt_from_evidence,
    project_cml_memory_pack,
    project_liminaldb_event_inputs,
    project_proofpath_authorization_records,
    verify_portable_receipt,
)

NOW = 2_100_000_000
REPOSITORY = "safal207/LiminalOSAI"
AUDIENCE = "liminal-github-pilot"
SUBJECT = "user:alex"
TENANT = "tenant:liminal"
ORGANIZATION = "org:liminal"
SESSION_SHA = hashlib.sha256(b"portable-receipt-self-check-session").hexdigest()
CHECKED_HEAD = "1" * 40
SOURCE_HEAD = "2" * 40
RESULT_HEAD = "3" * 40


def write_json(path: Path, value: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)


def action(
    *,
    step_id: str,
    call_id: str,
    action_name: str,
    effect: str,
    safe_bindings: dict,
    safe_expectations: dict,
    authorized: bool = False,
) -> ActionEvidence:
    return ActionEvidence.build(
        step_id=step_id,
        call_id=call_id,
        action=action_name,
        effect=effect,
        request_sha256=hashlib.sha256(f"request:{call_id}".encode()).hexdigest(),
        resolved_arguments_sha256=hashlib.sha256(f"args:{call_id}".encode()).hexdigest(),
        runtime_status="success",
        locator_sha256=hashlib.sha256(f"locator:{call_id}".encode()).hexdigest(),
        connected_receipt_sha256=hashlib.sha256(f"connected:{call_id}".encode()).hexdigest(),
        raw_response_sha256=hashlib.sha256(f"raw:{call_id}".encode()).hexdigest(),
        normalized_payload_sha256=hashlib.sha256(f"payload:{call_id}".encode()).hexdigest(),
        authorization_event_ids=[f"authorization:{call_id}"] if authorized else [],
        authorization_event_sha256s=[hashlib.sha256(f"authorization:{call_id}".encode()).hexdigest()] if authorized else [],
        recorder_event_id=call_id,
        recorder_head_sha256=hashlib.sha256(f"recorder:{call_id}".encode()).hexdigest(),
        host_trace_head_sha256=hashlib.sha256(f"host:{call_id}".encode()).hexdigest(),
        expectations_met=True,
        reconciled=False,
        safe_bindings=safe_bindings,
        safe_expectations=safe_expectations,
    )


def build(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    governance_private, governance_public = generate_ed25519_keypair()
    idp_private, idp_public = generate_ed25519_keypair()
    kms_private, kms_public = generate_ed25519_keypair()

    engine_roots = {
        "policy_sha256": "a" * 64,
        "snapshot_sha256": "b" * 64,
        "plan_sha256": "c" * 64,
        "approval_ledger_head_sha256": "d" * 64,
        "transaction_journal_head_sha256": "e" * 64,
    }
    subject = GovernanceSubject.from_value(
        {
            "policy_id": "policy:v1.2:self-check",
            "transaction_id": "transaction:v1.2:self-check",
            "repository_full_name": REPOSITORY,
            "policy_sha256": engine_roots["policy_sha256"],
            "snapshot_sha256": engine_roots["snapshot_sha256"],
            "plan_sha256": engine_roots["plan_sha256"],
            "approval_ledger_head_sha256": engine_roots["approval_ledger_head_sha256"],
            "transaction_journal_anchor_sha256": engine_roots["transaction_journal_head_sha256"],
            "engine_evidence_sha256": canonical_sha256(engine_roots),
            "decision": "allow",
            "approval_status": "ready",
        }
    )
    capsule_claims = CapsuleClaims(
        capsule_id="capsule:v1.2:self-check",
        issuer_id="issuer:liminal-governance",
        subject_id=SUBJECT,
        key_id="governance-key:v1",
        algorithm=GOVERNANCE_ALGORITHM,
        audience=AUDIENCE,
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        nonce="nonce:v1.2:self-check",
        subject=subject,
    )
    payload_hash = canonical_sha256(capsule_claims.payload())
    unsigned_capsule = SignedGovernanceCapsule(capsule_claims, payload_hash, "AA")
    capsule = SignedGovernanceCapsule.from_document(
        SignedGovernanceCapsule(
            capsule_claims,
            payload_hash,
            base64url_encode(sign_ed25519(governance_private, unsigned_capsule.signed_message)),
        ).as_document()
    )
    governance_store = GovernanceTrustStore.build(
        trust_store_id="governance-trust:v1.2:self-check",
        keys=[
            {
                "issuer_id": capsule_claims.issuer_id,
                "key_id": capsule_claims.key_id,
                "algorithm": GOVERNANCE_ALGORITHM,
                "public_key_pem": governance_public.decode(),
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

    with tempfile.TemporaryDirectory(prefix="liminal-v12-self-check-") as temporary:
        root = Path(temporary)
        governance_private_path = root / "governance-private.pem"
        idp_private_path = root / "idp-private.pem"
        kms_private_path = root / "kms-private.pem"
        write_private(governance_private_path, governance_private)
        write_private(idp_private_path, idp_private)
        write_private(kms_private_path, kms_private)
        identity = issue_fixture_identity_assertion(
            private_key_path=idp_private_path,
            assertion_id="idp-assertion:v1.2:self-check",
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
            capsule_nonce=capsule_claims.nonce,
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 300,
        )
        kms = issue_fixture_kms_attestation(
            private_key_path=kms_private_path,
            receipt_id="kms-receipt:v1.2:self-check",
            provider_id="mock-kms",
            attestation_key_id="mock-kms-attestation:v1",
            tenant_id=TENANT,
            subject_id=SUBJECT,
            key_resource_id="kms://liminal/governance-key",
            key_version_id="version:1",
            governance_key_id=capsule_claims.key_id,
            public_key_sha256=hashlib.sha256(governance_public).hexdigest(),
            hardware_protection="hsm",
            repository_full_name=REPOSITORY,
            capsule_nonce=capsule_claims.nonce,
            capsule_payload_sha256=capsule.payload_sha256,
            capsule_signature_sha256=hashlib.sha256(base64url_decode(capsule.signature_b64url)).hexdigest(),
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 300,
        )
        identity_store = IdentityTrustStore.build(
            trust_store_id="identity-trust:v1.2:self-check",
            required_roles=["governance-approver"],
            require_mfa=True,
            max_assertion_ttl_seconds=600,
            max_attestation_ttl_seconds=600,
            max_clock_skew_seconds=0,
            idp_keys=[
                {
                    "issuer": "https://idp.example.test",
                    "key_id": "idp-signing-key:v1",
                    "public_key_pem": idp_public.decode(),
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
                    "public_key_pem": kms_public.decode(),
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
        actions = (
            action(
                step_id="check-ci",
                call_id="call:ci",
                action_name="get_commit_combined_status",
                effect="read",
                safe_bindings={"repository_full_name": REPOSITORY, "commit_sha": CHECKED_HEAD},
                safe_expectations={"state": "success"},
            ),
            action(
                step_id="merge-pr",
                call_id="call:merge",
                action_name="merge_pull_request",
                effect="write",
                safe_bindings={"repository_full_name": REPOSITORY, "pr_number": 120, "expected_head_sha": CHECKED_HEAD},
                safe_expectations={"merged": True},
                authorized=True,
            ),
        )
        recovery = RecoveryEvidence.build(
            {
                "status": "completed",
                "completed_steps": [{"step_id": "check-ci"}, {"step_id": "merge-pr"}],
                "pending_step_ids": [],
                "failed_step_ids": [],
                "manual_recovery_required": True,
                "automatic_rollback": False,
                "automatic_pending_write_replay": False,
            }
        )
        receipt = issue_portable_receipt_from_evidence(
            private_key_path=governance_private_path,
            governance_capsule=capsule,
            identity_bundle=bundle,
            governance_trust_store=governance_store,
            identity_trust_store=identity_store,
            receipt_id="receipt:v1.2:self-check",
            intent_id="intent:v1.2:self-check",
            intent_sha256=hashlib.sha256(b"visible intent redacted by digest").hexdigest(),
            source_head_oid=SOURCE_HEAD,
            result_head_oid=RESULT_HEAD,
            policy_id=subject.policy_id,
            policy_sha256=subject.policy_sha256,
            snapshot_sha256=subject.snapshot_sha256,
            plan_sha256=subject.plan_sha256,
            approval_ledger_head_sha256=subject.approval_ledger_head_sha256,
            transaction_journal_final_sha256="f" * 64,
            actions=actions,
            recovery=recovery,
            issued_at_unix=NOW + 20,
            execution_verified_at_unix=NOW + 10,
            expected_session_sha256=SESSION_SHA,
            expected_tenant_id=TENANT,
            expected_organization_id=ORGANIZATION,
            expected_roles=["repository-maintainer"],
        )

    verification = verify_portable_receipt(
        receipt,
        governance_store,
        identity_store,
        expected_repository=REPOSITORY,
        expected_source_head_oid=SOURCE_HEAD,
        expected_result_head_oid=RESULT_HEAD,
    )
    proofpath = project_proofpath_authorization_records(receipt)
    cml = project_cml_memory_pack(receipt, source_commit=SOURCE_HEAD)
    liminaldb = project_liminaldb_event_inputs(receipt)
    rinse = build_rinse_supersession_fixture(receipt)

    write_json(output_dir / "portable-action-receipt.json", receipt.as_document())
    write_json(output_dir / "governance-trust-store.json", governance_store.as_document())
    write_json(output_dir / "identity-trust-store.json", identity_store.as_document())
    write_json(output_dir / "verification.json", verification)
    write_json(output_dir / "proofpath-authorization-records.json", proofpath)
    write_json(output_dir / "cml-memory-pack.json", cml)
    write_json(output_dir / "liminaldb-event-inputs.json", liminaldb)
    write_json(output_dir / "rinse-supersession.json", rinse)

    ledger_root = output_dir / "projection-ledger"
    ledger = ProjectionLedger(ledger_root)
    ledger.append(
        source_receipt_sha256=receipt.receipt_sha256,
        projection_profile=liminaldb["profile"],
        projection=liminaldb,
    )
    ledger.write_snapshot()
    reopened = ProjectionLedger(ledger_root)
    replay = reopened.verify_snapshot()
    write_json(output_dir / "projection-ledger-verification.json", replay)

    result = {
        "status": "valid",
        "receipt_sha256": receipt.receipt_sha256,
        "receipt_payload_sha256": receipt.payload_sha256,
        "actions_root_sha256": receipt.claims.actions_root_sha256,
        "proofpath_record_count": len(proofpath),
        "cml_pack_id": cml["pack_id"],
        "liminaldb_event_count": len(liminaldb["event_inputs"]),
        "rinse_source_receipt_preserved": rinse["supersession"]["source_receipt_preserved"],
        "projection_replay_equal": replay["replay_equal"],
        "fresh_authorization": verification["fresh_authorization"],
    }
    write_json(output_dir / "self-check-summary.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = build(Path(args.output_dir))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
