from __future__ import annotations

import copy
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
    IdentityAttestationBundle,
    IdentityTrustStore,
    canonical_sha256,
    issue_fixture_identity_assertion,
    issue_fixture_kms_attestation,
)
from sdk.liminal_portable_receipt import (
    AUTHORITY,
    PROOFPATH_PROFILE,
    PROOFPATH_SCHEMA,
    ActionEvidence,
    BoundaryEvidence,
    CIGateEvidence,
    PortableActionReceipt,
    ProjectionLedger,
    ReceiptError,
    RecoveryEvidence,
    build_rinse_supersession_fixture,
    issue_portable_receipt_from_evidence,
    project_cml_memory_pack,
    project_liminaldb_event_inputs,
    project_proofpath_authorization_records,
    project_rinse_trace_event,
    verify_portable_receipt,
)

NOW = 2_100_000_000
REPOSITORY = "safal207/LiminalOSAI"
AUDIENCE = "liminal-github-pilot"
SUBJECT = "user:alex"
TENANT = "tenant:liminal"
ORGANIZATION = "org:liminal"
SESSION_SHA = hashlib.sha256(b"portable-receipt-session").hexdigest()
CHECKED_HEAD = "1" * 40
SOURCE_HEAD = "2" * 40
RESULT_HEAD = "3" * 40


def _write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)


def _action(
    *,
    step_id: str,
    call_id: str,
    action: str,
    effect: str,
    safe_bindings: dict,
    safe_expectations: dict,
    authorization: bool = False,
    runtime_status: str = "success",
    expectations_met: bool = True,
) -> ActionEvidence:
    ids = [f"authorization:{call_id}"] if authorization else []
    hashes = [hashlib.sha256(f"auth:{call_id}".encode()).hexdigest()] if authorization else []
    return ActionEvidence.build(
        step_id=step_id,
        call_id=call_id,
        action=action,
        effect=effect,
        request_sha256=hashlib.sha256(f"request:{call_id}".encode()).hexdigest(),
        resolved_arguments_sha256=hashlib.sha256(f"args:{call_id}".encode()).hexdigest(),
        runtime_status=runtime_status,
        locator_sha256=hashlib.sha256(f"locator:{call_id}".encode()).hexdigest(),
        connected_receipt_sha256=hashlib.sha256(f"connected:{call_id}".encode()).hexdigest(),
        raw_response_sha256=hashlib.sha256(f"raw:{call_id}".encode()).hexdigest(),
        normalized_payload_sha256=hashlib.sha256(f"payload:{call_id}".encode()).hexdigest(),
        authorization_event_ids=ids,
        authorization_event_sha256s=hashes,
        recorder_event_id=call_id,
        recorder_head_sha256=hashlib.sha256(f"recorder:{call_id}".encode()).hexdigest(),
        host_trace_head_sha256=hashlib.sha256(f"host:{call_id}".encode()).hexdigest(),
        expectations_met=expectations_met,
        reconciled=False,
        safe_bindings=safe_bindings,
        safe_expectations=safe_expectations,
    )


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        governance_private, governance_public = generate_ed25519_keypair()
        idp_private, idp_public = generate_ed25519_keypair()
        kms_private, kms_public = generate_ed25519_keypair()
        self.governance_private = governance_private
        self.governance_public = governance_public
        self.private_path = root / "governance-private.pem"
        _write_private(self.private_path, governance_private)

        evidence = {
            "policy_sha256": "a" * 64,
            "snapshot_sha256": "b" * 64,
            "plan_sha256": "c" * 64,
            "approval_ledger_head_sha256": "d" * 64,
            "transaction_journal_head_sha256": "e" * 64,
        }
        self.subject = GovernanceSubject.from_value(
            {
                "policy_id": "policy:v1.2",
                "transaction_id": "transaction:v1.2",
                "repository_full_name": REPOSITORY,
                "policy_sha256": evidence["policy_sha256"],
                "snapshot_sha256": evidence["snapshot_sha256"],
                "plan_sha256": evidence["plan_sha256"],
                "approval_ledger_head_sha256": evidence["approval_ledger_head_sha256"],
                "transaction_journal_anchor_sha256": evidence["transaction_journal_head_sha256"],
                "engine_evidence_sha256": canonical_sha256(evidence),
                "decision": "allow",
                "approval_status": "ready",
            }
        )
        claims = CapsuleClaims(
            capsule_id="capsule:v1.2:test",
            issuer_id="issuer:liminal-governance",
            subject_id=SUBJECT,
            key_id="governance-key:v1",
            algorithm=GOVERNANCE_ALGORITHM,
            audience=AUDIENCE,
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 600,
            nonce="nonce:v1.2:test",
            subject=self.subject,
        )
        payload_hash = canonical_sha256(claims.payload())
        unsigned = SignedGovernanceCapsule(claims, payload_hash, "AA")
        self.capsule = SignedGovernanceCapsule.from_document(
            SignedGovernanceCapsule(
                claims,
                payload_hash,
                base64url_encode(sign_ed25519(governance_private, unsigned.signed_message)),
            ).as_document()
        )
        self.governance_store = GovernanceTrustStore.build(
            trust_store_id="governance-trust:v1.2:test",
            keys=[
                {
                    "issuer_id": claims.issuer_id,
                    "key_id": claims.key_id,
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

        idp_path = root / "idp-private.pem"
        kms_path = root / "kms-private.pem"
        _write_private(idp_path, idp_private)
        _write_private(kms_path, kms_private)
        identity = issue_fixture_identity_assertion(
            private_key_path=idp_path,
            assertion_id="idp-assertion:v1.2:test",
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
            private_key_path=kms_path,
            receipt_id="kms-receipt:v1.2:test",
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
            capsule_payload_sha256=self.capsule.payload_sha256,
            capsule_signature_sha256=hashlib.sha256(base64url_decode(self.capsule.signature_b64url)).hexdigest(),
            issued_at_unix=NOW,
            not_before_unix=NOW,
            expires_at_unix=NOW + 300,
        )
        self.identity_store = IdentityTrustStore.build(
            trust_store_id="identity-trust:v1.2:test",
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
        self.bundle = IdentityAttestationBundle.build(
            identity_assertion=identity,
            kms_attestation=kms,
            capsule_sha256=self.capsule.capsule_sha256,
            capsule_payload_sha256=self.capsule.payload_sha256,
        )
        self.actions = (
            _action(
                step_id="check-ci",
                call_id="call:ci",
                action="get_commit_combined_status",
                effect="read",
                safe_bindings={"repository_full_name": REPOSITORY, "commit_sha": CHECKED_HEAD},
                safe_expectations={"state": "success"},
            ),
            _action(
                step_id="merge-pr",
                call_id="call:merge",
                action="merge_pull_request",
                effect="write",
                authorization=True,
                safe_bindings={"repository_full_name": REPOSITORY, "pr_number": 120, "expected_head_sha": CHECKED_HEAD},
                safe_expectations={"merged": True},
            ),
        )
        self.recovery = RecoveryEvidence.build(
            {
                "schema_version": "test-recovery-v1",
                "transaction_id": self.subject.transaction_id,
                "status": "completed",
                "completed_steps": [
                    {"step_id": "check-ci", "action": "get_commit_combined_status", "effect": "read", "reversible": True, "recovery_plan": "none", "locator": "ci"},
                    {"step_id": "merge-pr", "action": "merge_pull_request", "effect": "write", "reversible": False, "recovery_plan": "manual", "locator": "merge"},
                ],
                "pending_step_ids": [],
                "failed_step_ids": [],
                "manual_recovery_required": True,
                "automatic_rollback": False,
                "automatic_pending_write_replay": False,
                "authority": {"automatic_rollback": False},
            }
        )
        self.receipt = self.issue()

    def issue(self, **overrides) -> PortableActionReceipt:
        values = {
            "private_key_path": self.private_path,
            "governance_capsule": self.capsule,
            "identity_bundle": self.bundle,
            "governance_trust_store": self.governance_store,
            "identity_trust_store": self.identity_store,
            "receipt_id": "receipt:v1.2:test",
            "intent_id": "intent:v1.2:test",
            "intent_sha256": hashlib.sha256(b"raw user intent is never embedded").hexdigest(),
            "source_head_oid": SOURCE_HEAD,
            "result_head_oid": RESULT_HEAD,
            "policy_id": self.subject.policy_id,
            "policy_sha256": self.subject.policy_sha256,
            "snapshot_sha256": self.subject.snapshot_sha256,
            "plan_sha256": self.subject.plan_sha256,
            "approval_ledger_head_sha256": self.subject.approval_ledger_head_sha256,
            "transaction_journal_final_sha256": "f" * 64,
            "actions": self.actions,
            "recovery": self.recovery,
            "issued_at_unix": NOW + 20,
            "execution_verified_at_unix": NOW + 10,
            "expected_session_sha256": SESSION_SHA,
            "expected_tenant_id": TENANT,
            "expected_organization_id": ORGANIZATION,
            "expected_roles": ["repository-maintainer"],
        }
        values.update(overrides)
        return issue_portable_receipt_from_evidence(**values)


class PortableReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="portable-receipt-test-")
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self, receipt=None, **kwargs):
        return verify_portable_receipt(
            receipt or self.fixture.receipt,
            self.fixture.governance_store,
            self.fixture.identity_store,
            **kwargs,
        )

    def tampered(self, mutator):
        value = copy.deepcopy(self.fixture.receipt.as_document())
        mutator(value)
        return value

    def test_01_issue_and_verify(self):
        result = self.verify()
        self.assertEqual(result["status"], "valid")

    def test_02_signature_is_ed25519_64_bytes(self):
        self.assertEqual(len(base64url_decode(self.fixture.receipt.signature_b64url)), 64)

    def test_03_receipt_authority_is_observation_only(self):
        result = self.verify()
        self.assertFalse(result["fresh_authorization"])
        self.assertFalse(result["authority"]["execution_authority"])
        self.assertFalse(result["authority"]["automatic_write_authorization"])

    def test_04_payload_tamper_rejected(self):
        value = self.tampered(lambda doc: doc["claims"].__setitem__("intent_sha256", "9" * 64))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_05_signature_tamper_rejected(self):
        value = self.tampered(lambda doc: doc.__setitem__("signature_b64url", ("A" if doc["signature_b64url"][0] != "A" else "B") + doc["signature_b64url"][1:]))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_06_unknown_receipt_field_rejected(self):
        value = self.fixture.receipt.as_document()
        value["unexpected"] = True
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_07_unknown_schema_rejected(self):
        value = self.fixture.receipt.as_document()
        value["schema_version"] = "future-v9"
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_08_noncanonical_signature_encoding_rejected(self):
        value = self.fixture.receipt.as_document()
        value["signature_b64url"] += "="
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_09_embedded_capsule_tamper_rejected(self):
        value = self.tampered(lambda doc: doc["governance_capsule"].__setitem__("payload_sha256", "7" * 64))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_10_embedded_identity_bundle_tamper_rejected(self):
        value = self.tampered(lambda doc: doc["identity_bundle"].__setitem__("bundle_sha256", "8" * 64))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_11_wrong_expected_repository_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(expected_repository="safal207/other")

    def test_12_wrong_source_head_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(expected_source_head_oid="4" * 40)

    def test_13_wrong_result_head_rejected(self):
        with self.assertRaises(ReceiptError):
            self.verify(expected_result_head_oid="5" * 40)

    def test_14_final_journal_tamper_rejected(self):
        value = self.tampered(lambda doc: doc["claims"].__setitem__("transaction_journal_final_sha256", "6" * 64))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_15_final_engine_hash_tamper_rejected(self):
        value = self.tampered(lambda doc: doc["claims"].__setitem__("final_engine_evidence_sha256", "6" * 64))
        with self.assertRaises(ReceiptError):
            self.verify(value)

    def test_16_action_request_tamper_rejected(self):
        value = self.fixture.receipt.as_document()
        value["claims"]["actions"][0]["request_sha256"] = "6" * 64
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_17_action_result_tamper_rejected(self):
        value = self.fixture.receipt.as_document()
        value["claims"]["actions"][0]["raw_response_sha256"] = "6" * 64
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_18_write_action_requires_explicit_authorization(self):
        with self.assertRaises(ReceiptError):
            _action(
                step_id="unauthorized-write",
                call_id="call:unauthorized",
                action="merge_pull_request",
                effect="write",
                safe_bindings={"expected_head_sha": CHECKED_HEAD},
                safe_expectations={"merged": True},
                authorization=False,
            )

    def test_19_action_root_tamper_rejected(self):
        value = self.fixture.receipt.as_document()
        value["claims"]["actions_root_sha256"] = "6" * 64
        with self.assertRaises(ReceiptError):
            PortableActionReceipt.from_document(value)

    def test_20_ci_exact_head_is_derived(self):
        gate = self.fixture.receipt.claims.ci_gate
        self.assertTrue(gate.observed)
        self.assertTrue(gate.exact_head_verified)
        self.assertEqual(gate.checked_commit_oid, CHECKED_HEAD)
        self.assertEqual(gate.merge_expected_head_oid, CHECKED_HEAD)

    def test_21_ci_exact_head_requires_success(self):
        with self.assertRaises(ReceiptError):
            CIGateEvidence.build(
                observed=True,
                checked_commit_oid=CHECKED_HEAD,
                state="failure",
                merge_expected_head_oid=CHECKED_HEAD,
                exact_head_verified=True,
            )

    def test_22_unobserved_ci_cannot_claim_exact_head(self):
        with self.assertRaises(ReceiptError):
            CIGateEvidence.build(
                observed=False,
                checked_commit_oid=CHECKED_HEAD,
                state="not_observed",
                merge_expected_head_oid=None,
                exact_head_verified=False,
            )

    def test_23_capability_is_explicitly_pending(self):
        boundary = self.fixture.receipt.claims.capability
        self.assertEqual(boundary.status, "not_implemented")
        self.assertEqual(boundary.root_sha256, "0" * 64)

    def test_24_containment_is_explicitly_pending(self):
        boundary = self.fixture.receipt.claims.containment
        self.assertEqual(boundary.status, "not_implemented")
        self.assertEqual(boundary.root_sha256, "0" * 64)

    def test_25_pending_boundary_cannot_claim_nonzero_root(self):
        with self.assertRaises(ReceiptError):
            BoundaryEvidence.from_value(
                {"profile_id": "future", "status": "not_implemented", "root_sha256": "1" * 64},
                "boundary",
            )

    def test_26_completed_receipt_cannot_have_failed_steps(self):
        bad_recovery = RecoveryEvidence.build(
            {
                "status": "completed",
                "completed_steps": [{"step_id": "check-ci"}],
                "pending_step_ids": [],
                "failed_step_ids": ["merge-pr"],
                "manual_recovery_required": True,
                "automatic_rollback": False,
                "automatic_pending_write_replay": False,
            }
        )
        with self.assertRaises(ReceiptError):
            self.fixture.issue(recovery=bad_recovery)

    def test_27_recovery_cannot_claim_auto_rollback(self):
        with self.assertRaises(ReceiptError):
            RecoveryEvidence.build(
                {
                    "status": "halted",
                    "completed_steps": [],
                    "pending_step_ids": [],
                    "failed_step_ids": ["x"],
                    "manual_recovery_required": True,
                    "automatic_rollback": True,
                    "automatic_pending_write_replay": False,
                }
            )

    def test_28_receipt_excludes_private_key_material(self):
        text = json.dumps(self.fixture.receipt.as_document(), sort_keys=True)
        self.assertNotIn("BEGIN PRIVATE KEY", text)

    def test_29_receipt_excludes_raw_user_intent(self):
        text = json.dumps(self.fixture.receipt.as_document(), sort_keys=True)
        self.assertNotIn("raw user intent is never embedded", text)

    def test_30_receipt_is_digest_only_for_connector_payload(self):
        text = json.dumps(self.fixture.receipt.as_document(), sort_keys=True)
        self.assertNotIn("secret-token-value", text)
        self.assertIn("normalized_payload_sha256", text)

    def test_31_historical_verification_survives_evidence_expiry(self):
        # Verification uses the signed historical execution time, not wall-clock now.
        result = self.verify()
        self.assertEqual(result["historical_evidence_time_unix"], NOW + 10)

    def test_32_proofpath_projection_uses_exact_profile(self):
        records = project_proofpath_authorization_records(self.fixture.receipt)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["schema"], PROOFPATH_SCHEMA)
        self.assertEqual(records[0]["profile"], PROOFPATH_PROFILE)

    def test_33_proofpath_projection_is_consumed_not_fresh_authority(self):
        record = project_proofpath_authorization_records(self.fixture.receipt)[0]
        self.assertEqual(record["consumption_state"], "CONSUMED")
        self.assertEqual(record["current_state"], "CONSUMED")
        self.assertIn("grants no fresh authority", record["claim_boundary"])

    def test_34_cml_projection_denies_execution_and_merge_authority(self):
        pack = project_cml_memory_pack(self.fixture.receipt, source_commit=SOURCE_HEAD)
        self.assertFalse(pack["manifest"]["execution_authority"])
        self.assertFalse(pack["manifest"]["merge_authority"])
        self.assertFalse(pack["manifest"]["contains_private_data"])

    def test_35_cml_projection_is_deterministic(self):
        first = project_cml_memory_pack(self.fixture.receipt, source_commit=SOURCE_HEAD)
        second = project_cml_memory_pack(self.fixture.receipt, source_commit=SOURCE_HEAD)
        self.assertEqual(first, second)
        self.assertEqual(len(first["pack_id"]), 64)

    def test_36_liminaldb_projection_preserves_independent_dimensions(self):
        packet = project_liminaldb_event_inputs(self.fixture.receipt)
        kinds = [event["kind"] for event in packet["event_inputs"]]
        self.assertEqual(kinds, ["authorization", "observation", "observation", "response_integrity", "continuity_snapshot"])
        self.assertTrue(packet["projection_boundary"]["durability_only"])
        self.assertEqual(packet["projection_boundary"]["authority_effect"], "none")

    def test_37_liminaldb_projection_does_not_claim_causal_validation(self):
        packet = project_liminaldb_event_inputs(self.fixture.receipt)
        for event in packet["event_inputs"]:
            dimensions = event.get("dimensions")
            if dimensions:
                self.assertEqual(dimensions["causal_validity"], "NOT_EVALUATED")

    def test_38_rinse_trace_is_hash_only_and_immutable_reference(self):
        trace = project_rinse_trace_event(self.fixture.receipt)
        self.assertEqual(trace["id"], f"receipt:{self.fixture.receipt.receipt_sha256}")
        self.assertTrue(trace["context"]["source_receipt_immutable"])
        self.assertEqual(trace["context"]["authority_effect"], "none")

    def test_39_rinse_supersession_preserves_source_receipt(self):
        fixture = build_rinse_supersession_fixture(self.fixture.receipt)
        self.assertTrue(fixture["supersession"]["source_receipt_preserved"])
        self.assertEqual(fixture["source_receipt_sha256"], self.fixture.receipt.receipt_sha256)
        ids = [item["source_trace_ids"] for item in fixture["interpretations"]]
        self.assertEqual(ids[0], ids[1])

    def test_40_projection_ledger_snapshot_reopen_equals_full_replay(self):
        ledger_root = self.root / "ledger"
        packet = project_liminaldb_event_inputs(self.fixture.receipt)
        ledger = ProjectionLedger(ledger_root)
        ledger.append(
            source_receipt_sha256=self.fixture.receipt.receipt_sha256,
            projection_profile=packet["profile"],
            projection=packet,
        )
        snapshot = ledger.write_snapshot()
        reopened = ProjectionLedger(ledger_root)
        verified = reopened.verify_snapshot()
        self.assertEqual(snapshot["snapshot_sha256"], verified["snapshot_sha256"])
        self.assertTrue(verified["replay_equal"])

    def test_41_projection_ledger_rejects_duplicate_receipt(self):
        ledger = ProjectionLedger(self.root / "ledger-duplicate")
        packet = project_liminaldb_event_inputs(self.fixture.receipt)
        kwargs = {
            "source_receipt_sha256": self.fixture.receipt.receipt_sha256,
            "projection_profile": packet["profile"],
            "projection": packet,
        }
        ledger.append(**kwargs)
        with self.assertRaises(ReceiptError):
            ledger.append(**kwargs)

    def test_42_projection_ledger_detects_tamper(self):
        ledger = ProjectionLedger(self.root / "ledger-tamper")
        packet = project_liminaldb_event_inputs(self.fixture.receipt)
        ledger.append(
            source_receipt_sha256=self.fixture.receipt.receipt_sha256,
            projection_profile=packet["profile"],
            projection=packet,
        )
        raw = json.loads(ledger.journal_path.read_text().strip())
        raw["projection_sha256"] = "9" * 64
        ledger.journal_path.write_text(json.dumps(raw) + "\n")
        with self.assertRaises(ReceiptError):
            ledger.verify()

    def test_43_wrong_receipt_signing_key_rejected_at_issue(self):
        private, _ = generate_ed25519_keypair()
        path = self.root / "wrong-private.pem"
        _write_private(path, private)
        with self.assertRaises(ReceiptError):
            self.fixture.issue(private_key_path=path)

    def test_44_safe_binding_rejects_secret_shaped_extra_key(self):
        with self.assertRaises(ReceiptError):
            _action(
                step_id="safe-map",
                call_id="call:safe",
                action="get_commit_combined_status",
                effect="read",
                safe_bindings={"commit_sha": CHECKED_HEAD, "token": "secret-token-value"},
                safe_expectations={"state": "success"},
            )


if __name__ == "__main__":
    unittest.main()
