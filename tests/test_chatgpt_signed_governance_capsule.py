from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_governance_capsule import (
    ALGORITHM,
    AUTHORITY,
    MAX_CAPSULE_TTL_SECONDS,
    CapsuleError,
    GovernanceCapsuleSession,
    GovernanceTrustStore,
    SignedGovernanceCapsule,
    generate_ed25519_keypair,
    issue_capsule,
    verify_capsule,
    verify_capsule_against_engine,
)
from sdk.liminal_governance_capsule._contracts import canonical_sha256

NOW = 1_800_000_000
REPO = "safal207/LiminalOSAI"
AUDIENCE = "github-transaction-executor"


class FakeJournal:
    def __init__(self, anchor: str):
        self.document = {
            "entries": [{"entry_sha256": anchor}],
            "head_sha256": anchor,
        }

    def read(self):
        return copy.deepcopy(self.document)

    def extend(self, digest: str):
        self.document["entries"].append({"entry_sha256": digest})
        self.document["head_sha256"] = digest


class FakeOrchestrator:
    def __init__(self, anchor: str):
        self.journal = FakeJournal(anchor)

    def prepare_next(self):
        return {"next_step": None}

    def authorize_step(self, **kwargs):
        return kwargs

    def run_next(self, connector):
        return {"status": "completed"}

    def run(self, connector):
        return {"status": "completed"}

    def record_user_message(self, **kwargs):
        return kwargs

    def record_assistant_draft(self, **kwargs):
        return kwargs

    def record_claim(self, **kwargs):
        return kwargs

    def seal(self, **kwargs):
        return kwargs

    def export_live_session(self, output_path):
        Path(output_path).write_text("{}")
        return {"output_path": str(output_path)}


class FakeEngine:
    def __init__(self):
        self.anchor = "a" * 64
        self.orchestrator = FakeOrchestrator(self.anchor)
        self.state = {
            "policy_id": "policy-1",
            "policy_sha256": "b" * 64,
            "snapshot_sha256": "c" * 64,
            "plan_sha256": "d" * 64,
            "transaction_id": "transaction-1",
            "repository_full_name": REPO,
            "decision": "allow",
            "approval": {"status": "ready", "head_sha256": "e" * 64},
            "transaction": {"journal": {"head_sha256": self.anchor}},
        }

    def verify(self, allow_pending=False):
        value = copy.deepcopy(self.state)
        value["transaction"]["journal"]["head_sha256"] = (
            self.orchestrator.journal.read()["head_sha256"]
        )
        return value

    def evidence_summary(self):
        state = self.verify(allow_pending=True)
        values = {
            "policy_sha256": state["policy_sha256"],
            "snapshot_sha256": state["snapshot_sha256"],
            "plan_sha256": state["plan_sha256"],
            "approval_ledger_head_sha256": state["approval"]["head_sha256"],
            "transaction_journal_head_sha256": state["transaction"]["journal"]["head_sha256"],
        }
        return {**values, "engine_evidence_sha256": canonical_sha256(values)}

    def prepare_next(self):
        return {
            "next_step": None,
            "approval_status": self.state["approval"]["status"],
            "policy_decision": self.state["decision"],
        }

    def authorize_step(self, **kwargs):
        return self.orchestrator.authorize_step(**kwargs)

    def run_next(self, connector):
        return self.orchestrator.run_next(connector)

    def run(self, connector):
        return self.orchestrator.run(connector)

    def record_user_message(self, **kwargs):
        return self.orchestrator.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs):
        return self.orchestrator.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs):
        return self.orchestrator.record_claim(**kwargs)

    def seal(self, **kwargs):
        return self.orchestrator.seal(**kwargs)

    def export_live_session(self, output_path):
        return self.orchestrator.export_live_session(output_path)


class GovernanceCapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = generate_ed25519_keypair()
        cls.other_private, cls.other_public = generate_ed25519_keypair()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.private_path = self.root / "private.pem"
        self.private_path.write_bytes(self.private_key)
        self.engine = FakeEngine()

    def trust_store(self, **overrides):
        public_key = overrides.pop("public_key", self.public_key)
        key = {
            "issuer_id": overrides.pop("issuer_id", "issuer-1"),
            "key_id": overrides.pop("key_id", "key-1"),
            "algorithm": ALGORITHM,
            "public_key_pem": public_key.decode(),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "valid_from_unix": overrides.pop("valid_from_unix", NOW - 10_000),
            "valid_until_unix": overrides.pop("valid_until_unix", NOW + 10_000),
            "revoked_at_unix": overrides.pop("revoked_at_unix", None),
            "allowed_audiences": overrides.pop("allowed_audiences", [AUDIENCE]),
            "allowed_repositories": overrides.pop("allowed_repositories", [REPO]),
        }
        if overrides:
            raise AssertionError(f"unused overrides: {overrides}")
        return GovernanceTrustStore.build(
            trust_store_id="trust-1", keys=[key], max_clock_skew_seconds=0
        )

    def capsule(self, **overrides):
        values = {
            "private_key_path": self.private_path,
            "capsule_id": "capsule-1",
            "issuer_id": "issuer-1",
            "subject_id": "user:alex",
            "key_id": "key-1",
            "audience": AUDIENCE,
            "ttl_seconds": 600,
            "issued_at_unix": NOW,
            "nonce": "nonce-1",
        }
        values.update(overrides)
        return issue_capsule(self.engine, **values)

    def test_issue_and_verify(self):
        result = verify_capsule(self.capsule(), self.trust_store(), at_unix=NOW)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["repository_full_name"], REPO)

    def test_signature_is_ed25519_64_bytes(self):
        capsule = self.capsule()
        import base64
        raw = base64.urlsafe_b64decode(capsule.signature_b64url + "==")
        self.assertEqual(len(raw), 64)

    def test_payload_tampering_fails_closed(self):
        doc = self.capsule().as_document()
        doc["claims"]["audience"] = "other-audience"
        with self.assertRaisesRegex(CapsuleError, "payload_sha256 mismatch"):
            SignedGovernanceCapsule.from_document(doc)

    def test_signature_tampering_fails_closed(self):
        doc = self.capsule().as_document()
        doc["signature_b64url"] = (
            ("A" if doc["signature_b64url"][0] != "A" else "B")
            + doc["signature_b64url"][1:]
        )
        with self.assertRaisesRegex(CapsuleError, "signature verification failed"):
            verify_capsule(doc, self.trust_store(), at_unix=NOW)

    def test_wrong_public_key_fails(self):
        with self.assertRaisesRegex(CapsuleError, "signature verification failed"):
            verify_capsule(
                self.capsule(), self.trust_store(public_key=self.other_public), at_unix=NOW
            )

    def test_unknown_key_fails(self):
        with self.assertRaisesRegex(CapsuleError, "not trusted"):
            verify_capsule(
                self.capsule(key_id="untrusted"), self.trust_store(), at_unix=NOW
            )

    def test_expired_capsule_fails(self):
        capsule = self.capsule(ttl_seconds=10)
        with self.assertRaisesRegex(CapsuleError, "expired"):
            verify_capsule(capsule, self.trust_store(), at_unix=NOW + 11)

    def test_not_yet_valid_capsule_fails(self):
        capsule = self.capsule(not_before_delay_seconds=100)
        with self.assertRaisesRegex(CapsuleError, "not yet valid"):
            verify_capsule(capsule, self.trust_store(), at_unix=NOW)

    def test_trust_store_ttl_limit(self):
        store = GovernanceTrustStore.build(
            trust_store_id="short",
            max_ttl_seconds=60,
            max_clock_skew_seconds=0,
            keys=[self.trust_store().keys[0].payload()],
        )
        with self.assertRaisesRegex(CapsuleError, "TTL exceeds"):
            verify_capsule(self.capsule(ttl_seconds=61), store, at_unix=NOW)

    def test_hard_ttl_limit(self):
        with self.assertRaisesRegex(CapsuleError, "exceeds maximum"):
            self.capsule(ttl_seconds=MAX_CAPSULE_TTL_SECONDS + 1)

    def test_revoked_key_fails(self):
        with self.assertRaisesRegex(CapsuleError, "revoked"):
            verify_capsule(
                self.capsule(), self.trust_store(revoked_at_unix=NOW), at_unix=NOW
            )

    def test_key_validity_window_fails(self):
        with self.assertRaisesRegex(CapsuleError, "before trusted key validity"):
            verify_capsule(
                self.capsule(), self.trust_store(valid_from_unix=NOW + 1), at_unix=NOW
            )

    def test_wrong_audience_fails(self):
        with self.assertRaisesRegex(CapsuleError, "audience mismatch"):
            verify_capsule(
                self.capsule(), self.trust_store(), at_unix=NOW,
                expected_audience="wrong-audience",
            )

    def test_unpermitted_audience_fails(self):
        with self.assertRaisesRegex(CapsuleError, "not permitted"):
            verify_capsule(
                self.capsule(),
                self.trust_store(allowed_audiences=["other-audience"]),
                at_unix=NOW,
            )

    def test_wrong_repository_fails(self):
        with self.assertRaisesRegex(CapsuleError, "repository mismatch"):
            verify_capsule(
                self.capsule(), self.trust_store(), at_unix=NOW,
                expected_repository="safal207/other",
            )

    def test_wrong_plan_sha_fails(self):
        with self.assertRaisesRegex(CapsuleError, "plan SHA mismatch"):
            verify_capsule(
                self.capsule(), self.trust_store(), at_unix=NOW,
                expected_plan_sha256="f" * 64,
            )

    def test_wrong_policy_sha_fails(self):
        with self.assertRaisesRegex(CapsuleError, "policy SHA mismatch"):
            verify_capsule(
                self.capsule(), self.trust_store(), at_unix=NOW,
                expected_policy_sha256="f" * 64,
            )

    def test_trust_store_tampering_fails(self):
        doc = self.trust_store().as_document()
        doc["max_ttl_seconds"] -= 1
        with self.assertRaisesRegex(CapsuleError, "trust_store_sha256 mismatch"):
            GovernanceTrustStore.from_document(doc)

    def test_duplicate_trust_key_fails(self):
        key = self.trust_store().keys[0].payload()
        with self.assertRaisesRegex(CapsuleError, "duplicate"):
            GovernanceTrustStore.build(trust_store_id="dup", keys=[key, key])

    def test_malformed_signature_fails(self):
        doc = self.capsule().as_document()
        doc["signature_b64url"] = "***"
        with self.assertRaisesRegex(CapsuleError, "base64url"):
            SignedGovernanceCapsule.from_document(doc)

    def test_private_key_never_enters_capsule(self):
        text = json.dumps(self.capsule().as_document())
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn(self.private_key.decode().splitlines()[1], text)

    def test_capsule_excludes_reviewed_file_content(self):
        text = json.dumps(self.capsule().as_document())
        self.assertNotIn("safe governed fixture", text)

    def test_authority_does_not_claim_identity_verification(self):
        self.assertFalse(AUTHORITY["external_idp_verification"])
        self.assertFalse(AUTHORITY["identity_inference"])
        self.assertFalse(AUTHORITY["key_custody"])

    def test_issue_requires_ready_approvals(self):
        self.engine.state["approval"]["status"] = "pending"
        with self.assertRaisesRegex(CapsuleError, "approvals are ready"):
            self.capsule()

    def test_issue_requires_policy_allow(self):
        self.engine.state["decision"] = "deny"
        with self.assertRaisesRegex(CapsuleError, "policy-denied"):
            self.capsule()

    def test_engine_match_succeeds(self):
        result = verify_capsule_against_engine(
            self.capsule(), self.trust_store(), self.engine,
            at_unix=NOW, expected_audience=AUDIENCE,
        )
        self.assertEqual(result["engine_status"], "matched")

    def test_journal_may_extend_after_issuance(self):
        capsule = self.capsule()
        self.engine.orchestrator.journal.extend("9" * 64)
        result = verify_capsule_against_engine(
            capsule, self.trust_store(), self.engine,
            at_unix=NOW, expected_audience=AUDIENCE,
        )
        self.assertTrue(result["transaction_journal_anchor_is_ancestor"])
        self.assertEqual(result["current_transaction_journal_head_sha256"], "9" * 64)

    def test_approval_ledger_change_invalidates_capsule(self):
        capsule = self.capsule()
        self.engine.state["approval"]["head_sha256"] = "8" * 64
        with self.assertRaisesRegex(CapsuleError, "approval_ledger_head_sha256"):
            verify_capsule_against_engine(
                capsule, self.trust_store(), self.engine,
                at_unix=NOW, expected_audience=AUDIENCE,
            )

    def test_non_descendant_journal_invalidates_capsule(self):
        capsule = self.capsule()
        self.engine.orchestrator.journal.document = {
            "entries": [{"entry_sha256": "7" * 64}],
            "head_sha256": "7" * 64,
        }
        with self.assertRaisesRegex(CapsuleError, "not a descendant"):
            verify_capsule_against_engine(
                capsule, self.trust_store(), self.engine,
                at_unix=NOW, expected_audience=AUDIENCE,
            )

    def test_session_checks_expiry_before_execution(self):
        capsule_path = self.root / "capsule.json"
        trust_path = self.root / "trust.json"
        capsule_path.write_text(json.dumps(self.capsule(ttl_seconds=10).as_document()))
        trust_path.write_text(json.dumps(self.trust_store().as_document()))
        session = GovernanceCapsuleSession(
            self.engine,
            capsule_path=capsule_path,
            trust_store_path=trust_path,
            expected_audience=AUDIENCE,
            clock=lambda: NOW + 11,
        )
        with self.assertRaisesRegex(CapsuleError, "expired"):
            session.run_next(object())


if __name__ == "__main__":
    unittest.main()
