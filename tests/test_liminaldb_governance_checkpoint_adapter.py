from __future__ import annotations

import tempfile
import unittest

from sdk.liminal_durable_governance_fence import GovernanceWorld, SQLiteGovernanceStore
from sdk.liminal_effect_commit import ZERO_SHA256
from sdk.liminal_liminaldb_governance_checkpoint import (
    AUTHORITY,
    BRIDGE_RECEIPT_SCHEMA,
    CheckpointingGovernanceStore,
    LiminalDBMirrorError,
    SQLiteCheckpointMirrorJournal,
)
from sdk.liminal_post_sandbox_contracts import canonical_sha256


class Clock:
    def __init__(self, now=2_300_000_000_000):
        self.now = now

    def __call__(self):
        return self.now


class FakeBridge:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.tamper = None

    def __call__(self, envelope):
        if self.fail:
            raise RuntimeError("bridge unavailable with sensitive detail")
        self.calls.append(dict(envelope))
        n = len(self.calls)
        envelope_ref = "sha256:" + f"{n:064x}"
        checkpoint_ref = "sha256:" + f"{1000+n:064x}"
        event_hash = "sha256:" + f"{2000+n:064x}"
        head = "sha256:" + f"{3000+n:064x}"
        projection = "sha256:" + f"{4000+n:064x}"
        snapshot = "sha256:" + f"{5000+n:064x}"
        signer_id = "liminalosai-governance-bridge"
        key_id = "conformance-key-v0.1"
        receipt_body = {
            "schema": BRIDGE_RECEIPT_SCHEMA,
            "envelope_ref": envelope_ref,
            "root_id_sha256": envelope["root_id_sha256"],
            "transition_kind": envelope["transition_kind"],
            "generation_before": envelope["generation_before"],
            "generation_after": envelope["generation_after"],
            "world_before_sha256": envelope["world_before_sha256"],
            "world_after_sha256": envelope["world_after_sha256"],
            "reservation_sha256": envelope["reservation_sha256"],
            "operation_sha256": envelope["operation_sha256"],
            "upstream_receipt_sha256": envelope["upstream_receipt_sha256"],
            "event_hash": event_hash,
            "checkpoint_ref": checkpoint_ref,
            "event_chain_head": head,
            "last_sequence": n,
            "projection_digest": projection,
            "snapshot_digest": snapshot,
            "signer_id": signer_id,
            "key_id": key_id,
            "verification_status": "LOCAL_SIGNATURE_VERIFIED",
        }
        checkpoint_body = {
            "schema": "liminaldb.signed-checkpoint-manifest.v0.1",
            "checkpoint_profile": "org.liminaldb.signed-checkpoint.v0.1",
            "ledger_profile": "org.liminaldb.trustworthy-transition-ledger.v0.1",
            "storage_root_identity": "sha256:" + envelope["root_id_sha256"],
            "event_chain_head": head,
            "last_sequence": n,
            "wal_segment": 0,
            "wal_offset": n,
            "projection_digest": projection,
            "snapshot_digest": snapshot,
            "signer_id": signer_id,
            "key_id": key_id,
            "issued_at_ms": envelope["captured_at_ms"],
            "expires_at_ms": None,
            "previous_checkpoint_ref": None,
        }
        bundle = {
            "envelope": {"body": dict(envelope), "envelope_ref": envelope_ref},
            "receipt": {"body": receipt_body, "receipt_ref": "sha256:" + f"{6000+n:064x}"},
            "checkpoint": {
                "body": checkpoint_body,
                "manifest_ref": checkpoint_ref,
                "signature_algorithm": "Ed25519",
                "signature_hex": "ab" * 64,
            },
            "trusted_key": {
                "signer_id": signer_id,
                "key_id": key_id,
                "public_key_hex": "cd" * 32,
                "valid_from_ms": 0,
                "valid_until_ms": None,
                "revoked_at_ms": None,
            },
        }
        if self.tamper == "world_after":
            bundle["receipt"]["body"]["world_after_sha256"] = "f" * 64
        if self.tamper == "checkpoint_root":
            bundle["checkpoint"]["body"]["storage_root_identity"] = "sha256:" + "e" * 64
        return bundle


def world(seed):
    return GovernanceWorld.build(
        objective_state_sha256=seed * 64,
        causal_state_sha256=chr(ord(seed) + 1) * 64,
        runtime_context_sha256=chr(ord(seed) + 2) * 64,
    )


class LiminalDBGovernanceCheckpointAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.primary_path = self.temp.name + "/primary.sqlite"
        self.mirror_path = self.temp.name + "/mirror.sqlite"
        self.primary = SQLiteGovernanceStore(self.primary_path)
        self.journal = SQLiteCheckpointMirrorJournal(self.mirror_path)
        self.bridge = FakeBridge()
        self.clock = Clock()
        self.store = CheckpointingGovernanceStore(
            delegate=self.primary,
            journal=self.journal,
            bridge=self.bridge,
            clock_ms=self.clock,
        )
        self.root = "governance:test"

    def tearDown(self):
        self.temp.cleanup()

    def test_authority_is_evidence_only(self):
        self.assertTrue(AUTHORITY["checkpoint_evidence_only"])
        self.assertTrue(AUTHORITY["pending_before_primary_mutation"])
        self.assertTrue(AUTHORITY["fail_closed_on_bridge_failure"])
        self.assertFalse(AUTHORITY["primary_cas_authority"])
        self.assertFalse(AUTHORITY["automatic_mirror_expiry"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["network_authority"])
        self.assertFalse(AUTHORITY["credential_authority"])
        self.assertFalse(AUTHORITY["distributed_consensus"])

    def test_initialize_and_mutate_are_checkpointed_and_clear(self):
        first = self.store.initialize(root_id=self.root, world=world("1").as_document())
        self.assertEqual(first["generation"], 0)
        mirror = self.store.mirror_state_document(root_id=self.root)
        self.assertEqual(mirror["status"], "CLEAR")
        self.assertNotEqual(mirror["last_checkpoint_ref"], "sha256:" + ZERO_SHA256)
        self.assertEqual([x["event_kind"] for x in self.journal.history(root_id=self.root)], ["PENDING", "ACKED"])

        second_world = world("4")
        second = self.store.mutate_world(
            root_id=self.root,
            expected_generation=first["generation"],
            expected_world_sha256=first["world_sha256"],
            new_world=second_world.as_document(),
            transition_receipt_sha256="9" * 64,
        )
        self.assertEqual(second["generation"], 1)
        self.assertEqual(second["world_sha256"], second_world.world_sha256)
        self.assertEqual(self.bridge.calls[-1]["transition_kind"], "mutate")
        self.assertEqual(self.bridge.calls[-1]["generation_before"], 0)
        self.assertEqual(self.bridge.calls[-1]["generation_after"], 1)

    def test_reserve_and_commit_bind_reservation_payload_and_receipt(self):
        state = self.store.initialize(root_id=self.root, world=world("1").as_document())
        reservation_id = "reservation:test:1"
        reservation_payload = "8" * 64
        reserved = self.store.reserve_effect(
            root_id=self.root,
            expected_generation=state["generation"],
            expected_world_sha256=state["world_sha256"],
            reservation_id=reservation_id,
            reservation_payload_sha256=reservation_payload,
        )
        reserve_envelope = self.bridge.calls[-1]
        self.assertEqual(reserve_envelope["reservation_sha256"], canonical_sha256(reservation_id))
        self.assertEqual(reserve_envelope["operation_sha256"], reservation_payload)
        self.assertTrue(reserved["reservation_active"])

        after = self.store.commit_effect(
            root_id=self.root,
            expected_generation=state["generation"],
            expected_world_sha256=state["world_sha256"],
            reservation_id=reservation_id,
            reservation_payload_sha256=reservation_payload,
            new_world=world("4").as_document(),
            inner_commit_receipt_sha256="7" * 64,
        )
        commit_envelope = self.bridge.calls[-1]
        self.assertEqual(commit_envelope["transition_kind"], "commit")
        self.assertEqual(commit_envelope["upstream_receipt_sha256"], "7" * 64)
        self.assertEqual(after["generation"], 1)
        self.assertFalse(after["reservation_active"])

    def test_bridge_failure_after_primary_success_stays_pending_across_restart(self):
        state = self.store.initialize(root_id=self.root, world=world("1").as_document())
        self.bridge.fail = True
        with self.assertRaisesRegex(LiminalDBMirrorError, "liminaldb_checkpoint_failed_mirror_stuck"):
            self.store.mutate_world(
                root_id=self.root,
                expected_generation=state["generation"],
                expected_world_sha256=state["world_sha256"],
                new_world=world("4").as_document(),
                transition_receipt_sha256="9" * 64,
            )
        primary_after = self.primary.read_state(root_id=self.root)
        self.assertEqual(primary_after["generation"], 1)
        self.assertEqual(self.journal.state_document(root_id=self.root)["status"], "PENDING")

        restarted = CheckpointingGovernanceStore(
            delegate=SQLiteGovernanceStore(self.primary_path),
            journal=SQLiteCheckpointMirrorJournal(self.mirror_path),
            bridge=FakeBridge(),
            clock_ms=self.clock,
        )
        with self.assertRaisesRegex(LiminalDBMirrorError, "liminaldb_mirror_pending"):
            restarted.mutate_world(
                root_id=self.root,
                expected_generation=primary_after["generation"],
                expected_world_sha256=primary_after["world_sha256"],
                new_world=world("7").as_document(),
                transition_receipt_sha256="a" * 64,
            )
        self.clock.now += 10_000_000
        self.assertEqual(restarted.mirror_state_document(root_id=self.root)["status"], "PENDING")
        restarted.reconcile_mirror(
            root_id=self.root, trusted_reconciliation_receipt_sha256="b" * 64
        )
        self.assertEqual(restarted.mirror_state_document(root_id=self.root)["status"], "CLEAR")
        self.assertEqual(self.journal.history(root_id=self.root)[-1]["event_kind"], "RECONCILED")

    def test_tampered_bridge_bundle_fails_closed_and_keeps_pending(self):
        self.store.initialize(root_id=self.root, world=world("1").as_document())
        state = self.primary.read_state(root_id=self.root)
        self.bridge.tamper = "world_after"
        with self.assertRaisesRegex(LiminalDBMirrorError, "bridge_receipt_world_after_sha256_mismatch"):
            self.store.mutate_world(
                root_id=self.root,
                expected_generation=state["generation"],
                expected_world_sha256=state["world_sha256"],
                new_world=world("4").as_document(),
                transition_receipt_sha256="9" * 64,
            )
        self.assertEqual(self.journal.state_document(root_id=self.root)["status"], "PENDING")

    def test_primary_failure_is_conservatively_stuck(self):
        state = self.store.initialize(root_id=self.root, world=world("1").as_document())
        with self.assertRaisesRegex(LiminalDBMirrorError, "primary_mutate_failed_mirror_stuck"):
            self.store.mutate_world(
                root_id=self.root,
                expected_generation=99,
                expected_world_sha256=state["world_sha256"],
                new_world=world("4").as_document(),
                transition_receipt_sha256="9" * 64,
            )
        self.assertEqual(self.primary.read_state(root_id=self.root)["generation"], 0)
        self.assertEqual(self.journal.state_document(root_id=self.root)["status"], "PENDING")

    def test_checkpoint_root_tamper_is_rejected(self):
        self.bridge.tamper = "checkpoint_root"
        with self.assertRaisesRegex(LiminalDBMirrorError, "bridge_checkpoint_root_mismatch"):
            self.store.initialize(root_id=self.root, world=world("1").as_document())
        self.assertEqual(self.journal.state_document(root_id=self.root)["status"], "PENDING")


if __name__ == "__main__":
    unittest.main()
