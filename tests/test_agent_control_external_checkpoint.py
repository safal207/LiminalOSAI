"""External evidence freshness depends on an independently pinned latest tip."""
import copy
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, connect, digest
from sdk.liminal_agent_control.external_checkpoint import (
    CHECKPOINT_DOMAIN, GOVERNANCE_SCHEMA, ZERO_DIGEST, append_checkpoint, checkpoint_anchor,
    checkpoint_entries, governance_envelope_body, initialize_checkpoint_schema, verify_checkpoint_chain,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


@unittest.skipIf(Ed25519PrivateKey is None, "external checkpoint tests require cryptography")
class ExternalCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "external.sqlite"
        self.private = bytes.fromhex(digest("external-checkpoint-test-key"))
        self.key = Ed25519PrivateKey.from_private_bytes(self.private)
        self.pins = {"authority_id": "authority", "signer_id": "authority", "key_id": "authority-key",
                     "public_key": self.key.public_key().public_bytes_raw().hex()}
        self.db = connect(self.path)
        self.addCleanup(self.db.close)
        initialize_checkpoint_schema(self.db)

    def append(self, **overrides):
        fields = {**self.pins, "private_key": self.private, "root_id": "root", "epoch": 1,
            "kind": "ROOT_CREATED", "state_digest": digest("state"), "now": 100.0}
        fields.update(overrides)
        return append_checkpoint(self.db, **fields)

    def verify(self, entries=None, **overrides):
        fields = {**self.pins, **overrides}
        return verify_checkpoint_chain(checkpoint_entries(self.db, "authority") if entries is None else entries,
                                       **fields)

    def resign(self, entry, **changes):
        body = {key: value for key, value in copy.deepcopy(entry).items()
                if key not in {"signature", "checkpoint_digest"}}
        body.update(changes)
        signed = {**body, "signature": self.key.sign(CHECKPOINT_DOMAIN + canonical_bytes(body)).hex()}
        return {**signed, "checkpoint_digest": digest(signed)}

    def test_real_signatures_persist_and_latest_anchor_verifies(self):
        first = self.append()
        second = self.append(epoch=2, kind="STOPPED", now=101, receipt_digest=digest("stop-ack"))
        self.assertEqual((first["sequence"], second["sequence"]), (1, 2))
        self.assertEqual(second["previous_digest"], first["checkpoint_digest"])
        self.db.close()
        self.db = connect(self.path, create=False)
        self.addCleanup(self.db.close)
        result = self.verify(anchor=checkpoint_anchor(second))
        self.assertEqual(result["verification_status"], "EXTERNAL_ANCHORED_VERIFIED")
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["entries"], 2)

    def test_no_anchor_reports_local_signature_only(self):
        self.append()
        self.assertEqual(self.verify()["verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertFalse(self.verify()["execution_authorized"])

    def test_independent_latest_anchor_rejects_local_snapshot_rollback(self):
        first = self.append()
        old_database = Path(self.directory.name) / "old.sqlite"
        saved = sqlite3.connect(old_database)
        self.db.backup(saved)
        saved.close()
        second = self.append(epoch=2, kind="STOPPED", now=101)
        latest_external_pin = checkpoint_anchor(second)
        with connect(old_database) as restored:
            old_entries = checkpoint_entries(restored, "authority")
        self.assertEqual(self.verify(old_entries)["verification_status"], "LOCAL_SIGNATURE_ONLY")
        with self.assertRaisesRegex(ControlError, "ANCHOR_MISMATCH"):
            self.verify(old_entries, anchor=latest_external_pin)
        self.assertEqual(old_entries[-1], first)

    def test_anchor_rejects_truncation_old_anchor_and_signed_fork(self):
        first = self.append()
        second = self.append(now=101)
        fork = self.resign(second, state_digest=digest("fork"))
        for entries, anchor in (([first], checkpoint_anchor(second)),
                                ([first, second], checkpoint_anchor(first)),
                                ([first, fork], checkpoint_anchor(second))):
            with self.subTest(entries=entries), self.assertRaisesRegex(ControlError, "ANCHOR_MISMATCH"):
                self.verify(entries, anchor=anchor)

    def test_missing_duplicate_reordered_and_wrong_predecessor_fail(self):
        first = self.append()
        second = self.append(now=101)
        third = self.append(now=102)
        broken = self.resign(second, previous_digest=digest("not-first"))
        for entries in ([second, third], [first, third], [first, first], [second, first], [first, broken]):
            with self.subTest(entries=entries), self.assertRaisesRegex(ControlError, "CHAIN_BROKEN"):
                self.verify(entries)

    def test_digest_repaired_after_tamper_still_fails_signature(self):
        entry = self.append()
        entry["state_digest"] = digest("tampered")
        entry["checkpoint_digest"] = digest({key: value for key, value in entry.items() if key != "checkpoint_digest"})
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            self.verify([entry])

    def test_signed_epoch_and_clock_rollbacks_fail_before_append(self):
        first = self.append(epoch=4)
        for fields, error in (({"epoch": 3, "now": 101}, "EPOCH_ROLLBACK"),
                              ({"epoch": 4, "now": 99}, "CLOCK_ROLLBACK")):
            with self.subTest(fields=fields), self.assertRaisesRegex(ControlError, error):
                self.append(**fields)
            self.assertEqual(checkpoint_entries(self.db, "authority"), [first])

    def test_authority_global_order_allows_distinct_root_epoch(self):
        first = self.append(epoch=5)
        second = self.append(root_id="other-root", epoch=1, now=100)
        third = self.append(epoch=5, now=100)
        self.assertEqual([entry["sequence"] for entry in (first, second, third)], [1, 2, 3])
        self.verify(anchor=checkpoint_anchor(third))

    def test_wrong_public_pin_or_signer_identity_rejected(self):
        self.append()
        other_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(digest("other-key")))
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            self.verify(public_key=other_key.public_key().public_bytes_raw().hex())
        with self.assertRaisesRegex(ControlError, "IDENTITY_MISMATCH"):
            self.verify(signer_id="outsider")
        with self.assertRaisesRegex(ControlError, "SIGNER_MISMATCH"):
            self.append(public_key=other_key.public_key().public_bytes_raw().hex())
        with self.assertRaisesRegex(ControlError, "PIN_MISMATCH"):
            self.append(key_id="new-unapproved-key")

    def test_append_joins_outer_transaction_and_rollback_removes_checkpoint(self):
        first = self.append()
        self.db.execute("BEGIN IMMEDIATE")
        self.append(kind="STOP_REQUESTED", epoch=2, now=101)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(checkpoint_entries(self.db, "authority"), [first])
        self.verify(anchor=checkpoint_anchor(first))

    def test_separate_connections_serialize_global_sequence(self):
        self.append()
        barrier = threading.Barrier(2)
        failures = []

        def append_from_connection(root_id):
            try:
                with connect(self.path) as db:
                    barrier.wait(timeout=5)
                    append_checkpoint(db, **self.pins, private_key=self.private, root_id=root_id,
                        epoch=1, kind="ROOT_CREATED", state_digest=digest(root_id), now=101)
            except Exception as exc:
                failures.append(exc)

        threads = [threading.Thread(target=append_from_connection, args=(root,))
                   for root in ("concurrent-one", "concurrent-two")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        entries = checkpoint_entries(self.db, "authority")
        self.assertEqual([entry["sequence"] for entry in entries], [1, 2, 3])
        self.verify(entries, anchor=checkpoint_anchor(entries[-1]))

    def test_database_updates_and_deletes_are_append_only(self):
        first = self.append()
        for sql in ("DELETE FROM external_authority_checkpoints", "UPDATE external_authority_checkpoints SET sequence=7"):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "APPEND_ONLY"):
                self.db.execute(sql)
        self.assertEqual(checkpoint_entries(self.db, "authority"), [first])

    def test_head_mutation_detected_and_no_new_entry_written(self):
        first = self.append()
        self.db.execute("UPDATE external_authority_checkpoint_heads SET checkpoint_digest=?", (digest("fake-tip"),))
        with self.assertRaisesRegex(ControlError, "STORAGE_CORRUPT"):
            self.append(now=101)
        self.assertEqual(checkpoint_entries(self.db, "authority"), [first])

    def test_unknown_fields_boolean_epoch_and_nonfinite_time_rejected(self):
        entry = self.append()
        malformed = {**entry, "raw_secret_arguments": "not allowed"}
        with self.assertRaisesRegex(ControlError, "MALFORMED"):
            self.verify([malformed])
        for values in ({"epoch": True}, {"now": float("nan")}, {"action_digest": "not-a-digest"}):
            with self.subTest(values=values), self.assertRaises(ControlError):
                self.append(**values)
        self.assertEqual(len(checkpoint_entries(self.db, "authority")), 1)

    def test_empty_chain_and_malformed_anchor_fail_closed(self):
        with self.assertRaisesRegex(ControlError, "CHAIN_REQUIRED"):
            self.verify([])
        entry = self.append()
        for anchor in ({}, {**checkpoint_anchor(entry), "execution_authorized": True}):
            with self.assertRaisesRegex(ControlError, "ANCHOR_MALFORMED"):
                self.verify(anchor=anchor)

    def test_governance_export_has_digest_only_rust_body_schema(self):
        entry = self.append(epoch=99, action_digest=digest("action"), receipt_digest=digest("ack"), now=100.125)
        body = governance_envelope_body(entry, transition_kind="mutate", generation_before=3,
            generation_after=4, world_before_digest=digest("before"), world_after_digest=digest("after"),
            operation_digest=digest("operation"))
        self.assertEqual(body["schema"], GOVERNANCE_SCHEMA)
        self.assertEqual(body["generation_after"], 4)
        self.assertEqual(body["captured_at_ms"], 100125)
        self.assertEqual(body["upstream_receipt_sha256"], entry["checkpoint_digest"])
        self.assertNotIn("root_id", body)
        self.assertNotIn("envelope_ref", body)
        self.assertEqual(body["reservation_sha256"], ZERO_DIGEST)
        self.assertEqual(set(body), {"schema", "root_id_sha256", "transition_kind", "generation_before",
            "generation_after", "world_before_sha256", "world_after_sha256", "reservation_sha256",
            "operation_sha256", "upstream_receipt_sha256", "captured_at_ms"})

    def test_governance_export_requires_declared_transition_semantics(self):
        entry = self.append()
        for values in ({"transition_kind": "STOPPED"}, {"generation_after": 0},
                       {"operation_digest": ZERO_DIGEST}, {"reservation_digest": digest("reservation")}):
            arguments = {"transition_kind": "mutate", "generation_before": 0, "generation_after": 1,
                "world_before_digest": ZERO_DIGEST, "world_after_digest": digest("after"),
                "operation_digest": digest("operation"), **values}
            with self.subTest(values=values), self.assertRaisesRegex(ControlError, "GOVERNANCE_MALFORMED"):
                governance_envelope_body(entry, **arguments)

    def test_governance_export_rejects_unrepresentable_millisecond_clock(self):
        entry = self.append(now=1e300)
        with self.assertRaisesRegex(ControlError, "GOVERNANCE_MALFORMED"):
            governance_envelope_body(entry, transition_kind="initialize", generation_before=0,
                generation_after=0, world_before_digest=ZERO_DIGEST, world_after_digest=digest("initial"))


if __name__ == "__main__":
    unittest.main()
