"""Fail-closed LiminalDB checkpoint mirror for Durable Governance transitions.

This adapter wraps an existing DurableGovernanceStore. It never grants authority
and does not replace the primary generation/CAS store. Before a primary mutation
it writes a durable PENDING mirror intent; the intent is cleared only after a
trusted LiminalDB bridge returns a checkpoint bundle whose digest-only fields
match the exact primary transition. A crash or bridge failure therefore leaves a
persistent mirror block until explicit trusted reconciliation.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any, Callable, Mapping

from sdk.liminal_durable_governance_fence import DurableGovernanceStore, GovernanceWorld
from sdk.liminal_effect_commit import ZERO_SHA256
from sdk.liminal_post_sandbox_contracts import canonical_sha256

ENVELOPE_SCHEMA = "liminalosai-governance-transition-envelope-v0.1"
BRIDGE_RECEIPT_SCHEMA = "liminaldb-liminalosai-governance-checkpoint-receipt-v0.1"
MIRROR_STATE_SCHEMA = "liminal-liminaldb-governance-mirror-state-v0.1"
MIRROR_EVENT_SCHEMA = "liminal-liminaldb-governance-mirror-event-v0.1"
VERIFICATION_STATUS = "LOCAL_SIGNATURE_VERIFIED"

AUTHORITY = {
    "mode": "durable_governance_checkpoint_mirror",
    "primary_cas_authority": False,
    "checkpoint_evidence_only": True,
    "pending_before_primary_mutation": True,
    "fail_closed_on_bridge_failure": True,
    "explicit_mirror_reconciliation_required": True,
    "automatic_mirror_expiry": False,
    "bounded_bridge_timeout_required": True,
    "capability_grant": False,
    "runtime_mutation": False,
    "network_authority": False,
    "credential_authority": False,
    "signature_verification_delegated_to_trusted_bridge": True,
    "distributed_consensus": False,
    "kernel_enforcement": False,
}

Bridge = Callable[[Mapping[str, Any], float], Mapping[str, Any]]
ClockMs = Callable[[], int]
TrustedKeyPin = tuple[str, str, str]


class LiminalDBMirrorError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha(value: Any, name: str, *, allow_zero: bool = True) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise LiminalDBMirrorError(f"invalid_{name}")
    if not allow_zero and value == ZERO_SHA256:
        raise LiminalDBMirrorError(f"zero_{name}")
    return value


def _sha_ref(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise LiminalDBMirrorError(f"invalid_{name}")
    _sha(value[7:], name)
    return value


def _root(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 192
    ):
        raise LiminalDBMirrorError("invalid_root_id")
    return value


def _reservation_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 192
    ):
        raise LiminalDBMirrorError("invalid_reservation_id")
    return value


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LiminalDBMirrorError("invalid_generation")
    return value


def _clock(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LiminalDBMirrorError("invalid_trusted_clock_ms")
    return value


def _timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LiminalDBMirrorError("invalid_bridge_timeout_seconds")
    seconds = float(value)
    if seconds <= 0 or seconds > 300:
        raise LiminalDBMirrorError("invalid_bridge_timeout_seconds")
    return seconds


def _trusted_key_pin(value: Mapping[str, Any]) -> TrustedKeyPin:
    raw = dict(value)
    if set(raw) != {"signer_id", "key_id", "public_key_hex"}:
        raise LiminalDBMirrorError("invalid_trusted_key_pin")
    signer_id = raw["signer_id"]
    key_id = raw["key_id"]
    public_key = raw["public_key_hex"]
    if (
        not isinstance(signer_id, str)
        or not signer_id.strip()
        or signer_id != signer_id.strip()
        or not isinstance(key_id, str)
        or not key_id.strip()
        or key_id != key_id.strip()
        or not isinstance(public_key, str)
        or len(public_key) != 64
        or any(ch not in "0123456789abcdef" for ch in public_key)
    ):
        raise LiminalDBMirrorError("invalid_trusted_key_pin")
    return signer_id, key_id, public_key


class SQLiteCheckpointMirrorJournal:
    """Append-only mirror history plus one durable current guard per root."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise LiminalDBMirrorError("mirror_journal_path_required")
        self.path = path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mirror_guard (
                    root_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pending_intent_sha256 TEXT NOT NULL,
                    last_checkpoint_ref TEXT NOT NULL,
                    last_evidence_sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mirror_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    root_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_kind TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS mirror_history_root_idx "
                "ON mirror_history(root_id, id)"
            )
        finally:
            conn.close()

    def state_document(self, *, root_id: str) -> dict[str, Any]:
        root = _root(root_id)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT sequence,status,pending_intent_sha256,last_checkpoint_ref,last_evidence_sha256 FROM mirror_guard WHERE root_id=?",
                (root,),
            ).fetchone()
            if row is None:
                body = {
                    "schema": MIRROR_STATE_SCHEMA,
                    "root_id_sha256": canonical_sha256(root),
                    "sequence": 0,
                    "status": "CLEAR",
                    "pending_intent_sha256": ZERO_SHA256,
                    "last_checkpoint_ref": "sha256:" + ZERO_SHA256,
                    "last_evidence_sha256": ZERO_SHA256,
                    "authority": AUTHORITY,
                }
            else:
                body = {
                    "schema": MIRROR_STATE_SCHEMA,
                    "root_id_sha256": canonical_sha256(root),
                    "sequence": _generation(row[0]),
                    "status": row[1],
                    "pending_intent_sha256": _sha(row[2], "pending_intent_sha256"),
                    "last_checkpoint_ref": _sha_ref(row[3], "last_checkpoint_ref"),
                    "last_evidence_sha256": _sha(row[4], "last_evidence_sha256"),
                    "authority": AUTHORITY,
                }
            return {**body, "state_sha256": canonical_sha256(body)}
        finally:
            conn.close()

    def require_clear(self, *, root_id: str) -> None:
        state = self.state_document(root_id=root_id)
        if state["status"] == "PENDING":
            raise LiminalDBMirrorError("liminaldb_mirror_pending")

    def begin(self, *, root_id: str, intent_sha256: str) -> dict[str, Any]:
        root = _root(root_id)
        intent = _sha(intent_sha256, "intent_sha256", allow_zero=False)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence,status FROM mirror_guard WHERE root_id=?", (root,)
            ).fetchone()
            if row is not None and row[1] == "PENDING":
                raise LiminalDBMirrorError("liminaldb_mirror_pending")
            sequence = 1 if row is None else _generation(row[0]) + 1
            event = self._event(root, sequence, "PENDING", intent)
            if row is None:
                conn.execute(
                    "INSERT INTO mirror_guard VALUES (?,?,?,?,?,?)",
                    (
                        root,
                        sequence,
                        "PENDING",
                        intent,
                        "sha256:" + ZERO_SHA256,
                        ZERO_SHA256,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE mirror_guard SET sequence=?,status='PENDING',pending_intent_sha256=? WHERE root_id=?",
                    (sequence, intent, root),
                )
            conn.execute(
                "INSERT INTO mirror_history(root_id,sequence,event_kind,event_sha256) VALUES (?,?,?,?)",
                (root, sequence, "PENDING", event),
            )
            conn.execute("COMMIT")
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()
        return self.state_document(root_id=root)

    def acknowledge(
        self,
        *,
        root_id: str,
        intent_sha256: str,
        checkpoint_ref: str,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        intent = _sha(intent_sha256, "intent_sha256", allow_zero=False)
        checkpoint = _sha_ref(checkpoint_ref, "checkpoint_ref")
        evidence = _sha(evidence_sha256, "evidence_sha256", allow_zero=False)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence,status,pending_intent_sha256 FROM mirror_guard WHERE root_id=?",
                (root,),
            ).fetchone()
            if row is None or row[1] != "PENDING" or row[2] != intent:
                raise LiminalDBMirrorError("mirror_ack_mismatch")
            sequence = _generation(row[0])
            event = self._event(
                root,
                sequence,
                "ACKED",
                canonical_sha256(
                    {
                        "intent_sha256": intent,
                        "checkpoint_ref": checkpoint,
                        "evidence_sha256": evidence,
                    }
                ),
            )
            conn.execute(
                "UPDATE mirror_guard SET status='CLEAR',pending_intent_sha256=?,last_checkpoint_ref=?,last_evidence_sha256=? WHERE root_id=?",
                (ZERO_SHA256, checkpoint, evidence, root),
            )
            conn.execute(
                "INSERT INTO mirror_history(root_id,sequence,event_kind,event_sha256) VALUES (?,?,?,?)",
                (root, sequence, "ACKED", event),
            )
            conn.execute("COMMIT")
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()
        return self.state_document(root_id=root)

    def reconcile(
        self, *, root_id: str, reconciliation_receipt_sha256: str
    ) -> dict[str, Any]:
        root = _root(root_id)
        receipt = _sha(
            reconciliation_receipt_sha256,
            "reconciliation_receipt_sha256",
            allow_zero=False,
        )
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT sequence,status,pending_intent_sha256 FROM mirror_guard WHERE root_id=?",
                (root,),
            ).fetchone()
            if row is None or row[1] != "PENDING":
                raise LiminalDBMirrorError("mirror_reconciliation_not_required")
            sequence = _generation(row[0])
            event = self._event(
                root,
                sequence,
                "RECONCILED",
                canonical_sha256(
                    {
                        "pending_intent_sha256": row[2],
                        "reconciliation_receipt_sha256": receipt,
                    }
                ),
            )
            conn.execute(
                "UPDATE mirror_guard SET status='CLEAR',pending_intent_sha256=?,last_evidence_sha256=? WHERE root_id=?",
                (ZERO_SHA256, receipt, root),
            )
            conn.execute(
                "INSERT INTO mirror_history(root_id,sequence,event_kind,event_sha256) VALUES (?,?,?,?)",
                (root, sequence, "RECONCILED", event),
            )
            conn.execute("COMMIT")
        except Exception:
            self._rollback(conn)
            raise
        finally:
            conn.close()
        return self.state_document(root_id=root)

    def history(self, *, root_id: str) -> tuple[dict[str, Any], ...]:
        root = _root(root_id)
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT sequence,event_kind,event_sha256 FROM mirror_history WHERE root_id=? ORDER BY id",
                (root,),
            ).fetchall()
            return tuple(
                {
                    "sequence": row[0],
                    "event_kind": row[1],
                    "event_sha256": row[2],
                }
                for row in rows
            )
        finally:
            conn.close()

    @staticmethod
    def _event(root_id: str, sequence: int, kind: str, evidence_sha256: str) -> str:
        return canonical_sha256(
            {
                "schema": MIRROR_EVENT_SCHEMA,
                "root_id_sha256": canonical_sha256(root_id),
                "sequence": sequence,
                "event_kind": kind,
                "evidence_sha256": evidence_sha256,
                "authority_sha256": canonical_sha256(AUTHORITY),
            }
        )

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass


@dataclass(frozen=True)
class _TransitionEvidence:
    transition_kind: str
    generation_before: int
    generation_after: int
    world_before_sha256: str
    world_after_sha256: str
    reservation_sha256: str
    operation_sha256: str
    upstream_receipt_sha256: str
    captured_at_ms: int


class CheckpointingGovernanceStore:
    """DurableGovernanceStore wrapper requiring a bounded LiminalDB bridge."""

    def __init__(
        self,
        *,
        delegate: DurableGovernanceStore,
        journal: SQLiteCheckpointMirrorJournal,
        bridge: Bridge,
        bridge_timeout_seconds: float,
        clock_ms: ClockMs,
        pinned_trusted_keys: tuple[Mapping[str, Any], ...] | None = None,
    ) -> None:
        if not isinstance(delegate, DurableGovernanceStore):
            raise LiminalDBMirrorError("durable_governance_store_required")
        if not isinstance(journal, SQLiteCheckpointMirrorJournal):
            raise LiminalDBMirrorError("sqlite_mirror_journal_required")
        if not callable(bridge) or not callable(clock_ms):
            raise LiminalDBMirrorError("trusted_bridge_and_clock_required")
        pins = tuple(_trusted_key_pin(item) for item in (pinned_trusted_keys or ()))
        if len(pins) != len(set(pins)):
            raise LiminalDBMirrorError("duplicate_trusted_key_pin")
        self.delegate = delegate
        self.journal = journal
        self.bridge = bridge
        self.bridge_timeout_seconds = _timeout(bridge_timeout_seconds)
        self.clock_ms = clock_ms
        self._pinned_trusted_keys = frozenset(pins)

    def initialize(self, *, root_id: str, world: Mapping[str, Any]) -> dict[str, Any]:
        root = _root(root_id)
        item = GovernanceWorld.from_document(world)
        intent = self._begin(
            root, "initialize", {"world_after_sha256": item.world_sha256}
        )
        try:
            after = self.delegate.initialize(root_id=root, world=item.as_document())
        except Exception as exc:
            raise LiminalDBMirrorError("primary_initialize_failed_mirror_stuck") from exc
        evidence = _TransitionEvidence(
            "initialize",
            0,
            0,
            ZERO_SHA256,
            after["world_sha256"],
            ZERO_SHA256,
            ZERO_SHA256,
            after["state_sha256"],
            self._now(),
        )
        self._checkpoint(root, intent, evidence)
        return after

    def read_state(self, *, root_id: str) -> dict[str, Any]:
        return self.delegate.read_state(root_id=_root(root_id))

    def reserve_effect(
        self,
        *,
        root_id: str,
        expected_generation: int,
        expected_world_sha256: str,
        reservation_id: str,
        reservation_payload_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(
            expected_world_sha256, "expected_world_sha256", allow_zero=False
        )
        reservation = _reservation_id(reservation_id)
        reservation_payload = _sha(
            reservation_payload_sha256, "reservation_payload_sha256", allow_zero=False
        )
        before = self.delegate.read_state(root_id=root)
        intent = self._begin(
            root,
            "reserve",
            {
                "generation": generation,
                "world_sha256": expected_world,
                "reservation_sha256": canonical_sha256(reservation),
                "reservation_payload_sha256": reservation_payload,
            },
        )
        try:
            after = self.delegate.reserve_effect(
                root_id=root,
                expected_generation=generation,
                expected_world_sha256=expected_world,
                reservation_id=reservation,
                reservation_payload_sha256=reservation_payload,
            )
        except Exception as exc:
            raise LiminalDBMirrorError("primary_reserve_failed_mirror_stuck") from exc
        evidence = _TransitionEvidence(
            "reserve",
            before["generation"],
            after["generation"],
            before["world_sha256"],
            after["world_sha256"],
            canonical_sha256(reservation),
            reservation_payload,
            reservation_payload,
            self._now(),
        )
        self._checkpoint(root, intent, evidence)
        return after

    def commit_effect(
        self,
        *,
        root_id: str,
        expected_generation: int,
        expected_world_sha256: str,
        reservation_id: str,
        reservation_payload_sha256: str,
        new_world: Mapping[str, Any],
        inner_commit_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(
            expected_world_sha256, "expected_world_sha256", allow_zero=False
        )
        reservation = _reservation_id(reservation_id)
        reservation_payload = _sha(
            reservation_payload_sha256, "reservation_payload_sha256", allow_zero=False
        )
        inner_receipt = _sha(
            inner_commit_receipt_sha256,
            "inner_commit_receipt_sha256",
            allow_zero=False,
        )
        next_world = GovernanceWorld.from_document(new_world)
        before = self.delegate.read_state(root_id=root)
        intent = self._begin(
            root,
            "commit",
            {
                "generation": generation,
                "world_sha256": expected_world,
                "reservation_sha256": canonical_sha256(reservation),
                "inner_commit_receipt_sha256": inner_receipt,
            },
        )
        try:
            after = self.delegate.commit_effect(
                root_id=root,
                expected_generation=generation,
                expected_world_sha256=expected_world,
                reservation_id=reservation,
                reservation_payload_sha256=reservation_payload,
                new_world=next_world.as_document(),
                inner_commit_receipt_sha256=inner_receipt,
            )
        except Exception as exc:
            raise LiminalDBMirrorError("primary_commit_failed_mirror_stuck") from exc
        evidence = _TransitionEvidence(
            "commit",
            before["generation"],
            after["generation"],
            before["world_sha256"],
            after["world_sha256"],
            canonical_sha256(reservation),
            reservation_payload,
            inner_receipt,
            self._now(),
        )
        self._checkpoint(root, intent, evidence)
        return after

    def mutate_world(
        self,
        *,
        root_id: str,
        expected_generation: int,
        expected_world_sha256: str,
        new_world: Mapping[str, Any],
        transition_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(
            expected_world_sha256, "expected_world_sha256", allow_zero=False
        )
        transition_receipt = _sha(
            transition_receipt_sha256,
            "transition_receipt_sha256",
            allow_zero=False,
        )
        next_world = GovernanceWorld.from_document(new_world)
        before = self.delegate.read_state(root_id=root)
        intent = self._begin(
            root,
            "mutate",
            {
                "generation": generation,
                "world_sha256": expected_world,
                "transition_receipt_sha256": transition_receipt,
            },
        )
        try:
            after = self.delegate.mutate_world(
                root_id=root,
                expected_generation=generation,
                expected_world_sha256=expected_world,
                new_world=next_world.as_document(),
                transition_receipt_sha256=transition_receipt,
            )
        except Exception as exc:
            raise LiminalDBMirrorError("primary_mutate_failed_mirror_stuck") from exc
        evidence = _TransitionEvidence(
            "mutate",
            before["generation"],
            after["generation"],
            before["world_sha256"],
            after["world_sha256"],
            ZERO_SHA256,
            ZERO_SHA256,
            transition_receipt,
            self._now(),
        )
        self._checkpoint(root, intent, evidence)
        return after

    def reconcile_reservation(
        self,
        *,
        root_id: str,
        expected_generation: int,
        expected_world_sha256: str,
        reservation_id: str,
        new_world: Mapping[str, Any],
        reconciliation_receipt_sha256: str,
    ) -> dict[str, Any]:
        root = _root(root_id)
        generation = _generation(expected_generation)
        expected_world = _sha(
            expected_world_sha256, "expected_world_sha256", allow_zero=False
        )
        reservation = _reservation_id(reservation_id)
        reconciliation_receipt = _sha(
            reconciliation_receipt_sha256,
            "reconciliation_receipt_sha256",
            allow_zero=False,
        )
        next_world = GovernanceWorld.from_document(new_world)
        before = self.delegate.read_state(root_id=root)
        intent = self._begin(
            root,
            "reconcile",
            {
                "generation": generation,
                "world_sha256": expected_world,
                "reservation_sha256": canonical_sha256(reservation),
                "reconciliation_receipt_sha256": reconciliation_receipt,
            },
        )
        try:
            after = self.delegate.reconcile_reservation(
                root_id=root,
                expected_generation=generation,
                expected_world_sha256=expected_world,
                reservation_id=reservation,
                new_world=next_world.as_document(),
                reconciliation_receipt_sha256=reconciliation_receipt,
            )
        except Exception as exc:
            raise LiminalDBMirrorError("primary_reconcile_failed_mirror_stuck") from exc
        evidence = _TransitionEvidence(
            "reconcile",
            before["generation"],
            after["generation"],
            before["world_sha256"],
            after["world_sha256"],
            canonical_sha256(reservation),
            ZERO_SHA256,
            reconciliation_receipt,
            self._now(),
        )
        self._checkpoint(root, intent, evidence)
        return after

    def reconcile_mirror(
        self, *, root_id: str, trusted_reconciliation_receipt_sha256: str
    ) -> dict[str, Any]:
        receipt = _sha(
            trusted_reconciliation_receipt_sha256,
            "trusted_reconciliation_receipt_sha256",
            allow_zero=False,
        )
        return self.journal.reconcile(
            root_id=_root(root_id), reconciliation_receipt_sha256=receipt
        )

    def mirror_state_document(self, *, root_id: str) -> dict[str, Any]:
        return self.journal.state_document(root_id=_root(root_id))

    def _begin(
        self, root_id: str, transition_kind: str, binding: Mapping[str, Any]
    ) -> str:
        self.journal.require_clear(root_id=root_id)
        intent = canonical_sha256(
            {
                "transition_kind": transition_kind,
                "root_id_sha256": canonical_sha256(root_id),
                "binding": dict(binding),
                "authority_sha256": canonical_sha256(AUTHORITY),
            }
        )
        self.journal.begin(root_id=root_id, intent_sha256=intent)
        return intent

    def _checkpoint(
        self, root_id: str, intent_sha256: str, evidence: _TransitionEvidence
    ) -> None:
        envelope = self._envelope(root_id, evidence)
        try:
            bundle = self.bridge(envelope, self.bridge_timeout_seconds)
            checkpoint_ref, evidence_sha = self._verify_bundle(envelope, bundle)
            self.journal.acknowledge(
                root_id=root_id,
                intent_sha256=intent_sha256,
                checkpoint_ref=checkpoint_ref,
                evidence_sha256=evidence_sha,
            )
        except Exception as exc:
            if isinstance(exc, LiminalDBMirrorError):
                raise
            raise LiminalDBMirrorError("liminaldb_checkpoint_failed_mirror_stuck") from exc

    @staticmethod
    def _envelope(root_id: str, evidence: _TransitionEvidence) -> dict[str, Any]:
        return {
            "schema": ENVELOPE_SCHEMA,
            "root_id_sha256": canonical_sha256(root_id),
            "transition_kind": evidence.transition_kind,
            "generation_before": evidence.generation_before,
            "generation_after": evidence.generation_after,
            "world_before_sha256": evidence.world_before_sha256,
            "world_after_sha256": evidence.world_after_sha256,
            "reservation_sha256": evidence.reservation_sha256,
            "operation_sha256": evidence.operation_sha256,
            "upstream_receipt_sha256": evidence.upstream_receipt_sha256,
            "captured_at_ms": evidence.captured_at_ms,
        }

    def _verify_bundle(
        self, envelope: Mapping[str, Any], bundle: Mapping[str, Any]
    ) -> tuple[str, str]:
        raw = dict(bundle)
        if set(raw) != {"envelope", "receipt", "checkpoint", "trusted_key"}:
            raise LiminalDBMirrorError("bridge_bundle_keys_mismatch")
        if not all(isinstance(raw[key], Mapping) for key in raw):
            raise LiminalDBMirrorError("bridge_bundle_mapping_required")

        bridged_envelope = dict(raw["envelope"])
        if dict(bridged_envelope.get("body", {})) != dict(envelope):
            raise LiminalDBMirrorError("bridge_envelope_binding_mismatch")
        envelope_ref = _sha_ref(
            bridged_envelope.get("envelope_ref"), "envelope_ref"
        )

        receipt = dict(raw["receipt"])
        receipt_body = dict(receipt.get("body", {}))
        receipt_ref = _sha_ref(receipt.get("receipt_ref"), "receipt_ref")
        if (
            receipt_body.get("schema") != BRIDGE_RECEIPT_SCHEMA
            or receipt_body.get("verification_status") != VERIFICATION_STATUS
        ):
            raise LiminalDBMirrorError("bridge_receipt_not_verified")
        expected = {
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
        }
        for key, value in expected.items():
            if key not in receipt_body:
                raise LiminalDBMirrorError(f"bridge_receipt_{key}_missing")
            if receipt_body[key] != value:
                raise LiminalDBMirrorError(f"bridge_receipt_{key}_mismatch")

        checkpoint = dict(raw["checkpoint"])
        checkpoint_body = dict(checkpoint.get("body", {}))
        checkpoint_ref = _sha_ref(checkpoint.get("manifest_ref"), "checkpoint_ref")
        if checkpoint.get("signature_algorithm") != "Ed25519":
            raise LiminalDBMirrorError("bridge_checkpoint_algorithm_mismatch")
        signature = checkpoint.get("signature_hex")
        if (
            not isinstance(signature, str)
            or len(signature) != 128
            or any(ch not in "0123456789abcdef" for ch in signature)
        ):
            raise LiminalDBMirrorError("bridge_checkpoint_signature_shape_invalid")
        if checkpoint_body.get("storage_root_identity") != (
            "sha256:" + envelope["root_id_sha256"]
        ):
            raise LiminalDBMirrorError("bridge_checkpoint_root_mismatch")
        for receipt_key, checkpoint_key in (
            ("checkpoint_ref", "manifest_ref"),
            ("event_chain_head", "event_chain_head"),
            ("last_sequence", "last_sequence"),
            ("projection_digest", "projection_digest"),
            ("snapshot_digest", "snapshot_digest"),
            ("signer_id", "signer_id"),
            ("key_id", "key_id"),
        ):
            actual = (
                checkpoint_ref
                if checkpoint_key == "manifest_ref"
                else checkpoint_body.get(checkpoint_key)
            )
            if actual is None or receipt_key not in receipt_body:
                raise LiminalDBMirrorError(
                    f"bridge_checkpoint_{receipt_key}_missing"
                )
            if receipt_body[receipt_key] != actual:
                raise LiminalDBMirrorError(
                    f"bridge_checkpoint_{receipt_key}_mismatch"
                )

        event_hash = _sha_ref(receipt_body.get("event_hash"), "event_hash")
        event_chain_head = _sha_ref(
            receipt_body.get("event_chain_head"), "event_chain_head"
        )
        projection_digest = _sha_ref(
            receipt_body.get("projection_digest"), "projection_digest"
        )
        snapshot_digest = _sha_ref(
            receipt_body.get("snapshot_digest"), "snapshot_digest"
        )
        last_sequence = _generation(receipt_body.get("last_sequence"))

        trusted_key = dict(raw["trusted_key"])
        signer_id = checkpoint_body.get("signer_id")
        key_id = checkpoint_body.get("key_id")
        if (
            trusted_key.get("signer_id") != signer_id
            or trusted_key.get("key_id") != key_id
        ):
            raise LiminalDBMirrorError("bridge_trusted_key_identity_mismatch")
        public_key = trusted_key.get("public_key_hex")
        if (
            not isinstance(public_key, str)
            or len(public_key) != 64
            or any(ch not in "0123456789abcdef" for ch in public_key)
        ):
            raise LiminalDBMirrorError("bridge_trusted_key_shape_invalid")
        bridge_key_pin = _trusted_key_pin(
            {
                "signer_id": signer_id,
                "key_id": key_id,
                "public_key_hex": public_key,
            }
        )
        if self._pinned_trusted_keys and bridge_key_pin not in self._pinned_trusted_keys:
            raise LiminalDBMirrorError("bridge_trusted_key_not_pinned")

        evidence_sha = canonical_sha256(
            {
                "envelope_ref": envelope_ref,
                "receipt_ref": receipt_ref,
                "checkpoint_ref": checkpoint_ref,
                "event_hash": event_hash,
                "event_chain_head": event_chain_head,
                "last_sequence": last_sequence,
                "projection_digest": projection_digest,
                "snapshot_digest": snapshot_digest,
                "signer_id": signer_id,
                "key_id": key_id,
                "public_key_sha256": canonical_sha256(public_key),
                "verification_status": VERIFICATION_STATUS,
            }
        )
        return checkpoint_ref, evidence_sha

    def _now(self) -> int:
        return _clock(self.clock_ms())


__all__ = [
    "AUTHORITY",
    "BRIDGE_RECEIPT_SCHEMA",
    "ENVELOPE_SCHEMA",
    "MIRROR_EVENT_SCHEMA",
    "MIRROR_STATE_SCHEMA",
    "VERIFICATION_STATUS",
    "CheckpointingGovernanceStore",
    "LiminalDBMirrorError",
    "SQLiteCheckpointMirrorJournal",
]
