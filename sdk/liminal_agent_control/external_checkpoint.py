"""Signed evidence for an externally owned STOP authority, never new authority.

The controller owns the database, signing key and clock. A caller-owned latest
anchor must be obtained independently of this database to detect its rollback.
An exported chain alone proves local signatures, not freshness or permission.
Append joins the controller transaction, so evidence and state can commit together.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from .authority import ControlError, canonical_bytes, digest, validate_id
from .observer_auth import _crypto
from .orientation import _hash, _time

CHECKPOINT_SCHEMA = "liminal-external-authority-checkpoint-v1"
ANCHOR_SCHEMA = "liminal-external-authority-anchor-v1"
GOVERNANCE_SCHEMA = "liminalosai-governance-transition-envelope-v0.1"
CHECKPOINT_DOMAIN = b"liminal-external-authority-checkpoint-v1\x00"
ZERO_DIGEST = "0" * 64
_BODY_FIELDS = {"schema", "authority_id", "signer_id", "key_id", "sequence",
    "previous_digest", "root_id", "epoch", "kind", "state_digest",
    "action_digest", "receipt_digest", "observed_at"}
_ENTRY_FIELDS = _BODY_FIELDS | {"signature", "checkpoint_digest"}
_ANCHOR_FIELDS = {"schema", "authority_id", "signer_id", "key_id", "sequence", "checkpoint_digest"}


def initialize_checkpoint_schema(db: sqlite3.Connection) -> None:
    """No implicit commit; the surrounding controller owns its transaction."""
    for sql in (
        """CREATE TABLE IF NOT EXISTS external_authority_checkpoint_heads (
            authority_id TEXT PRIMARY KEY, signer_id TEXT NOT NULL, key_id TEXT NOT NULL,
            public_key TEXT NOT NULL, sequence INTEGER NOT NULL,
            checkpoint_digest TEXT NOT NULL, observed_at REAL NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS external_authority_checkpoints (
            authority_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            checkpoint_digest TEXT UNIQUE NOT NULL, entry_json TEXT NOT NULL,
            PRIMARY KEY(authority_id,sequence))""",
        """CREATE TRIGGER IF NOT EXISTS external_checkpoint_no_update
            BEFORE UPDATE ON external_authority_checkpoints
            BEGIN SELECT RAISE(ABORT,'EXTERNAL_CHECKPOINT_APPEND_ONLY'); END""",
        """CREATE TRIGGER IF NOT EXISTS external_checkpoint_no_delete
            BEFORE DELETE ON external_authority_checkpoints
            BEGIN SELECT RAISE(ABORT,'EXTERNAL_CHECKPOINT_APPEND_ONLY'); END""",
    ):
        db.execute(sql)


def _integer(value: Any, *, zero: bool = False) -> int:
    if type(value) is not int or not (0 if zero else 1) <= value < 2**63:
        raise ControlError("EXTERNAL_CHECKPOINT_MALFORMED")
    return value


def _hex(value: Any, length: int) -> str:
    if not isinstance(value, str) or len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise ControlError("EXTERNAL_CHECKPOINT_MALFORMED")
    return value


def _identity(authority_id: Any, signer_id: Any, key_id: Any, public_key: Any) -> None:
    for field, value in (("authority_id", authority_id), ("signer_id", signer_id), ("key_id", key_id)):
        validate_id(value, field)
    _hex(public_key, 64)


def _entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ENTRY_FIELDS or value["schema"] != CHECKPOINT_SCHEMA:
        raise ControlError("EXTERNAL_CHECKPOINT_MALFORMED")
    if len(canonical_bytes(value)) > 8192:
        raise ControlError("EXTERNAL_CHECKPOINT_MALFORMED")
    for field in ("authority_id", "signer_id", "key_id", "root_id", "kind"):
        validate_id(value[field], field)
    _integer(value["sequence"])
    _integer(value["epoch"])
    for field in ("previous_digest", "state_digest", "checkpoint_digest"):
        _hash(value[field])
    for field in ("action_digest", "receipt_digest"):
        if value[field] is not None:
            _hash(value[field])
    _hex(value["signature"], 128)
    _time(value["observed_at"])
    if digest({key: item for key, item in value.items() if key != "checkpoint_digest"}) != value["checkpoint_digest"]:
        raise ControlError("EXTERNAL_CHECKPOINT_DIGEST_MISMATCH")
    return json.loads(canonical_bytes(value))


def checkpoint_anchor(entry: dict[str, Any]) -> dict[str, Any]:
    """A candidate anchor; copying it from an export does not make it trusted."""
    entry = _entry(entry)
    return {"schema": ANCHOR_SCHEMA, **{field: entry[field] for field in
        ("authority_id", "signer_id", "key_id", "sequence", "checkpoint_digest")}}


def verify_checkpoint_chain(entries: Any, *, authority_id: str, signer_id: str,
                            key_id: str, public_key: str, anchor: Any = None) -> dict[str, Any]:
    """Verify a complete genesis-to-tip export against caller-owned pins.

    A supplied anchor is the expected latest tip, not an arbitrary older member.
    Neither successful status grants action permission or authenticates clock time.
    """
    _identity(authority_id, signer_id, key_id, public_key)
    if not isinstance(entries, (list, tuple)) or not entries:
        raise ControlError("EXTERNAL_CHECKPOINT_CHAIN_REQUIRED")
    _, public = _crypto()
    verifier = public.from_public_bytes(bytes.fromhex(public_key))
    previous, latest_time, roots = ZERO_DIGEST, -1.0, {}
    normalized = []
    for sequence, supplied in enumerate(entries, start=1):
        item = _entry(supplied)
        if any(item[field] != expected for field, expected in (
                ("authority_id", authority_id), ("signer_id", signer_id), ("key_id", key_id))):
            raise ControlError("EXTERNAL_CHECKPOINT_IDENTITY_MISMATCH")
        if item["sequence"] != sequence or item["previous_digest"] != previous:
            raise ControlError("EXTERNAL_CHECKPOINT_CHAIN_BROKEN")
        if item["observed_at"] < latest_time:
            raise ControlError("EXTERNAL_CHECKPOINT_CLOCK_ROLLBACK")
        if item["epoch"] < roots.get(item["root_id"], 0):
            raise ControlError("EXTERNAL_CHECKPOINT_EPOCH_ROLLBACK")
        body = {key: value for key, value in item.items() if key in _BODY_FIELDS}
        try:
            verifier.verify(bytes.fromhex(item["signature"]), CHECKPOINT_DOMAIN + canonical_bytes(body))
        except Exception as exc:
            raise ControlError("EXTERNAL_CHECKPOINT_SIGNATURE_INVALID") from exc
        previous, latest_time = item["checkpoint_digest"], item["observed_at"]
        roots[item["root_id"]] = item["epoch"]
        normalized.append(item)
    tip = checkpoint_anchor(normalized[-1])
    if anchor is not None:
        if (not isinstance(anchor, dict) or set(anchor) != _ANCHOR_FIELDS
                or anchor.get("schema") != ANCHOR_SCHEMA):
            raise ControlError("EXTERNAL_CHECKPOINT_ANCHOR_MALFORMED")
        _integer(anchor["sequence"])
        _hash(anchor["checkpoint_digest"])
        if canonical_bytes(anchor) != canonical_bytes(tip):
            raise ControlError("EXTERNAL_CHECKPOINT_ANCHOR_MISMATCH")
    return {"verification_status": "EXTERNAL_ANCHORED_VERIFIED" if anchor is not None else "LOCAL_SIGNATURE_ONLY",
            "tip": tip, "entries": len(normalized), "execution_authorized": False}


def checkpoint_entries(db: sqlite3.Connection, authority_id: str) -> list[dict[str, Any]]:
    validate_id(authority_id, "authority_id")
    try:
        entries = []
        for row in db.execute("SELECT sequence,checkpoint_digest,entry_json FROM external_authority_checkpoints "
                "WHERE authority_id=? ORDER BY sequence", (authority_id,)).fetchall():
            item = _entry(json.loads(row[2]))
            if (item["authority_id"] != authority_id or item["sequence"] != row[0]
                    or item["checkpoint_digest"] != row[1] or canonical_bytes(item).decode() != row[2]):
                raise ControlError("EXTERNAL_CHECKPOINT_STORAGE_CORRUPT")
            entries.append(item)
        return entries
    except (TypeError, ValueError) as exc:
        raise ControlError("EXTERNAL_CHECKPOINT_STORAGE_CORRUPT") from exc


def append_checkpoint(db: sqlite3.Connection, *, authority_id: str, signer_id: str,
                      key_id: str, public_key: str, private_key: bytes, root_id: str,
                      epoch: int, kind: str, state_digest: str, action_digest: str | None = None,
                      receipt_digest: str | None = None, now: float) -> dict[str, Any]:
    """Append atomically, using only the controller's private key and clock."""
    _identity(authority_id, signer_id, key_id, public_key)
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ControlError("EXTERNAL_CHECKPOINT_MALFORMED")
    private, _ = _crypto()
    signing_key = private.from_private_bytes(private_key)
    from cryptography.hazmat.primitives import serialization
    if signing_key.public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex() != public_key:
        raise ControlError("EXTERNAL_CHECKPOINT_SIGNER_MISMATCH")
    own_transaction = not db.in_transaction
    if own_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        head = db.execute("SELECT signer_id,key_id,public_key,sequence,checkpoint_digest,observed_at "
                          "FROM external_authority_checkpoint_heads WHERE authority_id=?", (authority_id,)).fetchone()
        entries = checkpoint_entries(db, authority_id)
        if head is None:
            if entries:
                raise ControlError("EXTERNAL_CHECKPOINT_STORAGE_CORRUPT")
            sequence, previous = 1, ZERO_DIGEST
        else:
            if tuple(head[:3]) != (signer_id, key_id, public_key):
                raise ControlError("EXTERNAL_CHECKPOINT_PIN_MISMATCH")
            verified = verify_checkpoint_chain(entries, authority_id=authority_id, signer_id=signer_id,
                key_id=key_id, public_key=public_key)
            if (head[3] != verified["tip"]["sequence"] or head[4] != verified["tip"]["checkpoint_digest"]
                    or head[5] != entries[-1]["observed_at"]):
                raise ControlError("EXTERNAL_CHECKPOINT_STORAGE_CORRUPT")
            sequence, previous = head[3] + 1, head[4]
        body = {"schema": CHECKPOINT_SCHEMA, "authority_id": authority_id, "signer_id": signer_id,
            "key_id": key_id, "sequence": sequence, "previous_digest": previous, "root_id": root_id,
            "epoch": epoch, "kind": kind, "state_digest": state_digest, "action_digest": action_digest,
            "receipt_digest": receipt_digest, "observed_at": _time(now)}
        signed = {**body, "signature": signing_key.sign(CHECKPOINT_DOMAIN + canonical_bytes(body)).hex()}
        entry = _entry({**signed, "checkpoint_digest": digest(signed)})
        verify_checkpoint_chain([*entries, entry], authority_id=authority_id, signer_id=signer_id,
            key_id=key_id, public_key=public_key)
        db.execute("INSERT INTO external_authority_checkpoints VALUES (?,?,?,?)", (
            authority_id, sequence, entry["checkpoint_digest"], canonical_bytes(entry).decode()))
        if head is None:
            db.execute("INSERT INTO external_authority_checkpoint_heads VALUES (?,?,?,?,?,?,?)", (
                authority_id, signer_id, key_id, public_key, sequence, entry["checkpoint_digest"], entry["observed_at"]))
        else:
            db.execute("UPDATE external_authority_checkpoint_heads SET sequence=?,checkpoint_digest=?,observed_at=? "
                "WHERE authority_id=?", (sequence, entry["checkpoint_digest"], entry["observed_at"], authority_id))
        if own_transaction:
            db.commit()
        return entry
    except Exception:
        if own_transaction:
            db.rollback()
        raise


def governance_envelope_body(entry: dict[str, Any], *, transition_kind: str,
                             generation_before: int, generation_after: int, world_before_digest: str,
                             world_after_digest: str, reservation_digest: str = ZERO_DIGEST,
                             operation_digest: str = ZERO_DIGEST) -> dict[str, Any]:
    """Digest-only Rust bridge *body* mapping; no CBOR envelope_ref is invented.

    Generations and worlds describe the governance transition, not STOP epochs.
    A later adapter must build/verify the Rust envelope and bind its returned receipt.
    """
    item = _entry(entry)
    _integer(generation_before, zero=True)
    _integer(generation_after, zero=True)
    for value in (world_before_digest, world_after_digest, reservation_digest, operation_digest):
        _hash(value)
    if world_after_digest == ZERO_DIGEST:
        raise ControlError("EXTERNAL_CHECKPOINT_GOVERNANCE_MALFORMED")
    valid = {
        "initialize": generation_before == generation_after == 0 and world_before_digest == ZERO_DIGEST
            and reservation_digest == operation_digest == ZERO_DIGEST,
        "reserve": generation_after == generation_before and world_after_digest == world_before_digest
            and reservation_digest != ZERO_DIGEST and operation_digest != ZERO_DIGEST,
        "commit": generation_after == generation_before + 1 and reservation_digest != ZERO_DIGEST
            and operation_digest != ZERO_DIGEST,
        "mutate": generation_after == generation_before + 1 and reservation_digest == ZERO_DIGEST
            and operation_digest != ZERO_DIGEST,
        "reconcile": generation_after == generation_before + 1 and reservation_digest == ZERO_DIGEST
            and operation_digest != ZERO_DIGEST,
    }
    if not isinstance(transition_kind, str) or not valid.get(transition_kind, False):
        raise ControlError("EXTERNAL_CHECKPOINT_GOVERNANCE_MALFORMED")
    if item["observed_at"] >= (2**64) / 1000:
        raise ControlError("EXTERNAL_CHECKPOINT_GOVERNANCE_MALFORMED")
    captured_at_ms = int(item["observed_at"] * 1000)
    if not 0 <= captured_at_ms < 2**64:
        raise ControlError("EXTERNAL_CHECKPOINT_GOVERNANCE_MALFORMED")
    return {"schema": GOVERNANCE_SCHEMA,
        "root_id_sha256": hashlib.sha256(item["root_id"].encode()).hexdigest(),
        "transition_kind": transition_kind, "generation_before": generation_before,
        "generation_after": generation_after, "world_before_sha256": world_before_digest,
        "world_after_sha256": world_after_digest, "reservation_sha256": reservation_digest,
        "operation_sha256": operation_digest, "upstream_receipt_sha256": item["checkpoint_digest"],
        "captured_at_ms": captured_at_ms}
