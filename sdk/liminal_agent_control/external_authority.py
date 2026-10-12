"""Separately owned, durable one-shot authority for the records-only pilot.

The authority database, signing key, clock and operator remain trusted and must
live outside the receiver/worker rollback domain. A permit is never reissued.
STOP closes admission immediately but acknowledges quiescence only after every
issued permit has an authenticated terminal receiver receipt. Lost results stay
pending indefinitely; this service does not turn absence into proof of denial.
"""
from __future__ import annotations

import json
import math
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

from .authority import (ControlError, canonical_bytes, connect, digest, require_key,
                        validate_action, validate_id, verify_receipt)
from .observer_auth import _crypto


EXTERNAL_PROFILE = "external_governed_v1"
SCHEMA = "liminal-external-authority-store-v1"
MAX_ROOTS = 64
MAX_EXECUTIONS = 256
MAX_RECORDED_ACTIONS = 1024
_AUTHORIZATION_FIELDS = {"action_digest", "policy_version", "expires_at", "receiver_id"}
_RECEIPT_FIELDS = {"schema", "status", "reason", "action_id", "attempt_id", "root_id", "execution_id",
                   "epoch", "action_digest", "effect_count", "accepted_epoch", "accepted_at", "receiver_id",
                   "observed_at", "key_id", "enforcement_profile", "signature"}
_TABLES = {"external_meta", "external_roots", "external_executions", "external_actions",
           "external_authority_checkpoint_heads", "external_authority_checkpoints"}


def _hex(value: Any, length: int = 64) -> str:
    if not isinstance(value, str) or len(value) != length:
        raise ControlError("EXTERNAL_AUTHORITY_DIGEST_INVALID")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ControlError("EXTERNAL_AUTHORITY_DIGEST_INVALID") from exc
    if len(raw) * 2 != length or raw.hex() != value:
        raise ControlError("EXTERNAL_AUTHORITY_DIGEST_INVALID")
    return value


def _time(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ControlError("EXTERNAL_AUTHORITY_TIME_INVALID")
    return float(value)


def validate_authority_pin(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"authority_id", "key_id", "public_key"}:
        raise ControlError("EXTERNAL_AUTHORITY_PIN_INVALID")
    validate_id(value["authority_id"], "authority_id")
    validate_id(value["key_id"], "key_id")
    _hex(value["public_key"])
    return json.loads(canonical_bytes(value))


class ExternalAuthorityStore:
    """SQLite is authoritative here; receiver SQLite is a different database.

    Initialization is explicit. Every later connection opens an existing file
    and checks the persisted identity rather than recreating missing state.
    """

    def __init__(self, db_path: str | Path, *, authority_id: str, key_id: str,
                 private_key: bytes, receipt_key: bytes, clock: Callable[[], float] = time.time,
                 create: bool = True) -> None:
        validate_id(authority_id, "authority_id")
        validate_id(key_id, "key_id")
        if not isinstance(private_key, bytes) or len(private_key) != 32 or not callable(clock):
            raise ControlError("EXTERNAL_AUTHORITY_CONFIGURATION_INVALID")
        self._receipt_key = require_key(receipt_key)
        if private_key == receipt_key:
            raise ControlError("EXTERNAL_AUTHORITY_KEYS_MUST_DIFFER")
        private, _ = _crypto()
        self._private_bytes = private_key
        self._private_key = private.from_private_bytes(private_key)
        self._pin = {"authority_id": authority_id, "key_id": key_id,
                     "public_key": self._private_key.public_key().public_bytes_raw().hex()}
        self._clock = clock
        path = Path(db_path).absolute()
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ControlError("EXTERNAL_AUTHORITY_DATABASE_UNSAFE")
        self.db_path = path
        self._config = {"schema": SCHEMA, "pin": canonical_bytes(self._pin).decode(),
                        "receipt_key_digest": digest({"key": receipt_key.hex()})}
        self._config.update(self._profile_configuration())
        if not path.exists():
            if not create:
                raise ControlError("EXTERNAL_AUTHORITY_STATE_MISSING")
            path.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive creation prevents two initializers from silently sharing
            # different configurations or replacing an existing database.
            try:
                descriptor = path.open("xb")
                descriptor.close()
                path.chmod(0o600)
            except FileExistsError as exc:
                raise ControlError("EXTERNAL_AUTHORITY_INITIALIZATION_RACE") from exc
            with connect(path, create=False) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE external_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE external_roots (
                        root_id TEXT PRIMARY KEY, receiver_id TEXT NOT NULL, policy_digest TEXT NOT NULL,
                        epoch INTEGER NOT NULL, state TEXT NOT NULL,
                        max_actions INTEGER NOT NULL, issued_count INTEGER NOT NULL,
                        lifetime_seconds REAL NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                        stopped_at REAL, stop_reason TEXT
                    );
                    CREATE TABLE external_executions (
                        execution_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES external_roots(root_id),
                        parent_execution_id TEXT REFERENCES external_executions(execution_id), epoch INTEGER NOT NULL
                    );
                    CREATE TABLE external_actions (
                        action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                        reservation_id TEXT UNIQUE NOT NULL, root_id TEXT NOT NULL REFERENCES external_roots(root_id),
                        action_digest TEXT NOT NULL, action_json TEXT NOT NULL, authorization_digest TEXT NOT NULL,
                        status TEXT NOT NULL, reason TEXT NOT NULL, issued_at REAL NOT NULL,
                        receipt_json TEXT, receipt_digest TEXT
                    );
                """)
                db.executemany("INSERT INTO external_meta VALUES (?,?)", self._config.items())
                db.execute("INSERT INTO external_meta VALUES ('last_now','0')")
                db.execute("INSERT INTO external_meta VALUES ('clock_fault','0')")
                from .external_checkpoint import initialize_checkpoint_schema
                initialize_checkpoint_schema(db)
        with self._connection() as db:
            self._check(db)

    def pin(self) -> dict[str, str]:
        return dict(self._pin)

    def _profile_configuration(self) -> dict[str, str]:
        """Persist subclass trust configuration without changing records metadata."""
        return {}

    def _validate_action(self, action: Any) -> dict[str, Any]:
        return validate_action(action)

    def _verify_terminal_receipt(self, receipt: Any) -> dict[str, Any]:
        if (not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS
                or not verify_receipt(receipt, self._receipt_key)):
            raise ControlError("EXTERNAL_AUTHORITY_RECEIPT_INVALID")
        return json.loads(canonical_bytes(receipt))

    def _bind_terminal_receipt(self, receipt: dict[str, Any], row: sqlite3.Row,
                               root: sqlite3.Row, action: dict[str, Any]) -> str:
        status = receipt["status"]
        if (status not in ("COMMITTED", "DENIED") or receipt["schema"] != "liminal.agent-control.receipt.v1"
                or receipt["receiver_id"] != root["receiver_id"] or receipt["enforcement_profile"] != EXTERNAL_PROFILE
                or receipt["key_id"] != "receiver-hmac-v1" or receipt["action_digest"] != row["action_digest"]
                or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                or type(receipt["effect_count"]) is not int or receipt["effect_count"] != (1 if status == "COMMITTED" else 0)):
            raise ControlError("EXTERNAL_AUTHORITY_RECEIPT_BINDING_MISMATCH")
        validate_id(receipt["reason"], "receipt reason")
        _time(receipt["observed_at"])
        if status == "COMMITTED":
            if type(receipt["accepted_epoch"]) is not int or receipt["accepted_epoch"] != action["epoch"]:
                raise ControlError("EXTERNAL_AUTHORITY_RECEIPT_BINDING_MISMATCH")
            _time(receipt["accepted_at"])
        elif receipt["accepted_epoch"] is not None or receipt["accepted_at"] is not None:
            raise ControlError("EXTERNAL_AUTHORITY_RECEIPT_BINDING_MISMATCH")
        return status

    def _terminal_reason_prefix(self) -> str:
        return "AUTHENTICATED_RECEIVER_"

    def _connection(self) -> sqlite3.Connection:
        db = None
        try:
            if not self.db_path.is_file() or self.db_path.is_symlink():
                raise ControlError("EXTERNAL_AUTHORITY_STATE_MISSING")
            db = connect(self.db_path, create=False)
            self._check(db)
            return db
        except Exception as exc:
            if db is not None:
                db.close()
            if isinstance(exc, ControlError):
                raise
            raise ControlError("EXTERNAL_AUTHORITY_STATE_INVALID") from exc

    def _check(self, db: sqlite3.Connection) -> None:
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not _TABLES <= tables:
                raise ControlError("EXTERNAL_AUTHORITY_SCHEMA_INVALID")
            meta = {r["key"]: r["value"] for r in db.execute("SELECT * FROM external_meta")}
            # Profile metadata is part of the identity. A network-profile file
            # must not reopen as the records store, including on old snapshots.
            if set(meta) != set(self._config) | {"last_now", "clock_fault"}:
                raise ControlError("EXTERNAL_AUTHORITY_PROFILE_MISMATCH")
            if any(self._config.get(k) != v for k, v in self._profile_configuration().items()):
                raise ControlError("EXTERNAL_AUTHORITY_PROFILE_MISMATCH")
            if any(meta.get(k) != v for k, v in self._config.items()):
                raise ControlError("EXTERNAL_AUTHORITY_PIN_MISMATCH")
            _time(float(meta["last_now"]))
            if meta.get("clock_fault") not in ("0", "1"):
                raise ControlError("EXTERNAL_AUTHORITY_SCHEMA_INVALID")
            # Validate required columns on reopen; an existing partial schema is
            # never upgraded or repaired implicitly.
            db.execute("SELECT root_id,receiver_id,policy_digest,epoch,state,max_actions,issued_count,lifetime_seconds,created_at,expires_at,stopped_at,stop_reason FROM external_roots LIMIT 0")
            db.execute("SELECT action_id,attempt_id,reservation_id,root_id,action_digest,action_json,authorization_digest,status,reason,issued_at,receipt_json,receipt_digest FROM external_actions LIMIT 0")
            db.execute("SELECT execution_id,root_id,parent_execution_id,epoch FROM external_executions LIMIT 0")
        except (sqlite3.Error, KeyError, ValueError) as exc:
            raise ControlError("EXTERNAL_AUTHORITY_SCHEMA_INVALID") from exc

    def _now(self, db: sqlite3.Connection) -> float:
        last = _time(float(db.execute("SELECT value FROM external_meta WHERE key='last_now'").fetchone()[0]))
        if db.execute("SELECT value FROM external_meta WHERE key='clock_fault'").fetchone()[0] == "1":
            raise ControlError("EXTERNAL_AUTHORITY_CLOCK_UNSAFE")
        try:
            now = _time(self._clock())
            unsafe = now < last
        except (ControlError, TypeError, ValueError, OverflowError):
            unsafe = True
        if unsafe:
            # This sticky fault must survive the exception/transaction context.
            # _now is sampled before each mutation, so there is no half-applied
            # action to commit. Pending permits remain pending; no STOPPED ack.
            db.execute("UPDATE external_meta SET value='1' WHERE key='clock_fault'")
            for root in db.execute("SELECT root_id FROM external_roots ORDER BY root_id").fetchall():
                self._checkpoint(db, root[0], "CLOCK_UNSAFE", last)
            db.commit()
            raise ControlError("EXTERNAL_AUTHORITY_CLOCK_ROLLBACK")
        db.execute("UPDATE external_meta SET value=? WHERE key='last_now'", (str(now),))
        return now

    def _root(self, db: sqlite3.Connection, root_id: str) -> sqlite3.Row:
        root = db.execute("SELECT * FROM external_roots WHERE root_id=?", (root_id,)).fetchone()
        if root is None:
            raise ControlError("EXTERNAL_AUTHORITY_UNKNOWN_ROOT")
        return root

    def _state(self, db: sqlite3.Connection, root_id: str) -> dict[str, Any]:
        root = self._root(db, root_id)
        counts = {r["status"]: r["n"] for r in db.execute(
            "SELECT status,COUNT(*) n FROM external_actions WHERE root_id=? GROUP BY status", (root_id,))}
        fault = db.execute("SELECT value FROM external_meta WHERE key='clock_fault'").fetchone()[0] == "1"
        return {**dict(root), "pending_count": counts.get("PENDING", 0),
                "committed_count": counts.get("COMMITTED", 0), "denied_count": counts.get("DENIED", 0),
                "clock_fault": fault, "admission_closed": root["state"] != "ACTIVE" or fault}

    def _checkpoint(self, db: sqlite3.Connection, root_id: str, event: str, now: float, *,
                    action_digest: str | None = None, receipt_digest: str | None = None) -> None:
        from .external_checkpoint import append_checkpoint
        state = self._state(db, root_id)
        append_checkpoint(db, authority_id=self._pin["authority_id"], signer_id=self._pin["authority_id"],
            key_id=self._pin["key_id"], public_key=self._pin["public_key"],
            private_key=self._private_bytes, root_id=root_id, epoch=state["epoch"], kind=event,
            state_digest=digest(state), now=now, action_digest=action_digest, receipt_digest=receipt_digest)

    def _close_expired(self, db: sqlite3.Connection, root: sqlite3.Row, now: float) -> sqlite3.Row:
        if root["state"] == "ACTIVE" and now >= root["expires_at"]:
            pending = self._state(db, root["root_id"])["pending_count"]
            db.execute("UPDATE external_roots SET state=?,epoch=epoch+1,stopped_at=?,stop_reason='EXPIRED' WHERE root_id=?",
                       ("STOPPING" if pending else "STOPPED", now, root["root_id"]))
            self._checkpoint(db, root["root_id"], "ROOT_EXPIRED", now)
            return self._root(db, root["root_id"])
        return root

    def create_root(self, root_id: str, receiver_id: str, policy_digest: str, max_actions: int,
                    lifetime_seconds: float) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(receiver_id, "receiver_id")
        _hex(policy_digest)
        lifetime = _time(lifetime_seconds)
        if type(max_actions) is not int or not 1 <= max_actions <= MAX_RECORDED_ACTIONS or not 0 < lifetime <= 86400:
            raise ControlError("EXTERNAL_AUTHORITY_LIMIT_INVALID")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM external_roots WHERE root_id=?", (root_id,)).fetchone()
            if existing:
                if ((existing["receiver_id"], existing["policy_digest"], existing["max_actions"], existing["lifetime_seconds"])
                        != (receiver_id, policy_digest, max_actions, lifetime) or existing["state"] != "ACTIVE"):
                    raise ControlError("EXTERNAL_AUTHORITY_ROOT_IMMUTABLE")
            else:
                if db.execute("SELECT COUNT(*) FROM external_roots").fetchone()[0] >= MAX_ROOTS:
                    raise ControlError("EXTERNAL_AUTHORITY_ROOT_CAPACITY")
                now = self._now(db)
                db.execute("INSERT INTO external_roots VALUES (?,?,?,1,'ACTIVE',?,0,?,?,?,NULL,NULL)",
                           (root_id, receiver_id, policy_digest, max_actions, lifetime, now, now + lifetime))
                self._checkpoint(db, root_id, "ROOT_CREATED", now)
            result = {"status": "ROOT_CREATED", **self._state(db, root_id)}
        return result

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(execution_id, "execution_id")
        if parent_execution_id is not None:
            validate_id(parent_execution_id, "parent_execution_id")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            root = self._root(db, root_id)
            now = self._now(db)
            root = self._close_expired(db, root, now)
            if root["state"] != "ACTIVE" and root["stop_reason"] == "EXPIRED":
                return {"status": "DENIED", "reason": "EXTERNAL_AUTHORITY_EXPIRED", **self._state(db, root_id)}
            if root["state"] != "ACTIVE":
                raise ControlError("EXTERNAL_AUTHORITY_ADMISSION_CLOSED")
            if parent_execution_id is not None:
                parent = db.execute("SELECT * FROM external_executions WHERE execution_id=?", (parent_execution_id,)).fetchone()
                if parent is None or parent["root_id"] != root_id or parent["epoch"] != root["epoch"]:
                    raise ControlError("EXTERNAL_AUTHORITY_LINEAGE_MISMATCH")
            existing = db.execute("SELECT * FROM external_executions WHERE execution_id=?", (execution_id,)).fetchone()
            if existing:
                if (existing["root_id"], existing["parent_execution_id"], existing["epoch"]) != (root_id, parent_execution_id, root["epoch"]):
                    raise ControlError("EXTERNAL_AUTHORITY_EXECUTION_IMMUTABLE")
            else:
                if db.execute("SELECT COUNT(*) FROM external_executions").fetchone()[0] >= MAX_EXECUTIONS:
                    raise ControlError("EXTERNAL_AUTHORITY_EXECUTION_LIMIT")
                db.execute("INSERT INTO external_executions VALUES (?,?,?,?)", (execution_id, root_id, parent_execution_id, root["epoch"]))
                self._checkpoint(db, root_id, "EXECUTION_BOUND", now)
            result = {"status": "BOUND", "root_id": root_id, "execution_id": execution_id,
                      "parent_execution_id": parent_execution_id, "epoch": root["epoch"]}
        return result

    def _result(self, row: sqlite3.Row, root: sqlite3.Row, *, first: bool = False) -> dict[str, Any]:
        action = json.loads(row["action_json"])
        status = ("PERMITTED" if row["status"] == "PENDING" else "DENIED") if first else (
            "UNKNOWN" if row["status"] == "PENDING" else "CONSUMED")
        return {"status": status, "reason": row["reason"], "reservation_id": row["reservation_id"],
                "action_digest": row["action_digest"], "receiver_id": root["receiver_id"],
                **{field: action[field] for field in ("root_id", "execution_id", "epoch", "action_id", "attempt_id")},
                "outcome": None if row["status"] == "PENDING" else row["status"],
                "receipt": json.loads(row["receipt_json"]) if row["receipt_json"] is not None else None}

    def begin(self, action: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any]:
        action = self._validate_action(action)
        if not isinstance(authorization, dict) or set(authorization) != _AUTHORIZATION_FIELDS:
            raise ControlError("EXTERNAL_AUTHORITY_GRANT_INVALID")
        authorization = json.loads(canonical_bytes(authorization))
        _hex(authorization["action_digest"])
        validate_id(authorization["policy_version"], "policy_version")
        validate_id(authorization["receiver_id"], "receiver_id")
        expiry = _time(authorization["expires_at"])
        action_hash, authorization_hash = digest(action), digest(authorization)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM external_actions WHERE action_id=? OR attempt_id=?",
                              (action["action_id"], action["attempt_id"])).fetchall()
            if rows:
                if len(rows) != 1 or rows[0]["action_digest"] != action_hash or rows[0]["authorization_digest"] != authorization_hash:
                    return {"status": "DENIED", "reason": "EXTERNAL_AUTHORITY_REUSE_MISMATCH",
                            "action_id": action["action_id"], "action_digest": action_hash}
                return self._result(rows[0], self._root(db, rows[0]["root_id"]))
            if db.execute("SELECT COUNT(*) FROM external_actions").fetchone()[0] >= MAX_RECORDED_ACTIONS:
                return {"status": "DENIED", "reason": "EXTERNAL_AUTHORITY_ACTION_CAPACITY",
                        "action_id": action["action_id"], "action_digest": action_hash}
            root = self._root(db, action["root_id"])
            now = self._now(db)  # after the writer lock, never caller/receiver time
            root = self._close_expired(db, root, now)
            execution = db.execute("SELECT * FROM external_executions WHERE execution_id=?", (action["execution_id"],)).fetchone()
            reason = None
            if root["stop_reason"] == "EXPIRED":
                reason = "EXTERNAL_AUTHORITY_EXPIRED"
            elif root["state"] != "ACTIVE" or root["epoch"] != action["epoch"]:
                reason = "EXTERNAL_AUTHORITY_STOPPED"
            elif now >= root["expires_at"] or now >= expiry:
                reason = "EXTERNAL_AUTHORITY_EXPIRED"
            elif (authorization["action_digest"] != action_hash or authorization["policy_version"] != root["policy_digest"]
                  or authorization["receiver_id"] != root["receiver_id"]):
                reason = "EXTERNAL_AUTHORITY_GRANT_MISMATCH"
            elif execution is None or execution["root_id"] != action["root_id"] or execution["epoch"] != action["epoch"]:
                reason = "EXTERNAL_AUTHORITY_LINEAGE_MISMATCH"
            elif root["issued_count"] >= root["max_actions"]:
                reason = "EXTERNAL_AUTHORITY_BUDGET_EXHAUSTED"
            status = "DENIED" if reason else "PENDING"
            reservation_id = "reservation:" + secrets.token_hex(24)
            db.execute("INSERT INTO external_actions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                       (action["action_id"], action["attempt_id"], reservation_id, action["root_id"], action_hash,
                        canonical_bytes(action).decode(), authorization_hash, status, reason or "ONE_SHOT_PERMIT", now))
            if status == "PENDING":
                db.execute("UPDATE external_roots SET issued_count=issued_count+1 WHERE root_id=?", (action["root_id"],))
            self._checkpoint(db, action["root_id"], "BEGIN_" + status, now, action_digest=action_hash)
            row = db.execute("SELECT * FROM external_actions WHERE action_id=?", (action["action_id"],)).fetchone()
            result = self._result(row, root, first=True)
        return result

    def finish(self, reservation_id: str, receipt: dict[str, Any]) -> dict[str, Any]:
        validate_id(reservation_id, "reservation_id")
        receipt = self._verify_terminal_receipt(receipt)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM external_actions WHERE reservation_id=?", (reservation_id,)).fetchone()
            if row is None:
                raise ControlError("EXTERNAL_AUTHORITY_RESERVATION_UNKNOWN")
            root = self._root(db, row["root_id"])
            action = json.loads(row["action_json"])
            status = self._bind_terminal_receipt(receipt, row, root, action)
            receipt_hash = digest(receipt)
            if row["status"] != "PENDING":
                if row["receipt_digest"] != receipt_hash:
                    raise ControlError("EXTERNAL_AUTHORITY_TERMINAL_IMMUTABLE")
                return {**self._result(row, root), "status": "SETTLED"}
            now = self._now(db)
            root = self._close_expired(db, root, now)
            db.execute("UPDATE external_actions SET status=?,reason=?,receipt_json=?,receipt_digest=? WHERE reservation_id=?",
                       (status, self._terminal_reason_prefix() + status, canonical_bytes(receipt).decode(), receipt_hash, reservation_id))
            if root["state"] == "STOPPING" and self._state(db, row["root_id"])["pending_count"] == 0:
                db.execute("UPDATE external_roots SET state='STOPPED' WHERE root_id=?", (row["root_id"],))
            self._checkpoint(db, row["root_id"], "FINISH_" + status, now,
                             action_digest=row["action_digest"], receipt_digest=receipt_hash)
            updated = db.execute("SELECT * FROM external_actions WHERE reservation_id=?", (reservation_id,)).fetchone()
            result = {**self._result(updated, root), "status": "SETTLED"}
        return result

    def query(self, action_id: str) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        with self._connection() as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM external_actions WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                return {"status": "UNKNOWN", "reason": "NOT_OBSERVED", "action_id": action_id,
                        "reservation_id": None, "outcome": None, "receipt": None}
            return self._result(row, self._root(db, row["root_id"]))

    def stop(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            root = self._root(db, root_id)
            if self._state(db, root_id)["clock_fault"]:
                raise ControlError("EXTERNAL_AUTHORITY_CLOCK_UNSAFE")
            if root["state"] == "ACTIVE":
                now = self._now(db)
                root = self._close_expired(db, root, now)
                if root["state"] == "ACTIVE":
                    pending = self._state(db, root_id)["pending_count"]
                    db.execute("UPDATE external_roots SET state=?,epoch=epoch+1,stopped_at=?,stop_reason='OPERATOR_STOP' WHERE root_id=?",
                               ("STOPPING" if pending else "STOPPED", now, root_id))
                    self._checkpoint(db, root_id, "STOP_REQUESTED", now)
            state = self._state(db, root_id)
            result = {"status": "STOPPED" if state["state"] == "STOPPED" else "STOP_PENDING", **state}
        return result

    def status(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with self._connection() as db:
            db.execute("BEGIN")
            state = self._state(db, root_id)
            try:
                state["deadline_reached"] = _time(self._clock()) >= state["expires_at"]
            except (ControlError, TypeError, ValueError, OverflowError):
                state["deadline_reached"] = None
                state["admission_closed"] = True
            if state["deadline_reached"]:
                state["admission_closed"] = True
            return {"status": state["state"], **state}

    def checkpoints(self) -> list[dict[str, Any]]:
        from .external_checkpoint import checkpoint_entries
        with self._connection() as db:
            db.execute("BEGIN")
            return checkpoint_entries(db, self._pin["authority_id"])
