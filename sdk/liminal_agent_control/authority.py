"""Trusted SQLite authority and authentication primitives for the owned pilot.

HMAC authenticates data between trusted services; it is not non-repudiation.
The worker must have neither these keys nor filesystem access to their databases.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Any


class ControlError(ValueError):
    pass


ACTION_FIELDS = frozenset({"action_id", "attempt_id", "root_id", "execution_id", "epoch", "target", "arguments"})


def _finite_json(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise ControlError("JSON nesting limit")
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            raise ControlError("integer outside supported range")
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _finite_json(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values():
            _finite_json(item, depth + 1)
        return
    raise ControlError("only finite JSON values with string keys are supported")


def canonical_bytes(value: Any) -> bytes:
    _finite_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_id(value: Any, field: str = "id") -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ControlError(f"invalid {field}")
    return value


def validate_action(action: Any) -> dict[str, Any]:
    if not isinstance(action, dict) or set(action) != ACTION_FIELDS:
        raise ControlError("action must contain exactly the declared fields")
    for field in ("action_id", "attempt_id", "root_id", "execution_id"):
        validate_id(action[field], field)
    if type(action["epoch"]) is not int or not 1 <= action["epoch"] < 2**63:
        raise ControlError("epoch must be a positive integer")
    if action["target"] != "records" or not isinstance(action["arguments"], dict):
        raise ControlError("only records target with object arguments is supported")
    encoded = canonical_bytes(action)
    if len(encoded) > 16384:
        raise ControlError("action exceeds 16 KiB")
    return json.loads(encoded)


def require_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ControlError("authentication keys must contain at least 32 bytes")
    return key


def sign_document(document: dict[str, Any], key: bytes) -> dict[str, Any]:
    require_key(key)
    body = {k: v for k, v in document.items() if k != "signature"}
    return {**body, "signature": hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()}


def verify_receipt(document: Any, key: bytes) -> bool:
    try:
        require_key(key)
        if not isinstance(document, dict) or not isinstance(document.get("signature"), str):
            return False
        expected = sign_document(document, key)["signature"]
        return hmac.compare_digest(expected, document["signature"])
    except (ControlError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def connect(path: str | Path, *, create: bool = True) -> sqlite3.Connection:
    target = str(path) if create else Path(path).resolve().as_uri() + "?mode=rw"
    connection = sqlite3.connect(target, timeout=30, isolation_level=None, uri=not create)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


class AuthorityStore:
    """Authority state shares the receiver transaction with acceptance.

Each method owns a short SQLite transaction. Revocation acknowledgement is
returned only after COMMIT. A root id cannot be resurrected or rebound.
"""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with connect(self.db_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS roots (
                    root_id TEXT PRIMARY KEY, owner_ref TEXT NOT NULL,
                    epoch INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES roots(root_id),
                    parent_execution_id TEXT REFERENCES executions(execution_id), epoch INTEGER NOT NULL
                );
            """)
        self.db_path.chmod(0o600)

    def create_root(self, root_id: str, owner_ref: str = "operator") -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(owner_ref, "owner_ref")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
            if existing:
                if existing["owner_ref"] != owner_ref or existing["revoked"]:
                    raise ControlError("root cannot be rebound or resurrected")
            else:
                db.execute("INSERT INTO roots(root_id,owner_ref,epoch) VALUES (?,?,1)", (root_id, owner_ref))
            return {"status": "ROOT_CREATED", "root_id": root_id, "owner_ref": owner_ref, "epoch": 1}

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(execution_id, "execution_id")
        if parent_execution_id is not None:
            validate_id(parent_execution_id, "parent_execution_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            root = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
            if root is None or root["revoked"]:
                raise ControlError("no active root")
            if parent_execution_id is not None:
                parent = db.execute("SELECT * FROM executions WHERE execution_id=?", (parent_execution_id,)).fetchone()
                if parent is None or parent["root_id"] != root_id or parent["epoch"] != root["epoch"]:
                    raise ControlError("parent lineage mismatch")
            existing = db.execute("SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
            if existing:
                if (existing["root_id"], existing["parent_execution_id"], existing["epoch"]) != (root_id, parent_execution_id, root["epoch"]):
                    raise ControlError("execution binding is immutable")
            else:
                db.execute("INSERT INTO executions VALUES (?,?,?,?)", (execution_id, root_id, parent_execution_id, root["epoch"]))
            return {"status": "BOUND", "root_id": root_id, "execution_id": execution_id,
                    "parent_execution_id": parent_execution_id, "epoch": root["epoch"]}

    def revoke(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            root = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
            if root is None:
                raise ControlError("unknown root")
            if not root["revoked"]:
                db.execute("UPDATE roots SET epoch=epoch+1,revoked=1,revoked_at=? WHERE root_id=?", (time.time(), root_id))
            root = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
            result = {"status": "REVOKED", "root_id": root_id, "epoch": root["epoch"], "revoked_at": root["revoked_at"]}
        return result

    @staticmethod
    def denial(db: sqlite3.Connection, action: dict[str, Any], *, enforce_epoch: bool = True) -> str | None:
        root = db.execute("SELECT * FROM roots WHERE root_id=?", (action["root_id"],)).fetchone()
        execution = db.execute("SELECT * FROM executions WHERE execution_id=?", (action["execution_id"],)).fetchone()
        if root is None or execution is None:
            return "UNKNOWN_LINEAGE"
        if execution["root_id"] != action["root_id"] or execution["epoch"] != action["epoch"]:
            return "EXECUTION_BINDING_MISMATCH"
        if enforce_epoch and (root["revoked"] or root["epoch"] != action["epoch"]):
            return "AUTHORITY_REVOKED"
        return None
