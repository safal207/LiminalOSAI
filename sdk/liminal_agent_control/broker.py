"""Trusted exact-grant broker with durable uncertain outcomes.

authorize() is an operator/host API, never an untrusted worker capability.
Only handle()/dispatch() accepts worker proposals. A timeout is UNKNOWN until
an authenticated receiver observation matches the exact frozen attempt.
"""
from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any, Callable

from .authority import ControlError, canonical_bytes, connect, digest, validate_action, validate_id


class Broker:
    def __init__(self, db_path: str | Path, receiver: Any, *, clock: Callable[[], float] = time.time) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.receiver, self.clock = receiver, clock
        with connect(self.db_path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS grants (
                action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, action_json TEXT NOT NULL,
                action_digest TEXT NOT NULL, policy_version TEXT NOT NULL, expires_at REAL NOT NULL,
                status TEXT NOT NULL, receipt_json TEXT, receiver_id TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS root_fences (
                root_id TEXT PRIMARY KEY, fenced_at REAL NOT NULL, receiver_ack_json TEXT
            )""")
            db.execute("BEGIN IMMEDIATE")
            if "receiver_id" not in {row[1] for row in db.execute("PRAGMA table_info(grants)")}:
                db.execute("ALTER TABLE grants ADD COLUMN receiver_id TEXT")
        self.db_path.chmod(0o600)

    def _now(self) -> float:
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
            raise ControlError("trusted clock unavailable")
        return float(now)

    def _receiver_identity(self) -> str:
        receiver_id = getattr(self.receiver, "receiver_id", None)
        if receiver_id is None:
            identity = self.receiver.identity()
            if not (self.receiver.verify_receipt(identity) and identity.get("status") == "IDENTITY"
                    and identity.get("schema") == "liminal.agent-control.identity.v1"):
                raise ControlError("receiver identity is not authenticated")
            receiver_id = identity.get("receiver_id")
        return validate_id(receiver_id, "receiver_id")

    def authorize(self, action: dict[str, Any], *, ttl_seconds: float = 60, policy_version: str = "owned-pilot-v1") -> dict[str, Any]:
        action = validate_action(action)
        receiver_id = self._receiver_identity()
        validate_id(policy_version, "policy_version")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 86400:
            raise ControlError("grant TTL must be finite and within one day")
        expires_at = self._now() + ttl_seconds
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM root_fences WHERE root_id=?", (action["root_id"],)).fetchone():
                raise ControlError("root is durably revoked; a new root is required")
            existing = db.execute("SELECT * FROM grants WHERE action_id=? OR attempt_id=?", (action["action_id"], action["attempt_id"])).fetchone()
            if existing:
                if existing["action_digest"] != digest(action) or existing["policy_version"] != policy_version:
                    raise ControlError("grant binding is immutable")
                if existing["receiver_id"] != receiver_id:
                    raise ControlError("grant receiver identity mismatch or legacy unbound grant")
                expires_at = existing["expires_at"]  # Never refresh authority through a repeat call.
            else:
                db.execute("INSERT INTO grants(action_id,attempt_id,action_json,action_digest,policy_version,expires_at,status,receipt_json,receiver_id) VALUES (?,?,?,?,?,?,?,NULL,?)",
                           (action["action_id"], action["attempt_id"], canonical_bytes(action).decode(), digest(action), policy_version, expires_at, "AUTHORIZED", receiver_id))
        return {"status": "AUTHORIZED", "action_id": action["action_id"], "action_digest": digest(action),
                "policy_version": policy_version, "expires_at": expires_at, "receiver_id": receiver_id}

    @staticmethod
    def _result(status: str, reason: str, action_id: str | None, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"status": status, "reason": reason, "action_id": action_id, "receipt": receipt}

    def _bound_receipt(self, receipt: Any, action: dict[str, Any], receiver_id: str | None) -> bool:
        return (isinstance(receipt, dict) and self.receiver.verify_receipt(receipt)
                and isinstance(receiver_id, str) and receipt.get("receiver_id") == receiver_id
                and receipt.get("schema") == "liminal.agent-control.receipt.v1"
                and receipt.get("action_digest") == digest(action)
                and all(receipt.get(k) == action[k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                and type(receipt.get("effect_count")) is int
                and ((receipt.get("status") == "COMMITTED" and receipt.get("effect_count") == 1)
                     or (receipt.get("status") == "DENIED" and receipt.get("effect_count") == 0)))

    def dispatch(self, proposal: dict[str, Any]) -> dict[str, Any]:
        try:
            action = validate_action(proposal)
            now = self._now()
            receiver_id = self._receiver_identity()
        except Exception:
            return self._result("BLOCKED", "INVALID_PROPOSAL_OR_CLOCK", None)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM root_fences WHERE root_id=?", (action["root_id"],)).fetchone():
                return self._result("BLOCKED", "ROOT_REVOKED", action["action_id"])
            row = db.execute("SELECT * FROM grants WHERE action_id=?", (action["action_id"],)).fetchone()
            if row is None or row["action_digest"] != digest(action):
                return self._result("BLOCKED", "NO_EXACT_AUTHORIZATION", action["action_id"])
            if row["receiver_id"] != receiver_id:
                return self._result("BLOCKED", "RECEIVER_IDENTITY_MISMATCH", action["action_id"])
            if row["status"] != "AUTHORIZED":
                reason = "RECONCILIATION_REQUIRED" if row["status"] == "UNKNOWN" else "ACTION_ALREADY_CONSUMED"
                return self._result("BLOCKED", reason, action["action_id"])
            if now >= row["expires_at"]:
                return self._result("BLOCKED", "AUTHORIZATION_EXPIRED", action["action_id"])
            authorization = {"action_digest": row["action_digest"], "policy_version": row["policy_version"], "expires_at": row["expires_at"], "receiver_id": row["receiver_id"]}
            db.execute("UPDATE grants SET status='UNKNOWN' WHERE action_id=?", (action["action_id"],))
        # The durable reservation precedes the first possible receiver side effect.
        try:
            receipt = self.receiver.commit(action, authorization=authorization)
            if not self._bound_receipt(receipt, action, receiver_id):
                return self._result("UNKNOWN", "RECEIVER_RECEIPT_INVALID", action["action_id"])
        except Exception:
            return self._result("UNKNOWN", "RECEIVER_OUTCOME_UNAVAILABLE", action["action_id"])
        status = "COMMITTED" if receipt["status"] == "COMMITTED" else "DENIED"
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE grants SET status=?,receipt_json=? WHERE action_id=? AND status='UNKNOWN'", (status, canonical_bytes(receipt).decode(), action["action_id"]))
        return self._result("COMMITTED" if status == "COMMITTED" else "BLOCKED", receipt["reason"], action["action_id"], receipt)

    handle = dispatch

    def revoke(self, root_id: str) -> dict[str, Any]:
        """Acknowledge only after durable local fence AND authenticated receiver ack."""
        validate_id(root_id, "root_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO root_fences VALUES (?,?,NULL)", (root_id, self._now()))
            for row in db.execute("SELECT action_id,action_json FROM grants WHERE status='AUTHORIZED'").fetchall():
                if json.loads(row["action_json"])["root_id"] == root_id:
                    db.execute("UPDATE grants SET status='CANCELLED' WHERE action_id=?", (row["action_id"],))
            stored = db.execute("SELECT receiver_ack_json FROM root_fences WHERE root_id=?", (root_id,)).fetchone()[0]
        ack = json.loads(stored) if stored else None
        try:
            # A key may be reused by a replacement receiver. A cached receipt is
            # usable only with an already pinned, matching current receiver id.
            cached_valid = bool(ack and getattr(self.receiver, "receiver_id", None) == ack.get("receiver_id")
                and self.receiver.verify_receipt(ack) and ack.get("status") == "REVOKED"
                and ack.get("root_id") == root_id and type(ack.get("epoch")) is int and ack["epoch"] > 1)
        except Exception:
            cached_valid = False
        if not cached_valid:
            try:
                ack = self.receiver.revoke(root_id)
                if not (self.receiver.verify_receipt(ack) and ack.get("status") == "REVOKED"
                        and ack.get("root_id") == root_id and type(ack.get("epoch")) is int and ack["epoch"] > 1):
                    raise ControlError("invalid receiver revocation acknowledgement")
            except Exception:
                return {"status": "INCOMPLETE", "root_id": root_id, "broker_fenced": True,
                        "reason": "RECEIVER_REVOCATION_UNCONFIRMED", "receiver_ack": None}
            with connect(self.db_path) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE root_fences SET receiver_ack_json=? WHERE root_id=?", (canonical_bytes(ack).decode(), root_id))
        return {"status": "REVOKED", "root_id": root_id, "epoch": ack["epoch"],
                "broker_fenced": True, "receiver_ack": ack}

    def state(self, action_id: str) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM grants WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            return self._result("UNKNOWN", "NO_GRANT", action_id)
        return {"status": row["status"], "action_id": action_id, "action_digest": row["action_digest"],
                "policy_version": row["policy_version"], "expires_at": row["expires_at"], "receiver_id": row["receiver_id"],
                "receipt": json.loads(row["receipt_json"]) if row["receipt_json"] else None}

    def reconcile(self, action_id: str) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM grants WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            return self._result("UNKNOWN", "NO_GRANT", action_id)
        if row["status"] != "UNKNOWN":
            return self.state(action_id)
        action = json.loads(row["action_json"])
        if row["receiver_id"] is None:
            return self._result("UNKNOWN", "RECEIVER_IDENTITY_UNBOUND", action_id)
        try:
            receipt = self.receiver.query(action_id)  # Observation only: never calls commit/finalize.
            if not self._bound_receipt(receipt, action, row["receiver_id"]) or receipt["status"] != "COMMITTED":
                return self._result("UNKNOWN", "NO_MATCHING_COMMITTED_RECEIPT", action_id)
        except Exception:
            return self._result("UNKNOWN", "RECEIVER_OUTCOME_UNAVAILABLE", action_id)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE grants SET status='COMMITTED',receipt_json=? WHERE action_id=? AND status='UNKNOWN'", (canonical_bytes(receipt).decode(), action_id))
        return self._result("COMMITTED", "RECONCILED_FROM_RECEIVER", action_id, receipt)
