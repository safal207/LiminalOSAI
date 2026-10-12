"""Host-owned durable session admission; never invokes external callbacks.

All budget reservations are conservative and permanent. STOP closes admission,
not the completion of work admitted earlier. Host methods are not worker APIs.
"""
from __future__ import annotations

import math
import json
import re
import time
from pathlib import Path
from typing import Any, Callable

from .authority import ACTION_FIELDS, AuthorityStore, ControlError, canonical_bytes, connect, digest, validate_id


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ControlError(f"invalid {field}")
    return value


def _number(value: Any, field: str, *, positive: bool = False) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0 or (positive and value == 0)):
        raise ControlError(f"invalid {field}")
    return float(value)


def _action(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ACTION_FIELDS:
        raise ControlError("invalid action fields")
    for field in ("action_id", "attempt_id", "root_id", "execution_id", "target"):
        validate_id(value[field], field)
    if type(value["epoch"]) is not int or not 1 <= value["epoch"] < 2**63:
        raise ControlError("invalid epoch")
    if not isinstance(value["arguments"], dict) or len(canonical_bytes(value)) > 16384:
        raise ControlError("invalid action arguments")
    return json.loads(canonical_bytes(value))


class SessionAuthority:
    """One SQLite authority domain for receiver and staged egress admission.

    The database, clock and all administrative methods must be inaccessible to
    untrusted workers. A session never reactivates after STOP, expiry or clock
    failure. A trusted new controller needs a new root, never renewed old state.
    """

    def __init__(self, db_path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.db_path, self.clock = Path(db_path), clock
        AuthorityStore(self.db_path)
        with connect(self.db_path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS brakes_sessions (
                    root_id TEXT PRIMARY KEY REFERENCES roots(root_id),
                    controller_id TEXT NOT NULL, policy_digest TEXT NOT NULL,
                    objective_digest TEXT NOT NULL, max_actions INTEGER NOT NULL,
                    max_executions INTEGER NOT NULL, max_depth INTEGER NOT NULL,
                    max_stages INTEGER NOT NULL, created_at REAL NOT NULL,
                    hard_deadline REAL NOT NULL, lease_seconds REAL NOT NULL,
                    lease_until REAL NOT NULL, last_now REAL NOT NULL,
                    lease_revision INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL, stop_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS brakes_actions (
                    action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                    root_id TEXT NOT NULL REFERENCES brakes_sessions(root_id),
                    execution_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    channel TEXT NOT NULL, action_digest TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, policy_digest TEXT NOT NULL,
                    status TEXT NOT NULL, admitted_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS brakes_executions (
                    execution_id TEXT PRIMARY KEY REFERENCES executions(execution_id),
                    root_id TEXT NOT NULL REFERENCES brakes_sessions(root_id),
                    parent_execution_id TEXT, epoch INTEGER NOT NULL,
                    depth INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS brakes_stages (
                    action_id TEXT NOT NULL REFERENCES brakes_actions(action_id),
                    stage_id TEXT NOT NULL, status TEXT NOT NULL,
                    admitted_at REAL NOT NULL, PRIMARY KEY(action_id, stage_id)
                );
            """)

    def _now(self) -> float:
        try:
            return _number(self.clock(), "trusted clock")
        except Exception as exc:
            raise ControlError("trusted clock unavailable") from exc

    def _require_transaction(self, db: Any) -> None:
        if not db.in_transaction:
            raise ControlError("requires caller's write transaction")
        databases = db.execute("PRAGMA database_list").fetchall()
        main = next((row[2] for row in databases if row[1] == "main"), None)
        if not main or Path(main).resolve() != self.db_path.resolve():
            raise ControlError("transaction belongs to a different authority database")

    @staticmethod
    def _close(db: Any, row: Any, state: str, reason: str) -> None:
        db.execute("UPDATE brakes_sessions SET state=?,stop_reason=? WHERE root_id=? AND state='ACTIVE'",
                   (state, reason, row["root_id"]))
        db.execute("UPDATE roots SET epoch=epoch+1,revoked=1,revoked_at=? WHERE root_id=? AND revoked=0",
                   (row["last_now"], row["root_id"]))

    def _fresh(self, db: Any, root_id: str) -> tuple[Any, str | None]:
        row = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
        if row is None:
            return None, "UNKNOWN_SESSION"
        if row["state"] != "ACTIVE":
            return row, row["stop_reason"] or "SESSION_STOPPED"
        root = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
        if root is None or root["revoked"]:
            self._close(db, row, "STOPPED", "ROOT_REVOKED")
        else:
            try:
                now = self._now()  # Read only after obtaining the write lock.
                if now < row["last_now"]:
                    raise ControlError("clock rollback")
            except ControlError:
                self._close(db, row, "CLOCK_UNSAFE", "CLOCK_UNSAFE")
            else:
                db.execute("UPDATE brakes_sessions SET last_now=? WHERE root_id=?", (now, root_id))
                row = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
                if now >= row["hard_deadline"]:
                    self._close(db, row, "EXPIRED", "HARD_DEADLINE_EXPIRED")
                elif now >= row["lease_until"]:
                    self._close(db, row, "EXPIRED", "LEASE_EXPIRED")
        row = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
        return row, None if row["state"] == "ACTIVE" else row["stop_reason"]

    @staticmethod
    def _result(status: str, reason: str, action_id: str | None = None, **extra: Any) -> dict[str, Any]:
        return {"status": status, "reason": reason, "action_id": action_id, **extra}

    @staticmethod
    def _snapshot(db: Any, row: Any) -> dict[str, Any]:
        root = db.execute("SELECT epoch FROM roots WHERE root_id=?", (row["root_id"],)).fetchone()
        result = dict(row)
        result.update(status=row["state"], epoch=root[0], control_profile="durable-session-v1")
        result["action_count"] = db.execute("SELECT COUNT(*) FROM brakes_actions WHERE root_id=?", (row["root_id"],)).fetchone()[0]
        result["execution_count"] = db.execute("SELECT COUNT(*) FROM executions WHERE root_id=?", (row["root_id"],)).fetchone()[0]
        result["stage_count"] = db.execute("SELECT COUNT(*) FROM brakes_stages s JOIN brakes_actions a USING(action_id) WHERE a.root_id=?", (row["root_id"],)).fetchone()[0]
        result["pending_action_count"] = db.execute("SELECT COUNT(*) FROM brakes_actions WHERE root_id=? AND status IN ('RESERVED','UNKNOWN')", (row["root_id"],)).fetchone()[0]
        result["pending_stage_count"] = db.execute("SELECT COUNT(*) FROM brakes_stages s JOIN brakes_actions a USING(action_id) WHERE a.root_id=? AND s.status IN ('RESERVED','UNKNOWN')", (row["root_id"],)).fetchone()[0]
        result["remaining_actions"] = row["max_actions"] - result["action_count"]
        result["remaining_stages"] = row["max_stages"] - result["stage_count"]
        return result

    def create_session(self, root_id: str, *, controller_id: str, policy_digest: str,
                       objective_digest: str, max_actions: int, max_executions: int,
                       max_depth: int, max_stages: int, lifetime_seconds: float,
                       lease_seconds: float) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(controller_id, "controller_id")
        _hash(policy_digest, "policy_digest")
        _hash(objective_digest, "objective_digest")
        for name, value, minimum in (("max_actions", max_actions, 1), ("max_executions", max_executions, 1),
                                     ("max_depth", max_depth, 0), ("max_stages", max_stages, 0)):
            if type(value) is not int or not minimum <= value < 2**63:
                raise ControlError(f"invalid {name}")
        lifetime = _number(lifetime_seconds, "lifetime_seconds", positive=True)
        lease = _number(lease_seconds, "lease_seconds", positive=True)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            now = self._now()
            deadline = _number(now + lifetime, "hard_deadline", positive=True)
            lease_until = min(deadline, _number(now + lease, "lease_until", positive=True))
            if db.execute("SELECT 1 FROM roots WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("session root must be new")
            db.execute("INSERT INTO roots(root_id,owner_ref,epoch) VALUES (?,?,1)", (root_id, controller_id))
            db.execute("INSERT INTO brakes_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,'ACTIVE',NULL)",
                       (root_id, controller_id, policy_digest, objective_digest, max_actions,
                        max_executions, max_depth, max_stages, now, deadline, lease, lease_until, now))
            return self._snapshot(db, db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone())

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        for field, value in (("root_id", root_id), ("execution_id", execution_id)):
            validate_id(value, field)
        if parent_execution_id is not None:
            validate_id(parent_execution_id, "parent_execution_id")
        failure = None
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session, failure = self._fresh(db, root_id)
            if failure is None:
                epoch = db.execute("SELECT epoch FROM roots WHERE root_id=?", (root_id,)).fetchone()[0]
                old = db.execute("SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
                if old:
                    registered = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (execution_id,)).fetchone()
                    if registered is None:
                        failure = "EXECUTION_NOT_REGISTERED"
                    elif (old["root_id"], old["parent_execution_id"], old["epoch"]) != (root_id, parent_execution_id, epoch):
                        failure = "EXECUTION_BINDING_MISMATCH"
                else:
                    depth, ancestor, seen = 0, parent_execution_id, set()
                    while ancestor is not None and failure is None:
                        parent = db.execute("SELECT * FROM executions WHERE execution_id=?", (ancestor,)).fetchone()
                        registered = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (ancestor,)).fetchone()
                        if (ancestor in seen or parent is None or registered is None
                                or parent["root_id"] != root_id or parent["epoch"] != epoch):
                            failure = "PARENT_LINEAGE_MISMATCH"
                            break
                        seen.add(ancestor)
                        depth += 1
                        ancestor = parent["parent_execution_id"]
                    count = db.execute("SELECT COUNT(*) FROM executions WHERE root_id=?", (root_id,)).fetchone()[0]
                    if failure is None and (depth > session["max_depth"] or count >= session["max_executions"]):
                        failure = "EXECUTION_DEPTH_EXCEEDED" if depth > session["max_depth"] else "EXECUTION_BUDGET_EXHAUSTED"
                    if failure is None:
                        db.execute("INSERT INTO executions VALUES (?,?,?,?)", (execution_id, root_id, parent_execution_id, epoch))
                        db.execute("INSERT INTO brakes_executions VALUES (?,?,?,?,?)", (execution_id, root_id, parent_execution_id, epoch, depth))
        if failure:
            raise ControlError(failure)
        return {"status": "BOUND", "root_id": root_id, "execution_id": execution_id,
                "parent_execution_id": parent_execution_id, "epoch": epoch}

    def renew(self, root_id: str, *, controller_id: str, expected_epoch: int,
              expected_revision: int) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        failure = None
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row, failure = self._fresh(db, root_id)
            if failure is None:
                epoch = db.execute("SELECT epoch FROM roots WHERE root_id=?", (root_id,)).fetchone()[0]
                if (type(expected_epoch) is not int or epoch != expected_epoch
                        or type(expected_revision) is not int or expected_revision != row["lease_revision"]
                        or controller_id != row["controller_id"]):
                    failure = "CONTROLLER_OR_EPOCH_MISMATCH"
                else:
                    db.execute("UPDATE brakes_sessions SET lease_until=?,lease_revision=lease_revision+1 WHERE root_id=?",
                               (min(row["hard_deadline"], row["last_now"] + row["lease_seconds"]), root_id))
                    result = self._snapshot(db, db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone())
        if failure:
            raise ControlError(failure)
        return result

    def stop(self, root_id: str, reason: str = "OPERATOR_STOP") -> dict[str, Any]:
        validate_id(root_id, "root_id")
        validate_id(reason, "reason")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
            if row is None:
                raise ControlError("UNKNOWN_SESSION")
            self._close(db, row, "STOPPED", reason)
            return self._snapshot(db, db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone())

    def status(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row, reason = self._fresh(db, root_id)
            if row is None:
                return self._result("BLOCKED", reason)
            return self._snapshot(db, row)

    def check_session_in_transaction(self, db: Any, root_id: str) -> dict[str, Any]:
        """Fresh administrative check; does not reserve or authorize any effect."""
        self._require_transaction(db)
        validate_id(root_id, "root_id")
        row, reason = self._fresh(db, root_id)
        if reason:
            return self._result("BLOCKED", reason, root_id=root_id)
        epoch = db.execute("SELECT epoch FROM roots WHERE root_id=?", (root_id,)).fetchone()[0]
        return self._result("ADMITTED", "SESSION_ACTIVE", root_id=root_id,
                            policy_digest=row["policy_digest"], epoch=epoch)

    def admit_in_transaction(self, db: Any, action: dict[str, Any], *, channel: str,
                             payload_digest: str | None = None, policy_digest: str | None = None) -> dict[str, Any]:
        self._require_transaction(db)
        try:
            action = _action(action)
            if channel not in {"records", "egress"}:
                raise ControlError("unsupported channel")
            payload_digest = _hash(payload_digest, "payload_digest") if payload_digest is not None else digest(action)
            if policy_digest is not None:
                _hash(policy_digest, "policy_digest")
        except (ControlError, ValueError, TypeError):
            return self._result("BLOCKED", "INVALID_ACTION_BINDING")
        aid = action["action_id"]
        row, reason = self._fresh(db, action["root_id"])
        if reason:
            return self._result("BLOCKED", reason, aid)
        if policy_digest is not None and policy_digest != row["policy_digest"]:
            return self._result("BLOCKED", "POLICY_MISMATCH", aid)
        reason = AuthorityStore.denial(db, action)
        if reason:
            return self._result("BLOCKED", reason, aid)
        registered = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (action["execution_id"],)).fetchone()
        if (registered is None or registered["root_id"] != action["root_id"]
                or registered["epoch"] != action["epoch"]):
            return self._result("BLOCKED", "EXECUTION_NOT_REGISTERED", aid)
        old = db.execute("SELECT * FROM brakes_actions WHERE action_id=? OR attempt_id=?", (aid, action["attempt_id"])).fetchone()
        if old:
            exact = (old["action_id"] == aid and old["action_digest"] == digest(action)
                     and old["payload_digest"] == payload_digest and old["channel"] == channel)
            return self._result("BLOCKED", "ACTION_ALREADY_RESERVED" if exact else "ACTION_BINDING_MISMATCH", aid)
        used = db.execute("SELECT COUNT(*) FROM brakes_actions WHERE root_id=?", (action["root_id"],)).fetchone()[0]
        if used >= row["max_actions"]:
            return self._result("BLOCKED", "ACTION_BUDGET_EXHAUSTED", aid)
        db.execute("INSERT INTO brakes_actions VALUES (?,?,?,?,?,?,?,?,?,'RESERVED',?)",
                   (aid, action["attempt_id"], action["root_id"], action["execution_id"], action["epoch"],
                    channel, digest(action), payload_digest, row["policy_digest"], row["last_now"]))
        return self._result("ADMITTED", "SESSION_ADMISSION_RESERVED", aid, root_id=action["root_id"],
                            epoch=action["epoch"], channel=channel, policy_digest=row["policy_digest"])

    def reserve(self, action: dict[str, Any], *, channel: str, payload_digest: str | None = None,
                policy_digest: str | None = None) -> dict[str, Any]:
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            return self.admit_in_transaction(db, action, channel=channel, payload_digest=payload_digest, policy_digest=policy_digest)

    def begin_stage(self, action_id: str, *, stage_id: str) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        validate_id(stage_id, "stage_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            action = db.execute("SELECT * FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()
            if action is None:
                return self._result("BLOCKED", "UNKNOWN_ACTION", action_id)
            row, reason = self._fresh(db, action["root_id"])
            if reason:
                return self._result("BLOCKED", reason, action_id)
            if action["status"] != "RESERVED":
                return self._result("BLOCKED", "ACTION_NOT_PENDING", action_id)
            if db.execute("SELECT 1 FROM brakes_stages WHERE action_id=? AND stage_id=?", (action_id, stage_id)).fetchone():
                return self._result("BLOCKED", "STAGE_ALREADY_RESERVED", action_id)
            used = db.execute("SELECT COUNT(*) FROM brakes_stages s JOIN brakes_actions a USING(action_id) WHERE a.root_id=?", (action["root_id"],)).fetchone()[0]
            if used >= row["max_stages"]:
                return self._result("BLOCKED", "STAGE_BUDGET_EXHAUSTED", action_id)
            db.execute("INSERT INTO brakes_stages VALUES (?,?,'RESERVED',?)", (action_id, stage_id, row["last_now"]))
            return self._result("ADMITTED", "STAGE_RESERVED", action_id, stage_id=stage_id)

    def finish_action_in_transaction(self, db: Any, action_id: str, *, outcome: str) -> None:
        self._require_transaction(db)
        if outcome not in {"RETURNED", "UNKNOWN", "COMMITTED"}:
            raise ControlError("invalid action completion")
        row = db.execute("SELECT status,channel FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()
        if row is None or (outcome == "COMMITTED" and row["channel"] != "records"):
            raise ControlError("invalid action completion binding")
        if row["status"] not in {"RESERVED", outcome}:
            raise ControlError("action outcome cannot be rewritten")
        db.execute("UPDATE brakes_actions SET status=? WHERE action_id=?", (outcome, action_id))

    def finish_action(self, action_id: str, *, outcome: str) -> None:
        if outcome not in {"RETURNED", "UNKNOWN"}:
            raise ControlError("invalid action outcome")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self.finish_action_in_transaction(db, action_id, outcome=outcome)

    def finish_stage(self, action_id: str, stage_id: str, *, outcome: str) -> None:
        if outcome not in {"RETURNED", "UNKNOWN"}:
            raise ControlError("invalid stage outcome")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM brakes_stages WHERE action_id=? AND stage_id=?", (action_id, stage_id)).fetchone()
            if row is None or row["status"] not in {"RESERVED", outcome}:
                raise ControlError("stage outcome cannot be rewritten")
            db.execute("UPDATE brakes_stages SET status=? WHERE action_id=? AND stage_id=?", (outcome, action_id, stage_id))
