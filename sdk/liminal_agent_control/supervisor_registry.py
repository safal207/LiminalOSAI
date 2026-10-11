"""Durable, host-only registration for one owned Docker workload at a time.

The registry is not worker authority. A nonblocking host lease excludes a live
controller; an unfinished row never authorizes a new launch. Recovery is an
explicit trusted-host operation, not an automatic startup cleanup heuristic.
"""
from __future__ import annotations

from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # Docker runtime is supported on Linux only.
    fcntl = None
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from typing import Any, Iterator


class RegistryError(ValueError):
    pass


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SESSION = re.compile(r"liminal-(?:control|matched)-[0-9a-f]{32}\Z")


def ownership_labels(record: dict) -> dict[str, str]:
    return {"liminal.control.registry": record["registry_id"],
            "liminal.control.owner": record["ownership_token"],
            "liminal.control.plan": record["plan_sha256"]}


class SupervisorRegistry:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._lease_fd: int | None = None
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS supervisor_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workloads (
                    session_id TEXT PRIMARY KEY, slot INTEGER NOT NULL DEFAULT 1 CHECK(slot=1),
                    status TEXT NOT NULL CHECK(status IN ('REGISTERED','CLOSED')),
                    record_json TEXT NOT NULL, completion_json TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_unfinished_workload ON workloads(slot)
                    WHERE status != 'CLOSED';
            """)
            db.execute("INSERT OR IGNORE INTO supervisor_meta VALUES ('registry_id',?)", (uuid.uuid4().hex,))
            self.registry_id = db.execute("SELECT value FROM supervisor_meta WHERE key='registry_id'").fetchone()[0]
        self.path.chmod(0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=1)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def lease(self) -> Iterator["SupervisorRegistry"]:
        if fcntl is None:
            raise RegistryError("SUPERVISOR_PLATFORM_UNAVAILABLE")
        if self._lease_fd is not None:
            raise RegistryError("SUPERVISOR_BUSY")
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RegistryError("SUPERVISOR_BUSY") from exc
            self._lease_fd = descriptor
            yield self
        finally:
            if self._lease_fd == descriptor:
                self._lease_fd = None
            os.close(descriptor)

    def _require_lease(self) -> None:
        if self._lease_fd is None:
            raise RegistryError("SUPERVISOR_LEASE_REQUIRED")

    def unfinished(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT record_json FROM workloads WHERE status != 'CLOSED'").fetchall()
        return [json.loads(row[0]) for row in rows]

    def register(self, *, session_id: str, root_id: str, action_id: str, image_id: str,
                 plan_sha256: str, backend_identity_sha256: str, receiver_id: str,
                 broker_context_sha256: str) -> dict:
        self._require_lease()
        if (not _SESSION.fullmatch(session_id) or not image_id.startswith("sha256:")
                or not _SHA256.fullmatch(image_id[7:])
                or any(not _SHA256.fullmatch(value) for value in
                       (plan_sha256, backend_identity_sha256, broker_context_sha256))
                or any(type(value) is not str or not 1 <= len(value) <= 256
                       for value in (root_id, action_id, receiver_id))):
            raise RegistryError("REGISTRATION_INVALID")
        record = {"registry_id": self.registry_id, "session_id": session_id,
                  "ownership_token": uuid.uuid4().hex, "root_id": root_id, "action_id": action_id,
                  "image_id": image_id, "plan_sha256": plan_sha256,
                  "backend_identity_sha256": backend_identity_sha256,
                  "receiver_id": receiver_id, "broker_context_sha256": broker_context_sha256,
                  "registered_at": time.time()}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM workloads WHERE status != 'CLOSED'").fetchone():
                raise RegistryError("RECOVERY_REQUIRED")
            db.execute("INSERT INTO workloads(session_id,status,record_json) VALUES (?,'REGISTERED',?)",
                       (session_id, json.dumps(record, sort_keys=True)))
        return record

    def complete(self, record: dict, evidence: dict) -> None:
        self._require_lease()
        if evidence.get("verified") is not True or evidence.get("zero_survivors") is not True:
            raise RegistryError("RECOVERY_INCOMPLETE")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT record_json FROM workloads WHERE session_id=? AND status='REGISTERED'",
                             (record["session_id"],)).fetchone()
            if row is None or json.loads(row[0]) != record:
                raise RegistryError("REGISTRY_BINDING_MISMATCH")
            db.execute("UPDATE workloads SET status='CLOSED',completion_json=? WHERE session_id=?",
                       (json.dumps({"completed_at": time.time(), "evidence": evidence}, sort_keys=True), record["session_id"]))
