"""Durable trusted-host ownership and lifecycle for one three-observer ring.

The controller lease excludes other controllers, but never blocks the separate
watchdog from closing a ring. SQLite serializes closing against new create or
enrollment transitions. An unresolved create request is retained even when a
container is presently absent: daemon-side completion may still arrive later.
This registry is host diagnostics and coordination, never worker authority.
"""
from __future__ import annotations

from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # Docker runtime is supported on Linux only.
    fcntl = None
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Iterator
import uuid

from .authority import ControlError, canonical_bytes, validate_id


class ObserverRegistryError(ValueError):
    pass


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"liminal-observer-[0-9a-f]{32}\Z")
_ROLES = ("reality", "continuity", "projection")


def _json(value: Any) -> str:
    try:
        return canonical_bytes(value).decode("utf-8")
    except (ControlError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH") from exc


def ownership_labels(record: dict[str, Any], observer_id: str) -> dict[str, str]:
    """Return exact labels; callers must also verify immutable image/container IDs."""
    try:
        child = next(item for item in record["observers"] if item["observer_id"] == observer_id)
        return {"liminal.observer.registry": record["registry_id"],
                "liminal.observer.ring": record["ring_id"],
                "liminal.observer.owner": record["ownership_token"],
                "liminal.observer.role": child["role"],
                "liminal.observer.observer": child["observer_id"]}
    except (KeyError, TypeError, StopIteration) as exc:
        raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH") from exc


class ObserverRingRegistry:
    def __init__(self, path: str | Path, *, create: bool = True) -> None:
        supplied = Path(path)
        if supplied.is_symlink():
            raise ObserverRegistryError("REGISTRY_PATH_UNSAFE")
        self.path = supplied.resolve()
        self.lock_path = self.path.with_name(self.path.name + ".controller.lock")
        self._lease_fd: int | None = None
        self._lease_pid: int | None = None
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.is_file():
            raise ObserverRegistryError("REGISTRY_NOT_FOUND")
        self._create = create
        with self._connect() as db:
            if create:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS observer_registry_meta (
                        key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS observer_registry_rings (
                        ring_id TEXT PRIMARY KEY, root_id TEXT NOT NULL UNIQUE,
                        slot INTEGER NOT NULL DEFAULT 1 CHECK(slot=1),
                        status TEXT NOT NULL CHECK(status IN ('REGISTERED','CLOSING','CLOSED')),
                        record_json TEXT NOT NULL, closing_reason TEXT,
                        closing_at REAL, completed_at REAL);
                    CREATE UNIQUE INDEX IF NOT EXISTS one_unfinished_observer_ring
                        ON observer_registry_rings(slot) WHERE status != 'CLOSED';
                    CREATE TABLE IF NOT EXISTS observer_registry_children (
                        ring_id TEXT NOT NULL REFERENCES observer_registry_rings(ring_id),
                        observer_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                        phase TEXT NOT NULL CHECK(phase IN
                            ('REGISTERED','CREATE_PENDING','CREATED','ENROLLED','REMOVED')),
                        container_id TEXT, enrollment_json TEXT, completed_at REAL,
                        absence_kind TEXT, PRIMARY KEY(ring_id,observer_id),
                        UNIQUE(ring_id,container_id));
                """)
                db.execute("INSERT OR IGNORE INTO observer_registry_meta VALUES ('registry_id',?)",
                           (uuid.uuid4().hex,))
            row = db.execute("SELECT value FROM observer_registry_meta WHERE key='registry_id'").fetchone()
            if row is None or re.fullmatch(r"[0-9a-f]{32}", row[0]) is None:
                raise ObserverRegistryError("REGISTRY_IDENTITY_UNAVAILABLE")
            self.registry_id = row[0]
        # Only the initial constructor may create the database. A missing file
        # later in this object's lifetime is loss of evidence, never bootstrap.
        self._create = False
        self.path.chmod(0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = None
        try:
            if self._create:
                db = sqlite3.connect(self.path, timeout=1)
            else:
                db = sqlite3.connect(self.path.as_uri() + "?mode=rw", timeout=1, uri=True)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        except sqlite3.Error as exc:
            raise ObserverRegistryError("REGISTRY_STORAGE_UNAVAILABLE") from exc
        finally:
            if db is not None:
                db.close()

    def _lock_descriptor(self) -> int:
        if fcntl is None:
            raise ObserverRegistryError("OBSERVER_REGISTRY_PLATFORM_UNAVAILABLE")
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(self.lock_path, flags, 0o600)
            information = os.fstat(descriptor)
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                os.close(descriptor)
                raise ObserverRegistryError("REGISTRY_LOCK_UNSAFE")
            os.set_inheritable(descriptor, False)
            return descriptor
        except OSError as exc:
            raise ObserverRegistryError("REGISTRY_LOCK_UNAVAILABLE") from exc

    @contextmanager
    def controller_lease(self) -> Iterator["ObserverRingRegistry"]:
        if self._lease_fd is not None:
            raise ObserverRegistryError("OBSERVER_CONTROLLER_BUSY")
        descriptor = self._lock_descriptor()
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ObserverRegistryError("OBSERVER_CONTROLLER_BUSY") from exc
            self._lease_fd, self._lease_pid = descriptor, os.getpid()
            yield self
        finally:
            if self._lease_fd == descriptor:
                self._lease_fd = self._lease_pid = None
            os.close(descriptor)

    def controller_present(self) -> bool:
        """Probe the independent flock; failures are errors, never controller absence."""
        if self._lease_fd is not None and self._lease_pid == os.getpid():
            return True
        descriptor = self._lock_descriptor()
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            return False
        finally:
            os.close(descriptor)

    def _require_lease(self) -> None:
        if self._lease_fd is None or self._lease_pid != os.getpid():
            raise ObserverRegistryError("OBSERVER_CONTROLLER_LEASE_REQUIRED")

    def _binding(self, db: sqlite3.Connection, record: dict[str, Any]) -> sqlite3.Row:
        if type(record) is not dict or record.get("registry_id") != self.registry_id:
            raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
        row = db.execute("SELECT * FROM observer_registry_rings WHERE ring_id=?",
                         (record.get("ring_id"),)).fetchone()
        if row is None or row["record_json"] != _json(record):
            raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
        return row

    @staticmethod
    def _child(db: sqlite3.Connection, record: dict[str, Any], observer_id: str) -> sqlite3.Row:
        if type(observer_id) is not str:
            raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
        row = db.execute("SELECT * FROM observer_registry_children WHERE ring_id=? AND observer_id=?",
                         (record["ring_id"], observer_id)).fetchone()
        if row is None:
            raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
        return row

    @staticmethod
    def _require_open(row: sqlite3.Row, record: dict[str, Any]) -> None:
        if row["status"] != "REGISTERED":
            raise ObserverRegistryError("OBSERVER_RING_CLOSING")
        now = time.time()
        if not math.isfinite(now) or now < record["registered_at"]:
            raise ObserverRegistryError("OBSERVER_REGISTRY_CLOCK_UNSAFE")
        if now >= record["deadline_at"]:
            raise ObserverRegistryError("OBSERVER_RING_EXPIRED")

    def register_ring(self, *, root_id: str, authority_db: str | Path,
                      image_id: str, observers: list[dict[str, str]],
                      lifetime_seconds: float) -> dict[str, Any]:
        """Register all children atomically before the first possible Docker request."""
        self._require_lease()
        try:
            validate_id(root_id, "root_id")
            if (not isinstance(image_id, str) or _IMAGE.fullmatch(image_id) is None
                    or isinstance(lifetime_seconds, bool)
                    or not isinstance(lifetime_seconds, (int, float))
                    or not math.isfinite(lifetime_seconds) or not 0 < lifetime_seconds <= 86400
                    or type(observers) is not list or len(observers) != 3):
                raise ValueError()
            path = Path(authority_db)
            if (not path.is_absolute() or str(path) != str(path.resolve(strict=True))
                    or not path.is_file() or path == self.path
                    or any(item.is_symlink() for item in (path, *path.parents))):
                raise ValueError()
            identities, keys, names, roles = set(), set(), set(), set()
            for child in observers:
                if type(child) is not dict or set(child) != {"observer_id", "role", "key_id", "container_name"}:
                    raise ValueError()
                validate_id(child["observer_id"], "observer_id")
                validate_id(child["key_id"], "key_id")
                if (child["role"] not in _ROLES or type(child["container_name"]) is not str
                        or _NAME.fullmatch(child["container_name"]) is None
                        or child["observer_id"] in identities or child["key_id"] in keys
                        or child["container_name"] in names or child["role"] in roles):
                    raise ValueError()
                identities.add(child["observer_id"])
                keys.add(child["key_id"])
                names.add(child["container_name"])
                roles.add(child["role"])
            registered_at = time.time()
            if not math.isfinite(registered_at):
                raise ValueError()
        except (ControlError, ValueError, TypeError, OSError, OverflowError) as exc:
            raise ObserverRegistryError("OBSERVER_RING_REGISTRATION_INVALID") from exc
        # Store a detached, canonical copy; caller-owned child dictionaries cannot
        # mutate the registry's durable identity after validation.
        record = {"schema": "liminal.observer-ring-registry.v1", "registry_id": self.registry_id,
                  "ring_id": "liminal-observer-ring-" + uuid.uuid4().hex,
                  "ownership_token": uuid.uuid4().hex, "root_id": root_id,
                  "authority_db": str(path), "image_id": image_id,
                  "observers": json.loads(_json(observers)), "registered_at": registered_at,
                  "lifetime_seconds": float(lifetime_seconds),
                  "deadline_at": registered_at + float(lifetime_seconds)}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM observer_registry_rings WHERE root_id=?", (root_id,)).fetchone():
                raise ObserverRegistryError("OBSERVER_ROOT_REPLACEMENT_FORBIDDEN")
            if db.execute("SELECT 1 FROM observer_registry_rings WHERE status!='CLOSED'").fetchone():
                raise ObserverRegistryError("OBSERVER_RECOVERY_REQUIRED")
            db.execute("INSERT INTO observer_registry_rings(ring_id,root_id,status,record_json) VALUES (?,?,'REGISTERED',?)",
                       (record["ring_id"], root_id, _json(record)))
            db.executemany("INSERT INTO observer_registry_children(ring_id,observer_id,ordinal,phase) VALUES (?,?,?,'REGISTERED')",
                           [(record["ring_id"], child["observer_id"], index) for index, child in enumerate(observers)])
        return record

    def unfinished(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT record_json FROM observer_registry_rings WHERE status!='CLOSED' ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]

    def snapshot(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as db:
            # One read transaction prevents a torn status/children snapshot.
            db.execute("BEGIN")
            ring = self._binding(db, record)
            rows = db.execute("SELECT * FROM observer_registry_children WHERE ring_id=? ORDER BY ordinal",
                              (record["ring_id"],)).fetchall()
            children = [{**record["observers"][row["ordinal"]], "phase": row["phase"],
                         "container_id": row["container_id"],
                         "enrollment": json.loads(row["enrollment_json"]) if row["enrollment_json"] else None,
                         "completed_at": row["completed_at"], "absence_kind": row["absence_kind"]}
                        for row in rows]
            return {"record": json.loads(ring["record_json"]), "status": ring["status"],
                    "deadline_at": record["deadline_at"], "closing_reason": ring["closing_reason"],
                    "closing_at": ring["closing_at"], "completed_at": ring["completed_at"], "children": children}

    def mark_create_pending(self, record: dict[str, Any], observer_id: str) -> None:
        self._require_lease()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_open(self._binding(db, record), record)
            child = self._child(db, record, observer_id)
            if child["phase"] != "REGISTERED":
                raise ObserverRegistryError("OBSERVER_CREATE_ALREADY_SUBMITTED")
            db.execute("UPDATE observer_registry_children SET phase='CREATE_PENDING' WHERE ring_id=? AND observer_id=?",
                       (record["ring_id"], observer_id))

    def confirm_created(self, record: dict[str, Any], observer_id: str, container_id: str) -> None:
        """Pin a positively verified immutable ID; absent/timeout responses cannot call this."""
        self._require_lease()
        if type(container_id) is not str or _HEX64.fullmatch(container_id) is None:
            raise ObserverRegistryError("IMMUTABLE_CONTAINER_ID_UNAVAILABLE")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_open(self._binding(db, record), record)
            child = self._child(db, record, observer_id)
            if child["phase"] not in {"CREATE_PENDING", "CREATED", "ENROLLED"}:
                raise ObserverRegistryError("OBSERVER_CREATE_NOT_SUBMITTED")
            if child["container_id"] is not None:
                if child["container_id"] != container_id:
                    raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
                return  # Retry preserves an enrolled child's state and key.
            db.execute("UPDATE observer_registry_children SET phase='CREATED',container_id=? WHERE ring_id=? AND observer_id=?",
                       (container_id, record["ring_id"], observer_id))

    def confirm_enrolled(self, record: dict[str, Any], observer_id: str, enrollment: dict[str, str]) -> None:
        self._require_lease()
        if (type(enrollment) is not dict or set(enrollment) != {"observer_id", "role", "key_id", "public_key"}
                or type(enrollment["public_key"]) is not str or _HEX64.fullmatch(enrollment["public_key"]) is None):
            raise ObserverRegistryError("OBSERVER_ENROLLMENT_INVALID")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_open(self._binding(db, record), record)
            child = self._child(db, record, observer_id)
            declared = record["observers"][child["ordinal"]]
            if any(enrollment[field] != declared[field] for field in ("observer_id", "role", "key_id")):
                raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
            if child["phase"] not in {"CREATED", "ENROLLED"} or child["container_id"] is None:
                raise ObserverRegistryError("OBSERVER_CREATE_UNCONFIRMED")
            encoded = _json(enrollment)
            if child["enrollment_json"] is not None:
                if child["enrollment_json"] != encoded:
                    raise ObserverRegistryError("OBSERVER_ENROLLMENT_REPLACEMENT_FORBIDDEN")
                return
            for other in db.execute("SELECT enrollment_json FROM observer_registry_children WHERE ring_id=? AND enrollment_json IS NOT NULL",
                                    (record["ring_id"],)):
                if json.loads(other[0])["public_key"] == enrollment["public_key"]:
                    raise ObserverRegistryError("OBSERVER_ENROLLMENT_DUPLICATE_KEY")
            db.execute("UPDATE observer_registry_children SET phase='ENROLLED',enrollment_json=? WHERE ring_id=? AND observer_id=?",
                       (encoded, record["ring_id"], observer_id))

    def begin_closing(self, record: dict[str, Any], reason: str) -> None:
        """Atomically deny future create/enrollment; independent watchdog may call it."""
        try:
            validate_id(reason, "reason")
        except ControlError as exc:
            raise ObserverRegistryError("OBSERVER_CLOSING_REASON_INVALID") from exc
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._binding(db, record)
            if row["status"] == "REGISTERED":
                db.execute("UPDATE observer_registry_rings SET status='CLOSING',closing_reason=?,closing_at=? WHERE ring_id=?",
                           (reason, time.time(), record["ring_id"]))

    def complete_child(self, record: dict[str, Any], observer_id: str,
                       container_id: str | None, verified_absent: bool) -> None:
        if verified_absent is not True:
            raise ObserverRegistryError("OBSERVER_REMOVAL_UNVERIFIED")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            ring = self._binding(db, record)
            child = self._child(db, record, observer_id)
            if ring["status"] not in {"CLOSING", "CLOSED"}:
                raise ObserverRegistryError("OBSERVER_RING_NOT_CLOSING")
            if child["phase"] == "CREATE_PENDING":
                raise ObserverRegistryError("CREATE_OUTCOME_UNCONFIRMED")
            if child["container_id"] != container_id:
                raise ObserverRegistryError("REGISTRY_BINDING_MISMATCH")
            if child["phase"] == "REMOVED":
                return
            absence = "NEVER_CREATE_SUBMITTED" if child["phase"] == "REGISTERED" else "PINNED_CONTAINER_ABSENT"
            db.execute("UPDATE observer_registry_children SET phase='REMOVED',completed_at=?,absence_kind=? WHERE ring_id=? AND observer_id=?",
                       (time.time(), absence, record["ring_id"], observer_id))

    def complete_ring(self, record: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._binding(db, record)
            if row["status"] == "CLOSED":
                return
            if row["status"] != "CLOSING":
                raise ObserverRegistryError("OBSERVER_RING_NOT_CLOSING")
            children = db.execute("SELECT phase FROM observer_registry_children WHERE ring_id=?", (record["ring_id"],)).fetchall()
            if len(children) != 3 or any(child[0] != "REMOVED" for child in children):
                raise ObserverRegistryError("OBSERVER_RING_RECOVERY_INCOMPLETE")
            db.execute("UPDATE observer_registry_rings SET status='CLOSED',completed_at=? WHERE ring_id=?",
                       (time.time(), record["ring_id"]))
