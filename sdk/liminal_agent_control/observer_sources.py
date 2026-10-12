"""Persisted host-collected evidence bindings for exact observer challenges.

Distinct source IDs identify configured collection domains. They do not prove
independent ownership or truth. Enrollment, collection and binding are trusted
host operations; observers only read their role's packet and sign its digest.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, TYPE_CHECKING

from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .orientation import _hash, _time

if TYPE_CHECKING:
    from .brakes_store import SessionAuthority

_PACKET_FIELDS = {"source_id", "role", "request_digest", "observed_at", "payload"}
_BINDING_FIELDS = ("nonce", "root_id", "observer_id", "source_id", "role", "request_digest",
                   "source_profile_digest", "packet_digest", "observed_at", "bound_at", "expires_at")


def initialize_schema(db: Any) -> None:
    for statement in (
        """CREATE TABLE IF NOT EXISTS observer_source_profiles (
            root_id TEXT PRIMARY KEY REFERENCES observer_auth_profiles(root_id),
            epoch INTEGER NOT NULL, auth_profile_digest TEXT NOT NULL,
            ring_profile_digest TEXT NOT NULL, profile_digest TEXT NOT NULL,
            profile_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS observer_source_bindings (
            nonce TEXT PRIMARY KEY REFERENCES observer_auth_challenges(nonce),
            root_id TEXT NOT NULL REFERENCES observer_source_profiles(root_id),
            observer_id TEXT NOT NULL, source_id TEXT NOT NULL, role TEXT NOT NULL,
            request_digest TEXT NOT NULL, source_profile_digest TEXT NOT NULL,
            packet_digest TEXT NOT NULL, packet_json TEXT NOT NULL,
            observed_at REAL NOT NULL, bound_at REAL NOT NULL, expires_at REAL NOT NULL,
            binding_digest TEXT NOT NULL)""",
    ):
        db.execute(statement)


def _profile(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != {"sources", "max_source_age_seconds"}
            or len(canonical_bytes(value)) > 65536):
        raise ControlError("OBSERVER_SOURCE_PROFILE_MALFORMED")
    value = json.loads(canonical_bytes(value))
    if not isinstance(value["sources"], list) or not 2 <= len(value["sources"]) <= 256:
        raise ControlError("OBSERVER_SOURCE_PROFILE_MALFORMED")
    observers, sources = set(), set()
    for source in value["sources"]:
        if not isinstance(source, dict) or set(source) != {"observer_id", "source_id"}:
            raise ControlError("OBSERVER_SOURCE_PROFILE_MALFORMED")
        validate_id(source["observer_id"], "observer_id")
        validate_id(source["source_id"], "source_id")
        if source["observer_id"] in observers or source["source_id"] in sources:
            raise ControlError("OBSERVER_SOURCE_DUPLICATE_SOURCE")
        observers.add(source["observer_id"])
        sources.add(source["source_id"])
    if _time(value["max_source_age_seconds"]) <= 0:
        raise ControlError("OBSERVER_SOURCE_PROFILE_MALFORMED")
    return value


def _load(db: Any, root_id: str) -> tuple[Any, Any]:
    row = db.execute("SELECT * FROM observer_source_profiles WHERE root_id=?", (root_id,)).fetchone()
    try:
        profile = _profile(json.loads(row["profile_json"])) if row else None
    except (ControlError, KeyError, TypeError, ValueError):
        raise ControlError("OBSERVER_SOURCE_PROFILE_MISMATCH")
    return row, profile


def profile_reason_in_transaction(db: Any, root_id: str) -> str | None:
    try:
        row, profile = _load(db, root_id)
        if row is None:
            return None
        from .observer_auth import _load as load_auth
        from .observer_ring import _load as load_ring
        auth_row, auth_profile = load_auth(db, root_id)
        ring_row, ring_profile = load_ring(db, root_id)
        if (auth_row is None or ring_row is None or row["epoch"] != auth_row["epoch"]
                or row["epoch"] != ring_row["epoch"] or row["auth_profile_digest"] != auth_row["profile_digest"]
                or row["ring_profile_digest"] != ring_row["profile_digest"]
                or digest(profile) != row["profile_digest"]
                or digest(auth_profile) != auth_row["profile_digest"]
                or digest(ring_profile) != ring_row["profile_digest"]
                or {item["observer_id"] for item in profile["sources"]}
                != {item["observer_id"] for item in auth_profile["keys"]}
                or {item["observer_id"] for item in profile["sources"]}
                != {item["observer_id"] for item in ring_profile["observers"]}):
            return "OBSERVER_SOURCE_PROFILE_MISMATCH"
    except (ControlError, KeyError, TypeError, ValueError):
        return "OBSERVER_SOURCE_PROFILE_MISMATCH"
    return None


def validate_source_packet(request: dict[str, Any], packet: Any, *, source_id: str | None = None) -> dict[str, Any]:
    """Public structural binding check; trusted host gates enforce age/enrollment."""
    from .observer_auth import _request
    request = _request(request)
    if (not isinstance(packet, dict) or set(packet) != _PACKET_FIELDS
            or not isinstance(packet["payload"], dict) or len(canonical_bytes(packet)) > 262144):
        raise ControlError("OBSERVER_SOURCE_PACKET_MALFORMED")
    validate_id(packet["source_id"], "source_id")
    validate_id(packet["role"], "source role")
    _hash(packet["request_digest"])
    _time(packet["observed_at"])
    if (packet["request_digest"] != digest(request) or packet["role"] != request["role"]
            or (source_id is not None and packet["source_id"] != source_id)):
        raise ControlError("OBSERVER_SOURCE_BINDING_MISMATCH")
    return json.loads(canonical_bytes(packet))


def write_source_packet(source_directory: str | Path, request: dict[str, Any], packet: dict[str, Any]) -> Path:
    """Atomically write one public packet in a host-owned role directory.

The directory must already exist as an absolute path without symlink aliases.
The nonce determines the only filename. Existing packets cannot be replaced by
    different evidence. The host collector must redact sensitive payloads before
    handing a packet to this public evidence writer.
"""
    packet = validate_source_packet(request, packet)
    directory = Path(source_directory)
    try:
        if (not directory.is_absolute() or directory.resolve(strict=True) != directory
                or not directory.is_dir()):
            raise ControlError("OBSERVER_SOURCE_DIRECTORY_UNSAFE")
    except (OSError, RuntimeError) as exc:
        raise ControlError("OBSERVER_SOURCE_DIRECTORY_UNSAFE") from exc
    target = directory / (request["nonce"] + ".json")
    encoded = canonical_bytes(packet)
    def read_existing() -> Path:
        try:
            descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as existing:
                if not stat.S_ISREG(os.fstat(existing.fileno()).st_mode):
                    raise ControlError("OBSERVER_SOURCE_DIRECTORY_UNSAFE")
                if existing.read(262145) != encoded:
                    raise ControlError("OBSERVER_SOURCE_BINDING_IMMUTABLE")
            return target
        except OSError as exc:
            raise ControlError("OBSERVER_SOURCE_DIRECTORY_UNSAFE") from exc
    if target.exists() or target.is_symlink():
        return read_existing()
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".packet-", dir=directory)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o644)
        # Link creation is atomic and never replaces an existing packet, even
        # when two trusted collectors race. Readers additionally use O_NOFOLLOW.
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            return read_existing()
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _binding(db: Any, request: Any) -> tuple[Any, Any, Any, Any]:
    row, profile = _load(db, request["root_id"])
    binding = db.execute("SELECT * FROM observer_source_bindings WHERE nonce=?", (request["nonce"],)).fetchone()
    challenge = db.execute("SELECT * FROM observer_auth_challenges WHERE nonce=?", (request["nonce"],)).fetchone()
    return row, profile, binding, challenge


def evidence_reason_in_transaction(db: Any, request: dict[str, Any], envelope: dict[str, Any], *,
                                   now: float | None = None, consumed_at: float | None = None) -> str | None:
    """Require persisted collector identity/digest at ingestion and every gate.

At use-time SUPPORT and UNKNOWN retain a bounded source lifetime. A freshly
ingested VETO remains a permanent safety signal after its packet expires.
Exact response retries may be read as history without granting new execution.
"""
    try:
        row, profile, binding, challenge = _binding(db, request)
        if row is None:
            return None
        reason = profile_reason_in_transaction(db, request["root_id"])
        if reason:
            return reason
        if binding is None:
            return "OBSERVER_SOURCE_BINDING_REQUIRED"
        expected_source = next(item for item in profile["sources"] if item["observer_id"] == request["observer_id"])
        packet = validate_source_packet(request, json.loads(binding["packet_json"]), source_id=expected_source["source_id"])
        if (challenge is None or challenge["request_digest"] != digest(request)
                or challenge["request_json"] != canonical_bytes(request).decode()
                or binding["root_id"] != request["root_id"] or binding["observer_id"] != request["observer_id"]
                or binding["role"] != request["role"] or binding["source_id"] != expected_source["source_id"]
                or binding["request_digest"] != digest(request) or binding["source_profile_digest"] != row["profile_digest"]
                or binding["packet_digest"] != digest(packet) or envelope["evidence_digest"] != binding["packet_digest"]
                or binding["observed_at"] != packet["observed_at"]
                or digest({field: binding[field] for field in _BINDING_FIELDS}) != binding["binding_digest"]
                or binding["expires_at"] != min(request["valid_until"], binding["observed_at"] + profile["max_source_age_seconds"])
                or not request["issued_at"] <= binding["bound_at"] < request["valid_until"]
                or not binding["observed_at"] <= binding["bound_at"] < binding["expires_at"]
                or envelope["observed_at"] < binding["observed_at"]):
            return "OBSERVER_SOURCE_BINDING_MISMATCH"
        when = consumed_at if consumed_at is not None else now
        if when is None or not binding["bound_at"] <= when < binding["expires_at"]:
            return "OBSERVER_SOURCE_STALE"
        if now is not None and envelope["verdict"] != "VETO" and not binding["bound_at"] <= now < binding["expires_at"]:
            return "OBSERVER_SOURCE_STALE"
    except (ControlError, KeyError, TypeError, ValueError, StopIteration):
        return "OBSERVER_SOURCE_BINDING_MISMATCH"
    return None


class ObserverSourceStore:
    def __init__(self, authority: SessionAuthority) -> None:
        self.authority, self.db_path = authority, authority.db_path
        with connect(self.db_path) as db:
            initialize_schema(db)

    def _active(self, db: Any, root_id: str) -> Any:
        row, reason = self.authority._fresh(db, root_id)
        if reason:
            db.commit()
            raise ControlError(reason)
        return row

    def install(self, root_id: str, profile: dict[str, Any]) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        profile = _profile(profile)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            self._active(db, root_id)
            from .observer_auth import ObserverAuthStore
            auth_row, auth_profile, ring_row, _ = ObserverAuthStore._require(db, root_id)
            if db.execute("SELECT 1 FROM observer_source_profiles WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("observer source profile is immutable")
            if {item["observer_id"] for item in profile["sources"]} != {item["observer_id"] for item in auth_profile["keys"]}:
                raise ControlError("OBSERVER_SOURCE_COVERAGE_REQUIRED")
            for table in ("orientation_seeds", "orientation_tickets", "brakes_actions", "observer_auth_challenges"):
                if db.execute(f"SELECT 1 FROM {table} WHERE root_id=?", (root_id,)).fetchone():
                    raise ControlError("observer source profile requires a root with no seeds, tickets or actions")
            if db.execute("SELECT 1 FROM observer_auth_proofs p JOIN observer_ring_attestations a "
                          "USING(attestation_digest) WHERE a.root_id=?", (root_id,)).fetchone():
                raise ControlError("observer source profile requires a root with no observer proofs")
            db.execute("INSERT INTO observer_source_profiles VALUES (?,?,?,?,?,?)", (root_id, auth_row["epoch"],
                auth_row["profile_digest"], ring_row["profile_digest"], digest(profile), canonical_bytes(profile).decode()))
            return {"root_id": root_id, "epoch": auth_row["epoch"], "profile_digest": digest(profile),
                    "profile": profile, "execution_authorized": False}

    def bind(self, request: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
        from .observer_auth import _request, ObserverAuthStore
        request = _request(request)
        packet = validate_source_packet(request, packet)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, request["root_id"])
            ObserverAuthStore._require(db, request["root_id"])
            row, profile, old, challenge = _binding(db, request)
            if row is None:
                raise ControlError("OBSERVER_SOURCE_PROFILE_REQUIRED")
            reason = profile_reason_in_transaction(db, request["root_id"])
            if reason:
                raise ControlError(reason)
            if (challenge is None or challenge["request_digest"] != digest(request)
                    or challenge["request_json"] != canonical_bytes(request).decode()):
                raise ControlError("OBSERVER_SOURCE_BINDING_MISMATCH")
            expected_source = next((item for item in profile["sources"] if item["observer_id"] == request["observer_id"]), None)
            if expected_source is None or packet["source_id"] != expected_source["source_id"]:
                raise ControlError("OBSERVER_SOURCE_BINDING_MISMATCH")
            if old:
                if old["packet_digest"] != digest(packet) or old["packet_json"] != canonical_bytes(packet).decode():
                    raise ControlError("OBSERVER_SOURCE_BINDING_IMMUTABLE")
                # Check the original binding; retries cannot repair corrupted or
                # expired history by overwriting its collection time.
                envelope = {"evidence_digest": digest(packet), "observed_at": max(request["issued_at"], packet["observed_at"]),
                            "verdict": "VETO"}
                reason = evidence_reason_in_transaction(db, request, envelope, consumed_at=old["bound_at"])
                if reason:
                    raise ControlError(reason)
                return {**{field: old[field] for field in _BINDING_FIELDS}, "binding_digest": old["binding_digest"],
                        "execution_authorized": False}
            now = session["last_now"]
            expires_at = min(request["valid_until"], _time(packet["observed_at"]) + profile["max_source_age_seconds"])
            if (challenge["consumed_at"] is not None or not request["issued_at"] <= now < request["valid_until"]
                    or not _time(packet["observed_at"]) <= now < expires_at):
                raise ControlError("OBSERVER_SOURCE_STALE")
            body = {"nonce": request["nonce"], "root_id": request["root_id"], "observer_id": request["observer_id"],
                    "source_id": packet["source_id"], "role": packet["role"], "request_digest": digest(request),
                    "source_profile_digest": row["profile_digest"], "packet_digest": digest(packet),
                    "observed_at": _time(packet["observed_at"]), "bound_at": now, "expires_at": expires_at}
            db.execute("INSERT INTO observer_source_bindings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(body[field] for field in _BINDING_FIELDS[:8]) + (canonical_bytes(packet).decode(),)
                + tuple(body[field] for field in _BINDING_FIELDS[8:]) + (digest(body),))
            return {**body, "binding_digest": digest(body), "execution_authorized": False}

    def snapshot(self, root_id: str) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            result = {"root_id": root_id, "profile": None, "bindings": [], "reason": None,
                      "execution_authorized": False, "downstream_gates_required": True}
            try:
                row, profile = _load(db, root_id)
                if row is None:
                    return result
                result.update(profile=profile, profile_digest=row["profile_digest"], epoch=row["epoch"],
                              reason=profile_reason_in_transaction(db, root_id))
                for item in db.execute("SELECT * FROM observer_source_bindings WHERE root_id=? ORDER BY rowid", (root_id,)):
                    result["bindings"].append({**{field: item[field] for field in _BINDING_FIELDS},
                        "binding_digest": item["binding_digest"], "packet": json.loads(item["packet_json"])})
            except (ControlError, KeyError, TypeError, ValueError):
                result["reason"] = "OBSERVER_SOURCE_BINDING_MISMATCH"
            return result
