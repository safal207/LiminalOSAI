"""Host-owned independent observer roles; agreement never grants authority.

Identity labels and role labels do not authenticate independent principals. The
trusted host must authenticate observers, separate their evidence sources and
keep this database/API inaccessible to workers. SUPPORT is a bounded claim about
one exact projection, not proof of semantic truth. A later VETO is append-only
and permanent for that projection; counts of SUPPORT cannot outweigh it.
"""
from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .orientation import _hash, _time

if TYPE_CHECKING:
    from .brakes_store import SessionAuthority


_BINDINGS = ("action_id", "root_id", "execution_id", "epoch", "action_digest",
             "projection_digest", "center_id", "predecessor_hash")


def initialize_schema(db: Any) -> None:
    """No executescript: initialization must preserve an enclosing transaction."""
    for statement in (
        """CREATE TABLE IF NOT EXISTS observer_ring_profiles (
            root_id TEXT PRIMARY KEY REFERENCES orientation_profiles(root_id),
            epoch INTEGER NOT NULL, policy_digest TEXT NOT NULL, objective_digest TEXT NOT NULL,
            orientation_profile_digest TEXT NOT NULL, profile_digest TEXT NOT NULL,
            profile_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS observer_ring_attestations (
            attestation_digest TEXT PRIMARY KEY, action_id TEXT NOT NULL,
            root_id TEXT NOT NULL REFERENCES observer_ring_profiles(root_id),
            observer_id TEXT NOT NULL, slot TEXT NOT NULL, attestation_json TEXT NOT NULL,
            ingested_at REAL NOT NULL, UNIQUE(action_id,observer_id,slot))""",
        """CREATE TABLE IF NOT EXISTS observer_ring_execution_holds (
            execution_id TEXT PRIMARY KEY, root_id TEXT NOT NULL REFERENCES observer_ring_profiles(root_id),
            action_id TEXT NOT NULL, projection_digest TEXT NOT NULL,
            reason TEXT NOT NULL, observed_at REAL NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS observer_ring_holds (
            root_id TEXT PRIMARY KEY REFERENCES observer_ring_profiles(root_id),
            reason TEXT NOT NULL, observed_at REAL NOT NULL)""",
    ):
        db.execute(statement)
    from .observer_auth import initialize_schema as initialize_auth
    initialize_auth(db)


def _profile(value: Any) -> dict[str, Any]:
    fields = {"observers", "required_roles", "max_attestation_age_seconds", "max_attestations"}
    if not isinstance(value, dict) or set(value) != fields or len(canonical_bytes(value)) > 65536:
        raise ControlError("invalid observer ring profile")
    value = json.loads(canonical_bytes(value))
    if not isinstance(value["observers"], list) or not 1 <= len(value["observers"]) <= 256:
        raise ControlError("invalid ring observers")
    identities, roles = set(), set()
    for observer in value["observers"]:
        if not isinstance(observer, dict) or set(observer) != {"observer_id", "role"}:
            raise ControlError("invalid ring observer")
        validate_id(observer["observer_id"], "observer_id")
        validate_id(observer["role"], "observer role")
        if observer["observer_id"] in identities:
            raise ControlError("duplicate observer identity")
        identities.add(observer["observer_id"])
        roles.add(observer["role"])
    required = value["required_roles"]
    if not isinstance(required, list) or not required:
        raise ControlError("invalid required observer roles")
    for role in required:
        validate_id(role, "required role")
    if len(set(required)) != len(required) or not set(required) <= roles:
        raise ControlError("invalid required observer role coverage")
    if _time(value["max_attestation_age_seconds"]) <= 0:
        raise ControlError("invalid attestation age limit")
    if type(value["max_attestations"]) is not int or not len(required) <= value["max_attestations"] < 2**31:
        raise ControlError("invalid attestation limit")
    return value


def _load(db: Any, root_id: str) -> tuple[Any, Any]:
    row = db.execute("SELECT * FROM observer_ring_profiles WHERE root_id=?", (root_id,)).fetchone()
    return row, json.loads(row["profile_json"]) if row else None


def _projection(db: Any, action_id: str) -> Any:
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='center_projections'").fetchone():
        return None
    return db.execute("SELECT * FROM center_projections WHERE action_id=?", (action_id,)).fetchone()


def _projection_reason(db: Any, projection: Any, row: Any) -> str | None:
    if projection is None:
        return "OBSERVER_RING_PROJECTION_REQUIRED"
    body = json.loads(projection["projection_json"])
    if (digest(body) != projection["projection_digest"]
            or any(type(body.get(key)) is not type(projection[key]) or body.get(key) != projection[key]
                   for key in _BINDINGS if key != "projection_digest")
            or body.get("created_at") != projection["created_at"]
            or projection["root_id"] != row["root_id"] or projection["epoch"] != row["epoch"]
            or body.get("orientation_profile_digest") != row["orientation_profile_digest"]):
        return "OBSERVER_RING_BINDING_MISMATCH"
    for table in ("orientation_tickets", "brakes_actions"):
        action = db.execute(f"SELECT * FROM {table} WHERE action_id=?", (projection["action_id"],)).fetchone()
        if action and any(action[key] != projection[key] for key in ("root_id", "execution_id", "epoch", "action_digest")):
            return "OBSERVER_RING_BINDING_MISMATCH"
    execution = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (projection["execution_id"],)).fetchone()
    if not execution or execution["root_id"] != row["root_id"] or execution["epoch"] != row["epoch"]:
        return "OBSERVER_RING_BINDING_MISMATCH"
    return None



def _lineage_reason(db: Any, execution_id: str, profile_row: Any, session: Any) -> str | None:
    """A held ancestor also holds existing and future delegated descendants."""
    seen, previous_depth = set(), None
    while execution_id is not None:
        registered = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (execution_id,)).fetchone()
        authority = db.execute("SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
        if (execution_id in seen or registered is None or authority is None
                or registered["root_id"] != profile_row["root_id"] or registered["epoch"] != profile_row["epoch"]
                or any(registered[key] != authority[key] for key in ("root_id", "epoch", "parent_execution_id"))
                or not 0 <= registered["depth"] <= session["max_depth"]
                or (previous_depth is not None and registered["depth"] != previous_depth - 1)
                or (registered["parent_execution_id"] is None and registered["depth"] != 0)):
            return "OBSERVER_RING_LINEAGE_MISMATCH"
        seen.add(execution_id)
        held = db.execute("SELECT reason FROM observer_ring_execution_holds WHERE execution_id=?", (execution_id,)).fetchone()
        if held:
            return held[0]
        previous_depth = registered["depth"]
        execution_id = registered["parent_execution_id"]
    return None


def _assessment(db: Any, action_id: str, *, now: float, root_id: str | None = None) -> dict[str, Any]:
    projection = _projection(db, action_id)
    if root_id is None and projection:
        root_id = projection["root_id"]
    if root_id is None:
        for table in ("brakes_actions", "orientation_tickets"):
            known = db.execute(f"SELECT root_id FROM {table} WHERE action_id=?", (action_id,)).fetchone()
            if known:
                root_id = known[0]
                break
    row, profile = _load(db, root_id) if root_id is not None else (None, None)
    result = {"action_id": action_id, "evaluated_at": now, "required_roles": [], "supported_roles": [],
              "execution_authorized": False, "downstream_gates_required": True, "reason": None}
    if profile is None:
        return result
    result["required_roles"] = profile["required_roles"]
    held = db.execute("SELECT reason FROM observer_ring_holds WHERE root_id=?", (root_id,)).fetchone()
    session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
    root = db.execute("SELECT * FROM roots WHERE root_id=?", (root_id,)).fetchone()
    if held:
        result["reason"] = held[0]
    elif session and now < session["last_now"]:
        result["reason"] = "CLOCK_UNSAFE"
    elif (not session or not root or session["state"] != "ACTIVE" or root["revoked"]
          or now >= session["lease_until"] or now >= session["hard_deadline"]
          or root["epoch"] != row["epoch"] or session["policy_digest"] != row["policy_digest"]
          or session["objective_digest"] != row["objective_digest"]):
        result["reason"] = "OBSERVER_RING_SESSION_CLOSED"
    else:
        result["reason"] = _projection_reason(db, projection, row)
    if result["reason"]:
        return result
    from .observer_auth import profile_reason_in_transaction, attestation_reason_in_transaction
    auth_reason = profile_reason_in_transaction(db, root_id, ring_row=row, ring_profile=profile)
    if auth_reason:
        result["reason"] = auth_reason
        return result
    lineage_reason = _lineage_reason(db, projection["execution_id"], row, session)
    if lineage_reason:
        result["reason"] = lineage_reason
        return result
    identities = {item["observer_id"]: item["role"] for item in profile["observers"]}
    reasons, supported = set(), set()
    for stored in db.execute("SELECT * FROM observer_ring_attestations WHERE action_id=? ORDER BY rowid", (action_id,)):
        try:
            attestation = json.loads(stored["attestation_json"])
            observer = attestation["observer_id"]
            if not isinstance(attestation, dict):
                raise ValueError("invalid attestation")
        except (TypeError, ValueError, KeyError):
            reasons.add("OBSERVER_RING_BINDING_MISMATCH")
            continue
        auth_reason = attestation_reason_in_transaction(db, stored, attestation)
        if auth_reason:
            result["reason"] = auth_reason
            return result
        if (digest(attestation) != stored["attestation_digest"] or observer not in identities
                or attestation["role"] != identities[observer] or observer == projection["execution_id"]
                or attestation["ring_profile_digest"] != row["profile_digest"]
                or any(type(attestation.get(key)) is not type(projection[key]) or attestation.get(key) != projection[key]
                       for key in _BINDINGS)):
            reasons.add("OBSERVER_RING_BINDING_MISMATCH")
            continue
        if attestation["verdict"] == "VETO":
            reasons.add("OBSERVER_RING_VETO")
        elif attestation["role"] in profile["required_roles"]:
            if attestation["verdict"] == "UNKNOWN":
                reasons.add("OBSERVER_RING_UNKNOWN")
            elif (now < attestation["observed_at"] or now >= attestation["valid_until"]
                  or now - attestation["observed_at"] > profile["max_attestation_age_seconds"]):
                reasons.add("OBSERVER_RING_ATTESTATION_STALE")
            elif attestation["verdict"] == "SUPPORT":
                supported.add(attestation["role"])
            else:
                reasons.add("OBSERVER_RING_BINDING_MISMATCH")
    result["supported_roles"] = sorted(supported)
    if not set(profile["required_roles"]) <= supported:
        reasons.add("OBSERVER_RING_ROLE_REQUIRED")
    for reason in ("OBSERVER_RING_BINDING_MISMATCH", "OBSERVER_RING_VETO", "OBSERVER_RING_UNKNOWN",
                   "OBSERVER_RING_ATTESTATION_STALE", "OBSERVER_RING_ROLE_REQUIRED"):
        if reason in reasons:
            result["reason"] = reason
            break
    return result


def check_in_transaction(db: Any, action_id: str, *, now: float, root_id: str | None = None) -> str | None:
    """All required roles must support; one VETO dominates any number of votes.

    Admission callers pass root_id because an unprojected action may have no
    stored row yet. Stage callers can resolve it from the stored brakes action.
    This hook checks evidence only. The caller must still check authority,
    continuity, policy, quotas and the actual downstream effect boundary.
    """
    if not db.in_transaction:
        raise ControlError("observer ring check requires transaction")
    return _assessment(db, action_id, now=_time(now), root_id=root_id)["reason"]


def _attest_in_transaction(db: Any, action_id: str, *, observer_id: str, verdict: str,
                           evidence_digest: str, observed_at: float, valid_until: float,
                           session: Any) -> dict[str, Any]:
    """Append under the caller's write lock; signed ingestion adds its proof atomically."""
    if not db.in_transaction:
        raise ControlError("observer attestation requires transaction")
    validate_id(action_id, "action_id")
    validate_id(observer_id, "observer_id")
    if verdict not in {"SUPPORT", "UNKNOWN", "VETO"}:
        raise ControlError("invalid observer verdict")
    _hash(evidence_digest)
    observed_at, valid_until = _time(observed_at), _time(valid_until)
    projection = _projection(db, action_id)
    if projection is None:
        raise ControlError("OBSERVER_RING_PROJECTION_REQUIRED")
    row, profile = _load(db, projection["root_id"])
    if profile is None:
        raise ControlError("OBSERVER_RING_PROFILE_REQUIRED")
    reason = _projection_reason(db, projection, row)
    if reason:
        raise ControlError(reason)
    observer = next((item for item in profile["observers"] if item["observer_id"] == observer_id), None)
    if observer is None:
        raise ControlError("OBSERVER_RING_UNKNOWN_OBSERVER")
    if observer_id == projection["execution_id"]:
        raise ControlError("OBSERVER_RING_SELF_ENDORSEMENT")
    body = {key: projection[key] for key in _BINDINGS}
    body.update(observer_id=observer_id, role=observer["role"], verdict=verdict,
                evidence_digest=evidence_digest, observed_at=observed_at, valid_until=valid_until,
                ring_profile_digest=row["profile_digest"])
    slot = "VETO" if verdict == "VETO" else "ASSESSMENT"
    old = db.execute("SELECT * FROM observer_ring_attestations WHERE action_id=? AND observer_id=? AND slot=?",
                     (action_id, observer_id, slot)).fetchone()
    if old:
        if old["attestation_digest"] != digest(body):
            raise ControlError("OBSERVER_RING_ATTESTATION_IMMUTABLE")
        return {**body, "attestation_digest": old["attestation_digest"], "execution_authorized": False}
    if slot != "VETO" and db.execute("SELECT 1 FROM observer_ring_attestations WHERE action_id=? AND observer_id=? AND slot='VETO'",
                                     (action_id, observer_id)).fetchone():
        raise ControlError("OBSERVER_RING_VETO_LATCHED")
    now = session["last_now"]
    projection_body = json.loads(projection["projection_json"])
    if (observed_at < projection["created_at"] or observed_at > now
            or now - observed_at > profile["max_attestation_age_seconds"]
            or valid_until <= now or valid_until <= observed_at
            or valid_until > observed_at + profile["max_attestation_age_seconds"]
            or (verdict != "VETO" and valid_until > projection_body["deadline"])):
        raise ControlError("OBSERVER_RING_ATTESTATION_STALE")
    count = db.execute("SELECT COUNT(*) FROM observer_ring_attestations WHERE root_id=?", (projection["root_id"],)).fetchone()[0]
    if count >= profile["max_attestations"]:
        # A full history must not silently drop a later safety signal.
        db.execute("INSERT OR IGNORE INTO observer_ring_holds VALUES (?, 'OBSERVER_RING_ATTESTATION_LIMIT', ?)",
                   (projection["root_id"], now))
        db.commit()
        raise ControlError("OBSERVER_RING_ATTESTATION_LIMIT")
    db.execute("INSERT INTO observer_ring_attestations VALUES (?,?,?,?,?,?,?)", (digest(body), action_id,
               projection["root_id"], observer_id, slot, canonical_bytes(body).decode(), now))
    if verdict == "VETO":
        db.execute("INSERT OR IGNORE INTO observer_ring_execution_holds VALUES (?,?,?,?, 'OBSERVER_RING_VETO', ?)",
                   (projection["execution_id"], projection["root_id"], action_id, projection["projection_digest"], now))
    return {**body, "attestation_digest": digest(body), "execution_authorized": False}


class ObserverRingStore:
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
            session = self._active(db, root_id)
            orientation = db.execute("SELECT * FROM orientation_profiles WHERE root_id=?", (root_id,)).fetchone()
            if orientation is None:
                raise ControlError("OBSERVER_RING_ORIENTATION_REQUIRED")
            if db.execute("SELECT 1 FROM observer_ring_profiles WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("observer ring profile is immutable")
            for table in ("orientation_seeds", "orientation_tickets", "brakes_actions"):
                if db.execute(f"SELECT 1 FROM {table} WHERE root_id=?", (root_id,)).fetchone():
                    raise ControlError("observer ring profile requires a root with no seeds, tickets or actions")
            db.execute("INSERT INTO observer_ring_profiles VALUES (?,?,?,?,?,?,?)", (root_id, orientation["epoch"],
                       session["policy_digest"], session["objective_digest"], orientation["profile_digest"],
                       digest(profile), canonical_bytes(profile).decode()))
            return {"root_id": root_id, "epoch": orientation["epoch"], "profile_digest": digest(profile),
                    "profile": profile, "execution_authorized": False}

    def attest(self, action_id: str, *, observer_id: str, verdict: str, evidence_digest: str,
               observed_at: float, valid_until: float) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            projection = _projection(db, action_id)
            if projection is None:
                raise ControlError("OBSERVER_RING_PROJECTION_REQUIRED")
            session = self._active(db, projection["root_id"])
            from .observer_auth import auth_required_in_transaction
            if auth_required_in_transaction(db, projection["root_id"]):
                raise ControlError("OBSERVER_RING_AUTH_REQUIRED")
            return _attest_in_transaction(db, action_id, observer_id=observer_id, verdict=verdict,
                evidence_digest=evidence_digest, observed_at=observed_at, valid_until=valid_until, session=session)

    def snapshot(self, root_id: str) -> dict[str, Any]:
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            row, profile = _load(db, root_id)
            result = {"root_id": root_id, "profile": profile, "attestations": [], "coverage": [],
                      "execution_authorized": False, "downstream_gates_required": True}
            if profile is None:
                return result
            result.update(profile_digest=row["profile_digest"], epoch=row["epoch"])
            result["attestations"] = [{**json.loads(item["attestation_json"]), "attestation_digest": item["attestation_digest"],
                                        "ingested_at": item["ingested_at"]}
                                       for item in db.execute("SELECT * FROM observer_ring_attestations WHERE root_id=? ORDER BY rowid", (root_id,))]
            try:
                now = self.authority._now()
            except ControlError:
                now = None
            result["evaluated_at"] = now
            held = db.execute("SELECT * FROM observer_ring_holds WHERE root_id=?", (root_id,)).fetchone()
            result["hold"] = dict(held) if held else None
            result["execution_holds"] = [dict(item) for item in db.execute(
                "SELECT * FROM observer_ring_execution_holds WHERE root_id=? ORDER BY execution_id", (root_id,))]
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='center_projections'").fetchone():
                for item in db.execute("SELECT action_id FROM center_projections WHERE root_id=? ORDER BY rowid", (root_id,)):
                    result["coverage"].append(_assessment(db, item[0], now=now, root_id=root_id) if now is not None else {
                        "action_id": item[0], "evaluated_at": None, "required_roles": profile["required_roles"],
                        "supported_roles": [], "execution_authorized": False, "downstream_gates_required": True,
                        "reason": "CLOCK_UNSAFE"})
            return result
