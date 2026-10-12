"""Host-owned moving checkpoints and hash-linked observed trajectories.

Ideas and projections are separate from the event chain. None of these records
grants authority. The trusted host owns the clock, DB, schedule and observations;
hash links detect broken history, not a hostile writer replacing the whole DB.
"""
from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

from .authority import ControlError, canonical_bytes, connect, digest, validate_id
from .brakes_store import _action
from .orientation import _distances, _hash, _time

if TYPE_CHECKING:
    from .brakes_store import SessionAuthority


_STATE_FIELDS = ("node_id", "revision", "last_observed_at", "last_progress_at",
                 "away_since", "pending_action_id", "checkpoint_center_id")
_ZERO = "0" * 64


def initialize_schema(db: Any) -> None:
    for statement in (
        """CREATE TABLE IF NOT EXISTS center_profiles (
            root_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, policy_digest TEXT NOT NULL,
            objective_digest TEXT NOT NULL, orientation_profile_digest TEXT NOT NULL,
            profile_digest TEXT NOT NULL, profile_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS center_states (
            execution_id TEXT PRIMARY KEY, root_id TEXT NOT NULL, head_hash TEXT NOT NULL,
            sequence INTEGER NOT NULL, node_id TEXT NOT NULL, revision INTEGER NOT NULL,
            last_observed_at REAL NOT NULL, last_progress_at REAL NOT NULL, away_since REAL,
            pending_action_id TEXT, checkpoint_center_id TEXT, hold_reason TEXT)""",
        """CREATE TABLE IF NOT EXISTS center_events (
            root_id TEXT NOT NULL, execution_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            parent_hash TEXT NOT NULL, event_hash TEXT NOT NULL, event_json TEXT NOT NULL,
            PRIMARY KEY(execution_id,sequence))""",
        """CREATE TABLE IF NOT EXISTS center_ideas (
            root_id TEXT NOT NULL, execution_id TEXT NOT NULL, idea_id TEXT NOT NULL,
            content_digest TEXT NOT NULL, predecessor_hash TEXT NOT NULL, recorded_at REAL NOT NULL,
            PRIMARY KEY(execution_id,idea_id))""",
        """CREATE TABLE IF NOT EXISTS center_projections (
            action_id TEXT PRIMARY KEY, root_id TEXT NOT NULL, execution_id TEXT NOT NULL,
            epoch INTEGER NOT NULL, action_digest TEXT NOT NULL, projection_digest TEXT NOT NULL,
            center_id TEXT NOT NULL, predecessor_hash TEXT NOT NULL, created_at REAL NOT NULL,
            projection_json TEXT NOT NULL, status TEXT NOT NULL)""",
    ):
        db.execute(statement)


def _load(db: Any, root_id: str) -> tuple[Any, Any]:
    row = db.execute("SELECT * FROM center_profiles WHERE root_id=?", (root_id,)).fetchone()
    return row, json.loads(row["profile_json"]) if row else None


def _window(profile: Any, now: float) -> Any:
    return next((w for w in profile["windows"] if w["starts_at"] <= now < w["ends_at"]), None)


def _profile(value: Any, orientation: Any) -> dict[str, Any]:
    fields = {"windows", "max_past_age_seconds", "max_future_horizon_seconds",
              "max_transition_seconds", "max_away_seconds", "max_idle_seconds",
              "progress_edge_ids", "max_ideas"}
    if not isinstance(value, dict) or set(value) != fields or len(canonical_bytes(value)) > 65536:
        raise ControlError("invalid center profile")
    result = json.loads(canonical_bytes(value))
    for field in fields - {"windows", "progress_edge_ids", "max_ideas"}:
        if _time(result[field]) <= 0:
            raise ControlError("invalid center time threshold")
    if type(result["max_ideas"]) is not int or not 1 <= result["max_ideas"] <= 1024:
        raise ControlError("invalid idea limit")
    edges = {e["edge_id"] for e in orientation["edges"]}
    progress = result["progress_edge_ids"]
    if (not isinstance(progress, list) or any(not isinstance(e, str) for e in progress)
            or len(set(progress)) != len(progress) or not set(progress) <= edges):
        raise ControlError("invalid progress edges")
    if any(e["edge_id"] in progress and e["destination"] in orientation["center_nodes"] for e in orientation["edges"]):
        raise ControlError("checkpoint returns cannot count as progress")
    windows = result["windows"]
    if not isinstance(windows, list) or not 1 <= len(windows) <= 128:
        raise ControlError("invalid center windows")
    seen, previous = set(), None
    for window in windows:
        if not isinstance(window, dict) or set(window) != {"center_id", "previous_center_id", "starts_at", "ends_at", "center_nodes"}:
            raise ControlError("invalid center window")
        validate_id(window["center_id"], "center_id")
        start, end = _time(window["starts_at"]), _time(window["ends_at"])
        centers = window["center_nodes"]
        if (end <= start or window["center_id"] in seen
                or window["previous_center_id"] != (previous["center_id"] if previous else None)
                or (previous and start != previous["ends_at"])):
            raise ControlError("center windows must be a contiguous predecessor chain")
        if (not isinstance(centers, list) or not centers or any(not isinstance(c, str) for c in centers)
                or len(set(centers)) != len(centers) or not set(centers) <= set(orientation["center_nodes"])):
            raise ControlError("invalid scheduled center nodes")
        if len(_distances({**orientation, "center_nodes": centers})) != len(orientation["nodes"]):
            raise ControlError("every node must return to each scheduled center")
        seen.add(window["center_id"])
        previous = window
    return result


def _state(db: Any, execution_id: str) -> Any:
    return db.execute("SELECT * FROM center_states WHERE execution_id=?", (execution_id,)).fetchone()


def _integrity(db: Any, row: Any, state: Any) -> str | None:
    if state is None:
        return "CENTER_SEED_REQUIRED"
    events = db.execute("SELECT * FROM center_events WHERE execution_id=? ORDER BY sequence", (state["execution_id"],)).fetchall()
    parent, sequence, last_time, after = _ZERO, 0, -1.0, None
    try:
        for event in events:
            payload = json.loads(event["event_json"])
            sequence += 1
            if (event["root_id"] != row["root_id"] or event["sequence"] != sequence
                    or event["parent_hash"] != parent or digest(payload) != event["event_hash"]
                    or payload["sequence"] != sequence or payload["parent_hash"] != parent
                    or payload["root_id"] != row["root_id"] or payload["execution_id"] != state["execution_id"]
                    or payload["profile_digest"] != row["profile_digest"] or payload["epoch"] != row["epoch"]
                    or _time(payload["recorded_at"]) < last_time
                    or (sequence == 1 and payload["kind"] != "SEED")
                    or (sequence > 1 and payload["kind"] not in {"ADMITTED", "OBSERVED"})):
                return "CENTER_CHAIN_BROKEN"
            parent, last_time, after = event["event_hash"], payload["recorded_at"], payload["state_after"]
        if (not events or sequence != state["sequence"] or parent != state["head_hash"]
                or any(after[key] != state[key] for key in _STATE_FIELDS)):
            return "CENTER_CHAIN_BROKEN"
        orientation = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (state["execution_id"],)).fetchone()
        if orientation is None or any(orientation[k] != state[k] for k in ("node_id", "revision", "pending_action_id")):
            return "CENTER_CHAIN_BROKEN"
    except (ValueError, TypeError, KeyError, ControlError):
        return "CENTER_CHAIN_BROKEN"
    return None


def _append(db: Any, row: Any, state: Any, kind: str, *, now: float, center_id: str,
            details: dict[str, Any], updates: dict[str, Any] | None = None) -> dict[str, Any]:
    updates = updates or {}
    after = {key: updates.get(key, state[key]) for key in _STATE_FIELDS}
    payload = {"root_id": row["root_id"], "execution_id": state["execution_id"],
               "epoch": row["epoch"], "profile_digest": row["profile_digest"],
               "orientation_profile_digest": row["orientation_profile_digest"],
               "sequence": state["sequence"] + 1, "parent_hash": state["head_hash"],
               "kind": kind, "center_id": center_id, "recorded_at": now,
               "details": details, "state_after": after}
    event_hash = digest(payload)
    db.execute("INSERT INTO center_events VALUES (?,?,?,?,?,?)", (row["root_id"], state["execution_id"],
               payload["sequence"], payload["parent_hash"], event_hash, canonical_bytes(payload).decode()))
    db.execute("""UPDATE center_states SET head_hash=?,sequence=?,node_id=?,revision=?,last_observed_at=?,
               last_progress_at=?,away_since=?,pending_action_id=?,checkpoint_center_id=? WHERE execution_id=?""",
               (event_hash, payload["sequence"], *(after[key] for key in _STATE_FIELDS), state["execution_id"]))
    return {**payload, "event_hash": event_hash}


def _hold(db: Any, execution_id: str, reason: str) -> str:
    db.execute("UPDATE center_states SET hold_reason=COALESCE(hold_reason,?) WHERE execution_id=?", (reason, execution_id))
    return reason


def _snapshot_payload(row: Any, json_field: str) -> dict[str, Any]:
    """A broken payload must remain visible without breaking the diagnostic UI."""
    try:
        value = json.loads(row[json_field])
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    return {"root_id": row["root_id"], "execution_id": row["execution_id"],
            "invalid_payload": True, "diagnosis": "CENTER_CHAIN_BROKEN",
            "stored_payload_digest": digest(row[json_field])}


def _reason(db: Any, row: Any, profile: Any, state: Any, now: float) -> str | None:
    integrity = _integrity(db, row, state)
    if integrity:
        if state is not None:
            _hold(db, state["execution_id"], integrity)
        return integrity
    if state["hold_reason"]:
        return state["hold_reason"]
    if now < state["last_observed_at"] or now - state["last_observed_at"] > profile["max_past_age_seconds"]:
        return "CENTER_PAST_STALE"
    if _window(profile, now) is None:
        return "CENTER_WINDOW_CLOSED"
    return None


def _away_since(state: Any, window: Any) -> float | None:
    # Relabelling a node as the next center is not a verified return to it.
    if state["away_since"] is not None:
        return state["away_since"]
    if state["checkpoint_center_id"] != window["center_id"]:
        return window["starts_at"]
    return None if state["node_id"] in window["center_nodes"] else state["last_observed_at"]


def _balance_reason(state: Any, profile: Any, window: Any, edge: Any, now: float) -> str | None:
    needs_reorientation = state["checkpoint_center_id"] != window["center_id"]
    if needs_reorientation and edge["destination"] not in window["center_nodes"]:
        return "CENTER_REORIENTATION_REQUIRED"
    outside = state["node_id"] not in window["center_nodes"] or needs_reorientation
    idle = now - state["last_progress_at"] >= profile["max_idle_seconds"]
    away = _away_since(state, window)
    if idle and not outside:
        return "CENTER_STAGNATION_HOLD"
    if ((idle or (away is not None and now - away >= profile["max_away_seconds"]))
            and edge["destination"] not in window["center_nodes"]):
        return "CENTER_RETURN_REQUIRED"
    return None


def center_nodes_in_transaction(db: Any, root_id: str, *, now: float) -> list[str] | None:
    _, profile = _load(db, root_id)
    if profile is None:
        return None
    window = _window(profile, now)
    return window["center_nodes"] if window else []


def seed_in_transaction(db: Any, root_id: str, execution_id: str, *, now: float) -> None:
    row, profile = _load(db, root_id)
    if profile is None:
        return
    orientation = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (execution_id,)).fetchone()
    window = _window(profile, now)
    if (orientation is None or orientation["root_id"] != root_id or window is None
            or not window["starts_at"] <= orientation["observed_at"] <= now
            or now - orientation["observed_at"] > profile["max_past_age_seconds"]):
        raise ControlError("CENTER_SEED_BINDING_MISMATCH")
    away = None if orientation["node_id"] in window["center_nodes"] else orientation["observed_at"]
    db.execute("INSERT INTO center_states VALUES (?,?,?,0,?,?,?,?,?,NULL,?,NULL)",
               (execution_id, root_id, _ZERO, orientation["node_id"], orientation["revision"],
                orientation["observed_at"], orientation["observed_at"], away,
                window["center_id"] if away is None else None))
    _append(db, row, _state(db, execution_id), "SEED", now=now, center_id=window["center_id"],
            details={"evidence_digest": orientation["evidence_digest"], "observed_at": orientation["observed_at"]})


def admission_in_transaction(db: Any, action: dict[str, Any], *, edge: Any, now: float) -> str | None:
    row, profile = _load(db, action["root_id"])
    if profile is None:
        return None
    state = _state(db, action["execution_id"])
    reason = _reason(db, row, profile, state, now)
    if reason:
        return reason
    projection = db.execute("SELECT * FROM center_projections WHERE action_id=?", (action["action_id"],)).fetchone()
    if projection is None:
        return "CENTER_PROJECTION_REQUIRED"
    item = json.loads(projection["projection_json"])
    window = _window(profile, now)
    if (projection["status"] != "PROJECTED" or projection["action_digest"] != digest(action)
            or projection["projection_digest"] != digest(item) or item["edge_id"] != edge["edge_id"]
            or item["expected_revision"] != state["revision"] or item["epoch"] != row["epoch"]
            or item["profile_digest"] != row["profile_digest"]):
        return "CENTER_PROJECTION_MISMATCH"
    if item["predecessor_hash"] != state["head_hash"]:
        return "CENTER_PREDECESSOR_MISMATCH"
    if item["center_id"] != window["center_id"]:
        return "CENTER_WINDOW_CLOSED"
    if not item["not_before"] <= now < item["deadline"]:
        return "CENTER_TRANSITION_EXPIRED" if now >= item["deadline"] else "CENTER_NOT_BEFORE"
    reason = _balance_reason(state, profile, window, edge, now)
    if reason:
        return reason
    _append(db, row, state, "ADMITTED", now=now, center_id=window["center_id"],
            details={"action_id": action["action_id"], "action_digest": digest(action),
                     "edge_id": edge["edge_id"], "projection_digest": projection["projection_digest"]},
            updates={"pending_action_id": action["action_id"], "away_since": _away_since(state, window)})
    db.execute("UPDATE center_projections SET status='CONSUMED' WHERE action_id=?", (action["action_id"],))
    return None


def pending_in_transaction(db: Any, action_id: str, *, now: float) -> str | None:
    occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone()
    if occurrence is None:
        return None
    row, profile = _load(db, occurrence["root_id"])
    if profile is None:
        return None
    state = _state(db, occurrence["execution_id"])
    reason = _reason(db, row, profile, state, now)
    if reason:
        return reason
    projection = db.execute("SELECT * FROM center_projections WHERE action_id=?", (action_id,)).fetchone()
    if projection is None or state["pending_action_id"] != action_id or projection["status"] != "CONSUMED":
        return "CENTER_PENDING_MISMATCH"
    item = json.loads(projection["projection_json"])
    if digest(item) != projection["projection_digest"]:
        return "CENTER_PROJECTION_MISMATCH"
    if _window(profile, now)["center_id"] != item["center_id"]:
        return "CENTER_WINDOW_CLOSED"
    if now >= item["deadline"] or now - occurrence["admitted_at"] >= profile["max_transition_seconds"]:
        return "CENTER_TRANSITION_EXPIRED"
    orientation = json.loads(db.execute("SELECT profile_json FROM orientation_profiles WHERE root_id=?", (row["root_id"],)).fetchone()[0])
    edge = next(e for e in orientation["edges"] if e["edge_id"] == occurrence["edge_id"])
    return _balance_reason(state, profile, _window(profile, now), edge, now)


def observe_in_transaction(db: Any, action_id: str, observation: dict[str, Any], *, now: float) -> bool:
    """Append a validated observed fact. False means it cannot restore centering.

    Call after ordinary observation validation and before orientation mutation.
    Historical facts may be late; preserving them must never reopen admission.
    """
    occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone()
    if occurrence is None:
        return True
    row, profile = _load(db, occurrence["root_id"])
    if profile is None:
        return True
    state = _state(db, occurrence["execution_id"])
    integrity = _integrity(db, row, state)
    if integrity:
        if state is not None:
            _hold(db, state["execution_id"], integrity)
        return False
    projection = db.execute("SELECT * FROM center_projections WHERE action_id=?", (action_id,)).fetchone()
    if projection is None or state["pending_action_id"] != action_id:
        _hold(db, state["execution_id"], "CENTER_PENDING_MISMATCH")
        return False
    item = json.loads(projection["projection_json"])
    window = _window(profile, now)
    observed = observation["observed_at"]
    session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (row["root_id"],)).fetchone()
    root = db.execute("SELECT * FROM roots WHERE root_id=?", (row["root_id"],)).fetchone()
    authority_open = (session["state"] == "ACTIVE" and not root["revoked"] and root["epoch"] == row["epoch"]
                      and now < min(session["hard_deadline"], session["lease_until"]))
    timely = (authority_open and not state["hold_reason"] and digest(item) == projection["projection_digest"]
              and window is not None and window["center_id"] == item["center_id"]
              and item["not_before"] <= observed <= now < item["deadline"]
              and now - occurrence["admitted_at"] < profile["max_transition_seconds"]
              and now - observed <= profile["max_past_age_seconds"])
    updates = {}
    if observation["outcome"] == "CONFIRMED":
        updates.update(node_id=occurrence["destination"], revision=occurrence["revision"],
                       last_observed_at=observed, pending_action_id=None)
        if timely:
            if occurrence["destination"] in window["center_nodes"]:
                updates["away_since"] = None
                updates["checkpoint_center_id"] = window["center_id"]
            elif state["away_since"] is None:
                updates["away_since"] = observed
            if occurrence["edge_id"] in profile["progress_edge_ids"]:
                updates["last_progress_at"] = observed
    if not authority_open:
        _hold(db, state["execution_id"], "CENTER_AUTHORITY_CLOSED_HOLD")
    elif not timely:
        _hold(db, state["execution_id"], "CENTER_LATE_OBSERVATION_HOLD")
    if observation["outcome"] == "CONTRADICTED":
        _hold(db, state["execution_id"], "CENTER_CONTRADICTION_HOLD")
        timely = False
    _append(db, row, state, "OBSERVED", now=now, center_id=item["center_id"],
            details={"action_id": action_id, "action_digest": occurrence["action_digest"],
                     "observed_at": observed, "evidence_digest": observation["evidence_digest"],
                     "observation_digest": digest(observation), "outcome": observation["outcome"],
                     "timely": timely}, updates=updates)
    return timely


class CenterContinuityStore:
    def __init__(self, authority: SessionAuthority) -> None:
        self.authority, self.db_path = authority, authority.db_path
        with connect(self.db_path) as db:
            initialize_schema(db)

    def _active(self, db: Any, root_id: str) -> Any:
        session, reason = self.authority._fresh(db, root_id)
        if reason:
            db.commit()
            raise ControlError(reason)
        return session

    def install(self, root_id: str, profile: dict[str, Any]) -> dict[str, Any]:
        profile = json.loads(canonical_bytes(profile))
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, root_id)
            if db.execute("SELECT 1 FROM center_profiles WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("center profile is immutable")
            orientation = db.execute("SELECT * FROM orientation_profiles WHERE root_id=?", (root_id,)).fetchone()
            if orientation is None:
                raise ControlError("ORIENTATION_PROFILE_REQUIRED")
            for table in ("orientation_states", "orientation_tickets", "brakes_actions"):
                if db.execute(f"SELECT 1 FROM {table} WHERE root_id=?", (root_id,)).fetchone():
                    raise ControlError("center profile must precede seeds, tickets and actions")
            profile = _profile(profile, json.loads(orientation["profile_json"]))
            db.execute("INSERT INTO center_profiles VALUES (?,?,?,?,?,?,?)", (root_id, orientation["epoch"],
                       session["policy_digest"], session["objective_digest"], orientation["profile_digest"],
                       digest(profile), canonical_bytes(profile).decode()))
            return {"root_id": root_id, "epoch": orientation["epoch"], "profile_digest": digest(profile), "profile": profile}

    def record_idea(self, root_id: str, execution_id: str, idea_id: str, content_digest: str,
                    expected_head_hash: str) -> dict[str, Any]:
        validate_id(idea_id, "idea_id")
        _hash(content_digest)
        _hash(expected_head_hash)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, root_id)
            row, profile = _load(db, root_id)
            state = _state(db, execution_id)
            if profile is None or state is None or state["root_id"] != root_id:
                raise ControlError("CENTER_SEED_REQUIRED")
            reason = _integrity(db, row, state)
            if reason or state["hold_reason"] or expected_head_hash != state["head_hash"]:
                raise ControlError(reason or state["hold_reason"] or "CENTER_PREDECESSOR_MISMATCH")
            idea = (root_id, execution_id, idea_id, content_digest, expected_head_hash)
            old = db.execute("SELECT * FROM center_ideas WHERE execution_id=? AND idea_id=?", (execution_id, idea_id)).fetchone()
            if old:
                if tuple(old)[:5] != idea:
                    raise ControlError("CENTER_IDEA_IMMUTABLE")
                recorded_at = old["recorded_at"]
            else:
                count = db.execute("SELECT COUNT(*) FROM center_ideas WHERE root_id=?", (root_id,)).fetchone()[0]
                if count >= profile["max_ideas"]:
                    raise ControlError("CENTER_IDEA_LIMIT")
                recorded_at = session["last_now"]
                db.execute("INSERT INTO center_ideas VALUES (?,?,?,?,?,?)", (*idea, recorded_at))
            return {"root_id": root_id, "execution_id": execution_id, "idea_id": idea_id,
                    "content_digest": content_digest, "predecessor_hash": expected_head_hash,
                    "recorded_at": recorded_at, "execution_authorized": False}

    def project(self, action: dict[str, Any], *, edge_id: str, expected_revision: int,
                predecessor_hash: str, idea_id: str, not_before: float, deadline: float) -> dict[str, Any]:
        action = _action(action)
        _hash(predecessor_hash)
        not_before, deadline = _time(not_before), _time(deadline)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ControlError("invalid projection revision")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, action["root_id"])
            now = session["last_now"]
            row, profile = _load(db, action["root_id"])
            if profile is None:
                raise ControlError("CENTER_PROFILE_REQUIRED")
            state = _state(db, action["execution_id"])
            reason = _reason(db, row, profile, state, now)
            if reason:
                db.commit()  # Preserve a detected broken-chain HOLD.
                raise ControlError(reason)
            if predecessor_hash != state["head_hash"]:
                raise ControlError("CENTER_PREDECESSOR_MISMATCH")
            if state["pending_action_id"]:
                raise ControlError("CENTER_OBSERVATION_REQUIRED")
            ticket = db.execute("SELECT * FROM orientation_tickets WHERE action_id=?", (action["action_id"],)).fetchone()
            if (ticket is None or ticket["status"] != "PREPARED" or ticket["action_digest"] != digest(action)
                    or ticket["edge_id"] != edge_id or ticket["expected_revision"] != expected_revision
                    or expected_revision != state["revision"] or action["epoch"] != row["epoch"]):
                raise ControlError("CENTER_TICKET_MISMATCH")
            idea = db.execute("SELECT * FROM center_ideas WHERE execution_id=? AND idea_id=?", (action["execution_id"], idea_id)).fetchone()
            if idea is None or idea["predecessor_hash"] != predecessor_hash:
                raise ControlError("CENTER_IDEA_BINDING_MISMATCH")
            window = _window(profile, now)
            if (not now <= not_before < deadline <= window["ends_at"]
                    or deadline - now > profile["max_future_horizon_seconds"]
                    or deadline - not_before > profile["max_transition_seconds"]):
                raise ControlError("CENTER_PROJECTION_TIME_BOUNDS")
            value = {key: action[key] for key in ("action_id", "root_id", "execution_id", "epoch")}
            value.update(action_digest=digest(action), edge_id=edge_id, expected_revision=expected_revision,
                         predecessor_hash=predecessor_hash, idea_id=idea_id, not_before=not_before,
                         deadline=deadline, center_id=window["center_id"], profile_digest=row["profile_digest"],
                         orientation_profile_digest=row["orientation_profile_digest"], created_at=now)
            old = db.execute("SELECT * FROM center_projections WHERE action_id=?", (action["action_id"],)).fetchone()
            if old:
                previous = json.loads(old["projection_json"])
                value["created_at"] = previous["created_at"]
                if old["projection_digest"] != digest(value) or old["status"] != "PROJECTED":
                    raise ControlError("CENTER_PROJECTION_IMMUTABLE")
            else:
                db.execute("INSERT INTO center_projections VALUES (?,?,?,?,?,?,?,?,?,?,'PROJECTED')",
                           (action["action_id"], action["root_id"], action["execution_id"], action["epoch"],
                            digest(action), digest(value), window["center_id"], predecessor_hash, now,
                            canonical_bytes(value).decode()))
            return {**value, "projection_digest": digest(value), "execution_authorized": False}

    def snapshot(self, root_id: str) -> dict[str, Any]:
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            row, profile = _load(db, root_id)
            if profile is None:
                return {"root_id": root_id, "profile": None, "states": [], "events": [], "ideas": [], "projections": []}
            try:
                now = self.authority._now()
            except ControlError:
                now = None
            session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (root_id,)).fetchone()
            states = []
            for state in db.execute("SELECT * FROM center_states WHERE root_id=? ORDER BY execution_id", (root_id,)):
                item = dict(state)
                reason = _integrity(db, row, state) or state["hold_reason"]
                window = _window(profile, now) if now is not None else None
                if not reason:
                    if now is None or now < state["last_observed_at"] or now < session["last_now"]:
                        reason = "CLOCK_UNSAFE"
                    elif session["state"] != "ACTIVE":
                        reason = session["stop_reason"] or "SESSION_STOPPED"
                    elif now >= min(session["hard_deadline"], session["lease_until"]):
                        reason = "SESSION_EXPIRED"
                    elif now - state["last_observed_at"] > profile["max_past_age_seconds"]:
                        reason = "CENTER_PAST_STALE"
                    elif window is None:
                        reason = "CENTER_WINDOW_CLOSED"
                    elif state["pending_action_id"]:
                        reason = "CENTER_OBSERVATION_REQUIRED"
                    else:
                        reason = _balance_reason(state, profile, window, {"destination": ""}, now)
                item.update(diagnosis=reason or "READY_FOR_RECHECK", active_center_id=window["center_id"] if window else None,
                            execution_authorized=False)
                states.append(item)
            events = [{**_snapshot_payload(e, "event_json"), "event_hash": e["event_hash"]}
                      for e in db.execute("SELECT * FROM center_events WHERE root_id=? ORDER BY execution_id,sequence", (root_id,))]
            projections = [{**_snapshot_payload(p, "projection_json"), "projection_digest": p["projection_digest"], "status": p["status"]}
                           for p in db.execute("SELECT * FROM center_projections WHERE root_id=? ORDER BY action_id", (root_id,))]
            return {"root_id": root_id, "profile": profile, "profile_digest": row["profile_digest"],
                    "orientation_profile_digest": row["orientation_profile_digest"], "epoch": row["epoch"],
                    "policy_digest": row["policy_digest"], "objective_digest": row["objective_digest"],
                    "states": states, "events": events, "projections": projections,
                    "ideas": [dict(i) for i in db.execute("SELECT * FROM center_ideas WHERE root_id=? ORDER BY execution_id,idea_id", (root_id,))],
                    "centers": profile["windows"], "active_center": _window(profile, now) if now is not None else None,
                    "snapshot_at": now, "execution_authorized": False}
