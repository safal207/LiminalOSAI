"""Host-owned spatial/temporal transition constraints, never action authority.

Spaces are named task/resource zones. A graph's center is a set of validated
states, not a claim about consciousness or a safety score. Reservations consume
trajectory budgets; only independent effect observations advance observed state.
The DB, profile, seeds, tickets and observer interface belong to the trusted host.
"""
from __future__ import annotations

import json
import math
import re
from collections import deque
from typing import Any, TYPE_CHECKING

from .authority import ACTION_FIELDS, AuthorityStore, ControlError, canonical_bytes, connect, digest, validate_id
if TYPE_CHECKING:
    from .brakes_store import SessionAuthority


def initialize_schema(db: Any) -> None:
    """Safe inside an existing transaction: executescript would commit it."""
    for statement in (
        """CREATE TABLE IF NOT EXISTS orientation_profiles (
            root_id TEXT PRIMARY KEY REFERENCES brakes_sessions(root_id), epoch INTEGER NOT NULL,
            policy_digest TEXT NOT NULL, objective_digest TEXT NOT NULL,
            profile_digest TEXT NOT NULL, profile_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS orientation_states (
            execution_id TEXT PRIMARY KEY REFERENCES brakes_executions(execution_id),
            root_id TEXT NOT NULL REFERENCES orientation_profiles(root_id), node_id TEXT NOT NULL,
            revision INTEGER NOT NULL, observed_at REAL NOT NULL, evidence_digest TEXT NOT NULL,
            steps INTEGER NOT NULL, away_steps INTEGER NOT NULL, visits_json TEXT NOT NULL,
            pending_action_id TEXT, hold_reason TEXT)""",
        """CREATE TABLE IF NOT EXISTS orientation_seeds (
            execution_id TEXT PRIMARY KEY REFERENCES orientation_states(execution_id),
            root_id TEXT NOT NULL, node_id TEXT NOT NULL, observed_at REAL NOT NULL,
            evidence_digest TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS orientation_tickets (
            action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, root_id TEXT NOT NULL,
            execution_id TEXT NOT NULL, epoch INTEGER NOT NULL, action_digest TEXT NOT NULL,
            edge_id TEXT NOT NULL, expected_revision INTEGER NOT NULL, profile_digest TEXT NOT NULL,
            status TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS orientation_occurrences (
            action_id TEXT PRIMARY KEY REFERENCES orientation_tickets(action_id), root_id TEXT NOT NULL,
            execution_id TEXT NOT NULL, action_digest TEXT NOT NULL, epoch INTEGER NOT NULL,
            source TEXT NOT NULL, destination TEXT NOT NULL, edge_id TEXT NOT NULL,
            revision INTEGER NOT NULL, channel TEXT NOT NULL, status TEXT NOT NULL,
            admitted_at REAL NOT NULL, observed_at REAL, evidence_digest TEXT,
            observer_id TEXT, observation_digest TEXT,
            UNIQUE(execution_id,revision))""",
        """CREATE TABLE IF NOT EXISTS orientation_observations (
            observation_digest TEXT PRIMARY KEY, action_id TEXT NOT NULL,
            observation_json TEXT NOT NULL, ingested_at REAL NOT NULL)""",
    ):
        db.execute(statement)


def _hash(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ControlError("invalid evidence digest")
    return value


def _time(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ControlError("invalid observation time")
    return float(value)


def _profile(value: Any) -> dict[str, Any]:
    fields = {"nodes", "edges", "center_nodes", "max_steps", "max_visits", "max_away_steps",
              "max_observation_age_seconds", "observers"}
    if not isinstance(value, dict) or set(value) != fields or len(canonical_bytes(value)) > 65536:
        raise ControlError("invalid orientation profile")
    value = json.loads(canonical_bytes(value))
    for key in ("max_steps", "max_visits", "max_away_steps"):
        if type(value[key]) is not int or not (0 if key == "max_away_steps" else 1) <= value[key] < 2**31:
            raise ControlError("invalid orientation limit")
    if _time(value["max_observation_age_seconds"]) <= 0:
        raise ControlError("invalid observation age limit")
    if not isinstance(value["observers"], dict) or set(value["observers"]) != {"records", "egress"}:
        raise ControlError("invalid observers")
    for observer in value["observers"].values():
        validate_id(observer, "observer")
    if not isinstance(value["nodes"], list) or not 1 <= len(value["nodes"]) <= 256:
        raise ControlError("invalid nodes")
    nodes = {}
    for node in value["nodes"]:
        if not isinstance(node, dict) or set(node) != {"node_id", "space_id", "phase"}:
            raise ControlError("invalid node")
        for item in node.values():
            validate_id(item, "node field")
        if node["node_id"] in nodes:
            raise ControlError("duplicate node")
        nodes[node["node_id"]] = node
    centers = value["center_nodes"]
    if (not isinstance(centers, list) or not centers or any(not isinstance(c, str) for c in centers)
            or len(set(centers)) != len(centers) or not set(centers) <= nodes.keys()):
        raise ControlError("invalid center nodes")
    if not isinstance(value["edges"], list) or len(value["edges"]) > 1024:
        raise ControlError("invalid edges")
    edges = set()
    for edge in value["edges"]:
        if not isinstance(edge, dict) or set(edge) != {"edge_id", "source", "destination", "channel"}:
            raise ControlError("invalid edge")
        for item in edge.values():
            validate_id(item, "edge field")
        if (edge["edge_id"] in edges or edge["source"] not in nodes or edge["destination"] not in nodes
                or edge["channel"] not in {"records", "egress"}):
            raise ControlError("invalid edge binding")
        edges.add(edge["edge_id"])
    if set(_distances(value)) != nodes.keys():
        raise ControlError("every node must have a directed return path to a center")
    return value


def _distances(profile: dict[str, Any]) -> dict[str, int]:
    distances = dict.fromkeys(profile["center_nodes"], 0)
    queue = deque(distances)
    reverse: dict[str, list[str]] = {}
    for edge in profile["edges"]:
        reverse.setdefault(edge["destination"], []).append(edge["source"])
    while queue:
        node = queue.popleft()
        for source in reverse.get(node, []):
            if source not in distances:
                distances[source] = distances[node] + 1
                queue.append(source)
    return distances


def _load(db: Any, root_id: str) -> tuple[Any, Any]:
    row = db.execute("SELECT * FROM orientation_profiles WHERE root_id=?", (root_id,)).fetchone()
    return row, json.loads(row["profile_json"]) if row else None


def _state_reason(state: Any, profile: Any, now: float, *, pending: bool = False) -> str | None:
    if state is None:
        return "ORIENTATION_SEED_REQUIRED"
    if state["hold_reason"]:
        return state["hold_reason"]
    if state["pending_action_id"] and not pending:
        return "ORIENTATION_OBSERVATION_REQUIRED"
    if now < state["observed_at"] or now - state["observed_at"] > profile["max_observation_age_seconds"]:
        return "ORIENTATION_OBSERVATION_STALE"
    return None


def admission_in_transaction(db: Any, action: dict[str, Any], *, channel: str, now: float,
                              payload_digest: str | None = None,
                              policy_digest: str | None = None) -> str | None:
    """Call after authority/quota checks, in the SAME action reservation transaction."""
    if not db.in_transaction:
        raise ControlError("orientation admission requires transaction")
    profile_row, profile = _load(db, action["root_id"])
    if profile is None:
        return None
    state = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (action["execution_id"],)).fetchone()
    reason = _state_reason(state, profile, now)
    if reason:
        return reason
    if state["root_id"] != action["root_id"] or profile_row["epoch"] != action["epoch"]:
        return "ORIENTATION_BINDING_MISMATCH"
    ticket = db.execute("SELECT * FROM orientation_tickets WHERE action_id=?", (action["action_id"],)).fetchone()
    if ticket is None:
        return "ORIENTATION_TICKET_REQUIRED"
    if (ticket["action_digest"] != digest(action) or ticket["profile_digest"] != profile_row["profile_digest"]
            or ticket["expected_revision"] != state["revision"] or ticket["status"] != "PREPARED"):
        return "ORIENTATION_TICKET_MISMATCH"
    edge = next(e for e in profile["edges"] if e["edge_id"] == ticket["edge_id"])
    if edge["source"] != state["node_id"] or edge["channel"] != channel:
        return "ORIENTATION_EDGE_MISMATCH"
    if channel == "records":
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='receiver_meta'").fetchone():
            return "ORIENTATION_OBSERVER_MISMATCH"
        receiver = db.execute("SELECT value FROM receiver_meta WHERE key='receiver_id'").fetchone()
        if receiver is None or receiver[0] != profile["observers"]["records"]:
            return "ORIENTATION_OBSERVER_MISMATCH"
    visits = json.loads(state["visits_json"])
    # Reserving a return does not establish that the center was reached.
    away = state["away_steps"] if edge["destination"] in profile["center_nodes"] else state["away_steps"] + 1
    if state["steps"] >= profile["max_steps"]:
        return "ORIENTATION_STEP_LIMIT"
    if visits.get(edge["destination"], 0) >= profile["max_visits"]:
        return "ORIENTATION_VISIT_LIMIT"
    if away > profile["max_away_steps"]:
        return "ORIENTATION_AWAY_LIMIT"
    visits[edge["destination"]] = visits.get(edge["destination"], 0) + 1
    db.execute("UPDATE orientation_states SET steps=steps+1,away_steps=?,visits_json=?,pending_action_id=? WHERE execution_id=?",
               (away, canonical_bytes(visits).decode(), action["action_id"], action["execution_id"]))
    db.execute("UPDATE orientation_tickets SET status='RESERVED' WHERE action_id=?", (action["action_id"],))
    db.execute("INSERT INTO orientation_occurrences VALUES (?,?,?,?,?,?,?,?,?,?,'PENDING',?,NULL,NULL,NULL,NULL)",
               (action["action_id"], action["root_id"], action["execution_id"], digest(action), action["epoch"],
                edge["source"], edge["destination"], edge["edge_id"], state["revision"] + 1, channel, now))
    return None


def check_pending_in_transaction(db: Any, action_id: str, *, now: float) -> str | None:
    action = db.execute("SELECT * FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()
    if action is None:
        return "ORIENTATION_UNKNOWN_ACTION"
    _, profile = _load(db, action["root_id"])
    if profile is None:
        return None
    state = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (action["execution_id"],)).fetchone()
    reason = _state_reason(state, profile, now, pending=True)
    if reason:
        return reason
    occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone()
    if (state["pending_action_id"] != action_id or occurrence is None or occurrence["status"] != "PENDING"
            or occurrence["revision"] != state["revision"] + 1):
        return "ORIENTATION_PENDING_MISMATCH"
    return None


def _observe(db: Any, action_id: str, observation: dict[str, Any], *, now: float,
             internal_record: bool = False) -> dict[str, Any]:
    fields = {"action_id", "action_digest", "root_id", "execution_id", "epoch", "profile_digest",
              "observed_at", "evidence_digest", "observer_id", "outcome"}
    if not isinstance(observation, dict) or set(observation) != fields:
        raise ControlError("invalid observation fields")
    _hash(observation["evidence_digest"])
    observed = _time(observation["observed_at"])
    if observation["outcome"] not in {"CONFIRMED", "UNKNOWN", "CONTRADICTED"}:
        raise ControlError("invalid observation outcome")
    occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone()
    if occurrence is None:
        raise ControlError("ORIENTATION_UNKNOWN_ACTION")
    row, profile = _load(db, occurrence["root_id"])
    for key in ("action_id", "action_digest", "root_id", "execution_id", "epoch"):
        if type(observation[key]) is not type(occurrence[key]) or observation[key] != occurrence[key]:
            raise ControlError("ORIENTATION_OBSERVATION_BINDING_MISMATCH")
    if observation["action_id"] != action_id or observation["profile_digest"] != row["profile_digest"]:
        raise ControlError("ORIENTATION_OBSERVATION_BINDING_MISMATCH")
    if observation["observer_id"] != profile["observers"][occurrence["channel"]]:
        raise ControlError("ORIENTATION_OBSERVER_MISMATCH")
    if occurrence["channel"] == "records" and not internal_record:
        raise ControlError("record observations require the receiver effect transaction")
    if observed < occurrence["admitted_at"] or observed > now or now - observed > profile["max_observation_age_seconds"]:
        raise ControlError("ORIENTATION_OBSERVATION_STALE")
    observation_digest = digest(observation)
    if db.execute("SELECT 1 FROM orientation_observations WHERE observation_digest=?", (observation_digest,)).fetchone():
        return dict(occurrence)
    state = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (occurrence["execution_id"],)).fetchone()
    if (state["hold_reason"] or state["pending_action_id"] != action_id
            or occurrence["revision"] != state["revision"] + 1
            or occurrence["status"] not in {"PENDING", "UNKNOWN"}):
        raise ControlError("ORIENTATION_OBSERVATION_NOT_PENDING")
    if observation["outcome"] == "CONFIRMED":
        action = db.execute("SELECT status FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()
        required = {"COMMITTED"} if internal_record else {"RETURNED", "UNKNOWN"}
        pending = db.execute("SELECT 1 FROM brakes_stages WHERE action_id=? AND status='RESERVED'", (action_id,)).fetchone()
        if action is None or action[0] not in required or pending:
            raise ControlError("ORIENTATION_EFFECT_STILL_IN_FLIGHT")
        away = 0 if occurrence["destination"] in profile["center_nodes"] else state["away_steps"]
        db.execute("UPDATE orientation_states SET node_id=?,revision=?,observed_at=?,evidence_digest=?,away_steps=?,pending_action_id=NULL WHERE execution_id=?",
                   (occurrence["destination"], occurrence["revision"], observed, observation["evidence_digest"], away, occurrence["execution_id"]))
    elif observation["outcome"] == "CONTRADICTED":
        db.execute("UPDATE orientation_states SET hold_reason='ORIENTATION_CONTRADICTION_HOLD' WHERE execution_id=?",
                   (occurrence["execution_id"],))
    db.execute("INSERT INTO orientation_observations VALUES (?,?,?,?)",
               (observation_digest, action_id, canonical_bytes(observation).decode(), now))
    db.execute("UPDATE orientation_occurrences SET status=?,observed_at=?,evidence_digest=?,observer_id=?,observation_digest=? WHERE action_id=?",
               (observation["outcome"], observed, observation["evidence_digest"], observation["observer_id"], observation_digest, action_id))
    return dict(db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone())


def confirm_record_in_transaction(db: Any, action_id: str, *, receiver_id: str,
                                  receipt_digest: str, now: float) -> None:
    action = db.execute("SELECT * FROM brakes_actions WHERE action_id=?", (action_id,)).fetchone()
    if action is None:
        return
    row, profile = _load(db, action["root_id"])
    if profile is None:
        return
    session = db.execute("SELECT last_now FROM brakes_sessions WHERE root_id=?", (action["root_id"],)).fetchone()
    if _time(now) < session["last_now"]:
        raise ControlError("CLOCK_UNSAFE")
    db.execute("UPDATE brakes_sessions SET last_now=? WHERE root_id=?", (now, action["root_id"]))
    observation = {key: action[key] for key in ("action_id", "action_digest", "root_id", "execution_id", "epoch")}
    observation.update(profile_digest=row["profile_digest"], observed_at=now, evidence_digest=receipt_digest,
                       observer_id=receiver_id, outcome="CONFIRMED")
    _observe(db, action_id, observation, now=now, internal_record=True)


class OrientationStore:
    def __init__(self, authority: SessionAuthority) -> None:
        self.authority, self.db_path = authority, authority.db_path
        with connect(self.db_path) as db:
            initialize_schema(db)

    def _active(self, db: Any, root_id: str) -> Any:
        row, reason = self.authority._fresh(db, root_id)
        if reason:
            db.commit()  # Preserve terminal clock/lease failure before raising.
            raise ControlError(reason)
        return row

    def install(self, root_id: str, profile: dict[str, Any]) -> dict[str, Any]:
        profile = _profile(profile)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, root_id)
            if db.execute("SELECT 1 FROM orientation_profiles WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("orientation profile is immutable")
            if db.execute("SELECT 1 FROM brakes_actions WHERE root_id=?", (root_id,)).fetchone():
                raise ControlError("orientation profile requires a root with no admitted actions")
            epoch = db.execute("SELECT epoch FROM roots WHERE root_id=?", (root_id,)).fetchone()[0]
            db.execute("INSERT INTO orientation_profiles VALUES (?,?,?,?,?,?)", (root_id, epoch,
                       session["policy_digest"], session["objective_digest"], digest(profile), canonical_bytes(profile).decode()))
            return {"root_id": root_id, "epoch": epoch, "profile_digest": digest(profile), "profile": profile}

    def seed(self, root_id: str, execution_id: str, node_id: str, *, evidence_digest: str,
             observed_at: float) -> dict[str, Any]:
        _hash(evidence_digest)
        observed_at = _time(observed_at)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, root_id)
            row, profile = _load(db, root_id)
            registered = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?", (execution_id,)).fetchone()
            if (profile is None or registered is None or registered["root_id"] != root_id
                    or registered["epoch"] != row["epoch"] or node_id not in _distances(profile)):
                raise ControlError("ORIENTATION_SEED_BINDING_MISMATCH")
            if observed_at > session["last_now"] or session["last_now"] - observed_at > profile["max_observation_age_seconds"]:
                raise ControlError("ORIENTATION_OBSERVATION_STALE")
            if db.execute("SELECT 1 FROM orientation_states WHERE execution_id=?", (execution_id,)).fetchone():
                raise ControlError("orientation seed is immutable")
            db.execute("INSERT INTO orientation_states VALUES (?,?,?,0,?,?,0,0,?,NULL,NULL)",
                       (execution_id, root_id, node_id, observed_at, evidence_digest, canonical_bytes({node_id: 1}).decode()))
            db.execute("INSERT INTO orientation_seeds VALUES (?,?,?,?,?)",
                       (execution_id, root_id, node_id, observed_at, evidence_digest))
            return dict(db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (execution_id,)).fetchone())

    def prepare(self, action: dict[str, Any], *, edge_id: str, expected_revision: int) -> dict[str, Any]:
        # Freeze caller-owned data before waiting for the database write lock.
        action = json.loads(canonical_bytes(action))
        if not isinstance(action, dict) or set(action) != ACTION_FIELDS or len(canonical_bytes(action)) > 16384:
            raise ControlError("invalid transition action")
        for key in ("action_id", "attempt_id", "root_id", "execution_id", "target"):
            validate_id(action[key], key)
        if type(action["epoch"]) is not int or type(expected_revision) is not int or expected_revision < 0:
            raise ControlError("invalid transition revision")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._active(db, action["root_id"])
            row, profile = _load(db, action["root_id"])
            if profile is None:
                raise ControlError("ORIENTATION_PROFILE_REQUIRED")
            reason = AuthorityStore.denial(db, action)
            state = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (action["execution_id"],)).fetchone()
            reason = reason or _state_reason(state, profile, session["last_now"])
            if reason:
                raise ControlError(reason)
            edge = next((e for e in profile["edges"] if e["edge_id"] == edge_id), None)
            if state["revision"] != expected_revision or edge is None or edge["source"] != state["node_id"]:
                raise ControlError("ORIENTATION_EDGE_OR_REVISION_MISMATCH")
            ticket = (action["action_id"], action["attempt_id"], action["root_id"], action["execution_id"], action["epoch"],
                      digest(action), edge_id, expected_revision, row["profile_digest"], "PREPARED")
            old = db.execute("SELECT * FROM orientation_tickets WHERE action_id=? OR attempt_id=?",
                             (action["action_id"], action["attempt_id"])).fetchone()
            if old:
                if tuple(old) != ticket:
                    raise ControlError("ORIENTATION_TICKET_IMMUTABLE")
            else:
                db.execute("INSERT INTO orientation_tickets VALUES (?,?,?,?,?,?,?,?,?,?)", ticket)
            return dict(db.execute("SELECT * FROM orientation_tickets WHERE action_id=?", (action["action_id"],)).fetchone())

    def observe(self, action_id: str, *, observation: dict[str, Any]) -> dict[str, Any]:
        observation = json.loads(canonical_bytes(observation))
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action_id,)).fetchone()
            if occurrence is None:
                raise ControlError("ORIENTATION_UNKNOWN_ACTION")
            session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (occurrence["root_id"],)).fetchone()
            try:
                now = self.authority._now()
                if now < session["last_now"]:
                    raise ControlError("clock rollback")
            except ControlError:
                self.authority._close(db, session, "CLOCK_UNSAFE", "CLOCK_UNSAFE")
                db.commit()
                raise ControlError("CLOCK_UNSAFE")
            db.execute("UPDATE brakes_sessions SET last_now=? WHERE root_id=?", (now, occurrence["root_id"]))
            return _observe(db, action_id, observation, now=now)

    def snapshot(self, root_id: str) -> dict[str, Any]:
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            row, profile = _load(db, root_id)
            if profile is None:
                return {"root_id": root_id, "profile": None, "executions": [], "occurrences": [], "observations": [], "seeds": [], "tickets": []}
            distances = _distances(profile)
            states = []
            for state in db.execute("SELECT * FROM orientation_states WHERE root_id=? ORDER BY execution_id", (root_id,)):
                item = dict(state)
                item["visits"] = json.loads(item.pop("visits_json"))
                item["distance_to_center"] = distances[item["node_id"]]
                states.append(item)
            occurrences = [dict(o) for o in db.execute("SELECT * FROM orientation_occurrences WHERE root_id=? ORDER BY execution_id,revision", (root_id,))]
            observations = [json.loads(o[0]) for o in db.execute("SELECT observation_json FROM orientation_observations o JOIN orientation_occurrences c USING(action_id) WHERE c.root_id=? ORDER BY o.rowid", (root_id,))]
            seeds = [dict(s) for s in db.execute("SELECT * FROM orientation_seeds WHERE root_id=? ORDER BY execution_id", (root_id,))]
            tickets = [dict(t) for t in db.execute("SELECT * FROM orientation_tickets WHERE root_id=? ORDER BY action_id", (root_id,))]
            return {"root_id": root_id, "profile": profile, "profile_digest": row["profile_digest"],
                    "policy_digest": row["policy_digest"], "objective_digest": row["objective_digest"],
                    "epoch": row["epoch"], "executions": states, "occurrences": occurrences, "observations": observations,
                    "seeds": seeds, "tickets": tickets}
