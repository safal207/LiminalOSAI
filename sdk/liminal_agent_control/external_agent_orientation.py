"""Required host orientation veto for the separate G03 orientation profile.

The host must provision the session, profiles, seed, ticket, idea and projection.
This adapter only consumes an existing transition and rechecks it before POST.
A local veto cannot settle a remote reservation, prove NO_EFFECT, or advance the
observed trajectory. The receiver transaction remains the STOP/COMMIT boundary.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from . import center_continuity, orientation
from .authority import AuthorityStore, ControlError, canonical_bytes, digest
from .brakes_store import SessionAuthority
from .external_agent_coordinator import agent_policy_digest, validate_run_binding
from .external_agent_effect_gateway import ClosedChannelEffectGateway, _copy, _identity, _reason
from .external_agent_receiver_gateway import ReceiverFencedEffectGateway
from .external_network_protocol import validate_network_action

ORIENTATION_STAGE = "g03-endpoint-post"
ORIENTATION_CONTRACT_SCHEMA = "liminal-agent-orientation-admission-contract-v1"


class OrientationAdmissionGuard:
    """One pending, already prepared host transition; never an auto-planner."""

    _AUTHORITY_METHODS = ("_connect", "_fresh", "_now", "_require_transaction",
                          "admit_in_transaction", "reserve", "begin_stage")

    def __init__(self, authority: SessionAuthority, *, run_binding: Any) -> None:
        if type(authority) is not SessionAuthority:
            raise ControlError("AGENT_ORIENTATION_AUTHORITY_REQUIRED")
        self.authority = self._bound_authority = authority
        self.run_binding = validate_run_binding(run_binding)
        self._run_binding_bytes = canonical_bytes(self.run_binding)
        self._policy_digest = agent_policy_digest(self.run_binding, "effect")
        self._path = Path(authority.db_path).absolute()
        self._path_identity = self._database_identity()
        self._authority_methods = {name: _identity(getattr(authority, name, None))
                                   for name in self._AUTHORITY_METHODS}
        if any(expected != (authority, getattr(SessionAuthority, name))
               for name, expected in self._authority_methods.items()):
            raise ControlError("AGENT_ORIENTATION_AUTHORITY_ROUTE_CHANGED")
        self._authority_clock = authority.clock
        self._lock = threading.RLock()
        # Use existing-only authority access. Construction does not initialize
        # tables, roots, profiles, tickets or any observations.
        with authority._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            session, failure = authority._fresh(db, self.run_binding["effect"]["root_id"])
            if failure is None:
                self._profile_binding_bytes = canonical_bytes(self._profile_binding(db, session))
        if failure:
            raise ControlError(failure)
        body = {"schema": ORIENTATION_CONTRACT_SCHEMA, "required": True,
                "run_binding_digest": digest(self.run_binding),
                "effect": _copy(self.run_binding["effect"]),
                "authority_store_path": str(self._path),
                "authority_store_identity": list(self._path_identity),
                "bindings": json.loads(self._profile_binding_bytes),
                "channel": "egress", "stage_id": ORIENTATION_STAGE,
                "scope": "ONE_PENDING_HOST_TRANSITION",
                "failure_outcome": "PRESERVE_PENDING_QUERY_ONLY",
                "observation_bridge": "NOT_CONNECTED",
                "execution_authorized": False}
        self._configuration_bytes = canonical_bytes({**body, "contract_digest": digest(body)})
        self.assert_bound()

    def _database_identity(self) -> tuple[int, int]:
        if (not self._path.is_file()
                or any(item.is_symlink() for item in (self._path, *self._path.parents))):
            raise ControlError("AGENT_ORIENTATION_DATABASE_UNSAFE")
        stat = self._path.stat()
        return stat.st_dev, stat.st_ino

    def configuration(self) -> dict:
        # Query-only recovery must remain possible if the live local authority
        # is stopped, missing or replaced. Only admission uses assert_bound.
        return json.loads(self._configuration_bytes)

    def _assert_identity(self) -> None:
        if (self.authority is not self._bound_authority
                or type(self.authority) is not SessionAuthority
                or Path(self.authority.db_path).absolute() != self._path
                or self._database_identity() != self._path_identity
                or self.authority.clock is not self._authority_clock
                or canonical_bytes(validate_run_binding(self.run_binding)) != self._run_binding_bytes):
            raise ControlError("AGENT_ORIENTATION_BINDING_IMMUTABLE")
        if any(_identity(getattr(self.authority, name, None)) != expected
               for name, expected in self._authority_methods.items()):
            raise ControlError("AGENT_ORIENTATION_AUTHORITY_ROUTE_CHANGED")

    def _profile_binding(self, db: Any, session: Any) -> dict:
        part = self.run_binding["effect"]
        root = db.execute("SELECT * FROM roots WHERE root_id=?", (part["root_id"],)).fetchone()
        execution = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?",
                               (part["execution_id"],)).fetchone()
        base_execution = db.execute("SELECT * FROM executions WHERE execution_id=?",
                                    (part["execution_id"],)).fetchone()
        if (session is None or session["policy_digest"] != self._policy_digest
                or root is None or root["epoch"] != part["epoch"] or root["revoked"]
                or execution is None or base_execution is None
                or any(row["root_id"] != part["root_id"] or row["epoch"] != part["epoch"]
                       for row in (execution, base_execution))
                or execution["parent_execution_id"] != base_execution["parent_execution_id"]):
            raise ControlError("AGENT_ORIENTATION_SESSION_BINDING_MISMATCH")
        orient = db.execute("SELECT * FROM orientation_profiles WHERE root_id=?", (part["root_id"],)).fetchone()
        center = db.execute("SELECT * FROM center_profiles WHERE root_id=?", (part["root_id"],)).fetchone()
        if orient is None:
            raise ControlError("ORIENTATION_PROFILE_REQUIRED")
        if center is None:
            raise ControlError("CENTER_PROFILE_REQUIRED")
        profile = orientation._profile(json.loads(orient["profile_json"]))
        center_profile = center_continuity._profile(json.loads(center["profile_json"]), profile)
        if (any(row["epoch"] != part["epoch"] or row["policy_digest"] != self._policy_digest
                or row["objective_digest"] != session["objective_digest"] for row in (orient, center))
                or digest(profile) != orient["profile_digest"]
                or digest(center_profile) != center["profile_digest"]
                or center["orientation_profile_digest"] != orient["profile_digest"]):
            raise ControlError("AGENT_ORIENTATION_PROFILE_BINDING_MISMATCH")
        orientation._hash(session["objective_digest"])
        return {"policy_digest": self._policy_digest, "objective_digest": session["objective_digest"],
                "orientation_profile_digest": orient["profile_digest"],
                "center_profile_digest": center["profile_digest"],
                "execution_parent": execution["parent_execution_id"], "execution_depth": execution["depth"]}

    def _bound_profiles(self, db: Any, session: Any) -> None:
        if canonical_bytes(self._profile_binding(db, session)) != self._profile_binding_bytes:
            raise ControlError("AGENT_ORIENTATION_PROFILE_IMMUTABLE")

    def assert_bound(self) -> None:
        with self._lock:
            self._assert_identity()
            with self.authority._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?",
                                     (self.run_binding["effect"]["root_id"],)).fetchone()
                self._bound_profiles(db, session)
                self._assert_identity()

    def _action(self, proposed: Any) -> dict:
        action = validate_network_action(proposed)
        if canonical_bytes(action) not in {canonical_bytes(item) for item in self.run_binding["effect_actions"]}:
            raise ControlError("AGENT_ORIENTATION_ACTION_BINDING_MISMATCH")
        return action

    def _pending(self, db: Any, action: dict, session: Any, *, require_stage: bool) -> str | None:
        row = db.execute("SELECT * FROM brakes_actions WHERE action_id=? OR attempt_id=?",
                         (action["action_id"], action["attempt_id"])).fetchall()
        if (len(row) != 1 or any(row[0][field] != action[field]
                                 for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                or row[0]["status"] != "RESERVED" or row[0]["channel"] != "egress"
                or row[0]["action_digest"] != digest(action) or row[0]["payload_digest"] != digest(action)
                or row[0]["policy_digest"] != self._policy_digest):
            return "AGENT_ORIENTATION_PENDING_BINDING_MISMATCH"
        reason = AuthorityStore.denial(db, action)
        if reason:
            return reason
        ticket = db.execute("SELECT * FROM orientation_tickets WHERE action_id=?", (action["action_id"],)).fetchone()
        occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (action["action_id"],)).fetchone()
        state = db.execute("SELECT * FROM orientation_states WHERE execution_id=?", (action["execution_id"],)).fetchone()
        if (ticket is None or occurrence is None or state is None
                or ticket["status"] != "RESERVED" or ticket["profile_digest"] != json.loads(self._profile_binding_bytes)["orientation_profile_digest"]
                or any(ticket[field] != action[field] or occurrence[field] != action[field]
                       for field in ("action_id", "root_id", "execution_id", "epoch"))
                or ticket["attempt_id"] != action["attempt_id"]
                or ticket["action_digest"] != digest(action) or occurrence["action_digest"] != digest(action)
                or occurrence["channel"] != "egress" or occurrence["edge_id"] != ticket["edge_id"]
                or state["root_id"] != action["root_id"] or ticket["expected_revision"] != state["revision"]
                or occurrence["revision"] != ticket["expected_revision"] + 1):
            return "AGENT_ORIENTATION_PENDING_BINDING_MISMATCH"
        projection = db.execute("SELECT * FROM center_projections WHERE action_id=?", (action["action_id"],)).fetchone()
        if projection is None:
            return "CENTER_PROJECTION_REQUIRED"
        item = json.loads(projection["projection_json"])
        bindings = json.loads(self._profile_binding_bytes)
        if (projection["status"] != "CONSUMED" or projection["action_digest"] != digest(action)
                or any(projection[field] != action[field] or item.get(field) != action[field]
                       for field in ("action_id", "root_id", "execution_id", "epoch"))
                or item.get("action_digest") != digest(action)
                or item.get("edge_id") != ticket["edge_id"]
                or item.get("expected_revision") != ticket["expected_revision"]
                or item.get("profile_digest") != bindings["center_profile_digest"]
                or item.get("orientation_profile_digest") != bindings["orientation_profile_digest"]
                or projection["projection_digest"] != digest(item)
                or item.get("predecessor_hash") != projection["predecessor_hash"]
                or item.get("center_id") != projection["center_id"]):
            return "CENTER_PROJECTION_MISMATCH"
        idea = db.execute("SELECT * FROM center_ideas WHERE execution_id=? AND idea_id=?",
                          (action["execution_id"], item.get("idea_id"))).fetchone()
        if (idea is None or idea["root_id"] != action["root_id"]
                or idea["predecessor_hash"] != projection["predecessor_hash"]):
            return "CENTER_IDEA_BINDING_MISMATCH"
        orientation._hash(idea["content_digest"])
        reason = orientation.check_pending_in_transaction(db, action["action_id"], now=session["last_now"])
        if reason:
            return reason
        events = [json.loads(row[0]) for row in db.execute(
            "SELECT event_json FROM center_events WHERE execution_id=? ORDER BY sequence",
            (action["execution_id"],))]
        admitted = [event for event in events if event["kind"] == "ADMITTED"
                    and event["details"].get("action_id") == action["action_id"]]
        expected = {"action_id": action["action_id"], "action_digest": digest(action),
                    "edge_id": ticket["edge_id"], "projection_digest": projection["projection_digest"]}
        if (len(admitted) != 1 or admitted[0]["details"] != expected
                or admitted[0]["parent_hash"] != projection["predecessor_hash"]):
            return "CENTER_PROJECTION_MISMATCH"
        if require_stage:
            stage = db.execute("SELECT * FROM brakes_stages WHERE action_id=? AND stage_id=?",
                               (action["action_id"], ORIENTATION_STAGE)).fetchone()
            if stage is None or stage["status"] != "RESERVED":
                return "AGENT_ORIENTATION_STAGE_REQUIRED"
        return None

    def admit(self, proposed: Any) -> None:
        action = self._action(proposed)
        with self._lock:
            self._assert_identity()
            with self.authority._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                session, failure = self.authority._fresh(db, action["root_id"])
                if failure is None:
                    self._bound_profiles(db, session)
                    old = db.execute("SELECT 1 FROM brakes_actions WHERE action_id=? OR attempt_id=?",
                                     (action["action_id"], action["attempt_id"])).fetchone()
                    if old is None:
                        result = self.authority.admit_in_transaction(db, action, channel="egress",
                            payload_digest=digest(action), policy_digest=self._policy_digest)
                        if result["status"] != "ADMITTED":
                            failure = result["reason"]
                    if failure is None:
                        failure = self._pending(db, action, session, require_stage=False)
                    self._assert_identity()
            if failure:
                raise ControlError(failure)
            # begin_stage owns another short writer transaction. If it fails,
            # the already consumed action reservation remains permanent.
            with self.authority._connect() as db:
                stage = db.execute("SELECT * FROM brakes_stages WHERE action_id=? AND stage_id=?",
                                   (action["action_id"], ORIENTATION_STAGE)).fetchone()
            if stage is None:
                result = self.authority.begin_stage(action["action_id"], stage_id=ORIENTATION_STAGE)
                if result["status"] != "ADMITTED":
                    raise ControlError(result["reason"])
            self.check(action)

    def check(self, proposed: Any) -> None:
        action = self._action(proposed)
        with self._lock:
            self._assert_identity()
            with self.authority._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                session, failure = self.authority._fresh(db, action["root_id"])
                if failure is None:
                    self._bound_profiles(db, session)
                    failure = self._pending(db, action, session, require_stage=True)
                    self._assert_identity()
            if failure:
                raise ControlError(failure)


class OrientationFencedEffectGateway(ReceiverFencedEffectGateway):
    """Receiver-fenced profile with an additional required local admission veto."""

    def __init__(self, *args, orientation_guard: Any = None, run_binding: Any, **kwargs):
        if type(orientation_guard) is not OrientationAdmissionGuard:
            raise ControlError("AGENT_ORIENTATION_GUARD_REQUIRED")
        names = ("admit", "check", "assert_bound", "configuration")
        routes = {name: _identity(getattr(orientation_guard, name, None)) for name in names}
        if any(expected != (orientation_guard, getattr(OrientationAdmissionGuard, name))
               for name, expected in routes.items()):
            raise ControlError("AGENT_ORIENTATION_GUARD_ROUTE_CHANGED")
        binding = validate_run_binding(run_binding)
        orientation_guard.assert_bound()
        if canonical_bytes(orientation_guard.run_binding) != canonical_bytes(binding):
            raise ControlError("AGENT_ORIENTATION_BINDING_MISMATCH")
        self.orientation_guard = self._bound_orientation_guard = orientation_guard
        self._orientation_routes = routes
        self._orientation_contract_bytes = canonical_bytes(orientation_guard.configuration())
        super().__init__(*args, run_binding=binding, **kwargs)

    def _configuration(self) -> str:
        configuration = json.loads(super()._configuration())
        # Persist the contract, not live guard health: safe query/reconcile is
        # still available after STOP or loss of local orientation admission.
        configuration["orientation_gate"] = json.loads(self._orientation_contract_bytes)
        return canonical_bytes(configuration).decode()

    def _assert_gate_ready(self) -> None:
        super()._assert_gate_ready()
        guard = self.orientation_guard
        if guard is not self._bound_orientation_guard or type(guard) is not OrientationAdmissionGuard:
            raise ControlError("AGENT_ORIENTATION_GUARD_IMMUTABLE")
        if any(_identity(getattr(guard, name, None)) != expected
               for name, expected in self._orientation_routes.items()):
            raise ControlError("AGENT_ORIENTATION_GUARD_ROUTE_CHANGED")
        guard.assert_bound()
        # Sidecar storage can wait behind a writer after the first gate check.
        # Recheck the base gate directly, without another sidecar transaction.
        ClosedChannelEffectGateway._assert_gate_ready(self)

    def _before_authority_begin(self, action: dict) -> None:
        self.orientation_guard.admit(action)
        ClosedChannelEffectGateway._assert_gate_ready(self)

    def _before_endpoint_commit(self, action: dict, authorization: dict, reservation_id: str, permit_pair: dict) -> None:
        super()._before_endpoint_commit(action, authorization, reservation_id, permit_pair)
        try:
            self.orientation_guard.check(action)
            ClosedChannelEffectGateway._assert_gate_ready(self)
        except BaseException as error:
            reason = _reason(error)
            self._close_admission()
            try:
                self._dispatch_event(action, reservation_id, permit_pair, "BLOCKED", reason)
            except BaseException:
                pass
            raise ControlError(reason) from error
