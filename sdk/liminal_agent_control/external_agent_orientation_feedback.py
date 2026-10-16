"""Signed receiver facts for a separate observation-enabled G03 profile.

A valid owned receiver COMMITTED receipt can complete the corresponding local
stage/action and record a trajectory observation in one authority transaction.
Receipt ingestion never issues a permit, retries a POST, settles NO_EFFECT, or
reopens a stopped/expired authority. The observation timestamp is trusted local
ingestion time; the receiver's signed terminal_at remains a separate clock.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from . import center_continuity, orientation
from .authority import ControlError, canonical_bytes, digest, validate_id
from .brakes_store import SessionAuthority
from .external_agent_coordinator import ExternalAgentCoordinator
from .external_agent_effect_gateway import _copy, _identity
from .external_agent_bridge import _RESULT_FIELDS
from .external_agent_orientation import (
    ORIENTATION_STAGE, OrientationAdmissionGuard, OrientationFencedEffectGateway,
)
from .external_agent_receiver_protocol import bind_receipt
from .external_agent_receiver_bridge import ReceiverFencedAgentBridge

FEEDBACK_SCHEMA = "liminal-agent-orientation-feedback-v1"
FEEDBACK_CONTRACT_SCHEMA = "liminal-agent-orientation-feedback-contract-v1"


def _feedback(action_id: Any, status: str, reason: str, receipt_digest: str | None = None,
              observation_digest: str | None = None) -> dict:
    return {"schema": FEEDBACK_SCHEMA, "status": status, "reason": reason,
            "action_id": action_id, "receipt_digest": receipt_digest,
            "observation_digest": observation_digest, "execution_authorized": False}


class ReceiptOrientationObserver:
    """Host-owned ingestion of one exact signed receiver fact; no network calls."""

    _GUARD_METHODS = ("_assert_identity", "_database_identity", "_profile_binding", "_action",
                      "assert_bound", "configuration")
    _AUTHORITY_METHODS = ("_connect", "_now", "_require_transaction",
                          "finish_action_in_transaction", "finish_stage_in_transaction")

    def __init__(self, orientation_guard: OrientationAdmissionGuard) -> None:
        if type(orientation_guard) is not OrientationAdmissionGuard:
            raise ControlError("AGENT_ORIENTATION_GUARD_REQUIRED")
        self.orientation_guard = self._bound_guard = orientation_guard
        self._guard_routes = {name: _identity(getattr(orientation_guard, name, None))
                              for name in self._GUARD_METHODS}
        if any(route != (orientation_guard, getattr(OrientationAdmissionGuard, name))
               for name, route in self._guard_routes.items()):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ROUTE_CHANGED")
        orientation_guard.assert_bound()
        self._authority = orientation_guard.authority
        self._authority_path = Path(self._authority.db_path).absolute()
        self._path_identity = orientation_guard._path_identity
        self._authority_clock = self._authority.clock
        self._guard_lock = orientation_guard._lock
        self._feedback_order_lock = threading.RLock()
        self._run_close_reason: str | None = None
        self._authority_routes = {name: _identity(getattr(self._authority, name, None))
                                  for name in self._AUTHORITY_METHODS}
        if any(route != (self._authority, getattr(SessionAuthority, name))
               for name, route in self._authority_routes.items()):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ROUTE_CHANGED")
        self._run_bytes = canonical_bytes(orientation_guard.run_binding)
        self._profile_bytes = orientation_guard._profile_binding_bytes
        body = {"schema": FEEDBACK_CONTRACT_SCHEMA, "required": True,
                "run_binding_digest": digest(self._run), "endpoint_pin": _copy(self._pin),
                "orientation_contract_digest": orientation_guard.configuration()["contract_digest"],
                "receipt": "SIGNED_EXACT_COMMITTED_ONLY", "stage_id": ORIENTATION_STAGE,
                "local_completion": "ONE_AUTHORITY_TRANSACTION",
                "observation_time": "TRUSTED_LOCAL_RECEIPT_INGESTION",
                "closed_authority": "HISTORICAL_FACT_WITHOUT_REOPENING",
                "run_closure": "EXACT_OBSERVED_COORDINATOR_SHARED_LOCAL_LOCK",
                "failure": "REMOTE_TRUTH_PRESERVED_QUERY_ONLY",
                "execution_authorized": False}
        self._configuration_bytes = canonical_bytes({**body, "contract_digest": digest(body)})

    @property
    def _run(self) -> dict:
        return json.loads(self._run_bytes)

    @property
    def _profiles(self) -> dict:
        return json.loads(self._profile_bytes)

    @property
    def _pin(self) -> dict:
        # Never verify against a caller-mutable cached dictionary. Each packet
        # uses the endpoint signer frozen into this profile's immutable bytes.
        return self._run["endpoint_pin"]

    def configuration(self) -> dict:
        """Frozen descriptor: safe recovery never depends on live guard health."""
        return json.loads(self._configuration_bytes)

    def _mark_run_closed(self, reason: str) -> None:
        """Local-only sticky boundary, serialized with feedback transactions.

        This does not access a store or make an RPC. An observation already
        holding the lock linearizes first; subsequent ingestion is historical.
        """
        validate_id(reason, "run closure reason")
        with self._feedback_order_lock:
            if self._run_close_reason is None:
                self._run_close_reason = reason

    def _persist_run_closed(self) -> None:
        with self._feedback_order_lock:
            self._assert_identity()
            if self._run_close_reason is None:
                raise ControlError("AGENT_ORIENTATION_RUN_CLOSURE_REQUIRED")
            with self._authority._connect() as db:
                db.execute("PRAGMA busy_timeout=0")
                db.execute("BEGIN IMMEDIATE")
                self._authority._require_transaction(db)
                session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?",
                                     (self._run["effect"]["root_id"],)).fetchone()
                root = db.execute("SELECT * FROM roots WHERE root_id=?",
                                  (self._run["effect"]["root_id"],)).fetchone()
                if (session is None or root is None or root["epoch"] < self._run["effect"]["epoch"]
                        or session["state"] not in {"ACTIVE", "STOPPED", "EXPIRED", "CLOCK_UNSAFE"}
                        or session["policy_digest"] != self._profiles["policy_digest"]
                        or session["objective_digest"] != self._profiles["objective_digest"]):
                    raise ControlError("AGENT_ORIENTATION_FEEDBACK_SESSION_MISSING")
                SessionAuthority._close(db, session, "STOPPED", "AGENT_RUN_CLOSED")
                self._assert_identity()

    def _assert_identity(self) -> None:
        guard = self.orientation_guard
        if guard is not self._bound_guard or type(guard) is not OrientationAdmissionGuard:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_GUARD_CHANGED")
        if any(_identity(getattr(guard, name, None)) != route for name, route in self._guard_routes.items()):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ROUTE_CHANGED")
        if (guard.authority is not self._authority
                or Path(self._authority.db_path).absolute() != self._authority_path
                or guard._path != self._authority_path or guard._path_identity != self._path_identity
                or self._authority.clock is not self._authority_clock or guard._lock is not self._guard_lock
                or canonical_bytes(guard.run_binding) != self._run_bytes
                or guard._profile_binding_bytes != self._profile_bytes):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_BINDING_CHANGED")
        if any(_identity(getattr(self._authority, name, None)) != route
               for name, route in self._authority_routes.items()):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ROUTE_CHANGED")
        guard._assert_identity()

    def _historical_profiles(self, db: Any) -> Any:
        """Check the frozen admitted lineage, allowing only closure to be old.

        Admission's _profile_binding deliberately rejects revoked roots. This
        observation-only check permits the original epoch's historical fact;
        it never clears revocation, closure, epoch, clock state or a hold.
        """
        part = self._run["effect"]
        session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (part["root_id"],)).fetchone()
        root = db.execute("SELECT * FROM roots WHERE root_id=?", (part["root_id"],)).fetchone()
        execution = db.execute("SELECT * FROM brakes_executions WHERE execution_id=?",
                               (part["execution_id"],)).fetchone()
        base_execution = db.execute("SELECT * FROM executions WHERE execution_id=?",
                                    (part["execution_id"],)).fetchone()
        if (session is None or root is None or root["epoch"] < part["epoch"]
                or session["policy_digest"] != self._profiles["policy_digest"]
                or session["objective_digest"] != self._profiles["objective_digest"]
                or execution is None or base_execution is None
                or any(row["root_id"] != part["root_id"] or row["epoch"] != part["epoch"]
                       for row in (execution, base_execution))
                or execution["parent_execution_id"] != base_execution["parent_execution_id"]
                or execution["parent_execution_id"] != self._profiles["execution_parent"]
                or execution["depth"] != self._profiles["execution_depth"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROFILE_MISMATCH")
        orient = db.execute("SELECT * FROM orientation_profiles WHERE root_id=?", (part["root_id"],)).fetchone()
        center = db.execute("SELECT * FROM center_profiles WHERE root_id=?", (part["root_id"],)).fetchone()
        if orient is None or center is None:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROFILE_MISSING")
        profile = orientation._profile(json.loads(orient["profile_json"]))
        center_profile = center_continuity._profile(json.loads(center["profile_json"]), profile)
        if (any(row["epoch"] != part["epoch"] or row["policy_digest"] != self._profiles["policy_digest"]
                or row["objective_digest"] != self._profiles["objective_digest"] for row in (orient, center))
                or digest(profile) != orient["profile_digest"]
                or digest(center_profile) != center["profile_digest"]
                or orient["profile_digest"] != self._profiles["orientation_profile_digest"]
                or center["profile_digest"] != self._profiles["center_profile_digest"]
                or center["orientation_profile_digest"] != orient["profile_digest"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROFILE_MISMATCH")
        return session, profile

    def _admitted(self, db: Any, action: dict) -> Any:
        aid = action["action_id"]
        rows = db.execute("SELECT * FROM brakes_actions WHERE action_id=? OR attempt_id=?",
                          (aid, action["attempt_id"])).fetchall()
        if (len(rows) != 1 or any(rows[0][key] != action[key]
                                 for key in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                or rows[0]["action_digest"] != digest(action) or rows[0]["payload_digest"] != digest(action)
                or rows[0]["channel"] != "egress" or rows[0]["policy_digest"] != self._profiles["policy_digest"]
                or rows[0]["status"] not in {"RESERVED", "RETURNED", "UNKNOWN"}):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ACTION_MISMATCH")
        ticket = db.execute("SELECT * FROM orientation_tickets WHERE action_id=?", (aid,)).fetchone()
        occurrence = db.execute("SELECT * FROM orientation_occurrences WHERE action_id=?", (aid,)).fetchone()
        stage = db.execute("SELECT * FROM brakes_stages WHERE action_id=? AND stage_id=?",
                           (aid, ORIENTATION_STAGE)).fetchone()
        if (ticket is None or occurrence is None or stage is None
                or ticket["status"] != "RESERVED"
                or any(ticket[key] != action[key] or occurrence[key] != action[key]
                       for key in ("action_id", "root_id", "execution_id", "epoch"))
                or ticket["attempt_id"] != action["attempt_id"]
                or ticket["action_digest"] != digest(action) or occurrence["action_digest"] != digest(action)
                or ticket["profile_digest"] != self._profiles["orientation_profile_digest"]
                or occurrence["channel"] != "egress" or occurrence["edge_id"] != ticket["edge_id"]
                or occurrence["revision"] != ticket["expected_revision"] + 1
                or stage["status"] not in {"RESERVED", "RETURNED", "UNKNOWN"}):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ADMISSION_MISMATCH")
        projection = db.execute("SELECT * FROM center_projections WHERE action_id=?", (aid,)).fetchone()
        if projection is None:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROJECTION_MISSING")
        item = json.loads(projection["projection_json"])
        if (projection["status"] != "CONSUMED" or projection["action_digest"] != digest(action)
                or any(projection[key] != action[key] or item.get(key) != action[key]
                       for key in ("action_id", "root_id", "execution_id", "epoch"))
                or item.get("action_digest") != digest(action)
                or item.get("edge_id") != ticket["edge_id"]
                or item.get("expected_revision") != ticket["expected_revision"]
                or item.get("profile_digest") != self._profiles["center_profile_digest"]
                or item.get("orientation_profile_digest") != self._profiles["orientation_profile_digest"]
                or digest(item) != projection["projection_digest"]
                or item.get("predecessor_hash") != projection["predecessor_hash"]
                or item.get("center_id") != projection["center_id"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROJECTION_MISMATCH")
        idea = db.execute("SELECT * FROM center_ideas WHERE execution_id=? AND idea_id=?",
                          (action["execution_id"], item.get("idea_id"))).fetchone()
        if (idea is None or idea["root_id"] != action["root_id"]
                or idea["predecessor_hash"] != projection["predecessor_hash"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_IDEA_MISMATCH")
        orientation._hash(idea["content_digest"])
        events = [json.loads(row[0]) for row in db.execute(
            "SELECT event_json FROM center_events WHERE execution_id=? ORDER BY sequence",
            (action["execution_id"],))]
        admitted = [event for event in events if event["kind"] == "ADMITTED"
                    and event["details"].get("action_id") == aid]
        expected = {"action_id": aid, "action_digest": digest(action), "edge_id": ticket["edge_id"],
                    "projection_digest": projection["projection_digest"]}
        if (len(admitted) != 1 or admitted[0]["details"] != expected
                or admitted[0]["parent_hash"] != projection["predecessor_hash"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_PROJECTION_MISMATCH")
        return rows[0], stage, occurrence

    def _already_confirmed(self, db: Any, action: dict, occurrence: Any,
                           receipt_digest: str, profile: dict) -> str | None:
        if occurrence["status"] != "CONFIRMED":
            return None
        row = db.execute("SELECT * FROM orientation_observations WHERE observation_digest=?",
                         (occurrence["observation_digest"],)).fetchone()
        if row is None:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_OBSERVATION_MISMATCH")
        observation = json.loads(row["observation_json"])
        fields = {"action_id", "action_digest", "root_id", "execution_id", "epoch", "profile_digest",
                  "observed_at", "evidence_digest", "observer_id", "outcome"}
        if (type(observation) is not dict or set(observation) != fields
                or any(type(observation[key]) is not type(action[key]) or observation[key] != action[key]
                       for key in ("action_id", "root_id", "execution_id", "epoch"))
                or observation["action_digest"] != digest(action)
                or observation["profile_digest"] != self._profiles["orientation_profile_digest"]
                or observation["outcome"] != "CONFIRMED" or observation["evidence_digest"] != receipt_digest
                or observation["observer_id"] != profile["observers"]["egress"]
                or digest(observation) != row["observation_digest"] or row["action_id"] != action["action_id"]
                or occurrence["evidence_digest"] != receipt_digest
                or occurrence["observer_id"] != observation["observer_id"]
                or occurrence["observed_at"] != observation["observed_at"]):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_OBSERVATION_MISMATCH")
        orientation._time(observation["observed_at"])
        return row["observation_digest"]

    def observe_committed(self, action: Any, authorization: Any, reservation_id: Any, receipt: Any) -> dict:
        self._assert_identity()
        action = self._bound_guard._action(action)
        validate_id(reservation_id, "reservation_id")
        receipt = bind_receipt(receipt, self._pin, action, authorization, reservation_id)
        receipt_digest = digest(receipt)
        if receipt["status"] != "COMMITTED":
            return _feedback(action["action_id"], "NOT_CONFIRMED", "SIGNED_COMMITTED_RECEIPT_REQUIRED", receipt_digest)
        with self._guard_lock:
            self._assert_identity()
            with self._authority._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                with self._feedback_order_lock:
                    self._authority._require_transaction(db)
                    session, profile = self._historical_profiles(db)
                    if self._run_close_reason is not None:
                        SessionAuthority._close(db, session, "STOPPED", "AGENT_RUN_CLOSED")
                    local_action, stage, occurrence = self._admitted(db, action)
                    duplicate = self._already_confirmed(db, action, occurrence, receipt_digest, profile)
                    if duplicate is not None:
                        if local_action["status"] == "RESERVED" or stage["status"] == "RESERVED":
                            raise ControlError("AGENT_ORIENTATION_FEEDBACK_COMPLETION_MISMATCH")
                        self._assert_identity()
                        db.commit()
                        return _feedback(action["action_id"], "ALREADY_CONFIRMED", "SIGNED_RECEIPT_ALREADY_OBSERVED",
                                         receipt_digest, duplicate)
                    try:
                        now = self._authority._now()
                        if now < session["last_now"]:
                            raise ControlError("clock rollback")
                    except ControlError as error:
                        # Clock failure is terminal control state, not part of an
                        # attempted effect observation. Persist it before raising;
                        # no stage/action/observation mutation has occurred yet.
                        SessionAuthority._close(db, session, "CLOCK_UNSAFE", "CLOCK_UNSAFE")
                        db.commit()
                        raise ControlError("AGENT_ORIENTATION_FEEDBACK_CLOCK_UNSAFE") from error
                    db.execute("UPDATE brakes_sessions SET last_now=? WHERE root_id=?", (now, action["root_id"]))
                    if stage["status"] == "RESERVED":
                        self._authority.finish_stage_in_transaction(db, action["action_id"], ORIENTATION_STAGE,
                                                                    outcome="RETURNED")
                    if local_action["status"] == "RESERVED":
                        self._authority.finish_action_in_transaction(db, action["action_id"], outcome="RETURNED")
                    observation = {key: action[key]
                                   for key in ("action_id", "root_id", "execution_id", "epoch")}
                    observation.update(action_digest=digest(action), profile_digest=self._profiles["orientation_profile_digest"],
                        observed_at=now, evidence_digest=receipt_digest,
                        observer_id=profile["observers"]["egress"], outcome="CONFIRMED")
                    result = orientation._observe(db, action["action_id"], observation, now=now)
                    self._assert_identity()
                    db.commit()
                    return _feedback(action["action_id"], "CONFIRMED", "SIGNED_RECEIPT_OBSERVED",
                                     receipt_digest, result["observation_digest"])


class ObservedOrientationFencedEffectGateway(OrientationFencedEffectGateway):
    """Separate profile: receiver truth plus atomic local trajectory feedback."""

    def __init__(self, *args, orientation_guard: Any = None, **kwargs):
        observer = ReceiptOrientationObserver(orientation_guard)
        self.orientation_observer = self._bound_orientation_observer = observer
        self._observer_routes = {name: _identity(getattr(observer, name))
                                 for name in ("observe_committed", "configuration")}
        self._feedback_contract_bytes = canonical_bytes(observer.configuration())
        super().__init__(*args, orientation_guard=orientation_guard, **kwargs)

    def _configuration(self) -> str:
        configuration = json.loads(super()._configuration())
        configuration["orientation_feedback"] = json.loads(self._feedback_contract_bytes)
        return canonical_bytes(configuration).decode()

    def _assert_observer_route(self) -> ReceiptOrientationObserver:
        observer = self.orientation_observer
        if observer is not self._bound_orientation_observer or type(observer) is not ReceiptOrientationObserver:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_OBSERVER_CHANGED")
        if any(_identity(getattr(observer, name, None)) != route for name, route in self._observer_routes.items()):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_ROUTE_CHANGED")
        if (getattr(self, "orientation_guard", None) is not observer._bound_guard
                or canonical_bytes(observer.configuration()) != self._feedback_contract_bytes):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_BINDING_CHANGED")
        return observer

    def _assert_gate_ready(self) -> None:
        observer = self._assert_observer_route()
        with observer._feedback_order_lock:
            if observer._run_close_reason is not None:
                raise ControlError("AGENT_ORIENTATION_RUN_CLOSED")
        self._assert_feedback_coordinator(self._bound_coordinator)
        super()._assert_gate_ready()

    def _assert_feedback_coordinator(self, coordinator: Any) -> None:
        if (type(coordinator) is not ObservedOrientationCoordinator
                or coordinator.effect_gateway is not self
                or coordinator._orientation_observer is not self._bound_orientation_observer):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_COORDINATOR_REQUIRED")

    def bind_launch_gate(self, gate: Any) -> None:
        with self._bound_orientation_observer._feedback_order_lock:
            if self._bound_orientation_observer._run_close_reason is not None:
                raise ControlError("AGENT_ORIENTATION_RUN_CLOSED")
        self._assert_feedback_coordinator(getattr(gate, "_coordinator", None))
        super().bind_launch_gate(gate)

    def _with_feedback(self, result: dict) -> dict:
        result = _copy(result)
        aid = result.get("action_id")
        receipt = result.get("receipt")
        if type(receipt) is not dict or receipt.get("status") != "COMMITTED":
            result["orientation_feedback"] = _feedback(aid, "NOT_CONFIRMED", "SIGNED_COMMITTED_RECEIPT_REQUIRED")
            return result
        try:
            observer = self._assert_observer_route()
            granted = self._grant(aid)
            with self._connection() as db:
                row = db.execute("SELECT * FROM network_gateway_grants WHERE action_id=?", (aid,)).fetchone()
            if (granted is None or row is None or row["reservation_id"] is None
                    or result.get("reservation_id") != row["reservation_id"]
                    or row["action_id"] != granted[0]["action_id"]
                    or row["attempt_id"] != granted[0]["attempt_id"]
                    or row["action_digest"] != digest(granted[0])
                    or row["authorization_digest"] != digest(granted[1])
                    or canonical_bytes(json.loads(row["action_json"])) != canonical_bytes(granted[0])
                    or canonical_bytes(json.loads(row["authorization_json"])) != canonical_bytes(granted[1])):
                raise ControlError("AGENT_ORIENTATION_FEEDBACK_RESERVATION_MISMATCH")
            coordinator = self._bound_coordinator
            if coordinator is None:
                observer._mark_run_closed("UNBOUND_RECOVERY")
            else:
                self._assert_feedback_coordinator(coordinator)
                state = coordinator.fence_state()
                if state.get("closed") is not False:
                    observer._mark_run_closed("COORDINATOR_ADMISSION_CLOSED")
            result["orientation_feedback"] = observer.observe_committed(
                granted[0], granted[1], row["reservation_id"], receipt)
        except BaseException:
            # Local failure never rewrites signed remote truth or asks for a
            # new permit/POST. Recovery may query and retry only this ingestion.
            result["orientation_feedback"] = _feedback(aid, "UNAVAILABLE", "LOCAL_ORIENTATION_FEEDBACK_UNAVAILABLE")
        return result

    def execute(self, proposed: Any) -> dict:
        with self._lock:
            return self._with_feedback(super().execute(proposed))

    def reconcile(self, action_id: str) -> dict:
        with self._lock:
            return self._with_feedback(super().reconcile(action_id))


class ObservedOrientationAgentBridge(ReceiverFencedAgentBridge):
    """The bounded receiver bridge with explicit non-authoritative feedback."""

    def __init__(self, **arguments):
        super().__init__(**arguments)
        contract = self.configuration().get("effect_gateway_configuration", {}).get("orientation_feedback", {})
        if (contract.get("schema") != FEEDBACK_CONTRACT_SCHEMA or contract.get("required") is not True
                or contract.get("receipt") != "SIGNED_EXACT_COMMITTED_ONLY"
                or contract.get("execution_authorized") is not False):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_BRIDGE_REQUIRED")

    def _public_result(self, action: dict, result: Any) -> dict:
        result = _copy(result)
        if (type(result) is not dict or set(result) != _RESULT_FIELDS | {"orientation_feedback"}
                or len(canonical_bytes(result)) > self.budget.max_frame_bytes - 512):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_RESULT_INVALID")
        feedback = result["orientation_feedback"]
        fields = {"schema", "status", "reason", "action_id", "receipt_digest",
                  "observation_digest", "execution_authorized"}
        if (type(feedback) is not dict or set(feedback) != fields
                or feedback["schema"] != FEEDBACK_SCHEMA
                or feedback["status"] not in {"CONFIRMED", "ALREADY_CONFIRMED", "NOT_CONFIRMED", "FAILED", "UNAVAILABLE"}
                or feedback["action_id"] != action["action_id"]
                or feedback["execution_authorized"] is not False):
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_RESULT_INVALID")
        validate_id(feedback["reason"], "feedback reason")
        for name in ("receipt_digest", "observation_digest"):
            if feedback[name] is not None:
                orientation._hash(feedback[name])
        base = super()._public_result(action, {key: value for key, value in result.items()
                                              if key != "orientation_feedback"})
        if feedback["status"] in {"CONFIRMED", "ALREADY_CONFIRMED"}:
            receipt = base["receipt"]
            if (type(receipt) is not dict or receipt.get("status") != "COMMITTED"
                    or feedback["receipt_digest"] != digest(receipt) or feedback["observation_digest"] is None):
                raise ControlError("AGENT_ORIENTATION_FEEDBACK_RESULT_INVALID")
        return {**base, "orientation_feedback": feedback}


class ObservedOrientationCoordinator(ExternalAgentCoordinator):
    """Close the sidecar feedback trajectory with this separate owned run.

    A short local lock orders feedback against run closure after the feedback
    transaction already holds its writer lock. The databases
    are not one distributed transaction, and a missing sidecar never prevents
    the base coordinator's bridge, external STOP, or owned cleanup attempts.
    """

    def __init__(self, *args, effect_gateway: Any, **kwargs):
        if type(effect_gateway) is not ObservedOrientationFencedEffectGateway:
            raise ControlError("AGENT_ORIENTATION_FEEDBACK_GATEWAY_REQUIRED")
        self._orientation_observer = effect_gateway._assert_observer_route()
        self._orientation_closure = {"status": "NOT_CLOSED", "execution_authorized": False}
        super().__init__(*args, effect_gateway=effect_gateway, **kwargs)

    def _persist_orientation_closure(self) -> None:
        try:
            self._orientation_observer._persist_run_closed()
        except BaseException:
            self._orientation_closure = {"status": "UNAVAILABLE", "execution_authorized": False}
        else:
            self._orientation_closure = {"status": "CLOSED", "execution_authorized": False}

    def _close_local(self, reason: str) -> None:
        self._orientation_observer._mark_run_closed(reason)
        super()._close_local(reason)

    def _emergency_contain(self, reason: str, error: BaseException) -> dict:
        self._orientation_observer._mark_run_closed(reason)
        result = super()._emergency_contain(reason, error)
        return self._finalize_orientation_closure(result)

    def _reconcile_closed(self, failures: list[dict] | None = None) -> dict:
        return self._finalize_orientation_closure(super()._reconcile_closed(failures))

    def _finalize_orientation_closure(self, result: dict) -> dict:
        # Every independent base containment attempt has already happened.
        # This writer uses busy_timeout=0 and cannot delay those attempts.
        self._persist_orientation_closure()
        result["orientation_feedback_closure"] = _copy(self._orientation_closure)
        if self._orientation_closure["status"] != "CLOSED":
            result["status"] = "UNKNOWN"
        try:
            self._update(state="STOPPED" if result["status"] == "STOPPED" else "CLOSING", aggregate=result)
        except BaseException:
            # The base emergency path already records unavailable journaling.
            # This metadata cannot certify closure when it was not persisted.
            result["status"] = "UNKNOWN"
        return result
