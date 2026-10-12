"""Advisory per-agent view of host-collected orientation; never permission.

The host supplies the snapshot and fresh authority status. Admission rechecks
everything transactionally; a cached view cannot authorize its candidate edges.
"""
from __future__ import annotations

import math
from typing import Any

from .authority import digest


def _finite_time(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _center_context(snapshot: dict, continuity: dict, state: dict, now: float) -> tuple[Any, bool, str | None]:
    """Recompute moving-frame advice at authority time, without issuing a grant."""
    try:
        profile = continuity["profile"]
        if not isinstance(profile, dict):
            return None, False, "CENTER_CONTEXT_REQUIRED"
        bindings = ("root_id", "epoch", "policy_digest", "objective_digest")
        if (any(continuity.get(key) != snapshot.get(key) or type(continuity.get(key)) is not type(snapshot.get(key)) for key in bindings)
                or continuity.get("orientation_profile_digest") != snapshot.get("profile_digest")
                or continuity.get("profile_digest") != digest(profile)
                or (snapshot.get("center_profile_digest") is not None
                    and continuity.get("profile_digest") != snapshot["center_profile_digest"])):
            return None, False, "CENTER_CONTEXT_BINDING_MISMATCH"
        if not isinstance(continuity["states"], list) or any(not isinstance(s, dict) for s in continuity["states"]):
            return None, False, "CENTER_CONTEXT_INVALID"
        center_state = next((s for s in continuity["states"] if s.get("execution_id") == state["execution_id"]), None)
        if (center_state is None or center_state.get("root_id") != snapshot["root_id"]
                or any(center_state.get(key) != state.get(key) for key in ("node_id", "revision", "pending_action_id"))
                or center_state.get("last_observed_at") != state.get("observed_at")):
            return None, False, "CENTER_CONTEXT_BINDING_MISMATCH"
        if (not _finite_time(continuity.get("snapshot_at")) or continuity["snapshot_at"] > now
                or not _finite_time(center_state["last_progress_at"]) or center_state["last_progress_at"] > now
                or (center_state["away_since"] is not None
                    and (not _finite_time(center_state["away_since"]) or center_state["away_since"] > now))):
            return None, False, "CLOCK_UNSAFE"
        diagnosis = center_state.get("diagnosis")
        if center_state.get("hold_reason"):
            return None, False, center_state["hold_reason"]
        if diagnosis not in {"READY_FOR_RECHECK", "CENTER_REORIENTATION_REQUIRED", "CENTER_RETURN_REQUIRED",
                             "CENTER_STAGNATION_HOLD"}:
            return None, False, diagnosis or "CENTER_CONTEXT_INVALID"
        if now - center_state["last_observed_at"] > profile["max_past_age_seconds"]:
            return None, False, "CENTER_PAST_STALE"
        window = next((w for w in profile["windows"] if w["starts_at"] <= now < w["ends_at"]), None)
        if window is None:
            return None, False, "CENTER_WINDOW_CLOSED"
        centers = window["center_nodes"]
        if not centers or not set(centers) <= set(snapshot["profile"]["center_nodes"]):
            return None, False, "CENTER_CONTEXT_BINDING_MISMATCH"
        needs_reorientation = center_state["checkpoint_center_id"] != window["center_id"]
        outside = state["node_id"] not in centers or needs_reorientation
        idle = now - center_state["last_progress_at"] >= profile["max_idle_seconds"]
        if idle and not outside:
            return None, False, "CENTER_STAGNATION_HOLD"
        away_since = center_state["away_since"]
        if away_since is None and needs_reorientation:
            away_since = window["starts_at"]
        elif away_since is None and outside:
            away_since = center_state["last_observed_at"]
        return_only = (needs_reorientation or idle
                       or (away_since is not None and now - away_since >= profile["max_away_seconds"]))
        return window, return_only, None
    except (KeyError, TypeError, ValueError):
        return None, False, "CENTER_CONTEXT_INVALID"


def guidance(snapshot: dict, authority_status: dict, execution_id: str, *,
             continuity_snapshot: dict | None = None) -> dict[str, Any]:
    result = {"execution_id": execution_id, "execution_authorized": False,
              "downstream_gates_required": True, "disposition": "HOLD",
              "reason": "ORIENTATION_UNAVAILABLE", "candidates": []}
    profile = snapshot.get("profile")
    state = next((s for s in snapshot.get("executions", []) if s["execution_id"] == execution_id), None)
    if not profile or state is None:
        return result
    if (authority_status.get("status") != "ACTIVE" or authority_status.get("root_id") != snapshot.get("root_id")
            or authority_status.get("epoch") != snapshot.get("epoch")
            or authority_status.get("policy_digest") != snapshot.get("policy_digest")
            or authority_status.get("objective_digest") != snapshot.get("objective_digest")):
        return {**result, "reason": "AUTHORITY_NOT_CURRENT"}
    if state.get("root_id") != snapshot.get("root_id"):
        return {**result, "reason": "ORIENTATION_STATE_BINDING_MISMATCH"}
    result.update(node_id=state["node_id"], revision=state["revision"],
                  observed_at=state["observed_at"], profile_digest=snapshot["profile_digest"])
    if state["hold_reason"] or state.get("observer_hold_reason") or state["pending_action_id"]:
        return {**result, "reason": state["hold_reason"] or state.get("observer_hold_reason") or "OBSERVATION_REQUIRED"}
    now = authority_status["last_now"]
    if not _finite_time(now) or not _finite_time(state["observed_at"]):
        return {**result, "reason": "CLOCK_UNSAFE"}
    if now < state["observed_at"] or now - state["observed_at"] > profile["max_observation_age_seconds"]:
        return {**result, "reason": "OBSERVATION_STALE"}
    if authority_status["remaining_actions"] <= 0 or state["steps"] >= profile["max_steps"]:
        return {**result, "reason": "BUDGET_EXHAUSTED"}
    centers, return_only, needs_reorientation = profile["center_nodes"], False, False
    if snapshot.get("requires_center_context") and continuity_snapshot is None:
        return {**result, "reason": "CENTER_CONTEXT_REQUIRED"}
    if continuity_snapshot is not None:
        window, return_only, reason = _center_context(snapshot, continuity_snapshot, state, now)
        if reason:
            return {**result, "reason": reason}
        centers = window["center_nodes"]
        result["active_center_id"] = window["center_id"]
        temporal_state = next(s for s in continuity_snapshot["states"] if s["execution_id"] == execution_id)
        needs_reorientation = temporal_state["checkpoint_center_id"] != window["center_id"]
    for edge in profile["edges"]:
        center = edge["destination"] in centers
        if (edge["source"] != state["node_id"]
                or (return_only and not center)
                or state["visits"].get(edge["destination"], 0) >= profile["max_visits"]
                or (not center and state["away_steps"] >= profile["max_away_steps"])):
            continue
        result["candidates"].append({**edge, "returns_to_center": center})
    if not result["candidates"]:
        return {**result, "reason": "NO_BOUNDED_TRANSITION"}
    result["candidates"].sort(key=lambda edge: (not edge["returns_to_center"], edge["edge_id"]))
    result["disposition"] = ("RETURN_CANDIDATE" if (state["node_id"] not in centers or needs_reorientation)
                             and any(e["returns_to_center"] for e in result["candidates"]) else "TRANSITION_CANDIDATE")
    result["reason"] = "HOST_GRANT_AND_FRESH_ADMISSION_STILL_REQUIRED"
    return result
