"""Advisory per-agent view of host-collected orientation; never permission.

The host supplies the snapshot and fresh authority status. Admission rechecks
everything transactionally; a cached view cannot authorize its candidate edges.
"""
from __future__ import annotations

from typing import Any


def guidance(snapshot: dict, authority_status: dict, execution_id: str) -> dict[str, Any]:
    result = {"execution_id": execution_id, "execution_authorized": False,
              "downstream_gates_required": True, "disposition": "HOLD",
              "reason": "ORIENTATION_UNAVAILABLE", "candidates": []}
    profile = snapshot.get("profile")
    state = next((s for s in snapshot.get("executions", []) if s["execution_id"] == execution_id), None)
    if not profile or state is None:
        return result
    result.update(node_id=state["node_id"], revision=state["revision"],
                  observed_at=state["observed_at"], profile_digest=snapshot["profile_digest"])
    if (authority_status.get("status") != "ACTIVE" or authority_status.get("root_id") != snapshot.get("root_id")
            or authority_status.get("epoch") != snapshot.get("epoch")
            or authority_status.get("policy_digest") != snapshot.get("policy_digest")
            or authority_status.get("objective_digest") != snapshot.get("objective_digest")):
        return {**result, "reason": "AUTHORITY_NOT_CURRENT"}
    if state["hold_reason"] or state["pending_action_id"]:
        return {**result, "reason": state["hold_reason"] or "OBSERVATION_REQUIRED"}
    now = authority_status["last_now"]
    if now < state["observed_at"] or now - state["observed_at"] > profile["max_observation_age_seconds"]:
        return {**result, "reason": "OBSERVATION_STALE"}
    if authority_status["remaining_actions"] <= 0 or state["steps"] >= profile["max_steps"]:
        return {**result, "reason": "BUDGET_EXHAUSTED"}
    for edge in profile["edges"]:
        center = edge["destination"] in profile["center_nodes"]
        if (edge["source"] != state["node_id"]
                or state["visits"].get(edge["destination"], 0) >= profile["max_visits"]
                or (not center and state["away_steps"] >= profile["max_away_steps"])):
            continue
        result["candidates"].append({**edge, "returns_to_center": center})
    if not result["candidates"]:
        return {**result, "reason": "NO_BOUNDED_TRANSITION"}
    result["candidates"].sort(key=lambda edge: (not edge["returns_to_center"], edge["edge_id"]))
    result["disposition"] = ("RETURN_CANDIDATE" if state["node_id"] not in profile["center_nodes"]
                             and any(e["returns_to_center"] for e in result["candidates"]) else "TRANSITION_CANDIDATE")
    result["reason"] = "HOST_GRANT_AND_FRESH_ADMISSION_STILL_REQUIRED"
    return result
