"""Owned moving-center and observer-ring demonstration; no model or network."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import tempfile

from .authority import digest
from .brakes_store import SessionAuthority
from .broker import Broker
from .center_continuity import CenterContinuityStore
from .multi_agent import _source, _source_digests
from .observer_ring import ObserverRingStore
from .orientation import OrientationStore
from .receiver import Receiver


ROLES = ("reality", "continuity", "projection")


def _setup(work: Path, clock: list[float]) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    authority = SessionAuthority(work / "authority.sqlite", clock=lambda: clock[0])
    policy = digest("owned center continuity demonstration")
    authority.create_session("campaign", controller_id="operator", policy_digest=policy,
        objective_digest=digest("bounded work with time-bound checkpoints"),
        max_actions=10, max_executions=1, max_depth=1, max_stages=8,
        lifetime_seconds=200, lease_seconds=200)
    authority.bind_execution("campaign", "alpha")
    receiver = Receiver(authority.db_path, secrets.token_bytes(32), secrets.token_bytes(32),
                        admission_controller=authority)
    # Broker grant/receipt timestamps use wall time. Trajectory, deadlines and
    # observations use the explicitly controlled trusted authority clock.
    broker = Broker(work / "broker.sqlite", receiver)
    graph = OrientationStore(authority)
    graph.install("campaign", {
        "nodes": [{"node_id": name, "space_id": space, "phase": phase}
                  for name, space, phase in (("center-a", "control", "checkpoint_a"),
                      ("work", "owned_records", "record_observed"),
                      ("center-b", "control", "checkpoint_b"))],
        "edges": [{"edge_id": name, "source": source, "destination": destination,
                   "channel": "records"} for name, source, destination in (
            ("writea", "center-a", "work"), ("returna", "work", "center-a"),
            ("returnb", "work", "center-b"), ("writeb", "center-b", "work"))],
        "center_nodes": ["center-a", "center-b"], "max_steps": 8,
        "max_visits": 5, "max_away_steps": 3, "max_observation_age_seconds": 90,
        "observers": {"records": receiver.receiver_id, "egress": "unused-owned-sink"}})
    center = CenterContinuityStore(authority)
    center.install("campaign", {
        "windows": [
            {"center_id": "A", "previous_center_id": None, "starts_at": 100,
             "ends_at": 120, "center_nodes": ["center-a"]},
            {"center_id": "B", "previous_center_id": "A", "starts_at": 120,
             "ends_at": 200, "center_nodes": ["center-b"]}],
        "max_past_age_seconds": 90, "max_future_horizon_seconds": 30,
        "max_transition_seconds": 15, "max_away_seconds": 10,
        "max_idle_seconds": 20, "progress_edge_ids": ["writea", "writeb"],
        "max_ideas": 20})
    ring = ObserverRingStore(authority)
    ring.install("campaign", {
        "observers": [{"observer_id": role + "-observer", "role": role} for role in ROLES],
        "required_roles": list(ROLES), "max_attestation_age_seconds": 30,
        "max_attestations": 100})
    graph.seed("campaign", "alpha", "center-a", evidence_digest=digest("owned initial state"),
               observed_at=clock[0])
    return {"authority": authority, "receiver": receiver, "broker": broker,
            "graph": graph, "center": center, "ring": ring, "policy": policy}


def _action(name: str) -> dict:
    return {"root_id": "campaign", "execution_id": "alpha", "epoch": 1,
            "action_id": name, "attempt_id": "attempt:" + name, "target": "records",
            "arguments": {"owned_marker": name}}


def _project(env: dict, action: dict, edge: str, revision: int, now: float, deadline: float) -> dict:
    env["graph"].prepare(action, edge_id=edge, expected_revision=revision)
    predecessor = env["center"].snapshot("campaign")["states"][0]["head_hash"]
    idea_id = "idea:" + action["action_id"]
    env["center"].record_idea("campaign", "alpha", idea_id, digest({"idea": action}),
        expected_head_hash=predecessor)
    projection = env["center"].project(action, edge_id=edge, expected_revision=revision,
        predecessor_hash=predecessor, idea_id=idea_id, not_before=now, deadline=deadline)
    env["broker"].authorize(action, policy_version=env["policy"])
    return projection


def _support(env: dict, action: dict, now: float, deadline: float, roles=ROLES) -> None:
    for role in roles:
        env["ring"].attest(action["action_id"], observer_id=role + "-observer", verdict="SUPPORT",
            evidence_digest=digest({"fixture_role": role, "action_digest": digest(action)}),
            observed_at=now, valid_until=deadline)


def _veto_case(work: Path) -> dict:
    clock = [100.0]
    env = _setup(work, clock)
    action = _action("veto:write")
    _project(env, action, "writea", 0, clock[0], 110)
    _support(env, action, clock[0], 110)
    env["ring"].attest(action["action_id"], observer_id="reality-observer", verdict="VETO",
        evidence_digest=digest("owned contradictory evidence"), observed_at=clock[0], valid_until=110)
    result = env["broker"].dispatch(action)
    return {"result": result, "record_count": len(env["receiver"].records()),
            "action_count": env["authority"].status("campaign")["action_count"],
            "ring": env["ring"].snapshot("campaign"),
            "continuity": env["center"].snapshot("campaign")}


def run_demo() -> dict:
    frames, outcomes = [], {}
    clock = [100.0]
    with tempfile.TemporaryDirectory(prefix="liminal-center-") as temporary:
        work = Path(temporary)
        env = _setup(work / "main", clock)

        def capture(label: str) -> dict:
            # Status evaluates the trusted clock before other read-only views.
            authority = env["authority"].status("campaign")
            frame = {"label": label, "now": clock[0], "graph": env["graph"].snapshot("campaign"),
                     "continuity": env["center"].snapshot("campaign"),
                     "ring": env["ring"].snapshot("campaign"), "authority": authority,
                     "record_count": len(env["receiver"].records())}
            frames.append(frame)
            return frame

        seed = capture("Центр A: подтверждённое начало отдельной траектории")
        write = _action("alpha:write")
        outcomes["write_projection"] = _project(env, write, "writea", 0, clock[0], 110)
        proposed = capture("Идея и прогноз записаны отдельно. Реальная позиция не изменилась")
        _support(env, write, clock[0], 110, ROLES[:2])
        # This reaches the actual receiver gate, with an exact broker grant.
        # A denied receiver probe has no accepted effect and does not consume the
        # broker's outbound dispatch. It is not a retry of an unknown operation.
        grant = env["broker"].authorize(write, policy_version=env["policy"])
        authorization = {key: grant[key] for key in
                         ("action_digest", "policy_version", "expires_at", "receiver_id")}
        outcomes["missing_role"] = env["receiver"].commit(write, authorization=authorization)
        missing = capture("Два наблюдателя из трёх: получатель отклонил действие, эффектов ноль")
        clock[0] = 105.0
        _support(env, write, clock[0], 110, ROLES[2:])
        outcomes["write"] = env["broker"].dispatch(write)
        written = capture("Три роли поддержали прогноз. Запись подтверждена получателем")
        clock[0] = 116.0
        away = capture("11 секунд вне центра: требуется подтверждённое возвращение")
        return_a = _action("alpha:return-a")
        outcomes["old_return_projection"] = _project(env, return_a, "returna", 1, clock[0], 119)
        _support(env, return_a, clock[0], 119)
        capture("Возвращение в A запланировано до 119. Сам прогноз агента не перемещает")
        clock[0] = 120.0
        changed = capture("По расписанию действует центр B. История и реальная позиция сохранены")
        outcomes["old_return"] = env["broker"].dispatch(return_a)
        rejected = capture("Прогноз старого центра отклонён до эффекта")
        clock[0] = 121.0
        return_b = _action("alpha:return-b")
        outcomes["new_return_projection"] = _project(env, return_b, "returnb", 1, clock[0], 130)
        _support(env, return_b, clock[0], 130)
        outcomes["new_return"] = env["broker"].dispatch(return_b)
        returned = capture("Возвращение в действующий центр B подтверждено. Прогресс не переписан")
        next_write = _action("alpha:next-write")
        outcomes["next_write_projection"] = _project(env, next_write, "writeb", 2, clock[0], 135)
        _support(env, next_write, clock[0], 135)
        clock[0] = 126.0
        outcomes["stagnation"] = env["broker"].dispatch(next_write)
        idle = capture("21 секунда без объявленного прогресса: HOLD для проверки, без автоматического действия")
        clock[0] = 127.0
        env["authority"].stop("campaign")
        stopped = capture("STOP закрывает полномочия. Согласие наблюдателей не может их восстановить")
        veto = _veto_case(work / "veto")
        outcomes["veto_case"] = veto

        def state(frame):
            return frame["continuity"]["states"][0]

        events = returned["continuity"]["events"]
        links = all(event["sequence"] == index + 1 and event["parent_hash"] ==
                    ("0" * 64 if index == 0 else events[index - 1]["event_hash"])
                    and event["event_hash"] == digest({key: value for key, value in event.items()
                                                       if key != "event_hash"})
                    for index, event in enumerate(events))
        checks = {
            "ideas_and_projections_do_not_change_fact": state(seed)["head_hash"] == state(proposed)["head_hash"]
                and state(proposed)["node_id"] == "center-a" and proposed["record_count"] == 0,
            "two_roles_do_not_authorize": outcomes["missing_role"]["reason"] == "OBSERVER_RING_ROLE_REQUIRED"
                and missing["record_count"] == 0 and missing["authority"]["action_count"] == 0,
            "useful_record_confirmed": outcomes["write"]["status"] == "COMMITTED"
                and state(written)["node_id"] == "work" and written["record_count"] == 1,
            "away_time_requires_return": state(away)["diagnosis"] == "CENTER_RETURN_REQUIRED",
            "moving_center_does_not_move_agent": state(changed)["active_center_id"] == "B"
                and state(changed)["node_id"] == "work"
                and state(changed)["head_hash"] == state(written)["head_hash"],
            "old_projection_denied_without_effect": outcomes["old_return"]["status"] == "BLOCKED"
                and outcomes["old_return"]["reason"] == "OBSERVER_RING_ATTESTATION_STALE"
                and rejected["record_count"] == 1 and rejected["authority"]["action_count"] == 1,
            "old_forecast_remains_bound_to_previous_center": outcomes["old_return_projection"]["center_id"] == "A"
                and state(rejected)["active_center_id"] == "B",
            "fresh_return_to_current_center_confirmed": outcomes["new_return"]["status"] == "COMMITTED"
                and state(returned)["node_id"] == "center-b" and state(returned)["revision"] == 2,
            "return_does_not_fake_progress": state(returned)["last_progress_at"] == 105,
            "stagnation_holds_without_creating_activity": outcomes["stagnation"]["reason"] == "CENTER_STAGNATION_HOLD"
                and idle["record_count"] == 2 and idle["authority"]["action_count"] == 2,
            "past_chain_is_linked_and_preserved": links and len(events) == 5
                and events[:len(seed["continuity"]["events"])] == seed["continuity"]["events"],
            "veto_overrides_three_supporting_roles": veto["result"]["reason"] == "OBSERVER_RING_VETO"
                and veto["record_count"] == 0 and veto["action_count"] == 0,
            "observer_agreement_never_grants_authority": all(
                not coverage["execution_authorized"] for frame in frames for coverage in frame["ring"]["coverage"]),
            "stop_remains_terminal": stopped["authority"]["status"] == "STOPPED"
                and stopped["record_count"] == 2,
        }
        return {"schema": "liminal-center-continuity-demo-v1", "source": _source(),
                "source_digests": _source_digests(), "frames": frames, "outcomes": outcomes,
                "checks": checks, "passed": all(checks.values()), "scope": {
                    "mode": "scripted owned SQLite receiver and trusted host observation fixtures",
                    "clock": "controlled authority seconds 100..127; broker grants and receipt metadata use wall time",
                    "model_calls": 0, "external_network": False, "physical_coordinates": False,
                    "center_schedule": "predeclared and immutable; no adaptive goalpost changes",
                    "observer_independence": "separate role fixtures in one trusted host; not independent deployed services",
                    "production_observer_authentication": "host adapter responsibility",
                    "orientation_authorizes_actions": False}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--html", type=Path)
    args = parser.parse_args()
    report = run_demo()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    if args.html:
        from .center_view import render
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(render(report), encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "checks": report["checks"], "source": report["source"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
