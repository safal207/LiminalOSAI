"""Executed signed observer processes and owned receiver rejection scenarios.

The three processes have different Ed25519 identities. Their evidence inputs are
host-owned fixtures on one machine; signatures establish who made a statement,
not that its contents are true or that its source is independent.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authority import ControlError, digest
from .brakes_store import SessionAuthority
from .broker import Broker
from .center_continuity import CenterContinuityStore
from .center_demo import _action, _project
from .multi_agent import _source, _source_digests
from .observer_auth import ObserverAuthStore, sign_attestation
from .observer_ring import ObserverRingStore
from .orientation import OrientationStore
from .receiver import Receiver


ROLES = ("reality", "continuity", "projection")


def _setup(work: Path, clock: list[float]) -> dict:
    """Install the host profiles and keys before any execution is seeded."""
    work.mkdir(parents=True, exist_ok=True)
    authority = SessionAuthority(work / "authority.sqlite", clock=lambda: clock[0])
    policy = digest("owned signed observers demonstration")
    authority.create_session("campaign", controller_id="operator", policy_digest=policy,
        objective_digest=digest("authenticated evidence for bounded transitions"),
        max_actions=10, max_executions=1, max_depth=1, max_stages=8,
        lifetime_seconds=200, lease_seconds=200)
    authority.bind_execution("campaign", "alpha")
    broker_key, receipt_key = secrets.token_bytes(32), secrets.token_bytes(32)
    receiver = Receiver(authority.db_path, broker_key, receipt_key,
                        admission_controller=authority)
    broker = Broker(work / "broker.sqlite", receiver)
    graph = OrientationStore(authority)
    graph.install("campaign", {
        "nodes": [{"node_id": "center-a", "space_id": "control", "phase": "checkpoint"},
                  {"node_id": "work", "space_id": "owned_records", "phase": "record_observed"}],
        "edges": [{"edge_id": "writea", "source": "center-a", "destination": "work", "channel": "records"},
                  {"edge_id": "returna", "source": "work", "destination": "center-a", "channel": "records"},
                  {"edge_id": "networka", "source": "center-a", "destination": "work", "channel": "egress"}],
        "center_nodes": ["center-a"], "max_steps": 8, "max_visits": 5,
        "max_away_steps": 3, "max_observation_age_seconds": 90,
        "observers": {"records": receiver.receiver_id, "egress": "owned-sink"}})
    center = CenterContinuityStore(authority)
    center.install("campaign", {
        "windows": [{"center_id": "A", "previous_center_id": None, "starts_at": 100,
                     "ends_at": 200, "center_nodes": ["center-a"]}],
        "max_past_age_seconds": 90, "max_future_horizon_seconds": 30,
        "max_transition_seconds": 15, "max_away_seconds": 10,
        "max_idle_seconds": 20, "progress_edge_ids": ["writea"], "max_ideas": 20})
    ring = ObserverRingStore(authority)
    ring.install("campaign", {
        "observers": [{"observer_id": role + "-observer", "role": role} for role in ROLES],
        "required_roles": list(ROLES), "max_attestation_age_seconds": 30,
        "max_attestations": 100})
    private_keys = {role: secrets.token_bytes(32) for role in ROLES}
    keys = [{"observer_id": role + "-observer", "key_id": role + "-key",
             "public_key": Ed25519PrivateKey.from_private_bytes(private_keys[role]).public_key()
                             .public_bytes_raw().hex()} for role in ROLES]
    auth = ObserverAuthStore(authority)
    auth.install("campaign", {"keys": keys, "max_challenge_age_seconds": 15,
                              "max_challenges": 100})
    graph.seed("campaign", "alpha", "center-a", evidence_digest=digest("owned initial state"),
               observed_at=clock[0])
    return {"authority": authority, "receiver": receiver, "broker": broker,
            "graph": graph, "center": center, "ring": ring, "auth": auth,
            "policy": policy, "private_keys": private_keys, "clock": clock,
            "broker_key": broker_key, "receipt_key": receipt_key}


def _prepare(env: dict, name: str = "signed:write", *, deadline: float = 110) -> dict:
    action = _action(name)
    _project(env, action, "writea", 0, env["clock"][0], deadline)
    return action


def _request(env: dict, action: dict, role: str, *, valid_until: float = 110) -> dict:
    return env["auth"].challenge(action["action_id"], role + "-observer", valid_until)


def _signed(env: dict, request: dict, *, role: str, verdict: str = "SUPPORT",
            private_key: bytes | None = None, valid_until: float | None = None) -> dict:
    return sign_attestation(request, private_key=private_key or env["private_keys"][role],
        verdict=verdict, evidence_digest=digest({"owned_fixture": role, "verdict": verdict}),
        observed_at=env["clock"][0], valid_until=valid_until or request["valid_until"])


def _support(env: dict, action: dict, *, roles=ROLES, valid_until: float = 110) -> list[dict]:
    results = []
    for role in roles:
        request = _request(env, action, role, valid_until=valid_until)
        results.append(env["auth"].ingest(_signed(env, request, role=role)))
    return results


def _commit(env: dict, action: dict) -> dict:
    """Exercise the actual receiver, with a genuine grant from the broker."""
    grant = env["broker"].authorize(action, policy_version=env["policy"])
    authorization = {key: grant[key] for key in
                     ("action_digest", "policy_version", "expires_at", "receiver_id")}
    return env["receiver"].commit(action, authorization=authorization)


def _reject(call) -> dict:
    try:
        result = call()
    except ControlError as error:
        return {"status": "REJECTED", "reason": str(error)}
    return {"status": "UNEXPECTED_ACCEPT", "result": result}


def _result(env: dict, action: dict, *, ingestion: dict | None = None) -> dict:
    result = _commit(env, action)
    return {"result": result, "record_count": len(env["receiver"].records()),
            "action_count": env["authority"].status("campaign")["action_count"],
            "ingestion": ingestion, "ring": env["ring"].snapshot("campaign")}


def _evidence(env: dict, action: dict, role: str) -> dict:
    """Public bounded fixture inputs for the independently launched processes."""
    continuity = env["center"].snapshot("campaign")
    orientation = env["graph"].snapshot("campaign")
    projection = next(item for item in continuity["projections"]
                      if item["action_id"] == action["action_id"])
    raw = {key: value for key, value in projection.items()
           if key not in {"projection_digest", "execution_authorized", "status"}}
    state = next(item for item in continuity["states"] if item["execution_id"] == action["execution_id"])
    common = {"projection": raw, "observed_at": env["clock"][0]}
    if role == "reality":
        edge = next(item for item in orientation["profile"]["edges"] if item["edge_id"] == raw["edge_id"])
        return {**common, "state": state, "edge": edge}
    if role == "continuity":
        events = [item for item in continuity["events"] if item["execution_id"] == action["execution_id"]]
        return {**common, "events": events}
    return {**common, "center_profile": continuity["profile"],
            "orientation_profile": orientation["profile"], "state": state}


def run_demo() -> dict:
    from .observer_process import run_observer

    outcomes, checks, processes, private_material, public_envelopes = {}, {}, [], [], []
    with tempfile.TemporaryDirectory(prefix="liminal-signed-observers-") as temporary:
        work = Path(temporary)

        def fresh(name):
            env = _setup(work / name, [100.0])
            private_material.extend(key.hex() for key in env["private_keys"].values())
            private_material.extend(env[key].hex() for key in ("broker_key", "receipt_key"))
            return env

        env = fresh("processes")
        proposed = _prepare(env)
        for role in ROLES:
            request = _request(env, proposed, role)
            executed = run_observer(request, private_key=env["private_keys"][role],
                                    evidence=_evidence(env, proposed, role))
            processes.append(executed["process"])
            if executed["envelope"] is not None:
                env["auth"].ingest(executed["envelope"])
                public_envelopes.append(executed["envelope"])
        outcomes["three_processes"] = {**_result(env, proposed),
            "authentication": env["auth"].snapshot("campaign"), "envelopes": public_envelopes}
        checks["three_distinct_observer_processes"] = (
            all(item["status"] == "PASS" and item["exit_code"] == 0 for item in processes)
            and len({item["pid"] for item in processes}) == 3
            and all(item["pid"] != os.getpid() for item in processes))
        checks["three_signed_roles_allow_one_actual_record"] = (
            outcomes["three_processes"]["result"]["status"] == "COMMITTED"
            and outcomes["three_processes"]["record_count"] == 1)

        env = fresh("forged_signature")
        proposed = _prepare(env)
        request = _request(env, proposed, ROLES[0])
        forged_key = secrets.token_bytes(32)
        private_material.append(forged_key.hex())
        forged = _signed(env, request, role=ROLES[0], private_key=forged_key)
        rejected = _reject(lambda: env["auth"].ingest(forged))
        _support(env, proposed, roles=ROLES[1:])
        outcomes["forged_signature"] = _result(env, proposed, ingestion=rejected)

        env = fresh("raw_bypass")
        proposed = _prepare(env)
        _support(env, proposed, roles=ROLES[1:])
        rejected = _reject(lambda: env["ring"].attest(proposed["action_id"],
            observer_id="reality-observer", verdict="SUPPORT", evidence_digest=digest("raw bypass"),
            observed_at=100, valid_until=110))
        outcomes["raw_bypass"] = _result(env, proposed, ingestion=rejected)

        env = fresh("compromised_signer")
        proposed = _prepare(env)
        _support(env, proposed, roles=ROLES[:1])
        outcomes["compromised_signer"] = _result(env, proposed)

        env = fresh("missing_process")
        proposed = _prepare(env)
        _support(env, proposed, roles=ROLES[:2])
        # A real subprocess is given a deadline shorter than interpreter startup.
        # A timed-out process supplies no envelope, so its role remains absent.
        request = _request(env, proposed, ROLES[2])
        failed = run_observer(request, private_key=env["private_keys"][ROLES[2]],
            evidence=_evidence(env, proposed, ROLES[2]), timeout_seconds=0.000001)
        outcomes["missing_process"] = {**_result(env, proposed), "process": failed["process"]}
        checks["failed_process_supplies_no_envelope"] = (
            failed["envelope"] is None and failed["process"]["status"] == "HOLD"
            and type(failed["process"]["pid"]) is int)

        env = fresh("stale_support")
        proposed = _prepare(env)
        _support(env, proposed, valid_until=104)
        env["clock"][0] = 105
        outcomes["stale_support"] = _result(env, proposed)

        env = fresh("replayed_challenge")
        proposed = _prepare(env)
        request = _request(env, proposed, ROLES[0])
        env["auth"].ingest(_signed(env, request, role=ROLES[0]))
        different = _signed(env, request, role=ROLES[0], verdict="UNKNOWN")
        rejected = _reject(lambda: env["auth"].ingest(different))
        outcomes["replayed_challenge"] = _result(env, proposed, ingestion=rejected)

        env = fresh("retargeted_challenge")
        original = _prepare(env, "original")
        other = _prepare(env, "other")
        request = _request(env, original, ROLES[0])
        changed = deepcopy(request)
        changed["action_id"] = other["action_id"]
        retargeted = _signed(env, changed, role=ROLES[0])
        rejected = _reject(lambda: env["auth"].ingest(retargeted))
        _support(env, other, roles=ROLES[1:])
        outcomes["retargeted_challenge"] = _result(env, other, ingestion=rejected)

        env = fresh("veto")
        proposed = _prepare(env)
        _support(env, proposed)
        request = _request(env, proposed, ROLES[0])
        env["auth"].ingest(_signed(env, request, role=ROLES[0], verdict="VETO"))
        outcomes["valid_veto"] = _result(env, proposed)

        env = fresh("revocation")
        proposed = _prepare(env)
        _support(env, proposed)
        env["auth"].revoke("campaign", "reality-key", "owned revocation fixture")
        outcomes["revocation"] = _result(env, proposed)

        env = fresh("restart")
        proposed = _prepare(env)
        _support(env, proposed, roles=ROLES[:2])
        # The reopened authority has no adapter instance attached. Persisted
        # profile enforcement at the effect boundary must still deny the call.
        restarted = SessionAuthority(env["authority"].db_path, clock=lambda: env["clock"][0])
        env["authority"] = restarted
        env["receiver"] = Receiver(restarted.db_path, env["broker_key"], env["receipt_key"],
                                    admission_controller=restarted)
        env["ring"] = ObserverRingStore(restarted)
        rejected = _reject(lambda: env["ring"].attest(proposed["action_id"],
            observer_id="projection-observer", verdict="SUPPORT", evidence_digest=digest("restart bypass"),
            observed_at=100, valid_until=110))
        outcomes["restart"] = _result(env, proposed, ingestion=rejected)

        expected = {
            "forged_signature": ("OBSERVER_AUTH_SIGNATURE_INVALID", "OBSERVER_RING_ROLE_REQUIRED"),
            "raw_bypass": ("OBSERVER_RING_AUTH_REQUIRED", "OBSERVER_RING_ROLE_REQUIRED"),
            "compromised_signer": (None, "OBSERVER_RING_ROLE_REQUIRED"),
            "missing_process": (None, "OBSERVER_RING_ROLE_REQUIRED"),
            "stale_support": (None, "OBSERVER_RING_ATTESTATION_STALE"),
            "replayed_challenge": ("OBSERVER_AUTH_CHALLENGE_REPLAY", "OBSERVER_RING_ROLE_REQUIRED"),
            "retargeted_challenge": ("OBSERVER_AUTH_BINDING_MISMATCH", "OBSERVER_RING_ROLE_REQUIRED"),
            "valid_veto": (None, "OBSERVER_RING_VETO"),
            "revocation": (None, "OBSERVER_AUTH_KEY_REVOKED"),
            "restart": ("OBSERVER_RING_AUTH_REQUIRED", "OBSERVER_RING_ROLE_REQUIRED"),
        }
        for name, (ingestion_reason, denial_reason) in expected.items():
            case = outcomes[name]
            checks[name + "_denied_before_effect"] = (
                case["result"]["status"] == "DENIED" and case["result"]["reason"] == denial_reason
                and case["record_count"] == 0 and case["action_count"] == 0
                and (ingestion_reason is None or case["ingestion"] == {
                    "status": "REJECTED", "reason": ingestion_reason}))
        checks["signed_agreement_never_itself_authorizes_execution"] = all(
            not coverage["execution_authorized"] for case in outcomes.values()
            for coverage in case["ring"]["coverage"])
        encoded_public = json.dumps({"outcomes": outcomes, "processes": processes, "checks": checks}, sort_keys=True)
        checks["no_private_key_material_in_report"] = all(secret not in encoded_public for secret in private_material)
        return {"schema": "liminal-signed-observers-demo-v1", "source": _source(),
                "source_digests": _source_digests(), "processes": processes,
                "checks": checks, "passed": all(checks.values()), "outcomes": outcomes,
                "scope": {
                    "mode": "three actual signed observer processes and owned SQLite receiver",
                    "observer_independence": "distinct processes and keys; same host and supplied evidence fixtures",
                    "semantic_truth": "signature authenticates statement origin; it does not prove truth",
                    "isolation": "process separation is not an OS sandbox; trusted host can access all fixture keys",
                    "external_network": False, "model_calls": 0, "private_keys_exported": False,
                    "clock": "controlled authority seconds 100..105; broker grant metadata uses wall time",
                    "already_accepted_effects": "revocation does not undo an already accepted receiver effect",
                    "execution_authorized_by_observers": False}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_demo()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "checks": report["checks"], "source": report["source"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
