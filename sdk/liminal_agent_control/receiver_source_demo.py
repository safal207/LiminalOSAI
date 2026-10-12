"""Owned receiver signatures checked by real, pinned Docker observers.

The receiver issuer generates an ephemeral Ed25519 key in a separate child
process and reads its configured receiver database. The controller receives a
public enrollment and public signed exports, never that signing key. This is a
process/key boundary on one trusted host, not independent organizational
ownership or protection from a compromised host/kernel/database.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

from .authority import ControlError, canonical_bytes, digest
from .brakes_store import SessionAuthority
from .broker import Broker
from .center_continuity import CenterContinuityStore
from .center_demo import _action, _project
from .multi_agent import _source, _source_digests
from .observer_auth import ObserverAuthStore
from .observer_auth_demo import ROLES, _commit, _reject
from .observer_container_demo import _docker_command, _packet
from .observer_ring import ObserverRingStore
from .observer_sources import ObserverSourceStore, write_source_packet
from .orientation import OrientationStore
from .receiver import Receiver
from .receiver_source import SOURCE_DOMAIN, verify_source_statement


NEGATIVE_CASES = (
    "forged_host_verified", "missing_signature", "attacker_key",
    "tamper_existing_record", "old_request_nonce", "expired_export", "source_outage",
)


def _tick(env: dict) -> float:
    """Keep the normal fixture authority clock aligned with issuer wall time."""
    env["clock"][0] = time.time()
    return env["clock"][0]


def _keys(path: Path, key: bytes) -> Path:
    path.write_bytes(key)
    path.chmod(0o600)
    return path


def _initial_environment(work: Path) -> dict:
    """Configure the governed receiver before any source challenge or seed."""
    work.mkdir(mode=0o700)
    clock = [time.time()]
    # The independent ring watchdog uses real wall time too. A frozen fixture
    # clock would race its durable last_now watermark and falsely stop the root.
    authority = SessionAuthority(work / "authority.sqlite")
    policy = digest("owned signed receiver source demonstration")
    authority.create_session("campaign", controller_id="operator", policy_digest=policy,
        objective_digest=digest("authenticate real receiver evidence before effects"),
        max_actions=10, max_executions=1, max_depth=1, max_stages=8,
        lifetime_seconds=200, lease_seconds=200)
    authority.bind_execution("campaign", "alpha")
    broker_key, receipt_key = secrets.token_bytes(32), secrets.token_bytes(32)
    receiver = Receiver(authority.db_path, broker_key, receipt_key, admission_controller=authority)
    broker = Broker(work / "broker.sqlite", receiver)
    graph = OrientationStore(authority)
    graph.install("campaign", {
        "nodes": [{"node_id": "center-a", "space_id": "control", "phase": "checkpoint"},
                  {"node_id": "work", "space_id": "owned_records", "phase": "record_observed"}],
        "edges": [{"edge_id": "writea", "source": "center-a", "destination": "work", "channel": "records"},
                  {"edge_id": "returna", "source": "work", "destination": "center-a", "channel": "records"}],
        "center_nodes": ["center-a"], "max_steps": 8, "max_visits": 5,
        "max_away_steps": 3, "max_observation_age_seconds": 90,
        "observers": {"records": receiver.receiver_id, "egress": "owned-sink"}})
    center = CenterContinuityStore(authority)
    center.install("campaign", {
        "windows": [{"center_id": "A", "previous_center_id": None, "starts_at": clock[0],
                     "ends_at": clock[0] + 200, "center_nodes": ["center-a"]}],
        "max_past_age_seconds": 90, "max_future_horizon_seconds": 30,
        "max_transition_seconds": 15, "max_away_seconds": 10,
        "max_idle_seconds": 20, "progress_edge_ids": ["writea"], "max_ideas": 20})
    ring = ObserverRingStore(authority)
    ring.install("campaign", {
        "observers": [{"observer_id": role + "-observer", "role": role} for role in ROLES],
        "required_roles": list(ROLES), "max_attestation_age_seconds": 30, "max_attestations": 100})
    collectors = work / "collectors"
    collectors.mkdir()
    policy_path = collectors / "installed-policy.json"
    policy_path.write_bytes(canonical_bytes({"center_profile": center.snapshot("campaign")["profile"],
        "orientation_profile": graph.snapshot("campaign")["profile"]}))
    policy_path.chmod(0o444)
    return {"authority": authority, "receiver": receiver, "broker": broker,
        "graph": graph, "center": center, "ring": ring, "policy": policy, "clock": clock,
        "audit_path": collectors / "audit.jsonl", "policy_path": policy_path,
        "broker_key_file": _keys(work / "broker.key", broker_key),
        "receipt_key_file": _keys(work / "receipt.key", receipt_key)}


def _install_source(env: dict, enrollments: list[dict], pin: dict) -> None:
    """Pin the receiver issuer and observer keys before seed, not from packets."""
    _tick(env)
    auth = ObserverAuthStore(env["authority"])
    auth.install("campaign", {"keys": [{field: item[field] for field in
        ("observer_id", "key_id", "public_key")} for item in enrollments],
        "max_challenge_age_seconds": 15, "max_challenges": 100})
    source = ObserverSourceStore(env["authority"])
    sources = [{"observer_id": role + "-observer", "source_id": role + "-collector"} for role in ROLES]
    sources[0]["issuer"] = pin
    source.install("campaign", {"sources": sources, "max_source_age_seconds": 30})
    env.update(auth=auth, source=source)
    env["graph"].seed("campaign", "alpha", "center-a", evidence_digest=digest("owned initial state"),
                      observed_at=env["clock"][0])


def _prepare(env: dict, name: str, *, edge_id: str = "writea", revision: int = 0) -> dict:
    now = _tick(env)
    action = _action("receiver-source:" + name)
    # project() requires not_before to be in its present/future. Leave a finite
    # margin for its transactions rather than using an already elapsed time.
    not_before = now + 1
    _project(env, action, edge_id, revision, not_before, now + 14)
    while time.time() <= not_before:
        time.sleep(min(0.05, max(0.001, not_before + 0.01 - time.time())))
    _tick(env)
    return action


def _request(env: dict, action: dict, role: str) -> dict:
    now = _tick(env)
    request = env["auth"].challenge(action["action_id"], role + "-observer", now + 12)
    _tick(env)
    return request


def _signed_packet(env: dict, action: dict, request: dict, statement: dict) -> dict:
    packet = _packet(env, action, "reality", request)
    packet["observed_at"] = statement["issued_at"]
    packet["payload"].update(deepcopy(statement["export"]))
    packet["payload"]["receiver_source_statement"] = deepcopy(statement)
    packet["payload"]["observed_at"] = statement["issued_at"]
    # Retained to demonstrate that this legacy assertion cannot replace a pin.
    packet["payload"]["receiver_snapshot_verified_by_host"] = True
    return packet


def _observe(env: dict, services: dict, directories: dict, action: dict, role: str,
             request: dict, packet: dict, *, binding_required: bool = True) -> dict:
    _tick(env)
    binding = _reject(lambda: env["source"].bind(request, packet))
    if binding_required and binding["status"] != "UNEXPECTED_ACCEPT":
        raise ControlError("RECEIVER_SOURCE_DEMO_VALID_BINDING_REJECTED:" + binding["reason"])
    write_source_packet(directories[role], request, packet)
    observed = services[role].attest(request)
    _tick(env)
    ingestion = (_reject(lambda: env["auth"].ingest(observed["envelope"]))
                 if observed["envelope"] is not None else {"status": "NO_ENVELOPE"})
    if binding_required and (ingestion["status"] != "UNEXPECTED_ACCEPT"
                             or observed["envelope"]["verdict"] != "SUPPORT"):
        raise ControlError("RECEIVER_SOURCE_DEMO_VALID_INGESTION_REJECTED:" + str(ingestion))
    return {"request": request, "packet": packet, "binding": binding, "ingestion": ingestion, **observed}


def _other_roles(env: dict, services: dict, directories: dict, action: dict) -> list[dict]:
    result = []
    for role in ROLES[1:]:
        request = _request(env, action, role)
        packet = _packet(env, action, role, request)
        result.append(_observe(env, services, directories, action, role, request, packet))
    return result


def _result(env: dict, action: dict, *, before: int = 0, refresh_clock: bool = True) -> dict:
    if refresh_clock:
        _tick(env)
    receipt = _commit(env, action)
    records = env["receiver"].records()
    return {"result": receipt, "record_count_before": before, "record_count": len(records),
        "candidate_effect_count": len(records) - before,
        "candidate_record_count": sum(item["action"]["action_id"] == action["action_id"] for item in records),
        "action_count": env["authority"].status("campaign")["action_count"]}


def _inspect_service(service, image_id: str, directories: dict, pin: dict) -> dict:
    inspected = _docker_command(["inspect", service.container_id])
    if inspected.returncode != 0:
        raise ControlError("RECEIVER_SOURCE_DEMO_CONTAINER_INSPECT_FAILED")
    document = json.loads(inspected.stdout)[0]
    command = document["Config"]["Cmd"]
    bind_mounts = [item for item in document.get("Mounts", []) if item["Type"] == "bind"]
    return {"container_id": service.container_id, "image_id": document["Image"],
        "pinned_image_matches": document["Image"] == image_id,
        "receiver_public_pin_in_fixed_command": pin["public_key"] in " ".join(command)
            and pin["receiver_id"] in " ".join(command),
        "only_public_evidence_and_sdk_mounted": len(bind_mounts) == 2
            and {item["Destination"] for item in bind_mounts} == {"/sdk", "/evidence"}
            and all(item["RW"] is False for item in bind_mounts)
            and next(item["Source"] for item in bind_mounts if item["Destination"] == "/evidence")
                == str(directories["reality"]),
        "network_none": document["HostConfig"]["NetworkMode"] == "none"}


def run_demo(image_id: str) -> dict:
    """Run real receiver effects and Docker rejection cases; never pull an image."""
    from .observer_container import validate_source_directories
    from .observer_lifecycle import ObserverRingSupervisor
    from .receiver_source_service import ReceiverSourceProcess
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    outcomes, checks, issuer_cleanup, observer_cleanup, ring_cleanup = {}, {}, [], [], []
    with tempfile.TemporaryDirectory(prefix="liminal-receiver-source-") as temporary:
        work = Path(temporary).resolve()
        directories = {role: work / (role + "-source") for role in ROLES}
        for directory in directories.values():
            directory.mkdir(mode=0o755)
        validate_source_directories(list(directories.values()))
        for case_name in ("positive", *NEGATIVE_CASES):
            env = _initial_environment(work / case_name)
            issuer_options = {"max_age_seconds": 2} if case_name == "expired_export" else {}
            issuer = ReceiverSourceProcess(db_path=env["authority"].db_path,
                broker_key_file=env["broker_key_file"], receipt_key_file=env["receipt_key_file"],
                issuer_id="receiver-issuer", source_id="reality-collector", key_id="receiver-source-key",
                expected_receiver_id=env["receiver"].receiver_id,
                **issuer_options)
            ring = None
            issuer_stop = None
            try:
                pin = issuer.start()
                issuer_pid = issuer.pid
                ring = ObserverRingSupervisor(env["authority"], "campaign",
                    registry_path=work / case_name / "registry.sqlite", image_id=image_id,
                    source_directories=directories, lifetime_seconds=60,
                    source_issuers={"reality": pin})
                ring.start()
                services = ring.services
                reality = services["reality"]
                _install_source(env, ring.enrollments, pin)
                inspection = _inspect_service(reality, image_id, directories, pin)
                before, previous = 0, None
                if case_name == "tamper_existing_record":
                    previous_action = _prepare(env, "previous-real-record")
                    previous_request = _request(env, previous_action, "reality")
                    previous_statement = issuer.issue(previous_request)
                    previous_witness = _observe(env, services, directories, previous_action, "reality",
                        previous_request, _signed_packet(env, previous_action, previous_request, previous_statement))
                    _other_roles(env, services, directories, previous_action)
                    previous = {**_result(env, previous_action), "witness": previous_witness}
                    if previous["result"]["status"] != "COMMITTED" or previous["candidate_effect_count"] != 1:
                        raise ControlError("RECEIVER_SOURCE_DEMO_REAL_BASELINE_NOT_COMMITTED")
                    before = 1
                    action = _prepare(env, case_name, edge_id="returna", revision=1)
                else:
                    action = _prepare(env, case_name)
                request = _request(env, action, "reality")
                source_failure = None
                if case_name == "source_outage":
                    issuer_stop = issuer.stop()
                    source_failure = _reject(lambda: issuer.issue(request))
                    packet = _packet(env, action, "reality", request)
                    statement = None
                elif case_name == "forged_host_verified":
                    packet = _packet(env, action, "reality", request)
                    packet["payload"]["receiver_snapshot"]["signature"] = "0" * 64
                    packet["payload"]["receiver_snapshot_verified_by_host"] = True
                    statement = None
                else:
                    statement = issuer.issue(request)
                    if case_name == "old_request_nonce":
                        request = _request(env, action, "reality")
                    packet = _signed_packet(env, action, request, statement)
                    if case_name == "missing_signature":
                        del packet["payload"]["receiver_source_statement"]["signature"]
                    elif case_name == "attacker_key":
                        attacker = Ed25519PrivateKey.generate()
                        forged = packet["payload"]["receiver_source_statement"]
                        forged["signature"] = attacker.sign(SOURCE_DOMAIN + canonical_bytes({
                            key: value for key, value in forged.items() if key != "signature"})).hex()
                        packet["payload"]["receiver_source_pin"] = {
                            **pin, "public_key": attacker.public_key().public_bytes_raw().hex()}
                    elif case_name == "tamper_existing_record":
                        forged = packet["payload"]["receiver_source_statement"]
                        forged["export"]["receiver_records"][0]["arguments"]["owned_marker"] = "collector-forgery"
                        forged["export_digest"] = digest(forged["export"])
                        packet["payload"].update(deepcopy(forged["export"]))
                valid = case_name in {"positive", "expired_export"}
                witness = _observe(env, services, directories, action, "reality", request, packet,
                                   binding_required=valid)
                other_witnesses = _other_roles(env, services, directories, action)
                freshness = None
                if case_name == "expired_export":
                    # Expire only the short receiver statement, while the
                    # already consumed observer challenge remains valid.
                    # Real time preserves compatibility with the watchdog.
                    while time.time() <= statement["expires_at"] + 0.01:
                        time.sleep(min(0.05, max(0.001, statement["expires_at"] + 0.02 - time.time())))
                    _tick(env)
                    freshness = _reject(lambda: verify_source_statement(request, statement, pin,
                        now=env["clock"][0], max_age_seconds=30))
                result = _result(env, action, before=before)
                outcomes[case_name] = {**result, "receiver_pin": pin,
                    "issuer_child_pid": issuer_pid, "controller_pid": os.getpid(),
                    "container": inspection, "witness": witness, "other_witnesses": other_witnesses,
                    "previous_real_record": previous, "source_failure": source_failure,
                    "freshness_check": freshness,
                    "challenge_still_valid_at_effect_attempt": env["clock"][0] < request["valid_until"]}
                checks[case_name + "_receiver_pin_fixed_outside_packet"] = (
                    inspection["receiver_public_pin_in_fixed_command"]
                    and env["source"].snapshot("campaign")["profile"]["sources"][0]["issuer"] == pin)
                checks[case_name + "_source_issuer_child_and_no_receiver_secrets_in_observer"] = (
                    issuer_pid != os.getpid() and set(pin) == {
                        "issuer_id", "key_id", "public_key", "receiver_id", "source_id"}
                    and inspection["only_public_evidence_and_sdk_mounted"]
                    and inspection["pinned_image_matches"] and inspection["network_none"])
                if case_name == "positive":
                    checks["signed_receiver_source_allows_one_actual_effect"] = (
                        result["result"]["status"] == "COMMITTED" and result["candidate_effect_count"] == 1
                        and result["candidate_record_count"] == 1
                        and witness["envelope"] is not None and witness["envelope"]["verdict"] == "SUPPORT")
                else:
                    checks[case_name + "_denied_before_candidate_effect"] = (
                        result["result"]["status"] == "DENIED" and result["candidate_effect_count"] == 0
                        and result["candidate_record_count"] == 0
                        and result["result"]["reason"] == (
                            "RECEIVER_SOURCE_STALE" if case_name == "expired_export"
                            else "OBSERVER_RING_ROLE_REQUIRED"))
                    if case_name not in {"expired_export"}:
                        checks[case_name + "_real_docker_observer_does_not_support"] = (
                            witness["envelope"] is not None and witness["envelope"]["verdict"] == "UNKNOWN")
                        checks[case_name + "_source_gate_rejects_collector_packet"] = (
                            witness["binding"]["status"] == "REJECTED"
                            and witness["binding"]["reason"].startswith("RECEIVER_SOURCE_"))
                if case_name == "expired_export":
                    checks["expired_receiver_signature_is_rechecked_after_support_at_effect_gate"] = (
                        witness["envelope"] is not None and witness["envelope"]["verdict"] == "SUPPORT"
                        and witness["ingestion"]["status"] == "UNEXPECTED_ACCEPT"
                        and freshness == {"status": "REJECTED", "reason": "RECEIVER_SOURCE_STALE"}
                        and outcomes[case_name]["challenge_still_valid_at_effect_attempt"]
                        and result["candidate_effect_count"] == 0)
                if case_name == "source_outage":
                    checks["stopped_source_issuer_cannot_issue_statement"] = (
                        issuer_stop["reaped"] is True and source_failure["status"] == "REJECTED")
                if case_name == "tamper_existing_record":
                    checks["tamper_case_uses_real_existing_record_without_a_new_effect"] = (
                        before == result["record_count"] == 1 and previous["candidate_effect_count"] == 1
                        and witness["packet"]["payload"]["receiver_records"][0]["arguments"]["owned_marker"]
                            == "collector-forgery")
            finally:
                if ring is not None:
                    closed = ring.close()
                    ring_cleanup.append(closed)
                    observer_cleanup.extend(closed.get("cleanup", []))
                issuer_cleanup.append(issuer.stop() if issuer_stop is None else issuer_stop)
        checks["all_owned_observer_containers_removed"] = (
            len(observer_cleanup) == len(ROLES) * (1 + len(NEGATIVE_CASES))
            and all(item["removed"] is True for item in observer_cleanup))
        checks["all_managed_rings_closed_by_independent_watchdogs"] = (
            len(ring_cleanup) == 1 + len(NEGATIVE_CASES)
            and all(item["status"] == "RECOVERED" and item["admission_closed"] is True
                        and item["observers_removed"] is True for item in ring_cleanup))
        checks["all_receiver_issuer_children_reaped"] = (
            len(issuer_cleanup) == 1 + len(NEGATIVE_CASES)
            and all(item["reaped"] is True for item in issuer_cleanup))
        hashes = _source_digests()
        test_path = "tests/test_agent_control_receiver_source_runtime.py"
        test_file = Path(__file__).resolve().parents[2] / test_path
        hashes[test_path] = hashlib.sha256(test_file.read_bytes()).hexdigest()
        return {"schema": "liminal-receiver-source-demo-v1", "source": _source(),
            "source_files_sha256": hashes, "image_id": image_id, "checks": checks,
            "passed": all(checks.values()), "outcomes": outcomes,
            "observer_cleanup": observer_cleanup, "issuer_cleanup": issuer_cleanup, "ring_cleanup": ring_cleanup,
            "scope": {"receiver_source": "separate child-owned signing key; configured receiver DB exports only",
                "continuity_projection": "baseline collectors on the same trusted host; independently owned truth not proved",
                "collector": "may deliver or tamper public packets but cannot replace the provisioned issuer public key",
                "host": "receiver DB, issuer provisioning, host/kernel, Docker daemon and clocks remain trusted",
                "rollback": "no independently anchored storage-rollback claim",
                "already_accepted_effects": "a stop does not undo an already accepted receiver effect",
                "external_network": False, "model_calls": 0}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Immutable local Docker image ID; no automatic pull")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_demo(args.image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "checks": report["checks"], "source": report["source"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
