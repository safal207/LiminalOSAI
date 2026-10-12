"""Owned Docker observer services with separate read-only evidence exports.

The services generate their signing keys internally. Docker separation and
source-bound statements are checked; all collectors still have one trusted host
owner. No external network, model API or semantic-independence claim is made.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import secrets
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authority import ControlError, canonical_bytes, digest
from .brakes_store import SessionAuthority
from .broker import Broker
from .center_continuity import CenterContinuityStore
from .center_demo import _action, _project
from .multi_agent import _source, _source_digests
from .observer_auth import ObserverAuthStore, sign_attestation
from .observer_auth_demo import ROLES, _commit, _evidence, _reject
from .observer_ring import ObserverRingStore
from .observer_sources import ObserverSourceStore
from .orientation import OrientationStore
from .receiver import Receiver


def _setup(work: Path, clock: list[float], *, public_keys: list[dict] | None = None) -> dict:
    """Enroll source identities before seed; fixture keys are unit-test-only."""
    work.mkdir(parents=True, exist_ok=True)
    authority = SessionAuthority(work / "authority.sqlite", clock=lambda: clock[0])
    policy = digest("owned isolated observer demonstration")
    authority.create_session("campaign", controller_id="operator", policy_digest=policy,
        objective_digest=digest("source-bound authenticated evidence for bounded transitions"),
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
        "required_roles": list(ROLES), "max_attestation_age_seconds": 30, "max_attestations": 100})
    private_keys = None
    if public_keys is None:
        private_keys = {role: secrets.token_bytes(32) for role in ROLES}
        public_keys = [{"observer_id": role + "-observer", "key_id": role + "-key",
            "public_key": Ed25519PrivateKey.from_private_bytes(private_keys[role]).public_key()
                          .public_bytes_raw().hex()} for role in ROLES]
    auth = ObserverAuthStore(authority)
    auth.install("campaign", {"keys": public_keys, "max_challenge_age_seconds": 15, "max_challenges": 100})
    source = ObserverSourceStore(authority)
    source.install("campaign", {"sources": [{"observer_id": role + "-observer",
        "source_id": role + "-collector"} for role in ROLES], "max_source_age_seconds": 5})
    # The forecast collector copies the installed immutable policy separately
    # from the authority DB. The audit collector maintains its own append-only
    # copy of exported events. Neither export is a separately owned service.
    collectors = work / "collectors"
    collectors.mkdir()
    policy_path = collectors / "installed-policy.json"
    policy_path.write_bytes(canonical_bytes({"center_profile": center.snapshot("campaign")["profile"],
        "orientation_profile": graph.snapshot("campaign")["profile"]}))
    policy_path.chmod(0o444)
    graph.seed("campaign", "alpha", "center-a", evidence_digest=digest("owned initial state"),
               observed_at=clock[0])
    return {"authority": authority, "receiver": receiver, "broker": broker,
        "graph": graph, "center": center, "ring": ring, "auth": auth, "source": source,
        "policy": policy, "clock": clock, "private_keys": private_keys,
        "broker_key": broker_key, "receipt_key": receipt_key,
        "audit_path": collectors / "audit.jsonl", "policy_path": policy_path}


def _prepare(env: dict, name: str = "container:write", *, deadline: float = 110) -> dict:
    action = _action(name)
    _project(env, action, "writea", 0, env["clock"][0], deadline)
    return action


def _request(env: dict, action: dict, role: str, *, valid_until: float = 110) -> dict:
    return env["auth"].challenge(action["action_id"], role + "-observer", valid_until)


def _audit_export(path: Path, events: list[dict]) -> list[dict]:
    existing = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    if len(existing) > len(events) or existing != events[:len(existing)]:
        raise ControlError("OBSERVER_COLLECTOR_HISTORY_DIVERGED")
    with path.open("ab") as stream:
        for event in events[len(existing):]:
            stream.write(canonical_bytes(event) + b"\n")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _packet(env: dict, action: dict, role: str, request: dict) -> dict:
    payload = _evidence(env, action, role)
    if role == "reality":
        snapshot = env["receiver"].snapshot("campaign", "alpha")
        if not env["receiver"].verify_receipt(snapshot):
            raise ControlError("OBSERVER_COLLECTOR_RECEIVER_SIGNATURE_INVALID")
        payload.update(receiver_records=env["receiver"].records(), receiver_snapshot=snapshot,
                       receiver_snapshot_verified_by_host=True)
    elif role == "continuity":
        payload["events"] = _audit_export(env["audit_path"], payload["events"])
        payload["collector_kind"] = "append-only exported audit copy"
    else:
        installed = json.loads(env["policy_path"].read_text(encoding="utf-8"))
        payload.update(installed)
        payload["collector_kind"] = "installed immutable policy export"
    return {"source_id": role + "-collector", "role": role,
        "request_digest": digest(request), "observed_at": env["clock"][0], "payload": payload}


def _unit_support(env: dict, action: dict, *, roles=ROLES, packets: dict | None = None) -> list[dict]:
    """Authenticated source fixtures for non-Docker effect-boundary tests."""
    if env["private_keys"] is None:
        raise ControlError("fixture signing keys are unavailable for container identities")
    results = []
    for role in roles:
        request = _request(env, action, role)
        packet = _packet(env, action, role, request)
        if packets is not None:
            packets[role] = {"request": request, "packet": packet}
        env["source"].bind(request, packet)
        envelope = sign_attestation(request, private_key=env["private_keys"][role], verdict="SUPPORT",
            evidence_digest=digest(packet), observed_at=env["clock"][0], valid_until=request["valid_until"])
        results.append(env["auth"].ingest(envelope))
    return results


def _result(env: dict, action: dict, *, ingestion: dict | None = None) -> dict:
    result = _commit(env, action)
    return {"result": result, "record_count": len(env["receiver"].records()),
        "action_count": env["authority"].status("campaign")["action_count"],
        "ingestion": ingestion, "ring": env["ring"].snapshot("campaign"),
        "sources": env["source"].snapshot("campaign")}


def _docker_command(arguments: list[str], *, timeout: float = 10) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *arguments], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False, timeout=timeout)


def _container_probe(container_id: str, nonce: str, *, authority_path: Path,
                     foreign_sources: list[Path], foreign_nonces: list[str], foreign_pids: list[int]) -> dict:
    inspected = _docker_command(["inspect", container_id])
    if inspected.returncode != 0:
        raise ControlError("OBSERVER_DEMO_INSPECT_FAILED")
    document = json.loads(inspected.stdout)[0]
    evidence_mount = next(mount for mount in document.get("Mounts", []) if mount["Destination"] == "/evidence")
    source_directory = Path(evidence_mount["Source"])
    packet_path = source_directory / (nonce + ".json")
    packet_before = packet_path.read_bytes()
    # Deliberately permissive public fixture modes make a RW mount writable to
    # UID 65532. A failure with EROFS then demonstrates the RO mount, rather than
    # ordinary file-owner permissions. The enclosing temporary parent is 0700.
    packet_path.chmod(0o666)
    source_directory.chmod(0o777)
    # Probe results expose booleans, never key bytes. These are trusted-host
    # probes, not an executable-command capability given to the agent.
    script = (
        "import errno,json,os,pathlib,socket,stat; "
        "key=pathlib.Path('/tmp/observer-private/key.bin'); "
        "r={'own_key_readable':key.is_file() and len(key.read_bytes())==32,"
        "'host_socket_absent':not pathlib.Path('/var/run/docker.sock').exists(),"
        "'authority_db_absent':not pathlib.Path(" + repr(str(authority_path)) + ").exists(),"
        "'foreign_evidence_absent':not pathlib.Path('/evidence-other').exists(),"
        "'foreign_key_path_absent':not pathlib.Path('/tmp/foreign-observer/key.bin').exists()}; "
        "r['other_actual_nonce_files_absent']=all(not (pathlib.Path('/evidence')/n).exists() for n in "
            + repr([nonce + ".json" for nonce in foreign_nonces]) + "); "
        "r['other_actual_host_source_paths_absent']=all(not pathlib.Path(p).exists() for p in "
            + repr([str(path) for path in foreign_sources]) + "); "
        "r['other_actual_host_pid_key_paths_absent']=all(not pathlib.Path('/proc/'+str(p)+'/root/tmp/observer-private/key.bin').exists() for p in "
            + repr(foreign_pids) + "); "
        "r['other_source_parent_traversal_absent']=all(not (pathlib.Path('/evidence')/'..'/p).exists() for p in "
            + repr([path.name for path in foreign_sources]) + "); "
        "p=pathlib.Path('/evidence')/" + repr(nonce + ".json") + "; "
        "r['own_evidence_mode_permits_write']=stat.S_IMODE(p.stat().st_mode)==0o666; "
        "r['source_directory_mode_permits_write']=stat.S_IMODE(p.parent.stat().st_mode)==0o777; "
        "r['root_probe_directory_mode_permits_write']=stat.S_IMODE(pathlib.Path('/var/tmp').stat().st_mode)==0o1777; "
        "\ntry:\n p.open('wb').write(b'forged');r['own_evidence_write_returns_erofs']=False"
        "\nexcept OSError as e:\n r['own_evidence_write_returns_erofs']=e.errno==errno.EROFS"
        "\ntry:\n (pathlib.Path('/var/tmp')/" + repr("liminal-owned-probe-" + nonce) + ").write_text('x');r['root_write_returns_erofs']=False"
        "\nexcept OSError as e:\n r['root_write_returns_erofs']=e.errno==errno.EROFS"
        "\np=pathlib.Path('/tmp/liminal-owned-tmp-probe')"
        "\ntry:\n p.write_text('x');r['private_tmp_writable']=True;p.unlink()"
        "\nexcept OSError:\n r['private_tmp_writable']=False"
        "\ns=socket.socket();s.settimeout(.1)"
        "\ntry:\n s.connect(('198.51.100.1',443));r['outbound_connect_denied']=False"
        "\nexcept OSError:\n r['outbound_connect_denied']=True"
        "\nfinally:\n s.close()"
        "\nprint(json.dumps(r,sort_keys=True))"
    )
    try:
        observed = _docker_command(["exec", container_id, "/usr/local/bin/python", "-I", "-c", script])
        packet_unchanged = packet_path.read_bytes() == packet_before
    finally:
        packet_path.chmod(0o644)
        source_directory.chmod(0o755)
    if observed.returncode != 0:
        raise ControlError("OBSERVER_DEMO_PROBE_FAILED")
    probe = json.loads(observed.stdout)
    probe["public_packet_bytes_unchanged"] = packet_unchanged
    host = document["HostConfig"]
    return {"container_id": container_id, "image_id": document["Image"],
        "user": document["Config"]["User"], "mounts": document.get("Mounts", []),
        "isolation": {"network_mode": host["NetworkMode"], "readonly_rootfs": host["ReadonlyRootfs"],
            "cap_drop": host.get("CapDrop"), "security_options": host.get("SecurityOpt"),
            "memory_bytes": host.get("Memory"), "nano_cpus": host.get("NanoCpus"),
            "pids_limit": host.get("PidsLimit"), "tmpfs": host.get("Tmpfs")},
        "probes": probe}


def run_demo(image_id: str) -> dict:
    from .observer_container import DockerObserver, validate_source_directories
    from .observer_sources import write_source_packet

    outcomes, checks, containers, cleanup, services = {}, {}, [], [], {}
    with tempfile.TemporaryDirectory(prefix="liminal-observer-containers-") as temporary:
        work = Path(temporary)
        directories = {role: work / (role + "-source") for role in ROLES}
        for directory in directories.values():
            directory.mkdir(mode=0o755)
        validate_source_directories(list(directories.values()))
        try:
            enrollments = []
            for role in ROLES:
                service = DockerObserver(image_id=image_id, observer_id=role + "-observer", role=role,
                    key_id=role + "-key", source_directory=directories[role])
                services[role] = service
                enrollment = service.start()
                enrollments.append({key: enrollment[key] for key in ("observer_id", "key_id", "public_key")})

            def fresh(name):
                return _setup(work / name, [100.0], public_keys=enrollments)

            def observe(env, action, role, *, packet=None, write=True, bind=True):
                request = _request(env, action, role)
                packet = _packet(env, action, role, request) if packet is None else packet(request)
                if bind:
                    env["source"].bind(request, packet)
                if write:
                    write_source_packet(directories[role], request, packet)
                result = services[role].attest(request)
                if result["envelope"] is not None:
                    env["auth"].ingest(result["envelope"])
                return {"request": request, "packet": packet, **result}

            env = fresh("positive")
            proposed = _prepare(env)
            witnesses = [observe(env, proposed, role) for role in ROLES]
            host_pids = {role: json.loads(_docker_command(["inspect", services[role].container_id]).stdout)[0]["State"]["Pid"]
                         for role in ROLES}
            for role, witness in zip(ROLES, witnesses):
                containers.append({"role": role, "enrollment": next(item for item in enrollments
                    if item["observer_id"] == role + "-observer"),
                    **_container_probe(services[role].container_id, witness["request"]["nonce"],
                        authority_path=env["authority"].db_path,
                        foreign_sources=[directories[other] for other in ROLES if other != role],
                        foreign_nonces=[other["request"]["nonce"] for other in witnesses
                                        if other["request"]["role"] != role],
                        foreign_pids=[host_pids[other] for other in ROLES if other != role])})
            outcomes["positive"] = {**_result(env, proposed), "witnesses": witnesses,
                "authentication": env["auth"].snapshot("campaign"),
                "receiver_snapshot": env["receiver"].snapshot("campaign", "alpha")}
            checks["three_distinct_containers_and_public_keys"] = (
                len({item["container_id"] for item in containers}) == 3
                and len({item["public_key"] for item in enrollments}) == 3)
            checks["three_source_bound_roles_allow_one_actual_effect"] = (
                outcomes["positive"]["result"]["status"] == "COMMITTED"
                and outcomes["positive"]["record_count"] == 1)
            checks["actual_container_probes_pass"] = all(all(item["probes"].values()) for item in containers)
            replacement = deepcopy(witnesses[0]["packet"])
            replacement["payload"]["replacement"] = True
            refused = _reject(lambda: write_source_packet(directories[ROLES[0]], witnesses[0]["request"], replacement))
            checks["public_packet_writer_refuses_replacement"] = refused == {
                "status": "REJECTED", "reason": "OBSERVER_SOURCE_BINDING_IMMUTABLE"}
            checks["inspection_confirms_isolation_bounds"] = all(
                item["image_id"] == image_id and item["user"] in {"65532", "65532:65532"}
                and item["isolation"]["network_mode"] == "none"
                and item["isolation"]["readonly_rootfs"] is True
                and "ALL" in (item["isolation"]["cap_drop"] or [])
                and any(option.startswith("no-new-privileges") for option in item["isolation"]["security_options"] or [])
                and 0 < item["isolation"]["memory_bytes"] <= 256 * 1024 * 1024
                and 0 < item["isolation"]["nano_cpus"] <= 1000000000
                and 0 < item["isolation"]["pids_limit"] <= 64
                and {mount["Destination"] for mount in item["mounts"] if mount["Type"] == "bind"} == {"/evidence", "/sdk"}
                and len([mount for mount in item["mounts"] if mount["Type"] == "bind"]) == 2
                and all(mount["Destination"] in {"/evidence", "/sdk"} and mount["RW"] is False
                    for mount in item["mounts"] if mount["Type"] == "bind")
                and next(mount["Source"] for mount in item["mounts"] if mount["Destination"] == "/evidence")
                    == str(directories[item["role"]])
                and next(mount["Source"] for mount in item["mounts"] if mount["Destination"] == "/sdk")
                    == str(Path(__file__).resolve().parents[1]) for item in containers)

            env = fresh("stale_source")
            proposed = _prepare(env)
            for role in ROLES:
                observe(env, proposed, role)
            env["clock"][0] = 106
            outcomes["stale_source"] = _result(env, proposed)

            env = fresh("missing_file")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            absent = observe(env, proposed, ROLES[2], write=False)
            outcomes["missing_file"] = {**_result(env, proposed), "process": absent["process"]}
            checks["missing_own_file_supplies_no_statement"] = absent["envelope"] is None

            env = fresh("incomplete_reality")
            proposed = _prepare(env)
            for role in ROLES[1:]:
                observe(env, proposed, role)

            def incomplete_reality(request):
                packet = _packet(env, proposed, ROLES[0], request)
                del packet["payload"]["receiver_snapshot"]
                return packet

            incomplete = observe(env, proposed, ROLES[0], packet=incomplete_reality)
            outcomes["incomplete_reality"] = {**_result(env, proposed), "witness": incomplete}
            checks["missing_receiver_evidence_yields_signed_unknown"] = (
                incomplete["envelope"] is not None and incomplete["envelope"]["verdict"] == "UNKNOWN")

            env = fresh("cross_role")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            request = _request(env, proposed, ROLES[2])
            foreign = _packet(env, proposed, ROLES[2], request)
            foreign.update(role="continuity", source_id="continuity-collector")
            rejected = _reject(lambda: env["source"].bind(request, foreign))
            # The safe writer rejects a mismatched packet before publishing.
            writer_rejection = _reject(lambda: write_source_packet(directories[ROLES[2]], request, foreign))
            outcomes["cross_role"] = {**_result(env, proposed, ingestion=rejected), "writer": writer_rejection}

            env = fresh("source_mismatch")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            request = _request(env, proposed, ROLES[2])
            bound = _packet(env, proposed, ROLES[2], request)
            env["source"].bind(request, bound)
            changed = deepcopy(bound)
            changed["payload"]["collector_kind"] = "replacement export"
            write_source_packet(directories[ROLES[2]], request, changed)
            signed = services[ROLES[2]].attest(request)
            rejected = _reject(lambda: env["auth"].ingest(signed["envelope"]))
            outcomes["source_mismatch"] = {**_result(env, proposed, ingestion=rejected), "process": signed["process"]}

            env = fresh("veto")
            proposed = _prepare(env)
            for role in ROLES:
                observe(env, proposed, role)

            def contradiction(request):
                packet = _packet(env, proposed, ROLES[0], request)
                packet["payload"]["state"]["node_id"] = "work"
                return packet

            veto = observe(env, proposed, ROLES[0], packet=contradiction)
            outcomes["valid_veto"] = {**_result(env, proposed), "veto": veto}
            checks["source_contradiction_yields_valid_signed_veto"] = (
                veto["envelope"] is not None and veto["envelope"]["verdict"] == "VETO")

            env = fresh("no_binding")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            request = _request(env, proposed, ROLES[2])
            packet = _packet(env, proposed, ROLES[2], request)
            write_source_packet(directories[ROLES[2]], request, packet)
            signed = services[ROLES[2]].attest(request)
            rejected = _reject(lambda: env["auth"].ingest(signed["envelope"]))
            outcomes["no_binding"] = _result(env, proposed, ingestion=rejected)

            env = fresh("restart")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            restarted = SessionAuthority(env["authority"].db_path, clock=lambda: env["clock"][0])
            env["authority"] = restarted
            env["receiver"] = Receiver(restarted.db_path, env["broker_key"], env["receipt_key"],
                admission_controller=restarted)
            env["auth"] = ObserverAuthStore(restarted)
            request = _request(env, proposed, ROLES[2])
            packet = _packet(env, proposed, ROLES[2], request)
            write_source_packet(directories[ROLES[2]], request, packet)
            signed = services[ROLES[2]].attest(request)
            rejected = _reject(lambda: env["auth"].ingest(signed["envelope"]))
            outcomes["restart"] = _result(env, proposed, ingestion=rejected)

            env = fresh("missing_service")
            proposed = _prepare(env)
            for role in ROLES[:2]:
                observe(env, proposed, role)
            stopped = services[ROLES[2]].stop()
            absent = observe(env, proposed, ROLES[2])
            outcomes["missing_service"] = {**_result(env, proposed), "process": absent["process"], "stop": stopped}
            checks["stopped_service_supplies_no_statement"] = absent["envelope"] is None and stopped["removed"] is True

            expected = {"stale_source": "OBSERVER_SOURCE_STALE", "missing_file": "OBSERVER_RING_ROLE_REQUIRED",
                "incomplete_reality": "OBSERVER_RING_UNKNOWN",
                "cross_role": "OBSERVER_RING_ROLE_REQUIRED", "source_mismatch": "OBSERVER_RING_ROLE_REQUIRED",
                "valid_veto": "OBSERVER_RING_VETO", "no_binding": "OBSERVER_RING_ROLE_REQUIRED",
                "restart": "OBSERVER_RING_ROLE_REQUIRED", "missing_service": "OBSERVER_RING_ROLE_REQUIRED"}
            for name, reason in expected.items():
                case = outcomes[name]
                checks[name + "_denied_before_effect"] = (
                    case["result"]["status"] == "DENIED" and case["result"]["reason"] == reason
                    and case["record_count"] == 0 and case["action_count"] == 0)
            checks["signed_payload_replacement_rejected"] = outcomes["source_mismatch"]["ingestion"] == {
                "status": "REJECTED", "reason": "OBSERVER_SOURCE_BINDING_MISMATCH"}
            checks["source_binding_remains_mandatory_after_restart"] = all(
                outcomes[name]["ingestion"] == {"status": "REJECTED", "reason": "OBSERVER_SOURCE_BINDING_REQUIRED"}
                for name in ("no_binding", "restart"))
        finally:
            for service in services.values():
                cleanup.append(service.stop())
        checks["all_owned_containers_removed"] = len(cleanup) == 3 and all(item["removed"] is True for item in cleanup)
        return {"schema": "liminal-isolated-observers-demo-v1", "source": _source(),
            "source_digests": _source_digests(), "image_id": image_id, "containers": containers,
            "cleanup": cleanup, "checks": checks, "passed": all(checks.values()), "outcomes": outcomes,
            "scope": {"mode": "executed Docker services, internal keys, source-bound read-only role exports",
                "collector_ownership": "separate mounted exports of one trusted host; not independently owned sources",
                "reality_source": "actual receiver records and signed snapshot; host exporter verifies receiver HMAC",
                "continuity_source": "append-only copied actual center events in a separate audit file",
                "projection_source": "copied installed immutable policy and center schedule",
                "private_keys": "generated inside each container tmpfs; exported only public enrollment",
                "host_authority": "Docker daemon, enrollment, exporters, DB, clock and policy remain trusted",
                "isolation_limit": "shared kernel and Docker daemon; containment is bounded by tested configuration",
                "external_network": False, "model_calls": 0, "semantic_truth_proved": False,
                "already_accepted_effects": "holds do not undo already accepted receiver effects"}}


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
