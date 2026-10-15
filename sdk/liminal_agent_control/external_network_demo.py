"""Bounded real-process experiment for the owned-loopback network STOP profile.

The fixture owns the authority, gateway and endpoint on one trusted host. It
does not establish unrestricted worker socket mediation or arbitrary API safety.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

from .authority import ControlError, canonical_bytes, digest
from .external_network_protocol import NETWORK_PROFILE, network_action
from .external_stop_demo import _Child, _backup, _key, _write_json
from .multi_agent import ROOT, _source

SCHEMA = "liminal-external-network-runtime-v1"
CASE_IDS = ("network_positive", "network_binding_swap", "network_stop_before_dispatch",
    "network_pending_dispatch_stop", "network_lost_begin_response", "network_lost_transport_response",
    "network_lost_finish_response", "network_restore_consumed_state", "network_restore_stopped_state",
    "network_authority_restart_outage", "network_ambiguous_endpoint", "network_cross_profile_receipt")
DESIGN = ROOT / "experiments/agent_control/preregistration_external_network.json"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[1]


def _wait_file(path: Path, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise ControlError("NETWORK_RUNTIME_BARRIER_TIMEOUT")
        time.sleep(0.01)


def _sources() -> dict[str, str]:
    paths = sorted((ROOT / "sdk").rglob("*.py")) + sorted((ROOT / "adapters").rglob("*.py"))
    paths += [ROOT / path for path in ("tests/test_agent_control_external_network_runtime.py",
        "tests/test_agent_control_external_network_authority.py",
        "tests/test_agent_control_external_network_endpoint.py",
        "tests/test_agent_control_external_network_gateway.py",
        "scripts/verify_external_network_evidence.py", "tests/test_agent_control_external_network_evidence.py",
        "scripts/verify_external_stop_evidence.py", ".github/workflows/agent-control.yml",
        "docs/AGENT_CONTROL_EXTERNAL_NETWORK.md", "README.md")]
    paths.append(DESIGN)
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def _result(client: Any, operation: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """Preserve real refusal/unavailable observations instead of fabricating effects."""
    try:
        return getattr(client, operation)(*args, **kwargs)
    except ControlError as exc:
        return {"status": "ERROR", "reason": str(exc)}


def run_demo() -> dict[str, Any]:
    """Run the preregistered matrix with real HTTP and independent SQLite effects."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .external_authority_service import HTTPExternalAuthorityClient
    from .external_checkpoint import verify_checkpoint_chain
    from .external_network_gateway import HTTPNetworkGatewayClient

    design = json.loads(DESIGN.read_text())
    if (design.get("experiment_id") != SCHEMA or design.get("scenario_ids") != list(CASE_IDS)
            or design.get("model_calls_budget") != 0 or design.get("live_internet") is not False):
        raise ControlError("NETWORK_RUNTIME_DESIGN_MISMATCH")
    outcomes: dict[str, Any] = {}
    processes: list[dict[str, Any]] = []
    cleanup: list[dict[str, Any]] = []
    authority_evidence: list[dict[str, Any]] = []
    endpoint_evidence: list[dict[str, Any]] = []
    seen_authority_pairs: set[str] = set()
    seen_endpoint_pairs: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="liminal-external-network-") as temporary:
        work = Path(temporary).resolve()
        controller = work / "controller"
        controller.mkdir(mode=0o700)
        endpoint_directory = work / "endpoint"
        endpoint_directory.mkdir(mode=0o700)
        authority_key, endpoint_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        authority_signing_file = _key(controller / "authority-signing.key", authority_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        endpoint_signing_file = _key(endpoint_directory / "endpoint-signing.key", endpoint_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        authority_receipt_file = _key(controller / "legacy-record-receipt.key")
        authority_operator_file = _key(controller / "operator.key")
        authority_request_file = _key(controller / "gateway-client.key")
        endpoint_request_file = _key(endpoint_directory / "gateway-request.key")
        gateway_operator_file = _key(work / "gateway-operator.key")
        gateway_worker_file = _key(work / "gateway-worker.key")
        authority_pin = {"authority_id": "network-fixture-controller", "key_id": "fixture-authority-ed25519",
            "public_key": authority_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        endpoint_pin = {"endpoint_id": "network-fixture-endpoint", "key_id": "fixture-endpoint-ed25519",
            "public_key": endpoint_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        authority_pin_file, endpoint_pin_file = work / "authority-pin.json", work / "endpoint-pin.json"
        _write_json(authority_pin_file, authority_pin)
        _write_json(endpoint_pin_file, endpoint_pin)
        authority_db, endpoint_db = controller / "authority.sqlite", endpoint_directory / "endpoint.sqlite"
        endpoint_port = _free_port()
        endpoint_url = "http://127.0.0.1:" + str(endpoint_port)
        authority_child: _Child | None = None
        endpoint_child: _Child | None = None
        authority_url: str | None = None
        authority_admin = authority_receiver = None
        live_gateways: list[_Child] = []

        def record_pairs(pairs: list[dict[str, Any]], target: list[dict[str, Any]], seen: set[str]) -> None:
            for pair in pairs:
                identity = digest(pair)
                if identity not in seen:
                    target.append(deepcopy(pair))
                    seen.add(identity)

        def capture(client: Any, operation: str, **params: Any) -> dict[str, Any]:
            answer = _result(client, operation, **params)
            record_pairs(client.evidence, authority_evidence, seen_authority_pairs)
            return answer

        def stop_child(child: _Child, role: str) -> None:
            cleanup.append({"role": role, **child.stop()})

        def start_authority(*, initialize: bool, port: int = 0) -> None:
            nonlocal authority_child, authority_admin, authority_receiver, authority_url
            arguments = ["--db", str(authority_db), "--authority-id", authority_pin["authority_id"],
                "--key-id", authority_pin["key_id"], "--signing-key-file", str(authority_signing_file),
                "--receipt-key-file", str(authority_receipt_file), "--operator-key-file", str(authority_operator_file),
                "--receiver-key-file", str(authority_request_file), "--profile", NETWORK_PROFILE,
                "--endpoint-pin-file", str(endpoint_pin_file), "--port", str(port)]
            if initialize:
                arguments.append("--initialize")
            authority_child = _Child("sdk.liminal_agent_control.external_authority_service", arguments)
            startup = authority_child.start()
            authority_url = startup["url"]
            processes.append({"role": "external_authority", "pid": authority_child.pid,
                "command": authority_child.command, "startup": startup, "explicit_initialization": initialize})
            authority_admin = HTTPExternalAuthorityClient(authority_url, authority_operator_file.read_bytes(),
                authority_pin, role="admin")
            authority_receiver = HTTPExternalAuthorityClient(authority_url, authority_request_file.read_bytes(),
                authority_pin, role="receiver")

        def start_endpoint(*, initialize: bool = False, flags: list[str] | None = None) -> None:
            nonlocal endpoint_child
            arguments = ["--db", str(endpoint_db), "--endpoint-id", endpoint_pin["endpoint_id"],
                "--key-id", endpoint_pin["key_id"], "--private-key-file", str(endpoint_signing_file),
                "--authority-pin-file", str(authority_pin_file), "--gateway-key-file", str(endpoint_request_file),
                "--port", str(endpoint_port), *(flags or [])]
            if initialize:
                arguments.append("--initialize")
            endpoint_child = _Child("sdk.liminal_agent_control.external_network_endpoint", arguments)
            startup = endpoint_child.start()
            if startup["url"] != endpoint_url or startup["pin"] != endpoint_pin:
                raise ControlError("NETWORK_RUNTIME_ENDPOINT_IDENTITY_CHANGED")
            processes.append({"role": "endpoint", "pid": endpoint_child.pid, "command": endpoint_child.command,
                "startup": startup, "explicit_initialization": initialize, "fixture_flags": flags or []})

        def restart_endpoint(flags: list[str] | None = None) -> None:
            assert endpoint_child is not None
            stop_child(endpoint_child, "endpoint")
            start_endpoint(flags=flags)

        def endpoint_snapshot() -> dict[str, Any]:
            # Read actual rows directly; no implementation inventory/decision helper or signing key is used.
            with sqlite3.connect("file:" + str(endpoint_db) + "?mode=ro", uri=True) as database:
                database.row_factory = sqlite3.Row
                database.execute("BEGIN")
                meta = {row["key"]: row["value"] for row in database.execute("SELECT * FROM network_endpoint_meta")}
                rows = database.execute("SELECT * FROM network_endpoint_effects ORDER BY sequence").fetchall()
                count = database.execute("SELECT COUNT(*) FROM network_endpoint_effects").fetchone()[0]
            config = json.loads(meta["configuration"])
            if config["pin"] != endpoint_pin or config["url"] != endpoint_url or count != len(rows):
                raise ControlError("NETWORK_RUNTIME_EFFECT_INVENTORY_MISMATCH")
            effects = [{**{key: row[key] for key in ("sequence", "action_id", "attempt_id", "root_id",
                "reservation_id", "body_digest", "committed_at")}, "body": json.loads(row["body_json"])} for row in rows]
            counters = {key: int(meta[key]) for key in ("commit_request_count", "query_request_count")}
            return {"endpoint_id": endpoint_pin["endpoint_id"], "pin": config["pin"], "url": config["url"],
                **counters, "effects": effects, "receipts": [json.loads(row["receipt_json"]) for row in rows],
                "requests": [{"action_id": row["action_id"], "permit_request": json.loads(row["permit_request_json"]),
                    "permit": json.loads(row["permit_json"]), "permit_digest": row["permit_digest"]} for row in rows],
                "independent_sqlite_effect_count": count,
                "independent_sqlite_action_ids": sorted(row["action_id"] for row in rows),
                "independent_sqlite_request_counts": counters,
                "observation": "actual readonly endpoint SQLite inventory"}

        def spawn_gateway(case: dict[str, Any], *, initialize: bool, flags: list[str] | None = None) -> None:
            assert authority_url is not None
            arguments = ["--db", str(case["directory"] / "gateway.sqlite"), "--gateway-id", case["gateway_id"],
                "--authority-url", authority_url, "--authority-request-key-file", str(authority_request_file),
                "--authority-pin-file", str(authority_pin_file), "--endpoint-url", endpoint_url,
                "--endpoint-request-key-file", str(endpoint_request_file), "--endpoint-pin-file", str(endpoint_pin_file),
                "--operator-key-file", str(gateway_operator_file), "--worker-key-file", str(gateway_worker_file),
                *(flags or [])]
            if initialize:
                arguments.append("--initialize")
            child = _Child("sdk.liminal_agent_control.external_network_gateway", arguments)
            startup = child.start()
            live_gateways.append(child)
            processes.append({"role": "gateway", "pid": child.pid, "command": child.command, "startup": startup,
                "explicit_initialization": initialize, "fixture_flags": flags or []})
            case.update(child=child, admin=HTTPNetworkGatewayClient(startup["url"], gateway_operator_file.read_bytes(), role="admin"),
                worker=HTTPNetworkGatewayClient(startup["url"], gateway_worker_file.read_bytes(), role="worker"))

        def gateway_inventory(case: dict[str, Any]) -> dict[str, Any]:
            inventory = case["admin"].inventory()
            if inventory["profile"] != NETWORK_PROFILE or inventory["gateway_id"] != case["gateway_id"]:
                raise ControlError("NETWORK_RUNTIME_GATEWAY_PROFILE_CHANGED")
            record_pairs(inventory["authority_evidence"], authority_evidence, seen_authority_pairs)
            record_pairs(inventory["endpoint_evidence"], endpoint_evidence, seen_endpoint_pairs)
            return inventory

        def stop_gateway(case: dict[str, Any]) -> None:
            gateway_inventory(case)
            stop_child(case["child"], "gateway")
            live_gateways.remove(case["child"])

        def new_case(name: str, *, flags: list[str] | None = None) -> dict[str, Any]:
            directory = work / name
            directory.mkdir(mode=0o700)
            root_id = "runtime:" + name
            policy = digest({"profile": NETWORK_PROFILE, "endpoint": endpoint_url, "owned_case": name})
            case = {"name": name, "directory": directory, "root_id": root_id, "policy": policy,
                "gateway_id": "gateway:" + name, "endpoint_before": endpoint_snapshot()}
            created = capture(authority_admin, "create_root", root_id=root_id,
                receiver_id=endpoint_pin["endpoint_id"], policy_digest=policy, max_actions=10, lifetime_seconds=180)
            bound = capture(authority_admin, "bind_execution", root_id=root_id, execution_id=root_id + ":worker")
            if created.get("status") == "ERROR" or bound.get("status") == "ERROR":
                raise ControlError("NETWORK_RUNTIME_ROOT_SETUP_FAILED")
            spawn_gateway(case, initialize=True, flags=flags)
            return case

        def authorize(case: dict[str, Any], name: str = "candidate") -> tuple[dict[str, Any], dict[str, Any]]:
            action = network_action(root_id=case["root_id"], execution_id=case["root_id"] + ":worker", epoch=1,
                action_id=case["root_id"] + ":" + name, attempt_id=case["root_id"] + ":attempt:" + name,
                endpoint_url=endpoint_url, marker=case["root_id"] + ":" + name)
            authorization = {"action_digest": digest(action), "policy_version": case["policy"],
                "expires_at": time.time() + 120, "receiver_id": endpoint_pin["endpoint_id"]}
            saved = _result(case["admin"], "authorize", action, authorization)
            if saved.get("status") == "ERROR":
                raise ControlError("NETWORK_RUNTIME_HOST_AUTHORIZATION_FAILED:" + saved.get("reason", ""))
            return action, authorization

        def snapshot(case: dict[str, Any]) -> dict[str, Any]:
            before_copy = gateway_inventory(case)
            stop_gateway(case)
            copied = _backup(case["directory"] / "gateway.sqlite", case["directory"] / "old-snapshot.sqlite")
            spawn_gateway(case, initialize=False)
            return {**copied, "gateway_stopped_during_copy": True, "authority_database_not_restored": True,
                "endpoint_database_not_restored": True, "gateway_state_at_snapshot": before_copy}

        def restore(case: dict[str, Any]) -> dict[str, Any]:
            before_restore = gateway_inventory(case)
            stop_gateway(case)
            copied = _backup(case["directory"] / "old-snapshot.sqlite", case["directory"] / "gateway.sqlite")
            spawn_gateway(case, initialize=False)
            after_restore = gateway_inventory(case)
            return {**copied, "gateway_stopped_during_copy": True, "authority_database_not_restored": True,
                "endpoint_database_not_restored": True, "gateway_state_before_restore": before_restore,
                "gateway_state_after_restore": after_restore}

        def finish_case(case: dict[str, Any], *, action: dict[str, Any], authorization: dict[str, Any],
                        results: dict[str, Any], checks: dict[str, bool], **extra: Any) -> None:
            after, gateway = endpoint_snapshot(), gateway_inventory(case)
            before = case["endpoint_before"]
            state = capture(authority_admin, "status", root_id=case["root_id"])
            query = capture(authority_receiver, "query", action_id=action["action_id"])
            outcomes[case["name"]] = {"action": action, "authorization": authorization, "results": results,
                "endpoint_before": before, "endpoint_after": after,
                "request_count_delta": after["commit_request_count"] - before["commit_request_count"],
                "effect_count_delta": after["independent_sqlite_effect_count"] - before["independent_sqlite_effect_count"],
                "gateway_inventory": gateway, "external_state": state, "external_query": query,
                "checks": checks, **extra}
            stop_gateway(case)

        try:
            start_authority(initialize=True)
            start_endpoint(initialize=True)

            case = new_case("network_positive")
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            state = capture(authority_admin, "status", root_id=case["root_id"])
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result}, checks={
                "one_actual_request": after["commit_request_count"] - case["endpoint_before"]["commit_request_count"] == 1,
                "one_durable_effect": after["independent_sqlite_effect_count"] - case["endpoint_before"]["independent_sqlite_effect_count"] == 1,
                "authenticated_remote_commit": result.get("status") == "COMMITTED" and result.get("effect_count") == 1,
                "external_terminal": state["committed_count"] == 1 and state["pending_count"] == 0})

            case = new_case("network_binding_swap")
            action, grant = authorize(case)
            changed: dict[str, Any] = {}
            for kind in ("endpoint", "method", "headers", "body"):
                altered = deepcopy(action)
                if kind == "endpoint":
                    altered["arguments"]["url"] = "http://127.0.0.1:1/v1/record"
                elif kind == "method":
                    altered["arguments"]["method"] = "GET"
                elif kind == "headers":
                    altered["arguments"]["headers"] = {"X-Injected": "synthetic"}
                else:
                    altered["arguments"]["body"]["synthetic_marker"] = "changed:synthetic:marker"
                changed[kind] = {"action": altered, "result": _result(case["worker"], "execute", altered)}
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results=changed, checks={
                "every_swap_rejected": all(item["result"].get("status") in {"DENIED", "ERROR"} for item in changed.values()),
                "zero_actual_requests": after["commit_request_count"] == case["endpoint_before"]["commit_request_count"],
                "zero_durable_effects": after["independent_sqlite_effect_count"] == case["endpoint_before"]["independent_sqlite_effect_count"]})

            case = new_case("network_stop_before_dispatch")
            action, grant = authorize(case)
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            result = _result(case["worker"], "execute", action)
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result}, stop_response=stopped, checks={
                "stop_acknowledged": stopped["status"] == "STOPPED" and stopped["pending_count"] == 0,
                "old_authorization_denied": result.get("status") == "DENIED",
                "zero_actual_requests": after["commit_request_count"] == case["endpoint_before"]["commit_request_count"],
                "zero_durable_effects": after["independent_sqlite_effect_count"] == case["endpoint_before"]["independent_sqlite_effect_count"]})

            reached, release = work / "endpoint-reached", work / "endpoint-release"
            restart_endpoint(["--barrier-reached-file", str(reached), "--barrier-release-file", str(release)])
            case = new_case("network_pending_dispatch_stop")
            action, grant = authorize(case)
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(_result, case["worker"], "execute", action)
                try:
                    _wait_file(reached)
                    held_inventory = endpoint_snapshot()
                    stopped = capture(authority_admin, "stop", root_id=case["root_id"])
                finally:
                    release.write_text("release\n")
                result = pending.result(timeout=10)
            final = capture(authority_admin, "status", root_id=case["root_id"])
            finish_case(case, action=action, authorization=grant, results={"execute": result},
                stop_response=stopped, held_endpoint_inventory=held_inventory, final_stop_state=final, checks={
                "actual_request_held_before_commit": held_inventory["commit_request_count"] - case["endpoint_before"]["commit_request_count"] == 1
                    and held_inventory["independent_sqlite_effect_count"] == case["endpoint_before"]["independent_sqlite_effect_count"],
                "no_early_stop_ack": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1,
                "original_request_completed": result.get("status") == "COMMITTED",
                "stop_ack_after_terminal": final["state"] == "STOPPED" and final["pending_count"] == 0})
            restart_endpoint()

            case = new_case("network_lost_begin_response", flags=["--drop-begin-response"])
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            retry = _result(case["worker"], "execute", action)
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result, "retry": retry},
                stop_response=stopped, checks={
                "lost_delivery_is_unknown": result.get("status") == "UNKNOWN",
                "retry_never_reissues": retry.get("status") in {"UNKNOWN", "DENIED"},
                "actual_permit_stays_pending": stopped["status"] == "STOP_PENDING" and stopped["issued_count"] == 1
                    and stopped["pending_count"] == 1,
                "no_transport_after_unknown": after["commit_request_count"] == case["endpoint_before"]["commit_request_count"]})

            restart_endpoint(["--drop-first-commit-response"])
            case = new_case("network_lost_transport_response")
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            unknown_state = capture(authority_admin, "status", root_id=case["root_id"])
            after_loss = endpoint_snapshot()
            reconciled = _result(case["worker"], "reconcile", action["action_id"])
            after_reconcile = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant,
                results={"execute": result, "reconcile": reconciled}, after_loss=after_loss,
                unresolved_external_state=unknown_state, checks={
                "actual_commit_despite_response_loss": after_loss["independent_sqlite_effect_count"] - case["endpoint_before"]["independent_sqlite_effect_count"] == 1,
                "unknown_before_reconciliation": result.get("status") == "UNKNOWN" and result.get("effect_count") is None
                    and unknown_state["pending_count"] == 1,
                "authenticated_reconciliation": reconciled.get("status") == "COMMITTED" and reconciled.get("effect_count") == 1,
                "query_only_no_second_post": after_reconcile["commit_request_count"] == after_loss["commit_request_count"]})
            restart_endpoint()

            case = new_case("network_lost_finish_response", flags=["--drop-finish-response"])
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            settled_before = capture(authority_receiver, "query", action_id=action["action_id"])
            after_loss = endpoint_snapshot()
            reconciled = _result(case["worker"], "reconcile", action["action_id"])
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result, "reconcile": reconciled},
                settled_before_recovery=settled_before, after_loss=after_loss, checks={
                "authority_already_terminal": settled_before.get("status") == "COMMITTED" or
                    settled_before.get("receipt", {}).get("status") == "COMMITTED",
                "recovery_observes_terminal": reconciled.get("status") == "COMMITTED",
                "no_second_post": after["commit_request_count"] == after_loss["commit_request_count"],
                "one_original_effect": after["independent_sqlite_effect_count"] - case["endpoint_before"]["independent_sqlite_effect_count"] == 1})

            case = new_case("network_restore_consumed_state")
            action, grant = authorize(case)
            saved = snapshot(case)
            first = _result(case["worker"], "execute", action)
            before_restore = endpoint_snapshot()
            restored = restore(case)
            retry = _result(case["worker"], "execute", action)
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": first, "retry": retry},
                snapshot=saved, restore=restored, endpoint_before_restore=before_restore, checks={
                "first_request_committed": first.get("status") == "COMMITTED",
                "restored_grant_cannot_redispatch": retry.get("status") in {"UNKNOWN", "DENIED", "COMMITTED"}
                    and after["commit_request_count"] == before_restore["commit_request_count"],
                "one_surviving_endpoint_effect": after["independent_sqlite_effect_count"] - case["endpoint_before"]["independent_sqlite_effect_count"] == 1})

            case = new_case("network_restore_stopped_state")
            action, grant = authorize(case)
            saved = snapshot(case)
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            restored = restore(case)
            result = _result(case["worker"], "execute", action)
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result}, snapshot=saved,
                restore=restored, stop_response=stopped,
                local_clock_restore="NOT_APPLICABLE: gateway has no local-clock authorization source", checks={
                "external_stop_survives": stopped["status"] == "STOPPED" and stopped["epoch"] > action["epoch"],
                "restored_authorization_denied": result.get("status") == "DENIED",
                "zero_requests_after_restore": after["commit_request_count"] == case["endpoint_before"]["commit_request_count"]})

            case = new_case("network_authority_restart_outage")
            action, grant = authorize(case)
            first = _result(case["worker"], "execute", action)
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            initial_pid = authority_child.pid
            authority_port = urlparse(authority_url).port
            stop_child(authority_child, "external_authority")
            start_authority(initialize=False, port=authority_port)
            restarted_state = capture(authority_admin, "status", root_id=case["root_id"])
            retry = _result(case["worker"], "execute", action)
            query = capture(authority_receiver, "query", action_id=action["action_id"])
            fresh_case = new_case("outage_positive_control")
            outage_action, outage_grant = authorize(fresh_case, "outage-candidate")
            stop_child(authority_child, "external_authority")
            before_outage = endpoint_snapshot()
            unavailable = _result(fresh_case["worker"], "execute", outage_action)
            after_outage = endpoint_snapshot()
            start_authority(initialize=False, port=authority_port)
            recovered_action, recovered_grant = authorize(fresh_case, "fresh-after-outage")
            recovered = _result(fresh_case["worker"], "execute", recovered_action)
            recovery_inventory = gateway_inventory(fresh_case)
            stop_gateway(fresh_case)
            finish_case(case, action=action, authorization=grant,
                results={"execute": first, "retry": retry, "outage": unavailable, "recovery": recovered},
                stop_response=stopped, restarted_external_state=restarted_state, restarted_external_query=query,
                outage_action=outage_action, outage_authorization=outage_grant,
                recovery_action=recovered_action, recovery_authorization=recovered_grant,
                outage_endpoint_before=before_outage, outage_endpoint_after=after_outage,
                recovery_gateway_inventory=recovery_inventory, checks={
                "different_authority_process": authority_child.pid != initial_pid,
                "stop_and_consumption_survive_restart": restarted_state["state"] == "STOPPED"
                    and restarted_state["epoch"] == stopped["epoch"] and restarted_state["committed_count"] == 1,
                "outage_no_fresh_transport": after_outage["commit_request_count"] == before_outage["commit_request_count"]
                    and unavailable.get("status") in {"UNKNOWN", "DENIED"},
                "fresh_recovery_control": recovered.get("status") == "COMMITTED"})

            restart_endpoint(["--drop-first-commit-response", "--query-unavailable"])
            case = new_case("network_ambiguous_endpoint")
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            reconciled = _result(case["worker"], "reconcile", action["action_id"])
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant, results={"execute": result, "reconcile": reconciled},
                stop_response=stopped, checks={
                "actual_effect_is_independently_visible": after["independent_sqlite_effect_count"] - case["endpoint_before"]["independent_sqlite_effect_count"] == 1,
                "missing_endpoint_proof_preserves_unknown": result.get("status") == "UNKNOWN" and reconciled.get("status") == "UNKNOWN"
                    and reconciled.get("effect_count") is None,
                "no_false_stop_or_zero_claim": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1,
                "query_never_reposts": after["commit_request_count"] - case["endpoint_before"]["commit_request_count"] == 1})
            restart_endpoint()

            case = new_case("network_cross_profile_receipt", flags=["--drop-begin-response"])
            action, grant = authorize(case)
            result = _result(case["worker"], "execute", action)
            pending = capture(authority_receiver, "query", action_id=action["action_id"])
            reservation = pending["reservation_id"]
            records_receipt = {"schema": "liminal.receiver.receipt.v1", "status": "COMMITTED", "effect_count": 1,
                "action_id": action["action_id"], "enforcement_profile": "external_governed_v1"}
            wrong_profile = capture(authority_receiver, "finish", reservation_id=reservation, receipt=records_receipt)
            altered = deepcopy(outcomes["network_positive"]["results"]["execute"]["receipt"])
            altered["action_id"] = action["action_id"]
            altered["reservation_id"] = reservation
            altered_proof = capture(authority_receiver, "finish", reservation_id=reservation, receipt=altered)
            stopped = capture(authority_admin, "stop", root_id=case["root_id"])
            after = endpoint_snapshot()
            finish_case(case, action=action, authorization=grant,
                results={"execute": result, "records_profile_finish": wrong_profile, "altered_endpoint_finish": altered_proof},
                records_profile_receipt=records_receipt, altered_endpoint_receipt=altered, stop_response=stopped, checks={
                "records_receipt_rejected": wrong_profile.get("status") == "ERROR",
                "altered_endpoint_receipt_rejected": altered_proof.get("status") == "ERROR",
                "reservation_not_cleared": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1,
                "no_endpoint_request": after["commit_request_count"] == case["endpoint_before"]["commit_request_count"]})

            checkpoint_export = capture(authority_admin, "checkpoints")
            entries = checkpoint_export["entries"] if isinstance(checkpoint_export, dict) else checkpoint_export
            verification = verify_checkpoint_chain(entries, authority_id=authority_pin["authority_id"],
                signer_id=authority_pin["authority_id"], key_id=authority_pin["key_id"], public_key=authority_pin["public_key"])
            final_endpoint_inventory = endpoint_snapshot()
        finally:
            for child in list(live_gateways):
                stop_child(child, "gateway")
            if endpoint_child is not None and endpoint_child.process is not None and endpoint_child.process.poll() is None:
                stop_child(endpoint_child, "endpoint")
            if authority_child is not None and authority_child.process is not None and authority_child.process.poll() is None:
                stop_child(authority_child, "external_authority")

    checks = {name + ":" + key: value for name, outcome in outcomes.items() for key, value in outcome["checks"].items()}
    checks.update({"all_cases_collected": set(outcomes) == set(CASE_IDS),
        "all_processes_reaped": all(item["reaped"] for item in cleanup)
            and {item["pid"] for item in processes} == {item["pid"] for item in cleanup},
        "separate_child_processes": all(item["pid"] != os.getpid() for item in processes),
        "all_three_service_roles_executed": {"external_authority", "gateway", "endpoint"}.issubset({item["role"] for item in processes}),
        "authority_key_not_delivered_to_gateway_or_endpoint": all(str(authority_signing_file) not in item["command"]
            for item in processes if item["role"] != "external_authority"),
        "public_checkpoint_signatures_verified": verification["verification_status"] == "LOCAL_SIGNATURE_ONLY"})
    source = _source()
    source["scope"] = "checked-out commit/tree; source_files_sha256 binds actual runtime inputs"
    return {"schema": SCHEMA, "source": source, "source_files_sha256": _sources(), "preregistration": design,
        "controller_pid": os.getpid(), "authority_public_pin": authority_pin, "endpoint_public_pin": endpoint_pin,
        "outcomes": outcomes, "checks": checks, "passed": all(checks.values()),
        "authority_evidence": authority_evidence, "endpoint_evidence": endpoint_evidence,
        "authority_checkpoints": entries, "checkpoint_anchor": verification["tip"],
        "checkpoint_anchor_provenance": "collector-observed tip; no independently owned latest-anchor service",
        "checkpoint_verification": verification, "endpoint_final_inventory": final_endpoint_inventory,
        "processes": processes, "cleanup": cleanup,
        "scope": {"actual_loopback_http": True, "distinct_authority_gateway_endpoint_processes": True,
            "separate_sqlite_databases": True, "actual_synthetic_sqlite_effects": True, "private_keys_bundled": False,
            "endpoint_receipts_publicly_verifiable": True, "independent_latest_anchor": "NOT_ESTABLISHED",
            "authority_pin_provenance": "fixture-generated", "endpoint_pin_provenance": "fixture-generated",
            "model_calls": 0, "external_network": "NOT_RUN", "docker": "NOT_RUN",
            "command_profile": "NOT_RUN", "full_worker_socket_mediation": "NOT_ESTABLISHED",
            "sender_quiescence": "NOT_ESTABLISHED", "external_human_reproduction": "NOT_ESTABLISHED"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_demo()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, report)
    print(json.dumps({"passed": report["passed"], "source": report["source"],
                      "report": str(args.output.resolve())}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
