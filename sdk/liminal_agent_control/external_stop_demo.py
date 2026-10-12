"""Real loopback processes: external STOP survives local receiver rollback.

This fixture owns both processes on a trusted host. Their databases and keys
are separate, but this is not protection against a compromised host or operator.
Only harmless synthetic SQLite records are written. No model is invoked.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

from .authority import ControlError, canonical_bytes, digest
from .brakes_store import SessionAuthority
from .multi_agent import ROOT, _source
from .receiver import HTTPReceiverClient

SCHEMA = "liminal-external-stop-runtime-v1"
CASE_IDS = ("positive", "stop_restore", "terminal_restore", "pending_duplicate",
            "authority_restart", "authority_outage", "split_api_denied", "unsafe_local_restore")
DESIGN = ROOT / "experiments/agent_control/preregistration_external_stop.json"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _key(path: Path, value: bytes | None = None) -> Path:
    path.write_bytes(value if value is not None else secrets.token_bytes(32))
    path.chmod(0o600)
    return path


class _Child:
    """Bounded child startup and cleanup; no shell or inherited HTTP proxies."""
    def __init__(self, module: str, arguments: list[str]) -> None:
        self.command = [sys.executable, "-m", module, *arguments]
        self.process: subprocess.Popen[str] | None = None
        self.startup: dict[str, Any] | None = None

    def start(self) -> dict[str, Any]:
        environment = dict(os.environ)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            environment.pop(name, None)
        environment["PYTHONUNBUFFERED"] = "1"
        self.process = subprocess.Popen(self.command, cwd=ROOT, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert self.process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=15):
                self.stop()
                raise ControlError("EXTERNAL_STOP_DEMO_CHILD_START_TIMEOUT")
            line = self.process.stdout.readline()
        try:
            self.startup = json.loads(line)
            if not isinstance(self.startup, dict) or "url" not in self.startup:
                raise ValueError("invalid startup identity")
        except (TypeError, ValueError) as exc:
            cleanup = self.stop()
            raise ControlError("EXTERNAL_STOP_DEMO_CHILD_START_FAILED:" + cleanup["stderr"][-4000:]) from exc
        return deepcopy(self.startup)

    @property
    def pid(self) -> int:
        assert self.process is not None
        return self.process.pid

    def stop(self) -> dict[str, Any]:
        if self.process is None:
            return {"pid": None, "reaped": True, "exit_code": None, "stderr": ""}
        child = self.process
        if child.poll() is None:
            child.terminate()
        try:
            _, stderr = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            _, stderr = child.communicate(timeout=5)
        return {"pid": child.pid, "reaped": child.poll() is not None,
                "exit_code": child.returncode, "stderr": stderr[-4000:]}


def _backup(source: Path, destination: Path) -> dict[str, Any]:
    """SQLite backup API copies a coherent state, not SQLite/WAL file fragments."""
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as destination_db:
        source_db.backup(destination_db)
        destination_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return {"method": "sqlite3.Connection.backup", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "destination_sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def _action(root_id: str, name: str) -> dict[str, Any]:
    return {"root_id": root_id, "execution_id": root_id + ":worker", "epoch": 1,
            "action_id": root_id + ":" + name, "attempt_id": root_id + ":attempt:" + name,
            "target": "records", "arguments": {"synthetic_marker": root_id + ":" + name}}


def _grant(action: dict[str, Any], policy: str, receiver_id: str) -> dict[str, Any]:
    return {"action_digest": digest(action), "policy_version": policy,
            "expires_at": time.time() + 120, "receiver_id": receiver_id}


def _local_session(db: Path, root_id: str, policy: str) -> SessionAuthority:
    authority = SessionAuthority(db)
    authority.create_session(root_id, controller_id="fixture-operator", policy_digest=policy,
        objective_digest=digest("one bounded synthetic owned record"), max_actions=10,
        max_executions=1, max_depth=0, max_stages=10, lifetime_seconds=180, lease_seconds=180)
    authority.bind_execution(root_id, root_id + ":worker")
    return authority


def _sources() -> dict[str, str]:
    paths = sorted((ROOT / "sdk").rglob("*.py")) + sorted((ROOT / "adapters").rglob("*.py"))
    paths += [ROOT / "tests/test_agent_control_external_stop_runtime.py", DESIGN]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def run_demo() -> dict[str, Any]:
    """Run versioned real-process cases; missing evidence raises, never passes."""
    from .external_authority_service import HTTPExternalAuthorityClient
    from .external_checkpoint import verify_checkpoint_chain
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    design = json.loads(DESIGN.read_text())
    if (design.get("experiment_id") != SCHEMA or design.get("scenario_ids") != list(CASE_IDS)
            or design.get("model_calls_budget") != 0 or design.get("live_internet") is not False):
        raise ControlError("EXTERNAL_STOP_DEMO_DESIGN_MISMATCH")
    outcomes, processes, cleanup, signed_statements, authority_evidence = {}, [], [], [], []
    case_evidence: dict[str, list[dict[str, Any]]] = {}
    current_case: str | None = None
    with tempfile.TemporaryDirectory(prefix="liminal-external-stop-") as temporary:
        work = Path(temporary).resolve()
        controller = work / "controller"
        controller.mkdir(mode=0o700)
        signing_key = Ed25519PrivateKey.generate()
        signing_file = _key(controller / "authority-signing.key", signing_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        receipt_file = _key(controller / "receiver-receipt.key")
        operator_file, receiver_auth_file = _key(controller / "operator.key"), _key(controller / "receiver-client.key")
        broker_file = _key(work / "broker.key")
        pin = {"authority_id": "external-fixture-controller", "key_id": "fixture-ed25519",
               "public_key": signing_key.public_key().public_bytes(
                   serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        pin_file = work / "public-authority-pin.json"
        _write_json(pin_file, pin)
        controller_db = controller / "authority.sqlite"
        authority_child: _Child | None = None
        live_receivers: list[_Child] = []
        admin = receiver_authority = None
        authority_url: str | None = None

        def start_authority(*, initialize: bool, port: int = 0) -> None:
            nonlocal authority_child, admin, receiver_authority, authority_url
            arguments = ["--db", str(controller_db), "--authority-id", pin["authority_id"],
                "--key-id", pin["key_id"], "--signing-key-file", str(signing_file),
                "--receipt-key-file", str(receipt_file), "--operator-key-file", str(operator_file),
                "--receiver-key-file", str(receiver_auth_file), "--port", str(port)]
            if initialize:
                arguments.append("--initialize")
            authority_child = _Child("sdk.liminal_agent_control.external_authority_service", arguments)
            startup = authority_child.start()
            authority_url = startup["url"]
            processes.append({"role": "external_authority", "pid": authority_child.pid,
                              "command": authority_child.command, "startup": startup,
                              "explicit_initialization": initialize})
            admin = HTTPExternalAuthorityClient(authority_url, operator_file.read_bytes(), pin, role="admin")
            receiver_authority = HTTPExternalAuthorityClient(authority_url, receiver_auth_file.read_bytes(), pin, role="receiver")

        def capture(client: Any, operation: str, **params: Any) -> Any:
            result = getattr(client, operation)(**params)
            statements = getattr(client, "responses", [])
            evidence = getattr(client, "evidence", [])
            if not statements or not evidence:
                raise ControlError("EXTERNAL_STOP_DEMO_SIGNED_RESPONSE_REQUIRED")
            signed_statements.append(deepcopy(statements[-1]))
            pair = deepcopy(evidence[-1])
            authority_evidence.append(pair)
            if current_case is not None:
                case_evidence.setdefault(current_case, []).append(pair)
            return result

        def spawn_receiver(directory: Path, *, external: bool = True) -> tuple[_Child, HTTPReceiverClient]:
            arguments = ["--db", str(directory / "receiver.sqlite"), "--broker-key-file", str(broker_file),
                         "--receipt-key-file", str(receipt_file), "--governed"]
            if external:
                assert authority_url is not None
                arguments += ["--external-authority-url", authority_url,
                    "--external-authority-key-file", str(receiver_auth_file),
                    "--external-authority-pin-file", str(pin_file)]
            child = _Child("sdk.liminal_agent_control.receiver", arguments)
            startup = child.start()
            live_receivers.append(child)
            processes.append({"role": "receiver" if external else "unsafe_local_baseline", "pid": child.pid,
                              "command": child.command, "startup": startup})
            client = HTTPReceiverClient(startup["url"], broker_file.read_bytes(), receipt_file.read_bytes())
            identity = client.identity()
            expected_profile = "external_governed_v1" if external else "governed_v1"
            if identity["enforcement_profile"] != expected_profile:
                raise ControlError("EXTERNAL_STOP_DEMO_PROFILE_MISMATCH")
            return child, client

        def stop_receiver(child: _Child) -> None:
            cleanup.append({"role": "receiver", **child.stop()})
            live_receivers.remove(child)

        def new_case(name: str, *, external: bool = True) -> dict[str, Any]:
            nonlocal current_case
            current_case = name
            directory = work / name
            directory.mkdir(mode=0o700)
            root_id, policy = "runtime:" + name, digest({"owned_record_case": name})
            local = _local_session(directory / "receiver.sqlite", root_id, policy)
            child, client = spawn_receiver(directory, external=external)
            identity = client.identity()
            if external:
                capture(admin, "create_root", root_id=root_id, receiver_id=identity["receiver_id"],
                        policy_digest=policy, max_actions=10, lifetime_seconds=180)
                capture(admin, "bind_execution", root_id=root_id, execution_id=root_id + ":worker")
            return {"directory": directory, "root_id": root_id, "policy": policy,
                    "local": local, "child": child, "client": client, "identity": identity}

        def snapshot(case: dict[str, Any]) -> dict[str, Any]:
            stop_receiver(case["child"])
            result = _backup(case["directory"] / "receiver.sqlite", case["directory"] / "old-snapshot.sqlite")
            case["child"], case["client"] = spawn_receiver(case["directory"])
            result["receiver_stopped_during_copy"] = True
            result["receiver_identity_preserved"] = case["client"].identity()["receiver_id"] == case["identity"]["receiver_id"]
            return result

        def restore(case: dict[str, Any], *, external: bool = True) -> dict[str, Any]:
            if case["child"] in live_receivers:
                stop_receiver(case["child"])
            result = _backup(case["directory"] / "old-snapshot.sqlite", case["directory"] / "receiver.sqlite")
            case["child"], case["client"] = spawn_receiver(case["directory"], external=external)
            result["receiver_stopped_during_copy"] = True
            result["receiver_identity_preserved"] = case["client"].identity()["receiver_id"] == case["identity"]["receiver_id"]
            result["controller_database_not_restored"] = True
            return result

        def commit(case: dict[str, Any], name: str = "candidate") -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
            action = _action(case["root_id"], name)
            grant = _grant(action, case["policy"], case["identity"]["receiver_id"])
            receipt = case["client"].commit(action, authorization=grant)
            if not case["client"].verify_receipt(receipt):
                raise ControlError("EXTERNAL_STOP_DEMO_RECEIPT_AUTHENTICATION_FAILED")
            return action, grant, receipt

        def actual_counts(case: dict[str, Any]) -> dict[str, int]:
            with sqlite3.connect("file:" + str(case["directory"] / "receiver.sqlite") + "?mode=ro", uri=True) as db:
                return {"accepted_count": db.execute("SELECT COUNT(*) FROM accepted").fetchone()[0],
                        "effect_count": db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]}

        try:
            start_authority(initialize=True)
            initial_authority_pid = authority_child.pid

            case = new_case("positive")
            action, grant, receipt = commit(case)
            inventory = case["client"].records()
            state = capture(admin, "status", root_id=case["root_id"])
            query = capture(receiver_authority, "query", action_id=action["action_id"])
            outcomes["positive"] = {"action": action, "grant": grant, "receipt": receipt,
                "records": inventory, "external_state": state, "external_query": query, **actual_counts(case),
                "checks": {"real_effect": receipt["status"] == "COMMITTED" and len(inventory) == 1,
                    "external_settled": state["committed_count"] == 1 and state["pending_count"] == 0,
                    "distinct_processes": case["child"].pid not in {initial_authority_pid, os.getpid()}}}

            case = new_case("stop_restore")
            saved = snapshot(case)
            action = _action(case["root_id"], "candidate")
            grant = _grant(action, case["policy"], case["identity"]["receiver_id"])
            stopped = capture(admin, "stop", root_id=case["root_id"])
            case["local"].stop(case["root_id"])
            restored = restore(case)
            receipt = case["client"].commit(action, authorization=grant)
            inventory = case["client"].records()
            state = capture(admin, "status", root_id=case["root_id"])
            local_after = case["local"].status(case["root_id"])
            outcomes["stop_restore"] = {"action": action, "grant": grant, "stop_response": stopped,
                "snapshot": saved, "restore": restored, "receipt": receipt, "records": inventory,
                "external_state": state, "restored_local_state": local_after, **actual_counts(case),
                "checks": {"stop_acknowledged": stopped["state"] == "STOPPED" and stopped["pending_count"] == 0,
                    "local_stop_was_rolled_back": local_after["state"] == "ACTIVE" and local_after["epoch"] == 1,
                    "external_stop_survived": state["state"] == "STOPPED" and state["epoch"] > 1,
                    "no_acceptance_or_effect": receipt["status"] == "DENIED" and not inventory,
                    "same_pinned_receiver": saved["receiver_identity_preserved"] and restored["receiver_identity_preserved"]}}

            case = new_case("terminal_restore")
            saved = snapshot(case)
            action, grant, committed = commit(case)
            before = case["client"].records()
            restored = restore(case)
            empty_before_retry = case["client"].records()
            retry = case["client"].commit(action, authorization=grant)
            after = case["client"].records()
            state = capture(admin, "status", root_id=case["root_id"])
            query = capture(receiver_authority, "query", action_id=action["action_id"])
            outcomes["terminal_restore"] = {"action": action, "grant": grant, "committed_receipt": committed,
                "records_before_restore": before, "snapshot": saved, "restore": restored,
                "records_before_retry": empty_before_retry, "retry_receipt": retry, "records": after,
                "external_state": state, "external_query": query, **actual_counts(case),
                "checks": {"real_previous_effect": committed["status"] == "COMMITTED" and len(before) == 1,
                    "local_effect_record_was_rolled_back": not empty_before_retry,
                    "surviving_consumption": state["state"] == "ACTIVE" and state["committed_count"] == 1,
                    "no_reexecution": retry["status"] == "UNKNOWN" and not after,
                    "same_pinned_receiver": restored["receiver_identity_preserved"]}}

            case = new_case("pending_duplicate")
            action = _action(case["root_id"], "candidate")
            grant = _grant(action, case["policy"], case["identity"]["receiver_id"])
            issued = capture(receiver_authority, "begin", action=action, authorization=grant)
            retry = case["client"].commit(action, authorization=grant)
            inventory = case["client"].records()
            stopped = capture(admin, "stop", root_id=case["root_id"])
            outcomes["pending_duplicate"] = {"action": action, "grant": grant, "issued_permit": issued,
                "retry_receipt": retry, "records": inventory, "stop_response": stopped, **actual_counts(case),
                "checks": {"actual_unresolved_permit": issued["status"] == "PERMITTED",
                    "duplicate_unknown_no_effect": retry["status"] == "UNKNOWN" and not inventory,
                    "stop_not_falsely_acknowledged": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1}}

            case = new_case("authority_restart")
            stopped = capture(admin, "stop", root_id=case["root_id"])
            assert authority_child is not None and authority_child.startup is not None
            authority_port = urlparse(authority_child.startup["url"]).port
            cleanup.append({"role": "external_authority", **authority_child.stop()})
            start_authority(initialize=False, port=authority_port)
            action, grant, receipt = commit(case)
            inventory = case["client"].records()
            state = capture(admin, "status", root_id=case["root_id"])
            outcomes["authority_restart"] = {"action": action, "grant": grant, "stop_response": stopped,
                "receipt": receipt, "records": inventory, "external_state": state, **actual_counts(case),
                "checks": {"different_authority_process": authority_child.pid != initial_authority_pid,
                    "same_public_pin": authority_child.startup.get("pin", pin) == pin,
                    "terminal_state_survived": state["state"] == "STOPPED" and state["epoch"] == stopped["epoch"],
                    "no_effect": receipt["status"] == "DENIED" and not inventory}}

            case = new_case("authority_outage")
            assert authority_child is not None and authority_child.startup is not None
            authority_port = urlparse(authority_child.startup["url"]).port
            cleanup.append({"role": "external_authority", **authority_child.stop()})
            action, grant, receipt = commit(case)
            outage_inventory = case["client"].records()
            outage_counts = actual_counts(case)
            start_authority(initialize=False, port=authority_port)
            fresh_action, fresh_grant, fresh_receipt = commit(case, "fresh-after-outage")
            after = case["client"].records()
            state = capture(admin, "status", root_id=case["root_id"])
            query = capture(receiver_authority, "query", action_id=fresh_action["action_id"])
            outcomes["authority_outage"] = {"action": action, "grant": grant, "receipt": receipt,
                "records_during_outage": outage_inventory, "outage_records": outage_inventory,
                "outage_accepted_count": outage_counts["accepted_count"], "outage_effect_count": outage_counts["effect_count"],
                "fresh_action": fresh_action,
                "fresh_grant": fresh_grant, "fresh_receipt": fresh_receipt, "records": after,
                "external_state": state, "external_query": query, **actual_counts(case),
                "checks": {"outage_no_acceptance_or_effect": receipt["status"] in {"DENIED", "UNKNOWN"} and not outage_inventory,
                    "actual_recovery_control": fresh_receipt["status"] == "COMMITTED" and len(after) == 1,
                    "outage_did_not_consume": state["issued_count"] == 1 and state["committed_count"] == 1}}

            case = new_case("split_api_denied")
            action = _action(case["root_id"], "candidate")
            grant = _grant(action, case["policy"], case["identity"]["receiver_id"])
            rejected = {}
            for operation, parameters in (("accept", {"action": action, "authorization": grant}),
                                          ("finalize", {"action_id": action["action_id"]})):
                try:
                    rejected[operation] = {"unexpected_result": getattr(case["client"], operation)(**parameters)}
                except ControlError as exc:
                    rejected[operation] = {"status": "REJECTED", "reason": str(exc)}
            inventory = case["client"].records()
            outcomes["split_api_denied"] = {"action": action, "grant": grant,
                "attempts": rejected, "records": inventory, **actual_counts(case),
                "checks": {"split_apis_disabled": all(item.get("status") == "REJECTED" for item in rejected.values()),
                           "no_effect": not inventory}}

            case = new_case("unsafe_local_restore", external=False)
            action = _action(case["root_id"], "candidate")
            grant = _grant(action, case["policy"], case["identity"]["receiver_id"])
            stop_receiver(case["child"])
            saved = _backup(case["directory"] / "receiver.sqlite", case["directory"] / "old-snapshot.sqlite")
            local_stop = case["local"].stop(case["root_id"])
            restored = restore(case, external=False)
            receipt = case["client"].commit(action, authorization=grant)
            inventory = case["client"].records()
            outcomes["unsafe_local_restore"] = {"variant": "explicit_local_only_unsafe_control",
                "action": action, "grant": grant, "snapshot": saved, "local_stop": local_stop,
                "restore": restored, "receipt": receipt, "records": inventory, **actual_counts(case),
                "checks": {"unsafe_control_really_executed": receipt["status"] == "COMMITTED" and len(inventory) == 1,
                           "local_only_profile": receipt["enforcement_profile"] == "governed_v1"}}

            current_case = None
            checkpoint_export = capture(admin, "checkpoints")
            entries = checkpoint_export if isinstance(checkpoint_export, list) else checkpoint_export["checkpoints"]
            verification = verify_checkpoint_chain(entries, authority_id=pin["authority_id"],
                signer_id=pin["authority_id"], key_id=pin["key_id"], public_key=pin["public_key"])
            for name, outcome in outcomes.items():
                outcome.update(authority_pin=pin, authority_evidence=case_evidence.get(name, []) + [authority_evidence[-1]],
                               checkpoint_entries=entries, checkpoint_anchor=verification["tip"])
        finally:
            for child in list(live_receivers):
                stop_receiver(child)
            if authority_child is not None and authority_child.process is not None and authority_child.process.poll() is None:
                cleanup.append({"role": "external_authority", **authority_child.stop()})

    checks = {name + ":" + check: value for name, case in outcomes.items() for check, value in case["checks"].items()}
    checks.update({"all_cases_collected": set(outcomes) == set(CASE_IDS),
                   "all_processes_reaped": all(item["reaped"] for item in cleanup),
                   "public_checkpoint_signatures_verified": verification["verification_status"] == "LOCAL_SIGNATURE_ONLY",
                   "separate_child_processes": all(item["pid"] != os.getpid() for item in processes),
                   "receiver_never_receives_signing_key": all(str(signing_file) not in item["command"]
                       for item in processes if item["role"] != "external_authority")})
    source = _source()
    source["scope"] = "checked-out commit/tree; source_files_sha256 binds actual runtime inputs"
    return {"schema": SCHEMA, "source": source, "source_files_sha256": _sources(),
        "preregistration": design, "controller_pid": os.getpid(), "authority_public_pin": pin,
        "outcomes": outcomes, "checks": checks, "passed": all(checks.values()),
        "authority_signed_statements": signed_statements, "authority_evidence": authority_evidence,
        "authority_checkpoints": entries,
        "checkpoint_anchor": verification["tip"],
        "checkpoint_anchor_provenance": "collector-observed tip from fresh pinned signed live export; no separately owned latest-anchor service",
        "checkpoint_verification": verification, "processes": processes, "cleanup": cleanup,
        "scope": {"actual_loopback_http": True, "distinct_authority_receiver_processes": True,
            "separate_authority_database": True, "actual_synthetic_sqlite_effects": True,
            "private_keys_bundled": False, "receiver_receipts_authenticated_during_collection": True,
            "receiver_receipts_publicly_verifiable": False, "independent_latest_anchor": "NOT_ESTABLISHED",
            "model_calls": 0, "external_network": "NOT_RUN", "docker": "NOT_RUN",
            "rust_liminaldb_runtime": "NOT_RUN", "external_human_reproduction": "NOT_ESTABLISHED"}}


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
