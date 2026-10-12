"""Real Docker lifecycle experiment with external admission and a trusted supervisor.

The small HTTP wrappers in this module are owned fixture infrastructure, not a
general command tool. Only the dispatcher proposal cache is restored. Authority,
supervisor, registry, Docker daemon, host clock and signing keys stay intact.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from .authority import ControlError, canonical_bytes, digest
from .external_stop_demo import _Child, _backup, _key, _write_json
from .multi_agent import ROOT, _source

SCHEMA = "liminal-external-command-runtime-v1"
CASE_IDS = ("command_positive", "command_binding_swap", "command_stop_before_create",
    "command_stop_between_create_start", "command_pending_launch_stop", "command_lost_launch_response",
    "command_restore_local_state", "command_descendant_cleanup", "command_observation_unavailable",
    "command_authority_restart_outage")
DESIGN = ROOT / "experiments/agent_control/preregistration_external_command.json"
FIXTURE = ROOT / "experiments/agent_control/external_command_fixture.py"


def _sources() -> dict[str, str]:
    paths = sorted((ROOT / "sdk").rglob("*.py")) + sorted((ROOT / "adapters").rglob("*.py"))
    paths += sorted((ROOT / "tests").glob("test_agent_control_external_command*.py"))
    paths += [ROOT / path for path in ("scripts/verify_external_command_evidence.py",
        "scripts/verify_external_stop_evidence.py", ".github/workflows/agent-control.yml",
        "docs/AGENT_CONTROL_EXTERNAL_COMMAND.md", "README.md",
        "experiments/agent_control/observer-requirements.txt")]
    paths += [DESIGN, FIXTURE]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def _wait_file(path: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise ControlError("COMMAND_RUNTIME_BARRIER_TIMEOUT")
        time.sleep(0.02)


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ControlError("FIXTURE_DUPLICATE_FIELD")
        value[key] = item
    return value


class _FixtureClient:
    def __init__(self, url: str, key: bytes, role: str) -> None:
        self.url, self.key, self.role = url, key.hex(), role

    def call(self, operation: str, **payload: Any) -> dict[str, Any]:
        request = Request(self.url + "/fixture", data=canonical_bytes({"operation": operation, "payload": payload}),
            headers={"Content-Type": "application/json", "X-Fixture-Role": self.role,
                "X-Fixture-Key": self.key}, method="POST")
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=20) as response:
                result = json.loads(response.read(2 * 1024 * 1024 + 1))
        except (OSError, ValueError, HTTPError, URLError) as exc:
            return {"status": "UNKNOWN", "reason": "FIXTURE_DELIVERY_UNAVAILABLE", "exception_type": type(exc).__name__}
        return result


def _service(args: argparse.Namespace) -> int:
    """Owned host harness; static credentials keep operator and worker routes separate."""
    operator_key = args.operator_key_file.read_bytes().hex()
    worker_key = args.worker_key_file.read_bytes().hex()
    if len(operator_key) != 64 or len(worker_key) != 64 or hmac.compare_digest(operator_key, worker_key):
        raise ControlError("FIXTURE_ROLE_KEYS_MUST_DIFFER")
    faults: dict[str, Any] = {}
    supervisor = None
    if args.supervisor_service:
        from .external_authority_service import HTTPExternalAuthorityClient
        from .external_command_supervisor import ExternalCommandSupervisor
        from .runtime import DockerController, RuntimeBoundaryError

        class FixtureController(DockerController):
            def __init__(self, docker_binary: str) -> None:
                super().__init__(docker_binary)
                self.call_database = args.db.with_name("actual-docker-calls.sqlite")
                with sqlite3.connect(self.call_database) as database:
                    database.execute("PRAGMA synchronous=FULL")
                    database.execute("CREATE TABLE IF NOT EXISTS calls(sequence INTEGER PRIMARY KEY, operation TEXT, arguments_digest TEXT, started_at REAL, finished_at REAL, returncode INTEGER, stdout TEXT)")

            def command(self, command: list[str], *, timeout: float = 10) -> Any:
                # The journal records actual CLI invocation, separately from a
                # permit or dispatcher result. No environment/secret is logged.
                if command[0] not in {"create", "start"}:
                    return super().command(command, timeout=timeout)
                with sqlite3.connect(self.call_database) as database:
                    cursor = database.execute("INSERT INTO calls(operation,arguments_digest,started_at) VALUES (?,?,?)",
                        (command[0], digest(command), time.time()))
                    sequence = cursor.lastrowid
                returned = super().command(command, timeout=timeout)
                with sqlite3.connect(self.call_database) as database:
                    database.execute("UPDATE calls SET finished_at=?,returncode=?,stdout=? WHERE sequence=?",
                        (time.time(), returned.returncode, returned.stdout.decode(errors="replace")[:8192], sequence))
                return returned

            def _inspect(self, session_id: str) -> dict | None:
                if faults.get("observation_unavailable"):
                    self._record_process_failure(session_id, {"Id": self.owned_container_ids.get(session_id)},
                        None, "FIXTURE_OBSERVATION_UNAVAILABLE", stage="fixture fault")
                    raise RuntimeBoundaryError("DOCKER_OBSERVATION_UNAVAILABLE")
                return super()._inspect(session_id)

        authority = HTTPExternalAuthorityClient(args.authority_url, args.authority_request_key_file.read_bytes(),
            json.loads(args.authority_pin_file.read_text()), role="receiver")
        supervisor = ExternalCommandSupervisor(args.db, args.registry, supervisor_id=args.supervisor_id,
            key_id=args.key_id, private_key=args.private_key_file.read_bytes(), authority_client=authority,
            controller=FixtureController(args.docker_binary), create=args.initialize)

        def after_dispatch(stage: str, action: dict, result: Any) -> None:
            if faults.get("hold_stage") == stage:
                reached, release = Path(faults["reached_file"]), Path(faults["release_file"])
                reached.write_text("actual daemon response reached host callback\n")
                _wait_file(release, timeout=45)
        supervisor.after_dispatch_hook = after_dispatch
        startup = {"role": "owned_workload_supervisor", "pin": supervisor.pin()}
    else:
        from .external_command_protocol import validate_command_action
        forward = _FixtureClient(args.supervisor_url, args.worker_key_file.read_bytes(), "worker")
        with sqlite3.connect(args.db) as database:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("CREATE TABLE IF NOT EXISTS proposals(action_id TEXT PRIMARY KEY, action_json TEXT NOT NULL, result_json TEXT)")
        startup = {"role": "proposal_dispatcher", "cache": "non-authorizing proposal/result SQLite"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_POST(self) -> None:
            try:
                if self.path != "/fixture" or self.headers.get("Content-Type") != "application/json":
                    raise ControlError("FIXTURE_ROUTE_DENIED")
                role = self.headers.get("X-Fixture-Role")
                supplied = self.headers.get("X-Fixture-Key", "")
                expected = operator_key if role == "admin" else worker_key if role == "worker" else ""
                if not expected or not hmac.compare_digest(supplied, expected):
                    raise ControlError("FIXTURE_ROLE_DENIED")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 262144:
                    raise ControlError("FIXTURE_PACKET_BOUND")
                packet = json.loads(self.rfile.read(length), object_pairs_hook=_unique_object)
                if set(packet) != {"operation", "payload"} or type(packet["payload"]) is not dict:
                    raise ControlError("FIXTURE_PACKET_INVALID")
                operation, payload = packet["operation"], packet["payload"]
                worker_operations = {"execute", "reconcile"}
                admin_operations = {"authorize", "cleanup", "inventory", "faults"}
                if operation not in (worker_operations if role == "worker" else admin_operations):
                    raise ControlError("FIXTURE_OPERATION_DENIED")
                if operation == "faults":
                    if set(payload) - {"hold_stage", "reached_file", "release_file", "observation_unavailable",
                                       "drop_delivery", "delivery_reached", "delivery_release"}:
                        raise ControlError("FIXTURE_FAULT_INVALID")
                    faults.clear()
                    faults.update(payload)
                    result = {"status": "CONFIGURED", "execution_authorized": False}
                elif supervisor is not None:
                    result = supervisor.execute(payload["action"]) if operation == "execute" else getattr(supervisor, operation)(**payload)
                    if operation == "inventory":
                        with sqlite3.connect(supervisor.controller.call_database) as database:
                            database.row_factory = sqlite3.Row
                            result["docker_calls"] = [dict(row) for row in database.execute("SELECT * FROM calls ORDER BY sequence")]
                elif operation == "inventory":
                    with sqlite3.connect(args.db) as database:
                        rows = database.execute("SELECT action_id,action_json,result_json FROM proposals ORDER BY action_id").fetchall()
                    result = {"rows": [{"action_id": row[0], "action": json.loads(row[1]),
                        "result": json.loads(row[2]) if row[2] else None} for row in rows], "execution_authorized": False}
                elif operation in worker_operations:
                    if operation == "execute":
                        action = validate_command_action(payload["action"])
                        if set(payload) != {"action"}:
                            raise ControlError("DISPATCHER_PACKET_INVALID")
                        with sqlite3.connect(args.db) as database:
                            database.execute("BEGIN IMMEDIATE")
                            existing = database.execute("SELECT action_json FROM proposals WHERE action_id=?", (action["action_id"],)).fetchone()
                            if existing is not None and existing[0].encode() != canonical_bytes(action):
                                raise ControlError("DISPATCHER_PROPOSAL_IMMUTABLE")
                            if existing is None and database.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] >= 1024:
                                raise ControlError("DISPATCHER_PROPOSAL_CAPACITY")
                            database.execute("INSERT OR IGNORE INTO proposals VALUES (?,?,NULL)",
                                (action["action_id"], canonical_bytes(action).decode()))
                    result = forward.call(operation, **payload)
                    if faults.get("drop_delivery"):
                        Path(faults["delivery_reached"]).write_text("supervisor response reached dispatcher\n")
                        _wait_file(Path(faults["delivery_release"]), timeout=45)
                    if operation == "execute":
                        with sqlite3.connect(args.db) as database:
                            database.execute("UPDATE proposals SET result_json=? WHERE action_id=?",
                                (canonical_bytes(result).decode(), payload["action"]["action_id"]))
                else:
                    raise ControlError("DISPATCHER_CANNOT_AUTHORIZE")
            except Exception as exc:
                result = {"status": "ERROR", "reason": str(exc)[:200], "exception_type": type(exc).__name__,
                    "execution_authorized": False}
            encoded = canonical_bytes(result)
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError):
                pass

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def __init__(self, *values: Any) -> None:
            self._slots = threading.BoundedSemaphore(16)
            super().__init__(*values)

        def get_request(self) -> Any:
            request, address = super().get_request()
            request.settimeout(3)
            return request, address

        def process_request(self, request: Any, address: Any) -> None:
            if not self._slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                self._slots.release()
                raise

        def process_request_thread(self, request: Any, address: Any) -> None:
            try:
                super().process_request_thread(request, address)
            finally:
                self._slots.release()

    server = Server(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    startup["url"] = "http://127.0.0.1:" + str(server.server_port)
    print(json.dumps(startup), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        if supervisor is not None:
            supervisor.close()
    return 0


def run_demo(*, image: str | None = None, docker_binary: str = "docker") -> dict[str, Any]:
    """Required real Docker matrix. Missing backend is an error, never simulated evidence."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .external_authority_service import HTTPExternalAuthorityClient
    from .external_checkpoint import verify_checkpoint_chain
    from .external_command_protocol import COMMAND_PROFILE, command_action, command_spec
    from .runtime import DockerController

    image = image or os.environ.get("LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE")
    if type(image) is not str:
        raise ControlError("COMMAND_RUNTIME_IMMUTABLE_DOCKER_IMAGE_REQUIRED")
    docker = DockerController(docker_binary)
    try:
        docker.image_id(image)
        version = docker.command(["version", "--format", "{{.Server.Version}}"])
        identity = docker.command(["info", "--format", "{{.ID}}"])
        if version.returncode or identity.returncode or not version.stdout.strip() or not identity.stdout.strip():
            raise ControlError("COMMAND_RUNTIME_DOCKER_UNAVAILABLE")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ControlError("COMMAND_RUNTIME_DOCKER_UNAVAILABLE") from exc
    design = json.loads(DESIGN.read_text())
    if (design.get("experiment_id") != SCHEMA or design.get("scenario_ids") != list(CASE_IDS)
            or design.get("profile") != COMMAND_PROFILE or design.get("model_calls_budget") != 0
            or design.get("live_internet") is not False or design.get("max_actions_per_root") != 2
            or hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != design.get("fixture_sha256")):
        raise ControlError("COMMAND_RUNTIME_DESIGN_MISMATCH")
    outcomes: dict[str, Any] = {}
    processes: list[dict[str, Any]] = []
    cleanup: list[dict[str, Any]] = []
    authority_evidence: list[dict[str, Any]] = []
    seen_pairs: set[str] = set()
    sentinel_id: str | None = None
    daemon_identity = {"backend": "Docker", "server_version": version.stdout.decode().strip(),
        "daemon_id": identity.stdout.decode().strip(), "image_id": image}

    def pairs(values: list[dict]) -> None:
        for value in values:
            key = digest(value)
            if key not in seen_pairs:
                seen_pairs.add(key)
                authority_evidence.append(deepcopy(value))

    with tempfile.TemporaryDirectory(prefix="liminal-external-command-") as temporary:
        work = Path(temporary).resolve()
        # The container's unprivileged UID can traverse this one immutable
        # fixture workspace. Controller key directories remain mode 0700.
        work.chmod(0o755)
        workspace = work / "readonly-fixture"
        workspace.mkdir(mode=0o755)
        mounted_fixture = workspace / FIXTURE.name
        mounted_fixture.write_bytes(FIXTURE.read_bytes())
        mounted_fixture.chmod(0o444)
        authority_directory, supervisor_directory = work / "authority", work / "supervisor"
        authority_directory.mkdir(mode=0o700)
        supervisor_directory.mkdir(mode=0o700)
        authority_key, supervisor_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        authority_private = _key(authority_directory / "signing.key", authority_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        supervisor_private = _key(supervisor_directory / "signing.key", supervisor_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        receipt_key = _key(authority_directory / "records-legacy.key")
        authority_operator = _key(authority_directory / "operator.key")
        authority_request = _key(supervisor_directory / "authority-request.key")
        supervisor_operator = _key(supervisor_directory / "operator.key")
        supervisor_worker = _key(work / "dispatcher-worker.key")
        dispatcher_operator = _key(work / "dispatcher-fixture-operator.key")
        authority_pin = {"authority_id": "command-fixture-controller", "key_id": "fixture-authority-ed25519",
            "public_key": authority_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        supervisor_pin = {"supervisor_id": "command-fixture-supervisor", "key_id": "fixture-supervisor-ed25519",
            "public_key": supervisor_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        authority_pin_file, supervisor_pin_file = work / "authority-pin.json", work / "supervisor-pin.json"
        _write_json(authority_pin_file, authority_pin)
        _write_json(supervisor_pin_file, supervisor_pin)
        authority_db = authority_directory / "authority.sqlite"
        supervisor_db, registry_db = supervisor_directory / "supervisor.sqlite", supervisor_directory / "registry.sqlite"
        authority_child: _Child | None = None
        supervisor_child: _Child | None = None
        live_dispatchers: list[_Child] = []
        authority_url: str | None = None
        admin = external_receiver = host = None
        supervisor_url: str | None = None

        def stop_child(child: _Child, role: str) -> dict:
            result = {"role": role, **child.stop()}
            cleanup.append(result)
            return result

        def capture(client: Any, operation: str, **payload: Any) -> dict:
            try:
                result = getattr(client, operation)(**payload)
            except ControlError as exc:
                result = {"status": "ERROR", "reason": str(exc)}
            pairs(client.evidence)
            return result

        def start_authority(*, initialize: bool, port: int = 0) -> None:
            nonlocal authority_child, authority_url, admin, external_receiver
            arguments = ["--db", str(authority_db), "--authority-id", authority_pin["authority_id"],
                "--key-id", authority_pin["key_id"], "--signing-key-file", str(authority_private),
                "--receipt-key-file", str(receipt_key), "--operator-key-file", str(authority_operator),
                "--receiver-key-file", str(authority_request), "--profile", COMMAND_PROFILE,
                "--supervisor-pin-file", str(supervisor_pin_file), "--port", str(port)]
            if initialize:
                arguments.append("--initialize")
            authority_child = _Child("sdk.liminal_agent_control.external_authority_service", arguments)
            startup = authority_child.start()
            authority_url = startup["url"]
            processes.append({"role": "external_authority", "pid": authority_child.pid,
                "command": authority_child.command, "startup": startup, "explicit_initialization": initialize})
            admin = HTTPExternalAuthorityClient(authority_url, authority_operator.read_bytes(), authority_pin, role="admin")
            external_receiver = HTTPExternalAuthorityClient(authority_url, authority_request.read_bytes(), authority_pin, role="receiver")

        def start_supervisor() -> None:
            nonlocal supervisor_child, supervisor_url, host
            arguments = ["--supervisor-service", "--db", str(supervisor_db), "--registry", str(registry_db),
                "--supervisor-id", supervisor_pin["supervisor_id"], "--key-id", supervisor_pin["key_id"],
                "--private-key-file", str(supervisor_private), "--authority-url", str(authority_url),
                "--authority-request-key-file", str(authority_request), "--authority-pin-file", str(authority_pin_file),
                "--operator-key-file", str(supervisor_operator), "--worker-key-file", str(supervisor_worker),
                "--docker-binary", docker_binary, "--initialize"]
            supervisor_child = _Child("sdk.liminal_agent_control.external_command_demo", arguments)
            startup = supervisor_child.start()
            if startup["pin"] != supervisor_pin:
                raise ControlError("COMMAND_RUNTIME_SUPERVISOR_IDENTITY_CHANGED")
            supervisor_url = startup["url"]
            host = _FixtureClient(supervisor_url, supervisor_operator.read_bytes(), "admin")
            processes.append({"role": "owned_workload_supervisor", "pid": supervisor_child.pid,
                "command": supervisor_child.command, "startup": startup, "explicit_initialization": True})

        def inventory() -> dict:
            value = host.call("inventory")
            if value.get("profile") != COMMAND_PROFILE or value.get("supervisor_pin") != supervisor_pin:
                raise ControlError("COMMAND_RUNTIME_SUPERVISOR_INVENTORY_UNAVAILABLE:" + value.get("reason", ""))
            pairs(value["authority_evidence"])
            return value

        def docker_snapshot() -> dict:
            current = inventory()
            ids = {command["container_id"] for command in current["commands"] if command["container_id"]}
            ids.update(call["stdout"].strip() for call in current["docker_calls"]
                if call["operation"] == "create" and call["returncode"] == 0 and call["stdout"]
                    and len(call["stdout"].strip()) == 64)
            objects = []
            for container_id in sorted(ids):
                answer = docker.command(["inspect", container_id])
                if answer.returncode:
                    error = answer.stderr.decode(errors="replace").lower()
                    available = "no such object:" in error or "no such container:" in error
                    objects.append({"container_id": container_id, "available": available,
                        "exists": False if available else None, "observed_at": time.time()})
                    continue
                raw = json.loads(answer.stdout)[0]
                fields = ("Running", "Paused", "Pid", "StartedAt", "FinishedAt", "ExitCode")
                objects.append({"container_id": container_id, "available": True, "exists": True,
                    "image_id": raw["Image"], "labels": raw.get("Config", {}).get("Labels", {}),
                    "state": {key: raw["State"].get(key) for key in fields}, "observed_at": time.time()})
            return {"source": "independent parent Docker inspect by exact immutable container ID",
                "daemon_identity": daemon_identity, "objects": objects, "observed_at": time.time()}

        def dispatch(case: dict, *, initialize: bool) -> None:
            child = _Child("sdk.liminal_agent_control.external_command_demo", ["--dispatcher-service", "--db", str(case["db"]),
                "--supervisor-url", str(supervisor_url), "--operator-key-file", str(dispatcher_operator),
                "--worker-key-file", str(supervisor_worker)])
            startup = child.start()
            live_dispatchers.append(child)
            processes.append({"role": "proposal_dispatcher", "pid": child.pid, "command": child.command,
                "startup": startup, "explicit_initialization": initialize})
            case.update(child=child, worker=_FixtureClient(startup["url"], supervisor_worker.read_bytes(), "worker"),
                operator=_FixtureClient(startup["url"], dispatcher_operator.read_bytes(), "admin"))

        def stop_dispatcher(case: dict) -> dict:
            value = stop_child(case["child"], "proposal_dispatcher")
            live_dispatchers.remove(case["child"])
            return value

        def new_case(name: str, fixture: str = "positive") -> dict:
            directory = work / name
            directory.mkdir(mode=0o700)
            root_id = "runtime:" + name
            policy = digest({"profile": COMMAND_PROFILE, "owned_case": name, "fixture_sha256": design["fixture_sha256"]})
            case = {"name": name, "root_id": root_id, "policy": policy, "directory": directory,
                "db": directory / "proposals.sqlite", "command_id": root_id + ":command",
                "spec": command_spec(root_id + ":command", image, str(workspace), fixture),
                "actions": {}, "authorizations": {}, "supervisor_before": inventory(),
                "independent_docker_before": docker_snapshot()}
            created = capture(admin, "create_root", root_id=root_id, receiver_id=supervisor_pin["supervisor_id"],
                policy_digest=policy, max_actions=design["max_actions_per_root"], lifetime_seconds=600)
            bound = capture(admin, "bind_execution", root_id=root_id, execution_id=root_id + ":worker")
            if created.get("status") == "ERROR" or bound.get("status") == "ERROR":
                raise ControlError("COMMAND_RUNTIME_ROOT_SETUP_FAILED")
            dispatch(case, initialize=True)
            return case

        def approve(case: dict, stage: str = "CREATE") -> dict:
            options = {}
            if stage == "START":
                command = next(item for item in inventory()["commands"] if item["command_id"] == case["command_id"])
                parent = capture(external_receiver, "query", action_id=case["actions"]["create"]["action_id"])
                options = {"parent_reservation_id": parent["reservation_id"], "container_id": command["container_id"]}
            action = command_action(action_id=case["root_id"] + ":" + stage.lower(),
                attempt_id=case["root_id"] + ":attempt:" + stage.lower(), root_id=case["root_id"],
                execution_id=case["root_id"] + ":worker", epoch=1, stage=stage, spec=case["spec"], **options)
            grant = {"action_digest": digest(action), "policy_version": case["policy"],
                "expires_at": time.time() + 300, "receiver_id": supervisor_pin["supervisor_id"]}
            saved = host.call("authorize", action=action, grant=grant)
            if saved.get("status") != "AUTHORIZED":
                raise ControlError("COMMAND_RUNTIME_HOST_AUTHORIZATION_FAILED:" + saved.get("reason", ""))
            case["actions"][stage.lower()], case["authorizations"][stage.lower()] = action, grant
            return action

        def wait_create(case: dict) -> dict:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                result = case["worker"].call("reconcile", action_id=case["actions"]["create"]["action_id"])
                current = inventory()
                command = next((item for item in current["commands"] if item["command_id"] == case["command_id"]), None)
                if command is not None and command["create_confirmed"]:
                    return result
                time.sleep(0.03)
            raise ControlError("COMMAND_RUNTIME_CREATE_NOT_CONFIRMED")

        def wait_finished(case: dict, stage: str) -> dict:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                current = inventory()
                grant = next(item for item in current["grants"] if item["action"]["action_id"] == case["actions"][stage]["action_id"])
                if grant["callback_phase"] == "FINISHED":
                    return current
                time.sleep(0.03)
            raise ControlError("COMMAND_RUNTIME_CALLBACK_NOT_FINISHED")

        def launch_positive(case: dict, results: dict) -> None:
            action = approve(case)
            results["execute_create"] = case["worker"].call("execute", action=action)
            results["reconcile_create"] = wait_create(case)
            start = approve(case, "START")
            results["execute_start"] = case["worker"].call("execute", action=start)
            wait_finished(case, "start")
            results["reconcile_start"] = case["worker"].call("reconcile", action_id=start["action_id"])

        def clean(case: dict) -> dict:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                result = host.call("cleanup", command_id=case["command_id"])
                if result.get("status") == "QUIESCENT":
                    return result
                time.sleep(0.03)
            raise ControlError("COMMAND_RUNTIME_QUIESCENCE_NOT_CONFIRMED:" + result.get("reason", ""))

        def counts(value: dict) -> tuple[int, int]:
            calls = value["docker_calls"]
            return sum(call["operation"] == "create" for call in calls), sum(call["operation"] == "start" for call in calls)

        def finish_case(case: dict, results: dict, checks: dict, **extra: Any) -> None:
            after = inventory()
            before_counts, after_counts = counts(case["supervisor_before"]), counts(after)
            queries = {stage: capture(external_receiver, "query", action_id=action["action_id"])
                for stage, action in case["actions"].items()}
            outcomes[case["name"]] = {"actions": deepcopy(case["actions"]), "authorizations": deepcopy(case["authorizations"]),
                "results": results, "supervisor_before": case["supervisor_before"], "supervisor_after": after,
                "create_count_delta": after_counts[0] - before_counts[0], "start_count_delta": after_counts[1] - before_counts[1],
                "independent_docker_before": case["independent_docker_before"], "independent_docker_after": docker_snapshot(),
                "external_state": capture(admin, "status", root_id=case["root_id"]), "external_queries": queries,
                "dispatcher_cache": case["operator"].call("inventory"), "checks": checks, **extra}
            stop_dispatcher(case)

        def command_for(case: dict) -> dict:
            return next(item for item in inventory()["commands"] if item["command_id"] == case["command_id"])

        def process_snapshot(container_id: str) -> dict:
            inspected = docker.command(["inspect", container_id])
            if inspected.returncode:
                raise ControlError("COMMAND_RUNTIME_PROCESS_INSPECT_UNAVAILABLE")
            item = json.loads(inspected.stdout)[0]
            top = docker.command(["top", container_id])
            if top.returncode:
                raise ControlError("COMMAND_RUNTIME_PROCESS_TOP_UNAVAILABLE")
            lines = top.stdout.decode().strip().splitlines()
            columns = lines[0].split()
            pid_index, parent_index = columns.index("PID"), columns.index("PPID")
            nodes = [{"pid": int(fields[pid_index]), "ppid": int(fields[parent_index])}
                for fields in (line.split() for line in lines[1:])]
            return {"container_id": container_id, "image_id": item["Image"], "root_pid": item["State"]["Pid"],
                "running": item["State"]["Running"], "processes": nodes, "observed_at": time.time(),
                "source": "independent parent Docker inspect + top"}

        def wait_descendants(case: dict) -> dict:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = process_snapshot(command_for(case)["container_id"])
                if result["running"] and len(result["processes"]) >= 2:
                    return result
                time.sleep(0.03)
            raise ControlError("COMMAND_RUNTIME_DESCENDANT_NOT_OBSERVED")

        try:
            start_authority(initialize=True)
            start_supervisor()

            case = new_case("command_positive")
            results: dict[str, Any] = {}
            launch_positive(case, results)
            before_cleanup = docker_snapshot()
            start_call = [call for call in inventory()["docker_calls"] if call["operation"] == "start"][-1]
            results["cleanup"] = clean(case)
            finish_case(case, results, {"actual_stdout_marker": start_call["stdout"] == "LIMINAL_COMMAND_POSITIVE\n",
                "positive_fixture_exit": start_call["returncode"] == 0, "quiescence_independently_settled": results["cleanup"]["process_quiescent"]},
                positive_stdout=start_call["stdout"], independent_docker_before_cleanup=before_cleanup)

            case = new_case("command_binding_swap")
            action = approve(case)
            swapped = deepcopy(action)
            swapped["arguments"]["spec"]["argv"][-1] = "descendant"
            denied = case["worker"].call("execute", action=swapped)
            finish_case(case, {"execute_create": denied}, {"altered_argv_rejected": denied["status"] in {"DENIED", "ERROR"},
                "no_actual_daemon_launch": counts(inventory()) == counts(case["supervisor_before"])}, swapped_action=swapped)

            case = new_case("command_stop_before_create")
            action = approve(case)
            stopped = capture(admin, "stop", root_id=case["root_id"])
            denied = case["worker"].call("execute", action=action)
            finish_case(case, {"execute_create": denied}, {"admission_closed": stopped["status"] == "STOPPED",
                "old_grant_denied": denied["status"] == "DENIED", "no_actual_daemon_launch": counts(inventory()) == counts(case["supervisor_before"])},
                stop_response=stopped)

            case = new_case("command_stop_between_create_start")
            action = approve(case)
            results = {"execute_create": case["worker"].call("execute", action=action)}
            results["reconcile_create"] = wait_create(case)
            start = approve(case, "START")
            created_inspection = docker_snapshot()
            stopped = capture(admin, "stop", root_id=case["root_id"])
            results["execute_start"] = case["worker"].call("execute", action=start)
            results["cleanup"] = clean(case)
            final = capture(admin, "status", root_id=case["root_id"])
            finish_case(case, results, {"create_keeps_lifecycle_pending": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1,
                "later_start_denied": results["execute_start"]["status"] == "DENIED", "cleanup_settles_created_object": final["state"] == "STOPPED"},
                stop_response=stopped, final_stop_state=final, independent_created_inspection=created_inspection)

            case = new_case("command_pending_launch_stop")
            action = approve(case)
            reached, release = work / "create-callback-reached", work / "create-callback-release"
            host.call("faults", hold_stage="CREATE", reached_file=str(reached), release_file=str(release))
            results = {"execute_create": case["worker"].call("execute", action=action)}
            try:
                _wait_file(reached)
                held = inventory()
                held_daemon = docker_snapshot()
                stopped = capture(admin, "stop", root_id=case["root_id"])
                results["retry"] = case["worker"].call("execute", action=action)
                results["held_cleanup"] = host.call("cleanup", command_id=case["command_id"])
            finally:
                release.write_text("release\n")
            host.call("faults")
            results["reconcile_create"] = wait_create(case)
            start = approve(case, "START")
            results["execute_start"] = case["worker"].call("execute", action=start)
            results["cleanup"] = clean(case)
            final = capture(admin, "status", root_id=case["root_id"])
            finish_case(case, results, {"daemon_create_finished_but_callback_held": held["docker_calls"][-1]["finished_at"] is not None
                    and next(grant for grant in held["grants"] if grant["action"]["action_id"] == action["action_id"])["callback_phase"] == "INFLIGHT",
                "no_early_stop_ack": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 1,
                "held_cleanup_unknown": results["held_cleanup"]["status"] == "UNKNOWN", "old_permit_not_reissued": results["retry"]["status"] == "UNKNOWN",
                "later_start_denied": results["execute_start"]["status"] == "DENIED", "terminal_after_release": final["state"] == "STOPPED"},
                held_supervisor_inventory=held, held_independent_docker=held_daemon, stop_response=stopped, final_stop_state=final)

            case = new_case("command_lost_launch_response")
            action = approve(case)
            reached, release = work / "dispatcher-delivery-reached", work / "dispatcher-delivery-release"
            case["operator"].call("faults", drop_delivery=True, delivery_reached=str(reached), delivery_release=str(release))
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(case["worker"].call, "execute", action=action)
                _wait_file(reached)
                committed_callback = wait_finished(case, "create")
                crash = stop_dispatcher(case)
                lost_result = pending.result(timeout=10)
            dispatch(case, initialize=False)
            results = {"execute_create": lost_result, "reconcile_create": wait_create(case)}
            start = approve(case, "START")
            results["execute_start"] = case["worker"].call("execute", action=start)
            wait_finished(case, "start")
            results["cleanup"] = clean(case)
            results["retry"] = case["worker"].call("execute", action=action)
            finish_case(case, results, {"delivery_loss_preserved": lost_result["status"] == "UNKNOWN",
                "real_callback_completed_before_crash": committed_callback["docker_calls"][-1]["finished_at"] is not None,
                "dispatcher_actually_restarted": crash["pid"] != case["child"].pid and crash["reaped"],
                "owned_original_reconciled": results["cleanup"]["process_quiescent"]},
                dispatcher_crash=crash, dispatcher_restarted_pid=case["child"].pid, supervisor_after_lost_delivery=committed_callback,
                lost_response_boundary="actual CREATE daemon return persisted before dispatcher HTTP delivery/cache result lost")

            case = new_case("command_restore_local_state")
            cache_snapshot = case["operator"].call("inventory")
            stop_dispatcher(case)
            backup = _backup(case["db"], case["directory"] / "old-cache.sqlite")
            dispatch(case, initialize=False)
            results = {}
            launch_positive(case, results)
            results["cleanup"] = clean(case)
            cache_before = case["operator"].call("inventory")
            before_restore = inventory()
            stop_dispatcher(case)
            restored = _backup(case["directory"] / "old-cache.sqlite", case["db"])
            dispatch(case, initialize=False)
            cache_after = case["operator"].call("inventory")
            results["retry"] = case["worker"].call("execute", action=case["actions"]["create"])
            after_retry = inventory()
            restore = {**restored, "dispatcher_stopped_during_restore": True, "authority_database_not_restored": True,
                "supervisor_database_not_restored": True, "registry_database_not_restored": True,
                "cache_snapshot": cache_snapshot, "cache_before": cache_before, "cache_after": cache_after,
                "scope": "non-authorizing proposal cache only; supervisor/registry rollback unsupported"}
            finish_case(case, results, {"proposal_cache_rolled_back": len(cache_before["rows"]) == 2 and not cache_after["rows"],
                "no_new_create_after_restore": counts(before_restore) == counts(after_retry),
                "consumed_action_observed": results["retry"]["status"] == "QUIESCENT"},
                snapshot=backup, restore=restore, supervisor_before_restore=before_restore)

            case = new_case("command_descendant_cleanup", "descendant")
            action = approve(case)
            results = {"execute_create": case["worker"].call("execute", action=action), "reconcile_create": wait_create(case)}
            start = approve(case, "START")
            results["execute_start"] = case["worker"].call("execute", action=start)
            tree = wait_descendants(case)
            # An independently created harmless sentinel is a negative cleanup
            # control, outside the command profile and its stage counters.
            from adapters.docker.liminal_docker_executor import build_docker_argv
            from .external_command_protocol import command_plan
            sentinel_name = "liminal-unrelated-" + secrets.token_hex(16)
            sentinel_args = build_docker_argv(command_plan(case["spec"]), docker_binary=docker_binary, container_name=sentinel_name)
            sentinel_args[1:3] = ["create", "--interactive"]
            sentinel_args[-1] = "sentinel"
            sentinel_args[sentinel_args.index(image):sentinel_args.index(image)] = ["--entrypoint", "python3", "--log-driver", "none",
                "--label", "liminal.fixture.role=unrelated-sentinel"]
            sentinel_created = docker.command(sentinel_args[1:], timeout=30)
            sentinel_id = sentinel_created.stdout.decode().strip()
            if sentinel_created.returncode or len(sentinel_id) != 64:
                raise ControlError("COMMAND_RUNTIME_SENTINEL_CREATE_FAILED")
            if docker.command(["start", sentinel_id], timeout=10).returncode:
                raise ControlError("COMMAND_RUNTIME_SENTINEL_START_FAILED")
            sentinel_before = process_snapshot(sentinel_id)
            term = docker.command(["kill", "--signal", "TERM", tree["container_id"]], timeout=5)
            time.sleep(0.15)
            after_term = process_snapshot(tree["container_id"])
            stopped = capture(admin, "stop", root_id=case["root_id"])
            results["cleanup"] = clean(case)
            sentinel_after = process_snapshot(sentinel_id)
            final = capture(admin, "status", root_id=case["root_id"])
            finish_case(case, results, {"owned_descendant_observed": len(tree["processes"]) >= 2,
                "actual_term_ignored": term.returncode == 0 and after_term["running"],
                "stop_pending_while_process_live": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 2,
                "fresh_quiescence_after_forced_cleanup": final["state"] == "STOPPED" and results["cleanup"]["process_quiescent"],
                "unrelated_sentinel_survived": sentinel_before["container_id"] == sentinel_after["container_id"] and sentinel_after["running"]},
                process_tree=tree, process_tree_after_term=after_term, graceful_signal_returncode=term.returncode,
                unrelated_sentinel_before=sentinel_before, unrelated_sentinel_after=sentinel_after,
                unrelated_sentinel_setup={"role": "trusted negative control outside command profile", "container_id": sentinel_id,
                    "create_returncode": sentinel_created.returncode, "image_id": image}, stop_response=stopped, final_stop_state=final)
            if docker.command(["rm", "--force", sentinel_id], timeout=10).returncode:
                raise ControlError("COMMAND_RUNTIME_SENTINEL_CLEANUP_FAILED")
            sentinel_id = None

            case = new_case("command_observation_unavailable", "descendant")
            action = approve(case)
            results = {"execute_create": case["worker"].call("execute", action=action), "reconcile_create": wait_create(case)}
            start = approve(case, "START")
            results["execute_start"] = case["worker"].call("execute", action=start)
            tree = wait_descendants(case)
            host.call("faults", observation_unavailable=True)
            results["unavailable_reconcile"] = case["worker"].call("reconcile", action_id=start["action_id"])
            results["unavailable_cleanup"] = host.call("cleanup", command_id=case["command_id"])
            unavailable_inventory = inventory()
            stopped = capture(admin, "stop", root_id=case["root_id"])
            host.call("faults")
            results["cleanup"] = clean(case)
            final = capture(admin, "status", root_id=case["root_id"])
            finish_case(case, results, {"original_observation_unknown": results["unavailable_reconcile"]["status"] == "UNKNOWN",
                "original_cleanup_unknown": results["unavailable_cleanup"]["status"] == "UNKNOWN" and not results["unavailable_cleanup"]["process_quiescent"],
                "unknown_keeps_stop_pending": stopped["status"] == "STOP_PENDING" and stopped["pending_count"] == 2,
                "later_fresh_recovery_separate": final["state"] == "STOPPED" and results["cleanup"]["process_quiescent"]},
                process_tree=tree, unavailable_supervisor_inventory=unavailable_inventory, stop_response=stopped, final_stop_state=final)

            case = new_case("command_authority_restart_outage")
            results = {}
            launch_positive(case, results)
            results["cleanup"] = clean(case)
            stopped = capture(admin, "stop", root_id=case["root_id"])
            original_pid, port = authority_child.pid, urlparse(authority_url).port
            stop_child(authority_child, "external_authority")
            start_authority(initialize=False, port=port)
            restarted = capture(admin, "status", root_id=case["root_id"])
            results["retry"] = case["worker"].call("execute", action=case["actions"]["create"])
            outage_root = "runtime:command-outage-control"
            outage_policy = digest({"profile": COMMAND_PROFILE, "control": "outage"})
            capture(admin, "create_root", root_id=outage_root, receiver_id=supervisor_pin["supervisor_id"],
                policy_digest=outage_policy, max_actions=2, lifetime_seconds=300)
            capture(admin, "bind_execution", root_id=outage_root, execution_id=outage_root + ":worker")
            outage_action = command_action(action_id=outage_root + ":create", attempt_id=outage_root + ":attempt",
                root_id=outage_root, execution_id=outage_root + ":worker", epoch=1, stage="CREATE",
                spec=command_spec(outage_root + ":command", image, str(workspace)))
            outage_grant = {"action_digest": digest(outage_action), "policy_version": outage_policy,
                "expires_at": time.time() + 120, "receiver_id": supervisor_pin["supervisor_id"]}
            approved = host.call("authorize", action=outage_action, grant=outage_grant)
            if approved.get("status") != "AUTHORIZED":
                raise ControlError("COMMAND_RUNTIME_OUTAGE_CONTROL_NOT_AUTHORIZED")
            restarted_pid = authority_child.pid
            stop_child(authority_child, "external_authority")
            before_outage = inventory()
            results["outage"] = case["worker"].call("execute", action=outage_action)
            after_outage = inventory()
            start_authority(initialize=False, port=port)
            outage_query = capture(external_receiver, "query", action_id=outage_action["action_id"])
            finish_case(case, results, {"actual_authority_restart": original_pid != restarted_pid,
                "durable_stop_and_consumption": restarted["state"] == "STOPPED" and restarted["epoch"] == stopped["epoch"]
                    and restarted["committed_count"] == 2,
                "outage_no_fresh_daemon_launch": counts(before_outage) == counts(after_outage) and results["outage"]["status"] == "UNKNOWN",
                "outage_action_not_issued": outage_query.get("status") == "UNKNOWN" and outage_query.get("reservation_id") is None},
                stop_response=stopped, restarted_external_state=restarted, original_authority_pid=original_pid,
                restarted_authority_pid=restarted_pid, outage_action=outage_action, outage_authorization=outage_grant,
                outage_supervisor_before=before_outage, outage_supervisor_after=after_outage, outage_external_query=outage_query)

            final_inventory = inventory()
            final_docker_inventory = docker_snapshot()
            checkpoints = capture(admin, "checkpoints")
            entries = checkpoints["entries"] if isinstance(checkpoints, dict) else checkpoints
            verification = verify_checkpoint_chain(entries, authority_id=authority_pin["authority_id"],
                signer_id=authority_pin["authority_id"], key_id=authority_pin["key_id"], public_key=authority_pin["public_key"])
        finally:
            for release_name in ("create-callback-release", "dispatcher-delivery-release"):
                (work / release_name).write_text("release during bounded host cleanup\n")
            if host is not None:
                try:
                    host.call("faults")
                    for command in inventory()["commands"]:
                        if not command["cleanup_complete"]:
                            deadline = time.monotonic() + 3
                            while time.monotonic() < deadline:
                                if host.call("cleanup", command_id=command["command_id"]).get("process_quiescent"):
                                    break
                                time.sleep(0.03)
                except Exception:
                    pass
            for child in list(live_dispatchers):
                stop_child(child, "proposal_dispatcher")
            if sentinel_id is not None:
                docker.command(["rm", "--force", sentinel_id], timeout=10)
            if supervisor_child is not None:
                stop_child(supervisor_child, "owned_workload_supervisor")
            if authority_child is not None and authority_child.process.poll() is None:
                stop_child(authority_child, "external_authority")

    checks = {name + ":" + key: value for name, outcome in outcomes.items() for key, value in outcome["checks"].items()}
    checks.update({"all_cases_collected": set(outcomes) == set(CASE_IDS),
        "all_child_processes_reaped": all(row["reaped"] for row in cleanup)
            and {row["pid"] for row in processes} == {row["pid"] for row in cleanup},
        "separate_trusted_roles": authority_pin["public_key"] != supervisor_pin["public_key"]
            and all(row["pid"] != os.getpid() for row in processes),
        "no_unfinished_registry": not final_inventory["unfinished_registry"],
        "all_created_owned_objects_removed": all(row["available"] and row["exists"] is False for row in final_docker_inventory["objects"]),
        "all_dispatched_callbacks_finished": all(grant["callback_phase"] == "FINISHED" for grant in final_inventory["grants"] if grant["reservation_id"]),
        "public_checkpoint_signatures_verified": verification["verification_status"] == "LOCAL_SIGNATURE_ONLY"})
    source = _source()
    source["scope"] = "checked-out commit/tree; source_files_sha256 binds actual runtime inputs"
    return {"schema": SCHEMA, "source": source, "source_files_sha256": _sources(), "preregistration": design,
        "controller_pid": os.getpid(), "authority_public_pin": authority_pin, "supervisor_public_pin": supervisor_pin,
        "outcomes": outcomes, "checks": checks, "passed": all(checks.values()), "authority_evidence": authority_evidence,
        "authority_checkpoints": entries, "checkpoint_anchor": verification["tip"], "checkpoint_verification": verification,
        "checkpoint_anchor_provenance": "collector-observed tip; no independently owned latest-anchor service",
        "supervisor_final_inventory": final_inventory, "independent_docker_final_inventory": final_docker_inventory,
        "docker_identity": daemon_identity, "processes": processes, "cleanup": cleanup,
        "scope": {"actual_docker": True, "distinct_authority_supervisor_processes": True, "separate_sqlite_databases": True,
            "model_calls": 0, "private_keys_bundled": False, "business_effects": "NOT_ESTABLISHED", "arbitrary_shell": "NOT_RUN",
            "kernel_containment": "NOT_ESTABLISHED", "independent_latest_anchor": "NOT_ESTABLISHED", "live_training": "NOT_RUN",
            "authority_pin_provenance": "fixture-generated", "supervisor_pin_provenance": "fixture-generated",
            "rollback_scope": "dispatcher proposal cache only", "supervisor_registry_rollback": "NOT_SUPPORTED",
            "dispatcher_os_isolation": "NOT_ESTABLISHED",
            "trusted_host_daemon_and_supervisor_intact": True, "external_human_reproduction": "NOT_ESTABLISHED"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--docker-binary", default="docker")
    parser.add_argument("--supervisor-service", action="store_true")
    parser.add_argument("--dispatcher-service", action="store_true")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--supervisor-id")
    parser.add_argument("--key-id")
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--authority-url")
    parser.add_argument("--authority-request-key-file", type=Path)
    parser.add_argument("--authority-pin-file", type=Path)
    parser.add_argument("--operator-key-file", type=Path)
    parser.add_argument("--worker-key-file", type=Path)
    parser.add_argument("--supervisor-url")
    parser.add_argument("--initialize", action="store_true")
    args = parser.parse_args()
    if args.supervisor_service or args.dispatcher_service:
        return _service(args)
    if args.output is None:
        parser.error("--output required")
    report = run_demo(image=args.image, docker_binary=args.docker_binary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, report)
    print(json.dumps({"passed": report["passed"], "source": report["source"], "report": str(args.output.resolve())}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
