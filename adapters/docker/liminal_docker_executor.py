#!/usr/bin/env python3
"""Trusted Docker backend for LiminalOS isolated execution and containment.

The model-facing SDK never receives Docker/container authority or raw host PIDs.
This trusted adapter assigns opaque session identities, can expose a bounded
process-tree backend to the canonical containment supervisor, and retains immutable daemon/container identities for bounded reconciliation.
Unacknowledged requests never establish a successful cleanup claim.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any, Callable, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sdk.liminal_isolated_execution import IsolatedExecutionPlan
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_process_tree_containment import (
    ACTION_SCHEMA,
    OBSERVATION_SCHEMA,
    ProcessTreeContainmentSupervisor,
)
from sdk.liminal_runtime_mediation import ExecutionObservation
from sdk.liminal_runtime_mediation import ExecutionOutcomeUnknown
from adapters.docker._bounded_cli import OutputLimitExceeded, run_cli

_CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
ZERO_SHA256 = "0" * 64
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_INSPECT_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                   '"session":{{json (index .Config.Labels "org.liminal.session")}},'
                   '"plan":{{json (index .Config.Labels "org.liminal.plan")}},'
                   '"status":{{json .State.Status}},"running":{{json .State.Running}},'
                   '"exit_code":{{json .State.ExitCode}}}')


class DockerExecutionError(RuntimeError):
    def __init__(self, message: str, *, session=None, phase=None, cleanup_state="UNKNOWN"):
        super().__init__(message)
        self.session = session
        self.phase = phase
        self.cleanup_state = cleanup_state


class DockerReconciliationRequired(DockerExecutionError, ExecutionOutcomeUnknown):
    pass


class DockerExecutionTimeout(DockerExecutionError, ExecutionOutcomeUnknown):
    pass


class DockerOutputLimitError(DockerExecutionError, ExecutionOutcomeUnknown):
    pass


@dataclass(frozen=True)
class DockerRunResult:
    session_id: str
    returncode: int
    stdout: bytes
    container_id: str
    daemon_id: str


@dataclass(frozen=True)
class DockerSessionIdentity:
    session_id: str
    plan_sha256: str
    image_id: str
    daemon_id: str
    container_id: str | None = None

    def as_document(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _validate_container_name(value: str) -> str:
    if not isinstance(value, str) or not _CONTAINER.fullmatch(value):
        raise DockerExecutionError("invalid trusted container/session name")
    return value


def build_docker_argv(
    plan: IsolatedExecutionPlan,
    *,
    docker_binary: str = "docker",
    container_name: str | None = None,
    entrypoint: str = "",
) -> list[str]:
    """Build a trusted launch; an empty entrypoint executes the exact plan argv.

    Fixed host-owned worker profiles may explicitly supply their interpreter.
    This override is adapter configuration, never model-supplied plan data.
    """
    plan.validate()
    if not isinstance(entrypoint, str) or "\x00" in entrypoint:
        raise DockerExecutionError("invalid trusted entrypoint override")
    p = plan.profile
    out = [docker_binary, "run", "--rm"]
    if container_name is not None:
        out += ["--name", _validate_container_name(container_name)]
    out += [
        "--entrypoint", entrypoint,
        "--log-driver", "none",
        "--network", p.network_mode,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", f"{p.uid}:{p.gid}",
        "--pids-limit", str(p.pids_limit),
        "--memory", f"{p.memory_mb}m",
        "--cpus", p.cpus,
        "--tmpfs", p.tmpfs,
        "--workdir", "/workspace",
        "--mount", f"type=bind,src={plan.host_workspace},dst=/workspace,readonly",
        plan.image_id,
        *plan.argv,
    ]
    return out


class DockerProcessTreeBackend:
    """Concrete trusted backend for one already-running governed container.

    Raw host PIDs never leave this adapter. They are converted to opaque,
    session-bound process identities and retained as terminated tombstones after
    removal so the supervisor can prove that nodes did not merely disappear.
    """

    def __init__(self, *, session_id: str, docker_binary: str = "docker") -> None:
        self.session_id = _validate_container_name(session_id)
        self.docker_binary = docker_binary
        self._daemon_identity = _daemon_id(docker_binary)
        observed = _inspect_object(self.session_id, docker_binary)
        if observed is None or observed.get("name") != "/" + self.session_id:
            raise DockerExecutionError("cannot attach to an unobserved execution session")
        self._container_id = observed["id"]
        self.backend_binding_sha256 = canonical_sha256(
            {"backend": "docker-process-tree-v2", "session_id": self.session_id,
             "container_id": self._container_id, "daemon_id": self._daemon_identity}
        )
        self._raw_to_opaque: dict[str, str] = {}
        self._parents: dict[str, str | None] = {}
        self._identities: dict[str, str] = {}
        self._root_process_id: str | None = None
        self._terminated = False

    @property
    def root_process_id(self) -> str:
        if self._root_process_id is None:
            self._observe_live_nodes()
        if self._root_process_id is None:
            raise DockerExecutionError("governed container has no observable root process")
        return self._root_process_id

    def supervisor(self) -> ProcessTreeContainmentSupervisor:
        return ProcessTreeContainmentSupervisor(
            session_id=self.session_id,
            root_process_id=self.root_process_id,
            backend_binding_sha256=self.backend_binding_sha256,
            backend=self,
        )

    def snapshot(self, session_id: str) -> dict[str, Any]:
        self._require_session(session_id)
        if self._terminated or not self._container_exists():
            if not self._raw_to_opaque:
                raise DockerExecutionError("cannot attest an execution session that was never observed")
            nodes = self._tombstones()
        else:
            nodes = self._observe_live_nodes()
        return self._observation(nodes)

    def freeze(self, session_id: str) -> dict[str, Any]:
        self._require_session(session_id)
        before = self.snapshot(session_id)
        live_count = sum(node["state"] != "terminated" for node in before["nodes"])
        proc = run_cli([self.docker_binary, "pause", self._container_id], timeout=10)
        self._require_daemon()
        if proc.returncode != 0:
            raise DockerExecutionError("docker pause failed for governed execution session")
        after = self.snapshot(session_id)
        lineage = lambda nodes: {
            node["process_id"]: (node["parent_process_id"], node["identity_sha256"])
            for node in nodes
        }
        if (before["root_process_id"] != after["root_process_id"]
                or lineage(before["nodes"]) != lineage(after["nodes"])):
            raise DockerExecutionError("trusted process lineage changed during freeze")
        after_states = {node["process_id"]: node["state"] for node in after["nodes"]}
        if any(after_states[node["process_id"]] !=
               ("terminated" if node["state"] == "terminated" else "frozen")
               for node in before["nodes"]):
            raise DockerExecutionError("governed execution session was not observed frozen")
        return self._action("freeze", live_count, after["nodes"])

    def terminate(self, session_id: str) -> dict[str, Any]:
        self._require_session(session_id)
        before = self.snapshot(session_id)
        live_count = sum(node["state"] != "terminated" for node in before["nodes"])
        self._require_daemon()
        _remove_container_verified(self._container_id, docker_binary=self.docker_binary)
        self._require_daemon()
        self._terminated = True
        return self._action("terminate", live_count, self._tombstones())

    def _observe_live_nodes(self) -> list[dict[str, Any]]:
        self._require_daemon()
        inspect = run_cli(
            [self.docker_binary, "inspect", "--format", "{{.State.Pid}} {{.State.Running}} {{.State.Paused}}", self._container_id],
            timeout=10,
        )
        if inspect.returncode != 0:
            raise DockerExecutionError("docker inspect failed for governed execution session")
        fields = inspect.stdout.decode("ascii").strip().split()
        if len(fields) != 3 or not fields[0].isdigit() or fields[1] not in {"true", "false"} or fields[2] not in {"true", "false"}:
            raise DockerExecutionError("docker inspect returned invalid process state")
        root_raw = fields[0]
        state = "frozen" if fields[2] == "true" else "running"
        if fields[1] != "true" and fields[2] != "true":
            raise DockerExecutionError("governed container is not running")

        # Do not pass host-specific `ps` formatting flags through `docker top`.
        # Docker delegates those flags to the host `ps` implementation, and the
        # accepted syntax differs across runner images. Parse the default table
        # by its PID/PPID headers instead; raw host PIDs remain inside this
        # trusted adapter and never enter model-facing receipts.
        top = run_cli([self.docker_binary, "top", self._container_id], timeout=10, stdout_limit=64 * 1024)
        self._require_daemon()
        if top.returncode != 0:
            raise DockerExecutionError("docker top failed for governed execution session")
        lines = [line for line in top.stdout.decode("utf-8").splitlines() if line.strip()]
        if len(lines) < 2:
            raise DockerExecutionError("docker top returned no process rows")
        header = lines[0].split()
        try:
            pid_index = header.index("PID")
            ppid_index = header.index("PPID")
        except ValueError as exc:
            raise DockerExecutionError("docker top output lacks PID/PPID columns") from exc
        required_index = max(pid_index, ppid_index)
        pairs: list[tuple[str, str]] = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) <= required_index:
                raise DockerExecutionError("docker top returned invalid pid lineage")
            raw_pid = parts[pid_index]
            raw_parent = parts[ppid_index]
            if not raw_pid.isdigit() or not raw_parent.isdigit():
                raise DockerExecutionError("docker top returned non-numeric pid lineage")
            pairs.append((raw_pid, raw_parent))
        raw_ids = {pid for pid, _ in pairs}
        if root_raw not in raw_ids:
            raise DockerExecutionError("container root PID missing from docker top")

        for raw_pid, raw_parent in pairs:
            opaque = self._opaque(raw_pid)
            if raw_pid == root_raw:
                parent = None
            else:
                if raw_parent not in raw_ids:
                    raise DockerExecutionError("container process has parent outside observed session")
                parent = self._opaque(raw_parent)
            existing = self._parents.get(opaque)
            if existing is not None and existing != parent:
                raise DockerExecutionError("trusted process lineage changed during session")
            self._parents[opaque] = parent
        self._root_process_id = self._opaque(root_raw)

        nodes = []
        for raw_pid, _ in sorted(pairs, key=lambda item: int(item[0])):
            opaque = self._opaque(raw_pid)
            nodes.append({
                "process_id": opaque,
                "parent_process_id": self._parents[opaque],
                "identity_sha256": self._identities[opaque],
                "state": state,
            })
        return nodes

    def _opaque(self, raw_pid: str) -> str:
        item = self._raw_to_opaque.get(raw_pid)
        if item is None:
            item = "proc:" + canonical_sha256({"session": self.session_id, "host_pid": raw_pid})[:32]
            self._raw_to_opaque[raw_pid] = item
            self._identities[item] = canonical_sha256(
                {"session": self.session_id, "opaque_process_id": item}
            )
        return item

    def _tombstones(self) -> list[dict[str, Any]]:
        ordered = sorted(self._parents)
        return [{
            "process_id": pid,
            "parent_process_id": self._parents[pid],
            "identity_sha256": self._identities[pid],
            "state": "terminated",
        } for pid in ordered]

    def _observation(self, nodes: list[dict[str, Any]]) -> dict[str, Any]:
        if self._root_process_id is None:
            raise DockerExecutionError("missing root process identity")
        canonical_nodes = sorted(nodes, key=lambda n: n["process_id"])
        tree_sha = canonical_sha256(canonical_nodes)
        body = {
            "schema": OBSERVATION_SCHEMA,
            "session_id": self.session_id,
            "root_process_id": self._root_process_id,
            "backend_binding_sha256": self.backend_binding_sha256,
            "nodes": canonical_nodes,
            "tree_sha256": tree_sha,
        }
        return {**body, "evidence_sha256": canonical_sha256(body)}

    def _action(self, action: str, affected_count: int, nodes: list[dict[str, Any]]) -> dict[str, Any]:
        result_tree_sha = canonical_sha256(sorted(nodes, key=lambda n: n["process_id"]))
        body = {
            "schema": ACTION_SCHEMA,
            "session_id": self.session_id,
            "root_process_id": self.root_process_id,
            "backend_binding_sha256": self.backend_binding_sha256,
            "action": action,
            "affected_count": affected_count,
            "result_tree_sha256": result_tree_sha,
        }
        return {**body, "evidence_sha256": canonical_sha256(body)}

    def _container_exists(self) -> bool:
        self._require_daemon()
        exists = _container_exists(self._container_id, docker_binary=self.docker_binary)
        self._require_daemon()
        return exists

    def _require_daemon(self) -> None:
        if _daemon_id(self.docker_binary) != self._daemon_identity:
            raise DockerExecutionError("attached execution daemon identity changed")

    def _require_session(self, session_id: str) -> None:
        if session_id != self.session_id:
            raise DockerExecutionError("cross-session Docker process control is forbidden")


class DockerExecutor:
    def __init__(self, docker_binary: str = "docker", *,
                 session_observer: Callable[[DockerSessionIdentity], None] | None = None) -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise DockerExecutionError("docker_binary must be non-empty")
        if session_observer is not None and not callable(session_observer):
            raise DockerExecutionError("session_observer must be callable")
        self.docker_binary = docker_binary
        self.session_observer = session_observer

    def __call__(self, plan: IsolatedExecutionPlan) -> ExecutionObservation:
        proc = run_docker_plan(plan, docker_binary=self.docker_binary, session_observer=self.session_observer)
        return ExecutionObservation.success({
            "backend": "docker",
            "plan_sha256": plan.plan_sha256,
            "image_id": plan.image_id,
            "exit_code": proc.returncode,
            "workload_status": "zero" if proc.returncode == 0 else "nonzero",
            "execution_session_sha256": canonical_sha256(proc.session_id),
            "stdout": "discarded",
            "stderr": "discarded",
        })


def _daemon_id(docker_binary: str) -> str:
    try:
        result = run_cli([docker_binary, "info", "--format", "{{.ID}}"], timeout=10, stdout_limit=1024)
        identity = result.stdout.decode("utf-8").strip()
    except (OSError, subprocess.TimeoutExpired, OutputLimitExceeded, UnicodeDecodeError) as exc:
        raise DockerExecutionError("Docker daemon identity unavailable") from exc
    if result.returncode != 0 or not identity or len(identity) > 256:
        raise DockerExecutionError("Docker daemon identity unavailable")
    return identity


def _same_daemon(identity: DockerSessionIdentity, docker_binary: str) -> None:
    if _daemon_id(docker_binary) != identity.daemon_id:
        raise DockerExecutionError("Docker daemon identity changed; reconciliation required")


def _inspect_object(reference: str, docker_binary: str) -> dict[str, Any] | None:
    result = run_cli([docker_binary, "inspect", "--format", _INSPECT_FORMAT, reference], timeout=10, stdout_limit=8192)
    if result.returncode != 0:
        if _is_not_found(result.stderr.decode("utf-8", errors="replace")):
            return None
        raise DockerExecutionError("Docker container observation unavailable")
    try:
        observed = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise DockerExecutionError("invalid Docker container observation") from exc
    if not isinstance(observed, dict) or not _CONTAINER_ID.fullmatch(str(observed.get("id", ""))):
        raise DockerExecutionError("invalid immutable Docker container ID")
    return observed


def _validate_owned_object(identity: DockerSessionIdentity, observed: dict[str, Any]) -> None:
    if (observed.get("name") != "/" + identity.session_id
            or observed.get("image") != identity.image_id
            or observed.get("session") != identity.session_id
            or observed.get("plan") != identity.plan_sha256
            or (identity.container_id is not None and observed["id"] != identity.container_id)):
        raise DockerExecutionError("Docker resource ownership mismatch")


def reconcile_docker_session(identity: DockerSessionIdentity, *, docker_binary: str = "docker") -> dict[str, Any]:
    """Remove only an observed owned immutable ID, never a replacement name.

    An unacknowledged create remains UNKNOWN even when presently absent or when
    one late-created inert object was removed: a pending request is not cancelled
    by an absence observation. Recovery never starts the object.
    """
    _validate_container_name(identity.session_id)
    if identity.container_id is not None and not _CONTAINER_ID.fullmatch(identity.container_id):
        raise DockerExecutionError("invalid reconciliation container ID")
    try:
        _same_daemon(identity, docker_binary)
        reference = identity.container_id or identity.session_id
        observed = _inspect_object(reference, docker_binary)
        target_id = identity.container_id
        if observed is not None:
            _validate_owned_object(identity, observed)
            target_id = observed["id"]
            removal = run_cli([docker_binary, "rm", "-f", target_id], timeout=15)
            if removal.returncode != 0 and not _is_not_found(removal.stderr.decode("utf-8", errors="replace")):
                raise DockerExecutionError("failed to terminate governed execution session")
            _same_daemon(identity, docker_binary)
            if _inspect_object(target_id, docker_binary) is not None:
                raise DockerExecutionError("governed execution session survived forced removal")
        _same_daemon(identity, docker_binary)
        return {
            "session": identity.as_document(), "observed_container_id": target_id,
            "cleanup_state": "VERIFIED_ABSENT" if identity.container_id is not None else "UNKNOWN",
            "creation_acknowledged": identity.container_id is not None,
        }
    except Exception as exc:
        raise DockerReconciliationRequired("Docker cleanup outcome is unknown", session=identity,
                                           phase="CLEANUP", cleanup_state="UNKNOWN") from exc


def run_docker_plan(
    plan: IsolatedExecutionPlan,
    *,
    docker_binary: str = "docker",
    stdout_limit: int | None = None,
    session_observer: Callable[[DockerSessionIdentity], None] | None = None,
) -> DockerRunResult:
    """Create inertly, bind immutable identity, then start and reconcile by ID."""
    plan.validate()
    if stdout_limit is not None and (isinstance(stdout_limit, bool) or not isinstance(stdout_limit, int) or stdout_limit < 1):
        raise DockerExecutionError("stdout_limit must be a positive byte count")
    if session_observer is not None and not callable(session_observer):
        raise DockerExecutionError("session_observer must be callable")
    # Failure before any create request is a configuration/transport failure,
    # never evidence that a container or workload was launched.
    session = DockerSessionIdentity(_new_session_id(plan), plan.plan_sha256, plan.image_id, _daemon_id(docker_binary))
    argv = build_docker_argv(plan, docker_binary=docker_binary, container_name=session.session_id)
    argv[1:3] = ["create", "--restart", "no", "--label", "org.liminal.session=" + session.session_id,
                 "--label", "org.liminal.plan=" + session.plan_sha256]
    if session_observer is not None:
        session_observer(session)
    deadline = time.monotonic() + plan.timeout_seconds
    phase = "CREATE"
    try:
        created = run_cli(argv, timeout=max(0.001, min(10, deadline - time.monotonic())), stdout_limit=1024)
        container_id = created.stdout.decode("ascii").strip()
        if created.returncode != 0 or not _CONTAINER_ID.fullmatch(container_id):
            raise DockerExecutionError("Docker create was not acknowledged with an immutable ID")
        session = replace(session, container_id=container_id)
        if session_observer is not None:
            session_observer(session)
        _same_daemon(session, docker_binary)
        observed = _inspect_object(container_id, docker_binary)
        if observed is None:
            raise DockerExecutionError("created Docker resource is unavailable")
        _validate_owned_object(session, observed)
        if observed.get("status") != "created" or observed.get("running") is not False:
            raise DockerExecutionError("created Docker resource is not inert")
        phase = "START"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("governed Docker session", plan.timeout_seconds)
        started = run_cli([docker_binary, "start", "--attach", container_id], timeout=remaining,
                          stdout_limit=stdout_limit or 0, stderr_limit=0)
        phase = "OBSERVE"
        _same_daemon(session, docker_binary)
        observed = _inspect_object(container_id, docker_binary)
        if observed is None:
            raise DockerExecutionError("workload terminal state is unavailable")
        _validate_owned_object(session, observed)
        exit_code = observed.get("exit_code")
        if (observed.get("running") is not False or observed.get("status") != "exited"
                or isinstance(exit_code, bool) or not isinstance(exit_code, int)
                or started.returncode < 0 or exit_code != started.returncode):
            raise DockerExecutionError("Docker client result does not establish workload completion")
        phase = "CLEANUP"
        cleanup = reconcile_docker_session(session, docker_binary=docker_binary)
        if cleanup["cleanup_state"] != "VERIFIED_ABSENT":
            raise DockerExecutionError("Docker cleanup is unresolved")
        return DockerRunResult(session.session_id, exit_code, started.stdout, container_id, session.daemon_id)
    except BaseException as exc:
        try:
            cleanup = reconcile_docker_session(session, docker_binary=docker_binary)
            cleanup_state = cleanup["cleanup_state"]
        except Exception:
            cleanup_state = "UNKNOWN"
        # Even verified removal cannot reconstruct a lost workload outcome.
        # Transport interruption never means that the admitted action had no effect.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if cleanup_state == "UNKNOWN" or phase in {"CREATE", "OBSERVE", "CLEANUP"}:
            error = DockerReconciliationRequired("Docker execution outcome requires reconciliation",
                                                 session=session, phase=phase, cleanup_state=cleanup_state)
        elif isinstance(exc, subprocess.TimeoutExpired):
            error = DockerExecutionTimeout("isolated container timed out; process tree removed",
                                           session=session, phase=phase, cleanup_state=cleanup_state)
        elif isinstance(exc, OutputLimitExceeded):
            error = DockerOutputLimitError("isolated container stdout exceeded its byte limit",
                                          session=session, phase=phase, cleanup_state=cleanup_state)
        else:
            error = DockerReconciliationRequired("Docker execution outcome requires reconciliation",
                                                 session=session, phase=phase, cleanup_state=cleanup_state)
        raise error from exc


def build_process_tree_supervisor(*, session_id: str, docker_binary: str = "docker") -> ProcessTreeContainmentSupervisor:
    """Attach the canonical supervisor to one trusted, already-running session."""
    backend = DockerProcessTreeBackend(session_id=session_id, docker_binary=docker_binary)
    return backend.supervisor()


def _new_session_id(plan: IsolatedExecutionPlan) -> str:
    return _validate_container_name(f"liminal-{plan.plan_sha256[:16]}-{secrets.token_hex(8)}")


def _is_not_found(stderr: str) -> bool:
    text = (stderr or "").lower()
    return "no such object" in text or "no such container" in text


def _container_exists(session_id: str, *, docker_binary: str = "docker") -> bool:
    return _inspect_object(_validate_container_name(session_id), docker_binary) is not None


def _remove_container_verified(container_id: str, *, docker_binary: str = "docker") -> None:
    if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
        raise DockerExecutionError("verified removal requires a full container ID")
    proc = run_cli([docker_binary, "rm", "-f", container_id], timeout=15)
    if proc.returncode != 0 and not _is_not_found(proc.stderr.decode("utf-8", errors="replace")):
        raise DockerExecutionError("failed to terminate governed execution session")
    if _container_exists(container_id, docker_binary=docker_binary):
        raise DockerExecutionError("governed execution session survived forced removal")


def _probe(plan: IsolatedExecutionPlan, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    probe_plan = IsolatedExecutionPlan.build(
        operation_id=plan.operation_id,
        image_id=plan.image_id,
        argv=tuple(argv),
        host_workspace=plan.host_workspace,
        timeout_seconds=min(plan.timeout_seconds, 15),
        profile=plan.profile,
    )
    result = run_docker_plan(probe_plan, stdout_limit=64 * 1024)
    return subprocess.CompletedProcess(list(argv), result.returncode, result.stdout.decode("utf-8"), "")


def self_test(*, image_id: str, host_workspace: str) -> dict[str, bool]:
    base = IsolatedExecutionPlan.build(
        operation_id="docker-self-test",
        image_id=image_id,
        argv=("/bin/true",),
        host_workspace=host_workspace,
        timeout_seconds=15,
    )
    probes: dict[str, bool] = {}

    uid = _probe(base, ("/bin/sh", "-c", "id -u"))
    probes["non_root_uid"] = uid.returncode == 0 and uid.stdout.strip() == str(base.profile.uid)

    nnp = _probe(base, ("/bin/sh", "-c", "awk '/^NoNewPrivs:/{print $2}' /proc/self/status"))
    probes["no_new_privileges"] = nnp.returncode == 0 and nnp.stdout.strip() == "1"

    caps = _probe(base, ("/bin/sh", "-c", "awk '/^CapEff:/{print $2}' /proc/self/status"))
    probes["capabilities_dropped"] = caps.returncode == 0 and caps.stdout.strip() == "0000000000000000"

    root_mount = _probe(base, ("/bin/sh", "-c", "awk '$2==\"/\"{print $4}' /proc/mounts"))
    root_opts = set(root_mount.stdout.strip().split(","))
    probes["read_only_root"] = root_mount.returncode == 0 and "ro" in root_opts

    workspace_mount = _probe(base, ("/bin/sh", "-c", "awk '$2==\"/workspace\"{print $4}' /proc/mounts"))
    workspace_opts = set(workspace_mount.stdout.strip().split(","))
    probes["workspace_read_only"] = workspace_mount.returncode == 0 and "ro" in workspace_opts

    network = _probe(base, ("/bin/sh", "-c", "ls -1 /sys/class/net | sort"))
    probes["network_none"] = network.returncode == 0 and network.stdout.strip().splitlines() == ["lo"]

    if not all(probes.values()):
        failed = ",".join(sorted(name for name, passed in probes.items() if not passed))
        raise DockerExecutionError("isolation self-test failed: " + failed)
    return probes


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trusted LiminalOS Docker isolation adapter")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("image_id", nargs="?")
    parser.add_argument("host_workspace", nargs="?")
    args = parser.parse_args(argv)
    if not args.self_test:
        parser.error("only --self-test CLI mode is exposed; normal execution is library-driven")
    if not args.image_id or not args.host_workspace:
        parser.error("--self-test requires image_id and host_workspace")
    probes = self_test(image_id=args.image_id, host_workspace=args.host_workspace)
    print("isolation-self-test", canonical_sha256(probes), "PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
