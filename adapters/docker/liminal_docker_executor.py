#!/usr/bin/env python3
"""Trusted Docker backend for LiminalOS isolated execution and containment.

The model-facing SDK never receives Docker/container authority or raw host PIDs.
This trusted adapter assigns opaque session identities, can expose a bounded
process-tree backend to the canonical containment supervisor, and guarantees
that timeout cleanup verifies the named container no longer exists.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import sys
from typing import Any, Sequence

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

_CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
ZERO_SHA256 = "0" * 64


class DockerExecutionError(RuntimeError):
    pass


def _validate_container_name(value: str) -> str:
    if not isinstance(value, str) or not _CONTAINER.fullmatch(value):
        raise DockerExecutionError("invalid trusted container/session name")
    return value


def build_docker_argv(
    plan: IsolatedExecutionPlan,
    *,
    docker_binary: str = "docker",
    container_name: str | None = None,
) -> list[str]:
    plan.validate()
    p = plan.profile
    out = [docker_binary, "run", "--rm"]
    if container_name is not None:
        out += ["--name", _validate_container_name(container_name)]
    out += [
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
        self.backend_binding_sha256 = canonical_sha256(
            {"backend": "docker-process-tree-v1", "session_id": self.session_id}
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
        proc = subprocess.run(
            [self.docker_binary, "pause", self.session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if proc.returncode != 0:
            raise DockerExecutionError("docker pause failed for governed execution session")
        frozen_nodes = [dict(node, state="frozen") for node in before["nodes"]]
        return self._action("freeze", live_count, frozen_nodes)

    def terminate(self, session_id: str) -> dict[str, Any]:
        self._require_session(session_id)
        before = self.snapshot(session_id)
        live_count = sum(node["state"] != "terminated" for node in before["nodes"])
        _remove_container_verified(self.session_id, docker_binary=self.docker_binary)
        self._terminated = True
        return self._action("terminate", live_count, self._tombstones())

    def _observe_live_nodes(self) -> list[dict[str, Any]]:
        inspect = subprocess.run(
            [self.docker_binary, "inspect", "--format", "{{.State.Pid}} {{.State.Running}} {{.State.Paused}}", self.session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if inspect.returncode != 0:
            raise DockerExecutionError("docker inspect failed for governed execution session")
        fields = inspect.stdout.strip().split()
        if len(fields) != 3 or not fields[0].isdigit() or fields[1] not in {"true", "false"} or fields[2] not in {"true", "false"}:
            raise DockerExecutionError("docker inspect returned invalid process state")
        root_raw = fields[0]
        state = "frozen" if fields[2] == "true" else "running"
        if fields[1] != "true" and fields[2] != "true":
            raise DockerExecutionError("governed container is not running")

        top = subprocess.run(
            [self.docker_binary, "top", self.session_id, "-eo", "pid=,ppid="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if top.returncode != 0:
            raise DockerExecutionError("docker top failed for governed execution session")
        pairs: list[tuple[str, str]] = []
        for line in top.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                if line.strip():
                    raise DockerExecutionError("docker top returned invalid pid lineage")
                continue
            pairs.append((parts[0], parts[1]))
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
        proc = subprocess.run(
            [self.docker_binary, "inspect", self.session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if proc.returncode == 0:
            return True
        if _is_not_found(proc.stderr):
            return False
        raise DockerExecutionError("docker inspect failed during survivor verification")

    def _require_session(self, session_id: str) -> None:
        if session_id != self.session_id:
            raise DockerExecutionError("cross-session Docker process control is forbidden")


class DockerExecutor:
    def __init__(self, docker_binary: str = "docker") -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise DockerExecutionError("docker_binary must be non-empty")
        self.docker_binary = docker_binary

    def __call__(self, plan: IsolatedExecutionPlan) -> ExecutionObservation:
        session_id = _new_session_id(plan)
        argv = build_docker_argv(plan, docker_binary=self.docker_binary, container_name=session_id)
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=plan.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            _remove_container_verified(session_id, docker_binary=self.docker_binary)
            raise DockerExecutionError("isolated container timed out; process tree removed") from exc

        # `docker run --rm` should have removed the container. Verify the exact
        # trusted name rather than assuming client exit means process-tree exit.
        if _container_exists(session_id, docker_binary=self.docker_binary):
            _remove_container_verified(session_id, docker_binary=self.docker_binary)
            raise DockerExecutionError("completed docker run left a surviving execution session")

        return ExecutionObservation.success({
            "backend": "docker",
            "plan_sha256": plan.plan_sha256,
            "image_id": plan.image_id,
            "exit_code": proc.returncode,
            "workload_status": "zero" if proc.returncode == 0 else "nonzero",
            "execution_session_sha256": canonical_sha256(session_id),
            "stdout": "discarded",
            "stderr": "discarded",
        })


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
    proc = subprocess.run(
        [docker_binary, "inspect", _validate_container_name(session_id)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
        shell=False,
    )
    if proc.returncode == 0:
        return True
    if _is_not_found(proc.stderr):
        return False
    raise DockerExecutionError("docker inspect failed during survivor verification")


def _remove_container_verified(session_id: str, *, docker_binary: str = "docker") -> None:
    name = _validate_container_name(session_id)
    proc = subprocess.run(
        [docker_binary, "rm", "-f", name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
        shell=False,
    )
    if proc.returncode != 0 and not _is_not_found(proc.stderr):
        raise DockerExecutionError("failed to terminate governed execution session")
    if _container_exists(name, docker_binary=docker_binary):
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
    session_id = _new_session_id(probe_plan)
    try:
        return subprocess.run(
            build_docker_argv(probe_plan, container_name=session_id),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=probe_plan.timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        _remove_container_verified(session_id)
        raise


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
