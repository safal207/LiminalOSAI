#!/usr/bin/env python3
"""Trusted Docker backend for LiminalOS isolated process execution.

This adapter is intentionally outside the model-facing SDK. It is the trusted
host boundary that may invoke Docker after RuntimeMediator and
IsolatedExecutionBroker have admitted the exact plan.

Each governed execution receives a unique trusted container/session identity.
The attached ProcessTreeSupervisor can freeze, remove and verify every active
session, so timeout or containment cannot silently leave a Docker process tree
behind.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import sys
from typing import Sequence

# Support direct `python adapters/docker/liminal_docker_executor.py ...` execution
# while keeping normal imports rooted at the repository package boundary.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sdk.liminal_isolated_execution import IsolatedExecutionPlan
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_process_tree import ProcessTreeError, ProcessTreeSupervisor, ZERO_SHA256
from sdk.liminal_runtime_mediation import ExecutionObservation

_CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


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
        "--network",
        p.network_mode,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        f"{p.uid}:{p.gid}",
        "--pids-limit",
        str(p.pids_limit),
        "--memory",
        f"{p.memory_mb}m",
        "--cpus",
        p.cpus,
        "--tmpfs",
        p.tmpfs,
        "--workdir",
        "/workspace",
        "--mount",
        f"type=bind,src={plan.host_workspace},dst=/workspace,readonly",
        plan.image_id,
        *plan.argv,
    ]
    return out


class DockerProcessTreeHost:
    """Trusted Docker callbacks consumed by ProcessTreeSupervisor."""

    def __init__(self, docker_binary: str = "docker") -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise DockerExecutionError("docker_binary must be non-empty")
        self.docker_binary = docker_binary

    def inspect(self, session_id: str) -> dict[str, object]:
        _validate_container_name(session_id)
        proc = subprocess.run(
            [self.docker_binary, "inspect", "--format", "{{.State.Running}} {{.State.Paused}}", session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if proc.returncode != 0:
            if _is_not_found(proc.stderr):
                return {"exists": False, "running": False, "descendant_count": 0, "tree_sha256": ZERO_SHA256}
            raise DockerExecutionError("docker inspect failed for supervised session")

        fields = proc.stdout.strip().split()
        if len(fields) != 2 or fields[0] not in {"true", "false"} or fields[1] not in {"true", "false"}:
            raise DockerExecutionError("docker inspect returned invalid state")
        running = fields[0] == "true"
        paused = fields[1] == "true"
        pids: list[str] = []
        if running or paused:
            top = subprocess.run(
                [self.docker_binary, "top", session_id, "-eo", "pid="],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
                shell=False,
            )
            if top.returncode != 0:
                raise DockerExecutionError("docker top failed for supervised session")
            pids = sorted(line.strip() for line in top.stdout.splitlines() if line.strip())
        return {
            "exists": True,
            "running": running or paused,
            "descendant_count": max(0, len(pids) - 1),
            "tree_sha256": canonical_sha256(pids),
        }

    def freeze(self, session_id: str) -> None:
        state = self.inspect(session_id)
        if not state["exists"] or not state["running"]:
            return
        proc = subprocess.run(
            [self.docker_binary, "pause", session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if proc.returncode != 0:
            # A natural exit racing the freeze is safe if the container is now absent/stopped.
            after = self.inspect(session_id)
            if after["exists"] and after["running"]:
                raise DockerExecutionError("docker pause failed for live supervised session")

    def terminate(self, session_id: str) -> None:
        _validate_container_name(session_id)
        proc = subprocess.run(
            [self.docker_binary, "rm", "-f", session_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
        if proc.returncode != 0 and not _is_not_found(proc.stderr):
            raise DockerExecutionError("docker remove failed for supervised session")


class DockerExecutor:
    def __init__(
        self,
        docker_binary: str = "docker",
        *,
        supervisor: ProcessTreeSupervisor | None = None,
        process_host: DockerProcessTreeHost | None = None,
    ) -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise DockerExecutionError("docker_binary must be non-empty")
        self.docker_binary = docker_binary
        self.process_host = process_host or DockerProcessTreeHost(docker_binary)
        self.supervisor = supervisor or ProcessTreeSupervisor(
            inspect_session=self.process_host.inspect,
            freeze_session=self.process_host.freeze,
            terminate_session=self.process_host.terminate,
        )

    def __call__(self, plan: IsolatedExecutionPlan) -> ExecutionObservation:
        session_id = _new_session_id(plan)
        binding = self.supervisor.register_session(
            session_id=session_id,
            operation_id=plan.operation_id,
            plan_sha256=plan.plan_sha256,
            backend_identity_sha256=canonical_sha256(
                {"backend": "docker", "session_id_sha256": canonical_sha256(session_id)}
            ),
        )
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
            cleanup = self.supervisor.quiesce_session(
                session_id,
                incident_id=f"timeout:{canonical_sha256(plan.operation_id)[:16]}",
            )
            if not cleanup["zero_survivors"]:
                raise DockerExecutionError("isolated container timed out and cleanup verification failed") from exc
            raise DockerExecutionError("isolated container timed out; process tree removed") from exc
        except Exception:
            # If Docker launched anything before the adapter faulted, fail closed by
            # attempting the same exact-session cleanup before re-raising.
            try:
                self.supervisor.quiesce_session(
                    session_id,
                    incident_id=f"adapter-failure:{canonical_sha256(plan.operation_id)[:16]}",
                )
            except Exception:
                pass
            raise

        try:
            self.supervisor.mark_complete(session_id)
        except ProcessTreeError as exc:
            cleanup = self.supervisor.quiesce_session(
                session_id,
                incident_id=f"completion-verification:{canonical_sha256(plan.operation_id)[:16]}",
            )
            if not cleanup["zero_survivors"]:
                raise DockerExecutionError("completed docker run left a surviving session") from exc

        return ExecutionObservation.success(
            {
                "backend": "docker",
                "plan_sha256": plan.plan_sha256,
                "image_id": plan.image_id,
                "exit_code": proc.returncode,
                "workload_status": "zero" if proc.returncode == 0 else "nonzero",
                "execution_session_binding_sha256": binding["binding_sha256"],
                "stdout": "discarded",
                "stderr": "discarded",
            }
        )


def _new_session_id(plan: IsolatedExecutionPlan) -> str:
    return _validate_container_name(
        f"liminal-{plan.plan_sha256[:16]}-{secrets.token_hex(8)}"
    )


def _is_not_found(stderr: str) -> bool:
    text = (stderr or "").lower()
    return "no such object" in text or "no such container" in text


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
    host = DockerProcessTreeHost()
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
        host.terminate(session_id)
        state = host.inspect(session_id)
        if state["exists"]:
            raise DockerExecutionError("timed-out isolation probe survived cleanup")
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
