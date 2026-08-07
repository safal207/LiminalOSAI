#!/usr/bin/env python3
"""Trusted Docker backend for LiminalOS isolated process execution.

This adapter is intentionally outside the model-facing SDK. It is the trusted
host boundary that may invoke Docker after RuntimeMediator and
IsolatedExecutionBroker have admitted the exact plan.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Sequence

from sdk.liminal_isolated_execution import IsolatedExecutionPlan
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation


class DockerExecutionError(RuntimeError):
    pass


def build_docker_argv(plan: IsolatedExecutionPlan, *, docker_binary: str = "docker") -> list[str]:
    plan.validate()
    p = plan.profile
    return [
        docker_binary,
        "run",
        "--rm",
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


class DockerExecutor:
    def __init__(self, docker_binary: str = "docker") -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise DockerExecutionError("docker_binary must be non-empty")
        self.docker_binary = docker_binary

    def __call__(self, plan: IsolatedExecutionPlan) -> ExecutionObservation:
        argv = build_docker_argv(plan, docker_binary=self.docker_binary)
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
            raise DockerExecutionError("isolated container timed out") from exc
        if proc.returncode != 0:
            raise DockerExecutionError("isolated container returned non-zero status")
        return ExecutionObservation.success(
            {
                "backend": "docker",
                "plan_sha256": plan.plan_sha256,
                "image_id": plan.image_id,
                "exit_code": proc.returncode,
                "stdout": "discarded",
                "stderr": "discarded",
            }
        )


def _probe(plan: IsolatedExecutionPlan, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    probe_plan = IsolatedExecutionPlan.build(
        operation_id=plan.operation_id,
        image_id=plan.image_id,
        argv=tuple(argv),
        host_workspace=plan.host_workspace,
        timeout_seconds=min(plan.timeout_seconds, 15),
        profile=plan.profile,
    )
    return subprocess.run(
        build_docker_argv(probe_plan),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=probe_plan.timeout_seconds,
        check=False,
        shell=False,
    )


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
    probes["non_root_uid"] = uid.returncode == 0 and uid.stdout.strip() == "65534"

    nnp = _probe(base, ("/bin/sh", "-c", "awk '/^NoNewPrivs:/{print $2}' /proc/self/status"))
    probes["no_new_privileges"] = nnp.returncode == 0 and nnp.stdout.strip() == "1"

    caps = _probe(base, ("/bin/sh", "-c", "awk '/^CapEff:/{print $2}' /proc/self/status"))
    probes["capabilities_dropped"] = caps.returncode == 0 and caps.stdout.strip() == "0000000000000000"

    root_mount = _probe(base, ("/bin/sh", "-c", "awk '$2==\"/\"{print $4}' /proc/mounts"))
    root_opts = set(root_mount.stdout.strip().split(","))
    probes["read_only_root"] = root_mount.returncode == 0 and "ro" in root_opts

    workspace_write = _probe(base, ("/bin/sh", "-c", "touch /workspace/liminal-write-probe"))
    probes["workspace_read_only"] = workspace_write.returncode != 0

    network = _probe(base, ("/bin/sh", "-c", "wget -q -T 2 -O /tmp/net-probe http://1.1.1.1"))
    probes["network_none"] = network.returncode != 0

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
