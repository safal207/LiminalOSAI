#!/usr/bin/env python3
"""Bounded real-Docker strict/one-weakened behavioral controls.

Only this trusted diagnostic producer weakens argv. No weakened profile is
accepted by the SDK. All destinations/resources are owned disposable fixtures;
this does not exercise exploits, internet egress, PID exhaustion or OOM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from adapters.docker import liminal_docker_executor as adapter
from adapters.docker._bounded_cli import run_cli
from sdk.liminal_isolated_execution import IsolatedExecutionPlan

SCHEMA = "liminal-docker-behavior-probe-v1"
SOURCE_PATHS = (
    "adapters/docker/liminal_docker_executor.py",
    "adapters/docker/_bounded_cli.py",
    "sdk/liminal_isolated_execution/__init__.py",
    "sdk/liminal_post_sandbox_contracts/__init__.py",
    "sdk/liminal_process_tree_containment/__init__.py",
    "tests/fixtures/isolated_executor/docker_behavior_probe.py",
    "tests/fixtures/isolated_executor/verify_docker_behavior_probe.py",
)
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
TOKEN = "liminal-owned-network-control-v1"
DOCKERFILE = '''ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN mkdir /liminal-writable && chmod 0777 /liminal-writable
WORKDIR /workspace
USER 65534:65534
ENTRYPOINT ["python3", "-c", "raise SystemExit(73)"]
'''
WORKER = '''import errno,json,os,socket,sys
mode=sys.argv[1]
r={"mode":mode,"uid":os.getuid()}
if mode in ("root_write","workspace_write"):
    path="/liminal-writable/probe" if mode=="root_write" else "/workspace/probe"
    try:
        with open(path,"xb") as f: f.write(b"bounded-control")
        os.unlink(path)
        r.update(written=True,errno=None)
    except OSError as e: r.update(written=False,errno=e.errno)
elif mode=="network":
    s=socket.socket();s.settimeout(2)
    try:
        s.connect((sys.argv[2],15432));s.sendall(b"ping"); data=s.recv(128)
        r.update(connected=True,response=data.decode("ascii"),errno=None)
    except OSError as e: r.update(connected=False,response=None,errno=e.errno)
    finally:s.close()
elif mode=="seccomp":
    fields=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)
    r["seccomp"]=int(fields["Seccomp"].strip())
else:r["marker"]="liminal-attached-stdout-v1"
print(json.dumps(r,sort_keys=True))
'''
SERVER = '''import socket,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",15432));s.listen(8);s.settimeout(1)
deadline=time.monotonic()+100
while time.monotonic()<deadline:
    try:c,_=s.accept()
    except socket.timeout:continue
    with c:
        c.settimeout(2)
        if c.recv(16)==b"ping":c.sendall(b"liminal-owned-network-control-v1")
s.close()
'''


def cli(argv, *, timeout=20, limit=256 * 1024, checked=True):
    result = run_cli(["docker", *argv], timeout=timeout, stdout_limit=limit, stderr_limit=8192)
    if checked and result.returncode != 0:
        raise RuntimeError("owned Docker operation failed: " + argv[0] + ": " + result.stderr.decode("utf-8", "replace")[:500])
    return result


def inspect(reference):
    return json.loads(cli(["inspect", reference]).stdout)[0]


def replace_option(argv, name, value):
    result = list(argv)
    i = result.index(name)
    result[i + 1] = value
    return result


def weaken(argv, protection, network):
    if protection == "entrypoint":
        i = argv.index("--entrypoint")
        return argv[:i] + argv[i + 2:]
    if protection == "logging":
        result = replace_option(argv, "--log-driver", "json-file")
        return result[:3] + ["--log-opt", "max-size=1m", "--log-opt", "max-file=1"] + result[3:]
    if protection == "root_write":
        return [value for value in argv if value != "--read-only"]
    if protection == "workspace_write":
        i = argv.index("--mount") + 1
        result = list(argv)
        if not result[i].endswith(",readonly"):
            raise AssertionError("unexpected workspace mount form")
        result[i] = result[i][:-len(",readonly")]
        return result
    if protection == "network":
        return replace_option(argv, "--network", network)
    if protection == "seccomp":
        return argv[:3] + ["--security-opt", "seccomp=unconfined"] + argv[3:]
    raise AssertionError("unknown diagnostic mutation")


def run_case(name, image, workspace, network, server_ip, owned_ids, *, relaxed, record=None):
    command = ("python3", "-c", WORKER, name, server_ip) if name == "network" else ("python3", "-c", WORKER, name)
    plan = IsolatedExecutionPlan.build(operation_id="behavior-" + name + ("-control" if relaxed else "-strict"),
        image_id=image, argv=command, host_workspace=str(workspace), timeout_seconds=12)
    record = {} if record is None else record
    record.update({"mutation": name if relaxed else None, "plan": {**plan.safe_body(), "argv": list(command),
              "host_workspace": str(workspace), "profile": plan.profile.body()}, "commands": []})
    original_builder = adapter.build_docker_argv

    def builder(*args, **kwargs):
        base = original_builder(*args, **kwargs)
        record["strict_builder_argv"] = list(base)
        return weaken(base, name, network) if relaxed else base

    def transport(argv, **kwargs):
        # Capture raw observations before the adapter performs verified cleanup.
        record["commands"].append(list(argv))
        result = run_cli(argv, **kwargs)
        if argv[1] == "create" and result.returncode == 0:
            record["create_argv"] = list(argv)
            created_id = result.stdout.decode("ascii").strip()
            owned_ids.append(created_id)
            record["created"] = inspect(created_id)
        if argv[1] == "start" and result.returncode >= 0:
            record["exited"] = inspect(argv[-1])
            if name == "logging":
                logs = cli(["logs", argv[-1]], checked=False, limit=64 * 1024)
                record["docker_logs"] = {"returncode": logs.returncode,
                    "stdout": logs.stdout.decode("utf-8"), "stderr": logs.stderr.decode("utf-8", "replace")}
        return result

    with patch.object(adapter, "build_docker_argv", side_effect=builder), patch.object(adapter, "run_cli", side_effect=transport):
        result = adapter.run_docker_plan(plan, stdout_limit=64 * 1024)
    absent = cli(["inspect", result.container_id], checked=False)
    record.update(session_id=result.session_id, container_id=result.container_id, daemon_id=result.daemon_id,
        returncode=result.returncode, stdout=result.stdout.decode("utf-8"),
        absence={"returncode": absent.returncode, "stdout": absent.stdout.decode("utf-8"),
                 "stderr": absent.stderr.decode("utf-8", "replace")})
    return record


def source_inputs():
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}


def produce(image, revision, *, report=None):
    if IMAGE_ID.fullmatch(image) is None or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("immutable image and revision required")
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=10).stdout
    if actual != revision or dirty:
        raise ValueError("behavior capture requires the exact clean tracked revision")
    prefix = "liminal-behavior-" + secrets.token_hex(8)
    network, server, tag = prefix + "-net", prefix + "-server", prefix + ":base"
    fixture = None
    owned_ids = []
    report = {} if report is None else report
    report.update({"schema": SCHEMA, "revision": revision, "base_image_id": image,
              "scope": "real-docker-generic-adapter-bounded-behavior-and-one-weakened-controls",
              "source_inputs": source_inputs(), "worker_sha256": hashlib.sha256(WORKER.encode()).hexdigest(),
              "dockerfile": DOCKERFILE, "server_source_sha256": hashlib.sha256(SERVER.encode()).hexdigest(),
              "cases": {}, "deferred": ["pids_exhaustion", "memory_exhaustion", "kernel_escape", "host_compromise"]})
    cli(["info", "--format", "{{.ID}}"])
    report["docker_version"] = json.loads(cli(["version", "--format", "{{json .}}"] ).stdout)
    report["base_image_inspect"] = inspect(image)
    try:
        cli(["tag", image, tag])
        with tempfile.TemporaryDirectory(prefix=prefix + "-") as temporary:
            directory = Path(temporary)
            (directory / "Dockerfile").write_text(DOCKERFILE)
            cli(["build", "--pull=false", "--network=none", "--build-arg", "BASE_IMAGE=" + tag,
                 "--iidfile", str(directory / "image-id"), str(directory)], timeout=100, limit=64 * 1024)
            fixture = (directory / "image-id").read_text().strip()
            if IMAGE_ID.fullmatch(fixture) is None:
                raise AssertionError("derived fixture image identity missing")
            report["image_id"] = fixture
            report["image_inspect"] = inspect(fixture)
            workspace = directory / "workspace"
            workspace.mkdir(mode=0o777)
            workspace.chmod(0o777)
            report["workspace"] = {"path": str(workspace), "mode": workspace.stat().st_mode & 0o777,
                                   "initial_entries": sorted(p.name for p in workspace.iterdir())}
            report["network_create"] = cli(["network", "create", "--internal", network]).stdout.decode().strip()
            cli(["create", "--name", server, "--network", network, "--read-only", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges:true", "--user", "65534:65534", "--pids-limit", "16",
                 "--memory", "64m", "--log-driver", "none", "--entrypoint", "python3", fixture, "-c", SERVER])
            cli(["start", server])
            server_inspect = inspect(server)
            server_ip = server_inspect["NetworkSettings"]["Networks"][network]["IPAddress"]
            ready_command = ["exec", server, "python3", "-c",
                "import socket; s=socket.create_connection(('127.0.0.1',15432),2); s.sendall(b'ping'); print(s.recv(128).decode()); s.close()"]
            deadline = time.monotonic() + 8
            while True:
                ready = cli(ready_command, checked=False)
                if ready.returncode == 0 and ready.stdout.decode().strip() == TOKEN:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("owned internal TCP server failed bounded health check")
                time.sleep(0.1)
            report["network_lab"] = {"name": network, "server": server_inspect, "server_ip": server_ip,
                "healthcheck": {"argv": ready_command, "returncode": ready.returncode, "stdout": ready.stdout.decode()},
                "inspect": json.loads(cli(["network", "inspect", network]).stdout)[0]}
            for name in ("entrypoint", "logging", "root_write", "workspace_write", "network", "seccomp"):
                report["cases"][name] = {}
                for variant in ("strict", "control"):
                    report["cases"][name][variant] = {}
                    run_case(name, fixture, workspace, network, server_ip, owned_ids, relaxed=variant == "control",
                             record=report["cases"][name][variant])
            report["workspace"]["final_entries"] = sorted(p.name for p in workspace.iterdir())
            report["network_lab"]["final_inspect"] = json.loads(cli(["network", "inspect", network]).stdout)[0]
    finally:
        workload_cleanup = []
        for container_id in owned_ids:
            cli(["rm", "-f", container_id], checked=False)
            absent = cli(["inspect", container_id], checked=False)
            workload_cleanup.append({"container_id": container_id, "absence_returncode": absent.returncode,
                "absence_stderr": absent.stderr.decode("utf-8", "replace")})
        server_removal = cli(["rm", "-f", server], checked=False)
        server_absence = cli(["inspect", server], checked=False)
        network_removal = cli(["network", "rm", network], checked=False)
        network_absence = cli(["network", "inspect", network], checked=False)
        cli(["image", "rm", tag], checked=False)
        if fixture:
            cli(["image", "rm", fixture], checked=False)
        # Check for leaked owned workload containers even after an earlier failure.
        inventory = cli(["ps", "-aq", "--filter", "name=" + prefix, "--no-trunc"])
        report["cleanup"] = {"workloads": workload_cleanup, "server_remove_returncode": server_removal.returncode,
            "server_absence_returncode": server_absence.returncode,
            "server_absence_stderr": server_absence.stderr.decode("utf-8", "replace"),
            "network_remove_returncode": network_removal.returncode,
            "network_absence_returncode": network_absence.returncode,
            "network_absence_stderr": network_absence.stderr.decode("utf-8", "replace"),
            "owned_lab_container_ids": inventory.stdout.decode().split()}
        if (inventory.stdout.strip() or server_absence.returncode == 0 or network_absence.returncode == 0
                or any(item["absence_returncode"] == 0 for item in workload_cleanup)):
            raise AssertionError("owned diagnostic lab cleanup not verified")
    report["capture_status"] = "COMPLETE"
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="existing immutable Python3 image ID")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": SCHEMA, "revision": args.revision, "capture_status": "FAILED"}
    try:
        produce(args.image, args.revision, report=report)
    except BaseException as error:
        report["capture_status"] = "FAILED"
        report["failure"] = {"type": type(error).__name__, "message": str(error)[:1000]}
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("captured six real Docker behavior pairs; no universal isolation verdict")


if __name__ == "__main__":
    main()
