#!/usr/bin/env python3
"""Trusted CI fault injector. Only its disposable daemon is stopped/restarted.

Transport failures are deliberately injected around real Docker operations.
This is bounded diagnostic evidence, not a kernel or arbitrary crash proof.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
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


class OwnedDaemon:
    def __init__(self, directory: Path):
        self.directory = directory
        self.process = None
        self.socket = directory / "docker.sock"

    def start(self):
        if self.process is not None:
            raise RuntimeError("owned daemon already started")
        self.process = subprocess.Popen([
            shutil.which("dockerd") or "/usr/bin/dockerd",
            "--host", "unix://" + str(self.socket),
            "--data-root", str(self.directory / "data"),
            "--exec-root", str(self.directory / "exec"),
            "--pidfile", str(self.directory / "daemon.pid"),
            "--storage-driver", "vfs", "--iptables=false", "--ip-forward=false",
            "--ip-masq=false", "--bridge=none", "--live-restore",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("owned daemon exited during startup")
            try:
                return adapter._daemon_id("docker")
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("owned daemon startup exceeded bound")

    def stop(self):
        if self.process is None:
            return
        process, self.process = self.process, None
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def checked(argv, *, timeout=20):
    result = run_cli(["docker", *argv], timeout=timeout, stdout_limit=8192)
    if result.returncode != 0:
        raise RuntimeError("owned Docker control operation failed: " + argv[0])
    return result.stdout.decode("utf-8").strip()


def error_document(error):
    return {"outcome": "UNKNOWN", "phase": error.phase, "cleanup_state": error.cleanup_state,
            "session": error.session.as_document()}


def exercise(daemon, image, workspace):
    cases = {}
    def plan(name, command=("/bin/true",)):
        return IsolatedExecutionPlan.build(operation_id=name, image_id=image, argv=command,
                                           host_workspace=workspace, timeout_seconds=15)

    def failed_run(name, fault, command=("/bin/true",)):
        calls = []
        def transport(argv, **kwargs):
            calls.append(argv[1])
            return fault(argv, kwargs)
        with patch.object(adapter, "run_cli", side_effect=transport):
            try:
                adapter.run_docker_plan(plan(name, command))
            except adapter.DockerReconciliationRequired as error:
                return error, calls
            except adapter.DockerExecutionTimeout as error:
                return error, calls
        raise AssertionError("injected uncertain operation was accepted as successful")

    completed = adapter.run_docker_plan(plan("normal"))
    cases["normal"] = {"exit_code": completed.returncode, "container_id": completed.container_id,
                       "target_absent": adapter._inspect_object(completed.container_id, "docker") is None}

    def lost_response(argv, kwargs):
        result = run_cli(argv, **kwargs)
        if argv[1] == "create":
            raise subprocess.TimeoutExpired("injected lost create response", 1)
        return result
    error, calls = failed_run("lost_create_response", lost_response)
    cases["lost_create_response"] = {**error_document(error), "start_dispatched": "start" in calls,
        "name_absent": adapter._inspect_object(error.session.session_id, "docker") is None}

    deferred = []
    def delay_create(argv, kwargs):
        if argv[1] == "create":
            deferred.append((argv, kwargs))
            raise subprocess.TimeoutExpired("injected deferred create dispatch", 1)
        return run_cli(argv, **kwargs)
    error, calls = failed_run("delayed_create", delay_create)
    absent_before = adapter._inspect_object(error.session.session_id, "docker") is None
    # Complete the held request only after the initial cleanup has observed absence.
    created = run_cli(deferred[0][0], **deferred[0][1])
    if created.returncode != 0:
        raise AssertionError("deferred create failed")
    late = adapter._inspect_object(error.session.session_id, "docker")
    recovery = adapter.reconcile_docker_session(error.session)
    cases["delayed_create"] = {**error_document(error), "start_dispatched": "start" in calls,
        "absent_before_delivery": absent_before, "late_status": late["status"],
        "late_running": late["running"], "late_container_id": late["id"],
        "recovery_cleanup": recovery["cleanup_state"],
        "late_absent_after": adapter._inspect_object(late["id"], "docker") is None}

    killed = {}
    def kill_start_client(argv, kwargs):
        if argv[1] != "start":
            return run_cli(argv, **kwargs)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, shell=False)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                observed = adapter._inspect_object(argv[-1], "docker")
                if observed and observed["running"]:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("start did not produce a running owned workload")
            process.kill()
            killed["client_returncode"] = process.wait(timeout=5)
            killed["running_at_client_death"] = observed["running"]
            return subprocess.CompletedProcess(argv, process.returncode, b"", b"")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    error, _ = failed_run("client_death", kill_start_client, ("/bin/sleep", "60"))
    cases["client_death"] = {**error_document(error), **killed,
        "target_absent": adapter._inspect_object(error.session.container_id, "docker") is None}

    def delay_start(argv, kwargs):
        if argv[1] == "start":
            raise subprocess.TimeoutExpired("injected deferred start dispatch", 1)
        return run_cli(argv, **kwargs)
    error, _ = failed_run("delayed_start_replacement", delay_start, ("/bin/sleep", "60"))
    sentinel = checked(["create", "--name", error.session.session_id, "--network", "none", image, "/bin/true"])
    try:
        delayed = run_cli(["docker", "start", error.session.container_id], timeout=10)
        recovery = adapter.reconcile_docker_session(error.session)
        untouched = adapter._inspect_object(sentinel, "docker")
        cases["delayed_start_replacement"] = {**error_document(error), "sentinel_id": sentinel,
            "delayed_start_returncode": delayed.returncode, "sentinel_status": untouched["status"],
            "sentinel_running": untouched["running"], "recovery_cleanup": recovery["cleanup_state"],
            "target_absent": adapter._inspect_object(error.session.container_id, "docker") is None}
    finally:
        checked(["rm", "-f", sentinel])

    before_restart = adapter._daemon_id("docker")
    def interrupt_daemon(argv, kwargs):
        if argv[1] != "start":
            return run_cli(argv, **kwargs)
        checked(["start", argv[-1]])
        daemon.stop()
        raise ConnectionError("injected owned daemon outage after start")
    error, _ = failed_run("daemon_restart", interrupt_daemon, ("/bin/sleep", "60"))
    after_restart = daemon.start()
    observed = adapter._inspect_object(error.session.container_id, "docker")
    recovery = adapter.reconcile_docker_session(error.session)
    cases["daemon_restart"] = {**error_document(error), "daemon_before": before_restart,
        "daemon_after": after_restart, "reobserved_container_id": None if observed is None else observed["id"],
        "recovery_cleanup": recovery["cleanup_state"],
        "target_absent": adapter._inspect_object(error.session.container_id, "docker") is None}
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("disposable-daemon probe requires a privileged CI step")
    old_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="liminal-owned-daemon-") as tmp:
        daemon = OwnedDaemon(Path(tmp))
        for key in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            os.environ.pop(key, None)
        os.environ["DOCKER_HOST"] = "unix://" + str(daemon.socket)
        try:
            daemon_id = daemon.start()
            checked(["load", "--input", str(Path(args.archive).resolve())], timeout=120)
            if checked(["image", "inspect", args.image, "--format", "{{.Id}}"] ) != args.image:
                raise AssertionError("immutable image mismatch in owned daemon")
            cases = exercise(daemon, args.image, str(ROOT))
            if checked(["ps", "-aq", "--no-trunc"]):
                raise AssertionError("owned daemon still has a scenario resource")
            report = {"schema": "liminal-docker-failure-probe-v1", "revision": args.revision,
                      "image_id": args.image, "daemon_id": daemon_id,
                      "scope": "fault-injected-control-plane-with-real-disposable-daemon", "cases": cases}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        finally:
            # This socket/data root belongs only to this test, never the runner daemon.
            try:
                if daemon.process is None:
                    daemon.start()
                if daemon.process.poll() is None:
                    ids = checked(["ps", "-aq", "--no-trunc"]).splitlines()
                    if ids:
                        checked(["rm", "-f", *ids])
            except Exception:
                # Failure already rejects the probe; best-effort fixture teardown
                # must not mutate a different daemon or suppress the original error.
                pass
            daemon.stop()
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    main()
