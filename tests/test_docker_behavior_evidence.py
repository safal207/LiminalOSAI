"""Synthetic packets test the independent verifier, not real Docker behavior."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from adapters.docker.liminal_docker_executor import build_docker_argv
from sdk.liminal_isolated_execution import IsolatedExecutionPlan

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "tests/fixtures/isolated_executor"
SPEC = importlib.util.spec_from_file_location("docker_behavior_verifier", DIRECTORY / "verify_docker_behavior_probe.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
BASE = "sha256:" + "a" * 64
IMAGE = "sha256:" + "b" * 64
REVISION = "c" * 40
NETWORK = "liminal-behavior-" + "d" * 16 + "-net"
SERVER_ID = "e" * 64


def fixture():
    literals = VERIFIER.literal_bindings(ROOT)
    source = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in VERIFIER.MANDATORY_SOURCES}
    server = {"Id": SERVER_ID, "Name": "/" + NETWORK[:-4] + "-server", "Image": IMAGE, "State": {"Running": True},
        "Config": {"Entrypoint": ["python3"], "Cmd": ["-c", literals["SERVER"]]},
        "NetworkSettings": {"Networks": {NETWORK: {"IPAddress": "172.30.0.2"}}}}
    network_inspect = {"Id": "f" * 64, "Name": NETWORK, "Internal": True, "Driver": "bridge", "Containers": {SERVER_ID: {}}}
    report = {"schema": "liminal-docker-behavior-probe-v1", "capture_status": "COMPLETE", "revision": REVISION, "base_image_id": BASE, "image_id": IMAGE,
        "scope": "real-docker-generic-adapter-bounded-behavior-and-one-weakened-controls",
        "source_inputs": source, "worker_sha256": hashlib.sha256(literals["WORKER"].encode()).hexdigest(),
        "server_source_sha256": hashlib.sha256(literals["SERVER"].encode()).hexdigest(), "dockerfile": literals["DOCKERFILE"],
        "base_image_inspect": {"Id": BASE, "RootFS": {"Layers": ["base-layer"]}},
        "image_inspect": {"Id": IMAGE, "RootFS": {"Layers": ["base-layer", "fixture-layer"]}, "Config": {"Entrypoint": VERIFIER.POISON}},
        "workspace": {"path": "/synthetic-fixture/workspace", "mode": 0o777, "initial_entries": [], "final_entries": []},
        "network_create": "f" * 64,
        "network_lab": {"name": NETWORK, "server": server, "server_ip": "172.30.0.2", "inspect": network_inspect,
                        "final_inspect": copy.deepcopy(network_inspect), "healthcheck": {"returncode": 0, "stdout": VERIFIER.TOKEN + "\n"}},
        "docker_version": {"Server": {"Version": "synthetic-only"}}, "cases": {},
        "deferred": ["pids_exhaustion", "memory_exhaustion", "kernel_escape", "host_compromise"],
        "cleanup": {"server_remove_returncode": 0, "server_absence_returncode": 1, "server_absence_stderr": "No such container",
                    "network_remove_returncode": 0, "network_absence_returncode": 1, "network_absence_stderr": "network not found", "owned_lab_container_ids": [], "workloads": []}}
    counter = 0
    for name in sorted(VERIFIER.CASES):
        report["cases"][name] = {}
        for variant in ("strict", "control"):
            counter += 1
            relaxed = variant == "control"
            operation = "behavior-" + name + ("-control" if relaxed else "-strict")
            command = ["python3", "-c", literals["WORKER"], name] + (["172.30.0.2"] if name == "network" else [])
            plan = IsolatedExecutionPlan.build(operation_id=operation, image_id=IMAGE, argv=command,
                host_workspace=report["workspace"]["path"], timeout_seconds=12)
            cid = format(counter, "064x")
            session = "liminal-" + plan.plan_sha256[:16] + "-" + format(counter, "016x")
            strict = build_docker_argv(plan, container_name=session)
            launch = VERIFIER.expected_control(strict, name, NETWORK) if relaxed else strict[:]
            create = launch[:]
            create[1:3] = ["create", "--restart", "no", "--label", "org.liminal.session=" + session,
                           "--label", "org.liminal.plan=" + plan.plan_sha256]
            log_control = relaxed and name == "logging"
            inspect = {"Id": cid, "Name": "/" + session, "Image": IMAGE, "LogPath": "/synthetic-log" if log_control else "",
                "Config": {"Labels": {"org.liminal.session": session, "org.liminal.plan": plan.plan_sha256},
                           "User": "65534:65534", "WorkingDir": "/workspace", "Cmd": command,
                           "Entrypoint": VERIFIER.POISON[:] if relaxed and name == "entrypoint" else []},
                "HostConfig": {"NetworkMode": NETWORK if relaxed and name == "network" else "none",
                    "ReadonlyRootfs": not (relaxed and name == "root_write"), "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"] + (["seccomp=unconfined"] if relaxed and name == "seccomp" else []),
                    "Privileged": False, "PidMode": "", "IpcMode": "private", "RestartPolicy": {"Name": "no"},
                    "PidsLimit": 64, "Memory": 256 * 1024 * 1024, "NanoCpus": 10**9,
                    "LogConfig": {"Type": "json-file" if log_control else "none", "Config": {"max-size": "1m", "max-file": "1"} if log_control else {}}},
                "Mounts": [{"Destination": "/workspace", "Type": "bind", "Source": report["workspace"]["path"], "RW": relaxed and name == "workspace_write"}],
                "State": {"Status": "created", "Running": False}}
            exited = copy.deepcopy(inspect)
            exit_code = 73 if relaxed and name == "entrypoint" else 0
            exited["State"].update(Status="exited", Running=False, ExitCode=exit_code)
            output = {"uid": 65534, "mode": name}
            if name in {"root_write", "workspace_write"}:
                output.update(written=relaxed, errno=None if relaxed else 30)
            elif name == "network":
                output.update(connected=relaxed, response=VERIFIER.TOKEN if relaxed else None, errno=None if relaxed else 101)
            elif name == "seccomp":
                output["seccomp"] = 0 if relaxed else 2
            else:
                output["marker"] = "liminal-attached-stdout-v1"
            stdout = "" if exit_code == 73 else json.dumps(output, sort_keys=True) + "\n"
            case = {"mutation": name if relaxed else None,
                "plan": {**plan.safe_body(), "argv": command, "host_workspace": report["workspace"]["path"], "profile": plan.profile.body()},
                "commands": [create, ["docker", "start", "--attach", cid], ["docker", "rm", "-f", cid]],
                "strict_builder_argv": strict, "create_argv": create, "created": inspect, "exited": exited,
                "session_id": session, "container_id": cid, "daemon_id": "synthetic-daemon",
                "returncode": exit_code, "stdout": stdout,
                "absence": {"returncode": 1, "stderr": "Error: No such container: " + cid, "stdout": ""}}
            if name == "logging":
                case["docker_logs"] = {"returncode": 0 if relaxed else 1, "stdout": stdout if relaxed else "", "stderr": ""}
            report["cases"][name][variant] = case
            report["cleanup"]["workloads"].append({"container_id": cid, "absence_returncode": 1, "absence_stderr": "No such container"})
    return report


class DockerBehaviorEvidenceTests(unittest.TestCase):
    def verify(self, report):
        return VERIFIER.verify(report, revision=REVISION, base_image=BASE)

    def test_accepts_complete_synthetic_packet_with_bounded_verdict(self):
        result = self.verify(fixture())
        self.assertEqual(result["pairs"], 6)
        self.assertEqual(result["workload_containers"], 12)
        self.assertEqual(result["universal_escape_resistance"], "NOT_ESTABLISHED")

    def test_each_protection_requires_observed_negative_control_sensitivity(self):
        for name in VERIFIER.CASES:
            with self.subTest(protection=name):
                report = fixture()
                strict, control = report["cases"][name]["strict"], report["cases"][name]["control"]
                if name == "entrypoint":
                    control["stdout"] = strict["stdout"]
                    control["returncode"] = 0
                    control["exited"]["State"]["ExitCode"] = 0
                elif name == "logging":
                    control["docker_logs"]["stdout"] = ""
                else:
                    control["stdout"] = strict["stdout"]
                with self.assertRaises(ValueError):
                    self.verify(report)

    def test_strict_write_must_be_read_only_error_not_permission_denial(self):
        for name in ("root_write", "workspace_write"):
            with self.subTest(protection=name):
                report = fixture()
                case = report["cases"][name]["strict"]
                output = json.loads(case["stdout"])
                output["errno"] = 13
                case["stdout"] = json.dumps(output)
                with self.assertRaisesRegex(ValueError, "EROFS"):
                    self.verify(report)

    def test_rejects_changed_source_missing_scenario_or_unbound_command(self):
        for mutation in ("source", "missing", "argv", "multiple-weakening", "daemon", "cleanup", "external-network"):
            with self.subTest(mutation=mutation):
                report = fixture()
                case = report["cases"]["network"]["strict"]
                if mutation == "source":
                    report["source_inputs"][next(iter(VERIFIER.MANDATORY_SOURCES))] = "0" * 64
                elif mutation == "missing":
                    report["cases"].pop("seccomp")
                elif mutation == "argv":
                    case["plan"]["argv"][-1] = "198.51.100.1"
                elif mutation == "multiple-weakening":
                    report["cases"]["network"]["control"]["create_argv"].remove("--read-only")
                elif mutation == "daemon":
                    case["daemon_id"] = "replacement-daemon"
                elif mutation == "cleanup":
                    report["cleanup"]["workloads"].pop()
                else:
                    report["network_lab"]["inspect"]["Internal"] = False
                with self.assertRaises(ValueError):
                    self.verify(report)

    def test_rejects_reconstructed_host_pid_control_counterexample(self):
        report = fixture()
        for variant in ("strict", "control"):
            case = report["cases"]["entrypoint"][variant]
            old_create = copy.deepcopy(case["create_argv"])
            strict = case["strict_builder_argv"]
            strict[3:3] = ["--pid", "host"]
            changed = VERIFIER.expected_control(strict, "entrypoint", NETWORK) if variant == "control" else strict[:]
            changed[1:3] = old_create[1:8]
            case["create_argv"] = changed
            case["commands"] = [changed if row == old_create else row for row in case["commands"]]
            for snap in ("created", "exited"):
                case[snap]["HostConfig"]["PidMode"] = "host"
        with self.assertRaisesRegex(ValueError, "extra or missing arguments"):
            self.verify(report)

    def test_rejects_server_aliasing_a_governed_workload_container(self):
        report = fixture()
        alias = report["cases"]["entrypoint"]["strict"]["container_id"]
        report["network_lab"]["server"]["Id"] = alias
        for key in ("inspect", "final_inspect"):
            report["network_lab"][key]["Containers"] = {alias: {}}
        with self.assertRaisesRegex(ValueError, "aliases a governed workload"):
            self.verify(report)
        report = fixture()
        report["network_lab"]["server"]["Name"] = "/unrelated-server"
        with self.assertRaisesRegex(ValueError, "server name mismatch"):
            self.verify(report)

    def test_rejects_missing_actual_config_and_captured_stdout(self):
        for mutation in ("root", "entrypoint", "logs", "stdout", "source-omission", "privileged", "incomplete", "extra-argv"):
            with self.subTest(mutation=mutation):
                report = fixture()
                if mutation == "root":
                    report["cases"]["root_write"]["strict"]["created"]["HostConfig"].pop("ReadonlyRootfs")
                elif mutation == "entrypoint":
                    report["cases"]["entrypoint"]["strict"]["created"]["Config"]["Entrypoint"] = VERIFIER.POISON[:]
                elif mutation == "logs":
                    report["cases"]["logging"]["strict"]["exited"]["LogPath"] = "/some-log"
                elif mutation == "stdout":
                    report["cases"]["logging"]["strict"]["stdout"] = ""
                elif mutation == "privileged":
                    report["cases"]["root_write"]["strict"]["created"]["HostConfig"]["Privileged"] = True
                elif mutation == "incomplete":
                    report["capture_status"] = "FAILED"
                elif mutation == "extra-argv":
                    case = report["cases"]["network"]["strict"]
                    case["strict_builder_argv"].insert(3, "--privileged")
                    case["create_argv"].insert(3, "--privileged")
                    case["commands"][0] = case["create_argv"]
                else:
                    report["source_inputs"].pop(next(iter(VERIFIER.MANDATORY_SOURCES)))
                with self.assertRaises(ValueError):
                    self.verify(report)


if __name__ == "__main__":
    unittest.main()
