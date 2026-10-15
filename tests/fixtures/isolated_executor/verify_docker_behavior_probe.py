#!/usr/bin/env python3
"""Offline behavioral-evidence checker independent of producer PASS fields.

A synthetic packet can test this checker, never establish actual Docker facts.
The CLI binds packet bytes to clean checked-out source and an expected revision.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
CASES = {"entrypoint", "logging", "root_write", "workspace_write", "network", "seccomp"}
MANDATORY_SOURCES = {
    "adapters/docker/liminal_docker_executor.py", "adapters/docker/_bounded_cli.py",
    "sdk/liminal_isolated_execution/__init__.py", "sdk/liminal_post_sandbox_contracts/__init__.py",
    "sdk/liminal_process_tree_containment/__init__.py",
    "tests/fixtures/isolated_executor/docker_behavior_probe.py",
    "tests/fixtures/isolated_executor/verify_docker_behavior_probe.py",
}
PROFILE = {"schema": "liminal-container-isolation-profile-v0.1", "network_mode": "none",
    "read_only_root": True, "drop_all_capabilities": True, "no_new_privileges": True,
    "uid": 65534, "gid": 65534, "pids_limit": 64, "memory_mb": 256,
    "cpus": "1.0", "tmpfs": "/tmp:rw,nosuid,nodev,noexec,size=64m", "workspace_mode": "ro"}
TOKEN = "liminal-owned-network-control-v1"
POISON = ["python3", "-c", "raise SystemExit(73)"]
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def option(argv, name):
    require(argv.count(name) == 1 and argv.index(name) + 1 < len(argv), "missing/duplicate option " + name)
    return argv[argv.index(name) + 1]


def expected_control(argv, name, network):
    changed = list(argv)
    if name == "entrypoint":
        i = changed.index("--entrypoint")
        del changed[i:i + 2]
    elif name == "logging":
        changed[changed.index("--log-driver") + 1] = "json-file"
        changed[3:3] = ["--log-opt", "max-size=1m", "--log-opt", "max-file=1"]
    elif name == "root_write":
        changed.remove("--read-only")
    elif name == "workspace_write":
        i = changed.index("--mount") + 1
        require(changed[i].endswith(",readonly"), "strict workspace flag missing")
        changed[i] = changed[i][:-len(",readonly")]
    elif name == "network":
        changed[changed.index("--network") + 1] = network
    elif name == "seccomp":
        changed[3:3] = ["--security-opt", "seccomp=unconfined"]
    return changed


def literal_bindings(source_root):
    producer = source_root / "tests/fixtures/isolated_executor/docker_behavior_probe.py"
    values = {}
    for node in ast.parse(producer.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {"WORKER", "SERVER", "DOCKERFILE"}:
                values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {"WORKER", "SERVER", "DOCKERFILE"}, "source literal bindings missing")
    return values


def verify_case(case, name, variant, report, worker):
    require(isinstance(case, dict), "case must be an object")
    relaxed = variant == "control"
    require(case.get("mutation") == (name if relaxed else None), "diagnostic mutation label mismatch")
    cid, session = case.get("container_id"), case.get("session_id")
    require(isinstance(cid, str) and HEX64.fullmatch(cid), "immutable workload identity missing")
    require(isinstance(session, str) and re.fullmatch(r"liminal-[0-9a-f]{16}-[0-9a-f]{16}", session), "session identity missing")
    plan = case.get("plan", {})
    expected_command = ["python3", "-c", worker, name]
    if name == "network":
        expected_command.append(report["network_lab"]["server_ip"])
    require(plan.get("argv") == expected_command, "worker command differs from pinned source")
    require(plan.get("profile") == PROFILE and plan.get("timeout_seconds") == 12, "profile/time bound mismatch")
    workspace = report["workspace"]["path"]
    require(plan.get("host_workspace") == workspace and plan.get("image_id") == report["image_id"], "plan boundary mismatch")
    operation = "behavior-" + name + ("-control" if relaxed else "-strict")
    require(plan.get("operation_id") == operation, "operation mismatch")
    expected_safe = {"operation_id": operation, "image_id": report["image_id"],
        "argv_sha256": digest(expected_command), "host_workspace_sha256": digest(workspace),
        "timeout_seconds": 12, "profile_sha256": digest(PROFILE)}
    require(all(plan.get(key) == value for key, value in expected_safe.items()), "plan digest binding mismatch")
    plan_sha = digest(expected_safe)
    require(session.split("-")[1] == plan_sha[:16], "session/plan digest mismatch")
    strict = case.get("strict_builder_argv")
    require(isinstance(strict, list) and strict[:3] == ["docker", "run", "--rm"], "generic builder prefix mismatch")
    require(option(strict, "--name") == session, "builder session mismatch")
    for key, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--user", "65534:65534"),
                       ("--pids-limit", "64"), ("--memory", "256m"), ("--cpus", "1.0"),
                       ("--tmpfs", PROFILE["tmpfs"]), ("--workdir", "/workspace"),
                       ("--entrypoint", ""), ("--log-driver", "none"),
                       ("--mount", "type=bind,src=" + workspace + ",dst=/workspace,readonly")):
        require(option(strict, key) == value, "strict builder protection missing " + key)
    require(strict.count("--read-only") == 1 and "no-new-privileges:true" in strict, "strict root/capability protection missing")
    exact_strict = ["docker", "run", "--rm", "--name", session,
        "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "65534:65534",
        "--pids-limit", "64", "--memory", "256m", "--cpus", "1.0", "--tmpfs", PROFILE["tmpfs"],
        "--workdir", "/workspace", "--mount", "type=bind,src=" + workspace + ",dst=/workspace,readonly",
        "--entrypoint", "", "--log-driver", "none",
        report["image_id"], *expected_command]
    require(strict == exact_strict, "generic strict builder has extra or missing arguments")
    launch = expected_control(strict, name, report["network_lab"]["name"]) if relaxed else list(strict)
    create = launch[:]
    create[1:3] = ["create", "--restart", "no", "--label", "org.liminal.session=" + session,
                   "--label", "org.liminal.plan=" + plan_sha]
    require(case.get("create_argv") == create, "create command is not exactly strict or one-weakened")
    commands = case.get("commands", [])
    require(commands.count(create) == 1 and commands.count(["docker", "start", "--attach", cid]) == 1,
            "actual create/attached-start census mismatch")
    require(["docker", "rm", "-f", cid] in commands, "immutable-ID adapter cleanup missing")
    initial, terminal = case.get("created", {}), case.get("exited", {})
    for observed in (initial, terminal):
        require(observed.get("Id") == cid and observed.get("Name") == "/" + session
                and observed.get("Image") == report["image_id"], "observed workload identity mismatch")
        config, host = observed.get("Config", {}), observed.get("HostConfig", {})
        require(config.get("Labels", {}).get("org.liminal.session") == session
                and config["Labels"].get("org.liminal.plan") == plan_sha, "resource ownership labels mismatch")
        require(config.get("User") == "65534:65534" and config.get("WorkingDir") == "/workspace"
                and config.get("Cmd") == expected_command, "actual command/user/workdir mismatch")
        require(config.get("Entrypoint") == (POISON if relaxed and name == "entrypoint" else [])
                or (config.get("Entrypoint") is None and not (relaxed and name == "entrypoint")), "entrypoint observation mismatch")
        require(host.get("NetworkMode") == (report["network_lab"]["name"] if relaxed and name == "network" else "none"), "network mode mismatch")
        require(host.get("ReadonlyRootfs") is (not (relaxed and name == "root_write")), "root protection observation mismatch")
        require(host.get("CapDrop") == ["ALL"] and "no-new-privileges:true" in host.get("SecurityOpt", []), "capability/no-new-privileges missing")
        require(("seccomp=unconfined" in host.get("SecurityOpt", [])) is (relaxed and name == "seccomp"), "seccomp control mismatch")
        require(host.get("Privileged") is False and host.get("PidMode") == ""
                and host.get("IpcMode") in {"private", "none"}
                and host.get("RestartPolicy", {}).get("Name") == "no", "unexpected privileged/host namespace/restart state")
        require(host.get("PidsLimit") == 64 and host.get("Memory") == 256 * 1024 * 1024 and host.get("NanoCpus") == 10**9, "resource config mismatch")
        mount = [item for item in observed.get("Mounts", []) if item.get("Destination") == "/workspace"]
        require(len(mount) == 1 and mount[0].get("Type") == "bind" and mount[0].get("Source") == workspace
                and mount[0].get("RW") is (relaxed and name == "workspace_write"), "workspace actual mount mismatch")
        log_type = "json-file" if relaxed and name == "logging" else "none"
        require(host.get("LogConfig", {}).get("Type") == log_type, "actual Docker log driver mismatch")
        if log_type == "none":
            require(observed.get("LogPath") == "", "none-driver daemon log path must be empty")
        elif observed is terminal:
            require(isinstance(observed.get("LogPath"), str) and bool(observed["LogPath"]), "terminal daemon log path missing")
        if log_type == "json-file":
            require(host["LogConfig"].get("Config") == {"max-size": "1m", "max-file": "1"}, "log control is unbounded")
    require(initial.get("State", {}).get("Status") == "created" and initial["State"].get("Running") is False, "create was not inert")
    expected_exit = 73 if name == "entrypoint" and relaxed else 0
    require(type(case.get("returncode")) is int and case["returncode"] == expected_exit
            and terminal.get("State", {}).get("Status") == "exited"
            and terminal["State"].get("Running") is False and terminal["State"].get("ExitCode") == expected_exit,
            "workload completion not independently observed")
    absence = case.get("absence", {})
    require(absence.get("returncode") == 1 and "no such" in absence.get("stderr", "").lower(), "workload absence not verified")
    if expected_exit == 73:
        require(case.get("stdout") == "", "poison ENTRYPOINT did not replace requested executable")
        return cid
    try:
        output = json.loads(case.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise ValueError("attached worker output missing under current log driver") from error
    require(output.get("uid") == 65534 and output.get("mode") == name, "worker process identity mismatch")
    if name in {"root_write", "workspace_write"}:
        require(output.get("written") is relaxed and output.get("errno") == (None if relaxed else 30), "write protection lacks EROFS/control sensitivity")
    elif name == "network":
        require(output.get("connected") is relaxed and output.get("response") == (TOKEN if relaxed else None)
                and output.get("errno") == (None if relaxed else 101), "network behavior/control sensitivity failed")
        if relaxed:
            endpoint = terminal.get("NetworkSettings", {}).get("Networks", {}).get(report["network_lab"]["name"], {})
            # Exited endpoint IP may already be released; actual create config and successful token bind destination.
            require(isinstance(endpoint, dict), "network endpoint observation missing")
    elif name == "seccomp":
        require(type(output.get("seccomp")) is int and output["seccomp"] == (0 if relaxed else 2), "seccomp process mode/control sensitivity failed")
    elif name in {"entrypoint", "logging"}:
        require(output.get("marker") == "liminal-attached-stdout-v1", "attached stdout was lost")
    if name == "logging":
        logs = case.get("docker_logs", {})
        if relaxed:
            require(logs.get("returncode") == 0 and logs.get("stdout") == case["stdout"], "log-retaining control is insensitive")
        else:
            require(logs.get("stdout") == "", "none-driver unexpectedly retained readable daemon output")
    return cid


def verify(report, *, revision, base_image, source_root=ROOT, check_source=True):
    require(isinstance(report, dict) and report.get("schema") == "liminal-docker-behavior-probe-v1", "schema mismatch")
    require(report.get("capture_status") == "COMPLETE", "capture incomplete/failed")
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report.get("revision") == revision, "revision mismatch")
    require(IMAGE.fullmatch(base_image) and report.get("base_image_id") == base_image, "base image mismatch")
    require(IMAGE.fullmatch(str(report.get("image_id", ""))), "fixture image identity missing")
    require(report.get("scope") == "real-docker-generic-adapter-bounded-behavior-and-one-weakened-controls", "scope mismatch")
    require(report.get("deferred") == ["pids_exhaustion", "memory_exhaustion", "kernel_escape", "host_compromise"], "bounded scope/deferred checks lost")
    source_root = Path(source_root)
    sources = report.get("source_inputs", {})
    require(isinstance(sources, dict) and set(sources) == MANDATORY_SOURCES, "source-input coverage mismatch")
    require(all(isinstance(value, str) and HEX64.fullmatch(value) for value in sources.values()), "invalid source fingerprint")
    if check_source:
        for path, fingerprint in sources.items():
            require(hashlib.sha256((source_root / path).read_bytes()).hexdigest() == fingerprint, "source fingerprint mismatch: " + path)
    literals = literal_bindings(source_root)
    require(report.get("worker_sha256") == hashlib.sha256(literals["WORKER"].encode()).hexdigest()
            and report.get("server_source_sha256") == hashlib.sha256(literals["SERVER"].encode()).hexdigest()
            and report.get("dockerfile") == literals["DOCKERFILE"], "fixture code binding mismatch")
    base, image = report.get("base_image_inspect", {}), report.get("image_inspect", {})
    require(base.get("Id") == base_image and image.get("Id") == report["image_id"]
            and image.get("Config", {}).get("Entrypoint") == POISON, "fixture image/poison entrypoint mismatch")
    layers, derived = base.get("RootFS", {}).get("Layers", []), image.get("RootFS", {}).get("Layers", [])
    require(isinstance(layers, list) and layers and isinstance(derived, list) and len(derived) == len(layers) + 1
            and derived[:len(layers)] == layers, "derived image does not preserve pinned base layers")
    workspace = report.get("workspace", {})
    require(isinstance(workspace.get("path"), str) and workspace["path"].startswith("/") and workspace.get("mode") == 0o777
            and workspace.get("initial_entries") == [] and workspace.get("final_entries") == [], "workspace writability/control/cleanup mismatch")
    lab = report.get("network_lab", {})
    require(isinstance(lab.get("name"), str) and re.fullmatch(r"liminal-behavior-[0-9a-f]{16}-net", lab["name"]), "owned network identity missing")
    server = lab.get("server", {})
    require(server.get("Name") == "/" + lab["name"][:-4] + "-server", "owned server name mismatch")
    require(HEX64.fullmatch(str(server.get("Id", ""))) and server.get("Image") == report["image_id"]
            and server.get("State", {}).get("Running") is True, "owned server not running on fixture image")
    require(server.get("Config", {}).get("Cmd") == ["-c", literals["SERVER"]]
            and server["Config"].get("Entrypoint") == ["python3"], "server source command mismatch")
    networks = server.get("NetworkSettings", {}).get("Networks", {})
    require(set(networks) == {lab["name"]} and networks[lab["name"]].get("IPAddress") == lab.get("server_ip")
            and re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", str(lab.get("server_ip", ""))), "server destination mismatch")
    for snap in (lab.get("inspect", {}), lab.get("final_inspect", {})):
        require(snap.get("Id") == report.get("network_create") and snap.get("Name") == lab["name"]
                and snap.get("Internal") is True and snap.get("Driver") == "bridge"
                and set(snap.get("Containers", {})) == {server["Id"]}, "network lab is not isolated/owned or leaked a client")
    health = lab.get("healthcheck", {})
    require(health.get("returncode") == 0 and health.get("stdout", "").strip() == TOKEN, "local server health control failed")
    require(isinstance(report.get("docker_version", {}).get("Server"), dict), "actual Docker server version missing")
    cases = report.get("cases", {})
    require(isinstance(cases, dict) and set(cases) == CASES, "behavior/control coverage mismatch")
    ids, daemons = [], set()
    for name in sorted(CASES):
        require(set(cases[name]) == {"strict", "control"}, "missing paired negative control")
        for variant in ("strict", "control"):
            ids.append(verify_case(cases[name][variant], name, variant, report, literals["WORKER"]))
            daemons.add(cases[name][variant].get("daemon_id"))
    require(server["Id"] not in ids, "server aliases a governed workload container")
    require(len(set(ids)) == 12 and len(daemons) == 1 and all(isinstance(value, str) and value for value in daemons), "workload/daemon identity census mismatch")
    cleanup = report.get("cleanup", {})
    require(cleanup.get("server_remove_returncode") == 0 and cleanup.get("server_absence_returncode") == 1
            and "no such" in cleanup.get("server_absence_stderr", "").lower()
            and ("not found" in cleanup.get("network_absence_stderr", "").lower() or "no such" in cleanup.get("network_absence_stderr", "").lower())
            and cleanup.get("network_remove_returncode") == 0 and cleanup.get("network_absence_returncode") == 1
            and cleanup.get("owned_lab_container_ids") == [], "owned lab cleanup not established")
    workloads = cleanup.get("workloads", [])
    require(isinstance(workloads, list) and len(workloads) == 12 and {row.get("container_id") for row in workloads} == set(ids)
            and all(row.get("absence_returncode") == 1 and "no such" in row.get("absence_stderr", "").lower() for row in workloads), "final workload absence census missing")
    return {"schema": "liminal-docker-behavior-verification-v1", "revision": revision,
            "base_image_id": base_image, "image_id": report["image_id"], "pairs": 6,
            "workload_containers": 12, "server_containers": 1,
            "verdict": "BOUNDED_BEHAVIORS_AND_CONTROL_SENSITIVITY_VERIFIED",
            "universal_escape_resistance": "NOT_ESTABLISHED"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=args.source_root, check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=args.source_root,
        check=True, capture_output=True, text=True, timeout=10).stdout
    require(actual == args.revision and not dirty, "verification source is not exact clean revision")
    raw = args.report.read_bytes()
    require(len(raw) <= 8 * 1024 * 1024, "report exceeds 8 MiB bound")
    record = verify(json.loads(raw), revision=args.revision, base_image=args.base_image, source_root=args.source_root)
    record["report_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
