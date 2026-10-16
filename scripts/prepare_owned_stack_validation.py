#!/usr/bin/env python3
"""Prepare real owned-stack inputs before unchanged strict test discovery.

No fake Docker/capture mode exists. READY_FOR_VALIDATION is preparation evidence,
not a repository test result. A checkout without the owned SDK is unaffected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKER_REFERENCE = "python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
CAPTURE_CLASS = "tests.test_agent_control_external_agent_receiver_evidence.ReceiverCaptureMutationTests"
ORIENTATION_CAPTURE_CLASS = "tests.test_agent_control_external_agent_orientation_evidence.OrientationCaptureEvidenceTests"
ORIENTATION_CAPTURE_TESTS = 6
MAX_RECEIVER_CAPTURE_BYTES = 24 * 1024 * 1024  # Same raw bound as the independent checker.
REQUIRED_SOURCES = (
    "experiments/agent_control/observer-requirements.txt",
    "experiments/agent_control/observer.Dockerfile",
    "scripts/run_python_tests.py",
    "scripts/verify_external_agent_receiver_evidence.py",
    "tests/test_agent_control_external_agent_receiver_runtime.py",
    "tests/test_agent_control_external_agent_receiver_evidence.py",
    "sdk/liminal_agent_control/external_agent_orientation_feedback.py",
    "sdk/liminal_agent_control/external_agent_orientation_demo.py",
    "experiments/agent_control/preregistration_external_agent_orientation.json",
    "scripts/verify_external_agent_orientation_evidence.py",
    "tests/test_agent_control_external_agent_orientation_runtime.py",
    "tests/test_agent_control_external_agent_orientation_evidence.py",
)
CAPTURE_CLASS_CHECK = """
import os
from pathlib import Path
import unittest
report = Path(os.environ['LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE'])
if not report.is_file() or report.stat().st_size == 0:
    raise SystemExit('fresh actual receiver report is required before discovery')
suite = unittest.defaultTestLoader.loadTestsFromName(
    'tests.test_agent_control_external_agent_receiver_evidence.ReceiverCaptureMutationTests')
if suite.countTestCases() != 9:
    raise SystemExit('all nine receiver capture tests must be present before discovery')
"""
ORIENTATION_CAPTURE_CLASS_CHECK = """
import os
from pathlib import Path
import unittest
report = Path(os.environ['LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE'])
if not report.is_file() or report.stat().st_size == 0:
    raise SystemExit('fresh actual orientation report is required before discovery')
suite = unittest.defaultTestLoader.loadTestsFromName(
    'tests.test_agent_control_external_agent_orientation_evidence.OrientationCaptureEvidenceTests')
if suite.countTestCases() != 6:
    raise SystemExit('all six orientation capture tests must be present before discovery')
"""


def command(argv, *, root, env=None, timeout=60, capture=False, output=None):
    """Run finite trusted setup commands; build/test logs stream to the job."""
    result = subprocess.run(
        list(map(str, argv)), cwd=root, env=env, stdin=subprocess.DEVNULL,
        stdout=output if output is not None else (subprocess.PIPE if capture else None),
        text=True, check=True, timeout=timeout, shell=False,
    )
    return result.stdout.strip() if capture else None


def immutable_image(value):
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("Docker did not return a full immutable image ID")
    return value


def snapshot_receiver_capture(source: Path, destination: Path):
    """Preserve the exact preparation bytes before full discovery rewrites source."""
    with source.open("rb") as stream:
        raw = stream.read(MAX_RECEIVER_CAPTURE_BYTES + 1)
    if not raw or len(raw) > MAX_RECEIVER_CAPTURE_BYTES:
        raise ValueError("receiver preparation capture is empty or oversized")
    with destination.open("xb") as stream:
        stream.write(raw)
    destination.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def export_environment(environment, python_bin, *, github_env=None, github_path=None):
    """Publish only a complete prepared environment, without multiline injection."""
    for key, value in environment.items():
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None or any(c in value for c in "\r\n"):
            raise ValueError("invalid prepared environment field")
    if any(c in str(python_bin) for c in "\r\n"):
        raise ValueError("invalid prepared Python path")
    if github_env:
        with Path(github_env).open("a", encoding="utf-8") as stream:
            for key, value in environment.items():
                stream.write(f"{key}={value}\n")
    if github_path:
        with Path(github_path).open("a", encoding="utf-8") as stream:
            stream.write(str(python_bin) + "\n")


def prepare(root: Path, output_directory: Path):
    root = root.resolve()
    owned_sdk = root / "sdk/liminal_agent_control"
    if not owned_sdk.exists():
        return {"status": "NOT_APPLICABLE", "reason": "owned SDK absent; unchanged full validation follows"}
    if not owned_sdk.is_dir():
        raise ValueError("owned SDK path is not a directory")
    missing = [name for name in REQUIRED_SOURCES if not (root / name).is_file()]
    if missing:
        raise ValueError("owned validation source input missing: " + ", ".join(missing))
    output_directory = output_directory.resolve()
    if output_directory == root or root in output_directory.parents:
        raise ValueError("preparation output must be outside the checkout")
    if output_directory.exists():
        raise ValueError("preparation requires a fresh output directory; stale captures are forbidden")
    revision = command(["git", "rev-parse", "HEAD"], root=root, capture=True)
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("invalid checked-out revision")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], root=root, capture=True):
        raise ValueError("actual capture preparation requires a clean source checkout")
    # A missing/unreachable daemon fails before installing dependencies or creating
    # an output tree. It is never translated into a successful preparation.
    daemon_id = command(["docker", "info", "--format", "{{.ID}}"], root=root, capture=True)
    if not daemon_id or len(daemon_id) > 256:
        raise ValueError("Docker daemon identity unavailable")
    output_directory.mkdir(parents=True, exist_ok=False)
    evidence = output_directory / "evidence"
    evidence.mkdir()
    venv = output_directory / "venv"
    command([sys.executable, "-m", "venv", venv], root=root, timeout=120)
    python = venv / "bin/python"
    command([python, "-m", "pip", "--isolated", "install", "-r",
             root / "experiments/agent_control/observer-requirements.txt"], root=root, timeout=300)
    command(["docker", "pull", "--platform", "linux/amd64", WORKER_REFERENCE], root=root, timeout=300)
    worker_id = immutable_image(command(
        ["docker", "image", "inspect", "--format", "{{.Id}}", WORKER_REFERENCE], root=root, capture=True))
    observer_id_file = output_directory / "observer-image-id.txt"
    command(["docker", "build", "--platform", "linux/amd64",
             "-f", root / "experiments/agent_control/observer.Dockerfile",
             "--iidfile", observer_id_file, root / "experiments/agent_control"], root=root, timeout=600)
    observer_id = immutable_image(observer_id_file.read_text(encoding="utf-8").strip())
    actual_observer = command(["docker", "image", "inspect", "--format", "{{.Id}}", observer_id], root=root, capture=True)
    if actual_observer != observer_id:
        raise ValueError("built observer image identity mismatch")
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHON": str(python),
        "PYTHONPATH": str(root / "sdk"),
        "EXPECTED_SOURCE_SHA": revision,
        "LIMINAL_AGENT_CONTROL_DOCKER_IMAGE": worker_id,
        "LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE": worker_id,
        "LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE": worker_id,
        "LIMINAL_OBSERVER_DOCKER_IMAGE": observer_id,
        "LIMINAL_EXTERNAL_AGENT_REQUIRE_DOCKER": "1",
        "LIMINAL_EXTERNAL_COMMAND_REQUIRE_DOCKER": "1",
        "LIMINAL_EXTERNAL_AGENT_RECEIVER_REQUIRE_DOCKER": "1",
        "LIMINAL_EXTERNAL_AGENT_ORIENTATION_REQUIRE_DOCKER": "1",
        "LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE": str(evidence / "receiver.json"),
        "LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE": str(evidence / "orientation.json"),
        "LIMINAL_EXTERNAL_AGENT_EVIDENCE": str(evidence / "agent.json"),
        "LIMINAL_EXTERNAL_COMMAND_EVIDENCE": str(evidence / "command.json"),
        "LIMINAL_EXTERNAL_NETWORK_EVIDENCE": str(evidence / "network.json"),
        "LIMINAL_EXTERNAL_STOP_EVIDENCE": str(evidence / "external-stop.json"),
        "LIMINAL_OBSERVER_LIFECYCLE_EVIDENCE": str(evidence / "observer-lifecycle.json"),
        "LIMINAL_RECEIVER_SOURCE_EVIDENCE": str(evidence / "receiver-source.json"),
        "LIMINAL_AGENT_CONTROL_RECOVERY_EVIDENCE": str(evidence / "supervisor-recovery.json"),
        "LIMINAL_AGENT_CONTROL_WATCHDOG_EVIDENCE": str(evidence / "watchdog.json"),
    }
    child_env = {**os.environ, **environment, "PATH": str(venv / "bin") + os.pathsep + os.environ.get("PATH", "")}
    # This child exits before the fresh capture-check and full-discovery children.
    command([python, root / "scripts/run_python_tests.py",
             "tests/test_agent_control_external_agent_receiver_runtime.py"],
            root=root, env=child_env, timeout=900)
    capture = Path(environment["LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE"])
    if not capture.is_file() or capture.stat().st_size == 0:
        raise ValueError("receiver runtime did not produce its required actual capture")
    preparation_capture = evidence / "receiver-preparation.json"
    preparation_sha256 = snapshot_receiver_capture(capture, preparation_capture)
    preparation_env = {**child_env, "LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE": str(preparation_capture)}
    with (evidence / "receiver-preparation-verification.json").open("x", encoding="utf-8") as stream:
        command([python, root / "scripts/verify_external_agent_receiver_evidence.py", preparation_capture,
                 "--expected-source-sha", revision, "--expected-report-sha256", preparation_sha256],
                root=root, env=preparation_env, timeout=120, output=stream)
    command([python, "-c", CAPTURE_CLASS_CHECK], root=root, env=preparation_env, timeout=60)
    # Run all nine now as well: presence alone cannot certify runnable evidence.
    command([python, root / "scripts/run_python_tests.py", CAPTURE_CLASS], root=root, env=preparation_env, timeout=120)
    # The observed-orientation profile has its own real Docker experiment and
    # independent checker. It cannot substitute for the receiver's 14-case matrix.
    command([python, root / "scripts/run_python_tests.py",
             "tests/test_agent_control_external_agent_orientation_runtime.py"],
            root=root, env=child_env, timeout=900)
    orientation_capture = Path(environment["LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE"])
    if not orientation_capture.is_file() or orientation_capture.stat().st_size == 0:
        raise ValueError("orientation runtime did not produce its required actual capture")
    orientation_preparation_capture = evidence / "orientation-preparation.json"
    orientation_preparation_sha256 = snapshot_receiver_capture(orientation_capture, orientation_preparation_capture)
    orientation_preparation_env = {
        **child_env, "LIMINAL_EXTERNAL_AGENT_ORIENTATION_EVIDENCE": str(orientation_preparation_capture)}
    with (evidence / "orientation-preparation-verification.json").open("x", encoding="utf-8") as stream:
        command([python, root / "scripts/verify_external_agent_orientation_evidence.py",
                 orientation_preparation_capture, "--expected-source-sha", revision,
                 "--expected-image", worker_id, "--expected-report-sha256", orientation_preparation_sha256],
                root=root, env=orientation_preparation_env, timeout=120, output=stream)
    command([python, "-c", ORIENTATION_CAPTURE_CLASS_CHECK], root=root,
            env=orientation_preparation_env, timeout=60)
    command([python, root / "scripts/run_python_tests.py", ORIENTATION_CAPTURE_CLASS],
            root=root, env=orientation_preparation_env, timeout=120)
    result = {
        "status": "READY_FOR_VALIDATION", "revision": revision, "daemon_id": daemon_id,
        "worker_reference": WORKER_REFERENCE, "worker_image_id": worker_id,
        "observer_image_id": observer_id, "receiver_capture_tests": 9,
        "receiver_preparation_capture": "evidence/receiver-preparation.json",
        "receiver_preparation_sha256": preparation_sha256,
        "orientation_capture_tests": ORIENTATION_CAPTURE_TESTS,
        "orientation_preparation_capture": "evidence/orientation-preparation.json",
        "orientation_preparation_sha256": orientation_preparation_sha256,
        "python_bin": str(venv / "bin"), "environment": environment,
    }
    (output_directory / "preparation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--github-env", default=os.environ.get("GITHUB_ENV"))
    parser.add_argument("--github-path", default=os.environ.get("GITHUB_PATH"))
    args = parser.parse_args(argv)
    try:
        result = prepare(ROOT, args.output_directory)
        if result["status"] == "READY_FOR_VALIDATION":
            export_environment(result["environment"], result["python_bin"],
                               github_env=args.github_env, github_path=args.github_path)
        print(json.dumps({key: value for key, value in result.items() if key != "environment"}, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "FAILED_PREPARATION", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
