#!/usr/bin/env python3
"""Trusted Docker backend for concrete LiminalOS wheel materialization.

The backend reuses the hardened Docker argv from the existing isolated execution
adapter, captures one bounded JSON receipt from the immutable installer image,
verifies it, and returns only digest evidence to RuntimeMediator.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from adapters.docker.liminal_docker_executor import build_docker_argv
from adapters.packages.liminal_wheel_materializer import (
    TARGET,
    canonical_sha256,
    normalize_distribution_name,
    normalize_registry,
    normalize_version,
    verify_receipt,
)
from sdk.liminal_isolated_execution import IsolatedExecutionPlan
from sdk.liminal_package_install_broker import INSTALLER_EXECUTABLE
from sdk.liminal_runtime_mediation import ExecutionObservation

MAX_RECEIPT_STDOUT_BYTES = 64 * 1024


class WheelDockerBackendError(RuntimeError):
    pass


def _flag_value(argv: tuple[str, ...], flag: str) -> str:
    matches = [idx for idx, item in enumerate(argv) if item == flag]
    if len(matches) != 1 or matches[0] + 1 >= len(argv):
        raise WheelDockerBackendError("installer_argv_contract_mismatch")
    return argv[matches[0] + 1]


def _validate_plan_contract(plan: IsolatedExecutionPlan) -> dict[str, Any]:
    plan.validate()
    argv = plan.argv
    if not argv or argv[0] != INSTALLER_EXECUTABLE:
        raise WheelDockerBackendError("installer_executable_mismatch")
    required_switches = {"--offline", "--no-execute-installed-code"}
    if not required_switches.issubset(set(argv)):
        raise WheelDockerBackendError("installer_safety_switch_missing")
    if _flag_value(argv, "--target") != TARGET:
        raise WheelDockerBackendError("installer_target_mismatch")
    package_name = normalize_distribution_name(_flag_value(argv, "--package"))
    version = normalize_version(_flag_value(argv, "--version"))
    registry = normalize_registry(_flag_value(argv, "--registry-provenance"))
    artifact_sha = _flag_value(argv, "--artifact-sha256")
    manifest_sha = _flag_value(argv, "--manifest-sha256")
    dependency_sha = _flag_value(argv, "--dependency-plan-sha256")
    dependency_count = _flag_value(argv, "--dependency-count")
    if not artifact_sha or not manifest_sha or not dependency_sha or not dependency_count.isdigit():
        raise WheelDockerBackendError("installer_digest_contract_mismatch")
    return {
        "package_name": package_name,
        "version": version,
        "registry": registry,
        "artifact_sha256": artifact_sha,
        "manifest_sha256": manifest_sha,
        "dependency_plan_sha256": dependency_sha,
        "dependency_count": int(dependency_count),
    }


class WheelMaterializingDockerExecutor:
    def __init__(self, docker_binary: str = "docker") -> None:
        if not isinstance(docker_binary, str) or not docker_binary.strip():
            raise WheelDockerBackendError("docker_binary_must_be_nonempty")
        self.docker_binary = docker_binary

    def __call__(self, plan: IsolatedExecutionPlan) -> ExecutionObservation:
        contract = _validate_plan_contract(plan)
        argv = build_docker_argv(plan, docker_binary=self.docker_binary)
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=plan.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise WheelDockerBackendError("wheel_materialization_container_timeout") from exc
        if proc.returncode != 0:
            raise WheelDockerBackendError("wheel_materialization_container_failed")
        if len(proc.stdout) > MAX_RECEIPT_STDOUT_BYTES:
            raise WheelDockerBackendError("wheel_materialization_receipt_too_large")
        try:
            text = proc.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WheelDockerBackendError("wheel_materialization_receipt_not_utf8") from exc
        lines = [line for line in text.splitlines() if line]
        if len(lines) != 1:
            raise WheelDockerBackendError("wheel_materialization_receipt_line_count_invalid")
        try:
            receipt = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise WheelDockerBackendError("wheel_materialization_receipt_invalid_json") from exc
        if not isinstance(receipt, dict):
            raise WheelDockerBackendError("wheel_materialization_receipt_invalid_json")
        verify_receipt(receipt)
        if receipt["artifact_sha256"] != contract["artifact_sha256"]:
            raise WheelDockerBackendError("wheel_materialization_artifact_binding_mismatch")
        if receipt["staged_manifest_sha256"] != contract["manifest_sha256"]:
            raise WheelDockerBackendError("wheel_materialization_manifest_binding_mismatch")
        if receipt["dependency_plan_sha256"] != contract["dependency_plan_sha256"]:
            raise WheelDockerBackendError("wheel_materialization_dependency_binding_mismatch")
        expected_coordinate = canonical_sha256({
            "registry": contract["registry"],
            "package_name": contract["package_name"],
            "version": contract["version"],
        })
        if receipt["package_coordinate_sha256"] != expected_coordinate:
            raise WheelDockerBackendError("wheel_materialization_coordinate_binding_mismatch")
        if receipt["outcome"] != "SUCCEEDED":
            raise WheelDockerBackendError("wheel_materialization_outcome_failed")
        return ExecutionObservation.success({
            "backend": "wheel-materializing-docker",
            "plan_sha256": plan.plan_sha256,
            "image_id": plan.image_id,
            "materialization_receipt_sha256": receipt["receipt_sha256"],
            "wheel_audit_sha256": receipt["wheel_audit_sha256"],
            "output_manifest_sha256": receipt["output_manifest_sha256"],
            "file_count": receipt["file_count"],
            "total_bytes": receipt["total_bytes"],
            "stdout": "verified-and-discarded",
            "stderr": "discarded",
        })


__all__ = ["MAX_RECEIPT_STDOUT_BYTES", "WheelDockerBackendError", "WheelMaterializingDockerExecutor"]
