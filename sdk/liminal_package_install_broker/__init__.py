"""Bound offline package installation governance for LiminalOS.

This model-facing SDK never invokes a package manager, opens sockets, mutates the
host filesystem or talks to Docker. It binds one exact host-staged package plan
to `package.install` and then requires the existing isolated execution stack to
admit the deterministic installer process separately.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_isolated_execution import IsolatedExecutionBroker, IsolatedExecutionPlan
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import RuntimeOperation

SCHEMA = "liminal-package-install-receipt-v0.1"
BINDING_SCHEMA = "liminal-package-workspace-binding-v0.1"
ZERO_SHA256 = "0" * 64
INSTALLER_EXECUTABLE = "/usr/local/bin/liminal-pkg-installer"
ARGUMENT_PROFILE = "bound-package-install-v0.1"
INSTALL_TARGET = "/tmp/liminal-site-packages"
MAX_DEPENDENCIES = 256

_AUTHORITY_ITEMS = (
    ("mode", "bound_offline_package_install_governance"),
    ("host_staged_plan_required", True),
    ("package_capability_required", True),
    ("isolated_process_capability_required", True),
    ("immutable_installer_image_required", True),
    ("staged_artifact_digest_required", True),
    ("dependency_plan_digest_required", True),
    ("registry_provenance_only", True),
    ("live_registry_fetch", False),
    ("direct_network_access", False),
    ("direct_package_manager_access", False),
    ("direct_docker_access", False),
    ("direct_host_filesystem_mutation", False),
    ("persistent_environment_mutation", False),
    ("ephemeral_tmpfs_materialization", True),
    ("installed_package_execution", False),
    ("supply_chain_authenticity_oracle", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$")
_PACKAGE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9._+!-]{0,127}$")
_REGISTRY = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,189}[a-z0-9])?$")
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class PackageInstallError(ValueError):
    pass


def _authority_document() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


def _ident(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value:
        raise PackageInstallError(f"invalid_{name}")
    if not _IDENT.fullmatch(value):
        raise PackageInstallError(f"invalid_{name}")
    return value


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise PackageInstallError(f"invalid_{name}")
    return value


def _package(value: str) -> str:
    if not isinstance(value, str):
        raise PackageInstallError("invalid_package_name")
    normalized = re.sub(r"[-_.]+", "-", value.lower())
    if not _PACKAGE.fullmatch(normalized):
        raise PackageInstallError("invalid_package_name")
    return normalized


def _version(value: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise PackageInstallError("invalid_version")
    return value


def _registry(value: str) -> str:
    if not isinstance(value, str):
        raise PackageInstallError("invalid_registry")
    normalized = value.lower()
    if not _REGISTRY.fullmatch(normalized) or "." not in normalized:
        raise PackageInstallError("invalid_registry")
    return normalized


def _bounded_int(value: int, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PackageInstallError(f"invalid_{name}")
    return value


def _coordinate(package_name: str, version: str) -> str:
    return f"{_package(package_name)}=={_version(version)}"


@dataclass(frozen=True)
class PackageWorkspaceBinding:
    binding_id: str
    host_workspace: str
    registry: str
    package_name: str
    version: str
    artifact_sha256: str
    dependency_plan_sha256: str
    staged_manifest_sha256: str
    dependency_count: int
    installer_image_id: str
    binding_sha256: str

    @classmethod
    def build(
        cls,
        *,
        binding_id: str,
        host_workspace: str,
        registry: str,
        package_name: str,
        version: str,
        artifact_sha256: str,
        dependency_plan_sha256: str,
        staged_manifest_sha256: str,
        dependency_count: int,
        installer_image_id: str,
    ) -> "PackageWorkspaceBinding":
        binding_id = _ident(binding_id, "binding_id")
        if not isinstance(host_workspace, str) or not host_workspace.startswith("/"):
            raise PackageInstallError("host_workspace_must_be_absolute")
        if "\x00" in host_workspace or "," in host_workspace or len(host_workspace) > 4096:
            raise PackageInstallError("invalid_host_workspace")
        registry = _registry(registry)
        package_name = _package(package_name)
        version = _version(version)
        artifact_sha256 = _sha(artifact_sha256, "artifact_sha256")
        dependency_plan_sha256 = _sha(dependency_plan_sha256, "dependency_plan_sha256")
        staged_manifest_sha256 = _sha(staged_manifest_sha256, "staged_manifest_sha256")
        dependency_count = _bounded_int(dependency_count, "dependency_count", minimum=0, maximum=MAX_DEPENDENCIES)
        if not isinstance(installer_image_id, str) or not _IMAGE.fullmatch(installer_image_id):
            raise PackageInstallError("installer_image_must_be_immutable_digest")
        item = cls(
            binding_id=binding_id,
            host_workspace=host_workspace,
            registry=registry,
            package_name=package_name,
            version=version,
            artifact_sha256=artifact_sha256,
            dependency_plan_sha256=dependency_plan_sha256,
            staged_manifest_sha256=staged_manifest_sha256,
            dependency_count=dependency_count,
            installer_image_id=installer_image_id,
            binding_sha256="",
        )
        return cls(**{**item.__dict__, "binding_sha256": canonical_sha256(item.safe_body())})

    @property
    def package_coordinate(self) -> str:
        return f"{self.package_name}=={self.version}"

    def safe_body(self) -> dict[str, Any]:
        return {
            "schema": BINDING_SCHEMA,
            "binding_id": self.binding_id,
            "host_workspace_sha256": canonical_sha256(self.host_workspace),
            "registry": self.registry,
            "package_coordinate": self.package_coordinate,
            "artifact_sha256": self.artifact_sha256,
            "dependency_plan_sha256": self.dependency_plan_sha256,
            "staged_manifest_sha256": self.staged_manifest_sha256,
            "dependency_count": self.dependency_count,
            "installer_image_id": self.installer_image_id,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.safe_body(), "binding_sha256": self.binding_sha256}


@dataclass(frozen=True)
class PackageInstallRequest:
    call_id: str
    subject_id: str
    policy_sha256: str
    workspace_binding_id: str
    registry: str
    package_name: str
    version: str
    artifact_sha256: str
    dependency_plan_sha256: str
    staged_manifest_sha256: str
    dependency_count: int

    def normalized(self) -> "PackageInstallRequest":
        return PackageInstallRequest(
            call_id=_ident(self.call_id, "call_id"),
            subject_id=_ident(self.subject_id, "subject_id"),
            policy_sha256=_sha(self.policy_sha256, "policy_sha256"),
            workspace_binding_id=_ident(self.workspace_binding_id, "workspace_binding_id"),
            registry=_registry(self.registry),
            package_name=_package(self.package_name),
            version=_version(self.version),
            artifact_sha256=_sha(self.artifact_sha256, "artifact_sha256"),
            dependency_plan_sha256=_sha(self.dependency_plan_sha256, "dependency_plan_sha256"),
            staged_manifest_sha256=_sha(self.staged_manifest_sha256, "staged_manifest_sha256"),
            dependency_count=_bounded_int(self.dependency_count, "dependency_count", minimum=0, maximum=MAX_DEPENDENCIES),
        )

    @property
    def package_coordinate(self) -> str:
        r = self.normalized()
        return f"{r.package_name}=={r.version}"

    def safe_body(self) -> dict[str, Any]:
        r = self.normalized()
        return {
            "call_id": r.call_id,
            "subject_id": r.subject_id,
            "policy_sha256": r.policy_sha256,
            "workspace_binding_id": r.workspace_binding_id,
            "registry": r.registry,
            "package_coordinate": f"{r.package_name}=={r.version}",
            "artifact_sha256": r.artifact_sha256,
            "dependency_plan_sha256": r.dependency_plan_sha256,
            "staged_manifest_sha256": r.staged_manifest_sha256,
            "dependency_count": r.dependency_count,
            "install_target": INSTALL_TARGET,
            "argument_profile": ARGUMENT_PROFILE,
        }


@dataclass(frozen=True)
class PackageInstallReceipt:
    receipt_id: str
    call_id: str
    subject_id: str
    request_sha256: str
    workspace_binding_sha256: str
    package_plan_sha256: str
    package_capability_receipt_sha256: str
    package_decision: str
    isolated_execution_receipt_sha256: str
    process_admission_decision: str
    execution_outcome: str
    installer_image_id: str
    artifact_sha256: str
    dependency_plan_sha256: str
    staged_manifest_sha256: str
    dependency_count: int
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "subject_id": self.subject_id,
            "request_sha256": self.request_sha256,
            "workspace_binding_sha256": self.workspace_binding_sha256,
            "package_plan_sha256": self.package_plan_sha256,
            "package_capability_receipt_sha256": self.package_capability_receipt_sha256,
            "package_decision": self.package_decision,
            "isolated_execution_receipt_sha256": self.isolated_execution_receipt_sha256,
            "process_admission_decision": self.process_admission_decision,
            "execution_outcome": self.execution_outcome,
            "installer_image_id": self.installer_image_id,
            "artifact_sha256": self.artifact_sha256,
            "dependency_plan_sha256": self.dependency_plan_sha256,
            "staged_manifest_sha256": self.staged_manifest_sha256,
            "dependency_count": self.dependency_count,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


Clock = Callable[[], int]


class PackageInstallBroker:
    def __init__(
        self,
        *,
        capability_broker: CapabilityBroker,
        isolated_execution_broker: IsolatedExecutionBroker,
        workspace_bindings: Iterable[PackageWorkspaceBinding],
        clock: Clock | None = None,
    ) -> None:
        self.capability_broker = capability_broker
        self.isolated_execution_broker = isolated_execution_broker
        self._clock = clock or (lambda: int(time.time()))
        bindings: dict[str, PackageWorkspaceBinding] = {}
        for item in workspace_bindings:
            if not isinstance(item, PackageWorkspaceBinding):
                raise PackageInstallError("workspace_bindings_must_be_host_objects")
            rebuilt = PackageWorkspaceBinding.build(
                binding_id=item.binding_id,
                host_workspace=item.host_workspace,
                registry=item.registry,
                package_name=item.package_name,
                version=item.version,
                artifact_sha256=item.artifact_sha256,
                dependency_plan_sha256=item.dependency_plan_sha256,
                staged_manifest_sha256=item.staged_manifest_sha256,
                dependency_count=item.dependency_count,
                installer_image_id=item.installer_image_id,
            )
            if rebuilt.binding_sha256 != item.binding_sha256:
                raise PackageInstallError("workspace_binding_digest_mismatch")
            if rebuilt.binding_id in bindings:
                raise PackageInstallError("duplicate_workspace_binding")
            bindings[rebuilt.binding_id] = rebuilt
        if not bindings:
            raise PackageInstallError("workspace_binding_required")
        self._bindings = MappingProxyType(bindings)
        self._seen_call_ids: set[str] = set()
        self._receipts: list[PackageInstallReceipt] = []
        self._lock = threading.RLock()

    def install(self, request: PackageInstallRequest) -> dict[str, Any]:
        req = request.normalized()
        with self._lock:
            now = self._now()
            request_sha = canonical_sha256(req.safe_body())
            if req.call_id in self._seen_call_ids:
                return self._finish(
                    req=req, request_sha=request_sha, binding=None, package_plan_sha=ZERO_SHA256,
                    capability_receipt_sha=ZERO_SHA256, package_decision="BLOCK",
                    isolated_receipt_sha=ZERO_SHA256, process_admission="NOT_REQUESTED",
                    execution_outcome="NOT_EXECUTED", reasons=("replayed_call_id",), now=now,
                )
            self._seen_call_ids.add(req.call_id)
            binding = self._bindings.get(req.workspace_binding_id)
            if binding is None:
                return self._finish(
                    req=req, request_sha=request_sha, binding=None, package_plan_sha=ZERO_SHA256,
                    capability_receipt_sha=ZERO_SHA256, package_decision="BLOCK",
                    isolated_receipt_sha=ZERO_SHA256, process_admission="NOT_REQUESTED",
                    execution_outcome="NOT_EXECUTED", reasons=("unknown_workspace_binding",), now=now,
                )

            mismatch_reasons: list[str] = []
            if req.registry != binding.registry:
                mismatch_reasons.append("registry_binding_mismatch")
            if f"{req.package_name}=={req.version}" != binding.package_coordinate:
                mismatch_reasons.append("package_coordinate_binding_mismatch")
            if req.artifact_sha256 != binding.artifact_sha256:
                mismatch_reasons.append("artifact_binding_mismatch")
            if req.dependency_plan_sha256 != binding.dependency_plan_sha256:
                mismatch_reasons.append("dependency_plan_binding_mismatch")
            if req.staged_manifest_sha256 != binding.staged_manifest_sha256:
                mismatch_reasons.append("staged_manifest_mismatch")
            if req.dependency_count != binding.dependency_count:
                mismatch_reasons.append("dependency_count_binding_mismatch")
            if mismatch_reasons:
                return self._finish(
                    req=req, request_sha=request_sha, binding=binding, package_plan_sha=ZERO_SHA256,
                    capability_receipt_sha=ZERO_SHA256, package_decision="BLOCK",
                    isolated_receipt_sha=ZERO_SHA256, process_admission="NOT_REQUESTED",
                    execution_outcome="NOT_EXECUTED", reasons=tuple(mismatch_reasons), now=now,
                )

            package_plan = {
                "request_sha256": request_sha,
                "workspace_binding_sha256": binding.binding_sha256,
                "installer_image_id": binding.installer_image_id,
                "installer_executable": INSTALLER_EXECUTABLE,
                "argument_profile": ARGUMENT_PROFILE,
                "install_target": INSTALL_TARGET,
            }
            package_plan_sha = canonical_sha256(package_plan)
            package_capability = self.capability_broker.authorize(
                subject_id=req.subject_id,
                capability_type="package.install",
                policy_sha256=req.policy_sha256,
                requested_scope={"registries": [binding.registry], "packages": [binding.package_coordinate]},
                action={
                    "call_id": req.call_id,
                    "workspace_binding_sha256": binding.binding_sha256,
                    "package_plan_sha256": package_plan_sha,
                    "artifact_sha256": binding.artifact_sha256,
                    "dependency_plan_sha256": binding.dependency_plan_sha256,
                    "staged_manifest_sha256": binding.staged_manifest_sha256,
                    "dependency_count": binding.dependency_count,
                },
                at_unix=now,
            )
            if package_capability["decision"] != "ALLOW":
                return self._finish(
                    req=req, request_sha=request_sha, binding=binding, package_plan_sha=package_plan_sha,
                    capability_receipt_sha=package_capability["receipt_sha256"], package_decision="BLOCK",
                    isolated_receipt_sha=ZERO_SHA256, process_admission="NOT_REQUESTED",
                    execution_outcome="NOT_EXECUTED", reasons=tuple(package_capability["reason_codes"]), now=now,
                )

            isolated_plan = IsolatedExecutionPlan.build(
                operation_id=f"package-install:{req.call_id}",
                image_id=binding.installer_image_id,
                argv=self._installer_argv(binding),
                host_workspace=binding.host_workspace,
                timeout_seconds=60,
            )
            operation = RuntimeOperation(
                operation_id=isolated_plan.operation_id,
                subject_id=req.subject_id,
                policy_sha256=req.policy_sha256,
                kind="process.execute",
                scope={
                    "executables": [INSTALLER_EXECUTABLE],
                    "working_directory": "/workspace",
                    "argument_profile": ARGUMENT_PROFILE,
                },
                payload_sha256=isolated_plan.payload_sha256,
                at_unix=now,
            )
            isolated = self.isolated_execution_broker.execute(operation=operation, plan=isolated_plan)
            reasons = ["package_capability_admitted", "host_staged_plan_matched"]
            if isolated["admission_decision"] == "ALLOW" and isolated["execution_outcome"] == "SUCCEEDED":
                reasons.extend(("process_capability_admitted", "isolated_install_succeeded"))
            else:
                reasons.append("isolated_process_gate_blocked_or_failed")
            return self._finish(
                req=req, request_sha=request_sha, binding=binding, package_plan_sha=package_plan_sha,
                capability_receipt_sha=package_capability["receipt_sha256"], package_decision="ALLOW",
                isolated_receipt_sha=isolated["receipt_sha256"],
                process_admission=isolated["admission_decision"], execution_outcome=isolated["execution_outcome"],
                reasons=tuple(reasons), now=now,
            )

    def receipts(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(item.as_document() for item in self._receipts)

    @staticmethod
    def _installer_argv(binding: PackageWorkspaceBinding) -> tuple[str, ...]:
        return (
            INSTALLER_EXECUTABLE,
            "--offline",
            "--manifest-sha256", binding.staged_manifest_sha256,
            "--registry-provenance", binding.registry,
            "--package", binding.package_name,
            "--version", binding.version,
            "--artifact-sha256", binding.artifact_sha256,
            "--dependency-plan-sha256", binding.dependency_plan_sha256,
            "--dependency-count", str(binding.dependency_count),
            "--target", INSTALL_TARGET,
            "--no-execute-installed-code",
        )

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PackageInstallError("invalid_host_clock")
        return value

    def _finish(
        self,
        *,
        req: PackageInstallRequest,
        request_sha: str,
        binding: PackageWorkspaceBinding | None,
        package_plan_sha: str,
        capability_receipt_sha: str,
        package_decision: str,
        isolated_receipt_sha: str,
        process_admission: str,
        execution_outcome: str,
        reasons: tuple[str, ...],
        now: int,
    ) -> dict[str, Any]:
        base = PackageInstallReceipt(
            receipt_id=f"package-install-receipt:{len(self._receipts)+1}",
            call_id=req.call_id,
            subject_id=req.subject_id,
            request_sha256=request_sha,
            workspace_binding_sha256=binding.binding_sha256 if binding else ZERO_SHA256,
            package_plan_sha256=package_plan_sha,
            package_capability_receipt_sha256=capability_receipt_sha,
            package_decision=package_decision,
            isolated_execution_receipt_sha256=isolated_receipt_sha,
            process_admission_decision=process_admission,
            execution_outcome=execution_outcome,
            installer_image_id=binding.installer_image_id if binding else "sha256:" + ZERO_SHA256,
            artifact_sha256=req.artifact_sha256,
            dependency_plan_sha256=req.dependency_plan_sha256,
            staged_manifest_sha256=req.staged_manifest_sha256,
            dependency_count=req.dependency_count,
            reason_codes=tuple(sorted(set(reasons))),
            at_unix=now,
            receipt_sha256="",
        )
        receipt = PackageInstallReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    expected = {
        "schema", "receipt_id", "call_id", "subject_id", "request_sha256",
        "workspace_binding_sha256", "package_plan_sha256", "package_capability_receipt_sha256",
        "package_decision", "isolated_execution_receipt_sha256", "process_admission_decision",
        "execution_outcome", "installer_image_id", "artifact_sha256", "dependency_plan_sha256",
        "staged_manifest_sha256", "dependency_count", "reason_codes", "at_unix", "authority",
        "receipt_sha256",
    }
    if set(raw) != expected:
        raise PackageInstallError("package_receipt_schema_mismatch")
    receipt_sha = raw.pop("receipt_sha256")
    if raw.get("schema") != SCHEMA or raw.get("authority") != _authority_document():
        raise PackageInstallError("package_receipt_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise PackageInstallError("package_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "ARGUMENT_PROFILE", "AUTHORITY", "BINDING_SCHEMA", "INSTALLER_EXECUTABLE", "INSTALL_TARGET",
    "MAX_DEPENDENCIES", "PackageInstallBroker", "PackageInstallError", "PackageInstallReceipt",
    "PackageInstallRequest", "PackageWorkspaceBinding", "SCHEMA", "verify_receipt",
]
