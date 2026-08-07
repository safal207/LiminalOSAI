"""Container-bound process execution governance for LiminalOS.

The model-facing SDK never starts a subprocess or talks to Docker directly. It
binds one validated immutable container plan to the exact payload digest already
admitted by RuntimeMediator, then calls a trusted backend callback.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

SCHEMA = "liminal-isolated-execution-receipt-v0.1"
PROFILE_SCHEMA = "liminal-container-isolation-profile-v0.1"
_IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")

AUTHORITY = {
    "mode": "container_bound_process_execution_governance",
    "runtime_mediation_required": True,
    "immutable_image_required": True,
    "workspace_read_only": True,
    "network_none": True,
    "drop_all_linux_capabilities": True,
    "no_new_privileges": True,
    "non_root_user": True,
    "trusted_backend_dispatch": True,
    "direct_host_subprocess_execution": False,
    "direct_docker_api_access": False,
    "direct_socket_creation": False,
    "direct_filesystem_mutation": False,
    "credential_material_access": False,
    "vm_isolation": False,
    "kernel_or_container_runtime_exploit_resistance": False,
}


class IsolationError(ValueError):
    pass


@dataclass(frozen=True)
class IsolationProfile:
    network_mode: str = "none"
    read_only_root: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    uid: int = 65534
    gid: int = 65534
    pids_limit: int = 64
    memory_mb: int = 256
    cpus: str = "1.0"
    tmpfs: str = "/tmp:rw,nosuid,nodev,noexec,size=64m"
    workspace_mode: str = "ro"

    def validate(self) -> None:
        if self.network_mode != "none":
            raise IsolationError("network_mode must be none")
        if self.read_only_root is not True or self.drop_all_capabilities is not True or self.no_new_privileges is not True:
            raise IsolationError("isolation hardening flags are mandatory")
        if self.workspace_mode != "ro":
            raise IsolationError("workspace must be read-only in this MVP")
        if self.uid == 0 or self.gid == 0 or self.uid < 1 or self.gid < 1:
            raise IsolationError("container must run as non-root uid/gid")
        if not 1 <= self.pids_limit <= 256:
            raise IsolationError("pids_limit is outside bounded profile")
        if not 32 <= self.memory_mb <= 1024:
            raise IsolationError("memory_mb is outside bounded profile")
        if self.cpus not in {"0.25", "0.5", "1.0", "2.0"}:
            raise IsolationError("cpus is outside bounded profile")
        if self.tmpfs != "/tmp:rw,nosuid,nodev,noexec,size=64m":
            raise IsolationError("tmpfs profile mismatch")

    def body(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema": PROFILE_SCHEMA,
            "network_mode": self.network_mode,
            "read_only_root": self.read_only_root,
            "drop_all_capabilities": self.drop_all_capabilities,
            "no_new_privileges": self.no_new_privileges,
            "uid": self.uid,
            "gid": self.gid,
            "pids_limit": self.pids_limit,
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "tmpfs": self.tmpfs,
            "workspace_mode": self.workspace_mode,
        }

    @property
    def profile_sha256(self) -> str:
        return canonical_sha256(self.body())


@dataclass(frozen=True)
class IsolatedExecutionPlan:
    operation_id: str
    image_id: str
    argv: tuple[str, ...]
    host_workspace: str
    timeout_seconds: int = 30
    profile: IsolationProfile = IsolationProfile()

    @classmethod
    def build(
        cls,
        *,
        operation_id: str,
        image_id: str,
        argv: Sequence[str],
        host_workspace: str,
        timeout_seconds: int = 30,
        profile: IsolationProfile | None = None,
    ) -> "IsolatedExecutionPlan":
        item = cls(
            operation_id=operation_id,
            image_id=image_id,
            argv=tuple(argv),
            host_workspace=host_workspace,
            timeout_seconds=timeout_seconds,
            profile=profile or IsolationProfile(),
        )
        item.validate()
        return item

    def validate(self) -> None:
        if not isinstance(self.operation_id, str) or not self.operation_id.strip() or "\x00" in self.operation_id:
            raise IsolationError("operation_id must be non-empty")
        if not isinstance(self.image_id, str) or not _IMAGE.fullmatch(self.image_id):
            raise IsolationError("image_id must be immutable sha256:<64 lowercase hex>")
        if not self.argv or len(self.argv) > 64:
            raise IsolationError("argv must contain 1..64 arguments")
        for arg in self.argv:
            if not isinstance(arg, str) or not arg or "\x00" in arg or len(arg) > 4096:
                raise IsolationError("argv contains an invalid argument")
        if not isinstance(self.host_workspace, str) or not self.host_workspace.startswith("/"):
            raise IsolationError("host_workspace must be an absolute path")
        if "\x00" in self.host_workspace or "," in self.host_workspace or len(self.host_workspace) > 4096:
            raise IsolationError("host_workspace contains unsupported characters")
        if not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 120:
            raise IsolationError("timeout_seconds must be between 1 and 120")
        self.profile.validate()

    def safe_body(self) -> dict[str, Any]:
        self.validate()
        return {
            "operation_id": self.operation_id,
            "image_id": self.image_id,
            "argv_sha256": canonical_sha256(list(self.argv)),
            "host_workspace_sha256": canonical_sha256(self.host_workspace),
            "timeout_seconds": self.timeout_seconds,
            "profile_sha256": self.profile.profile_sha256,
        }

    @property
    def plan_sha256(self) -> str:
        return canonical_sha256(self.safe_body())

    @property
    def payload_sha256(self) -> str:
        return canonical_sha256({"isolated_execution_plan_sha256": self.plan_sha256})


@dataclass(frozen=True)
class IsolatedExecutionReceipt:
    operation_id: str
    plan_sha256: str
    isolation_profile_sha256: str
    image_id: str
    mediation_receipt_sha256: str
    admission_decision: str
    execution_outcome: str
    backend_invoked: bool
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "operation_id": self.operation_id,
            "plan_sha256": self.plan_sha256,
            "isolation_profile_sha256": self.isolation_profile_sha256,
            "image_id": self.image_id,
            "mediation_receipt_sha256": self.mediation_receipt_sha256,
            "admission_decision": self.admission_decision,
            "execution_outcome": self.execution_outcome,
            "backend_invoked": self.backend_invoked,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


Backend = Callable[[IsolatedExecutionPlan], ExecutionObservation]


class IsolatedExecutionBroker:
    def __init__(self, *, mediator: RuntimeMediator, backend: Backend) -> None:
        self.mediator = mediator
        self.backend = backend
        self._receipts: list[IsolatedExecutionReceipt] = []

    def execute(self, *, operation: RuntimeOperation, plan: IsolatedExecutionPlan) -> dict[str, Any]:
        operation.validate()
        plan.validate()
        if operation.kind != "process.execute":
            raise IsolationError("isolated execution MVP only accepts process.execute")
        if operation.operation_id != plan.operation_id:
            raise IsolationError("operation_id does not match isolated execution plan")
        scope = operation.normalized_scope()
        if scope.get("working_directory") != "/workspace":
            raise IsolationError("isolated process working_directory must be /workspace")
        if plan.argv[0] not in set(scope.get("executables", [])):
            raise IsolationError("container executable is outside process capability scope")
        if operation.payload_sha256 != plan.payload_sha256:
            raise IsolationError("runtime payload is not bound to the isolated execution plan")

        mediation = self.mediator.mediate(operation, lambda _: self.backend(plan))
        base = IsolatedExecutionReceipt(
            operation_id=operation.operation_id,
            plan_sha256=plan.plan_sha256,
            isolation_profile_sha256=plan.profile.profile_sha256,
            image_id=plan.image_id,
            mediation_receipt_sha256=mediation["receipt_sha256"],
            admission_decision=mediation["admission_decision"],
            execution_outcome=mediation["execution_outcome"],
            backend_invoked=mediation["admission_decision"] == "ALLOW",
            receipt_sha256="",
        )
        receipt = IsolatedExecutionReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != SCHEMA or raw.get("authority") != AUTHORITY:
        raise IsolationError("isolated execution receipt schema or authority mismatch")
    if digest != canonical_sha256(raw):
        raise IsolationError("isolated execution receipt digest mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY", "Backend", "IsolationError", "IsolationProfile", "IsolatedExecutionBroker",
    "IsolatedExecutionPlan", "IsolatedExecutionReceipt", "PROFILE_SCHEMA", "SCHEMA", "verify_receipt",
]
