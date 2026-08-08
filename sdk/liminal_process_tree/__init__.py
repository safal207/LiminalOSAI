"""Host-bound process-tree supervision for active LiminalOS containment.

The model-facing control plane records opaque execution-session bindings and
invokes trusted host callbacks to freeze, terminate and verify those sessions.
It never enumerates host processes directly and never exposes raw argv,
environment variables, workspace paths or host process identifiers in receipts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-process-tree-containment-receipt-v0.1"
ZERO_SHA256 = "0" * 64
AUTHORITY = {
    "mode": "host_bound_process_tree_containment",
    "trusted_host_callbacks": True,
    "freeze_registered_sessions": True,
    "terminate_registered_sessions": True,
    "verify_zero_survivors": True,
    "digest_only_receipts": True,
    "direct_host_process_enumeration": False,
    "direct_subprocess_execution": False,
    "direct_docker_api_access": False,
    "kernel_escape_resistance": False,
    "container_runtime_compromise_resistance": False,
    "automatic_release": False,
}


class ProcessTreeError(ValueError):
    pass


@dataclass(frozen=True)
class ProcessTreeObservation:
    session_id: str
    exists: bool
    running: bool
    descendant_count: int
    tree_sha256: str

    @classmethod
    def from_mapping(cls, session_id: str, value: Mapping[str, Any]) -> "ProcessTreeObservation":
        if not isinstance(session_id, str) or not session_id.strip() or "\x00" in session_id:
            raise ProcessTreeError("session_id must be non-empty")
        allowed = {"exists", "running", "descendant_count", "tree_sha256"}
        if set(value) != allowed:
            raise ProcessTreeError("process observation schema mismatch")
        exists = value["exists"]
        running = value["running"]
        descendants = value["descendant_count"]
        tree_sha = value["tree_sha256"]
        if not isinstance(exists, bool) or not isinstance(running, bool):
            raise ProcessTreeError("process observation booleans are invalid")
        if running and not exists:
            raise ProcessTreeError("running session must exist")
        if not isinstance(descendants, int) or isinstance(descendants, bool) or descendants < 0 or descendants > 4096:
            raise ProcessTreeError("descendant_count is outside bounds")
        _require_sha(tree_sha, "tree_sha256")
        if not exists and (running or descendants != 0 or tree_sha != ZERO_SHA256):
            raise ProcessTreeError("absent session must have zero survivor evidence")
        return cls(session_id, exists, running, descendants, tree_sha)

    def safe_body(self) -> dict[str, Any]:
        return {
            "session_id_sha256": canonical_sha256(self.session_id),
            "exists": self.exists,
            "running": self.running,
            "descendant_count": self.descendant_count,
            "tree_sha256": self.tree_sha256,
        }


@dataclass(frozen=True)
class SessionBinding:
    session_id: str
    operation_id: str
    plan_sha256: str
    backend_identity_sha256: str
    status: str

    def safe_body(self) -> dict[str, Any]:
        return {
            "session_id_sha256": canonical_sha256(self.session_id),
            "operation_id_sha256": canonical_sha256(self.operation_id),
            "plan_sha256": self.plan_sha256,
            "backend_identity_sha256": self.backend_identity_sha256,
            "status": self.status,
        }


@dataclass(frozen=True)
class ProcessTreeContainmentReceipt:
    incident_id: str
    session_count: int
    active_before_count: int
    terminated_count: int
    already_absent_count: int
    survivor_count: int
    session_set_sha256: str
    before_root_sha256: str
    after_root_sha256: str
    failure_codes: tuple[str, ...]
    zero_survivors: bool
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "incident_id_sha256": canonical_sha256(self.incident_id),
            "session_count": self.session_count,
            "active_before_count": self.active_before_count,
            "terminated_count": self.terminated_count,
            "already_absent_count": self.already_absent_count,
            "survivor_count": self.survivor_count,
            "session_set_sha256": self.session_set_sha256,
            "before_root_sha256": self.before_root_sha256,
            "after_root_sha256": self.after_root_sha256,
            "failure_codes": list(self.failure_codes),
            "zero_survivors": self.zero_survivors,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


InspectSession = Callable[[str], Mapping[str, Any]]
FreezeSession = Callable[[str], None]
TerminateSession = Callable[[str], None]


class ProcessTreeSupervisor:
    """Tracks governed execution sessions and fails closed on survivors."""

    def __init__(
        self,
        *,
        inspect_session: InspectSession,
        freeze_session: FreezeSession,
        terminate_session: TerminateSession,
    ) -> None:
        self.inspect_session = inspect_session
        self.freeze_session = freeze_session
        self.terminate_session = terminate_session
        self._sessions: dict[str, SessionBinding] = {}
        self._receipts: list[ProcessTreeContainmentReceipt] = []

    def register_session(
        self,
        *,
        session_id: str,
        operation_id: str,
        plan_sha256: str,
        backend_identity_sha256: str,
    ) -> dict[str, Any]:
        _validate_id(session_id, "session_id")
        _validate_id(operation_id, "operation_id")
        _require_sha(plan_sha256, "plan_sha256")
        _require_sha(backend_identity_sha256, "backend_identity_sha256")
        if session_id in self._sessions:
            raise ProcessTreeError("execution session replay/duplicate is forbidden")
        binding = SessionBinding(session_id, operation_id, plan_sha256, backend_identity_sha256, "ACTIVE")
        self._sessions[session_id] = binding
        return {**binding.safe_body(), "binding_sha256": canonical_sha256(binding.safe_body())}

    def mark_complete(self, session_id: str) -> dict[str, Any]:
        binding = self._get(session_id)
        if binding.status in {"COMPLETED", "TERMINATED"}:
            return binding.safe_body()
        observation = self._inspect(session_id)
        if observation.exists or observation.running or observation.descendant_count:
            raise ProcessTreeError("cannot mark a live process tree complete")
        self._set_status(session_id, "COMPLETED")
        return self._sessions[session_id].safe_body()

    def quiesce_session(self, session_id: str, *, incident_id: str) -> dict[str, Any]:
        _validate_id(incident_id, "incident_id")
        binding = self._get(session_id)
        return self._quiesce((binding,), incident_id=incident_id)

    def quiesce_all(self, *, incident_id: str) -> dict[str, Any]:
        _validate_id(incident_id, "incident_id")
        candidates = tuple(
            self._sessions[key]
            for key in sorted(self._sessions)
            if self._sessions[key].status not in {"COMPLETED", "TERMINATED"}
        )
        return self._quiesce(candidates, incident_id=incident_id)

    def containment_freeze_hook(self, *, incident_id: str) -> Callable[[], None]:
        """Return a Phase-4-compatible hook that guarantees zero survivors."""
        def hook() -> None:
            receipt = self.quiesce_all(incident_id=incident_id)
            if not receipt["zero_survivors"]:
                raise ProcessTreeError("active containment left surviving execution sessions")
        return hook

    def state_document(self) -> dict[str, Any]:
        safe = [self._sessions[key].safe_body() for key in sorted(self._sessions)]
        body = {"sessions": safe, "session_count": len(safe), "authority": AUTHORITY}
        return {**body, "state_sha256": canonical_sha256(body)}

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def _quiesce(self, bindings: tuple[SessionBinding, ...], *, incident_id: str) -> dict[str, Any]:
        before_docs: list[dict[str, Any]] = []
        after_docs: list[dict[str, Any]] = []
        failure_codes: list[str] = []
        terminated = 0
        already_absent = 0
        active_before = 0
        survivors = 0

        for binding in bindings:
            session_hash = canonical_sha256(binding.session_id)[:16]
            try:
                before = self._inspect(binding.session_id)
            except Exception as exc:
                failure_codes.append(f"inspect_before:{session_hash}:{type(exc).__name__}")
                self._set_status(binding.session_id, "ERROR")
                continue
            before_docs.append(before.safe_body())
            if not before.exists:
                already_absent += 1
                self._set_status(binding.session_id, "COMPLETED")
                after_docs.append(before.safe_body())
                continue

            active_before += 1
            try:
                if before.running:
                    self.freeze_session(binding.session_id)
                    self._set_status(binding.session_id, "FROZEN")
            except Exception as exc:
                failure_codes.append(f"freeze:{session_hash}:{type(exc).__name__}")

            try:
                self.terminate_session(binding.session_id)
            except Exception as exc:
                failure_codes.append(f"terminate:{session_hash}:{type(exc).__name__}")

            try:
                after = self._inspect(binding.session_id)
                after_docs.append(after.safe_body())
            except Exception as exc:
                failure_codes.append(f"inspect_after:{session_hash}:{type(exc).__name__}")
                self._set_status(binding.session_id, "ERROR")
                survivors += 1
                continue

            if after.exists or after.running or after.descendant_count != 0:
                failure_codes.append(f"survivor:{session_hash}")
                self._set_status(binding.session_id, "ERROR")
                survivors += 1
            else:
                terminated += 1
                self._set_status(binding.session_id, "TERMINATED")

        session_safe = [binding.safe_body() for binding in bindings]
        session_set_sha = canonical_sha256(session_safe)
        before_root = canonical_sha256(before_docs)
        after_root = canonical_sha256(after_docs)
        zero_survivors = survivors == 0 and not failure_codes
        base = ProcessTreeContainmentReceipt(
            incident_id=incident_id,
            session_count=len(bindings),
            active_before_count=active_before,
            terminated_count=terminated,
            already_absent_count=already_absent,
            survivor_count=survivors,
            session_set_sha256=session_set_sha,
            before_root_sha256=before_root,
            after_root_sha256=after_root,
            failure_codes=tuple(sorted(failure_codes)),
            zero_survivors=zero_survivors,
            receipt_sha256="",
        )
        receipt = ProcessTreeContainmentReceipt(
            **{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())}
        )
        self._receipts.append(receipt)
        return receipt.as_document()

    def _inspect(self, session_id: str) -> ProcessTreeObservation:
        return ProcessTreeObservation.from_mapping(session_id, dict(self.inspect_session(session_id)))

    def _get(self, session_id: str) -> SessionBinding:
        _validate_id(session_id, "session_id")
        item = self._sessions.get(session_id)
        if item is None:
            raise ProcessTreeError("unknown execution session")
        return item

    def _set_status(self, session_id: str, status: str) -> None:
        if status not in {"ACTIVE", "FROZEN", "TERMINATED", "COMPLETED", "ERROR"}:
            raise ProcessTreeError("invalid session status")
        current = self._sessions[session_id]
        if current.status in {"TERMINATED", "COMPLETED"} and status not in {current.status}:
            raise ProcessTreeError("terminal execution session cannot be resurrected")
        self._sessions[session_id] = SessionBinding(
            current.session_id,
            current.operation_id,
            current.plan_sha256,
            current.backend_identity_sha256,
            status,
        )


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != SCHEMA or raw.get("authority") != AUTHORITY:
        raise ProcessTreeError("process-tree receipt schema or authority mismatch")
    if digest != canonical_sha256(raw):
        raise ProcessTreeError("process-tree receipt digest mismatch")
    if raw.get("zero_survivors") and (raw.get("survivor_count") != 0 or raw.get("failure_codes")):
        raise ProcessTreeError("zero-survivor claim contradicts receipt evidence")
    return dict(document)


def _validate_id(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 256:
        raise ProcessTreeError(f"{name} must be a bounded non-empty string")


def _require_sha(value: Any, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ProcessTreeError(f"{name} must be lowercase SHA-256")


__all__ = [
    "AUTHORITY",
    "ProcessTreeContainmentReceipt",
    "ProcessTreeError",
    "ProcessTreeObservation",
    "ProcessTreeSupervisor",
    "SCHEMA",
    "SessionBinding",
    "ZERO_SHA256",
    "verify_receipt",
]
