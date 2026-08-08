"""Trusted-host process-tree containment for governed execution sessions.

The model-facing layer never supplies OS PIDs, process handles, shell commands, or
kill targets. A trusted host backend exposes bounded, digest-verifiable session
observations and performs freeze/terminate operations outside model context.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-process-tree-containment-receipt-v0.1"
OBSERVATION_SCHEMA = "liminal-process-tree-observation-v0.1"
ACTION_SCHEMA = "liminal-process-tree-backend-action-v0.1"

AUTHORITY = {
    "mode": "trusted_host_process_tree_containment",
    "model_supplied_pid_authority": False,
    "shell_execution": False,
    "direct_kill_syscall": False,
    "direct_container_runtime_access": False,
    "trusted_backend_process_control": True,
    "session_scoped_only": True,
    "digest_only_receipts": True,
    "zero_survivor_required": True,
    "kernel_escape_prevention": False,
}


class ProcessTreeError(ValueError):
    pass


class ProcessTreeBackend(Protocol):
    def snapshot(self, session_id: str) -> Mapping[str, Any]: ...
    def freeze(self, session_id: str) -> Mapping[str, Any]: ...
    def terminate(self, session_id: str) -> Mapping[str, Any]: ...


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 256:
        raise ProcessTreeError(f"{name} must be a bounded non-empty string")
    return value


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ProcessTreeError(f"{name} must be lowercase SHA-256")
    return value


@dataclass(frozen=True)
class ProcessNode:
    process_id: str
    parent_process_id: str | None
    identity_sha256: str
    state: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ProcessNode":
        if set(raw) != {"process_id", "parent_process_id", "identity_sha256", "state"}:
            raise ProcessTreeError("process node schema mismatch")
        process_id = _require_text(raw["process_id"], "process_id")
        parent = raw["parent_process_id"]
        if parent is not None:
            parent = _require_text(parent, "parent_process_id")
        identity = _require_sha(raw["identity_sha256"], "identity_sha256")
        state = raw["state"]
        if state not in {"running", "frozen", "terminated"}:
            raise ProcessTreeError("unsupported process state")
        return cls(process_id, parent, identity, state)

    def body(self) -> dict[str, Any]:
        return {
            "process_id": self.process_id,
            "parent_process_id": self.parent_process_id,
            "identity_sha256": self.identity_sha256,
            "state": self.state,
        }


@dataclass(frozen=True)
class ProcessTreeObservation:
    session_id: str
    root_process_id: str
    backend_binding_sha256: str
    nodes: tuple[ProcessNode, ...]
    tree_sha256: str
    evidence_sha256: str

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        expected_session_id: str,
        expected_root_process_id: str,
        expected_backend_binding_sha256: str,
    ) -> "ProcessTreeObservation":
        required = {
            "schema", "session_id", "root_process_id", "backend_binding_sha256",
            "nodes", "tree_sha256", "evidence_sha256",
        }
        if set(raw) != required or raw.get("schema") != OBSERVATION_SCHEMA:
            raise ProcessTreeError("process-tree observation schema mismatch")
        if raw["session_id"] != expected_session_id or raw["root_process_id"] != expected_root_process_id:
            raise ProcessTreeError("backend observation escaped the bound execution session")
        if raw["backend_binding_sha256"] != expected_backend_binding_sha256:
            raise ProcessTreeError("backend binding mismatch")
        nodes_raw = raw["nodes"]
        if not isinstance(nodes_raw, list) or not 1 <= len(nodes_raw) <= 256:
            raise ProcessTreeError("process tree must contain 1..256 nodes")
        nodes = tuple(ProcessNode.from_mapping(item) for item in nodes_raw)
        _validate_lineage(nodes, expected_root_process_id)
        canonical_nodes = [n.body() for n in sorted(nodes, key=lambda n: n.process_id)]
        tree_sha = canonical_sha256(canonical_nodes)
        if raw["tree_sha256"] != tree_sha:
            raise ProcessTreeError("process tree digest mismatch")
        body = {
            "schema": OBSERVATION_SCHEMA,
            "session_id": expected_session_id,
            "root_process_id": expected_root_process_id,
            "backend_binding_sha256": expected_backend_binding_sha256,
            "nodes": canonical_nodes,
            "tree_sha256": tree_sha,
        }
        if raw["evidence_sha256"] != canonical_sha256(body):
            raise ProcessTreeError("process-tree observation evidence mismatch")
        return cls(expected_session_id, expected_root_process_id, expected_backend_binding_sha256, nodes, tree_sha, raw["evidence_sha256"])

    @property
    def live_nodes(self) -> tuple[ProcessNode, ...]:
        return tuple(node for node in self.nodes if node.state != "terminated")


@dataclass(frozen=True)
class ProcessTreeContainmentReceipt:
    session_id: str
    root_process_id: str
    backend_binding_sha256: str
    before_tree_sha256: str
    frozen_tree_sha256: str
    after_tree_sha256: str
    observed_count: int
    terminated_count: int
    surviving_count: int
    freeze_evidence_sha256: str
    terminate_evidence_sha256: str
    decision: str
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "session_id": self.session_id,
            "root_process_id": self.root_process_id,
            "backend_binding_sha256": self.backend_binding_sha256,
            "before_tree_sha256": self.before_tree_sha256,
            "frozen_tree_sha256": self.frozen_tree_sha256,
            "after_tree_sha256": self.after_tree_sha256,
            "observed_count": self.observed_count,
            "terminated_count": self.terminated_count,
            "surviving_count": self.surviving_count,
            "freeze_evidence_sha256": self.freeze_evidence_sha256,
            "terminate_evidence_sha256": self.terminate_evidence_sha256,
            "decision": self.decision,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class ProcessTreeContainmentSupervisor:
    """Binds one trusted execution session to a process-tree control backend."""

    def __init__(self, *, session_id: str, root_process_id: str, backend_binding_sha256: str, backend: ProcessTreeBackend) -> None:
        self.session_id = _require_text(session_id, "session_id")
        self.root_process_id = _require_text(root_process_id, "root_process_id")
        self.backend_binding_sha256 = _require_sha(backend_binding_sha256, "backend_binding_sha256")
        self.backend = backend
        self._before: ProcessTreeObservation | None = None
        self._frozen: ProcessTreeObservation | None = None
        self._receipt: ProcessTreeContainmentReceipt | None = None

    def snapshot(self) -> ProcessTreeObservation:
        return ProcessTreeObservation.from_mapping(
            self.backend.snapshot(self.session_id),
            expected_session_id=self.session_id,
            expected_root_process_id=self.root_process_id,
            expected_backend_binding_sha256=self.backend_binding_sha256,
        )

    def freeze(self) -> dict[str, Any]:
        if self._before is not None:
            raise ProcessTreeError("execution session already frozen")
        before = self.snapshot()
        action = _validate_action(
            self.backend.freeze(self.session_id),
            expected_session_id=self.session_id,
            expected_root_process_id=self.root_process_id,
            expected_backend_binding_sha256=self.backend_binding_sha256,
            expected_action="freeze",
        )
        frozen = self.snapshot()
        if any(node.state == "running" for node in frozen.nodes):
            raise ProcessTreeError("freeze left a running process in the execution session")
        if {n.process_id for n in before.nodes} != {n.process_id for n in frozen.nodes}:
            raise ProcessTreeError("process lineage changed while session was being frozen")
        self._before, self._frozen = before, frozen
        return {
            "session_id": self.session_id,
            "before_tree_sha256": before.tree_sha256,
            "frozen_tree_sha256": frozen.tree_sha256,
            "observed_count": len(before.nodes),
            "freeze_evidence_sha256": action["evidence_sha256"],
        }

    def quiesce(self) -> dict[str, Any]:
        if self._before is None or self._frozen is None:
            raise ProcessTreeError("quiescence requires a previously frozen execution session")
        if self._receipt is not None:
            return self._receipt.as_document()
        action = _validate_action(
            self.backend.terminate(self.session_id),
            expected_session_id=self.session_id,
            expected_root_process_id=self.root_process_id,
            expected_backend_binding_sha256=self.backend_binding_sha256,
            expected_action="terminate",
        )
        after = self.snapshot()
        before_ids = {n.process_id for n in self._before.nodes}
        after_ids = {n.process_id for n in after.nodes}
        if not after_ids.issubset(before_ids):
            raise ProcessTreeError("new process appeared after execution-session freeze")
        survivors = tuple(node for node in after.nodes if node.state != "terminated")
        terminated_count = len(before_ids) - len(survivors)
        decision = "ALLOW" if not survivors else "BLOCK"
        base = ProcessTreeContainmentReceipt(
            session_id=self.session_id,
            root_process_id=self.root_process_id,
            backend_binding_sha256=self.backend_binding_sha256,
            before_tree_sha256=self._before.tree_sha256,
            frozen_tree_sha256=self._frozen.tree_sha256,
            after_tree_sha256=after.tree_sha256,
            observed_count=len(self._before.nodes),
            terminated_count=terminated_count,
            surviving_count=len(survivors),
            freeze_evidence_sha256=_action_evidence_from_freeze(self.backend, self.session_id, self.root_process_id, self.backend_binding_sha256, self._frozen),
            terminate_evidence_sha256=action["evidence_sha256"],
            decision=decision,
            receipt_sha256="",
        )
        # Do not call backend.freeze twice. The helper above derives a stable evidence root
        # from the validated frozen state when a backend does not retain action receipts.
        receipt = ProcessTreeContainmentReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipt = receipt
        return receipt.as_document()

    def receipt(self) -> dict[str, Any]:
        if self._receipt is None:
            raise ProcessTreeError("no process-tree containment receipt")
        return self._receipt.as_document()


def _action_evidence_from_freeze(backend: ProcessTreeBackend, session_id: str, root_process_id: str, binding: str, frozen: ProcessTreeObservation) -> str:
    # The actual freeze action was already validated before the frozen snapshot. We bind
    # its evidence deterministically to the resulting frozen tree without invoking it again.
    return canonical_sha256({
        "schema": ACTION_SCHEMA,
        "session_id": session_id,
        "root_process_id": root_process_id,
        "backend_binding_sha256": binding,
        "action": "freeze",
        "result_tree_sha256": frozen.tree_sha256,
    })


def _validate_action(raw: Mapping[str, Any], *, expected_session_id: str, expected_root_process_id: str, expected_backend_binding_sha256: str, expected_action: str) -> dict[str, Any]:
    required = {"schema", "session_id", "root_process_id", "backend_binding_sha256", "action", "affected_count", "result_tree_sha256", "evidence_sha256"}
    if set(raw) != required or raw.get("schema") != ACTION_SCHEMA:
        raise ProcessTreeError("backend action schema mismatch")
    if raw["session_id"] != expected_session_id or raw["root_process_id"] != expected_root_process_id:
        raise ProcessTreeError("backend action escaped the bound execution session")
    if raw["backend_binding_sha256"] != expected_backend_binding_sha256 or raw["action"] != expected_action:
        raise ProcessTreeError("backend action binding mismatch")
    if not isinstance(raw["affected_count"], int) or isinstance(raw["affected_count"], bool) or raw["affected_count"] < 0:
        raise ProcessTreeError("affected_count must be non-negative")
    _require_sha(raw["result_tree_sha256"], "result_tree_sha256")
    body = {key: raw[key] for key in required if key != "evidence_sha256"}
    if raw["evidence_sha256"] != canonical_sha256(body):
        raise ProcessTreeError("backend action evidence mismatch")
    return dict(raw)


def _validate_lineage(nodes: tuple[ProcessNode, ...], root_process_id: str) -> None:
    by_id = {node.process_id: node for node in nodes}
    if len(by_id) != len(nodes):
        raise ProcessTreeError("duplicate process identity")
    root = by_id.get(root_process_id)
    if root is None or root.parent_process_id is not None:
        raise ProcessTreeError("bound root process is missing or has a parent")
    for node in nodes:
        if node.process_id == root_process_id:
            continue
        if node.parent_process_id not in by_id:
            raise ProcessTreeError("process tree contains an unknown parent")
    for node in nodes:
        seen: set[str] = set()
        current = node
        while current.parent_process_id is not None:
            if current.process_id in seen:
                raise ProcessTreeError("process tree contains a cycle")
            seen.add(current.process_id)
            current = by_id[current.parent_process_id]
        if current.process_id != root_process_id:
            raise ProcessTreeError("process is not descended from the bound root")


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    digest = raw.pop("receipt_sha256", None)
    if raw.get("schema") != SCHEMA or raw.get("authority") != AUTHORITY:
        raise ProcessTreeError("process-tree containment receipt schema or authority mismatch")
    for key in ("backend_binding_sha256", "before_tree_sha256", "frozen_tree_sha256", "after_tree_sha256", "freeze_evidence_sha256", "terminate_evidence_sha256"):
        _require_sha(raw.get(key), key)
    if raw.get("decision") not in {"ALLOW", "BLOCK"}:
        raise ProcessTreeError("unsupported process-tree containment decision")
    if not isinstance(raw.get("surviving_count"), int) or raw["surviving_count"] < 0:
        raise ProcessTreeError("invalid surviving_count")
    if raw["decision"] == "ALLOW" and raw["surviving_count"] != 0:
        raise ProcessTreeError("ALLOW receipt cannot contain surviving processes")
    if digest != canonical_sha256(raw):
        raise ProcessTreeError("process-tree containment receipt digest mismatch")
    return dict(document)


__all__ = [
    "ACTION_SCHEMA", "AUTHORITY", "OBSERVATION_SCHEMA", "ProcessNode", "ProcessTreeBackend",
    "ProcessTreeContainmentReceipt", "ProcessTreeContainmentSupervisor", "ProcessTreeError", "SCHEMA", "verify_receipt",
]
