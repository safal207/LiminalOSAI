"""Deterministic Phase 4 containment coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import canonical_sha256

STATES = ("IDLE", "DETECT", "FREEZE", "REVOKE", "SEAL", "SNAPSHOT", "REVIEW", "RELEASED")
INCIDENT_SCHEMA = "liminal-containment-incident-receipt-v0.1"
AUTHORITY = {
    "mode": "reference_containment_coordinator",
    "freeze_via_host_callback": True,
    "revoke_live_capabilities": True,
    "close_egress_via_host_callback": True,
    "seal_trace": True,
    "bounded_snapshot": True,
    "human_release_required": True,
    "os_process_control": False,
    "credential_discovery": False,
    "shell_execution": False,
    "deployment": False,
    "merge": False,
    "automatic_release": False,
}


class ContainmentError(ValueError):
    pass


class ContainmentBlocked(ContainmentError):
    pass


@dataclass(frozen=True)
class IncidentReceipt:
    incident_id: str
    phase3_receipt_sha256: str
    final_state: str
    transition_root_sha256: str
    revoked_capability_ids: tuple[str, ...]
    sealed_trace_sha256: str
    snapshot_sha256: str
    partial_failures: tuple[str, ...]
    human_release_id: str | None
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": INCIDENT_SCHEMA,
            "incident_id": self.incident_id,
            "phase3_receipt_sha256": self.phase3_receipt_sha256,
            "final_state": self.final_state,
            "transition_root_sha256": self.transition_root_sha256,
            "revoked_capability_ids": list(self.revoked_capability_ids),
            "sealed_trace_sha256": self.sealed_trace_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "partial_failures": list(self.partial_failures),
            "human_release_id": self.human_release_id,
            "authority": AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class ContainmentCoordinator:
    def __init__(
        self,
        *,
        broker: CapabilityBroker,
        freeze_runtime: Callable[[], None],
        close_egress: Callable[[], None],
        seal_trace: Callable[[], str],
        snapshot_forensics: Callable[[], Mapping[str, Any]],
    ) -> None:
        self.broker = broker
        self.freeze_runtime = freeze_runtime
        self.close_egress = close_egress
        self.seal_trace = seal_trace
        self.snapshot_forensics = snapshot_forensics
        self.state = "IDLE"
        self._transitions: list[dict[str, Any]] = []
        self._incident: IncidentReceipt | None = None

    def contain(self, phase3_receipt: Mapping[str, Any], *, incident_id: str, at_unix: int) -> dict[str, Any]:
        if self.state != "IDLE":
            raise ContainmentBlocked("containment already started")
        phase3_sha = _validated_phase3_receipt(phase3_receipt)
        failures: list[str] = []
        revoked: list[str] = []
        sealed = "0" * 64
        snapshot_sha = "0" * 64

        self._step("DETECT", at_unix, phase3_sha)
        try:
            self.freeze_runtime()
            self.close_egress()
        except Exception as exc:
            failures.append(f"freeze_or_egress:{type(exc).__name__}")
        self._step("FREEZE", at_unix, canonical_sha256({"failures": failures}))

        for cap in self.broker.state_document().get("capabilities", []):
            if cap.get("status") == "active":
                cap_id = cap["capability_id"]
                try:
                    decision = self.broker.revoke(cap_id, at_unix=at_unix)
                    if decision.get("decision") == "ALLOW":
                        revoked.append(cap_id)
                    else:
                        failures.append(f"revoke_blocked:{cap_id}")
                except Exception as exc:
                    failures.append(f"revoke:{cap_id}:{type(exc).__name__}")
        self._step("REVOKE", at_unix, canonical_sha256(sorted(revoked)))

        try:
            sealed = self.seal_trace()
            _require_sha(sealed, "sealed trace")
        except Exception as exc:
            failures.append(f"seal:{type(exc).__name__}")
            sealed = "0" * 64
        self._step("SEAL", at_unix, sealed)

        try:
            snapshot = dict(self.snapshot_forensics())
            _validate_snapshot(snapshot)
            snapshot_sha = canonical_sha256(snapshot)
        except Exception as exc:
            failures.append(f"snapshot:{type(exc).__name__}")
            snapshot_sha = "0" * 64
        self._step("SNAPSHOT", at_unix, snapshot_sha)
        self._step("REVIEW", at_unix, canonical_sha256(failures))

        body = IncidentReceipt(
            incident_id=incident_id,
            phase3_receipt_sha256=phase3_sha,
            final_state=self.state,
            transition_root_sha256=canonical_sha256(self._transitions),
            revoked_capability_ids=tuple(sorted(revoked)),
            sealed_trace_sha256=sealed,
            snapshot_sha256=snapshot_sha,
            partial_failures=tuple(sorted(failures)),
            human_release_id=None,
            receipt_sha256="",
        )
        self._incident = IncidentReceipt(**{**body.__dict__, "receipt_sha256": canonical_sha256(body.body())})
        return self._incident.as_document()

    def release(self, *, human_release_id: str, approved: bool, at_unix: int) -> dict[str, Any]:
        if self.state != "REVIEW" or self._incident is None:
            raise ContainmentBlocked("release requires REVIEW state")
        if not approved or not isinstance(human_release_id, str) or not human_release_id.strip():
            raise ContainmentBlocked("explicit human release approval is required")
        if self._incident.partial_failures:
            raise ContainmentBlocked("cannot release while containment has unresolved partial failures")
        self._step("RELEASED", at_unix, canonical_sha256({"human_release_id": human_release_id}))
        body = IncidentReceipt(**{**self._incident.__dict__, "final_state": "RELEASED", "human_release_id": human_release_id, "transition_root_sha256": canonical_sha256(self._transitions), "receipt_sha256": ""})
        self._incident = IncidentReceipt(**{**body.__dict__, "receipt_sha256": canonical_sha256(body.body())})
        return self._incident.as_document()

    def replay(self) -> dict[str, Any]:
        if not self._incident:
            raise ContainmentBlocked("no incident")
        return {
            "state": self.state,
            "transition_root_sha256": canonical_sha256(self._transitions),
            "incident_receipt_sha256": self._incident.receipt_sha256,
        }

    def _step(self, target: str, at_unix: int, evidence_sha256: str) -> None:
        expected = STATES[STATES.index(self.state) + 1]
        if target != expected:
            raise ContainmentBlocked(f"invalid containment transition {self.state}->{target}")
        _require_sha(evidence_sha256, "transition evidence")
        previous = self._transitions[-1]["transition_sha256"] if self._transitions else "0" * 64
        body = {"from": self.state, "to": target, "at_unix": at_unix, "evidence_sha256": evidence_sha256, "previous_transition_sha256": previous}
        transition = {**body, "transition_sha256": canonical_sha256(body)}
        self._transitions.append(transition)
        self.state = target


def _validated_phase3_receipt(value: Mapping[str, Any]) -> str:
    if value.get("decision") != "CONTAIN":
        raise ContainmentBlocked("Phase 4 requires decision=CONTAIN")
    sha = value.get("receipt_sha256")
    _require_sha(sha, "phase3 receipt")
    return sha


def _require_sha(value: Any, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ContainmentError(f"{name} must be lowercase SHA-256")


def _validate_snapshot(value: Mapping[str, Any]) -> None:
    allowed = {"trace_head_sha256", "broker_head_sha256", "event_count", "capability_count", "reason_codes"}
    if set(value) - allowed:
        raise ContainmentError("snapshot contains unsupported/raw fields")
    for key in ("trace_head_sha256", "broker_head_sha256"):
        if key in value:
            _require_sha(value[key], key)
