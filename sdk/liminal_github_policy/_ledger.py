"""Hash-chained explicit approval ledger for v0.9 policy snapshots."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ._contracts import (
    APPROVAL_LEDGER_SCHEMA,
    AUTHORITY,
    PolicyError,
    PolicySnapshot,
    canonical_sha256,
    exact_keys,
    identifier,
    mapping,
    string,
)

ZERO_HASH = "0" * 64
DECISIONS = ("approve", "deny")


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"approval ledger does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"approval ledger is not valid JSON: {exc}") from exc


def _optional_locator(value: Any, name: str) -> str | None:
    if value is None:
        return None
    item = string(value, name)
    if len(item.encode("utf-8")) > 2048:
        raise PolicyError(f"{name} exceeds 2048 UTF-8 bytes")
    return item


class ApprovalLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @classmethod
    def create(cls, path: str | Path, snapshot: PolicySnapshot) -> "ApprovalLedger":
        target = Path(path)
        if target.exists():
            raise PolicyError(f"approval ledger already exists: {target}")
        document = {
            "schema_version": APPROVAL_LEDGER_SCHEMA,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "plan_sha256": snapshot.plan_sha256,
            "policy_sha256": snapshot.policy_sha256,
            "entries": [],
            "head_sha256": ZERO_HASH,
            "authority": AUTHORITY,
        }
        _atomic_write_json(target, document)
        return cls(target)

    @staticmethod
    def _validate_event(
        event: Any,
        *,
        index: int,
        snapshot: PolicySnapshot,
        approval_ids: set[str],
        principal_requirements: set[tuple[str, str]],
    ) -> dict[str, Any]:
        raw = mapping(event, f"approval_event[{index}]")
        exact_keys(
            raw,
            {
                "type", "approval_id", "principal_id", "role", "decision",
                "requirement_id", "snapshot_sha256", "evidence_locator",
            },
            set(),
            f"approval_event[{index}]",
        )
        if raw["type"] != "approval_attestation":
            raise PolicyError("approval event type must be approval_attestation")
        approval_id = identifier(raw["approval_id"], f"approval_event[{index}].approval_id")
        if approval_id in approval_ids:
            raise PolicyError(f"duplicate approval_id: {approval_id}")
        principal_id = identifier(raw["principal_id"], f"approval_event[{index}].principal_id")
        role = identifier(raw["role"], f"approval_event[{index}].role")
        decision = string(raw["decision"], f"approval_event[{index}].decision")
        if decision not in DECISIONS:
            raise PolicyError(f"approval_event[{index}].decision must be approve or deny")
        requirement_id = identifier(raw["requirement_id"], f"approval_event[{index}].requirement_id")
        requirement = snapshot.requirement_map.get(requirement_id)
        if requirement is None:
            raise PolicyError(f"unknown approval requirement: {requirement_id}")
        if role not in requirement.required_role_counts:
            raise PolicyError(f"role {role} is not permitted for requirement {requirement_id}")
        if raw["snapshot_sha256"] != snapshot.snapshot_sha256:
            raise PolicyError("approval event targets a stale policy snapshot")
        principal_key = (requirement_id, principal_id)
        if principal_key in principal_requirements:
            raise PolicyError(f"principal {principal_id} already attested requirement {requirement_id}")
        return {
            "type": "approval_attestation",
            "approval_id": approval_id,
            "principal_id": principal_id,
            "role": role,
            "decision": decision,
            "requirement_id": requirement_id,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "evidence_locator": _optional_locator(raw["evidence_locator"], f"approval_event[{index}].evidence_locator"),
        }

    def read(self, snapshot: PolicySnapshot) -> dict[str, Any]:
        raw = mapping(_read_json(self.path), "approval_ledger")
        exact_keys(
            raw,
            {
                "schema_version", "snapshot_sha256", "plan_sha256", "policy_sha256",
                "entries", "head_sha256", "authority",
            },
            set(),
            "approval_ledger",
        )
        if raw["schema_version"] != APPROVAL_LEDGER_SCHEMA:
            raise PolicyError(f"approval_ledger.schema_version must be {APPROVAL_LEDGER_SCHEMA}")
        if raw["authority"] != AUTHORITY:
            raise PolicyError("approval_ledger.authority must remain fixed")
        if raw["snapshot_sha256"] != snapshot.snapshot_sha256:
            raise PolicyError("approval_ledger.snapshot_sha256 mismatch")
        if raw["plan_sha256"] != snapshot.plan_sha256:
            raise PolicyError("approval_ledger.plan_sha256 mismatch")
        if raw["policy_sha256"] != snapshot.policy_sha256:
            raise PolicyError("approval_ledger.policy_sha256 mismatch")
        entries_raw = raw["entries"]
        if not isinstance(entries_raw, list):
            raise PolicyError("approval_ledger.entries must be an array")
        previous = ZERO_HASH
        approval_ids: set[str] = set()
        principal_requirements: set[tuple[str, str]] = set()
        normalized_entries: list[dict[str, Any]] = []
        for index, entry_value in enumerate(entries_raw):
            entry = mapping(entry_value, f"approval_ledger.entries[{index}]")
            exact_keys(entry, {"index", "previous_sha256", "event", "entry_sha256"}, set(), f"approval_ledger.entries[{index}]")
            if entry["index"] != index:
                raise PolicyError(f"approval ledger index mismatch at {index}")
            if entry["previous_sha256"] != previous:
                raise PolicyError(f"approval ledger previous hash mismatch at {index}")
            event = self._validate_event(
                entry["event"], index=index, snapshot=snapshot,
                approval_ids=approval_ids, principal_requirements=principal_requirements,
            )
            payload = {"index": index, "previous_sha256": previous, "event": event}
            expected = canonical_sha256(payload)
            if entry["entry_sha256"] != expected:
                raise PolicyError(f"approval ledger entry hash mismatch at {index}")
            approval_ids.add(event["approval_id"])
            principal_requirements.add((event["requirement_id"], event["principal_id"]))
            previous = expected
            normalized_entries.append({**payload, "entry_sha256": expected})
        if raw["head_sha256"] != previous:
            raise PolicyError("approval_ledger.head_sha256 mismatch")
        return {
            "schema_version": APPROVAL_LEDGER_SCHEMA,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "plan_sha256": snapshot.plan_sha256,
            "policy_sha256": snapshot.policy_sha256,
            "entries": normalized_entries,
            "head_sha256": previous,
            "authority": AUTHORITY,
        }

    def append(
        self,
        snapshot: PolicySnapshot,
        *,
        approval_id: str,
        principal_id: str,
        role: str,
        decision: str,
        requirement_id: str,
        evidence_locator: str | None = None,
    ) -> dict[str, Any]:
        document = self.read(snapshot)
        event = {
            "type": "approval_attestation",
            "approval_id": approval_id,
            "principal_id": principal_id,
            "role": role,
            "decision": decision,
            "requirement_id": requirement_id,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "evidence_locator": evidence_locator,
        }
        prior_ids = {entry["event"]["approval_id"] for entry in document["entries"]}
        prior_principals = {
            (entry["event"]["requirement_id"], entry["event"]["principal_id"])
            for entry in document["entries"]
        }
        normalized = self._validate_event(
            event, index=len(document["entries"]), snapshot=snapshot,
            approval_ids=prior_ids, principal_requirements=prior_principals,
        )
        payload = {
            "index": len(document["entries"]),
            "previous_sha256": document["head_sha256"],
            "event": normalized,
        }
        entry = {**payload, "entry_sha256": canonical_sha256(payload)}
        document["entries"].append(entry)
        document["head_sha256"] = entry["entry_sha256"]
        _atomic_write_json(self.path, document)
        return entry

    def summary(self, snapshot: PolicySnapshot) -> dict[str, Any]:
        document = self.read(snapshot)
        events = [entry["event"] for entry in document["entries"]]
        denied = [event for event in events if event["decision"] == "deny"]
        satisfied: list[str] = []
        pending: list[str] = []
        requirement_status: dict[str, Any] = {}
        for requirement in snapshot.requirements:
            approvals = [
                event for event in events
                if event["requirement_id"] == requirement.requirement_id
                and event["decision"] == "approve"
            ]
            role_actual = {
                role: sum(1 for event in approvals if event["role"] == role)
                for role in requirement.required_role_counts
            }
            distinct = len({event["principal_id"] for event in approvals})
            role_ok = all(role_actual[role] >= needed for role, needed in requirement.required_role_counts.items())
            total_needed = sum(requirement.required_role_counts.values())
            distinct_ok = not requirement.require_distinct_principals or distinct >= total_needed
            ok = role_ok and distinct_ok
            (satisfied if ok else pending).append(requirement.requirement_id)
            requirement_status[requirement.requirement_id] = {
                "required_role_counts": dict(requirement.required_role_counts),
                "actual_role_counts": role_actual,
                "distinct_principals": distinct,
                "satisfied": ok,
            }
        if snapshot.decision == "deny" or denied:
            status = "denied"
        elif not pending:
            status = "ready"
        else:
            status = "pending"
        return {
            "schema_version": APPROVAL_LEDGER_SCHEMA,
            "status": status,
            "snapshot_decision": snapshot.decision,
            "entry_count": len(events),
            "satisfied_requirement_ids": satisfied,
            "pending_requirement_ids": pending,
            "denial_approval_ids": [event["approval_id"] for event in denied],
            "requirements": requirement_status,
            "head_sha256": document["head_sha256"],
            "authority": AUTHORITY,
        }
