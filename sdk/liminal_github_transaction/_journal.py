"""Hash-chained checkpoint journal for GitHub transactions v0.8."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ._contracts import (
    AUTHORITY,
    JOURNAL_SCHEMA,
    ZERO_HASH,
    TransactionError,
    TransactionPlan,
    array,
    boolean,
    canonical_sha256,
    exact_keys,
    identifier,
    mapping,
    scalar,
    sha256,
    string,
)

EVENT_KEYS = {
    "transaction_created": {
        "type", "sequence", "transaction_id", "plan_sha256",
        "runtime_config_sha256", "repository_full_name",
    },
    "step_started": {
        "type", "sequence", "step_id", "call_id", "action",
        "request_sha256", "resolved_arguments_sha256",
    },
    "step_finished": {
        "type", "sequence", "step_id", "call_id", "action",
        "request_sha256", "runtime_status", "locator",
        "connected_receipt_sha256", "raw_response_sha256",
        "normalized_payload_sha256", "exports", "expectations_met",
        "reconciled", "recorder_event_id", "recorder_head_sha256",
        "host_trace_head_sha256",
    },
    "transaction_halted": {
        "type", "sequence", "step_id", "reason", "detail_sha256",
    },
    "transaction_completed": {
        "type", "sequence", "completed_step_ids", "final_checkpoint_sha256",
    },
    "transaction_aborted": {"type", "sequence", "reason_sha256"},
}


def _optional_sha(value: Any, name: str) -> str | None:
    return None if value is None else sha256(value, name)


def _optional_string(value: Any, name: str) -> str | None:
    return None if value is None else string(value, name)


def _validate_event(value: Any, expected_sequence: int) -> dict[str, Any]:
    raw = mapping(value, f"journal.entries[{expected_sequence - 1}].event")
    event_type = string(raw.get("type"), "event.type")
    expected = EVENT_KEYS.get(event_type)
    if expected is None:
        raise TransactionError(f"unsupported transaction event type: {event_type}")
    exact_keys(raw, expected, set(), f"event[{event_type}]")
    if raw["sequence"] != expected_sequence:
        raise TransactionError(
            f"event[{event_type}].sequence must be {expected_sequence}"
        )
    normalized = dict(raw)
    normalized["type"] = event_type
    normalized["sequence"] = expected_sequence

    if event_type == "transaction_created":
        normalized["transaction_id"] = identifier(raw["transaction_id"], "event.transaction_id")
        normalized["plan_sha256"] = sha256(raw["plan_sha256"], "event.plan_sha256")
        normalized["runtime_config_sha256"] = sha256(
            raw["runtime_config_sha256"], "event.runtime_config_sha256"
        )
        normalized["repository_full_name"] = string(
            raw["repository_full_name"], "event.repository_full_name"
        )
    elif event_type == "step_started":
        normalized["step_id"] = identifier(raw["step_id"], "event.step_id")
        normalized["call_id"] = identifier(raw["call_id"], "event.call_id")
        normalized["action"] = string(raw["action"], "event.action")
        normalized["request_sha256"] = sha256(raw["request_sha256"], "event.request_sha256")
        normalized["resolved_arguments_sha256"] = sha256(
            raw["resolved_arguments_sha256"], "event.resolved_arguments_sha256"
        )
    elif event_type == "step_finished":
        normalized["step_id"] = identifier(raw["step_id"], "event.step_id")
        normalized["call_id"] = identifier(raw["call_id"], "event.call_id")
        normalized["action"] = string(raw["action"], "event.action")
        normalized["request_sha256"] = sha256(raw["request_sha256"], "event.request_sha256")
        status = string(raw["runtime_status"], "event.runtime_status")
        if status not in {"success", "failure", "cancelled"}:
            raise TransactionError("event.runtime_status must be success, failure, or cancelled")
        normalized["runtime_status"] = status
        normalized["locator"] = _optional_string(raw["locator"], "event.locator")
        for key in (
            "connected_receipt_sha256", "raw_response_sha256",
            "normalized_payload_sha256", "recorder_head_sha256",
            "host_trace_head_sha256",
        ):
            normalized[key] = _optional_sha(raw[key], f"event.{key}")
        normalized["recorder_event_id"] = _optional_string(
            raw["recorder_event_id"], "event.recorder_event_id"
        )
        exports_raw = mapping(raw["exports"], "event.exports")
        exports: dict[str, Any] = {}
        for key, item in exports_raw.items():
            export_name = identifier(key, "event.exports.key")
            exports[export_name] = scalar(item, f"event.exports.{export_name}")
        normalized["exports"] = exports
        normalized["expectations_met"] = boolean(raw["expectations_met"], "event.expectations_met")
        normalized["reconciled"] = boolean(raw["reconciled"], "event.reconciled")
    elif event_type == "transaction_halted":
        normalized["step_id"] = identifier(raw["step_id"], "event.step_id")
        normalized["reason"] = string(raw["reason"], "event.reason")
        normalized["detail_sha256"] = sha256(raw["detail_sha256"], "event.detail_sha256")
    elif event_type == "transaction_completed":
        step_ids = [
            identifier(item, f"event.completed_step_ids[{index}]")
            for index, item in enumerate(array(raw["completed_step_ids"], "event.completed_step_ids"))
        ]
        if len(step_ids) != len(set(step_ids)):
            raise TransactionError("event.completed_step_ids contains duplicates")
        normalized["completed_step_ids"] = step_ids
        normalized["final_checkpoint_sha256"] = sha256(
            raw["final_checkpoint_sha256"], "event.final_checkpoint_sha256"
        )
    elif event_type == "transaction_aborted":
        normalized["reason_sha256"] = sha256(raw["reason_sha256"], "event.reason_sha256")
    return normalized


def _entry_hash(previous_hash: str, event: dict[str, Any]) -> str:
    return canonical_sha256({"previous_entry_sha256": previous_hash, "event": event})


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


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
        _fsync_directory(path.parent)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise TransactionError(f"transaction journal lock already exists: {lock_path}") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        yield
    finally:
        lock_path.unlink(missing_ok=True)


def validate_journal(value: Any) -> dict[str, Any]:
    raw = mapping(value, "transaction_journal")
    exact_keys(
        raw,
        {"schema_version", "transaction_id", "plan_sha256",
         "runtime_config_sha256", "entries", "head_sha256", "authority"},
        set(), "transaction_journal",
    )
    if raw["schema_version"] != JOURNAL_SCHEMA:
        raise TransactionError(f"transaction_journal.schema_version must be {JOURNAL_SCHEMA}")
    if raw["authority"] != AUTHORITY:
        raise TransactionError("transaction_journal.authority must remain fixed")
    transaction_id = identifier(raw["transaction_id"], "journal.transaction_id")
    plan_hash = sha256(raw["plan_sha256"], "journal.plan_sha256")
    runtime_hash = sha256(raw["runtime_config_sha256"], "journal.runtime_config_sha256")
    previous = ZERO_HASH
    entries: list[dict[str, Any]] = []
    started: dict[str, dict[str, Any]] = {}
    finished: dict[str, dict[str, Any]] = {}
    terminal_seen = False
    for index, entry_value in enumerate(array(raw["entries"], "journal.entries")):
        entry = mapping(entry_value, f"journal.entries[{index}]")
        exact_keys(entry, {"previous_entry_sha256", "event", "entry_sha256"}, set(), f"journal.entries[{index}]")
        if terminal_seen:
            raise TransactionError("journal contains entries after terminal event")
        previous_field = sha256(entry["previous_entry_sha256"], f"journal.entries[{index}].previous_entry_sha256")
        if previous_field != previous:
            raise TransactionError(f"journal.entries[{index}] previous hash mismatch")
        event = _validate_event(entry["event"], index + 1)
        digest = sha256(entry["entry_sha256"], f"journal.entries[{index}].entry_sha256")
        if digest != _entry_hash(previous, event):
            raise TransactionError(f"journal.entries[{index}] hash mismatch")
        event_type = event["type"]
        if index == 0 and event_type != "transaction_created":
            raise TransactionError("journal must start with transaction_created")
        if event_type == "transaction_created":
            if index != 0:
                raise TransactionError("transaction_created may appear only once")
            if (event["transaction_id"] != transaction_id or event["plan_sha256"] != plan_hash
                    or event["runtime_config_sha256"] != runtime_hash):
                raise TransactionError("transaction_created does not match journal header")
        elif event_type == "step_started":
            step_id = event["step_id"]
            if step_id in started:
                raise TransactionError(f"step started more than once: {step_id}")
            started[step_id] = event
        elif event_type == "step_finished":
            step_id = event["step_id"]
            start = started.get(step_id)
            if start is None:
                raise TransactionError(f"step finished before start: {step_id}")
            if step_id in finished:
                raise TransactionError(f"step finished more than once: {step_id}")
            for key in ("call_id", "action", "request_sha256"):
                if event[key] != start[key]:
                    raise TransactionError(f"step finish {key} mismatch for {step_id}")
            finished[step_id] = event
        elif event_type == "transaction_halted":
            if event["step_id"] not in started:
                raise TransactionError("transaction_halted references a step that never started")
        elif event_type in {"transaction_completed", "transaction_aborted"}:
            if set(started) - set(finished):
                raise TransactionError("terminal transaction event cannot follow a pending step")
            terminal_seen = True
        entries.append({"previous_entry_sha256": previous, "event": event, "entry_sha256": digest})
        previous = digest
    head = sha256(raw["head_sha256"], "journal.head_sha256")
    if head != previous:
        raise TransactionError("transaction_journal.head_sha256 mismatch")
    return {
        "schema_version": JOURNAL_SCHEMA,
        "transaction_id": transaction_id,
        "plan_sha256": plan_hash,
        "runtime_config_sha256": runtime_hash,
        "entries": entries,
        "head_sha256": head,
        "authority": AUTHORITY,
    }


class TransactionJournal:
    """Atomic append-only SHA-256 journal."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    @classmethod
    def create(cls, path: str | Path, plan: TransactionPlan) -> "TransactionJournal":
        target = Path(path)
        with _exclusive_lock(target):
            if target.exists():
                raise TransactionError(f"transaction journal already exists: {target}")
            created = {
                "type": "transaction_created", "sequence": 1,
                "transaction_id": plan.transaction_id,
                "plan_sha256": plan.plan_sha256,
                "runtime_config_sha256": plan.runtime_config_sha256,
                "repository_full_name": plan.repository_full_name,
            }
            digest = _entry_hash(ZERO_HASH, created)
            document = {
                "schema_version": JOURNAL_SCHEMA,
                "transaction_id": plan.transaction_id,
                "plan_sha256": plan.plan_sha256,
                "runtime_config_sha256": plan.runtime_config_sha256,
                "entries": [{"previous_entry_sha256": ZERO_HASH, "event": created, "entry_sha256": digest}],
                "head_sha256": digest,
                "authority": AUTHORITY,
            }
            _atomic_write_json(target, document)
        return cls(target)

    def read(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise TransactionError(f"transaction journal does not exist: {self.path}") from exc
        except json.JSONDecodeError as exc:
            raise TransactionError(f"transaction journal is not valid JSON: {exc}") from exc
        return validate_journal(value)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            journal = self.read()
            if journal["entries"] and journal["entries"][-1]["event"]["type"] in {"transaction_completed", "transaction_aborted"}:
                raise TransactionError("cannot append after terminal transaction event")
            sequence = len(journal["entries"]) + 1
            candidate = _validate_event({**event, "sequence": sequence}, sequence)
            previous = journal["head_sha256"]
            digest = _entry_hash(previous, candidate)
            journal["entries"].append({"previous_entry_sha256": previous, "event": candidate, "entry_sha256": digest})
            journal["head_sha256"] = digest
            _atomic_write_json(self.path, journal)
            return candidate

    def summary(self) -> dict[str, Any]:
        journal = self.read()
        starts: dict[str, dict[str, Any]] = {}
        finishes: dict[str, dict[str, Any]] = {}
        halts: list[dict[str, Any]] = []
        completed_event = None
        aborted_event = None
        for entry in journal["entries"]:
            event = entry["event"]
            if event["type"] == "step_started":
                starts[event["step_id"]] = event
            elif event["type"] == "step_finished":
                finishes[event["step_id"]] = event
            elif event["type"] == "transaction_halted":
                halts.append(event)
            elif event["type"] == "transaction_completed":
                completed_event = event
            elif event["type"] == "transaction_aborted":
                aborted_event = event
        pending = sorted(set(starts) - set(finishes))
        successful = [
            step_id for step_id, event in finishes.items()
            if event["runtime_status"] == "success" and event["expectations_met"]
        ]
        failed = [
            step_id for step_id, event in finishes.items()
            if event["runtime_status"] != "success" or not event["expectations_met"]
        ]
        if aborted_event is not None:
            status = "aborted"
        elif completed_event is not None:
            status = "completed"
        elif pending:
            status = "reconciliation_required"
        elif halts:
            status = "halted"
        else:
            status = "ready"
        checkpoints = {
            step_id: dict(event["exports"])
            for step_id, event in finishes.items()
            if event["runtime_status"] == "success" and event["expectations_met"]
        }
        return {
            "schema_version": JOURNAL_SCHEMA,
            "transaction_id": journal["transaction_id"],
            "status": status,
            "successful_step_ids": successful,
            "failed_step_ids": failed,
            "pending_step_ids": pending,
            "checkpoints": checkpoints,
            "starts": starts,
            "finishes": finishes,
            "halts": halts,
            "head_sha256": journal["head_sha256"],
        }
