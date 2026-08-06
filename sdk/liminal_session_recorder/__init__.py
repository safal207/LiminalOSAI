"""Deterministic append-only recorder for ChatGPT live-session v0.3 events.

The recorder is a zero-dependency Python SDK. It writes only explicit, bounded
visible-session records. It does not capture hidden messages, infer claims,
infer authorization from prose, execute tools, verify sources, or approve
responses.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

JOURNAL_SCHEMA = "chatgpt-session-journal-v0.4"
LIVE_SESSION_SCHEMA = "chatgpt-live-session-v0.3"
ZERO_HASH = "0" * 64

EVENT_TYPES = {
    "user_message",
    "assistant_draft",
    "claim",
    "source",
    "tool_event",
    "user_authorization",
    "proposed_action",
    "contradiction",
}
CLAIM_KINDS = {"fact", "reasoning", "recommendation", "uncertainty"}
FRESHNESS_VALUES = {"current", "stable", "unknown"}
SOURCE_KINDS = {"official", "repository", "tool", "user_provided", "web", "other"}
TOOL_STATUSES = {"success", "failure", "cancelled"}
TOOL_EFFECTS = {"read", "write", "none"}

AUTHORITY = {
    "mode": "recording_only",
    "hidden_message_access": False,
    "chain_of_thought_access": False,
    "claim_inference": False,
    "authorization_inference": False,
    "source_truth_verification": False,
    "execution": False,
    "delivery": False,
    "external_submission": False,
    "deployment": False,
    "merge": False,
    "model_weight_update": False,
    "hidden_memory_write": False,
}


class RecorderError(ValueError):
    """Raised when a journal or event violates the v0.4 recorder contract."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecorderError(f"{name} must be a JSON object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise RecorderError(f"{name} must be a JSON array")
    return value


def _string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise RecorderError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise RecorderError(f"{name} must not be empty")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise RecorderError(f"{name} must be a boolean")
    return value


def _unit_interval(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RecorderError(f"{name} must be a finite number in [0, 1]")
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or number > 1.0:
        raise RecorderError(f"{name} must be a finite number in [0, 1]")
    return number


def _enum(value: Any, name: str, allowed: set[str]) -> str:
    item = _string(value, name)
    if item not in allowed:
        raise RecorderError(f"{name} must be one of {sorted(allowed)}")
    return item


def _string_list(value: Any, name: str) -> list[str]:
    result: list[str] = []
    for index, item in enumerate(_list(value, name)):
        result.append(_string(item, f"{name}[{index}]"))
    if len(result) != len(set(result)):
        raise RecorderError(f"{name} contains duplicates")
    return result


def _exact_keys(raw: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(raw)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        raise RecorderError(f"{name} missing keys: {', '.join(missing)}")
    if extra:
        raise RecorderError(f"{name} contains unsupported keys: {', '.join(extra)}")


def _validate_event_payload(payload: dict[str, Any], sequence: int) -> dict[str, Any]:
    """Validate one append payload and add its recorder-owned sequence number."""
    raw = _mapping(payload, "event")
    if "sequence" in raw:
        raise RecorderError("event.sequence is recorder-owned and must not be supplied")
    event_type = _enum(raw.get("type"), "event.type", EVENT_TYPES)

    common = {"id", "type"}
    expected_by_type = {
        "user_message": common | {"text"},
        "assistant_draft": common | {"response", "no_signal", "intent_alignment"},
        "claim": common
        | {
            "draft_event_id",
            "text",
            "kind",
            "confidence",
            "requires_current_information",
            "evidence_event_ids",
        },
        "source": common
        | {"handle", "verified", "freshness", "source_kind", "locator"},
        "tool_event": common
        | {
            "tool",
            "operation",
            "status",
            "effect",
            "evidence_eligible",
            "freshness",
            "locator",
            "reversible",
            "recovery_plan",
        },
        "user_authorization": common | {"text", "authorized_event_ids"},
        "proposed_action": common
        | {"draft_event_id", "description", "reversible", "recovery_plan"},
        "contradiction": common | {"draft_event_id", "text"},
    }
    _exact_keys(raw, expected_by_type[event_type], f"event[{event_type}]")

    event: dict[str, Any] = {
        "id": _string(raw.get("id"), "event.id"),
        "sequence": sequence,
        "type": event_type,
    }

    if event_type == "user_message":
        event["text"] = _string(raw.get("text"), "event.text")
    elif event_type == "assistant_draft":
        no_signal = _boolean(raw.get("no_signal"), "event.no_signal")
        response = _string(raw.get("response"), "event.response", allow_empty=True)
        if not no_signal and not response.strip():
            raise RecorderError("assistant_draft.response must not be empty unless no_signal is true")
        event.update(
            response=response,
            no_signal=no_signal,
            intent_alignment=_unit_interval(raw.get("intent_alignment"), "event.intent_alignment"),
        )
    elif event_type == "claim":
        event.update(
            draft_event_id=_string(raw.get("draft_event_id"), "event.draft_event_id"),
            text=_string(raw.get("text"), "event.text"),
            kind=_enum(raw.get("kind"), "event.kind", CLAIM_KINDS),
            confidence=_unit_interval(raw.get("confidence"), "event.confidence"),
            requires_current_information=_boolean(
                raw.get("requires_current_information"),
                "event.requires_current_information",
            ),
            evidence_event_ids=_string_list(
                raw.get("evidence_event_ids"), "event.evidence_event_ids"
            ),
        )
    elif event_type == "source":
        event.update(
            handle=_string(raw.get("handle"), "event.handle"),
            verified=_boolean(raw.get("verified"), "event.verified"),
            freshness=_enum(raw.get("freshness"), "event.freshness", FRESHNESS_VALUES),
            source_kind=_enum(raw.get("source_kind"), "event.source_kind", SOURCE_KINDS),
            locator=_string(raw.get("locator"), "event.locator"),
        )
    elif event_type == "tool_event":
        evidence_eligible = _boolean(raw.get("evidence_eligible"), "event.evidence_eligible")
        locator = _optional_string(raw.get("locator"), "event.locator")
        if evidence_eligible and locator is None:
            raise RecorderError("tool_event.locator is required when evidence_eligible is true")
        event.update(
            tool=_string(raw.get("tool"), "event.tool"),
            operation=_string(raw.get("operation"), "event.operation"),
            status=_enum(raw.get("status"), "event.status", TOOL_STATUSES),
            effect=_enum(raw.get("effect"), "event.effect", TOOL_EFFECTS),
            evidence_eligible=evidence_eligible,
            freshness=_enum(raw.get("freshness"), "event.freshness", FRESHNESS_VALUES),
            locator=locator,
            reversible=_boolean(raw.get("reversible"), "event.reversible"),
            recovery_plan=_optional_string(raw.get("recovery_plan"), "event.recovery_plan"),
        )
    elif event_type == "user_authorization":
        event.update(
            text=_string(raw.get("text"), "event.text"),
            authorized_event_ids=_string_list(
                raw.get("authorized_event_ids"), "event.authorized_event_ids"
            ),
        )
        if not event["authorized_event_ids"]:
            raise RecorderError("user_authorization.authorized_event_ids must not be empty")
    elif event_type == "proposed_action":
        event.update(
            draft_event_id=_string(raw.get("draft_event_id"), "event.draft_event_id"),
            description=_string(raw.get("description"), "event.description"),
            reversible=_boolean(raw.get("reversible"), "event.reversible"),
            recovery_plan=_optional_string(raw.get("recovery_plan"), "event.recovery_plan"),
        )
    elif event_type == "contradiction":
        event.update(
            draft_event_id=_string(raw.get("draft_event_id"), "event.draft_event_id"),
            text=_string(raw.get("text"), "event.text"),
        )
    return event


def _validate_final_graph(events: list[dict[str, Any]], request_id: str, draft_id: str) -> None:
    by_id = {event["id"]: event for event in events}
    if request_id not in by_id or by_id[request_id]["type"] != "user_message":
        raise RecorderError("request_event_id must reference a user_message event")
    if draft_id not in by_id or by_id[draft_id]["type"] != "assistant_draft":
        raise RecorderError("draft_event_id must reference an assistant_draft event")

    draft_ids = {event["id"] for event in events if event["type"] == "assistant_draft"}
    for event in events:
        if event["type"] in {"claim", "proposed_action", "contradiction"}:
            if event["draft_event_id"] not in draft_ids:
                raise RecorderError(
                    f"event {event['id']} references unknown assistant draft {event['draft_event_id']}"
                )

    source_handles: set[str] = set()
    tool_ids = {event["id"] for event in events if event["type"] == "tool_event"}
    for event in events:
        if event["type"] == "source":
            handle = event["handle"]
            if handle in source_handles:
                raise RecorderError(f"duplicate source handle: {handle}")
            source_handles.add(handle)
    overlap = sorted(source_handles & tool_ids)
    if overlap:
        raise RecorderError(
            "source handles and tool event ids must be globally unique: " + ", ".join(overlap)
        )

    for event in events:
        if event["type"] != "user_authorization":
            continue
        for target_id in event["authorized_event_ids"]:
            target = by_id.get(target_id)
            if target is None:
                raise RecorderError(
                    f"authorization {event['id']} targets unknown event {target_id}"
                )
            if target["type"] not in {"tool_event", "proposed_action"}:
                raise RecorderError(
                    f"authorization {event['id']} target {target_id} is not authorizable"
                )
            if event["sequence"] >= target["sequence"]:
                raise RecorderError(
                    f"authorization {event['id']} must occur before target {target_id}"
                )


def _entry_hash(previous_hash: str, event: dict[str, Any]) -> str:
    return _canonical_sha256(
        {"previous_entry_sha256": previous_hash, "event": event}
    )


def _seal_hash(session: dict[str, Any], head_hash: str) -> str:
    return _canonical_sha256({"session": session, "head_sha256": head_hash})


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
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


@contextmanager
def _journal_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RecorderError(f"journal lock already exists: {lock_path}") from exc
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _empty_journal(
    session_id: str, high_stakes: bool, requires_current_information: bool
) -> dict[str, Any]:
    session = {
        "id": _string(session_id, "session_id"),
        "high_stakes": _boolean(high_stakes, "high_stakes"),
        "requires_current_information": _boolean(
            requires_current_information, "requires_current_information"
        ),
        "request_event_id": None,
        "draft_event_id": None,
        "capture_complete": False,
        "sealed": False,
    }
    return {
        "schema_version": JOURNAL_SCHEMA,
        "recorder": {"implementation": "python", "version": "0.4"},
        "session": session,
        "entries": [],
        "head_sha256": ZERO_HASH,
        "seal_sha256": None,
        "authority": AUTHORITY,
    }


def validate_journal(raw_value: Any) -> dict[str, Any]:
    journal = _mapping(raw_value, "journal")
    _exact_keys(
        journal,
        {
            "schema_version",
            "recorder",
            "session",
            "entries",
            "head_sha256",
            "seal_sha256",
            "authority",
        },
        "journal",
    )
    if journal.get("schema_version") != JOURNAL_SCHEMA:
        raise RecorderError(f"schema_version must be {JOURNAL_SCHEMA!r}")
    recorder = _mapping(journal.get("recorder"), "journal.recorder")
    _exact_keys(recorder, {"implementation", "version"}, "journal.recorder")
    if recorder != {"implementation": "python", "version": "0.4"}:
        raise RecorderError("journal.recorder must identify the v0.4 Python SDK")

    session_raw = _mapping(journal.get("session"), "journal.session")
    _exact_keys(
        session_raw,
        {
            "id",
            "high_stakes",
            "requires_current_information",
            "request_event_id",
            "draft_event_id",
            "capture_complete",
            "sealed",
        },
        "journal.session",
    )
    session = {
        "id": _string(session_raw.get("id"), "journal.session.id"),
        "high_stakes": _boolean(
            session_raw.get("high_stakes"), "journal.session.high_stakes"
        ),
        "requires_current_information": _boolean(
            session_raw.get("requires_current_information"),
            "journal.session.requires_current_information",
        ),
        "request_event_id": _optional_string(
            session_raw.get("request_event_id"), "journal.session.request_event_id"
        ),
        "draft_event_id": _optional_string(
            session_raw.get("draft_event_id"), "journal.session.draft_event_id"
        ),
        "capture_complete": _boolean(
            session_raw.get("capture_complete"), "journal.session.capture_complete"
        ),
        "sealed": _boolean(session_raw.get("sealed"), "journal.session.sealed"),
    }
    if session["sealed"] != session["capture_complete"]:
        raise RecorderError("journal.session sealed and capture_complete must match")
    if session["sealed"] and (
        session["request_event_id"] is None or session["draft_event_id"] is None
    ):
        raise RecorderError("sealed journal requires request_event_id and draft_event_id")
    if not session["sealed"] and (
        session["request_event_id"] is not None or session["draft_event_id"] is not None
    ):
        raise RecorderError("unsealed journal must not contain request or draft selectors")

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_hash = ZERO_HASH
    for index, raw_entry in enumerate(_list(journal.get("entries"), "journal.entries")):
        entry = _mapping(raw_entry, f"journal.entries[{index}]")
        _exact_keys(
            entry,
            {"previous_entry_sha256", "event", "entry_sha256"},
            f"journal.entries[{index}]",
        )
        if entry.get("previous_entry_sha256") != previous_hash:
            raise RecorderError(f"journal.entries[{index}] previous hash mismatch")
        event_raw = _mapping(entry.get("event"), f"journal.entries[{index}].event")
        expected_sequence = index + 1
        supplied_sequence = event_raw.get("sequence")
        if supplied_sequence != expected_sequence:
            raise RecorderError(
                f"journal.entries[{index}].event.sequence must be {expected_sequence}"
            )
        payload = dict(event_raw)
        payload.pop("sequence")
        event = _validate_event_payload(payload, expected_sequence)
        if event["id"] in seen_ids:
            raise RecorderError(f"duplicate event id: {event['id']}")
        seen_ids.add(event["id"])
        expected_hash = _entry_hash(previous_hash, event)
        if entry.get("entry_sha256") != expected_hash:
            raise RecorderError(f"journal.entries[{index}] entry hash mismatch")
        entries.append(
            {
                "previous_entry_sha256": previous_hash,
                "event": event,
                "entry_sha256": expected_hash,
            }
        )
        previous_hash = expected_hash

    if journal.get("head_sha256") != previous_hash:
        raise RecorderError("journal.head_sha256 does not match the hash chain")
    if journal.get("authority") != AUTHORITY:
        raise RecorderError("journal.authority must remain the fixed no-authority map")

    seal_sha = journal.get("seal_sha256")
    if session["sealed"]:
        expected_seal = _seal_hash(session, previous_hash)
        if seal_sha != expected_seal:
            raise RecorderError("journal.seal_sha256 mismatch")
        _validate_final_graph(
            [entry["event"] for entry in entries],
            session["request_event_id"],
            session["draft_event_id"],
        )
    elif seal_sha is not None:
        raise RecorderError("unsealed journal must have null seal_sha256")

    return {
        "schema_version": JOURNAL_SCHEMA,
        "recorder": {"implementation": "python", "version": "0.4"},
        "session": session,
        "entries": entries,
        "head_sha256": previous_hash,
        "seal_sha256": seal_sha,
        "authority": AUTHORITY,
    }


class SessionRecorder:
    """Atomic, hash-chained recorder for one explicit assistant session."""

    def __init__(self, journal_path: str | Path):
        self.path = Path(journal_path)

    @classmethod
    def create(
        cls,
        journal_path: str | Path,
        *,
        session_id: str,
        high_stakes: bool,
        requires_current_information: bool,
    ) -> "SessionRecorder":
        path = Path(journal_path)
        with _journal_lock(path):
            if path.exists():
                raise RecorderError(f"journal already exists: {path}")
            _atomic_write_json(
                path,
                _empty_journal(
                    session_id, high_stakes, requires_current_information
                ),
            )
        return cls(path)

    def read(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise RecorderError(f"journal does not exist: {self.path}") from exc
        except json.JSONDecodeError as exc:
            raise RecorderError(f"journal is not valid JSON: {exc}") from exc
        return validate_journal(raw)

    def append_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        with _journal_lock(self.path):
            journal = self.read()
            if journal["session"]["sealed"]:
                raise RecorderError("cannot append to a sealed journal")
            sequence = len(journal["entries"]) + 1
            event = _validate_event_payload(payload, sequence)
            existing_ids = {entry["event"]["id"] for entry in journal["entries"]}
            if event["id"] in existing_ids:
                raise RecorderError(f"duplicate event id: {event['id']}")
            previous_hash = journal["head_sha256"]
            entry_hash = _entry_hash(previous_hash, event)
            journal["entries"].append(
                {
                    "previous_entry_sha256": previous_hash,
                    "event": event,
                    "entry_sha256": entry_hash,
                }
            )
            journal["head_sha256"] = entry_hash
            _atomic_write_json(self.path, journal)
            return event

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        with _journal_lock(self.path):
            journal = self.read()
            if journal["session"]["sealed"]:
                raise RecorderError("journal is already sealed")
            request_id = _string(request_event_id, "request_event_id")
            draft_id = _string(draft_event_id, "draft_event_id")
            events = [entry["event"] for entry in journal["entries"]]
            _validate_final_graph(events, request_id, draft_id)
            journal["session"].update(
                request_event_id=request_id,
                draft_event_id=draft_id,
                capture_complete=True,
                sealed=True,
            )
            journal["seal_sha256"] = _seal_hash(
                journal["session"], journal["head_sha256"]
            )
            _atomic_write_json(self.path, journal)
            return journal["session"]

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        journal = self.read()
        session = journal["session"]
        if not session["sealed"]:
            raise RecorderError("journal must be sealed before export")
        live_session = {
            "schema_version": LIVE_SESSION_SCHEMA,
            "session": {
                "id": session["id"],
                "request_event_id": session["request_event_id"],
                "draft_event_id": session["draft_event_id"],
                "high_stakes": session["high_stakes"],
                "requires_current_information": session[
                    "requires_current_information"
                ],
                "capture_complete": True,
            },
            "events": [entry["event"] for entry in journal["entries"]],
        }
        _atomic_write_json(Path(output_path), live_session)
        return live_session

    def verify(self) -> dict[str, Any]:
        journal = self.read()
        return {
            "schema_version": JOURNAL_SCHEMA,
            "session_id": journal["session"]["id"],
            "sealed": journal["session"]["sealed"],
            "event_count": len(journal["entries"]),
            "head_sha256": journal["head_sha256"],
            "seal_sha256": journal["seal_sha256"],
            "authority": AUTHORITY,
        }

    def record_user_message(self, *, event_id: str, text: str) -> dict[str, Any]:
        return self.append_event({"id": event_id, "type": "user_message", "text": text})

    def record_assistant_draft(
        self,
        *,
        event_id: str,
        response: str,
        no_signal: bool,
        intent_alignment: float,
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "assistant_draft",
                "response": response,
                "no_signal": no_signal,
                "intent_alignment": intent_alignment,
            }
        )

    def record_claim(
        self,
        *,
        event_id: str,
        draft_event_id: str,
        text: str,
        kind: str,
        confidence: float,
        requires_current_information: bool,
        evidence_event_ids: list[str],
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "claim",
                "draft_event_id": draft_event_id,
                "text": text,
                "kind": kind,
                "confidence": confidence,
                "requires_current_information": requires_current_information,
                "evidence_event_ids": evidence_event_ids,
            }
        )

    def record_source(
        self,
        *,
        event_id: str,
        handle: str,
        verified: bool,
        freshness: str,
        source_kind: str,
        locator: str,
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "source",
                "handle": handle,
                "verified": verified,
                "freshness": freshness,
                "source_kind": source_kind,
                "locator": locator,
            }
        )

    def record_tool_event(
        self,
        *,
        event_id: str,
        tool: str,
        operation: str,
        status: str,
        effect: str,
        evidence_eligible: bool,
        freshness: str,
        locator: str | None,
        reversible: bool,
        recovery_plan: str | None,
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "tool_event",
                "tool": tool,
                "operation": operation,
                "status": status,
                "effect": effect,
                "evidence_eligible": evidence_eligible,
                "freshness": freshness,
                "locator": locator,
                "reversible": reversible,
                "recovery_plan": recovery_plan,
            }
        )

    def record_authorization(
        self, *, event_id: str, text: str, authorized_event_ids: list[str]
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "user_authorization",
                "text": text,
                "authorized_event_ids": authorized_event_ids,
            }
        )

    def record_proposed_action(
        self,
        *,
        event_id: str,
        draft_event_id: str,
        description: str,
        reversible: bool,
        recovery_plan: str | None,
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "proposed_action",
                "draft_event_id": draft_event_id,
                "description": description,
                "reversible": reversible,
                "recovery_plan": recovery_plan,
            }
        )

    def record_contradiction(
        self, *, event_id: str, draft_event_id: str, text: str
    ) -> dict[str, Any]:
        return self.append_event(
            {
                "id": event_id,
                "type": "contradiction",
                "draft_event_id": draft_event_id,
                "text": text,
            }
        )


__all__ = [
    "AUTHORITY",
    "JOURNAL_SCHEMA",
    "LIVE_SESSION_SCHEMA",
    "RecorderError",
    "SessionRecorder",
    "validate_journal",
]
