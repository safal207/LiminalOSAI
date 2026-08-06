"""Host integration lifecycle built on the v0.4 SessionRecorder."""

from __future__ import annotations

import json
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from sdk.liminal_session_recorder import RecorderError, SessionRecorder

from ._core import (
    AUTHORITY,
    HOST_TRACE_SCHEMA,
    TOOL_STATUSES,
    HostAdapterError,
    ToolCallSpec,
    atomic_write_json,
    enum,
    exclusive_lock,
    optional_string,
    string,
)
from ._trace import (
    empty_trace,
    record_hash,
    validate_finish_record,
    validate_start_record,
    validate_trace,
)


class ToolCallHandle(AbstractContextManager["ToolCallHandle"]):
    """A started visible tool call that requires one explicit final outcome."""

    def __init__(self, adapter: "HostIntegrationAdapter", call_id: str):
        self._adapter = adapter
        self.call_id = call_id
        self._finished = False

    def __enter__(self) -> "ToolCallHandle":
        return self

    def succeed(self, *, locator: str | None) -> dict[str, Any]:
        result = self._adapter.finish_tool_call(
            self.call_id, status="success", locator=locator
        )
        self._finished = True
        return result

    def fail(self, *, locator: str | None) -> dict[str, Any]:
        result = self._adapter.finish_tool_call(
            self.call_id, status="failure", locator=locator
        )
        self._finished = True
        return result

    def cancel(self, *, locator: str | None = None) -> dict[str, Any]:
        result = self._adapter.finish_tool_call(
            self.call_id, status="cancelled", locator=locator
        )
        self._finished = True
        return result

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if exc is not None and not self._finished:
            locator = f"exception:{exc_type.__module__}.{exc_type.__qualname__}"
            self._adapter.finish_tool_call(
                self.call_id, status="failure", locator=locator
            )
            self._finished = True
            return False
        if exc is None and not self._finished:
            raise HostAdapterError(
                f"tool call {self.call_id} exited without an explicit outcome"
            )
        return False


class HostIntegrationAdapter:
    """Correlates visible host tool calls with deterministic recorder events."""

    def __init__(self, trace_path: str | Path):
        self.trace_path = Path(trace_path)

    @classmethod
    def create(
        cls,
        trace_path: str | Path,
        *,
        recorder_path: str | Path,
        session_id: str,
        high_stakes: bool,
        requires_current_information: bool,
    ) -> "HostIntegrationAdapter":
        trace = Path(trace_path)
        recorder = Path(recorder_path)
        with exclusive_lock(trace):
            if trace.exists():
                raise HostAdapterError(f"host trace already exists: {trace}")
            if recorder.exists():
                raise HostAdapterError(f"recorder journal already exists: {recorder}")
            SessionRecorder.create(
                recorder,
                session_id=session_id,
                high_stakes=high_stakes,
                requires_current_information=requires_current_information,
            )
            atomic_write_json(trace, empty_trace(recorder))
        return cls(trace)

    def _read_trace(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.trace_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise HostAdapterError(
                f"host trace does not exist: {self.trace_path}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise HostAdapterError(f"host trace is not valid JSON: {exc}") from exc
        return validate_trace(raw)

    @property
    def recorder(self) -> SessionRecorder:
        return SessionRecorder(self._read_trace()["recorder_journal"])

    def _append_record(self, record: dict[str, Any]) -> dict[str, Any]:
        with exclusive_lock(self.trace_path):
            trace = self._read_trace()
            records = [entry["record"] for entry in trace["entries"]]
            started = {
                item["call_id"]
                for item in records
                if item["type"] == "tool_call_started"
            }
            finished = {
                item["call_id"]
                for item in records
                if item["type"] == "tool_call_finished"
            }
            pending = started - finished
            sequence = len(trace["entries"]) + 1
            candidate = {**record, "sequence": sequence}
            if candidate.get("type") == "tool_call_started":
                normalized = validate_start_record(candidate, sequence)
                if pending:
                    raise HostAdapterError("only one visible tool call may be pending")
                if normalized["call_id"] in started:
                    raise HostAdapterError(
                        f"tool call id already exists in host trace: {normalized['call_id']}"
                    )
                if self.recorder.read()["head_sha256"] != normalized[
                    "recorder_head_before"
                ]:
                    raise HostAdapterError(
                        "recorder changed before the tool-call start could be committed"
                    )
            elif candidate.get("type") == "tool_call_finished":
                normalized = validate_finish_record(candidate, sequence)
                if normalized["call_id"] not in pending:
                    raise HostAdapterError(
                        f"tool call is not pending: {normalized['call_id']}"
                    )
            else:
                raise HostAdapterError("unsupported host trace record type")
            previous_hash = trace["head_sha256"]
            entry_hash = record_hash(previous_hash, normalized)
            trace["entries"].append(
                {
                    "previous_entry_sha256": previous_hash,
                    "record": normalized,
                    "entry_sha256": entry_hash,
                }
            )
            trace["head_sha256"] = entry_hash
            atomic_write_json(self.trace_path, trace)
            return normalized

    def _trace_records(self) -> list[dict[str, Any]]:
        return [entry["record"] for entry in self._read_trace()["entries"]]

    def _pending_starts(self) -> dict[str, dict[str, Any]]:
        starts: dict[str, dict[str, Any]] = {}
        finished: set[str] = set()
        for record in self._trace_records():
            if record["type"] == "tool_call_started":
                starts[record["call_id"]] = record
            else:
                finished.add(record["call_id"])
        return {
            call_id: record
            for call_id, record in starts.items()
            if call_id not in finished
        }

    def _ensure_no_pending(self) -> None:
        pending = sorted(self._pending_starts())
        if pending:
            raise HostAdapterError(
                "pending tool calls block recorder mutation: " + ", ".join(pending)
            )

    def _authorization_ids(self, call_id: str) -> list[str]:
        result: list[str] = []
        for entry in self.recorder.read()["entries"]:
            event = entry["event"]
            if (
                event["type"] == "user_authorization"
                and call_id in event["authorized_event_ids"]
            ):
                result.append(event["id"])
        return result

    def start_tool_call(self, spec: ToolCallSpec) -> ToolCallHandle:
        value = spec.normalized()
        if self._pending_starts():
            raise HostAdapterError("only one visible tool call may be pending")
        journal = self.recorder.read()
        if journal["session"]["sealed"]:
            raise HostAdapterError("cannot start a tool call after recorder seal")
        existing_ids = {entry["event"]["id"] for entry in journal["entries"]}
        if value.call_id in existing_ids:
            raise HostAdapterError(
                f"tool call id already exists in recorder: {value.call_id}"
            )
        started_ids = {
            record["call_id"]
            for record in self._trace_records()
            if record["type"] == "tool_call_started"
        }
        if value.call_id in started_ids:
            raise HostAdapterError(
                f"tool call id already exists in host trace: {value.call_id}"
            )
        authorization_ids = self._authorization_ids(value.call_id)
        if value.effect == "write" and not authorization_ids:
            raise HostAdapterError(
                f"write tool call {value.call_id} requires explicit prior authorization"
            )
        self._append_record(
            {
                "type": "tool_call_started",
                **value.as_dict(),
                "authorization_event_ids": authorization_ids,
                "recorder_head_before": journal["head_sha256"],
            }
        )
        return ToolCallHandle(self, value.call_id)

    def tool_call(self, spec: ToolCallSpec) -> ToolCallHandle:
        return self.start_tool_call(spec)

    def finish_tool_call(
        self, call_id: str, *, status: str, locator: str | None
    ) -> dict[str, Any]:
        target_id = string(call_id, "call_id")
        normalized_status = enum(status, "status", TOOL_STATUSES)
        normalized_locator = optional_string(locator, "locator")
        start = self._pending_starts().get(target_id)
        if start is None:
            raise HostAdapterError(f"tool call is not pending: {target_id}")
        if start["evidence_eligible"] and normalized_locator is None:
            raise HostAdapterError("evidence-eligible tool call requires locator")
        journal = self.recorder.read()
        if journal["head_sha256"] != start["recorder_head_before"]:
            raise HostAdapterError(
                "recorder changed while the tool call was pending; refusing ambiguous completion"
            )
        try:
            event = self.recorder.record_tool_event(
                event_id=target_id,
                tool=start["tool"],
                operation=start["operation"],
                status=normalized_status,
                effect=start["effect"],
                evidence_eligible=start["evidence_eligible"],
                freshness=start["freshness"],
                locator=normalized_locator,
                reversible=start["reversible"],
                recovery_plan=start["recovery_plan"],
            )
        except RecorderError as exc:
            raise HostAdapterError(f"recorder rejected tool completion: {exc}") from exc
        recorder_after = self.recorder.read()
        self._append_record(
            {
                "type": "tool_call_finished",
                "call_id": target_id,
                "status": normalized_status,
                "locator": normalized_locator,
                "recorder_event_id": event["id"],
                "recorder_head_after": recorder_after["head_sha256"],
            }
        )
        return event

    def recover_tool_call(self, call_id: str) -> dict[str, Any]:
        target_id = string(call_id, "call_id")
        start = self._pending_starts().get(target_id)
        if start is None:
            raise HostAdapterError(f"tool call is not pending: {target_id}")
        journal = self.recorder.read()
        matches = [
            entry
            for entry in journal["entries"]
            if entry["event"]["id"] == target_id
        ]
        if len(matches) != 1:
            raise HostAdapterError(
                "recovery requires exactly one matching recorder event"
            )
        entry = matches[0]
        event = entry["event"]
        if entry["previous_entry_sha256"] != start["recorder_head_before"]:
            raise HostAdapterError(
                "recovery event does not immediately follow the tool-call start"
            )
        if journal["entries"][-1]["event"]["id"] != target_id:
            raise HostAdapterError("recovery event must be the latest recorder event")
        for field in (
            "tool",
            "operation",
            "effect",
            "evidence_eligible",
            "freshness",
            "reversible",
            "recovery_plan",
        ):
            if event[field] != start[field]:
                raise HostAdapterError(f"recovery field mismatch: {field}")
        self._append_record(
            {
                "type": "tool_call_finished",
                "call_id": target_id,
                "status": event["status"],
                "locator": event["locator"],
                "recorder_event_id": target_id,
                "recorder_head_after": entry["entry_sha256"],
            }
        )
        return event

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        trace = self._read_trace()
        journal = self.recorder.read()
        starts: dict[str, dict[str, Any]] = {}
        finishes: dict[str, dict[str, Any]] = {}
        for entry in trace["entries"]:
            record = entry["record"]
            target = starts if record["type"] == "tool_call_started" else finishes
            target[record["call_id"]] = record
        pending = sorted(set(starts) - set(finishes))
        if pending and not allow_pending:
            raise HostAdapterError(
                "host trace contains pending tool calls: " + ", ".join(pending)
            )
        recorder_entries = {
            entry["event"]["id"]: entry for entry in journal["entries"]
        }
        for call_id, finish in finishes.items():
            start = starts[call_id]
            recorder_entry = recorder_entries.get(call_id)
            if recorder_entry is None:
                raise HostAdapterError(
                    f"completed call missing recorder event: {call_id}"
                )
            event = recorder_entry["event"]
            if event["type"] != "tool_event":
                raise HostAdapterError(
                    f"completed call maps to non-tool recorder event: {call_id}"
                )
            if recorder_entry["previous_entry_sha256"] != start[
                "recorder_head_before"
            ]:
                raise HostAdapterError(
                    f"recorder predecessor mismatch for call: {call_id}"
                )
            if recorder_entry["entry_sha256"] != finish["recorder_head_after"]:
                raise HostAdapterError(
                    f"recorder result hash mismatch for call: {call_id}"
                )
            if finish["recorder_event_id"] != call_id:
                raise HostAdapterError(
                    f"recorder event id mismatch for call: {call_id}"
                )
            for field in (
                "tool",
                "operation",
                "effect",
                "evidence_eligible",
                "freshness",
                "reversible",
                "recovery_plan",
            ):
                if event[field] != start[field]:
                    raise HostAdapterError(
                        f"tool metadata mismatch for {call_id}: {field}"
                    )
            if (
                event["status"] != finish["status"]
                or event["locator"] != finish["locator"]
            ):
                raise HostAdapterError(f"tool outcome mismatch for call: {call_id}")
            authorization_ids = []
            for entry in journal["entries"]:
                auth = entry["event"]
                if auth["sequence"] >= event["sequence"]:
                    break
                if (
                    auth["type"] == "user_authorization"
                    and call_id in auth["authorized_event_ids"]
                ):
                    authorization_ids.append(auth["id"])
            if authorization_ids != start["authorization_event_ids"]:
                raise HostAdapterError(
                    f"authorization edge mismatch for call: {call_id}"
                )
            if start["effect"] == "write" and not authorization_ids:
                raise HostAdapterError(f"write call lacks authorization: {call_id}")
        return {
            "schema_version": HOST_TRACE_SCHEMA,
            "recorder_session_id": journal["session"]["id"],
            "started_calls": len(starts),
            "completed_calls": len(finishes),
            "pending_call_ids": pending,
            "trace_head_sha256": trace["head_sha256"],
            "recorder_head_sha256": journal["head_sha256"],
            "authority": AUTHORITY,
        }

    def append_visible_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.append_event(payload)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_claim(**kwargs)

    def record_source(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_source(**kwargs)

    def record_authorization(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_authorization(**kwargs)

    def record_proposed_action(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_proposed_action(**kwargs)

    def record_contradiction(self, **kwargs: Any) -> dict[str, Any]:
        self._ensure_no_pending()
        return self.recorder.record_contradiction(**kwargs)

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        self.verify()
        return self.recorder.seal(
            request_event_id=request_event_id,
            draft_event_id=draft_event_id,
        )

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self.verify()
        return self.recorder.export_live_session(output_path)
