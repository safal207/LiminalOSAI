"""Hash-chained host trace schema and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._core import (
    AUTHORITY,
    FRESHNESS_VALUES,
    HOST_TRACE_SCHEMA,
    TOOL_EFFECTS,
    TOOL_STATUSES,
    ZERO_HASH,
    HostAdapterError,
    array,
    boolean,
    canonical_sha256,
    enum,
    exact_keys,
    mapping,
    optional_sha256,
    optional_string,
    string,
)


def empty_trace(recorder_path: Path) -> dict[str, Any]:
    return {
        "schema_version": HOST_TRACE_SCHEMA,
        "adapter": {"implementation": "python", "version": "0.5"},
        "recorder_journal": str(recorder_path),
        "entries": [],
        "head_sha256": ZERO_HASH,
        "authority": AUTHORITY,
    }


def record_hash(previous_hash: str, record: dict[str, Any]) -> str:
    return canonical_sha256(
        {"previous_entry_sha256": previous_hash, "record": record}
    )


def validate_start_record(raw: dict[str, Any], sequence: int) -> dict[str, Any]:
    exact_keys(
        raw,
        {
            "type",
            "sequence",
            "call_id",
            "tool",
            "operation",
            "effect",
            "evidence_eligible",
            "freshness",
            "reversible",
            "recovery_plan",
            "authorization_event_ids",
            "recorder_head_before",
        },
        "tool_call_started",
    )
    if raw.get("sequence") != sequence:
        raise HostAdapterError(f"tool_call_started.sequence must be {sequence}")
    authorization_ids = [
        string(item, f"authorization_event_ids[{index}]")
        for index, item in enumerate(
            array(raw.get("authorization_event_ids"), "authorization_event_ids")
        )
    ]
    if len(authorization_ids) != len(set(authorization_ids)):
        raise HostAdapterError("authorization_event_ids contains duplicates")
    return {
        "type": "tool_call_started",
        "sequence": sequence,
        "call_id": string(raw.get("call_id"), "call_id"),
        "tool": string(raw.get("tool"), "tool"),
        "operation": string(raw.get("operation"), "operation"),
        "effect": enum(raw.get("effect"), "effect", TOOL_EFFECTS),
        "evidence_eligible": boolean(
            raw.get("evidence_eligible"), "evidence_eligible"
        ),
        "freshness": enum(raw.get("freshness"), "freshness", FRESHNESS_VALUES),
        "reversible": boolean(raw.get("reversible"), "reversible"),
        "recovery_plan": optional_string(raw.get("recovery_plan"), "recovery_plan"),
        "authorization_event_ids": authorization_ids,
        "recorder_head_before": string(
            raw.get("recorder_head_before"), "recorder_head_before"
        ),
    }


def validate_finish_record(raw: dict[str, Any], sequence: int) -> dict[str, Any]:
    expected = {
        "type",
        "sequence",
        "call_id",
        "status",
        "locator",
        "recorder_event_id",
        "recorder_head_after",
    }
    if "payload_sha256" in raw:
        expected.add("payload_sha256")
    exact_keys(raw, expected, "tool_call_finished")
    if raw.get("sequence") != sequence:
        raise HostAdapterError(f"tool_call_finished.sequence must be {sequence}")
    record = {
        "type": "tool_call_finished",
        "sequence": sequence,
        "call_id": string(raw.get("call_id"), "call_id"),
        "status": enum(raw.get("status"), "status", TOOL_STATUSES),
        "locator": optional_string(raw.get("locator"), "locator"),
        "recorder_event_id": string(
            raw.get("recorder_event_id"), "recorder_event_id"
        ),
        "recorder_head_after": string(
            raw.get("recorder_head_after"), "recorder_head_after"
        ),
    }
    if "payload_sha256" in raw:
        record["payload_sha256"] = optional_sha256(
            raw.get("payload_sha256"), "payload_sha256"
        )
    return record


def validate_trace(raw_value: Any) -> dict[str, Any]:
    trace = mapping(raw_value, "host trace")
    exact_keys(
        trace,
        {
            "schema_version",
            "adapter",
            "recorder_journal",
            "entries",
            "head_sha256",
            "authority",
        },
        "host trace",
    )
    if trace.get("schema_version") != HOST_TRACE_SCHEMA:
        raise HostAdapterError(f"schema_version must be {HOST_TRACE_SCHEMA!r}")
    if trace.get("adapter") != {"implementation": "python", "version": "0.5"}:
        raise HostAdapterError("host trace adapter identity mismatch")
    if trace.get("authority") != AUTHORITY:
        raise HostAdapterError("host trace authority must remain fixed")
    recorder_journal = string(trace.get("recorder_journal"), "recorder_journal")

    entries: list[dict[str, Any]] = []
    previous_hash = ZERO_HASH
    starts: dict[str, dict[str, Any]] = {}
    finishes: set[str] = set()
    for index, raw_entry in enumerate(array(trace.get("entries"), "entries")):
        entry = mapping(raw_entry, f"entries[{index}]")
        exact_keys(
            entry,
            {"previous_entry_sha256", "record", "entry_sha256"},
            f"entries[{index}]",
        )
        if entry.get("previous_entry_sha256") != previous_hash:
            raise HostAdapterError(f"entries[{index}] previous hash mismatch")
        raw_record = mapping(entry.get("record"), f"entries[{index}].record")
        sequence = index + 1
        if raw_record.get("type") == "tool_call_started":
            record = validate_start_record(raw_record, sequence)
            call_id = record["call_id"]
            if call_id in starts:
                raise HostAdapterError(f"duplicate tool call start: {call_id}")
            starts[call_id] = record
        elif raw_record.get("type") == "tool_call_finished":
            record = validate_finish_record(raw_record, sequence)
            call_id = record["call_id"]
            if call_id not in starts:
                raise HostAdapterError(f"tool call finish without start: {call_id}")
            if call_id in finishes:
                raise HostAdapterError(f"duplicate tool call finish: {call_id}")
            finishes.add(call_id)
        else:
            raise HostAdapterError(
                f"unsupported host trace record type: {raw_record.get('type')!r}"
            )
        expected_hash = record_hash(previous_hash, record)
        if entry.get("entry_sha256") != expected_hash:
            raise HostAdapterError(f"entries[{index}] entry hash mismatch")
        entries.append(
            {
                "previous_entry_sha256": previous_hash,
                "record": record,
                "entry_sha256": expected_hash,
            }
        )
        previous_hash = expected_hash

    if trace.get("head_sha256") != previous_hash:
        raise HostAdapterError("host trace head_sha256 mismatch")
    return {
        "schema_version": HOST_TRACE_SCHEMA,
        "adapter": {"implementation": "python", "version": "0.5"},
        "recorder_journal": recorder_journal,
        "entries": entries,
        "head_sha256": previous_hash,
        "authority": AUTHORITY,
    }
