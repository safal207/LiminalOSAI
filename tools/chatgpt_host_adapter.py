#!/usr/bin/env python3
"""CLI for ChatGPT Host Integration Adapter v0.5."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_host_adapter import (  # noqa: E402
    HostAdapterError,
    HostIntegrationAdapter,
    ToolCallSpec,
)
from sdk.liminal_session_recorder import RecorderError  # noqa: E402


def _read_json(path: Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HostAdapterError(f"cannot read {name}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise HostAdapterError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise HostAdapterError(f"{name} must be a JSON object")
    return value


def _spec(path: Path) -> ToolCallSpec:
    raw = _read_json(path, "tool-call spec")
    expected = {
        "call_id",
        "tool",
        "operation",
        "effect",
        "evidence_eligible",
        "freshness",
        "reversible",
        "recovery_plan",
    }
    missing = sorted(expected - set(raw))
    extra = sorted(set(raw) - expected)
    if missing:
        raise HostAdapterError("tool-call spec missing keys: " + ", ".join(missing))
    if extra:
        raise HostAdapterError("tool-call spec contains unsupported keys: " + ", ".join(extra))
    return ToolCallSpec(**raw).normalized()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--trace", required=True, type=Path)
    init.add_argument("--journal", required=True, type=Path)
    init.add_argument("--session-id", required=True)
    init.add_argument("--high-stakes", action="store_true")
    init.add_argument("--requires-current-information", action="store_true")

    append = sub.add_parser("append")
    append.add_argument("--trace", required=True, type=Path)
    append.add_argument("--event", required=True, type=Path)

    start = sub.add_parser("start")
    start.add_argument("--trace", required=True, type=Path)
    start.add_argument("--spec", required=True, type=Path)

    finish = sub.add_parser("finish")
    finish.add_argument("--trace", required=True, type=Path)
    finish.add_argument("--call-id", required=True)
    finish.add_argument("--status", required=True, choices=["success", "failure", "cancelled"])
    finish.add_argument("--locator")

    recover = sub.add_parser("recover")
    recover.add_argument("--trace", required=True, type=Path)
    recover.add_argument("--call-id", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--trace", required=True, type=Path)
    verify.add_argument("--allow-pending", action="store_true")

    seal = sub.add_parser("seal")
    seal.add_argument("--trace", required=True, type=Path)
    seal.add_argument("--request-event-id", required=True)
    seal.add_argument("--draft-event-id", required=True)

    export = sub.add_parser("export")
    export.add_argument("--trace", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "init":
        adapter = HostIntegrationAdapter.create(
            args.trace,
            recorder_path=args.journal,
            session_id=args.session_id,
            high_stakes=args.high_stakes,
            requires_current_information=args.requires_current_information,
        )
        return adapter.verify(allow_pending=True)

    adapter = HostIntegrationAdapter(args.trace)
    if args.command == "append":
        return adapter.append_visible_event(_read_json(args.event, "event"))
    if args.command == "start":
        handle = adapter.start_tool_call(_spec(args.spec))
        return {"call_id": handle.call_id, "status": "started"}
    if args.command == "finish":
        return adapter.finish_tool_call(
            args.call_id, status=args.status, locator=args.locator
        )
    if args.command == "recover":
        return adapter.recover_tool_call(args.call_id)
    if args.command == "verify":
        return adapter.verify(allow_pending=args.allow_pending)
    if args.command == "seal":
        return adapter.seal(
            request_event_id=args.request_event_id,
            draft_event_id=args.draft_event_id,
        )
    if args.command == "export":
        return adapter.export_live_session(args.output)
    raise HostAdapterError(f"unsupported command: {args.command}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = run(args)
    except (HostAdapterError, RecorderError, OSError) as exc:
        print(f"host integration adapter error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
