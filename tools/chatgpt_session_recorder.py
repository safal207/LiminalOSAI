#!/usr/bin/env python3
"""CLI for the deterministic ChatGPT Session Recorder SDK v0.4."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_session_recorder import RecorderError, SessionRecorder  # noqa: E402


def _load_event(path: str) -> dict[str, Any]:
    try:
        if path == "-":
            value = json.load(sys.stdin)
        else:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecorderError(f"cannot read event JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RecorderError("event JSON must be an object")
    return value


def _bool_argument(parser: argparse.ArgumentParser, name: str, help_text: str) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        f"--{name}",
        dest=name.replace("-", "_"),
        action="store_true",
        help=help_text,
    )
    group.add_argument(
        f"--no-{name}",
        dest=name.replace("-", "_"),
        action="store_false",
        help=f"Do not set {help_text.lower()}",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a new journal")
    init.add_argument("--journal", required=True, type=Path)
    init.add_argument("--session-id", required=True)
    _bool_argument(init, "high-stakes", "Mark the session as high stakes")
    _bool_argument(
        init,
        "requires-current-information",
        "Mark the session as requiring current information",
    )

    append = subparsers.add_parser("append", help="Append one bounded event JSON object")
    append.add_argument("--journal", required=True, type=Path)
    append.add_argument("--event", required=True, help="JSON file path or '-' for stdin")

    seal = subparsers.add_parser("seal", help="Validate and seal the complete journal")
    seal.add_argument("--journal", required=True, type=Path)
    seal.add_argument("--request-event-id", required=True)
    seal.add_argument("--draft-event-id", required=True)

    export = subparsers.add_parser("export", help="Export chatgpt-live-session-v0.3")
    export.add_argument("--journal", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="Verify hash chain and seal integrity")
    verify.add_argument("--journal", required=True, type=Path)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "init":
            recorder = SessionRecorder.create(
                args.journal,
                session_id=args.session_id,
                high_stakes=args.high_stakes,
                requires_current_information=args.requires_current_information,
            )
            result = recorder.verify()
        elif args.command == "append":
            recorder = SessionRecorder(args.journal)
            result = {"event": recorder.append_event(_load_event(args.event))}
        elif args.command == "seal":
            recorder = SessionRecorder(args.journal)
            result = {
                "session": recorder.seal(
                    request_event_id=args.request_event_id,
                    draft_event_id=args.draft_event_id,
                )
            }
        elif args.command == "export":
            recorder = SessionRecorder(args.journal)
            result = {"live_session": recorder.export_live_session(args.output)}
        else:
            result = SessionRecorder(args.journal).verify()
    except RecorderError as exc:
        print(f"session recorder error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
