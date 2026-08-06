#!/usr/bin/env python3
"""CLI for validating and managing ChatGPT GitHub Agent Bridge v0.6 sessions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import (  # noqa: E402
    GitHubAgentBridge,
    GitHubBridgeError,
    GitHubOperation,
)


def _load_json(path: str, name: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GitHubBridgeError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GitHubBridgeError(f"{name} is not valid JSON: {exc}") from exc


def _operation(path: str) -> GitHubOperation:
    raw = _load_json(path, "operation file")
    if not isinstance(raw, dict):
        raise GitHubBridgeError("operation file must contain a JSON object")
    actual = set(raw)
    expected = {"call_id", "action", "arguments"}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        parts = []
        if missing:
            parts.append("missing: " + ", ".join(missing))
        if extra:
            parts.append("unsupported: " + ", ".join(extra))
        raise GitHubBridgeError("invalid operation file (" + "; ".join(parts) + ")")
    return GitHubOperation(
        call_id=raw["call_id"], action=raw["action"], arguments=raw["arguments"]
    )


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create bridge config, host trace, and recorder journal")
    init.add_argument("--config", required=True)
    init.add_argument("--trace", required=True)
    init.add_argument("--journal", required=True)
    init.add_argument("--session-id", required=True)
    init.add_argument("--allow-repo", action="append", required=True)
    init.add_argument("--protected-branch", action="append")
    init.add_argument("--max-request-bytes", type=int, default=1_048_576)
    init.add_argument("--high-stakes", action="store_true")
    init.add_argument("--requires-current-information", action="store_true")

    validate = sub.add_parser("validate-operation", help="validate and normalize one GitHub operation")
    validate.add_argument("--config", required=True)
    validate.add_argument("--operation", required=True)

    append = sub.add_parser("append", help="append one explicit visible-session event")
    append.add_argument("--config", required=True)
    append.add_argument("--event", required=True)

    verify = sub.add_parser("verify", help="verify bridge config and host/recorder correlation")
    verify.add_argument("--config", required=True)
    verify.add_argument("--allow-pending", action="store_true")

    seal = sub.add_parser("seal", help="seal a complete session")
    seal.add_argument("--config", required=True)
    seal.add_argument("--request-event-id", required=True)
    seal.add_argument("--draft-event-id", required=True)

    export = sub.add_parser("export", help="export a sealed session to live-session v0.3")
    export.add_argument("--config", required=True)
    export.add_argument("--output", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            bridge = GitHubAgentBridge.create(
                args.config,
                host_trace_path=args.trace,
                recorder_path=args.journal,
                session_id=args.session_id,
                high_stakes=args.high_stakes,
                requires_current_information=args.requires_current_information,
                allowed_repositories=args.allow_repo,
                protected_branches=args.protected_branch,
                max_request_bytes=args.max_request_bytes,
            )
            _print(bridge.verify())
        elif args.command == "validate-operation":
            normalized = GitHubAgentBridge(args.config).validate_operation(
                _operation(args.operation)
            )
            _print(normalized.as_dict())
        elif args.command == "append":
            event = _load_json(args.event, "event file")
            _print(GitHubAgentBridge(args.config).append_visible_event(event))
        elif args.command == "verify":
            _print(GitHubAgentBridge(args.config).verify(allow_pending=args.allow_pending))
        elif args.command == "seal":
            _print(
                GitHubAgentBridge(args.config).seal(
                    request_event_id=args.request_event_id,
                    draft_event_id=args.draft_event_id,
                )
            )
        elif args.command == "export":
            _print(GitHubAgentBridge(args.config).export_live_session(args.output))
        else:
            raise GitHubBridgeError(f"unsupported command: {args.command}")
    except GitHubBridgeError as exc:
        print(f"github bridge error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"github bridge error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
