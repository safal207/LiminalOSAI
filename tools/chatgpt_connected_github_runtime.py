#!/usr/bin/env python3
"""CLI for Connected GitHub Runtime Harness v0.7 lifecycle management."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_bridge import GitHubAgentBridge, GitHubBridgeError, GitHubOperation
from sdk.liminal_github_runtime import (
    ACTION_BINDINGS,
    ConnectedGitHubRuntime,
    GitHubRuntimeError,
)


def _load_json(path: str, name: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GitHubRuntimeError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GitHubRuntimeError(f"{name} is not valid JSON: {exc}") from exc


def _operation(path: str) -> GitHubOperation:
    raw = _load_json(path, "operation file")
    if not isinstance(raw, dict) or set(raw) != {"call_id", "action", "arguments"}:
        raise GitHubRuntimeError(
            "operation file must contain exactly call_id, action, and arguments"
        )
    return GitHubOperation(
        call_id=raw["call_id"],
        action=raw["action"],
        arguments=raw["arguments"],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--runtime-config", required=True)
    init.add_argument("--bridge-config", required=True)
    init.add_argument("--host-trace", required=True)
    init.add_argument("--journal", required=True)
    init.add_argument("--session-id", required=True)
    init.add_argument("--allowed-repository", action="append", required=True)
    init.add_argument("--protected-branch", action="append")
    init.add_argument("--high-stakes", action="store_true")
    init.add_argument("--requires-current-information", action="store_true")
    init.add_argument("--max-request-bytes", type=int, default=1_048_576)
    init.add_argument("--max-response-bytes", type=int, default=4_194_304)

    validate = sub.add_parser("validate")
    validate.add_argument("--runtime-config", required=True)
    validate.add_argument("--operation", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--runtime-config", required=True)
    verify.add_argument("--allow-pending", action="store_true")

    bindings = sub.add_parser("bindings")
    bindings.add_argument("--runtime-config", required=True)

    authorize = sub.add_parser("authorize")
    authorize.add_argument("--runtime-config", required=True)
    authorize.add_argument("--operation", required=True)
    authorize.add_argument("--event-id", required=True)
    authorize.add_argument("--text", required=True)

    seal = sub.add_parser("seal")
    seal.add_argument("--runtime-config", required=True)
    seal.add_argument("--request-event-id", required=True)
    seal.add_argument("--draft-event-id", required=True)

    export = sub.add_parser("export")
    export.add_argument("--runtime-config", required=True)
    export.add_argument("--output", required=True)

    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "init":
            GitHubAgentBridge.create(
                args.bridge_config,
                host_trace_path=args.host_trace,
                recorder_path=args.journal,
                session_id=args.session_id,
                high_stakes=args.high_stakes,
                requires_current_information=args.requires_current_information,
                allowed_repositories=args.allowed_repository,
                protected_branches=args.protected_branch,
                max_request_bytes=args.max_request_bytes,
            )
            runtime = ConnectedGitHubRuntime.create(
                args.runtime_config,
                bridge_config_path=args.bridge_config,
                max_response_bytes=args.max_response_bytes,
            )
            result = runtime.verify(allow_pending=True)
        else:
            runtime = ConnectedGitHubRuntime(args.runtime_config)
            if args.command == "validate":
                result = runtime.bridge.validate_operation(_operation(args.operation)).as_dict()
            elif args.command == "verify":
                result = runtime.verify(allow_pending=args.allow_pending)
            elif args.command == "bindings":
                runtime.verify(allow_pending=True)
                result = {"connector_name": "GitHub", "bindings": dict(ACTION_BINDINGS)}
            elif args.command == "authorize":
                result = runtime.authorize_operation(
                    event_id=args.event_id,
                    text=args.text,
                    operation=_operation(args.operation),
                )
            elif args.command == "seal":
                result = runtime.seal(
                    request_event_id=args.request_event_id,
                    draft_event_id=args.draft_event_id,
                )
            elif args.command == "export":
                result = runtime.export_live_session(args.output)
            else:
                raise GitHubRuntimeError(f"unsupported command: {args.command}")
    except (GitHubRuntimeError, GitHubBridgeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
