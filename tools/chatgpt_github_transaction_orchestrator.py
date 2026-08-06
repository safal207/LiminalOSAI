#!/usr/bin/env python3
"""CLI for GitHub Transaction Orchestrator v0.8 lifecycle operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_transaction import (
    GitHubTransactionOrchestrator,
    TransactionError,
)


def _read_json(path: str, name: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TransactionError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TransactionError(f"{name} is not valid JSON: {exc}") from exc


def _orchestrator(args) -> GitHubTransactionOrchestrator:
    return GitHubTransactionOrchestrator(args.plan, args.journal)


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--plan", required=True)
    init.add_argument("--journal", required=True)
    init.add_argument("--runtime-config", required=True)
    init.add_argument("--transaction-id", required=True)
    init.add_argument("--repository", required=True)
    init.add_argument("--steps", required=True)

    for name in ("verify", "next", "recovery"):
        command = sub.add_parser(name)
        command.add_argument("--plan", required=True)
        command.add_argument("--journal", required=True)
        if name == "verify":
            command.add_argument("--allow-pending", action="store_true")

    authorize = sub.add_parser("authorize")
    authorize.add_argument("--plan", required=True)
    authorize.add_argument("--journal", required=True)
    authorize.add_argument("--step-id", required=True)
    authorize.add_argument("--event-id", required=True)
    authorize.add_argument("--text", required=True)

    abort = sub.add_parser("abort")
    abort.add_argument("--plan", required=True)
    abort.add_argument("--journal", required=True)
    abort.add_argument("--reason", required=True)

    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("--plan", required=True)
    reconcile.add_argument("--journal", required=True)
    reconcile.add_argument("--receipt", required=True)
    reconcile.add_argument("--raw-response", required=True)

    seal = sub.add_parser("seal")
    seal.add_argument("--plan", required=True)
    seal.add_argument("--journal", required=True)
    seal.add_argument("--request-event-id", required=True)
    seal.add_argument("--draft-event-id", required=True)

    export = sub.add_parser("export")
    export.add_argument("--plan", required=True)
    export.add_argument("--journal", required=True)
    export.add_argument("--output", required=True)

    args = parser.parse_args()
    try:
        if args.command == "init":
            steps = _read_json(args.steps, "steps file")
            if not isinstance(steps, list):
                raise TransactionError("steps file must contain a JSON array")
            result = GitHubTransactionOrchestrator.create(
                args.plan,
                args.journal,
                runtime_config_path=args.runtime_config,
                transaction_id=args.transaction_id,
                repository_full_name=args.repository,
                steps=steps,
            ).verify()
        elif args.command == "verify":
            result = _orchestrator(args).verify(allow_pending=args.allow_pending)
        elif args.command == "next":
            result = _orchestrator(args).prepare_next()
        elif args.command == "authorize":
            result = _orchestrator(args).authorize_step(
                step_id=args.step_id,
                event_id=args.event_id,
                text=args.text,
            )
        elif args.command == "abort":
            result = _orchestrator(args).abort(reason=args.reason)
        elif args.command == "recovery":
            result = _orchestrator(args).recovery_report()
        elif args.command == "reconcile":
            result = _orchestrator(args).reconcile_pending(
                connected_receipt=_read_json(args.receipt, "receipt file"),
                raw_response=_read_json(args.raw_response, "raw response file"),
            )
        elif args.command == "seal":
            result = _orchestrator(args).seal(
                request_event_id=args.request_event_id,
                draft_event_id=args.draft_event_id,
            )
        else:
            result = _orchestrator(args).export_live_session(args.output)
        _print(result)
        return 0
    except TransactionError as exc:
        print(f"transaction error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
