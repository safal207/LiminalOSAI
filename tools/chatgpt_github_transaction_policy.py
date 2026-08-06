#!/usr/bin/env python3
"""CLI for GitHub Transaction Policy & Approval Engine v0.9."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_policy import GitHubTransactionPolicyEngine, PolicyError


def _engine(args: argparse.Namespace) -> GitHubTransactionPolicyEngine:
    return GitHubTransactionPolicyEngine(
        args.policy,
        args.snapshot,
        args.approval_ledger,
        args.transaction_plan,
        args.transaction_journal,
    )


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and approve immutable GitHub transaction plans."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--policy", required=True, type=Path)
    common.add_argument("--snapshot", required=True, type=Path)
    common.add_argument("--approval-ledger", required=True, type=Path)
    common.add_argument("--transaction-plan", required=True, type=Path)
    common.add_argument("--transaction-journal", required=True, type=Path)

    init = sub.add_parser("init", parents=[common])
    init.add_argument("--policy-id", required=True)
    init.add_argument("--repository", action="append", required=True)
    init.add_argument("--rules-file", type=Path)
    init.add_argument("--max-steps", type=int, default=64)
    init.add_argument("--max-write-steps", type=int, default=32)
    init.add_argument("--max-critical-steps", type=int, default=1)

    sub.add_parser("verify", parents=[common])
    sub.add_parser("prepare", parents=[common])
    sub.add_parser("evidence", parents=[common])

    attest = sub.add_parser("attest", parents=[common])
    attest.add_argument("--approval-id", required=True)
    attest.add_argument("--principal-id", required=True)
    attest.add_argument("--role", required=True)
    attest.add_argument("--decision", required=True, choices=["approve", "deny"])
    attest.add_argument("--requirement-id", required=True)
    attest.add_argument("--evidence-locator")

    authorize = sub.add_parser("authorize-step", parents=[common])
    authorize.add_argument("--step-id", required=True)
    authorize.add_argument("--event-id", required=True)
    authorize.add_argument("--text", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "init":
            rules = None
            if args.rules_file:
                rules = json.loads(args.rules_file.read_text(encoding="utf-8"))
            engine = GitHubTransactionPolicyEngine.create(
                args.policy,
                args.snapshot,
                args.approval_ledger,
                transaction_plan_path=args.transaction_plan,
                transaction_journal_path=args.transaction_journal,
                policy_id=args.policy_id,
                allowed_repositories=args.repository,
                rules=rules,
                max_steps=args.max_steps,
                max_write_steps=args.max_write_steps,
                max_critical_steps=args.max_critical_steps,
            )
            _print(engine.verify(allow_pending=True))
        elif args.command == "verify":
            _print(_engine(args).verify(allow_pending=True))
        elif args.command == "prepare":
            _print(_engine(args).prepare_next())
        elif args.command == "evidence":
            _print(_engine(args).evidence_summary())
        elif args.command == "attest":
            _print(_engine(args).record_approval(
                approval_id=args.approval_id,
                principal_id=args.principal_id,
                role=args.role,
                decision=args.decision,
                requirement_id=args.requirement_id,
                evidence_locator=args.evidence_locator,
            ))
        elif args.command == "authorize-step":
            _print(_engine(args).authorize_step(
                step_id=args.step_id,
                event_id=args.event_id,
                text=args.text,
            ))
        else:
            parser.error("unknown command")
    except (PolicyError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
