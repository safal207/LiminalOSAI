#!/usr/bin/env python3
"""CLI for Signed Governance Capsule v1.0."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sdk.liminal_github_policy import GitHubTransactionPolicyEngine
from sdk.liminal_governance_capsule import (
    ALGORITHM,
    CapsuleError,
    GovernanceTrustStore,
    generate_ed25519_keypair,
    issue_capsule,
    load_capsule,
    load_trust_store,
    verify_capsule,
    verify_capsule_against_engine,
)


def write_json(path: Path | None, value):
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(text, end="")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def write_private(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def engine_from_args(args):
    return GitHubTransactionPolicyEngine(
        args.policy,
        args.snapshot,
        args.approval_ledger,
        args.transaction_plan,
        args.transaction_journal,
    )


def command_keygen(args):
    private_key, public_key = generate_ed25519_keypair()
    write_private(args.private_key, private_key)
    args.public_key.parent.mkdir(parents=True, exist_ok=True)
    with args.public_key.open("xb") as handle:
        handle.write(public_key)
    return {
        "algorithm": ALGORITHM,
        "private_key": str(args.private_key),
        "public_key": str(args.public_key),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
    }


def command_trust_init(args):
    public_key = args.public_key.read_bytes()
    store = GovernanceTrustStore.build(
        trust_store_id=args.trust_store_id,
        max_ttl_seconds=args.max_ttl_seconds,
        max_clock_skew_seconds=args.max_clock_skew_seconds,
        keys=[{
            "issuer_id": args.issuer_id,
            "key_id": args.key_id,
            "algorithm": ALGORITHM,
            "public_key_pem": public_key.decode("utf-8"),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "valid_from_unix": args.valid_from_unix,
            "valid_until_unix": args.valid_until_unix,
            "revoked_at_unix": args.revoked_at_unix,
            "allowed_audiences": args.audience,
            "allowed_repositories": args.repository,
        }],
    )
    write_json(args.output, store.as_document())
    return {
        "trust_store_id": store.trust_store_id,
        "trust_store_sha256": store.trust_store_sha256,
        "output": str(args.output),
    }


def command_issue(args):
    engine = engine_from_args(args)
    capsule = issue_capsule(
        engine,
        private_key_path=args.private_key,
        capsule_id=args.capsule_id,
        issuer_id=args.issuer_id,
        subject_id=args.subject_id,
        key_id=args.key_id,
        audience=args.audience,
        ttl_seconds=args.ttl_seconds,
        issued_at_unix=args.issued_at_unix,
        not_before_delay_seconds=args.not_before_delay_seconds,
        nonce=args.nonce,
        output_path=args.output,
    )
    return {
        "capsule_id": capsule.claims.capsule_id,
        "capsule_sha256": capsule.capsule_sha256,
        "expires_at_unix": capsule.claims.expires_at_unix,
        "output": str(args.output),
    }


def command_verify(args):
    return verify_capsule(
        load_capsule(args.capsule),
        load_trust_store(args.trust_store),
        at_unix=args.at_unix,
        expected_audience=args.audience,
        expected_repository=args.repository,
        expected_plan_sha256=args.plan_sha256,
        expected_policy_sha256=args.policy_sha256,
    )


def command_verify_engine(args):
    return verify_capsule_against_engine(
        load_capsule(args.capsule),
        load_trust_store(args.trust_store),
        engine_from_args(args),
        at_unix=args.at_unix,
        expected_audience=args.audience,
    )


def add_engine_paths(parser):
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--approval-ledger", required=True, type=Path)
    parser.add_argument("--transaction-plan", required=True, type=Path)
    parser.add_argument("--transaction-journal", required=True, type=Path)


def build_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private-key", required=True, type=Path)
    keygen.add_argument("--public-key", required=True, type=Path)
    keygen.set_defaults(handler=command_keygen)

    trust = sub.add_parser("trust-init")
    trust.add_argument("--output", required=True, type=Path)
    trust.add_argument("--trust-store-id", required=True)
    trust.add_argument("--issuer-id", required=True)
    trust.add_argument("--key-id", required=True)
    trust.add_argument("--public-key", required=True, type=Path)
    trust.add_argument("--valid-from-unix", required=True, type=int)
    trust.add_argument("--valid-until-unix", required=True, type=int)
    trust.add_argument("--revoked-at-unix", type=int)
    trust.add_argument("--audience", action="append", required=True)
    trust.add_argument("--repository", action="append", required=True)
    trust.add_argument("--max-ttl-seconds", type=int, default=86400)
    trust.add_argument("--max-clock-skew-seconds", type=int, default=120)
    trust.set_defaults(handler=command_trust_init)

    issue = sub.add_parser("issue")
    add_engine_paths(issue)
    issue.add_argument("--private-key", required=True, type=Path)
    issue.add_argument("--output", required=True, type=Path)
    issue.add_argument("--capsule-id", required=True)
    issue.add_argument("--issuer-id", required=True)
    issue.add_argument("--subject-id", required=True)
    issue.add_argument("--key-id", required=True)
    issue.add_argument("--audience", required=True)
    issue.add_argument("--ttl-seconds", required=True, type=int)
    issue.add_argument("--issued-at-unix", type=int)
    issue.add_argument("--not-before-delay-seconds", type=int, default=0)
    issue.add_argument("--nonce")
    issue.set_defaults(handler=command_issue)

    verify = sub.add_parser("verify")
    verify.add_argument("--capsule", required=True, type=Path)
    verify.add_argument("--trust-store", required=True, type=Path)
    verify.add_argument("--at-unix", type=int)
    verify.add_argument("--audience")
    verify.add_argument("--repository")
    verify.add_argument("--plan-sha256")
    verify.add_argument("--policy-sha256")
    verify.add_argument("--output", type=Path)
    verify.set_defaults(handler=command_verify)

    verify_engine = sub.add_parser("verify-engine")
    add_engine_paths(verify_engine)
    verify_engine.add_argument("--capsule", required=True, type=Path)
    verify_engine.add_argument("--trust-store", required=True, type=Path)
    verify_engine.add_argument("--at-unix", type=int)
    verify_engine.add_argument("--audience", required=True)
    verify_engine.add_argument("--output", type=Path)
    verify_engine.set_defaults(handler=command_verify_engine)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = args.handler(args)
        output = getattr(args, "output", None)
        if args.command not in {"trust-init", "issue"}:
            write_json(output, result)
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CapsuleError, OSError, ValueError) as exc:
        print(f"chatgpt_governance_capsule: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
