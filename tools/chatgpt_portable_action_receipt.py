#!/usr/bin/env python3
"""Verify and project Portable Action Receipt v1.2 artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sdk.liminal_governance_capsule import GovernanceTrustStore
from sdk.liminal_identity_attestation import IdentityTrustStore
from sdk.liminal_portable_receipt import (
    ReceiptError,
    build_rinse_supersession_fixture,
    load_portable_receipt,
    project_cml_memory_pack,
    project_liminaldb_event_inputs,
    project_proofpath_authorization_records,
    project_rinse_trace_event,
    verify_portable_receipt,
)


def read_json(path: str, name: str):
    target = Path(path)
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReceiptError(f"{name} does not exist: {target}") from exc
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"{name} is not valid JSON: {exc}") from exc


def write_json(path: str | None, value) -> None:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if path is None:
        sys.stdout.write(text)
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def command_verify(args: argparse.Namespace) -> None:
    receipt = load_portable_receipt(args.receipt)
    governance = GovernanceTrustStore.from_document(
        read_json(args.governance_trust_store, "governance trust store")
    )
    identity = IdentityTrustStore.from_document(
        read_json(args.identity_trust_store, "identity trust store")
    )
    result = verify_portable_receipt(
        receipt,
        governance,
        identity,
        expected_repository=args.expected_repository,
        expected_source_head_oid=args.expected_source_head,
        expected_result_head_oid=args.expected_result_head,
    )
    write_json(args.output, result)


def command_project(args: argparse.Namespace) -> None:
    receipt = load_portable_receipt(args.receipt)
    if args.format == "proofpath":
        value = project_proofpath_authorization_records(receipt)
    elif args.format == "cml":
        value = project_cml_memory_pack(
            receipt,
            source_commit=args.source_commit,
            visibility=args.visibility,
        )
    elif args.format == "liminaldb":
        value = project_liminaldb_event_inputs(receipt)
    elif args.format == "rinse-trace":
        value = project_rinse_trace_event(receipt)
    elif args.format == "rinse-supersession":
        value = build_rinse_supersession_fixture(receipt)
    else:
        raise ReceiptError(f"unsupported projection format: {args.format}")
    write_json(args.output, value)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a portable receipt offline")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--governance-trust-store", required=True)
    verify.add_argument("--identity-trust-store", required=True)
    verify.add_argument("--expected-repository")
    verify.add_argument("--expected-source-head")
    verify.add_argument("--expected-result-head")
    verify.add_argument("--output")
    verify.set_defaults(handler=command_verify)

    project = sub.add_parser("project", help="create an evidence-only ecosystem projection")
    project.add_argument("--receipt", required=True)
    project.add_argument(
        "--format",
        required=True,
        choices=["proofpath", "cml", "liminaldb", "rinse-trace", "rinse-supersession"],
    )
    project.add_argument("--source-commit")
    project.add_argument("--visibility", default="partner")
    project.add_argument("--output")
    project.set_defaults(handler=command_project)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (ReceiptError, ValueError, OSError) as exc:
        print(f"portable receipt error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
