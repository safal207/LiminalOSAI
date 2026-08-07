#!/usr/bin/env python3
"""CLI for provider-neutral IdP and KMS attestation bridge v1.1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sdk.liminal_governance_capsule import CapsuleError, load_capsule, load_trust_store
from sdk.liminal_identity_attestation import (
    AttestationError,
    IdentityAttestationBundle,
    IdentityTrustStore,
    issue_fixture_identity_assertion,
    issue_fixture_kms_attestation,
    load_identity_assertion,
    load_identity_bundle,
    load_identity_trust_store,
    load_kms_attestation,
    verify_identity_bundle,
    write_identity_bundle,
)


def read_json(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AttestationError(f"JSON document must be an object: {path}")
    return value


def write_new(path: str, value: dict[str, Any]) -> None:
    target = Path(path)
    if target.exists():
        raise AttestationError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    trust = commands.add_parser("trust-init", help="Build identity trust store from JSON spec")
    trust.add_argument("--spec", required=True)
    trust.add_argument("--output", required=True)

    idp = commands.add_parser(
        "issue-fixture-idp", help="Issue deterministic test IdP assertion"
    )
    idp.add_argument("--private-key", required=True)
    idp.add_argument("--claims", required=True)
    idp.add_argument("--output", required=True)

    kms = commands.add_parser(
        "issue-fixture-kms", help="Issue deterministic mock KMS receipt"
    )
    kms.add_argument("--private-key", required=True)
    kms.add_argument("--claims", required=True)
    kms.add_argument("--output", required=True)

    bundle = commands.add_parser("bundle", help="Build identity bundle")
    bundle.add_argument("--identity-assertion", required=True)
    bundle.add_argument("--kms-attestation", required=True)
    bundle.add_argument("--capsule", required=True)
    bundle.add_argument("--output", required=True)

    verify = commands.add_parser("verify", help="Verify full identity-bound capsule")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--identity-trust-store", required=True)
    verify.add_argument("--capsule", required=True)
    verify.add_argument("--governance-trust-store", required=True)
    verify.add_argument("--at-unix", type=int)
    verify.add_argument("--expected-session-sha256")
    verify.add_argument("--expected-tenant-id")
    verify.add_argument("--expected-organization-id")
    verify.add_argument("--expected-role", action="append", default=[])
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "trust-init":
        spec = read_json(args.spec)
        store = IdentityTrustStore.build(**spec)
        write_new(args.output, store.as_document())
        print(json.dumps({"trust_store_sha256": store.trust_store_sha256}, sort_keys=True))
        return 0
    if args.command == "issue-fixture-idp":
        result = issue_fixture_identity_assertion(
            private_key_path=args.private_key,
            output_path=args.output,
            **read_json(args.claims),
        )
        print(json.dumps({"assertion_sha256": result.assertion_sha256}, sort_keys=True))
        return 0
    if args.command == "issue-fixture-kms":
        result = issue_fixture_kms_attestation(
            private_key_path=args.private_key,
            output_path=args.output,
            **read_json(args.claims),
        )
        print(json.dumps({"attestation_sha256": result.attestation_sha256}, sort_keys=True))
        return 0
    if args.command == "bundle":
        capsule = load_capsule(args.capsule)
        result = IdentityAttestationBundle.build(
            identity_assertion=load_identity_assertion(args.identity_assertion),
            kms_attestation=load_kms_attestation(args.kms_attestation),
            capsule_sha256=capsule.capsule_sha256,
            capsule_payload_sha256=capsule.payload_sha256,
        )
        write_identity_bundle(result, args.output)
        print(json.dumps({"bundle_sha256": result.bundle_sha256}, sort_keys=True))
        return 0
    if args.command == "verify":
        result = verify_identity_bundle(
            load_identity_bundle(args.bundle),
            load_identity_trust_store(args.identity_trust_store),
            load_capsule(args.capsule),
            load_trust_store(args.governance_trust_store),
            at_unix=args.at_unix,
            expected_session_sha256=args.expected_session_sha256,
            expected_tenant_id=args.expected_tenant_id,
            expected_organization_id=args.expected_organization_id,
            expected_roles=args.expected_role,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    raise AssertionError("unreachable")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AttestationError, CapsuleError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
