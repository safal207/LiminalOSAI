# ChatGPT Signed Governance Capsule v1.0

`Signed Governance Capsule` is the portable cryptographic boundary above the v0.9 GitHub Transaction Policy Engine.

It signs the exact policy, plan, approval ledger head, and transaction-journal anchor that were reviewed before execution. A verifier can validate the capsule offline with an explicit trust store and OpenSSL; no GitHub access, connector credentials, or private key are required.

## Stack

```text
Signed Governance Capsule v1.0
→ Transaction Policy & Approval Engine v0.9
→ Transaction Orchestrator v0.8
→ Connected GitHub Runtime v0.7
→ GitHub Agent Bridge v0.6
→ Host Integration Adapter v0.5
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
```

## Cryptographic contract

- Algorithm: Ed25519 through the local OpenSSL executable.
- Signed bytes: `LIMINAL-GOVERNANCE-CAPSULE-V1\0 || canonical-json(claims)`.
- Encoding: strict unpadded base64url.
- Payload and complete capsule receive independent SHA-256 digests.
- The private key is read only during issuance and is never copied into the capsule, trust store, receipt, or evidence output.

## Signed claims

A capsule contains:

- `capsule_id`, `issuer_id`, `subject_id`, and `key_id`;
- algorithm and intended audience;
- `issued_at_unix`, `not_before_unix`, and `expires_at_unix`;
- a unique nonce;
- exact policy ID and transaction ID;
- repository, policy SHA, snapshot SHA, and plan SHA;
- approval-ledger head;
- transaction-journal anchor at issuance;
- v0.9 engine-evidence SHA;
- fixed `allow` and `ready` governance state.

The capsule cannot be issued for a denied policy or incomplete approvals.

## Trust store

The offline trust store binds an `(issuer_id, key_id)` pair to:

- one Ed25519 public key and its SHA-256;
- key validity window and optional revocation time;
- allowed audiences;
- allowed repositories;
- maximum capsule TTL;
- maximum accepted clock skew.

Trust-store documents are themselves canonical and SHA-protected. They contain public keys only.

## Time and revocation

Verification fails closed when:

- the capsule is not yet valid;
- the capsule has expired;
- TTL exceeds the trust-store limit or the hard 24-hour limit;
- the key was not valid at issuance;
- key validity has ended;
- the key is revoked;
- clock skew exceeds the configured bound.

Callers can supply an explicit Unix timestamp for deterministic CI and offline audit.

## Journal ancestry

The signed subject records the transaction-journal head at issuance. Execution may append new hash-chained entries, so verification checks that the signed anchor is still present in the current validated journal.

This allows a capsule to remain valid while the exact transaction advances, but rejects a replaced or unrelated journal.

The approval-ledger head must remain exactly unchanged. Any later approval or denial requires a new capsule.

## Separate boundaries

A valid signature does not create GitHub authority.

```text
valid capsule
+ policy decision ALLOW
+ approvals READY
+ exact per-call write authorization
+ v0.8 transaction controls
= connector call may begin
```

The capsule does not replace v0.8 write authorization, CI/head binding, protected-branch controls, connector permissions, or GitHub's expected-head merge check.

## Python API

```python
from sdk.liminal_governance_capsule import (
    GovernanceCapsuleSession,
    GovernanceTrustStore,
    issue_capsule,
    verify_capsule,
)
```

Issue from one ready v0.9 engine:

```python
capsule = issue_capsule(
    engine,
    private_key_path="issuer-private.pem",
    capsule_id="release-2026-08-06",
    issuer_id="corp-release-governance",
    subject_id="idp:user:alex",
    key_id="release-key-2026-q3",
    audience="github-transaction-executor",
    ttl_seconds=900,
    output_path="governance-capsule.json",
)
```

Verify offline:

```python
verification = verify_capsule(
    capsule_document,
    trust_store_document,
    expected_audience="github-transaction-executor",
    expected_repository="safal207/LiminalOSAI",
)
```

Gate a live v0.9 engine:

```python
session = GovernanceCapsuleSession(
    engine,
    capsule_path="governance-capsule.json",
    trust_store_path="governance-trust-store.json",
    expected_audience="github-transaction-executor",
)

session.authorize_step(
    step_id="merge",
    event_id="visible-auth-merge",
    text="Authorize the exact merge call under the reviewed capsule.",
)
session.run_next(connector)
```

## CLI

```bash
python3 tools/chatgpt_governance_capsule.py keygen \
  --private-key issuer-private.pem \
  --public-key issuer-public.pem

python3 tools/chatgpt_governance_capsule.py trust-init ...
python3 tools/chatgpt_governance_capsule.py issue ...
python3 tools/chatgpt_governance_capsule.py verify ...
python3 tools/chatgpt_governance_capsule.py verify-engine ...
```

The CLI returns exit code `2` for malformed, untrusted, expired, revoked, mismatched, or tampered artifacts.

## Identity boundary

`subject_id`, `issuer_id`, and `key_id` are explicit identifiers supplied by the host. v1.0 verifies the signature and trust-store mapping, but it does not authenticate a human, contact an IdP, validate an OAuth session, manage keys, or prove that a named person controlled the signing key.

An enterprise host should create these identifiers only after its own IdP and key-management checks.

## Failure model

The verifier fails closed for:

- unknown fields or schema drift;
- non-canonical signatures;
- payload or trust-store SHA mismatch;
- wrong key, issuer, audience, repository, policy, or plan;
- stale approval ledger;
- non-descendant transaction journal;
- missing OpenSSL;
- invalid Ed25519 signature;
- expired, premature, or revoked credentials.
