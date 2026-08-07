# Identity, IdP, and KMS Attestation Bridge v1.1

## Purpose

v1.0 proves that a governance capsule was signed by a trusted key. v1.1 adds a provider-neutral evidence layer that binds that key operation to an authenticated organizational subject, tenant, role, session, repository, and time window.

```text
IdP identity assertion
+ KMS/HSM signing-operation attestation
+ Signed Governance Capsule v1.0
→ identity-bound governance verification receipt
```

This is an evidence and verification layer. It is not an identity provider, credential wallet, KMS client, GitHub executor, or authorization oracle.

## Schemas

- `liminal-idp-identity-assertion-v1.1`
- `liminal-kms-key-attestation-v1.1`
- `liminal-governance-identity-bundle-v1.1`
- `liminal-identity-trust-store-v1.1`
- `liminal-identity-verification-receipt-v1.1`

All signed documents use canonical JSON, SHA-256 digests, unpadded base64url signatures, Ed25519, and domain-separated signed messages.

## Identity assertion

The signed IdP assertion binds:

- exact HTTPS issuer and signing-key ID;
- subject, tenant, organization, audience, and repository;
- explicit roles, groups, authentication methods, and service-account flag;
- visible host-session digest;
- governance capsule nonce;
- issued, not-before, and expiry timestamps;
- explicit active identity status.

Roles and groups are accepted only as signed claims. The verifier never derives a role from an email address, display name, free text, or repository membership. MFA is satisfied only by an explicit `mfa` authentication-method claim when the trust store requires it.

No bearer token, cookie, refresh token, session cookie, or provider secret is stored in the assertion or verification receipt.

## KMS/HSM attestation

The signed provider receipt binds:

- provider and attestation-key IDs;
- subject and tenant;
- key resource and version IDs;
- governance capsule key ID and public-key fingerprint;
- sign operation and reported hardware-protection class;
- repository and capsule nonce;
- capsule payload and signature digests;
- active key status and validity window.

The reference signer is deliberately named `issue_fixture_kms_attestation`. It is a deterministic mock/provider contract fixture, not a claim that this repository invokes AWS KMS, Google Cloud KMS, Azure Key Vault, PKCS#11, or an HSM. A production host must perform the real provider call and translate provider evidence into this contract.

Private governance keys and KMS credentials never enter the evidence bundle.

## Cross-layer verification

`verify_identity_bundle` fails closed unless all of these remain true:

1. the v1.0 governance capsule verifies against its own trust store;
2. bundle capsule hashes match the exact capsule;
3. IdP and KMS signatures verify against pinned trust-store keys;
4. issuer, audience, tenant, repository, and hardware policy are allowed;
5. assertion and attestation are currently valid and their signing keys are active;
6. IdP subject, KMS subject, and capsule subject are identical;
7. IdP and KMS tenant are identical;
8. repository and capsule nonce are identical across all three layers;
9. KMS key ID and public-key fingerprint match the v1.0 capsule trust key;
10. KMS payload and signature digests match the exact capsule;
11. required roles and explicit MFA are present;
12. expected host session, tenant, and organization match;
13. optional authorization-time replay consumption has not already occurred.

`verify_identity_bundle_against_engine` additionally revalidates the capsule against the current v0.9 engine and transaction-journal ancestry.

## Replay model

Pure offline verification may be repeated safely. Authorization-time consumption is separate and host-owned. `IdentityReplayGuard` demonstrates the required fail-closed semantic for one process: the tuple `(issuer, subject, capsule nonce, session digest)` may be consumed only once.

A production deployment should persist the same replay key in a transactional store with an expiry at least as long as the assertion and capsule windows.

## Session wrapper

`IdentityAttestedGovernanceSession` sits above `GovernanceCapsuleSession`:

```text
IdentityAttestedGovernanceSession v1.1
→ GovernanceCapsuleSession v1.0
→ Policy & Approval Engine v0.9
→ Transaction Orchestrator v0.8
→ exact per-call write authorization
```

The first governed operation consumes replay state and activates the session. Every later governed boundary re-verifies current identity, KMS, capsule, trust, time, and engine state. Visible user messages, drafts, and claims remain recordable without turning identity verification into content access.

Identity verification does **not** create, infer, or replace v0.8 exact write authorization.

## CLI

```bash
python3 tools/chatgpt_identity_attestation.py trust-init \
  --spec identity-trust-spec.json \
  --output identity-trust-store.json

python3 tools/chatgpt_identity_attestation.py issue-fixture-idp \
  --private-key fixture-idp-private.pem \
  --claims idp-claims.json \
  --output identity-assertion.json

python3 tools/chatgpt_identity_attestation.py issue-fixture-kms \
  --private-key fixture-kms-private.pem \
  --claims kms-claims.json \
  --output kms-attestation.json

python3 tools/chatgpt_identity_attestation.py bundle \
  --identity-assertion identity-assertion.json \
  --kms-attestation kms-attestation.json \
  --capsule governance-capsule.json \
  --output identity-bundle.json

python3 tools/chatgpt_identity_attestation.py verify \
  --bundle identity-bundle.json \
  --identity-trust-store identity-trust-store.json \
  --capsule governance-capsule.json \
  --governance-trust-store governance-trust-store.json \
  --expected-session-sha256 "$SESSION_SHA256" \
  --expected-tenant-id tenant:liminal \
  --expected-organization-id org:liminal \
  --expected-role governance-approver
```

Contract, signature, trust, time, and I/O failures exit with status `2`.

## Explicit non-claims

v1.1 does not:

- authenticate a live browser or human by itself;
- contact an external IdP or validate a live OAuth/OIDC session;
- store or refresh bearer tokens and cookies;
- invoke a real KMS/HSM or prove hardware protection beyond signed provider evidence;
- own private keys, key rotation, or provider credentials;
- infer identity, role, authorization, consent, or organizational authority;
- grant GitHub write, merge, deployment, rollback, or delivery authority;
- access hidden messages, private reasoning, model weights, or hidden memory.

The host remains accountable for live authentication, provider invocation, replay persistence, exact write authorization, connector credentials, and final execution.
