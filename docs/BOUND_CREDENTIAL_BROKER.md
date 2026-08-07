# Bound Credential Broker MVP

## Purpose

The credential broker prevents model-visible secret handling. An agent may request *use* of a known credential reference, but raw credential material is resolved only inside a trusted host adapter after all governance checks pass.

```text
credential use intent
→ credential.access capability
→ immutable host binding
→ host-controlled decision time
→ short-lived opaque lease
→ authenticated trusted adapter
→ trusted secret provider
→ trusted injection sink
→ digest-only receipt
```

## Host configuration happens before model exposure

Credential bindings are loaded only during `CredentialBroker` construction. There is intentionally no post-construction `register_binding()` API.

A host constructs the broker with:

- the existing `CapabilityBroker`;
- an immutable list of exact credential bindings;
- a high-entropy adapter token shared only with the trusted injection adapter;
- lease TTL <= 30 seconds;
- a host clock (system clock by default, injectable for deterministic tests).

After construction the binding map is read-only. A binding SHA proves integrity, not provenance; provenance comes from the host-only construction boundary.

## Two independent gates

A `credential.access` capability is necessary but not sufficient.

1. **Capability gate** — binds subject, credential reference, purpose, policy, TTL and use count.
2. **Host binding gate** — binds credential reference to exact purpose, HTTPS DNS name, port and injection target.

Example binding:

```text
credential: cred:payments
purpose: payments_api
protocol: https
domain: api.example.com
port: 443
injection target: http_header:authorization
```

Wildcards and plaintext HTTP are rejected in the MVP.

## Trusted time

`CredentialUseRequest.at_unix` is retained only as requester-declared evidence. It is not used for capability expiry, lease issuance, lease expiry or lease consumption.

All security decisions use the broker's host-controlled clock:

```text
request-declared time ──> evidence only
host clock             ──> authorization / TTL / expiry / revocation decisions
```

Backdating a request therefore cannot resurrect an expired capability or lease.

## Atomic state transitions

Credential broker state is guarded by one instance-level reentrant lock. The lock covers:

- containment transitions;
- call-ID replay check + commit;
- capability admission for credential use;
- lease creation;
- receipt sequencing;
- lease authentication/check/consumption.

This prevents concurrent requests from both passing replay checks or creating duplicate logical leases/receipt sequence positions.

## Lease lifecycle

```text
authorize using host clock
→ capability use committed
→ opaque lease issued (<=30 s)
→ trusted adapter authenticates
→ source capability re-checked active
→ consume lease BEFORE provider access
→ provider resolves secret
→ sink receives secret
→ lease can never be reused
```

Revocation or expiry after lease issuance but before consumption blocks secret resolution.

Provider or sink failure does **not** reactivate the lease. A fresh governed request is required.

A model-facing caller that learns the opaque lease ID still cannot consume it without the adapter-held token.

## Secret boundary

The model-facing package `sdk/liminal_credential_broker`:

- has no Vault/KMS/Secrets Manager client;
- has no secret provider callback;
- never returns credential material;
- stores only credential-reference digests, binding digests and authorization receipts;
- exports read-only authority metadata; receipt verification uses a private immutable authority definition.

The trusted adapter `adapters/credentials/liminal_credential_injector.py` may receive a raw secret from an injected provider and passes it directly to an injected sink. Raw secret values and exception text are excluded from receipts.

Python does not guarantee physical memory zeroization; the adapter drops its application-level reference immediately after sink completion. A stronger provider/backend can add mlock/zeroization or hardware-backed operations later.

## Receipt verification

Authorization and injection verifiers require the **exact** schema key set before digest validation. Extra fields are rejected even if a caller recomputes the public SHA-256 digest. This prevents a digest-valid document from smuggling arbitrary or secret-bearing fields through the verifier.

## Network authority remains separate

A credential lease does **not** authorize network access.

```text
credential authorization ≠ network authorization
```

A real HTTP request must still pass through the existing Egress Gateway with its own `network.connect_domain` capability, DNS checks, redirect checks and transport boundary. A later integration step can combine both gates into a single credentialed-egress host adapter.

## Fail-closed cases

The provider is never invoked when any of the following is true:

- no matching credential capability;
- capability revoked, expired or exhausted;
- containment active;
- wrong purpose;
- wrong destination domain or port;
- wrong injection target;
- replayed call ID;
- replayed or expired lease;
- source capability revoked/expired after lease issuance;
- trusted adapter authentication fails;
- host clock regresses or returns an invalid value.

## CI hardening

The dedicated workflow also runs when shared capability or Phase 0 contract code changes. Checkout credentials are not persisted into PR-controlled test/build steps.

## Explicit nonclaims

This MVP is not a secret store and does not discover or rotate credentials. It does not create network authority, does not guarantee process-memory zeroization, and does not protect against compromise of the trusted provider/sink host boundary or theft of the adapter token.

Repository branch protection remains separately tracked in #134.
