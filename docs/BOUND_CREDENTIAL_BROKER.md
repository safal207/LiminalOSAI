# Bound Credential Broker MVP

## Purpose

The credential broker prevents model-visible secret handling. An agent may request *use* of a known credential reference, but raw credential material is resolved only inside a trusted host adapter after all governance checks pass.

```text
credential use intent
→ credential.access capability
→ exact host binding
→ short-lived opaque lease
→ trusted provider
→ trusted injection sink
→ digest-only receipt
```

## Two independent gates

A `credential.access` capability is necessary but not sufficient.

1. **Capability gate** — binds subject, credential reference, purpose, policy, TTL and use count.
2. **Host binding gate** — binds credential reference to exact purpose, HTTPS DNS name, port and injection target.

The binding is host-provisioned. The agent cannot widen it through prompt text.

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

## Lease lifecycle

```text
authorize
→ capability use committed
→ opaque lease issued (<=30 s)
→ re-check source capability active
→ consume lease BEFORE provider access
→ provider resolves secret
→ sink receives secret
→ lease can never be reused
```

Revocation or expiry after lease issuance but before consumption blocks secret resolution.

Provider or sink failure does **not** reactivate the lease. A fresh governed request is required.

## Secret boundary

The model-facing package `sdk/liminal_credential_broker`:

- has no Vault/KMS/Secrets Manager client;
- has no secret provider callback;
- never returns credential material;
- stores only credential-reference digests, binding digests and authorization receipts.

The trusted adapter `adapters/credentials/liminal_credential_injector.py` may receive a raw secret from an injected provider and passes it directly to an injected sink. Raw secret values and exception text are excluded from receipts.

Python does not guarantee physical memory zeroization; the adapter drops its application-level reference immediately after sink completion. A stronger provider/backend can add mlock/zeroization or hardware-backed operations later.

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
- source capability revoked/expired after lease issuance.

## Explicit nonclaims

This MVP is not a secret store and does not discover or rotate credentials. It does not create network authority, does not guarantee process-memory zeroization, and does not protect against compromise of the trusted provider/sink host boundary.

Repository branch protection remains separately tracked in #134.
