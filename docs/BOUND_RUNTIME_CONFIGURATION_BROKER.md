# Bound Runtime Configuration Broker

## Security objective

A runtime mutation must not silently change the meaning of already-granted authority.

```text
trusted runtime state S0 / epoch N
→ runtime.configure capability
→ immutable config plan bound to S0 + N
→ trusted host apply
→ trusted state observation S1
→ verify exact expected S1
→ epoch N+1
→ revoke all authority from epoch N
→ digest-only receipt
```

The important boundary is temporal: a capability admitted for one runtime state must not remain usable after that runtime state changes.

## Plan binding

A `RuntimeConfigPlan` binds:

- exact operation ID;
- exact allowlisted `setting_keys`;
- trusted `before_state_sha256`;
- expected `after_state_sha256`;
- opaque `change_set_sha256`;
- trusted-host binding digest;
- monotonic `epoch_before`.

The runtime operation payload is the digest of this exact plan. The request cannot substitute a different change-set or before/after state after capability admission.

## Trusted state evidence

Raw environment values are not returned to the model-facing broker. The trusted host backend exposes only:

```text
host_binding_sha256
state_sha256
evidence_sha256
```

The evidence digest covers the exact host binding and state digest.

## Epoch invalidation

On a verified successful mutation:

```text
epoch N
→ S0 → S1
→ epoch N+1
→ revoke every still-active capability
```

This is intentionally conservative. Existing capability contracts do not yet carry a runtime epoch field, so revocation is the fail-safe bridge: old contracts cannot be re-admitted under the same capability ID after they are revoked.

New authority must be issued after the runtime mutation and therefore after the new epoch is established.

## Fail-closed mutation handling

If a host mutation is admitted but the exact post-state cannot be verified, the broker assumes the runtime may have changed:

```text
admitted mutation
→ host error / forged evidence / after-state mismatch
→ advance epoch
→ revoke all old authority
→ mark runtime state tainted
→ BLOCK further runtime.configure
```

This prevents a partial configuration failure from preserving authority that was valid only for the prior state.

## Replay and stale-state protection

The broker rejects before host mutation:

- completed-plan replay;
- stale runtime epoch;
- stale trusted before-state digest;
- host-binding mismatch;
- operation/plan ID mismatch;
- setting-scope mismatch;
- payload/plan mismatch;
- mutation attempts while runtime state is tainted.

Containment remains authoritative: if `RuntimeMediator` is in containment, the configuration backend is not invoked.

## Receipt

The digest-only receipt includes:

- plan SHA-256;
- before/after runtime-state SHA-256;
- before/after epoch;
- mediation receipt SHA-256;
- trusted host evidence SHA-256;
- count and digest of revoked authority;
- decision/outcome/reason codes;
- canonical receipt SHA-256.

It excludes raw environment values, PATH contents, proxy credentials, mount paths, secrets and command lines.

## Authority boundary

This layer does not expose shell execution, direct filesystem mutation, direct network reconfiguration, credential material, kernel controls, container-runtime controls or policy mutation to the model-facing SDK. Concrete configuration application remains a trusted-host callback.

## Non-goals

- live package download/install;
- arbitrary environment variable pass-through;
- secret export;
- generic mount namespace mutation;
- branch protection or repository governance.

Refs: #157, #153, #146, #139, #134.
