# Epoch-Bound Capability Contracts

## Security objective

A capability is not valid merely because its subject, scope, policy, TTL and use count still match. It is valid only in the exact trusted runtime world for which it was issued.

```text
trusted runtime state
  epoch = N
  state_sha256 = S
        ↓
base CapabilityContract
        ↓
EpochBoundCapabilityContract
  base_contract_sha256
  runtime_epoch = N
  runtime_state_sha256 = S
        ↓
admission
        ↓
authorization re-check
```

If the runtime becomes `N+1/S2`, the old bound contract is stale even if its original TTL and use budget have not expired.

## Why this is a separate wrapper

The existing `liminal-capability-contract-v0.1` remains unchanged. Silent schema expansion would change the meaning of already-issued contracts and make older evidence ambiguous. This layer therefore wraps the exact existing base contract and cryptographically binds the wrapper to:

- the full verified base capability contract;
- the trusted runtime epoch;
- the trusted runtime-state SHA-256;
- the epoch-binding authority profile.

The wrapper hash is deterministic and independently verifiable.

## Trusted runtime source

The model does not supply the authoritative epoch or runtime-state digest. `EpochBoundCapabilityBroker` reads them from a trusted `RuntimeEpochProvider`.

The current `BoundRuntimeConfigBroker` already exposes the required state surface:

```text
state_document()
  epoch
  state_sha256
  tainted
```

The epoch-bound broker hashes this bounded snapshot before admission/use decisions. No raw environment values, PATH contents, proxy strings, mount paths or secrets are required.

## Admission invariant

```text
bound epoch/state
      ==
trusted current epoch/state
      ↓
base CapabilityBroker.admit()
```

Admission is blocked when:

- runtime state is tainted;
- epoch is stale;
- state digest is stale;
- a duplicate capability ID is presented with a different epoch binding;
- a delegated child is not bound to the same runtime world as its parent;
- the underlying capability broker rejects the base contract.

## Use invariant

Before every `authorize()` call the wrapper reconciles the underlying broker:

```text
active delegate authority
        ↓
known epoch-bound contract?
  NO → revoke
  YES
        ↓
current epoch/state still match?
  NO → revoke
  YES → keep eligible
```

Only after that reconciliation does the existing CapabilityBroker evaluate subject, capability type, policy, scope, validity window and use count.

The action delegated to the base broker is augmented by the **trusted** runtime epoch, runtime-state digest and runtime-snapshot digest. Therefore the underlying causal use receipt is itself bound to the runtime world in which the action was admitted.

## Runtime configuration rollover

The layer composes with `BoundRuntimeConfigBroker`:

```text
capability bound to epoch N / state S0
        ↓
runtime.configure
        ↓
exact S0 → S1 transition
        ↓
runtime epoch N+1
        ↓
old authority revoked by runtime-config broker
        +
old epoch-bound contracts fail independent use-time validation
```

This is deliberate defense in depth. Revocation is the immediate lifecycle response; epoch binding is the cryptographic validity rule.

## Delegation

A child capability that references a parent capability ID must have an epoch-bound parent and must use the exact same runtime epoch and runtime-state digest. A child cannot cross a runtime boundary even if its nominal scope is narrower.

During use-time reconciliation, a child whose underlying parent is no longer active is revoked before it can authorize a new action.

## Evidence

Epoch-bound decision receipts contain only bounded identifiers and digests:

- capability ID when allowed;
- base capability contract SHA-256;
- epoch-bound contract SHA-256;
- bound and observed runtime epochs;
- bound and observed runtime-state SHA-256 digests;
- trusted runtime snapshot SHA-256;
- underlying capability decision receipt SHA-256;
- ALLOW/BLOCK and reason codes.

They do not contain raw runtime configuration or secret material.

## Nonclaims

This layer does **not**:

- grant a new capability type;
- mutate runtime configuration;
- execute processes;
- open sockets;
- access credentials;
- replace containment;
- provide kernel/eBPF/seccomp enforcement;
- prove a compromised host or runtime is trustworthy.

It restricts the semantic lifetime of authority already defined elsewhere.

## Security invariant

> A capability issued for runtime world `(epoch=N, state=S)` cannot authorize an effect in runtime world `(epoch!=N or state!=S)`; stale or unbound active authority is revoked before delegation.

Refs: #124, #138, #153, #157, #159, #134.
