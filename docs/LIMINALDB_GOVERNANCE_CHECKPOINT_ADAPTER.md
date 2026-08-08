# LiminalDB Governance Checkpoint Adapter

Issues: LiminalOSAI #171, LiminalDB #112  
Pinned reference bridge: `safal207/LiminalDB@0cd6e77d52787bb36a97b75ba1a37cb027268eb3`

## Purpose

The Durable Cross-Process Governance Fence already owns the primary generation/CAS authority. This adapter adds an independent LiminalDB evidence mirror without moving authority into the evidence system.

```text
primary DurableGovernanceStore
        +
local durable mirror guard
        +
trusted LiminalDB checkpoint bridge
        ↓
checkpointed governance transition evidence
```

## Fail-closed ordering

Every mutating store call follows this order:

```text
mirror journal PENDING
        ↓
primary CAS mutation
        ↓
exact transition envelope from actual before/after state
        ↓
trusted LiminalDB bridge
        ↓
verify exact bundle bindings
        ↓
mirror journal ACKED / CLEAR
```

The `PENDING` marker is written **before** the primary mutation. This is intentionally conservative. If the process dies, the primary mutation fails, or the LiminalDB bridge is unavailable, restart still sees `PENDING` and refuses subsequent mirrored mutations until an explicit trusted reconciliation receipt clears the mirror guard.

There is no automatic timeout. Time passing is not evidence that the primary mutation or physical effect did not occur.

## Local mirror journal

`SQLiteCheckpointMirrorJournal` uses SQLite WAL, `synchronous=FULL` and `BEGIN IMMEDIATE` transactions. It keeps:

- one mutable current guard per governance root;
- append-only `PENDING`, `ACKED` and `RECONCILED` history events;
- exact pending-intent SHA-256;
- last accepted LiminalDB checkpoint reference;
- last evidence/reconciliation SHA-256.

A restart reconstructs the current guard from the same database. A pending guard cannot be cleared by a clock or model decision.

## Transition envelope

The adapter emits the exact schema consumed by the merged LiminalDB bridge:

`liminalosai-governance-transition-envelope-v0.1`

It binds:

- governance root SHA-256;
- transition kind;
- generation before/after;
- world SHA-256 before/after;
- reservation SHA-256 when applicable;
- effect/reservation payload SHA-256 when applicable;
- upstream primary/effect/reconciliation receipt SHA-256;
- trusted capture timestamp.

For `reserve` and `commit`, `operation_sha256` is the durable reservation-payload SHA-256. No raw operation text, argv or host data is mirrored.

## Trusted bridge boundary

The SDK receives an injected callback:

```text
bridge(envelope) -> LiminalDB checkpoint bundle
```

The SDK itself does not spawn a process, open a socket, read a signing key or write the LiminalDB ledger. Deployment decides how to connect to the trusted bridge.

The adapter verifies structural and exact-binding evidence from the bundle:

- echoed envelope body is exact;
- bridge receipt is `LOCAL_SIGNATURE_VERIFIED`;
- root/generation/world/reservation/operation/upstream fields match;
- checkpoint reference matches the receipt;
- checkpoint storage-root identity matches the LiminalOSAI root;
- event head, sequence, projection and snapshot digests match;
- signer/key identities match the trusted public-key record;
- checkpoint declares Ed25519 and correctly shaped signature/public-key material.

Cryptographic Ed25519 verification remains the trusted bridge's responsibility. The pinned LiminalDB implementation signs and calls its native `verify_signed_checkpoint` before returning success. LiminalOSAI does not duplicate Ed25519 verification with a second cryptographic implementation.

## Bridge failure after primary success

```text
PENDING
→ primary mutation succeeds
→ bridge fails / bundle mismatch
→ PENDING remains
→ all later mirrored mutations BLOCK
```

This prevents an evidence outage from silently degrading the governance path to an unmirrored mode.

The primary store state is not rolled back. The adapter does not claim transactional atomicity across SQLite CAS and the separate LiminalDB ledger. Instead it converts every ambiguous cross-system failure into a durable blocking state.

## Explicit mirror reconciliation

`reconcile_mirror` requires a non-zero trusted reconciliation receipt SHA-256. It only clears the local evidence-mirror guard; it does **not** alter the primary governance generation, capability state or physical runtime.

If the primary Durable Governance store itself has a stuck effect reservation, its separate `reconcile_reservation` path is still required. Mirror reconciliation cannot release primary authority.

## Cross-repository conformance

CI pins LiminalDB commit:

`0cd6e77d52787bb36a97b75ba1a37cb027268eb3`

and invokes its real `liminalosai_governance_checkpoint_bridge` example as the trusted callback while exercising the Python adapter. The reference bridge therefore proves the actual chain:

```text
Python DurableGovernanceStore
→ mirror PENDING
→ exact envelope
→ Rust TrustworthyTransitionLedger
→ snapshot
→ signed checkpoint
→ native signature verification
→ bundle verification in LiminalOSAI
→ mirror ACKED
```

## Nonclaims

This adapter does not provide:

- new capability/effect authority;
- distributed consensus;
- atomic commit across two independent storage engines;
- automatic rollback of physical effects;
- hostile/network-filesystem correctness;
- production KMS/HSM integration;
- independent Python-side Ed25519 verification;
- proof that the upstream governance decision was semantically correct;
- kernel/hypervisor enforcement.

Its claim is narrower: cooperating callers cannot silently continue mutating the governed world after an uncheckpointed or ambiguous mirror transition; explicit evidence-based reconciliation is required.
