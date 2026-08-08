# Durable Cross-Process Governance Commit Fence

Issue: #169

## Purpose

The existing `RuntimeCommitFence` serializes objective, causal, runtime and effect transitions inside one trusted host process. That is necessary but insufficient when several cooperating processes can act on the same governed runtime.

This layer adds a durable generation/CAS protocol around the already-existing Causal / Trajectory-Bound Effect Commit stack.

```text
durable world
  generation G
  objective state O
  causal state C
  runtime context R
        ↓
exact inner causal/objective/runtime authorization
        ↓
CAS reserve (G,O,C,R)
        ↓
durable reservation
        ↓
re-check local world + durable reservation
        ↓
inner physical effect
        ↓
post-effect causal world C'
        ↓
CAS commit reservation
        ↓
generation G+1 / world O,C',R
```

## Storage boundary

`DurableGovernanceStore` is a backend-neutral protocol. The effect broker depends on that protocol rather than a specific database.

`SQLiteGovernanceStore` is the reference implementation used for executable cross-process evidence. It uses:

- SQLite transactions with `BEGIN IMMEDIATE`;
- WAL journal mode;
- `synchronous=FULL`;
- one durable governance row per `root_id`;
- compare-and-swap checks on generation and world digest;
- a single durable reservation slot per root.

This does **not** replace LiminalDB. LiminalDB already proves a different durability surface: crash-consistent transition WAL/snapshots, signed checkpoints and local single-writer ownership. A future adapter can implement `DurableGovernanceStore` using LiminalDB while keeping the governance protocol unchanged.

## Durable world

A `GovernanceWorld` contains only digests:

```text
objective_state_sha256
causal_state_sha256
runtime_context_sha256
        ↓
world_sha256
```

The default provider hashes the current trusted Objective Integrity state, Causal Trajectory state and full runtime-context document. Raw objective text, argv, environment, credentials, paths and evaluator state are not persisted by this layer.

## Reservation protocol

Effect issuance proceeds under the existing local `RuntimeCommitFence`:

1. Read the durable state.
2. Require no active reservation.
3. Read the local objective/causal/runtime world.
4. Require local `world_sha256 == durable world_sha256`.
5. Issue the existing Causal-Bound Effect lease.
6. Build a digest-only reservation payload binding:
   - root digest;
   - generation;
   - durable world digest;
   - operation ID digest;
   - runtime kind;
   - scope digest;
   - payload digest;
   - capability receipt digest;
   - causal authorization receipt digest.
7. Atomically reserve the durable world using generation/world CAS.

A second process using the same durable root cannot reserve another effect or mutate the world while the reservation is active.

## No automatic expiry

Reservations have **no automatic timeout** at the durable layer.

This is deliberate:

```text
process reserves
→ physical effect may or may not happen
→ process dies
```

Time passing is not evidence that the physical effect did not happen. Automatically expiring the reservation could resurrect authority in an unknown world.

Therefore a crash-stuck reservation blocks future governed mutations/effects until explicit trusted reconciliation.

## Effect commit

Immediately before handing control to the existing inner effect stack, the broker verifies:

```text
durable generation == bound generation
durable world == bound world
reservation ID == bound reservation
reservation payload == bound payload
local world == durable world
```

The in-process durable lease handle is then burned. The durable reservation remains active while the inner Causal-Bound Effect stack performs its own final checks and host callback.

On clean inner success:

```text
inner effect succeeds
→ exact causal event appended by inner layer
→ recompute local governance world
→ durable commit_effect CAS
→ generation G+1
→ publish post-effect world
→ clear reservation
→ clean success receipt
```

## Failure semantics

### Inner effect failure or uncertainty

If the inner effect stack raises after the durable reservation exists, the reservation remains active:

```text
reservation
→ inner effect failure / unknown partial effect
→ EFFECT_FAILED_RESERVATION_STUCK
→ no automatic release
```

This is conservative because a failing host callback can have produced a partial external effect.

### Effect succeeds but durable finalization fails

```text
physical effect succeeds
→ causal event is committed locally
→ durable generation update fails
→ EFFECT_SUCCEEDED_DURABLE_COMMIT_FAILED
→ reservation remains active
→ fail closed
```

The layer does not claim automatic rollback of the physical effect.

### Explicit reconciliation

`reconcile_reservation` requires:

- exact root;
- exact generation;
- exact pre-reconciliation world;
- exact reservation identifier;
- a new trusted world document;
- a non-zero external reconciliation receipt digest.

Reconciliation advances the generation and clears the reservation. There is no model-controlled or time-based auto-release path.

## Cross-process evidence

The test suite uses real `multiprocessing.Process` workers with independent SQLite connections.

It proves:

1. a committed reservation survives abrupt `os._exit` of its process;
2. a second process cannot mutate the governance world while that reservation is active;
3. a second effect reservation is rejected while the crashed reservation remains;
4. explicit reconciliation advances the generation and releases the root;
5. stale generations cannot mutate a newer world.

These tests establish cross-process coordination on the local SQLite/filesystem boundary used by CI. They do not establish distributed consensus.

## Composition

The high-assurance path is now:

```text
Objective Integrity
      ↓
Epoch-Bound Capability
      ↓
Objective-Bound Effect
      ↓
Causal / Trajectory-Bound Effect
      ↓
Durable Governance Generation + Reservation
      ↓
Physical Effect
      ↓
Durable generation advance
```

The new layer does not weaken any existing inner check. It only adds a durable outer precondition and post-effect acknowledgement.

## Authority boundary

This component does **not**:

- grant capabilities;
- fabricate objective or causal evidence;
- mutate runtime configuration directly;
- create network or credential authority;
- execute containment or human release;
- automatically roll back physical effects;
- provide distributed consensus;
- prove correctness on hostile/network filesystems;
- provide syscall-complete, kernel, eBPF, seccomp or hypervisor enforcement.

Its claim is narrower:

> For cooperating processes using the same durable governance root, an effect cannot obtain a second concurrent governance reservation, and an uncertain post-reservation process failure cannot silently restore authority without an explicit generation-advancing reconciliation.

Refs: #129, #151, #157, #159, #161, #163, #165, #167, #169, #134.
