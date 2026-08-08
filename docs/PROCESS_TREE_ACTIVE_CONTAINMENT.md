# Process Tree & Active Containment Enforcement

## Security objective

A governed execution session must not leave a surviving descendant process after its authority is revoked or the causal detector triggers `CONTAIN`.

```text
process.execute
→ trusted execution-session identity
→ root + descendants observed outside model authority
→ DETECT / CONTAIN
→ freeze execution session(s) + independently close egress
→ revoke live capabilities
→ terminate/quiesce frozen session(s)
→ verify zero survivors
→ verify containment receipt
→ seal evidence
→ REVIEW
```

A policy decision that blocks future API calls is insufficient if an already-running child or background descendant can continue acting. The control plane therefore requires post-revocation process evidence, not merely `blocked=true`.

## Two complementary process profiles

### 1. `liminal_process_tree` — execution-session control

This layer tracks opaque governed execution sessions and coordinates trusted host callbacks across one or more sessions. Its key invariant is temporal:

```text
FREEZE only
→ capability REVOKE
→ QUIESCE / TERMINATE
```

`freeze_all()` is forbidden from terminating the workload. `quiesce_all()` is the post-revocation path and fails closed if a session is still executing because the FREEZE stage was skipped. Emergency exact-session cleanup used for timeout/adapter failure remains a separate `quiesce_session()` path.

The session receipt records only bounded counts and digests: active sessions before containment, terminated sessions, already-absent sessions, survivors, before/after roots and failure codes.

### 2. `liminal_process_lineage` — explicit root/descendant proof

For trusted backends capable of exposing fine-grained process lineage, this stronger profile binds:

- execution-session ID;
- bound root process identity;
- backend-binding SHA-256;
- opaque process identity + parent relation;
- trusted identity digest;
- state: `running | frozen | terminated`;
- deterministic tree digest and backend evidence digest.

The same opaque process identities must remain visible as terminated tombstones through the final observation. A backend cannot prove success merely by deleting a node from the snapshot.

`liminal_process_tree_containment` remains only as a compatibility import shim to the lineage profile; it defines no competing schema or authority surface.

## Fail-closed lineage invariants

The lineage verifier rejects:

- duplicate identities;
- missing or parented root;
- unknown parents;
- lineage cycles;
- nodes not descended from the bound root;
- cross-session observations/actions;
- backend-binding drift;
- trusted process-identity drift between snapshots;
- forged action evidence;
- action receipts not bound to the exact resulting tree digest;
- freeze that leaves a process executing;
- impossible affected counts;
- any final surviving process.

## Concrete Docker backend

The trusted Docker adapter assigns an opaque container/session identity and, for a running governed container, derives explicit root/child lineage from trusted host observations. Raw host PIDs stay inside the adapter and are converted to session-bound opaque process IDs before reaching the verifier.

The Docker backend supports:

```text
inspect exact named session
→ derive opaque root/child lineage
→ docker pause exact session
→ verify frozen lineage
→ docker rm -f exact session
→ retain terminated tombstones
→ verify container absence
→ digest-only lineage receipt
```

Timeout cleanup also targets the exact trusted container name and verifies that it no longer exists.

## Phase 4 integration

`ContainmentCoordinator` preserves the state machine:

```text
DETECT → FREEZE → REVOKE → SEAL → SNAPSHOT → REVIEW
```

Inside those states, process enforcement is ordered as:

```text
DETECT

FREEZE:
  attempt process/session freeze
  independently attempt egress closure

REVOKE:
  revoke all live sensitive capabilities

between REVOKE and SEAL:
  terminate/quiesce frozen process state
  cryptographically verify supported quiescence receipt
  require zero survivors

SEAL:
  bind the verified quiescence receipt digest into incident evidence
```

Freeze and egress closure are attempted independently: failure of one does not suppress the other. A surviving process, missing freeze, unverifiable receipt, backend mismatch or other quiescence failure becomes a containment partial failure. The coordinator remains in `REVIEW`, and explicit human release is blocked while partial failures remain.

## Authority boundary

The model-facing SDK never receives OS PIDs, process handles, command lines, environment variables, signal targets or direct Docker/container-runtime authority. Concrete OS/container control belongs to a trusted host backend.

This work does **not** claim kernel sandboxing, eBPF/seccomp enforcement, container-runtime exploit resistance, malware detection or proof that a compromised host kernel can be contained by user-space receipts.

## Security invariant

> Once an execution session loses authority, no process descended from that governed session may continue operating without the containment evidence recording the failure and blocking release.

Refs: #103, #131, #140, #152, #153, #134.
