# Process Tree & Active Containment Enforcement

## Security objective

A governed execution session must not leave a surviving descendant process after its authority is revoked or the causal detector triggers `CONTAIN`.

```text
process.execute
→ trusted host creates execution-session identity
→ root process identity is bound outside model context
→ descendants remain in one verified lineage
→ DETECT / CONTAIN
→ freeze session tree + close egress
→ revoke live capabilities
→ quiesce/terminate session tree
→ verify zero survivors
→ seal evidence
→ REVIEW
```

## Why this exists

A policy decision that blocks future API calls is insufficient if an already-running child or background descendant can continue acting. The containment boundary therefore needs a post-revocation process-tree proof, not just a boolean `frozen=true` claim.

## Trust boundary

The SDK never accepts an OS PID, process handle, command line, environment, signal target or container-runtime operation from the model. It receives only opaque trusted-host process identities and digest-safe observations from a backend bound to one execution session.

A backend observation contains:

- execution-session ID;
- bound root process identity;
- backend-binding SHA-256;
- opaque process identity + parent relation;
- trusted identity digest;
- state: `running | frozen | terminated`;
- deterministic process-tree digest and evidence digest.

The same process identities must remain visible as tombstones through termination. A backend cannot prove success by silently removing a process from the final snapshot.

## Fail-closed invariants

The supervisor rejects:

- duplicate identities;
- missing or parented root;
- unknown parents;
- lineage cycles;
- nodes not descended from the bound root;
- cross-session observations/actions;
- backend-binding drift;
- trusted process-identity drift between snapshots;
- action evidence whose digest is invalid;
- action receipts not bound to the exact resulting tree digest;
- freeze that leaves any process `running`;
- termination that reports impossible affected counts;
- any final surviving process.

## Phase 4 integration

`ContainmentCoordinator` keeps the existing state machine:

```text
DETECT → FREEZE → REVOKE → SEAL → SNAPSHOT → REVIEW
```

When a process-tree quiescence hook is configured, the concrete ordering inside the boundary is:

```text
FREEZE:
  freeze process tree
  close egress

REVOKE:
  revoke all live capabilities

between REVOKE and SEAL:
  terminate/quiesce frozen process tree
  require decision=ALLOW
  require surviving_count=0

SEAL:
  bind the process-tree containment receipt digest into incident evidence
```

A surviving or unverifiable descendant becomes a containment partial failure. Phase 4 therefore remains in `REVIEW`, and explicit human release is blocked until the failure is resolved.

## Receipt

The process-tree containment receipt is digest-only and includes:

- session/root identity;
- backend-binding digest;
- before/frozen/after tree digests;
- observed, terminated and surviving counts;
- freeze/terminate backend evidence digests;
- `ALLOW | BLOCK` decision;
- canonical receipt SHA-256.

It deliberately excludes raw PIDs, command lines, environment variables, stdout/stderr and secrets.

## Explicit nonclaims

This layer is not a kernel sandbox, eBPF/seccomp implementation, container-runtime exploit defense, malware detector or proof that the host kernel cannot be compromised. Concrete OS/container process control belongs to the trusted host backend. The SDK defines and verifies the bounded evidence contract and integrates its result into containment.

Refs: #103, #131, #140, #152, #153.
