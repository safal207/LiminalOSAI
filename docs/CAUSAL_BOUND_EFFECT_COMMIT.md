# Causal / Trajectory-Bound Effect Commit

Issue: #167

## Purpose

Phase 3 already detects dangerous composition of individually permitted actions. Objective-Bound Effect Commit already binds an effect to a clean objective-integrity head and exact runtime world. This layer closes the remaining gap between a causal-risk decision and the physical host effect.

```text
verified causal trajectory C
        +
exact proposed next effect E
        ↓
project C + E
        ↓
require ALLOW
        ↓
causal one-time lease
        ↓
Objective-Bound Effect lease
        ↓
RuntimeCommitFence
        ↓
re-check C and project C + E
        ↓
physical effect
        ↓
append exact E
```

## Why projection matters

Checking only the current trajectory is insufficient. The next locally authorized action can itself create the dangerous composition.

```text
credential.access                       current trajectory: ALLOW
→ proposed process.spawn_child          projected trajectory: REVISE
→ host callback                         BLOCKED before effect
```

The broker therefore requires both the current trajectory and the trajectory projected with the exact proposed event to remain `ALLOW`.

## Fenced trajectory ledger

`FencedTrajectoryRiskLedger` wraps the existing Phase-3 `TrajectoryEvent` and `analyze_trajectory` logic. It does not replace or mutate the Phase-3 schema.

The ledger:

- stores an append-only verified event chain;
- preserves the exact Phase-3 event digest and chain rules;
- recomputes the deterministic Phase-3 decision after each append;
- exposes only bounded head/graph/decision/risk evidence;
- projects an exact next event without committing it;
- requires an injected trusted event verifier;
- serializes append, projection and state reads through the same `RuntimeCommitFence` used by effect commit.

The injected verifier is important: event structure and hashes prove integrity, not truth. Privilege/capability semantics remain a trusted-host attestation problem.

## Proposal binding

`build_effect_trajectory_event()` creates the canonical digest-only proposal shape used by the reference mediator. The proposal binds:

- operation ID digest;
- runtime kind;
- normalized scope digest;
- payload digest;
- capability decision receipt digest;
- subject and capability ID;
- Phase-3 event kind;
- privilege before/after from the normalized `RuntimeOperation`;
- exact next sequence and previous causal head.

The broker independently verifies these bindings before asking the trajectory ledger to project the event.

## Lease binding

A causal lease binds:

- current trajectory head;
- current graph SHA-256;
- current Phase-3 decision receipt SHA-256;
- current trajectory state SHA-256;
- exact proposed event SHA-256;
- projected graph SHA-256;
- projected decision receipt SHA-256;
- operation kind, normalized scope digest and payload digest;
- capability decision receipt digest;
- inner Objective-Bound Effect authorization receipt digest;
- inherited bounded issue/expiry time.

Both the current and projected decisions must be `ALLOW`.

## Final commit

Immediately before the host callback, while holding the shared fence, the broker verifies:

```text
current head == bound head
current graph == bound graph
current decision receipt == bound decision receipt
current state == bound state
current decision == ALLOW
project(current + proposed event) == bound projected graph/receipt
projected decision == ALLOW
```

The causal lease is then burned exactly once and the existing Objective-Bound Effect lease is consumed while the same re-entrant fence remains held.

On success, the exact proposed event is appended before releasing the fence. A concurrent trusted trajectory append cannot interleave between the final check and the physical effect.

## Evidence failure after effect

A physical effect can succeed while post-effect evidence persistence fails. That condition is not reported as a clean success:

```text
host effect succeeds
→ exact proposed event append fails
→ EFFECT_SUCCEEDED_EVIDENCE_FAILED
→ fail closed to caller
```

This MVP does not claim automatic rollback of the physical effect. Recovery/containment must treat this as an evidence-integrity failure.

## Fail-closed conditions

The host callback is not invoked when:

- current causal decision is non-ALLOW;
- projected causal decision is REVISE/BLOCK/CONTAIN;
- a new verified event changes the causal head after lease issuance;
- graph/decision/state evidence changes;
- proposal sequence or previous head is stale;
- proposal kind/subject/capability/action/privilege binding is wrong;
- trusted event verification fails;
- causal lease is expired or replayed;
- the inner Objective-Bound Effect layer rejects objective/runtime/session/capability state.

## Concurrency claim

The security claim is limited to governed paths that share the same `RuntimeCommitFence` instance. Within that boundary:

```text
final causal re-check
→ effect callback
→ committed causal event append
```

is serialized against other fenced causal appends, objective observations and governed runtime configuration changes.

This is an in-process trusted-host coordination boundary, not kernel/hypervisor enforcement.

## Authority boundary

This component does **not**:

- grant capabilities;
- invent causal evidence;
- infer malicious intent from model prose;
- access credentials or hidden evaluator state;
- create network authority;
- execute containment or human release;
- discover or execute exploits;
- provide syscall-complete, kernel, eBPF, seccomp or hypervisor enforcement.

Its claim is narrower:

> For governed paths sharing the same trusted commit fence, a physical effect cannot commit from a causal-risk decision that has become stale, and an effect whose exact projected trajectory is already non-ALLOW is blocked before the callback.

Refs: #129, #151, #157, #159, #161, #163, #165, #167, #134.
