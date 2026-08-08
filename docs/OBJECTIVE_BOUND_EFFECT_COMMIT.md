# Objective-Bound Effect Commit

Issue: #165

## Security objective

The Objective Integrity Guard can prove that a proposed method is `ALLOW`, and the Epoch-Bound Effect Commit can prove that a host effect is committed in the same runtime world in which its capability was authorized. A narrow TOCTOU window remains if new trusted objective-integrity evidence arrives after the objective decision but before the physical effect.

This layer closes that window inside the mediated host boundary.

```text
Objective Integrity ALLOW @ observation head O
        ↓
objective-bound outer lease
        +
epoch/runtime-bound inner lease
        ↓
shared RuntimeCommitFence
        ↓
re-check objective policy/head/state/floor
        ↓
consume outer lease once
        ↓
re-check runtime/session/capability
        ↓
consume inner lease once
        ↓
trusted host effect
```

## Schema preservation

This feature does not change:

- `liminal-objective-integrity-decision-v0.1`;
- `liminal-objective-method-policy-v0.1`;
- `liminal-epoch-bound-effect-lease-v0.1`;
- `liminal-epoch-bound-effect-commit-receipt-v0.1`.

It adds an opt-in composition layer with separate objective-bound authorization and commit receipts. Old evidence therefore retains its original meaning.

## Fenced objective guard

`FencedObjectiveIntegrityGuard` uses the same `RuntimeCommitFence` instance as `EffectCommitBroker` for:

- trusted observation ingestion;
- containment enter/release state;
- objective decisions;
- completion decisions;
- objective state snapshots.

The effect commit broker already holds that fence over its final runtime/session checks and the physical host callback. Therefore trusted objective evidence cannot be inserted between the final objective check and the callback when both paths use this fenced profile.

This is an in-process trusted-host serialization boundary. It is not kernel/hypervisor enforcement and cannot govern an observation/effect path that bypasses the shared fence.

## Outer lease binding

The outer lease binds:

- objective ID;
- objective method-policy SHA-256;
- exact Objective Integrity decision receipt SHA-256;
- exact objective observation-head SHA-256;
- exact objective state SHA-256;
- objective decision `ALLOW`;
- operation ID/kind;
- normalized scope SHA-256;
- payload SHA-256;
- capability decision receipt SHA-256;
- inner epoch-bound effect authorization receipt SHA-256;
- issue/expiry time inherited from the inner lease.

Issue fails closed unless the objective decision exactly matches the operation and the trusted current objective state still has `decision_floor == ALLOW`.

## Final commit gate

Immediately before the physical effect, while the shared fence is held, the broker re-checks:

```text
objective_id unchanged
method_policy_sha256 unchanged
contained == false
decision_floor == ALLOW
observation_head == bound head
objective state SHA == bound state
```

Any mismatch consumes the outer lease and records a `NOT_EXECUTED` receipt. The lease cannot become valid again after a later release or state change.

If the objective state still matches, the outer lease is burned before the inner effect commit. The existing inner broker then re-checks:

- runtime epoch/state;
- execution session identity/activity;
- source epoch-bound capability status;
- containment;
- TTL/replay;
- trusted adapter authentication.

The callback runs while the same re-entrant commit fence remains held.

## Why two leases

The two-layer design keeps authority domains explicit:

```text
outer lease = method/objective integrity
inner lease = runtime/session/capability integrity
```

Neither lease broadens the other. A physical effect requires both to remain valid at commit time.

## Failure semantics

The effect is not invoked when:

- objective decision was not `ALLOW`;
- objective decision does not exactly bind the operation;
- objective policy/head/state is stale;
- a new trusted violation raises the objective floor;
- objective containment is active;
- outer lease is expired/replayed;
- any existing inner effect-commit gate fails.

The outer lease burns before inner execution. Callback failure cannot restore it. Receipts record only identifiers, decision/status values and digests; raw detector evidence, prompts, hidden answers, evaluator state, argv, environment, host paths and secrets are excluded.

## Concurrency invariant

The adversarial regression test proves the intended ordering:

```text
effect acquires fence
→ final objective re-check succeeds
→ callback starts
→ concurrent detector tries trusted observation ingestion
→ detector blocks on the same fence
→ callback completes
→ effect receipt seals old objective head
→ detector acquires fence and advances objective head
```

The reverse ordering is also safe: if the detector advances the head first, the old outer lease fails before callback.

## Authority boundary

This layer:

- does not grant capabilities;
- does not discover or access hidden answers/evaluator state;
- does not execute exploits;
- does not create network or credential authority;
- does not mutate objective policy;
- does not weaken containment;
- does not claim semantic omniscience;
- does not claim kernel-level serialization.

Its claim is narrow: **for governed paths sharing the same trusted commit fence, an effect bound to objective-integrity head `O` cannot be physically committed after trusted objective state has advanced away from `O`.**

GitHub branch protection remains separate governance work (#134).
