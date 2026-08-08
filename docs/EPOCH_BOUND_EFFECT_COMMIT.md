# Epoch-Bound Effect Commit Lease

Issue: #161

## Why this exists

Epoch-bound capabilities make an authorization stale when the trusted runtime world changes. A smaller TOCTOU window still remains if the runtime changes after authorization but before the trusted host callback actually performs the effect.

This layer closes that window inside the mediated host boundary.

```text
capability ALLOW
      ↓
one-time effect lease
      ↓
lease binds exact decision + operation + runtime world + session + host
      ↓
acquire shared RuntimeCommitFence
      ↓
re-observe runtime world + execution session
      ↓
check source capability still active and epoch-bound
      ↓
consume lease BEFORE callback
      ↓
trusted effect callback while fence remains held
      ↓
digest-only commit receipt
```

## Shared commit fence

`RuntimeCommitFence` is deliberately shared by two high-assurance paths:

- `EffectCommitBroker` holds it across the final runtime/session re-check, one-time lease consumption, and effect callback.
- `FencedBoundRuntimeConfigBroker` holds the same fence across a governed `runtime.configure` transition.

Therefore a governed runtime mutation cannot interleave between the final world check and the committed effect.

The fence is an in-process host coordination primitive, **not** a kernel or hypervisor security boundary. A privileged host writer, malicious kernel/runtime, or any mutation path that ignores the shared fence remains outside this claim.

## Lease binding

A lease is bound to:

- capability decision receipt SHA-256;
- epoch-bound capability contract SHA-256;
- capability id;
- operation id and runtime kind;
- normalized scope SHA-256;
- payload SHA-256;
- trusted runtime epoch;
- trusted runtime state SHA-256;
- trusted runtime snapshot SHA-256;
- trusted execution-session SHA-256;
- trusted session evidence SHA-256;
- trusted host binding SHA-256;
- bounded issue/expiry times.

Raw argv, environment values, secrets, host paths, PIDs and raw runtime configuration values are not included in model-facing receipts.

## Fail-closed conditions

The callback is not invoked when any of these checks fails before lease consumption:

- containment is active;
- lease is unknown, expired or replayed;
- trusted clock regresses;
- runtime is tainted;
- runtime epoch changed;
- runtime state digest changed;
- execution session is inactive or changed;
- execution session host binding is wrong;
- source capability is no longer active;
- source capability is no longer epoch-bound to the observed runtime world;
- trusted adapter authentication fails.

A lease is burned before the callback. If the callback fails, the same lease cannot be retried.

## Opt-in mediation path

`EpochBoundEffectRuntimeMediator` preserves the existing `RuntimeMediator.mediate(operation, executor)` surface while replacing direct callback dispatch with the effect-commit lease flow.

Legacy `RuntimeMediator` behavior is unchanged. Hosts opt into this stronger path explicitly.

## Authority boundary

This component does not:

- grant capabilities;
- mutate policy;
- create network or credential authority;
- expose secret material;
- create arbitrary execution sessions;
- bypass containment;
- claim syscall-complete or kernel-level enforcement.

Its security claim is narrower: **within a host that routes governed runtime mutations and committed effects through the same fence, an effect authorized in runtime world `(N,S)` cannot be committed after that world has changed.**
