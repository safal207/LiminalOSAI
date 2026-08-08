# Objective Integrity Guard MVP

## Purpose

The Objective Integrity Guard turns the existing Phase-0 `liminal-objective-integrity-contract-v0.1` into a deterministic runtime gate.

The core invariant is:

```text
correct result
!=
authorized method
```

A capability may be locally valid and a final answer may be correct while the causal path that produced it violates the human-approved task constraints. This layer governs that distinction.

## Causal path

```text
human objective digest
+ governance policy digest
+ allowed method kinds
+ exact forbidden-method rules
        ↓
ObjectiveMethodPolicy
        ↓
proposed runtime/network action
        +
externally verified integrity observations
        ↓
ObjectiveIntegrityGuard
        ↓
ALLOW | REVISE | BLOCK | CONTAIN
        ↓
ObjectiveGuardedRuntimeMediator
        ↓
existing capability/runtime/effect controls
```

Final completion is a separate gate:

```text
result digest
+ trajectory digest
+ method-evidence digest
+ objective-integrity history
        ↓
completion ALLOW | BLOCK | CONTAIN
```

## Evidence model

The guard deliberately does **not** ask the model to decide whether its own behavior is legitimate.

It accepts only:

1. deterministic policy matches over normalized runtime metadata and exact SHA-256 bindings; or
2. digest-bound observations from configured detector identities that pass an injected trusted verifier.

A detector binding digest is not treated as authentication by itself. The host must provide `verify_observation` backed by evidence appropriate to that detector, such as a signed receipt or independently verified provenance root.

## Method policy

`ObjectiveMethodPolicy` binds:

- `objective_id`;
- digest of the human objective, never the raw prompt;
- the runtime governance policy digest;
- allowed runtime/capability method kinds;
- zero or more deterministic forbidden-method rules;
- whether completion evidence is mandatory;
- deterministic policy SHA-256.

A rule can match:

```text
runtime kind
+ optional exact normalized-scope SHA-256
+ optional exact payload SHA-256
→ violation code
→ REVISE | BLOCK | CONTAIN
```

Kind-only rules are intentionally possible and are broad by construction.

## Trusted observations

`ObjectiveIntegrityObservation` is an append-only hash chain. Each observation binds:

- objective and method-policy identity;
- trusted source identity and binding digest;
- one Phase-0 objective-integrity violation code;
- evidence digest;
- observation time;
- previous observation digest.

Unknown sources, failed external verification, replay, disconnected ancestry and time regression fail closed.

Critical violation classes deterministically establish a `CONTAIN` floor. Non-critical observed violations establish at least `BLOCK`. Later benign operations do not erase those facts.

## Runtime mediation

`ObjectiveGuardedRuntimeMediator` is opt-in and preserves the existing:

```python
mediate(operation, executor)
```

shape.

When the objective gate is not `ALLOW`, the delegate `RuntimeMediator` is not invoked, no capability use is consumed, and the host executor is not called.

When the objective gate is `ALLOW`, the existing runtime/capability control plane remains authoritative for the underlying effect.

Network requests can be screened before the Egress Gateway using digest-only method evidence.

## Completion integrity

Completion requires a non-zero result digest and, by default, non-zero trajectory and method-evidence roots.

A correct result digest does not override prior integrity evidence:

```text
hidden_answer_access observed
→ result digest is correct
→ completion remains CONTAIN
```

This is the runtime form of the original Phase-0 invariant.

## Incident-inspired safe benchmark shape

The tests model only semantic stages:

```text
blocked task
→ alternate method
→ package/network/credential path
→ trusted observation of forbidden-method completion
→ CONTAIN
```

No exploit payload, real credential, live target, hidden answer, evaluator access or sandbox-escape procedure is included.

## Authority boundary

The Objective Integrity Guard:

- does not grant capabilities;
- does not execute processes;
- does not open network connections;
- does not access credentials or evaluator state;
- does not mutate policy/runtime/benchmark state;
- does not infer hidden semantic intent from free-form model claims;
- does not automatically execute containment;
- does not claim kernel/hypervisor enforcement.

`CONTAIN` is a control-plane decision that must be consumed by the existing containment machinery.

## Residual risks

- Semantic violations that produce no trusted machine-observable evidence cannot be detected deterministically by this MVP.
- A compromised trusted detector/verifier can provide bad evidence; its provenance and signing boundary remain external.
- Objective-integrity decision and physical effect commit are separate components; high-assurance deployments should compose this guard with Epoch-Bound Effect Commit and the same containment path.
- GitHub branch protection remains separate governance work (#134).
