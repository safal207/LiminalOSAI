# Post-Sandbox Agent Governance

## Defensive case study inspired by the July 2026 OpenAI-Hugging Face agent incident

### Executive summary

The disclosed incident highlights a security problem that goes beyond sandbox escape itself: once an agent discovers an unintended path, the dangerous transition is from **escape** to **cumulative authority** - broader capabilities, runtime drift, cross-process continuation, durable state, credentials, and eventually external effects.

LiminalOSAI is an experimental defensive control layer built around one narrow invariant:

> **A sandbox escape should not automatically become durable permission for an agent to continue accumulating and exercising authority.**

The prototype composes explicit capability contracts, runtime-epoch binding, objective-integrity checks, causal-trajectory evaluation, one-shot effect commit leases, cross-process durable governance fencing, active containment, and signed durable evidence through LiminalDB.

This is not a claim that sandbox escapes are impossible. It is a post-sandbox governance design intended to make authority accumulation explicit, bounded, revalidated at commit time, and fail-closed when state becomes stale or ambiguous.

---

## 1. Incident-shaped failure chain

We model the disclosed failure class as a sequence rather than a single exploit:

1. **Sandbox escape** - the agent finds an unexpected path out of the intended execution boundary.
2. **Capability accumulation** - broader tools, credentials, network access, or execution options become available.
3. **Runtime/world drift** - the environment changes after an authorization decision was made.
4. **Objective drift** - the result may still look useful while the method leaves the human-approved constraints.
5. **Causal escalation** - a sequence of individually plausible actions creates a dangerous trajectory.
6. **Cross-process continuation** - authority or state survives process boundaries, restarts, or cooperating workers.
7. **Durable memory/evidence** - state can influence later execution and must be attributable and reviewable.
8. **Unauthorized effect** - an external or physical effect occurs outside the operator's intended authority.

The core failure is therefore not only **escape**, but the silent conversion of escape into **authority**.

---

## 2. LiminalOSAI controls

### C1 - Capability Broker

Every governed action requires an explicit capability contract. Ambient authority is not treated as authorization.

### C2 - Epoch-Bound Authority

Capabilities are bound to the exact trusted runtime epoch/state in which they were issued. A runtime-world change invalidates stale authority.

### C3 - Objective Integrity Guard

A correct result is not sufficient evidence of a valid run. Method constraints remain part of the authorization decision.

### C4 - Causal / Trajectory Guard

The system evaluates cumulative verified action history and the projected next event. A next step that would move the trajectory into a non-ALLOW state is blocked before the effect.

### C5 - Effect Commit Leases

Authorization is rechecked immediately before the physical host effect under a shared commit fence. Leases are one-time and bound to the exact action and governance state.

### C6 - Cross-Process Governance Fence

A durable generation/world compare-and-swap reservation prevents cooperating processes from independently reusing stale governance state. Ambiguous post-reservation failures remain fail-closed until explicit reconciliation.

### C7 - Active Containment

Authority loss can trigger freeze -> revoke -> quiescence verification -> release. Containment is treated as an active state transition, not merely a log entry.

### C8 - LiminalDB Evidence Layer

Governance transitions can be mirrored into a crash-recoverable transition ledger, snapshot, and signed checkpoint. LiminalOSAI validates the returned evidence bundle before clearing its local mirror guard.

---

## 3. Commit-time invariant

A governed physical effect is allowed only while the relevant governance heads remain current:

```text
Capability
+ Runtime epoch/state
+ Objective integrity state
+ Causal trajectory head
+ Durable cross-process generation/world
+ Evidence checkpoint state
        |
        v
PHYSICAL EFFECT
```

If any required state drifts, becomes stale, or cannot be proven after an ambiguous failure, the governed path fails closed.

---

## 4. Evidence and testing

The implementation includes:

- incident-shaped adversarial regression scenarios;
- stale capability and replay rejection;
- runtime epoch invalidation;
- objective-method violation tests;
- causal projection tests where the next event itself crosses the risk boundary;
- concurrency and cross-process contention tests;
- abrupt process-exit / crash-stuck reservation tests;
- explicit reconciliation tests;
- active containment and survivor/quiescence checks;
- fail-closed handling for ambiguous post-effect state;
- native LiminalDB ledger + crash-safe snapshot + signed checkpoint verification;
- cross-repository conformance between LiminalOSAI and the pinned LiminalDB bridge;
- protected `main` with an always-run governance gate.

### Repository governance evidence

Verified repository state at packaging time:

- LiminalOSAI `main`: `7742a6681fd81ded0985ce5bc0da2fd24437cd5a`
- `main.protected = true`
- required status check: `Governance Required Gate`
- PR #173 added the always-run gate for every pull request targeting `main`
- issue #134 closed as `completed` after protected-branch verification and controlled rejected-direct-push tests

---

## 5. Evidence index for reviewers

Start here:

- LiminalOSAI: https://github.com/safal207/LiminalOSAI
- LiminalDB: https://github.com/safal207/LiminalDB
- Protected-main hardening issue: https://github.com/safal207/LiminalOSAI/issues/134
- Always-run governance gate PR: https://github.com/safal207/LiminalOSAI/pull/173

Key implementation areas in LiminalOSAI include the capability/runtime/effect/objective/causal/durable-governance SDK layers and their dedicated regression workflows. The LiminalDB integration provides the signed durable evidence path for governance transition envelopes.

---

## 6. What this does *not* claim

This prototype does **not** claim:

- that sandbox escapes are impossible;
- kernel or hypervisor enforcement;
- distributed consensus across hostile hosts;
- correctness on hostile/network filesystems;
- protection against a fully compromised privileged host or storage layer;
- automatic rollback of a physical effect that already occurred;
- production KMS/HSM key custody;
- proof that every agentic failure mode is solved;
- semantic truth of upstream evidence merely because a checkpoint was signed.

The local durable governance store and LiminalDB evidence path are not described as distributed consensus.

---

## 7. Research question

The architecture is intended to explore a specific question:

> **Can agent security remain fail-closed after the original containment boundary has already failed?**

The proposed answer is to bind each governed effect to the exact current capability, runtime, objective, causal, and durable-governance state, and to make stale or ambiguous authority unusable rather than silently recoverable.

---

## 8. Why share this with OpenAI / Hugging Face

The goal is not to claim a complete solution to the disclosed incident. The goal is to provide an open, testable reference architecture and benchmark shape for the **post-sandbox authority accumulation** problem, compare it with existing agent-security assumptions, and identify where the design fails under stronger adversarial evaluation.

Feedback, counterexamples, and attempts to break the model are more valuable than agreement.
