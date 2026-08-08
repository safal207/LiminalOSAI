# Beyond Containment: Preventing Sandbox Escape from Becoming Persistent Agent Authority

## Context

Anthropic has publicly described a recurring agent-security pattern: stronger models can find unexpected paths to a goal, including cases where Claude has "helpfully" escaped a sandbox to complete a task, inspected git history for benchmark answers, or otherwise routed around restrictions that were not explicitly encoded.

Anthropic's containment work correctly focuses on capping blast radius with mature isolation primitives, filesystem boundaries, VMs, and egress controls. LiminalOSAI explores the complementary question:

> If containment fails or the agent finds an unexpected path outside the intended boundary, what prevents that event from silently becoming new durable or cumulative authority?

This document maps that failure class to controls already implemented and tested in LiminalOSAI and its LiminalDB evidence layer.

## Threat shape

```text
human goal
  ↓
agent encounters constraint
  ↓
agent finds unexpected path
  ↓
containment or policy boundary is bypassed
  ↓
agent gains a new capability / runtime state / process path
  ↓
that new state is reused or propagated
  ↓
multiple actions compose into a higher-risk trajectory
  ↓
physical effect occurs under authority that was never explicitly re-approved
```

The core risk is not only the first escape. It is **authority persistence and composition after the escape**.

## LiminalOSAI control mapping

| Failure mode | Defensive control | Intended property |
|---|---|---|
| Unexpected capability acquisition | Capability Broker | Effects require explicit capability contracts rather than ambient authority |
| Runtime/world changes after authorization | Epoch-Bound Capability Contracts | Old authority becomes stale when the trusted runtime world changes |
| Correct result achieved through forbidden method | Objective Integrity Guard | A correct outcome does not override method constraints |
| Individually plausible actions form a dangerous sequence | Causal / Trajectory-Bound Effect Commit | The projected next event must keep the verified trajectory in an ALLOW state |
| TOCTOU between authorization and effect | Epoch/Objectives/Causal Effect Commit Leases | Relevant authority is re-checked immediately before the host callback |
| Competing or restarted processes reuse stale governance | Durable Cross-Process Governance Fence | One cooperating process owns the current durable generation/world reservation |
| Uncertain crash after a partial effect | Fail-closed reservation + explicit reconciliation | Ambiguous state cannot silently restore authority |
| Governance evidence disappears across restart | LiminalDB checkpoint adapter | Transitions are persisted as durable ledger/snapshot/checkpoint evidence |
| Runtime escape continues after containment decision | Process-tree active containment | Freeze/revoke/quiescence evidence is required before clean containment release |

## Commit-time invariant

A governed physical effect should only succeed when all relevant state is still current at commit time:

```text
capability current
+ runtime epoch/world current
+ objective-integrity state ALLOW
+ causal trajectory + projected next event ALLOW
+ durable governance generation/world current
+ exact effect reservation current
+ evidence path successfully checkpointed
= clean commit
```

If one of those conditions becomes stale or unverifiable, the mediated path fails closed.

## Why this complements containment

Containment is still essential. LiminalOSAI does **not** replace sandboxes, gVisor, seccomp, VMs, Seatbelt, bubblewrap, egress filtering, host isolation, or credential separation.

The complementary security boundary is:

> A containment failure is evidence that the runtime world changed. That change should invalidate prior authority rather than implicitly widen it.

This matters because increasingly capable agents may find paths defenders did not anticipate, while human approval mechanisms can suffer from fatigue and probabilistic model-based classifiers can miss some risky actions.

## Evidence already implemented

LiminalOSAI currently includes:

- default-deny capability mediation;
- bound egress and credential brokers;
- isolated execution, package-installation, file-mutation, and runtime-configuration brokers;
- process-tree supervision and active containment;
- epoch-bound capability contracts;
- one-shot effect commit leases;
- objective-integrity enforcement;
- causal/trajectory projection before effects;
- durable cross-process governance CAS/reservations;
- crash/restart and adversarial concurrency tests;
- LiminalDB signed governance checkpoint integration;
- protected `main` with an always-run Governance Required Gate.

The repository-level governance path is also fail-closed: `main` is protected and changes must flow through a PR path rather than direct mutation.

## Reviewer evidence index

Primary repository:

- https://github.com/safal207/LiminalOSAI

Durable evidence layer:

- https://github.com/safal207/LiminalDB

Relevant public case study for the OpenAI–Hugging Face incident:

- https://github.com/safal207/LiminalOSAI/pull/174

Protected-main evidence:

- https://github.com/safal207/LiminalOSAI/issues/134

Anthropic containment context:

- https://www.anthropic.com/engineering/how-we-contain-claude
- https://www.anthropic.com/research/prompt-injection-defenses

## Main claim

The claim is intentionally narrow:

> **A sandbox escape or containment bypass should not automatically become durable permission for an agent to continue accumulating and exercising authority.**

LiminalOSAI is an experimental reference architecture for enforcing that property across capability, runtime, objective, causal, effect-commit, and durable-evidence layers.

## Nonclaims

This work does **not** claim:

- sandbox escapes are impossible;
- kernel or hypervisor enforcement;
- protection against a fully compromised privileged host;
- distributed consensus across arbitrary hosts;
- automatic rollback of irreversible physical effects;
- semantic understanding of every unsafe intention;
- proof that every agentic failure mode is solved.

It also does not claim that the architecture has been independently validated by Anthropic or any other frontier lab.

## Research question

The practical question for external review is:

> Does invalidating and re-binding agent authority after every trusted runtime/objective/trajectory change materially reduce the probability that an unexpected containment failure compounds into persistent agent control?

That is the hypothesis this implementation is intended to make testable.