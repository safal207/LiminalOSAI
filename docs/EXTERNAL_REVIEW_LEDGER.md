# External Review Ledger

## Post-Sandbox Agent Governance / LiminalOSAI

This ledger records external technical-review outreach for the post-sandbox agent-governance work around LiminalOSAI and LiminalDB.

The purpose is **not** to imply endorsement. It is to make the review trail auditable and to distinguish clearly between sending material, receiving an acknowledgement, internal routing, substantive technical feedback, independent reproduction, and actual validation.

> **No organization listed here is described as endorsing or validating this work unless there is explicit evidence of that state.**

## Status vocabulary

| Status | Meaning |
|---|---|
| `SENT` | Review material was sent to a relevant contact or intake channel. |
| `ACKNOWLEDGED` | Receipt/intake was acknowledged, but technical review is not confirmed. |
| `ROUTED` | The recipient explicitly stated that the material was passed to an internal team for review. |
| `TECHNICAL_FEEDBACK` | Substantive technical feedback was received from a reviewer. |
| `REPRODUCED` | An external reviewer independently reproduced a test, failure trace, or benchmark result. |
| `VALIDATED` | Reserved for explicit, evidence-backed external validation. **Not currently claimed for any entry below.** |

## Machine-readable validation graph

The same review trail is represented as a causal state-transition graph:

- [`EXTERNAL_VALIDATION_GRAPH.md`](./EXTERNAL_VALIDATION_GRAPH.md) — Mermaid visualization and transition semantics;
- [`external_validation_graph.v0.1.yaml`](./external_validation_graph.v0.1.yaml) — machine-readable state for ProofPath/CML integration.

The graph introduces **EEW-v0.1 (External Evidence Weight)** as a conservative review-maturity score. It is not a safety-confidence percentage, probability, endorsement score, or scientific effect size. Current EEW is **7.86 / 100** because outreach and routing intentionally carry low weight until technical feedback and independent reproduction exist.

## Current review trail

| Date (UTC) | Organization / review target | Material / request | Status | Evidence / current state | Requested falsification |
|---|---|---|---|---|---|
| 2026-08-08 | **OpenAI** — Preparedness / agent-security routing request | Post-sandbox governance architecture; LiminalOSAI + LiminalDB; case-study PR | `ROUTED` | OpenAI Support case **#12892239**. Support explicitly stated that the material would be passed to the appropriate internal team for review. No endorsement or technical conclusion has been received. | Identify a failure trace where stale, drifted, or ambiguous authority can still produce a governed physical effect. |
| 2026-08-08 | **Anthropic Safeguards** | Post-sandbox governance prototype relevant to containment research | `ACKNOWLEDGED` | Safeguards intake acknowledged receipt and stated that other safety-related concerns are reviewed by the team. No technical review or endorsement has been confirmed. | Find a containment/recovery sequence in which authority survives a state transition that should invalidate it. |
| 2026-08-09 | **Meta** — Preparedness / AI Security correspondence contact for Muse Spark safety work | Reproducible benchmark + external review trail + post-sandbox governance one-pager | `SENT` | Sent to the public correspondence contact associated with Meta's Muse Spark Safety & Preparedness work. Awaiting response. | Provide one Meta-shaped loss-of-control, monitorability, agent-robustness, or prompt-injection failure trace that the control model should fail closed on. |
| 2026-08-01 | **OpenSSF AI/ML Security Working Group** | Adversarial review request for evidence-bound trust runtime for multi-agent systems | `SENT` | Review request sent. No substantive technical response recorded yet. | Break evidence-bound delegation, recovery lineage, or explicit human-authority assumptions. |
| 2026-08-01 / 2026-08-04 | **OWASP agentic-security / AI-testing contacts** | Adversarial review of LS Agent Trust Runtime / Causal Transition Guard | `SENT` | Review packets sent to relevant OWASP contacts. No substantive technical response recorded yet. | Construct an authority-escalation path where forged reasoning, stale state, or tool-side effects bypass the guard. |
| 2026-08-01 | **Invariant Labs** | Technical review request for evidence-bound trust runtime for AI-agent teams | `SENT` | Review request sent. No substantive technical response recorded yet. | Break stale-worker rejection, recovery lineage, or delegation-state consistency under multi-agent execution. |
| 2026-08-04 | **AVERI / third-party AI verification outreach** | Open-source evidence layer for auditing agentic AI actions | `SENT` | Review material sent. No substantive technical response recorded yet. | Challenge whether the evidence trail is sufficient for independent third-party verification of an agent action. |

## Narrow claim under review

The review program is centered on one intentionally limited claim:

> **A sandbox escape should not automatically become durable permission for an agent to continue accumulating and exercising authority.**

The architecture attempts to enforce this by binding governed effects to current capability, runtime epoch/state, objective-integrity state, causal-trajectory head, durable cross-process governance state, and evidence state at commit time.

A useful external review should try to produce a counterexample rather than confirm the design.

## What would increase evidential weight

The ledger should move an entry forward only when evidence supports the transition:

```text
SENT
  -> ACKNOWLEDGED
  -> ROUTED
  -> TECHNICAL_FEEDBACK
  -> REPRODUCED
  -> VALIDATED
```

These states are **not required to occur in order** and should never be inferred from silence. For example, a direct technical review may move from `SENT` to `TECHNICAL_FEEDBACK` without an explicit routing step.

Highest-value next evidence:

1. an external reviewer supplies a concrete counterexample or failure trace;
2. the trace is reproduced locally in a bounded test environment;
3. the failing invariant is documented;
4. the control is changed or the claim is narrowed;
5. the external reviewer can independently reproduce the result;
6. the ledger links the review evidence to the exact repository commit/PR.

## Public reviewer entry points

- LiminalOSAI: https://github.com/safal207/LiminalOSAI
- LiminalDB: https://github.com/safal207/LiminalDB
- Post-sandbox governance case study: https://github.com/safal207/LiminalOSAI/pull/174
- Always-run governance gate: https://github.com/safal207/LiminalOSAI/pull/173

## Non-claims

This ledger does **not** claim that:

- any listed organization endorses LiminalOSAI, LiminalDB, or the broader architecture;
- sending material constitutes review;
- an acknowledgement constitutes technical evaluation;
- internal routing constitutes validation;
- repository tests prove resistance to all agent-security failures;
- the architecture prevents sandbox escape itself.

The intended standard is falsifiability: **external criticism that changes the model is more valuable than a list of logos.**
