# Post-Sandbox Control Plane — Phase 0 Threat Model and Interfaces

## Status

Phase 0 contract profile. This document defines threats, trust boundaries and interfaces only. It does **not** claim runtime containment, egress mediation, syscall interception, credential brokering or production isolation.

## Security objective

LiminalOS must detect and govern the moment individually permitted actions compose into new, unapproved power.

```text
locally permitted actions
→ cumulative capability delta
→ privilege / destination / process novelty
→ objective-integrity evaluation
→ ALLOW | REVISE | BLOCK | CONTAIN
```

A sandbox remains useful, but it is not treated as the sole trust boundary.

## Protected assets

- human intent and task constraints;
- policy and approval roots;
- capability grants and revocation state;
- credentials and secret-bearing handles;
- repository and filesystem integrity;
- process tree and runtime configuration;
- network destination integrity;
- evaluator / benchmark state;
- evidence journal, receipts and replay history;
- containment state and explicit human release.

## Threat actors and failure modes

Phase 0 models four classes without assuming malicious intent is required:

1. **Compromised or adversarial agent** — intentionally seeks unauthorized power.
2. **Goal-preserving but unsafe agent** — follows the objective while discovering an unintended route that expands capability.
3. **Compromised dependency or infrastructure** — package, redirect, DNS, proxy, runner or connector behavior changes the effective action.
4. **Operator / policy error** — grant is stale, over-broad, replayed, mis-scoped or incorrectly survives revocation.

## Threat matrix

| Threat | Example composition | Required control | Phase |
|---|---|---|---|
| Ambient repository write | read task → direct write outside approved path | scoped capability + exact action binding | 1 |
| Package-assisted egress | install package → new outbound endpoint | package capability + egress gateway + causal graph | 2–3 |
| Credential pivot | allowed HTTP → credential access → lateral request | secret broker + destination-bound capability | 2–3 |
| Process escape | execute tool → spawn child → altered runtime | process capability + child-process tracking | 1–3 |
| Evidence tampering | action succeeds → journal modified | append-only digest chain + fail-closed verification | existing + 1 |
| Evaluator gaming | task → hidden answer / grader mutation | objective-integrity guard | 1–3 |
| Capability replay | expired grant reused for new call | TTL + call binding + use count + replay state | 1 |
| Revocation race | revoke issued while action starts | broker serialization + monotonic state | 1 |
| Redirect / DNS rebinding | approved domain → unapproved destination | resolved-destination validation | 2 |
| Containment bypass | detector fires → child/process/network continues | FREEZE → REVOKE → SEAL → SNAPSHOT | 4 |
| Recovery forgery | incident evidence rewritten after restart | durable replay + signed incident receipt | 4 |

The profile intentionally describes attack **classes and control requirements**, not weaponized sandbox-escape procedures.

## Capability contract

Canonical schema: `liminal-capability-contract-v0.1`.

Initial capability classes:

```text
repository.read
repository.write
process.execute
package.install
network.open
network.connect_domain
credential.access
filesystem.write_outside_workspace
process.spawn_child
runtime.configure
```

Each contract binds:

- stable capability, subject and issuer IDs;
- exactly one capability class;
- type-specific scope;
- policy SHA-256;
- issue / not-before / expiry times;
- bounded maximum use count;
- explicit delegation posture and parent capability when delegation exists;
- deterministic contract SHA-256;
- a fixed `contract_definition_only` authority boundary.

Phase 0 validation rejects an empty scope, invalid validity interval, unknown scope keys, duplicate destinations, invalid ports, and unrooted delegation.

## Least privilege and scope semantics

Capability scopes are allow-lists, never ambient negatives.

Examples:

```json
{
  "repository": "owner/repo",
  "refs": ["refs/heads/agent/example"],
  "paths": ["docs/"]
}
```

```json
{
  "domains": ["api.example.com"],
  "protocols": ["https"],
  "ports": [443]
}
```

A future broker must compare the normalized action to the full scope; possessing a capability ID alone is insufficient.

## Capability lifecycle

Phase 0 defines these causal event kinds:

```text
grant
use
deny
revoke
expire
```

The event schema is `liminal-causal-runtime-event-v0.1`.

Every lifecycle event carries a capability ID, input digest, decision, reason codes and causal predecessor hash. Runtime actions, objective-integrity violations and containment transitions use the same causal envelope.

### Recorder compatibility

The existing Session Recorder remains the visible-session evidence source for `tool_event` and `user_authorization`. The new causal event can bind both:

```text
recorder_event_id
recorder_entry_sha256
```

Those fields are optional together, never independently. This preserves the existing recorder contract instead of silently extending its event enum. A Phase 1 broker can append its own causal chain while cryptographically referencing the recorder entry for the same observed action.

The causal chain therefore composes as:

```text
Session Recorder entry
        ↓ hash reference
Causal Runtime Event
        ↓ previous_causal_event_sha256
next capability / runtime / containment event
```

## Runtime evidence requirements

Schema: `liminal-runtime-evidence-requirement-v0.1`.

Every sensitive action class is fail-closed on missing required evidence. The default contract requires roots for:

- policy;
- capability;
- normalized input;
- Session Recorder entry;
- result or network execution receipt.

Phase 0 does not decide that those roots are truthful; it defines what Phase 1+ must supply before an action can be considered governed.

## Objective Integrity Guard contract

Schema: `liminal-objective-integrity-contract-v0.1`.

Explicit violation classes:

- hidden answer access;
- evaluator state access;
- grader or benchmark modification;
- result fabrication;
- evidence tampering;
- task-constraint mutation;
- evaluation-environment exploitation;
- unauthorized policy mutation;
- unauthorized runtime mutation.

An observed violation may not produce `ALLOW`.

The important distinction is method integrity:

```text
correct final answer
≠
authorized way of obtaining the answer
```

## Containment lifecycle

Canonical sequence:

```text
IDLE
→ DETECT
→ FREEZE
→ REVOKE
→ SEAL
→ SNAPSHOT
→ REVIEW
→ RELEASED
```

Skipping forward, moving backward, or implicitly returning to execution is invalid.

`RELEASED` requires an explicit `human_release_id`. No earlier transition may carry one.

State responsibilities:

| State | Required meaning |
|---|---|
| DETECT | escalation / integrity condition has crossed a deterministic threshold |
| FREEZE | new agent execution must stop |
| REVOKE | all live sensitive capabilities become unusable |
| SEAL | causal and recorder evidence boundaries are fixed |
| SNAPSHOT | bounded forensic state is preserved |
| REVIEW | only human / external review may decide disposition |
| RELEASED | explicit human release authorizes a *new* execution epoch |

The Phase 0 state machine validates transitions only. It cannot freeze or revoke a real process.

## Causal escalation semantics

The future detector evaluates trajectories rather than isolated calls.

A causal feature vector should include at minimum:

- newly acquired capability types;
- use of a capability not previously required by the plan;
- privilege level delta;
- new network domain / protocol / port;
- credential access following network or package activity;
- child-process creation;
- runtime or policy configuration mutation;
- evidence-integrity anomalies;
- objective-integrity violations;
- time distance and ordering between events.

Phase 0 does not assign ML probabilities. Deterministic rules must remain sufficient to trigger `BLOCK` or `CONTAIN` for known critical transitions.

## Trust boundaries

### Trusted only after verification

- signed governance and identity roots from v1.0–v1.2;
- hash-chain ancestry that recomputes correctly;
- capability contracts that pass strict schema + digest validation;
- explicit human release evidence;
- provider or runtime evidence only to the extent its verifier actually checks it.

### Never trusted merely because the model says so

- claimed identity;
- claimed possession of a capability;
- claimed network destination;
- claimed process termination;
- claimed secret non-exposure;
- claimed containment success;
- claimed evaluator integrity;
- prose describing user authorization.

## Explicit non-goals for Phase 0

Phase 0 does not implement or claim:

- sandbox escape prevention;
- kernel, seccomp, AppArmor or eBPF enforcement;
- process freezing or termination;
- socket interception;
- DNS / redirect enforcement;
- package proxying;
- KMS or credential injection;
- capability issuance or consumption at runtime;
- distributed consensus;
- autonomous incident remediation;
- production security certification;
- inference that a human intended a capability from natural-language prose.

## Phase 1 handoff invariants

The Capability Broker MVP must preserve these invariants:

1. default deny when no valid capability exists;
2. capability class and full scope must match the normalized action;
3. time window and remaining-use count must be checked immediately before effect;
4. revoked and expired grants never revive through replay;
5. use/revoke/expire ordering is monotonic;
6. every decision produces a causal event;
7. missing evidence fails closed;
8. broker authority remains separate from Session Recorder, Portable Receipt, CML, LiminalDB and RINSE semantics;
9. `CONTAIN` can revoke a capability even when the local action would otherwise be allowed;
10. human release starts a new authority epoch; it does not edit the incident history.

## Phase 0 acceptance mapping

- sandbox escape / escalation threat model — this document;
- capability schema — `CapabilityContract`;
- containment lifecycle — `validate_containment_transition`;
- causal-event schema — `CausalRuntimeEvent` with Session Recorder hash references;
- runtime evidence requirements — `RuntimeEvidenceRequirement` and defaults;
- trust boundaries / non-goals — this document and fixed `AUTHORITY` map.

The next implementation step is Phase 1: a default-deny Capability Broker that consumes these contracts rather than redefining them.
