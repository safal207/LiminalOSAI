# LiminalOSAI Causal Execution Plan

> **Status:** ACTIVE EXECUTION PLAN
>
> **Planning horizon:** 90 days
>
> **Primary objective:** turn the v1.0 trustworthy-agent governance stack into one identity-bound, independently verifiable design-partner pilot without expanding every repository and historical branch in parallel.

This document converts the broader [ROADMAP](ROADMAP.md) into an ordered execution system. The roadmap describes where the project may go. This plan defines what must happen next, why each step depends on the previous one, what other repositories contribute, and what work must wait.

## 1. Operating decision

LiminalOSAI will follow **one production spine**:

```text
trusted v1.0 baseline
→ authenticated identity and protected key custody
→ explicit runtime capabilities
→ portable evidence receipts
→ one real GitHub pilot
→ containment and recovery
→ multi-agent control plane
→ hosted service
→ open authority protocol
```

Other projects remain valuable, but they are treated as supporting layers, application tracks, or separate revenue tracks. They must not create a second competing authority runtime.

## 2. Product thesis

The problem is not merely whether an AI agent can call a tool.

The problem is whether an organization can prove:

1. who requested an action;
2. what exact action plan was approved;
3. which policy evaluated it;
4. which identities approved it;
5. what bounded authority was available;
6. which exact calls were executed;
7. whether state drift occurred;
8. what evidence was produced;
9. how the system stopped or recovered;
10. who remains accountable for the result.

The target chain is:

```text
INTENT
→ IDENTITY
→ PLAN
→ POLICY
→ APPROVAL
→ CAPABILITY
→ EXACT AUTHORIZATION
→ EXECUTION
→ RECEIPT
→ RECOVERY
→ ACCOUNTABILITY
```

## 3. Current baseline

### Completed foundation

The merged v0.1–v1.0 stack already provides:

```text
Signed Governance Capsule v1.0
→ Transaction Policy & Approval Engine v0.9
→ Transaction Orchestrator v0.8
→ Connected GitHub Runtime v0.7
→ GitHub Agent Bridge v0.6
→ Host Integration Adapter v0.5
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
→ ALLOW | VERIFY | REVISE | NO_SIGNAL
```

This foundation proves a bounded vertical slice, but it is not yet a production security boundary.

### Immediate unresolved state

1. **Historical bridge PR #102 is stale.** It was built on the v0.6-era history and must not be merged directly into the current v1.0 stack.
2. **Repository protection is incomplete.** A signed merge history is useful evidence, but protected-branch and required-check policy must become explicit before production claims.
3. **v1.0 proves key possession, not real identity.** Identity, role, organization, and key custody remain host-supplied claims.
4. **Tool mediation is stronger than runtime mediation.** Shell, process, package, file, secret, and network capabilities are not yet governed as one runtime authority surface.
5. **There is no design-partner evidence yet.** CI fixtures demonstrate correctness boundaries, not customer value or operational adoption.

## 4. Ecosystem role map

Each repository receives one primary responsibility. Cross-project integration must preserve these boundaries.

| Project | Primary responsibility | Contribution to the production spine | Must not become |
|---|---|---|---|
| **LiminalOSAI** | Authority and execution control plane | identity binding, policies, capabilities, exact authorization, execution, containment | scientific truth engine, general memory store, payment platform |
| **ProofPath** | Portable action proof and independent verification | admission, provenance, reviewer separation, portable receipts, external verification | the live executor or identity provider |
| **Causal Memory Layer** | Causal lineage and bounded reusable memory | remembers why decisions changed, prior failures, missing evidence and causal gaps | an automatic authority source |
| **LiminalDB** | Durable transition and recovery evidence | append-only persistence, replay, snapshots, recovery proof | policy decision maker or scientific validator |
| **RINSE** | Immutable reinterpretation and supersession | revises meaning without mutating original evidence | source-of-truth mutation layer or executor |
| **TRACE / Kairos** | High-assurance scientific application track | demonstrates evidence gaps, bounded claims and reproducibility receipts | blocker for the first software-delivery pilot |
| **LiminalQAengineer** | Observation and reproducible audit capture | supplies bounded public or authorized evidence cases | automatic defect truth or external-action authority |
| **PythiaLabs** | Adjudication and claim discipline | converts evidence into bounded judgments and unresolved questions | executor, approver, or source of factual evidence by itself |
| **LS** | Human impact and product consequence | explains who is affected, severity, repair priority and human review needs | authority or cryptographic verifier |
| **Smart Market Data Gateway / TMI** | Fast-changing real-world evidence track | provides a demanding live-stream, freshness and fail-closed pilot domain | first core control-plane dependency |
| **CareerOS / Career RINSE** | Career and near-term revenue support | converts market and career evidence into actionable human-reviewed work | blocker for the governance product spine |
| **Liminal / related UX experiments** | Product and runtime experimentation | supplies selected integration patterns and UX lessons | competing canonical governance runtime |

## 5. Portfolio disposition

### ACTIVE — critical path

- LiminalOSAI baseline reconciliation.
- v1.1 Identity, IdP and KMS attestation.
- Phase 0 of post-sandbox control plane epic #103.
- Portable evidence receipt profile.
- One governed GitHub design-partner pilot.
- Capability Broker MVP.
- Recovery and containment contracts.

### ACTIVE — supporting integration

- Minimal ProofPath verifier profile for LiminalOSAI receipts.
- CML memory projection for decisions, denials and incident lessons.
- LiminalDB append-only receipt/recovery projection.
- RINSE supersession record for changed policy interpretations.

### BOUNDED RESEARCH TRACK

- One TRACE/Kairos case may demonstrate high-assurance evidence portability.
- One Smart Market Data Gateway/TMI case may demonstrate fast-changing state and incomplete-capture handling.
- Research tracks receive fixed time budgets and cannot delay the GitHub pilot.

### SEPARATE REVENUE AND CAREER TRACK

- CareerOS, Career RINSE, job applications, interview preparation and paid QA/analysis services continue as a separate weekly lane.
- Revenue work should reuse evidence and product skills, but must not redefine the LiminalOSAI architecture every week.

### FREEZE / RECONCILE

- No new stacked PR chain merely because a new architectural idea exists.
- No historical PR is merged from a stale base without a current-main reconciliation.
- No new protocol repository is created until two independently operated implementations need interoperability.
- No expansion into payments, production cloud mutation or autonomous deployment before rollback and containment exist.

## 6. Master causal dependency graph

```text
A. Reconcile stale state and freeze one baseline
   ↓ removes competing histories and ambiguous evidence
B. Bind real identity and protected key custody
   ↓ turns key possession into attributable organizational approval
C. Define capabilities and runtime threat model
   ↓ converts ambient power into explicit, revocable authority
D. Standardize portable receipts
   ↓ allows independent verification outside the executing host
E. Run one bounded GitHub design-partner pilot
   ↓ tests operational value, usability and failure behavior
F. Add capability broker and runtime mediation
   ↓ extends governance below typed connector calls
G. Add egress control, causal escalation and containment
   ↓ handles composed risk and unauthorized capability growth
H. Coordinate several specialized agents
   ↓ creates a governed multi-agent control plane
I. Operate a hosted service
   ↓ creates repeatable customer delivery and administration
J. Extract an open authority protocol
   ↓ enables vendor-neutral adoption after two real implementations exist
```

Skipping a dependency creates a false claim:

- pilot before identity → approvals are not attributable;
- runtime access before capabilities → ambient authority remains invisible;
- execution before portable receipts → the host must be blindly trusted;
- hosted service before containment → incidents cannot be governed safely;
- open protocol before two implementations → the specification only mirrors one codebase.

## 7. Ninety-day execution sequence

### Phase 0 — Days 0–7: establish one trusted baseline

**Goal:** eliminate historical ambiguity before adding another authority layer.

Actions:

1. Audit PR #102 against current `main`.
2. Classify every PR #102 change as already present, still missing, incompatible, or documentation-only.
3. Reimplement only still-needed deltas on current `main` with focused regression tests.
4. Close PR #102 as superseded after required deltas are integrated.
5. Create a v1.0 release evidence packet containing exact source SHA, workflow results, schemas, test summary, public-key trust assumptions and explicit non-claims.
6. Define required-check and protected-branch policy for the main branch.
7. Freeze new unrelated architecture branches during this phase.

Exit criteria:

- one current baseline;
- no stale bridge delta left unresolved;
- all v0.1–v1.0 workflows green;
- current trust root and authority boundaries documented;
- no direct stale-base merge.

### Phase 1 — Days 8–21: v1.1 identity contracts

**Goal:** bind governance approvals to authenticated organizational identities and protected key operations.

Actions:

1. Define a versioned identity-attestation schema.
2. Bind issuer, subject, audience, organization, group, role, repository, nonce, issue time and expiry.
3. Define KMS/HSM signing-operation receipt without exportable private keys.
4. Define rotation, deactivation and emergency revocation.
5. Add replay, role escalation, issuer confusion and stale assertion tests.
6. Implement provider-neutral verification first.
7. Add one reference OIDC adapter and one reference/mock KMS adapter only after the contracts pass review.

Exit criteria:

- approval can be traced to an authenticated subject and protected key operation;
- no token or private key enters the evidence bundle;
- identity evidence cannot replace exact v0.8 write authorization;
- offline verification is available wherever provider evidence permits it.

### Phase 2 — Days 15–28: threat model and capability contracts

This overlaps with identity implementation because it is mainly contract and adversarial-design work.

**Goal:** complete Phase 0 of issue #103 before building runtime mediation.

Actions:

1. Define sensitive capability classes:
   - repository read/write;
   - process execution;
   - package installation;
   - network connection;
   - credential access;
   - file-system scope;
   - child-process creation;
   - runtime-configuration mutation.
2. Define grant, use, delegate, revoke and expiry events.
3. Define containment state machine:

```text
DETECT → FREEZE → REVOKE → SEAL → SNAPSHOT → REVIEW → RELEASE | TERMINATE
```

4. Define causal-event schema compatible with Session Recorder.
5. Define objective-integrity violations: hidden-answer access, grader mutation, evidence fabrication, policy self-modification and constraint tampering.
6. Produce an attacker matrix and explicit non-goals.

Exit criteria:

- every sensitive action class has a typed capability;
- revocation and containment are first-class state transitions;
- missing runtime evidence fails closed;
- the threat model is strong enough to drive tests, not merely describe fears.

### Phase 3 — Days 22–35: portable evidence receipt profile

**Goal:** make a LiminalOSAI action independently verifiable without trusting the executing process.

Minimal integration path:

```text
LiminalOSAI execution evidence
→ ProofPath admission and receipt verification
→ CML causal-memory projection
→ LiminalDB durable transition projection
→ optional RINSE reinterpretation record
```

Actions:

1. Define one portable receipt schema that binds:
   - intent and transaction identity;
   - policy, plan and identity roots;
   - approval and capability roots;
   - exact calls and outputs by digest;
   - CI and exact-head state;
   - final decision;
   - recovery or containment state;
   - authority non-claims.
2. Build an offline verifier.
3. Create compatibility fixtures for ProofPath, CML and LiminalDB.
4. Reject semantic promotion: persistence, memory or review must not grant new execution authority.
5. Test redaction, selective disclosure, tampering and schema evolution.

Exit criteria:

- a second process can verify the receipt offline;
- every adapter preserves the same authority boundary;
- the receipt remains useful after secrets and bulky payloads are removed;
- replayed evidence cannot be presented as a new authorization.

### Phase 4 — Days 36–50: first governed GitHub pilot

**Goal:** prove operational value in one real, bounded workflow.

Recommended pilot scenario:

```text
human requests a small repository change
→ immutable plan
→ identity-bound policy approval
→ exact per-call write authorization
→ create branch
→ update one bounded file
→ open PR
→ run required checks
→ exact-head merge approval
→ merge or safe stop
→ portable receipt
→ independent offline verification
```

Pilot selection criteria:

- low blast radius;
- real repository and real operator;
- clear current manual workflow;
- measurable time or review burden;
- reversible change;
- no production deployment or secret rotation;
- willing design partner or internally owned non-critical repository.

Pilot metrics:

- time from intent to reviewable PR;
- number of manual approval steps;
- number of stale-state blocks;
- successful independent receipt verification rate;
- false-block rate;
- setup time for a new repository;
- operator comprehension of allow/block reasons;
- recovery success after an intentionally injected stale-head or failed-CI condition.

Exit criteria:

- one complete real workflow;
- no protected effect without all authority layers;
- a human can explain the final decision;
- the receipt verifies outside the executor;
- at least one intentionally injected failure stops safely;
- design-partner feedback identifies a repeated problem worth paying to remove.

### Phase 5 — Days 51–70: Capability Broker MVP

**Goal:** turn permissions from ambient configuration into explicit runtime objects.

Actions:

1. Implement capability grants with scope, TTL and parent authority.
2. Record grant/use/revoke/expiry in the evidence chain.
3. Enforce default deny for ungranted operations.
4. Bind each capability use to one transaction and call ID.
5. Prevent delegation beyond the parent grant.
6. Add stale, forged, replayed and over-broad grant tests.
7. Integrate capability state into the portable receipt.

Exit criteria:

- no sensitive runtime operation occurs without a live capability;
- capability growth is visible and attributable;
- revocation prevents subsequent use;
- a locally allowed tool call can still be blocked because the required runtime capability is absent.

### Phase 6 — Days 65–85: egress and containment prototype

**Goal:** demonstrate that locally permitted actions cannot silently compose into unapproved power.

Actions:

1. Mediate one bounded HTTP(S) egress path.
2. Bind destination, method, call ID, redirects and DNS result.
3. Keep secrets outside model-visible arguments.
4. Build a temporal capability-delta graph.
5. Implement deterministic escalation patterns.
6. Add `CONTAIN` as a first-class result.
7. Freeze execution, revoke capabilities, close egress, seal the trace and produce an incident receipt.
8. Test partial failure during containment.

Exit criteria:

- direct unapproved egress is denied;
- a dangerous multi-step trajectory can trigger containment even when individual steps are locally valid;
- containment produces independently verifiable evidence;
- explicit human release is required after containment.

### Phase 7 — Days 86–90: product decision

At day 90 choose one of four states:

- **PROCEED:** pilot demonstrates repeated operational value and the architecture survived adversarial testing.
- **REVISE:** problem is valuable but setup, identity, receipt or UX architecture is too heavy.
- **HOLD:** technical foundation is credible, but no design partner or workflow value is established.
- **STOP:** governance overhead exceeds value for the selected use case or the trust claims cannot be supported.

The decision must use pilot evidence, not code volume, test count or architectural elegance.

## 8. Immediate ordered backlog

| Order | Action | Dependency | Evidence of completion |
|---:|---|---|---|
| 1 | Reconcile PR #102 | current v1.0 main | current-main delta report and focused PR or superseded closure |
| 2 | Define protected baseline | step 1 | release evidence packet and required-check policy |
| 3 | Finish #103 Phase 0 threat model | baseline identity | reviewed schemas, attacker matrix and state machine |
| 4 | Implement v1.1 identity contracts | steps 1–2 | identity-attestation verifier and mutation tests |
| 5 | Define portable receipt | identity roots + current execution evidence | schema, fixtures and offline verifier |
| 6 | Add ProofPath verification adapter | portable receipt | independent verification result |
| 7 | Add CML/LiminalDB projections | verified receipt | causal-memory and durable-replay fixtures |
| 8 | Select pilot partner/workflow | steps 4–7 | written workflow baseline and success metrics |
| 9 | Run GitHub pilot | pilot selection | exact action receipt and user feedback |
| 10 | Implement Capability Broker | threat model + pilot lessons | live grant/use/revoke chain |
| 11 | Prototype egress/containment | capabilities | adversarial containment receipt |
| 12 | Make 90-day product decision | all prior evidence | PROCEED / REVISE / HOLD / STOP record |

## 9. Cross-repository task alignment

### ProofPath

Use only the minimum production spine required for the pilot:

- portable action receipt admission;
- exact-byte and provenance verification;
- reviewer identity/separation semantics where independently supported;
- offline verifier output.

Do not make the pilot wait for every historical PoCI, economy, witness-network or Control Cloud branch. Those become later capability modules after the first receipt is consumed by an external process.

### Causal Memory Layer

Prioritize one memory profile:

```text
observed failure or denial
→ verified receipt
→ bounded causal lesson
→ later plan receives advisory warning
→ no automatic authority grant
```

Vector recall and broader semantic memory remain useful, but the first integration should prove exact causal lineage and stable memory IDs.

### LiminalDB

Prioritize one durable transition profile:

```text
receipt admitted
→ journal append
→ snapshot
→ reopen
→ replay equality
→ recovery receipt
```

Historical stacked import PRs must be reconciled to current `main`; no production write is authorized merely because an offline contract validates.

### RINSE

Prioritize policy and incident reinterpretation:

```text
original decision preserved
→ new evidence appears
→ interpretation superseded or refined
→ source receipt remains immutable
```

RINSE never changes the original execution record and never authorizes a retry.

### TRACE / Kairos

Maintain one bounded scientific integration as a proof that the receipt model supports evidence gaps and claim boundaries. Do not make unresolved external scientific review a dependency of the software-delivery pilot.

### Smart Market Data Gateway / TMI

Use after the GitHub pilot or as a parallel bounded experiment for:

- time-window completeness;
- stale-stream detection;
- live-state expiry;
- no-signal behavior;
- recovery after partial evidence capture.

This is a strong second pilot because fast-changing data exposes stale evidence quickly.

### CareerOS / Career RINSE

Use as a separate operating lane with direct personal value:

- vacancy evidence;
- salary/order-book signals;
- interview and recruiter history;
- bounded portfolio cases;
- human-reviewed outreach queue.

This lane supports income and market learning while the core control plane matures.

## 10. Work-in-progress limits

At any moment:

- maximum **one** active LiminalOSAI implementation PR;
- maximum **one** active cross-repository integration PR;
- maximum **one** bounded application experiment;
- separate career/revenue tasks do not count as architecture PRs;
- no new stacked successor until the parent has a merge, close or explicit hold decision.

## 11. Decision and stop rules

Stop or revise work when any rule is violated:

1. A task cannot name the user problem it reduces.
2. A task has no dependency in the causal graph.
3. A task creates another source of execution authority.
4. A task cannot state which evidence proves completion.
5. A stale branch is being treated as current truth.
6. A signature is described as human identity without IdP/KMS evidence.
7. A memory or persistence layer is allowed to become authorization.
8. A scientific or market inference is promoted beyond its evidence.
9. A hosted-service feature is added before recovery and containment.
10. A new protocol is proposed before a second implementation needs interoperability.
11. Code volume is being used as a substitute for customer evidence.
12. More than the allowed work-in-progress limit is active.

## 12. Metrics hierarchy

### Trust metrics

- protected effects with complete authority chain;
- stale or substituted state rejection rate;
- independent receipt verification success;
- secret/private-key leakage count;
- recovery and containment integrity;
- percentage of decisions with human-readable causal explanation.

### Operational metrics

- pilot setup time;
- intent-to-reviewable-PR time;
- manual approval burden;
- false-block and false-allow rate in fixtures and pilot;
- mean time to safe stop;
- mean time to verified recovery.

### Product metrics

- repeated weekly use by a design partner;
- time saved compared with the prior workflow;
- reduced review ambiguity or incident-investigation time;
- willingness to continue or pay;
- number of repositories onboarded without custom architecture changes.

Tests and merged versions are input metrics, not proof of market value.

## 13. Definition of success at day 90

The plan succeeds when all of the following are true:

1. The v1.0 baseline is unambiguous and stale PR #102 is resolved.
2. At least one approval is bound to authenticated identity evidence and protected key custody.
3. A portable receipt verifies in an independent process.
4. One real GitHub workflow completes from human intent to safe merge or safe stop.
5. Stale head, expired identity, revoked authority, missing capability and failed CI each fail closed.
6. A durable replay proves the final evidence chain survives process restart.
7. At least one bounded failure produces a recovery or containment receipt.
8. A target user reports a concrete operational benefit or the project records an honest HOLD/REVISE decision.

The plan does **not** succeed merely because v1.1 or v1.2 code exists.

## 14. Governance of this execution plan

Changes to this document must state:

- the observed problem or new evidence;
- the affected dependency edge;
- the task being added, removed or reordered;
- the authority boundary;
- the completion evidence;
- the stop condition;
- whether the change affects the 90-day product decision.

Primary tracking issues:

- [#109 — execution epic](https://github.com/safal207/LiminalOSAI/issues/109)
- [#110 — stale bridge reconciliation](https://github.com/safal207/LiminalOSAI/issues/110)
- [#111 — identity, IdP and KMS bridge](https://github.com/safal207/LiminalOSAI/issues/111)
- [#103 — post-sandbox control plane](https://github.com/safal207/LiminalOSAI/issues/103)

The next implementation action is **#110**, not a new feature branch.