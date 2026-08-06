# LiminalOSAI Roadmap

> **Repository status: ROADMAP + REFERENCE IMPLEMENTATION**
>
> This repository is the canonical public roadmap and experimental reference implementation for a trustworthy control plane for AI agents.

LiminalOSAI explores how an AI agent can receive real operational authority without receiving unlimited or unverifiable power.

The target is a system that can transform human intent into bounded, reviewable, cryptographically attributable machine action:

```text
INTENT
→ PLAN
→ POLICY
→ APPROVAL
→ SIGNATURE
→ EXECUTION
→ EVIDENCE
→ ACCOUNTABILITY
```

## North Star

Build an agent control plane in which:

- every action is tied to an explicit user or organizational intent;
- plans are immutable, inspectable, and fail closed when they drift;
- authority is scoped by repository, action, risk, identity, time, and environment;
- risky operations require independent approvals;
- approvals are cryptographically attributable;
- execution remains separately authorized at the exact tool-call level;
- evidence survives across systems and can be independently verified;
- an agent can stop, refuse, or return `NO_SIGNAL` when confidence or authority is insufficient.

The long-term product direction is not “an agent with root access.” It is a **trustworthy runtime for bounded autonomous work**.

## Status legend

| Status | Meaning |
|---|---|
| ✅ Complete | Merged and validated by CI; not necessarily production-ready |
| 🚧 Active | Current implementation target |
| 🧭 Planned | Scoped direction with expected contracts |
| 🔭 Research | Open design or research area |

## Current architecture

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

## Completed foundation

### ✅ v0.1 — Liminal Adapter

- Converts structured conversation input into a deterministic safety decision.
- Produces `ALLOW`, `VERIFY`, `REVISE`, or `NO_SIGNAL`.
- Keeps evidence and authority boundaries explicit.

### ✅ v0.2 — Conversation Normalizer

- Normalizes host conversation records into a stable schema.
- Rejects malformed and ambiguous input.
- Preserves exact evidence references.

### ✅ v0.3 — Live Session Exporter

- Exports a recorded session into the normalizer and adapter pipeline.
- Preserves deterministic links between request, draft, claims, and evidence.

### ✅ v0.4 — Session Recorder SDK

- Append-only session event recording.
- Explicit user messages, assistant drafts, claims, and evidence bindings.
- Tamper-evident journal semantics.

### ✅ v0.5 — Host Integration Adapter

- Separates host-owned execution from agent-owned reasoning.
- Defines bounded integration contracts without claiming access to host credentials.

### ✅ v0.6 — GitHub Agent Bridge

- Introduces a narrow GitHub action catalog.
- Binds allowed repositories and host traces.
- Keeps GitHub credentials and connector ownership outside the SDK.

### ✅ v0.7 — Connected GitHub Runtime

- Normalizes connected GitHub calls and responses.
- Enforces response-size and schema boundaries.
- Produces stable receipts for downstream evidence.

### ✅ v0.8 — GitHub Transaction Orchestrator

- Executes immutable multi-step GitHub transaction plans.
- Uses exact per-step write authorization.
- Adds checkpoints, expectations, CI gates, and an append-only transaction journal.
- Prevents implicit replay or automatic authorization.

### ✅ v0.9 — Transaction Policy & Approval Engine

- Evaluates the whole transaction before execution.
- Adds risk-based approval requirements.
- Adds an append-only approval ledger with denial vetoes.
- Requires distinct principals for critical merge authority.
- Does not replace v0.8 exact write authorization.

### ✅ v1.0 — Signed Governance Capsule

- Adds portable Ed25519-signed governance capsules.
- Binds policy, snapshot, plan, approval ledger, journal anchor, issuer, key, audience, and expiry.
- Adds offline trust-store verification.
- Supports key validity, revocation, TTL, clock skew, and journal ancestry.
- Keeps private keys outside evidence artifacts.
- Proves possession of a trusted key, but does not independently prove real-world human identity.

## Active roadmap

### 🚧 v1.1 — Identity, IdP, and KMS Attestation Bridge

**Goal:** connect signed authority to real organizational identity and protected key custody.

Planned capabilities:

- OIDC/SAML identity assertions;
- issuer and subject binding to verified IdP claims;
- KMS/HSM-backed signing without exportable private keys;
- key rotation and emergency revocation;
- organization, team, and service-account identities;
- role and group mapping;
- short-lived delegated authority;
- signed identity evidence attached to the governance capsule;
- offline verification of the identity-to-key binding where possible.

Production gate:

- the system must never claim that a key identifies a person unless the IdP/KMS evidence supports that claim.

### 🧭 v1.2 — Multi-Agent Governance Control Plane

**Goal:** govern several specialized agents as one coordinated system.

Planned roles may include:

- planner;
- developer;
- QA reviewer;
- security reviewer;
- release manager;
- evidence auditor;
- rollback coordinator.

Planned capabilities:

- agent registry and capability manifests;
- least-authority delegation;
- separation of duties;
- quorum and threshold approvals;
- conflict-of-interest rules;
- parent/child transaction graphs;
- budget, time, and tool-call limits;
- coordinated stop and recovery protocols;
- cross-agent evidence chains.

### 🧭 v1.3 — Policy as Code and Organization Guardrails

**Goal:** make governance rules portable, reviewable, and reusable across teams.

Planned capabilities:

- versioned policy bundles;
- organization and repository policy inheritance;
- reusable risk classes;
- environment-aware rules for development, staging, and production;
- approval matrices;
- protected action catalogs;
- policy simulation before execution;
- explainable denial and remediation output;
- compatibility adapters for external policy engines where useful.

### 🧭 v1.4 — Portable Evidence Receipt Protocol

**Goal:** allow independent systems to verify what happened without trusting the original host.

Planned capabilities:

- standard machine-readable execution receipts;
- canonical content-addressed evidence bundles;
- inclusion and ancestry proofs;
- selective disclosure and redaction proofs;
- external timestamping;
- verifier CLI and SDKs;
- evidence export for audits, incident response, and compliance;
- integration path for TRACE scientific verification receipts.

### 🧭 v1.5 — Recovery, Compensation, and Rollback Governance

**Goal:** make failure handling as governed and attributable as forward execution.

Planned capabilities:

- explicit recovery plans before high-risk actions;
- rollback readiness checks;
- compensation transaction plans;
- recovery approvals;
- partial-failure reconciliation;
- non-replayable recovery tokens;
- evidence-linked incident reports;
- human takeover and safe-stop procedures.

### 🧭 v1.6 — Hosted Agent Governance Service

**Goal:** turn the reference implementation into an operational control plane.

Planned capabilities:

- organization and workspace management;
- hosted trust-store and policy management;
- GitHub App integration;
- Slack/Jira approval workflows;
- audit explorer;
- transaction and agent dashboards;
- encrypted evidence storage;
- tenant isolation;
- usage limits and billing boundaries;
- webhook and event ingestion;
- production observability and incident response.

## Protocol horizon

### 🔭 v2.0 — Open Agent Authority Protocol

**Goal:** define an interoperable protocol for safe delegation and verifiable agent action across vendors and tools.

Candidate protocol objects:

- intent envelope;
- immutable action plan;
- capability and authority manifest;
- policy decision;
- approval requirement;
- signed governance capsule;
- execution receipt;
- evidence bundle;
- recovery receipt;
- final accountability record.

Potential integration domains:

- source control and software delivery;
- cloud infrastructure and DevOps;
- scientific verification and TRACE;
- enterprise workflows and procurement;
- financial operations;
- regulated data systems;
- robotics and cyber-physical systems.

## Production-readiness gates

The roadmap is not complete when features merely exist. A production release must satisfy all applicable gates below.

### Security

- independent threat model;
- external security review;
- key custody through KMS/HSM;
- dependency and supply-chain controls;
- secret-leak prevention;
- replay resistance;
- denial-of-service and abuse analysis;
- adversarial testing of policy and approval bypasses.

### Correctness

- deterministic canonicalization;
- schema compatibility tests;
- property-based and fuzz testing;
- recovery and partial-failure tests;
- exact-head and stale-state protection;
- cross-platform verification;
- migration and rollback testing.

### Operations

- observability and audit search;
- incident response playbooks;
- backup and evidence retention policies;
- service-level objectives;
- tenant isolation;
- rate and budget controls;
- disaster recovery.

### Governance

- documented authority boundaries;
- approval and revocation procedures;
- separation of duties;
- privacy and data-minimization review;
- human override and safe-stop behavior;
- clear non-claims about identity, causality, and autonomy.

## Near-term execution order

1. **v1.1 Identity, IdP, and KMS Attestation Bridge**
2. **Threat model and attacker matrix for v1.0–v1.1**
3. **Multi-agent authority registry and delegation contracts**
4. **Portable evidence receipt specification**
5. **Recovery and compensation transaction model**
6. **Hosted control-plane prototype**

## What this repository is

- a canonical roadmap;
- an experimental reference implementation;
- a collection of deterministic governance contracts;
- a test bed for bounded agent authority;
- a foundation for future protocol and product work.

## What this repository is not

- a production operating system;
- proof of AGI or machine consciousness;
- a complete security boundary by itself;
- an identity provider;
- a key-management service;
- authorization to execute external actions without the host’s own controls;
- a replacement for independent security review.

## Roadmap governance

Changes to this roadmap should:

1. state the user or organizational problem;
2. define the authority boundary;
3. identify failure and abuse modes;
4. specify evidence produced;
5. preserve compatibility with lower layers where possible;
6. include tests and explicit non-claims;
7. avoid presenting research prototypes as production guarantees.

The roadmap is expected to evolve as implementation evidence, security review, and real integrations reveal better designs.
