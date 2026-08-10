# RFC 0001 — Provider-Independent Trusted Cyber Research Continuity

- **Status:** Draft
- **Issue:** #176
- **Repository:** LiminalOSAI
- **Scope:** Experimental protocol design only
- **Security posture:** This RFC does not make LiminalOSAI a production security boundary.

## 1. Summary

This RFC proposes an experimental **Trusted Research Continuity Protocol (TRCP)** for authorized cybersecurity research that must remain auditable when an AI model or provider becomes unavailable, restricted, degraded, rate-limited, or otherwise unusable during an active investigation.

The central principle is:

> **The safety and evidence layer should survive the model provider.**

TRCP does **not** weaken provider safeguards and does **not** treat refusal as permission to bypass controls. Instead, it preserves the same authorization, target scope, environment constraints, evidence rules, and human-review requirements across provider transitions.

LiminalOSAI is used here only as an **experimental orchestration and trace-producing lab bench**. Any future hardened enforcement or evidence guarantees belong in the formal Liminal Evidence Stack.

## 2. Motivation

Authorized defensive-security work can depend on a single AI provider for analysis, code review, triage, or reproduction support. A provider transition can happen because of:

- policy or classifier refusal;
- account or workspace restriction;
- model access changes;
- quota or rate limits;
- outage or degraded availability;
- model retirement;
- organization or verification mismatch;
- provider-specific technical failure.

This creates a distinct failure mode:

**Provider Safety Dependency Failure (PSDF):** a lawful, authorized, evidence-producing defensive workflow cannot continue because its execution path is coupled to one provider.

OpenAI's Trusted Access for Cyber documentation is a useful reference because it explicitly aims to reduce unnecessary friction for authorized defensive workflows while preserving safeguards and access controls. It also states that approval does not remove every safeguard or guarantee access to every cyber-specialized model.

A public August 2026 report involving Bitcoin security researcher Rob Hamilton is a motivating case study for continuity design. Reports described a defensive workflow changing model providers after access disruption during active work. This RFC does not rely on every disputed or evolving detail of that incident; the protocol should be useful even if the motivating case is later clarified.

## 3. Goals

TRCP should:

1. preserve authorization across provider transitions without expanding it;
2. preserve target and action scope exactly or reduce it;
3. produce a durable record for every provider transition;
4. normalize outputs so findings are not coupled to one model schema;
5. require independent verification before a finding is treated as confirmed;
6. preserve enough lineage for later replay and audit;
7. support local deterministic simulation without contacting real targets.

## 4. Non-goals

TRCP is not intended to:

- bypass model safeguards;
- defeat provider abuse controls;
- authorize testing that was not already authorized;
- expand target scope during failover;
- automatically exploit public systems;
- treat model-generated findings as confirmed vulnerabilities;
- provide credential-stealing, persistence, evasion, or destructive workflows;
- claim production security enforcement from LiminalOSAI.

## 5. Core invariants

The following invariants are mandatory:

### I1 — Scope monotonicity

A fallback provider may receive **equal or narrower** permissions than the original provider run. Never broader.

### I2 — Authorization continuity

Failover is valid only while the original authorization remains valid for the target, time window, environment, and activity class.

### I3 — Refusal is not authorization

A refusal, block, account restriction, or provider policy decision is an execution event. It never grants permission to weaken controls.

### I4 — Every transition is recorded

A provider/model change must create a `FailoverDecisionRecord` before the next run begins.

### I5 — Findings remain untrusted

AI-generated findings remain `UNVERIFIED` until a deterministic or human-approved verification step changes their status.

### I6 — Provider neutrality

Authorization, scope, normalized findings, verification state, and disclosure state must not depend on provider-specific response formats.

### I7 — Sensitive evidence is minimized

Secrets, credentials, exploit artifacts, customer data, or sensitive traces must be redacted, isolated, or referenced by protected artifact identifiers rather than copied unnecessarily across providers.

## 6. Protocol record types

### 6.1 AuthorizationRecord

Defines the legal and operational basis for the research.

Required fields:

```text
authorization_id
subject_id
asset_id
authority_source
valid_from
valid_until
allowed_activity_classes
owner_or_authorizer
proof_reference
created_at
```

### 6.2 ScopeEnvelope

Defines what the research workflow may and may not do.

```text
scope_id
authorization_id
allowed_targets
allowed_environments
allowed_actions
prohibited_actions
rate_limits
compute_limits
data_handling_class
network_mode
expires_at
```

`network_mode` SHOULD default to `LOCAL_ONLY` for simulations and tests in this repository.

### 6.3 ProviderRunRecord

Captures one provider/model execution without treating provider output as ground truth.

```text
run_id
scope_id
provider_id
model_id
started_at
ended_at
normalized_task_hash
provider_request_reference
outcome
output_artifact_reference
```

Suggested `outcome` values:

```text
COMPLETED
REFUSED
ACCESS_RESTRICTED
RATE_LIMITED
PROVIDER_ERROR
TIMEOUT
ABORTED_BY_OPERATOR
```

### 6.4 FailoverDecisionRecord

Explains why a provider transition is permitted.

```text
failover_id
previous_run_id
scope_id
reason
scope_revalidated
new_provider_id
new_model_id
permission_delta
human_approval_required
human_approval_reference
created_at
```

`permission_delta` MUST be `UNCHANGED` or `NARROWER`.

### 6.5 FindingRecord

Provider-neutral representation of a suspected issue.

```text
finding_id
source_run_ids
asset_id
finding_class
location_reference
summary
severity_claim
confidence_claim
evidence_references
status
created_at
```

Suggested `status` values:

```text
UNVERIFIED
REPRODUCED
NOT_REPRODUCED
DISPUTED
NEEDS_HUMAN_REVIEW
CONFIRMED
REMEDIATED
```

### 6.6 VerificationRecord

Captures an independent verification attempt.

```text
verification_id
finding_id
method
verifier_type
verifier_reference
result
evidence_references
performed_at
```

Verification methods in the initial simulator MUST be local and deterministic.

### 6.7 DisclosureRecord

Tracks responsible disclosure without publishing sensitive material by default.

```text
disclosure_id
finding_id
asset_owner_reference
notification_state
embargo_state
remediation_state
public_reference
updated_at
```

## 7. State machine

TRCP uses the following abstract workflow states:

```text
NEW
  -> AUTHORIZED
  -> ACTIVE
  -> DEGRADED
  -> FAILOVER_PENDING
  -> ACTIVE_ON_FALLBACK
  -> VERIFYING
  -> DISCLOSURE_PENDING
  -> CLOSED
```

Additional terminal or blocking states:

```text
AUTH_EXPIRED
SCOPE_INVALID
HUMAN_REVIEW_REQUIRED
ABORTED
```

### Allowed transitions

```text
NEW -> AUTHORIZED
AUTHORIZED -> ACTIVE
ACTIVE -> VERIFYING
ACTIVE -> DEGRADED
DEGRADED -> FAILOVER_PENDING
FAILOVER_PENDING -> ACTIVE_ON_FALLBACK
FAILOVER_PENDING -> HUMAN_REVIEW_REQUIRED
FAILOVER_PENDING -> ABORTED
ACTIVE_ON_FALLBACK -> VERIFYING
VERIFYING -> DISCLOSURE_PENDING
VERIFYING -> CLOSED
DISCLOSURE_PENDING -> CLOSED
ANY_ACTIVE_STATE -> AUTH_EXPIRED
ANY_ACTIVE_STATE -> SCOPE_INVALID
```

### Forbidden transition examples

```text
REFUSED -> broader scope
ACCESS_RESTRICTED -> unauthorized provider action
AUTH_EXPIRED -> failover continuation
SCOPE_INVALID -> active execution
UNVERIFIED finding -> public confirmed claim
```

## 8. Failover decision algorithm

A failover MAY proceed only when all checks pass:

```text
1. original authorization is still valid
2. target remains inside the same authorization
3. requested action remains inside ScopeEnvelope
4. fallback permissions are unchanged or narrower
5. data handling policy permits transfer to fallback provider
6. sensitive artifacts are minimized/redacted as required
7. required human gate is satisfied
8. FailoverDecisionRecord is persisted
9. only then may fallback execution start
```

If any check fails, transition to `HUMAN_REVIEW_REQUIRED`, `SCOPE_INVALID`, `AUTH_EXPIRED`, or `ABORTED`.

## 9. Human-review gates

Human approval is required when:

- authorization language is ambiguous;
- a fallback provider would receive a new data class;
- sensitive evidence cannot be adequately minimized;
- requested activity changes from analysis to active validation;
- scope validity cannot be determined deterministically;
- providers disagree on a high-impact finding;
- a finding is proposed for external disclosure;
- the workflow would leave the local deterministic test environment.

The initial implementation in LiminalOSAI MUST NOT leave the local deterministic test environment.

## 10. Provider-neutral vs provider-specific data

### Provider-neutral

- authorization identity and validity;
- target scope;
- allowed/prohibited action classes;
- normalized task hash;
- normalized finding schema;
- verification state;
- disclosure state;
- causal lineage and timestamps.

### Provider-specific

- model identifier;
- request/run identifier;
- refusal or policy error code;
- raw response artifact;
- token/accounting metadata;
- provider-specific safety classification.

Provider-specific data should be referenced, not allowed to redefine the provider-neutral authorization or scope.

## 11. Evidence-stack mapping

This RFC maps concepts to the broader Liminal stack as follows:

| Concern | Candidate layer |
| --- | --- |
| Experimental orchestration and failover simulation | LiminalOSAI |
| Authorization / decision evidence | ProofPath / DRP |
| Causal lineage across provider transitions | CML |
| Durable append-only evidence substrate | TTM DB / LiminalDB |
| Replay and admissibility | LTP |
| Independent verification / retrospective analysis | RINSE |
| Smart-contract workload | ContractGraph-QA |
| Scientific verification workload | TRACE |
| Agent QA workload | LiminalQA |

This mapping is architectural intent, not a claim that every integration is implemented today.

## 12. Minimal deterministic simulator v0.1

The first implementation should prove only protocol behavior.

### Constraints

- local-only;
- no real targets;
- no network calls;
- no credentials;
- no exploit execution;
- fixed mock providers;
- deterministic fixtures;
- machine-readable trace output.

### Mock scenario

```text
Provider A accepts task 1
Provider A returns ACCESS_RESTRICTED on task 2
TRCP revalidates authorization + scope
TRCP records FailoverDecisionRecord
Provider B executes the same normalized task fixture
Provider B returns a synthetic finding
verification fixture reproduces or rejects the finding
trace closes with explicit final state
```

### Required simulator assertions

1. failover never broadens scope;
2. expired authorization blocks continuation;
3. missing failover record blocks fallback execution;
4. provider-specific output does not change authorization;
5. unverified findings cannot become confirmed without verification;
6. deterministic replay produces the same state transitions and hashes.

## 13. Security considerations

The largest risk in a continuity protocol is accidentally turning redundancy into a control bypass. Therefore TRCP must treat provider failover as a **stricter evidence event**, not a relaxation event.

A second risk is uncontrolled data propagation. Switching providers can create new confidentiality and retention boundaries. The scope envelope therefore includes data-handling constraints, and failover can require human approval even when the activity itself is otherwise authorized.

A third risk is false-confidence amplification: multiple models repeating the same claim is not independent verification. Verification should be based on deterministic evidence, independent reproduction, or explicit qualified human review.

## 14. Relationship to `docs/EXPERIMENTAL_SCOPE.md`

This RFC follows the repository's existing reviewer boundary:

> LiminalOSAI is the lab bench. The Liminal Evidence Stack is the formal reviewer path.

TRCP in this repository is therefore an experimental protocol and simulator design. It is not a claim of production-grade authorization enforcement, cybersecurity certification, or secure multi-provider orchestration.

## 15. Acceptance criteria for RFC v0.1

- [x] Threat model includes provider-dependency failure.
- [x] Seven protocol records are defined.
- [x] State machine and forbidden transitions are defined.
- [x] Provider-neutral and provider-specific data are separated.
- [x] Human-review gates are specified.
- [x] Sensitive-evidence handling is addressed.
- [x] Motivating case is included with explicit uncertainty boundaries.
- [x] Experimental-scope boundary is explicit.
- [x] Local deterministic simulator requirements are defined.

## 16. Open questions

1. Which record schemas should graduate first into DRP / CML formal schemas?
2. Should `ScopeEnvelope` be signed or content-addressed in the first prototype?
3. What exact normalized task representation should produce `normalized_task_hash`?
4. Which failover reasons require mandatory human approval even in simulation?
5. What is the minimum provider adapter interface needed to keep the simulator provider-neutral?

## 17. References

- OpenAI, **Introducing Trusted Access for Cyber**: https://openai.com/index/trusted-access-for-cyber/
- OpenAI Help Center, **Trusted Access for Cyber Overview**: https://help.openai.com/en/articles/20001258-trusted-access-for-cyber
- OpenAI Help Center, **Trusted Access for Cyber — Common Issues and Troubleshooting**: https://help.openai.com/en/articles/20001259
- Public Rob Hamilton post used only as a motivating incident reference: https://x.com/Rob1Ham/status/2086464831360549034
- LiminalOSAI experimental boundary: `docs/EXPERIMENTAL_SCOPE.md`

## 18. Proposed next implementation issue

After review of this RFC, create a separate implementation issue for a **local deterministic TRCP simulator**. Do not connect the first simulator to live providers or real cybersecurity targets.
