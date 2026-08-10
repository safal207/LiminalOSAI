# RFC 0001 — Provider-Independent Trusted Cyber Research Continuity

- **Status:** Draft
- **Issues:** #176, #178
- **Repository:** LiminalOSAI
- **Scope:** Experimental protocol design + local deterministic reference simulator
- **Security posture:** This RFC does not make LiminalOSAI a production security boundary.

## 1. Summary

This RFC defines an experimental **Trusted Research Continuity Protocol (TRCP)** for authorized cybersecurity research that must remain auditable when an AI model or provider becomes unavailable, restricted, degraded, rate-limited, or otherwise unusable during an active investigation.

The central principle is:

> **The safety and evidence layer should survive the model provider.**

TRCP does not weaken provider safeguards and does not interpret refusal as permission to bypass controls. A provider transition may preserve or narrow an already-valid authorization and scope, but it may never expand them.

LiminalOSAI is used only as an experimental orchestration and trace-producing lab bench. Formal enforcement and evidence guarantees belong in the broader Liminal Evidence Stack.

## 2. Motivation

Authorized defensive-security work can become operationally coupled to one AI provider for analysis, triage, code review, or reproduction support. A provider transition can happen because of:

- policy/classifier refusal;
- account or workspace restriction;
- model access changes;
- quota or rate limits;
- service outage or degraded availability;
- model retirement;
- organization or verification mismatch;
- provider-specific technical failure.

This creates a continuity failure mode:

**Provider Safety Dependency Failure (PSDF):** a lawful, authorized, evidence-producing defensive workflow cannot continue because its execution path is coupled to one provider.

A public August 2026 report involving Bitcoin security researcher Rob Hamilton is used only as a motivating continuity case. This RFC does not depend on every evolving or disputed detail of that incident.

## 3. Goals

TRCP should:

1. preserve authorization across provider transitions without expanding it;
2. preserve or narrow target/action/environment scope;
3. make the approved fallback scope the effective runtime scope;
4. record every provider transition before fallback execution;
5. normalize findings independently of provider output format;
6. require deterministic or qualified human verification before confirmation;
7. preserve causal lineage for later replay and audit;
8. fail closed into explicit states when failover checks do not pass;
9. support a fully local deterministic simulator with no live providers or targets.

## 4. Non-goals

TRCP v0.1 is not intended to:

- bypass model safeguards;
- defeat provider abuse controls;
- authorize activity that was not already authorized;
- expand target or action scope during failover;
- automatically exploit public systems;
- treat model-generated findings as confirmed vulnerabilities;
- provide credential-stealing, persistence, evasion, or destructive workflows;
- contact live AI providers;
- contact real cybersecurity targets;
- automate public disclosure;
- claim production safety enforcement from LiminalOSAI.

## 5. v0.1 execution boundary

The first simulator is intentionally narrow.

It accepts only:

```text
network_mode = LOCAL_ONLY
data_handling_class = SYNTHETIC_ONLY
allowed_environments ⊆ {LOCAL_FIXTURE}
```

Any non-local or non-synthetic fallback is rejected before execution. In the simulator, such a transition enters `HUMAN_REVIEW_REQUIRED` rather than silently relaxing the boundary.

No credentials, live targets, exploit execution, provider APIs, or automatic disclosure are available in v0.1.

## 6. Core invariants

### I1 — Scope monotonicity

A fallback provider may receive equal or narrower permissions than the current effective scope. Never broader.

The identity of a scope record (`scope_id`) does not itself define permission change. `permission_delta` is calculated from permission semantics: targets, actions, environments, prohibited actions, data handling, network mode, and expiry.

### I2 — Effective fallback scope

After a `FailoverDecisionRecord` is persisted, its approved `fallback_scope` becomes the effective scope for all subsequent fallback task validation, provider-run records, and reports.

The original scope remains available as historical evidence but is no longer used as the active fallback permission set.

### I3 — Authorization continuity

Failover is valid only while the original authorization remains valid for the asset, time window, and activity class.

Expired authorization transitions to `AUTH_EXPIRED` and stops continuity.

### I4 — Refusal is not authorization

A refusal, block, provider policy decision, or access restriction is an execution event. It never grants permission to weaken controls.

### I5 — Every provider transition is recorded

Fallback execution is blocked until a durable `FailoverDecisionRecord` exists and matches the intended fallback provider/model.

### I6 — Findings remain untrusted

AI-generated findings remain `UNVERIFIED` until deterministic verification or an explicitly qualified human review updates their status.

### I7 — Provider neutrality

Authorization, effective scope, normalized findings, verification state, and disclosure state are provider-neutral records. Provider output cannot mutate them.

### I8 — Sensitive evidence is minimized

Failover requires data-handling approval and sensitive-artifact minimization. If either requirement is not satisfied, v0.1 transitions to `HUMAN_REVIEW_REQUIRED`.

## 7. Protocol record types

### 7.1 AuthorizationRecord

Defines the legal and operational basis for the research.

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

### 7.2 ScopeEnvelope

Defines what the workflow may and may not do.

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

For v0.1, `network_mode` must be `LOCAL_ONLY` and `data_handling_class` must be `SYNTHETIC_ONLY`.

### 7.3 ProviderRunRecord

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

Suggested outcomes:

```text
COMPLETED
REFUSED
ACCESS_RESTRICTED
RATE_LIMITED
PROVIDER_ERROR
TIMEOUT
ABORTED_BY_OPERATOR
```

### 7.4 FailoverDecisionRecord

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
data_handling_approved
sensitive_artifacts_minimized
human_approval_required
human_approval_reference
created_at
```

`permission_delta` must be `UNCHANGED` or `NARROWER`.

### 7.5 FindingRecord

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

Suggested statuses:

```text
UNVERIFIED
REPRODUCED
NOT_REPRODUCED
DISPUTED
NEEDS_HUMAN_REVIEW
CONFIRMED
REMEDIATED
```

### 7.6 VerificationRecord

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

The v0.1 simulator uses a local deterministic fixture verifier only.

### 7.7 DisclosureRecord

Tracks responsible disclosure state.

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

**Disclosure handling is optional and deferred in simulator v0.1.** The protocol reserves this record type, but the reference simulator does not create external disclosure records and reports `disclosure: null`. Therefore a verified local simulation may close directly from `VERIFYING` without entering `DISCLOSURE_PENDING`.

A future disclosure-enabled implementation must define and test the additional transition path before it is enabled.

## 8. State machine

Primary workflow states:

```text
NEW
  -> AUTHORIZED
  -> ACTIVE
  -> DEGRADED
  -> FAILOVER_PENDING
  -> ACTIVE_ON_FALLBACK
  -> VERIFYING
  -> CLOSED
```

Blocking/terminal states:

```text
AUTH_EXPIRED
SCOPE_INVALID
HUMAN_REVIEW_REQUIRED
ABORTED
```

Reserved future disclosure state:

```text
DISCLOSURE_PENDING
```

### Allowed v0.1 transitions

```text
NEW -> AUTHORIZED
AUTHORIZED -> ACTIVE
ACTIVE -> VERIFYING
ACTIVE -> DEGRADED
ACTIVE -> ABORTED
DEGRADED -> FAILOVER_PENDING
FAILOVER_PENDING -> ACTIVE_ON_FALLBACK
FAILOVER_PENDING -> AUTH_EXPIRED
FAILOVER_PENDING -> SCOPE_INVALID
FAILOVER_PENDING -> HUMAN_REVIEW_REQUIRED
FAILOVER_PENDING -> ABORTED
ACTIVE_ON_FALLBACK -> VERIFYING
ACTIVE_ON_FALLBACK -> AUTH_EXPIRED
ACTIVE_ON_FALLBACK -> SCOPE_INVALID
ACTIVE_ON_FALLBACK -> ABORTED
VERIFYING -> CLOSED
```

### Failover failure mapping

When a failover check fails, the simulator persists the state transition in the trace before raising an error:

- authorization no longer valid -> `AUTH_EXPIRED`;
- scope invalid/expired/broader than current effective scope -> `SCOPE_INVALID`;
- non-local/non-synthetic data boundary -> `HUMAN_REVIEW_REQUIRED`;
- data handling not approved -> `HUMAN_REVIEW_REQUIRED`;
- sensitive artifacts not minimized -> `HUMAN_REVIEW_REQUIRED`;
- mandatory human approval missing -> `HUMAN_REVIEW_REQUIRED`;
- fallback provider does not match the decision record -> `ABORTED`.

No failed failover check may leave the workflow silently parked in `FAILOVER_PENDING` as though it were still executable.

## 9. Executable failover algorithm

A failover may proceed only when all checks pass:

```text
1. current state == FAILOVER_PENDING
2. original authorization is still valid
3. candidate fallback scope is LOCAL_ONLY
4. candidate data handling is SYNTHETIC_ONLY
5. candidate scope validates against authorization and time
6. candidate permissions are equal to or narrower than current effective scope
7. data-handling approval is true
8. sensitive artifacts are minimized
9. if a human gate is required, an approval reference exists
10. persist FailoverDecisionRecord
11. make candidate scope the effective scope
12. only then allow fallback execution
```

Fallback execution then revalidates authorization, validates the exact task against the effective fallback scope, and verifies that the normalized task hash matches the original provider run.

## 10. Human-review gates

Human review is required when:

- authorization language is ambiguous;
- the fallback data class is outside the v0.1 synthetic boundary;
- sensitive artifacts are not minimized;
- data-handling approval is absent;
- an explicitly required human approval reference is absent;
- providers disagree on a high-impact finding;
- external disclosure is proposed;
- the workflow would leave the local deterministic environment.

The simulator includes executable paths for the first four failover-related cases and records `HUMAN_REVIEW_REQUIRED` in the trace.

## 11. Provider-neutral vs provider-specific data

### Provider-neutral

- authorization identity and validity;
- initial and effective scope;
- allowed/prohibited action classes;
- normalized task hash;
- normalized finding schema;
- verification state;
- disclosure state;
- causal lineage and timestamps.

### Provider-specific

- provider/model identifier;
- provider request/run identifier;
- refusal or error code;
- raw provider output artifact;
- provider accounting metadata;
- provider-specific safety classification.

Provider-specific data may be referenced as evidence but may not redefine authorization or effective scope.

## 12. Evidence-stack mapping

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

This is architectural intent, not a claim that all integrations exist today.

## 13. Minimal deterministic simulator v0.1

### Constraints

- local-only;
- synthetic-only data;
- no real targets;
- no network calls;
- no credentials;
- no exploit execution;
- fixed mock providers;
- deterministic fixtures;
- hash-chained machine-readable trace;
- no automatic disclosure.

### Default scenario

```text
Provider A accepts the synthetic task context
Provider A returns ACCESS_RESTRICTED
TRCP enters DEGRADED -> FAILOVER_PENDING
TRCP revalidates authorization and scope
TRCP persists FailoverDecisionRecord
approved fallback scope becomes effective
Provider B executes the same normalized task fixture
Provider B returns a synthetic finding
local verification reproduces the finding
finding becomes CONFIRMED
trace closes in CLOSED
```

## 14. Required simulator assertions

The implementation must verify:

1. failover cannot broaden scope;
2. a narrower fallback scope becomes the effective scope;
3. an action removed by the narrower scope is rejected during fallback;
4. expired authorization transitions to `AUTH_EXPIRED`;
5. missing failover record blocks fallback execution;
6. provider-specific output cannot mutate authorization/scope;
7. unverified findings cannot become confirmed;
8. deterministic replay produces identical transitions and hashes;
9. non-`LOCAL_ONLY` scope is rejected;
10. non-`SYNTHETIC_ONLY` failover enters `HUMAN_REVIEW_REQUIRED`;
11. unapproved data handling enters `HUMAN_REVIEW_REQUIRED`;
12. unminimized sensitive artifacts enter `HUMAN_REVIEW_REQUIRED`;
13. a required human gate must have an approval reference.

## 15. Security considerations

The largest risk is accidentally turning redundancy into a control bypass. TRCP therefore treats failover as a stricter evidence event, not a relaxation event.

A second risk is uncontrolled data propagation. Provider switching can create confidentiality and retention boundaries, so the v0.1 simulator fails closed outside `SYNTHETIC_ONLY` data.

A third risk is false-confidence amplification. Multiple models repeating the same claim is not independent verification. Confirmation requires deterministic evidence or an explicitly qualified human verification path.

A fourth risk is a stale effective scope. The implementation therefore updates the active scope only after the failover decision has been persisted and uses that effective scope for fallback task validation, provider-run records, and reports.

## 16. Relationship to `docs/EXPERIMENTAL_SCOPE.md`

This RFC follows the repository boundary:

> LiminalOSAI is the lab bench. The Liminal Evidence Stack is the formal reviewer path.

TRCP in this repository is an experimental protocol and simulator. It is not a production authorization service, security certification, or secure multi-provider orchestration product.

## 17. Acceptance criteria for RFC/simulator v0.1

- [x] Provider-dependency failure is documented.
- [x] Seven protocol record types are defined.
- [x] Scope monotonicity is defined and executable.
- [x] Approved fallback scope becomes the effective scope.
- [x] Failure transitions from `FAILOVER_PENDING` are explicit.
- [x] Provider-neutral and provider-specific data are separated.
- [x] Data-handling/minimization/human gates are executable.
- [x] Non-`LOCAL_ONLY` scope is rejected and tested.
- [x] Non-`SYNTHETIC_ONLY` failover is rejected into human review.
- [x] Disclosure is explicitly optional/deferred in simulator v0.1.
- [x] Motivating case is bounded by uncertainty language.
- [x] Experimental-scope boundary is explicit.
- [x] Deterministic replay and hash-chain behavior are tested.

## 18. v0.2 acceptance criteria

- [x] Evidence adapter builds provider-neutral bundle from v0.1 report
- [x] Bundle is deterministically serialized
- [x] Causal lineage is explicit and deterministic
- [x] Replay verifier does not use TRCPSimulator execution methods
- [x] Replay verifier checks 13 semantic invariants
- [x] Receipt is deterministic with stable SHA-256
- [x] 17 adversarial mutation tests fail verification
- [x] LOCAL_ONLY / SYNTHETIC_ONLY boundary preserved
- [x] CLI: `make trcp-replay`
- [x] Existing v0.1 tests still pass

## 19. Next hardening work

The first local deterministic simulator now exists. Follow-up work should focus on hardening rather than creating the simulator again:

1. graduate selected records into DRP/CML schemas;
2. add content-addressed or signed `ScopeEnvelope` experiments;
3. formalize transition schemas and replay receipts;
4. add property-based tests for scope monotonicity;
5. define a provider adapter interface that still uses mock providers only;
6. define a production-boundary review before any live-provider integration is considered;
7. keep real cybersecurity targets and live exploitation out of this repository unless separately authorized, designed, and reviewed.

## 20. TRCP v0.2 — Evidence adapter and independent replay

v0.2 adds an **evidence adapter** and an **independent replay verifier** on top of the v0.1 simulator. It does not modify v0.1 execution logic.

### 20.1 Evidence adapter

`sdk/liminal_trcp/evidence.py` accepts a completed v0.1 report and produces a provider-neutral evidence bundle:

```text
{
  "schema": "liminal-trcp-evidence-v0.2",
  "source_report_sha256": "...",
  "authorization": {...},
  "initial_scope": {...},
  "effective_scope": {...},
  "provider_runs": [...],
  "failover_decision": {...},
  "finding": {...} | null,
  "verification": {...} | null,
  "trace": [...],
  "causal_lineage": [...],
  "bundle_sha256": "..."
}
```

The bundle is deterministically serialized. Same input produces the same bundle and the same `bundle_sha256`.

### 20.2 Causal lineage

The evidence bundle explicitly records causal edges:

```text
AUTHORIZATION -> PRIMARY_RUN
PRIMARY_RUN -> PROVIDER_FAILURE
PROVIDER_FAILURE -> FAILOVER_DECISION
FAILOVER_DECISION -> EFFECTIVE_SCOPE
EFFECTIVE_SCOPE -> FALLBACK_RUN
FALLBACK_RUN -> FINDING
FINDING -> VERIFICATION
VERIFICATION -> CLOSED
```

Each edge has a deterministic `edge_id`. No UUIDs or random timestamps.

### 20.3 Independent replay verifier

`sdk/liminal_trcp/replay.py` validates evidence bundles **without** using `TRCPSimulator` execution methods. The verifier checks invariants from the bundle alone:

1. **BUNDLE_INTEGRITY** — bundle SHA-256 matches canonical serialization
2. **TRACE_HASH_CHAIN** — trace events form a valid SHA-256 chain
3. **TEMPORAL_ORDER** — timestamps are monotonically non-decreasing
4. **STATE_TRANSITION** — every state transition is legal per the v0.1 state machine
5. **CAUSAL_ORDER** — cause precedes effect (failover before fallback, finding before verification)
6. **AUTHORIZATION_CONTINUITY** — authorization_id is stable across all records
7. **SCOPE_MONOTONICITY** — effective scope ⊆ initial scope (equal-or-narrower)
8. **PROHIBITED_ACTION** — prohibited actions never appear in allowed set
9. **FAILOVER_DECISION_REQUIRED** — failover decision exists before fallback execution
10. **TASK_IDENTITY** — fallback normalized_task_hash matches primary
11. **VERIFICATION_CLOSURE** — CONFIRMED finding requires REPRODUCED verification
12. **VERIFICATION_CONSISTENCY** — verification finding_id matches finding
13. **FINAL_STATE** — final state is terminal

### 20.4 Deterministic verification receipt

The verifier produces a receipt:

```text
{
  "schema": "liminal-trcp-replay-receipt-v0.2",
  "result": "PASS" | "FAIL",
  "source_bundle_sha256": "...",
  "checks": [...],
  "failed_check": "..."  // only on FAIL
  "receipt_sha256": "..."
}
```

Same bundle → same receipt → same receipt SHA-256.

### 20.5 Security boundary

> Replay validates evidence produced by the experimental local simulator.
> It does not establish a production security boundary.

v0.2 remains **LOCAL_ONLY** and **SYNTHETIC_ONLY**. No live providers, no network, no real targets.

### 20.6 Tests

`tests/test_trcp_evidence_replay.py` covers:

- Happy-path PASS
- 17 adversarial mutation tests (each must produce FAIL)
- Deterministic receipt verification
- Independence from simulator execution methods
- Causal lineage integrity

### 20.7 CLI

```bash
python3 scripts/replay_trcp_evidence.py
make trcp-replay
```

Runs the full pipeline: simulator → report → evidence → replay → receipt.

## 21. References

- OpenAI, **Introducing Trusted Access for Cyber**: https://openai.com/index/trusted-access-for-cyber/
- OpenAI Help Center, **Trusted Access for Cyber Overview**: https://help.openai.com/en/articles/20001258-trusted-access-for-cyber
- OpenAI Help Center, **Trusted Access for Cyber — Common Issues and Troubleshooting**: https://help.openai.com/en/articles/20001259
- Public Rob Hamilton post used only as a motivating incident reference: https://x.com/Rob1Ham/status/2086464831360549034
- LiminalOSAI experimental boundary: `docs/EXPERIMENTAL_SCOPE.md`
