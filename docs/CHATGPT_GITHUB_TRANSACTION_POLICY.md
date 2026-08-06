# GitHub Transaction Policy & Approval Engine v0.9

v0.9 adds a **whole-plan policy and approval boundary** above GitHub Transaction Orchestrator v0.8.

It answers:

> Is this immutable multi-step transaction permitted by an explicit policy, and have all required approvals been recorded before execution begins?

## Stack position

```text
Policy & Approval Engine v0.9
→ Transaction Orchestrator v0.8
→ Connected GitHub Runtime v0.7
→ GitHub Agent Bridge v0.6
→ Host Integration Adapter v0.5
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
```

## Guarantees

1. The complete transaction plan is evaluated before execution.
2. The policy snapshot binds exact `plan_sha256` and `policy_sha256` values.
3. Editing, reordering, adding, or removing a step invalidates the snapshot.
4. Every action needs an explicit rule; unruled actions are denied.
5. Repository, total-step, write-step, critical-step, and occurrence limits are enforced.
6. Required approvals are structured attestations, never inferred from prose.
7. Approvals bind one exact snapshot and become stale after plan or policy drift.
8. A denial attestation vetoes execution.
9. A principal cannot fill two roles for the same requirement.
10. Policy readiness never replaces v0.8 exact write authorization.

## Default profile

| Risk | Actions | Approval |
|---|---|---|
| Low | repository/file/PR reads, compare, CI status | none |
| Moderate | branch/blob/tree/commit creation | one `operator`, transaction-scoped per action |
| High | file create/update/delete, ref update, PR creation | one `reviewer` per step |
| Critical | PR merge | one `reviewer` and one `release_manager`, distinct principals |

The fixed profile covers the current GitHub operation catalog. Registry drift fails closed.

## Policy document

A policy includes:

- policy identity;
- repository allowlist;
- maximum total, write, and critical steps;
- one exact rule per configured action;
- fixed authority limitations;
- `policy_sha256`.

Example merge rule:

```json
{
  "action": "merge_pull_request",
  "allowed": true,
  "risk_level": "critical",
  "approval_scope": "step",
  "required_role_counts": {
    "release_manager": 1,
    "reviewer": 1
  },
  "require_distinct_principals": true,
  "require_recovery_plan": true,
  "max_occurrences": 64
}
```

Wildcard actions, dynamic connector methods, arbitrary URLs, and hidden extensions are not accepted.

## Snapshot

Evaluation produces a deterministic snapshot containing:

- policy and plan hashes;
- transaction and repository identity;
- `allow` or `deny`;
- deterministic denial reasons;
- risk counts;
- exact approval requirements;
- `snapshot_sha256`.

Example requirement IDs:

```text
transaction:create_branch
step:file:create_file
step:pr:create_pull_request
step:merge:merge_pull_request
```

Transaction-scoped requirements are deduplicated per action. Step-scoped requirements remain tied to one exact reviewed step.

## Approval ledger

The ledger is append-only and SHA-chained. Each attestation records only:

- `approval_id`;
- `principal_id`;
- role;
- `approve` or `deny`;
- exact requirement ID;
- exact snapshot SHA;
- optional evidence locator.

It does not store file content, connector responses, credentials, tokens, or hidden messages.

### Identity boundary

v0.9 validates identifier structure and distinctness but does **not** authenticate real-world identities or verify signatures. The host must authenticate principals before submitting attestations.

The authority map therefore keeps these false:

```json
{
  "identity_verification": false,
  "signature_verification": false
}
```

## Ready state

A transaction is `ready` only when:

- the policy decision is `allow`;
- every required role count is satisfied;
- distinct-principal requirements are satisfied;
- no denial attestation exists;
- policy, snapshot, plan, ledger, and v0.8 journal still verify.

All policy approvals are collected before governed execution starts.

## Exact write authorization stays separate

Organizational approval is not a GitHub tool-call authorization. After the ledger becomes ready, each write still needs the exact v0.8 authorization for its `call_id`:

```python
engine.authorize_step(
    step_id="merge",
    event_id="write-authorization-merge",
    text="Authorize exactly transaction-merge-call-id",
)
```

The two independent boundaries are:

```text
policy approval for the reviewed plan
+ exact visible authorization for the concrete write call
```

Neither silently replaces the other.

## Python example

```python
from sdk.liminal_github_policy import GitHubTransactionPolicyEngine

engine = GitHubTransactionPolicyEngine.create(
    "policy.json",
    "policy-snapshot.json",
    "approval-ledger.json",
    transaction_plan_path="transaction-plan.json",
    transaction_journal_path="transaction-journal.json",
    policy_id="production-github-v1",
    allowed_repositories=["owner/repository"],
)

for requirement in engine.snapshot.requirements:
    print(requirement.requirement_id, requirement.required_role_counts)

engine.record_approval(
    approval_id="approval-001",
    principal_id="alice",
    role="reviewer",
    decision="approve",
    requirement_id="step:file:create_file",
    evidence_locator="urn:approval-system:001",
)
```

Execution remains blocked until the entire ledger is ready.

## CLI

Initialize policy artifacts for an existing v0.8 transaction:

```bash
python3 tools/chatgpt_github_transaction_policy.py init \
  --policy policy.json \
  --snapshot policy-snapshot.json \
  --approval-ledger approval-ledger.json \
  --transaction-plan transaction-plan.json \
  --transaction-journal transaction-journal.json \
  --policy-id production-v1 \
  --repository owner/repository
```

Record an attestation:

```bash
python3 tools/chatgpt_github_transaction_policy.py attest \
  --policy policy.json \
  --snapshot policy-snapshot.json \
  --approval-ledger approval-ledger.json \
  --transaction-plan transaction-plan.json \
  --transaction-journal transaction-journal.json \
  --approval-id approval-001 \
  --principal-id alice \
  --role reviewer \
  --decision approve \
  --requirement-id step:file:create_file
```

Inspect state:

```bash
python3 tools/chatgpt_github_transaction_policy.py prepare ...
python3 tools/chatgpt_github_transaction_policy.py verify ...
python3 tools/chatgpt_github_transaction_policy.py evidence ...
```

The CLI does not discover or invoke connector methods. Real execution remains host-owned.

## Fail-closed cases

v0.9 blocks:

- altered policy, plan, snapshot, or ledger hashes;
- repository outside the allowlist;
- unruled or denied actions;
- exceeded step or occurrence limits;
- missing required recovery plans;
- approvals for unknown requirements;
- unauthorized roles;
- duplicate approval IDs;
- the same principal attesting one requirement twice;
- stale-snapshot approvals;
- any denial attestation;
- execution before all approvals are ready;
- write execution without separate v0.8 authorization.

## Evidence binding

`evidence_summary()` binds:

```text
policy_sha256
snapshot_sha256
plan_sha256
approval_ledger_head_sha256
transaction_journal_head_sha256
→ engine_evidence_sha256
```

This proves which policy, plan, approvals, and transaction journal were used together. It does not prove a principal's real identity.

## Non-authority boundary

v0.9 does not:

- authenticate people or verify signatures;
- infer approval from chat text;
- authorize write calls automatically;
- own GitHub credentials or connector execution;
- approve merge, deployment, delivery, or force-push;
- retry pending writes or roll back automatically;
- access hidden messages, chain-of-thought, or hidden memory.
