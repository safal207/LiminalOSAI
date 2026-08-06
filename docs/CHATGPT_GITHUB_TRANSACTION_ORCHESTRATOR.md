# ChatGPT GitHub Transaction Orchestrator v0.8

## Purpose

The Transaction Orchestrator adds a deterministic multi-step control plane above
Connected GitHub Runtime v0.7.

It supports reviewed workflows such as:

```text
create branch
→ write files
→ open pull request
→ verify exact head CI state
→ merge the exact reviewed head
```

Each step remains a normal v0.7 GitHub operation. The orchestrator adds an
immutable plan, ordered scalar checkpoint binding, a hash-chained transaction
journal, step gates, and fail-closed recovery rules.

```text
Transaction Plan v0.8
→ Connected GitHub Runtime v0.7
→ GitHub Agent Bridge v0.6
→ Host Integration Adapter v0.5
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
```

The orchestrator does not grant authority to execute, merge, force-push, deploy,
or infer authorization. The host still supplies one connected GitHub invoker.

## Immutable plan

A plan is stored as `chatgpt-github-transaction-plan-v0.8` and pinned by
`plan_sha256`. It also pins the exact v0.7 runtime configuration hash.

Each step declares:

- `step_id`: stable transaction-local identifier;
- `call_id`: exact recorder and authorization target;
- `action`: one supported v0.7 action;
- `arguments`: literal values and prior checkpoint references;
- `exports`: named scalar outputs to preserve;
- `expect`: exact scalar output assertions;
- `gate_step_ids`: prior successful steps required before execution.

A transaction contains at most 64 steps. Step IDs and call IDs must be unique.

## Checkpoint references

A later step may use a prior scalar export:

```json
{
  "$checkpoint": "file.commit_sha"
}
```

References are whole JSON values. String interpolation is not supported.

A reference must target:

1. a strictly earlier step;
2. an export declared by that step;
3. a successful checkpoint whose expectations passed.

Repository names may never come from checkpoint references. Every step must
contain the same literal repository as the transaction plan.

The journal stores only declared scalar exports. It does not store full file
contents or arbitrary connector payloads.

## Example plan

```json
[
  {
    "step_id": "branch",
    "call_id": "tx-branch",
    "action": "create_branch",
    "arguments": {
      "repository_full_name": "owner/repo",
      "branch_name": "agent/reviewed-change",
      "base_ref": "main"
    },
    "exports": {
      "branch": "branch"
    },
    "expect": {}
  },
  {
    "step_id": "file",
    "call_id": "tx-file",
    "action": "create_file",
    "arguments": {
      "repository_full_name": "owner/repo",
      "path": "docs/change.md",
      "content": "reviewed content",
      "message": "docs: add reviewed change",
      "branch": {
        "$checkpoint": "branch.branch"
      }
    },
    "exports": {
      "commit_sha": "commit_sha"
    },
    "expect": {}
  }
]
```

## Exact write authorization

Every write step retains the v0.6/v0.7 exact authorization requirement:

```text
user_authorization
→ exact step call_id
→ tool_call_started
→ connected GitHub operation
→ tool_event
→ transaction checkpoint
```

`authorize_step(...)` records permission only for the immutable step call ID.
Positive prose elsewhere is never treated as permission.

Authorization is checked before `step_started` is appended. An unauthorized
write therefore produces no transaction start record and does not call the
connector.

Read steps do not require write authorization.

## Merge gate

`merge_pull_request` has additional static requirements:

1. `expected_head_sha` must be a checkpoint reference;
2. at least one prior gate must be `get_commit_combined_status`;
3. that CI gate must expect `state = success`;
4. the CI gate must inspect the same checkpoint reference used by
   `expected_head_sha`;
5. the gate must have completed successfully before merge starts.

This prevents a plan from checking one commit and merging another.

GitHub still performs its own `expected_head_sha` comparison at merge time.

## Hash-chained journal

The journal schema is `chatgpt-github-transaction-journal-v0.8`.

Every entry contains:

```json
{
  "previous_entry_sha256": "...",
  "event": {
    "type": "step_started",
    "sequence": 2
  },
  "entry_sha256": "..."
}
```

Recorded events include:

- `transaction_created`;
- `step_started`;
- `step_finished`;
- `transaction_halted`;
- `transaction_completed`;
- `transaction_aborted`.

A successful step checkpoint correlates:

- normalized request SHA-256;
- resolved argument SHA-256;
- connected runtime receipt SHA-256;
- raw response SHA-256;
- normalized payload SHA-256;
- recorder event and head SHA-256;
- host trace head SHA-256;
- declared scalar exports;
- exact expectation result.

`transaction_completed` binds the immediately preceding journal head.

## Execution modes

### Execute one step

```python
result = orchestrator.run_next(connector)
```

This is useful when a human or host authorizes each write immediately before it
runs.

### Execute until a boundary

```python
result = orchestrator.run(connector)
```

Execution stops when:

- all steps complete;
- a connector operation fails or is cancelled;
- a declared output is missing or non-scalar;
- an expectation is not met;
- a gate is unsatisfied;
- authorization is missing;
- a pending crash gap requires reconciliation.

A halted transaction is terminal. Retrying a failed write under the same
immutable plan is intentionally unsupported. Create a separate recovery
transaction with new call IDs.

## Crash gap and reconciliation

The orchestrator writes `step_started` before entering v0.7.

If the process stops after GitHub and v0.7 recorded the result but before the
transaction appended `step_finished`, the journal contains a pending step.

Pending steps are never replayed automatically.

```text
pending step
→ block run/run_next
→ require retained v0.7 receipt + raw connector response
→ verify request, response, payload, recorder, and locator hashes
→ append reconciled checkpoint
```

Reconciliation is available through:

```python
orchestrator.reconcile_pending(
    connected_receipt=receipt_document,
    raw_response=retained_raw_response,
)
```

The supplied raw response must reproduce the receipt hashes and match the
recorder tool event. The orchestrator does not guess missing outputs.

## Recovery report

`recovery_report()` lists successful steps with:

- action;
- effect;
- reversibility declared by v0.6;
- recovery guidance;
- evidence locator.

The report explicitly states:

```text
automatic_rollback = false
automatic_pending_write_replay = false
```

The orchestrator does not synthesize inverse GitHub operations. Recovery writes
must be separately planned, reviewed, and authorized.

## CLI

Initialize from a JSON step array:

```bash
python3 tools/chatgpt_github_transaction_orchestrator.py init \
  --plan reports/transaction-plan.json \
  --journal reports/transaction-journal.json \
  --runtime-config reports/runtime.json \
  --transaction-id reviewed-change-1 \
  --repository owner/repo \
  --steps transaction-steps.json
```

Inspect the next resolved operation:

```bash
python3 tools/chatgpt_github_transaction_orchestrator.py next \
  --plan reports/transaction-plan.json \
  --journal reports/transaction-journal.json
```

Authorize one write step:

```bash
python3 tools/chatgpt_github_transaction_orchestrator.py authorize \
  --plan reports/transaction-plan.json \
  --journal reports/transaction-journal.json \
  --step-id branch \
  --event-id auth-branch-1 \
  --text "Authorize exactly tx-branch"
```

Other lifecycle commands are:

- `verify`;
- `recovery`;
- `reconcile`;
- `abort`;
- `seal`;
- `export`.

The CLI intentionally does not discover or invoke GitHub tools. Connected
execution remains an SDK host operation.

## Safety properties

1. Plan, runtime configuration, and journal are SHA-pinned.
2. Steps execute only in immutable plan order.
3. Repositories are literal and transaction-scoped.
4. Checkpoint references target prior declared scalar exports only.
5. Every write requires exact prior authorization.
6. Merge requires a successful CI gate for the exact checkpoint head.
7. Raw response bodies and file contents are not copied into the journal.
8. Connector exceptions become failed checkpoints and halt the transaction.
9. Pending writes are never automatically replayed.
10. Failed or drifted transactions cannot continue under the same plan.
11. Automatic rollback is not claimed or attempted.
12. Visible-session seal/export requires transaction completion.

## Authority boundary

The orchestrator has no authority to:

- access hidden messages, chain-of-thought, or model state;
- infer authorization, claims, confidence, or source truth;
- discover arbitrary connector methods;
- access credentials;
- bypass repository allowlists or protected branches;
- force-push;
- merge without an exact authorized step and CI/head gate;
- replay ambiguous pending writes;
- generate or execute rollback writes;
- deploy or externally submit unrelated artifacts;
- modify model weights;
- write hidden model memory.

This is an external host SDK. It does not install itself inside hosted ChatGPT
and is not a substitute for GitHub branch protection, reviews, or deployment
controls.
