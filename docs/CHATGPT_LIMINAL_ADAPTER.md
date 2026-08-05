# ChatGPT Liminal Adapter v0.1

## Purpose

The ChatGPT Liminal Adapter is a deterministic, advisory-only response gate.
It accepts a normalized user request, a normalized draft response, and explicit
evidence metadata. It returns exactly one decision:

- `ALLOW` — the bounded packet satisfies the contract;
- `REVISE` — the draft conflicts with intent, confidence, contradiction, or action-boundary rules;
- `VERIFY` — factual or high-stakes claims need verified/current evidence;
- `NO_SIGNAL` — the packet explicitly declines to manufacture an unsupported answer.

The adapter does not generate a replacement answer, browse, execute tools,
approve delivery, submit externally, deploy, merge, update model weights, or
write hidden memory.

## Why it can strengthen an AI assistant

The adapter does not make the underlying model more intelligent. It adds an
external, reproducible control loop around a draft:

```text
user request
→ normalized intent
→ draft claims and proposed/performed actions
→ explicit evidence references
→ freshness / contradiction / confidence checks
→ action boundary
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

The useful gain is longitudinal reliability: fewer unsupported current claims,
clearer uncertainty, explicit recovery boundaries, and machine-readable traces
that can be compared across repeated tasks.

## Input contract

The CLI accepts one JSON file:

```bash
python3 tools/chatgpt_liminal_adapter.py \
  --input examples/chatgpt_liminal_adapter/self_check.json \
  --output-dir reports/chatgpt-liminal
```

Top-level schema:

```json
{
  "schema_version": "chatgpt-liminal-input-v0.1",
  "request": {
    "id": "request-1",
    "intent": "Describe the intended user outcome",
    "high_stakes": false,
    "requires_current_information": true
  },
  "draft": {
    "response": "Normalized draft text",
    "no_signal": false,
    "intent_alignment": 0.95,
    "claims": [],
    "actions": [],
    "contradictions": []
  },
  "evidence": []
}
```

### Claims

Each normalized claim contains:

```json
{
  "id": "claim-1",
  "text": "A specific claim",
  "kind": "fact",
  "confidence": 0.98,
  "requires_current_information": true,
  "evidence_refs": ["evidence-1"]
}
```

Supported kinds are `fact`, `reasoning`, `recommendation`, and `uncertainty`.
Facts always require verified evidence. A recommendation also requires evidence
when the request is high-stakes. A current claim requires at least one verified
evidence item marked `current`.

### Evidence

```json
{
  "id": "evidence-1",
  "verified": true,
  "freshness": "current",
  "source_kind": "repository",
  "locator": "tools/chatgpt_liminal_adapter.py@HEAD"
}
```

Freshness is `current`, `stable`, or `unknown`. Source kind is one of
`official`, `repository`, `tool`, `user_provided`, `web`, or `other`.
The adapter validates metadata; it does not fetch or independently prove the
source. Evidence normalization remains an upstream responsibility.

### Actions

```json
{
  "id": "action-1",
  "description": "Merge a pull request",
  "mode": "proposed",
  "reversible": false,
  "user_authorized": false,
  "recovery_plan": "Revert the merge commit after a failed post-merge check"
}
```

A performed action without user authorization is `REVISE`. A performed
irreversible action without a recovery plan is `REVISE`. A high-stakes proposed
irreversible action without a recovery plan is also `REVISE`.

## Decision precedence

The adapter applies deterministic precedence:

1. Schema violations fail closed with exit code `2`.
2. Intent, contradiction, confidence, and action-boundary violations produce `REVISE`.
3. Missing, unknown, unverified, or stale evidence produces `VERIFY`.
4. A clean explicit no-signal packet produces `NO_SIGNAL`.
5. Otherwise the result is `ALLOW`.

`ALLOW` is not execution or delivery approval. It means only that the supplied
normalized packet passed this adapter's bounded checks.

## Outputs

The output directory contains:

- `chatgpt-liminal-advice.json` — complete decision packet;
- `chatgpt-liminal-next-step.json` — bounded next action;
- `chatgpt-liminal-causal-graph.md` — compact causal trace.

The advice packet includes the SHA-256 hash of the exact input file, check
results, blocked claims, missing evidence IDs, action findings, and an explicit
authority map whose write/execution capabilities are all false.

## Limits and non-claims

This adapter does not:

- understand raw prose without normalization;
- establish that a locator is truthful merely because `verified` is true;
- replace browsing, primary-source checks, tests, or human review;
- update model weights or create persistent consciousness;
- grant permission to execute, send, merge, deploy, or publish;
- prove safety or factual correctness beyond the supplied packet.

Its role is narrower and useful: make evidence and action assumptions explicit,
apply repeatable checks, and preserve a reviewable trace.
