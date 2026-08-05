# ChatGPT Conversation Normalizer v0.2

## Purpose

The Conversation Normalizer converts a bounded, explicit conversation bundle
into the input contract consumed by `tools/chatgpt_liminal_adapter.py`.

It connects four records that normally remain scattered across an assistant
workflow:

```text
user request
+ draft response and explicit claims
+ cited sources
+ read/write tool events
→ chatgpt-liminal-input-v0.1
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

The normalizer is deterministic and fail-closed. It does not infer claims from
raw prose, browse, independently verify source truth, execute tools, approve a
response, or write hidden/model memory.

## Why this is v0.2

The v0.1 Liminal Adapter accepts an already normalized evidence packet. v0.2
adds the missing bridge from a structured conversation/tool trace to that
packet:

- source handles become stable evidence IDs;
- evidence-eligible tool events become tool evidence;
- successful write events become performed actions;
- proposed draft actions remain proposed actions;
- failed/cancelled writes are not misreported as performed;
- unresolved evidence handles remain deliberately missing so the adapter returns
  `VERIFY` instead of silently dropping them;
- input and normalized output receive SHA-256 integrity records.

## Input contract

The CLI accepts `chatgpt-conversation-bundle-v0.2`:

```bash
python3 tools/chatgpt_conversation_normalizer.py \
  --input examples/chatgpt_conversation_normalizer/self_check.json \
  --output-dir reports/conversation-normalizer
```

### Request

```json
{
  "id": "conversation-1",
  "text": "Report the current repository state with evidence",
  "high_stakes": false,
  "requires_current_information": true
}
```

The normalizer copies `request.text` into the adapter's explicit `intent` field.
It does not infer a hidden intent.

### Draft and claims

```json
{
  "response": "The current main branch contains the adapter.",
  "no_signal": false,
  "intent_alignment": 0.97,
  "claims": [
    {
      "id": "claim-1",
      "text": "The current main branch contains the adapter.",
      "kind": "fact",
      "confidence": 0.99,
      "requires_current_information": true,
      "evidence_handles": ["main-state"]
    }
  ],
  "proposed_actions": [],
  "contradictions": []
}
```

Claims must already be explicit. Supported claim kinds match the adapter:
`fact`, `reasoning`, `recommendation`, and `uncertainty`.

The normalizer resolves each `evidence_handles` entry against either a source
handle or a tool event ID. The two namespaces must not overlap.

An unknown handle becomes `missing:<handle>` in the adapter packet. No evidence
item is invented for it. The downstream adapter therefore reports missing
verification.

### Sources

```json
{
  "handle": "main-state",
  "verified": true,
  "freshness": "current",
  "source_kind": "repository",
  "locator": "refs/heads/main@HEAD"
}
```

A source handle `main-state` becomes adapter evidence ID
`source:main-state`.

The `verified` flag is upstream metadata. The normalizer does not prove that the
locator is truthful or that the source supports a specific claim.

### Tool events

```json
{
  "id": "merge-pr-96",
  "tool": "GitHub",
  "operation": "merge pull request 96",
  "status": "success",
  "effect": "write",
  "evidence_eligible": true,
  "freshness": "current",
  "locator": "pull/96#merged",
  "reversible": false,
  "user_authorized": true,
  "recovery_plan": "Revert the merge commit"
}
```

Supported statuses are `success`, `failure`, and `cancelled`. Supported effects
are `read`, `write`, and `none`.

When `evidence_eligible` is true, a locator is required and the event becomes
adapter evidence ID `tool:<event-id>`:

- `success` produces `verified: true` operational evidence;
- `failure` or `cancelled` produces `verified: false` evidence.

A successful write also becomes a performed action. A failed/cancelled write is
recorded in the normalization manifest but is not claimed as performed.

Operational success only proves the recorded tool operation completed. It does
not automatically prove every factual claim associated with the event.

### Proposed actions

The draft can contain actions not yet executed:

```json
{
  "id": "proposal-1",
  "description": "Open a pull request",
  "reversible": true,
  "user_authorized": false,
  "recovery_plan": null
}
```

These become adapter actions with `mode: proposed`. Successful write tool events
become actions with `mode: performed`.

## Outputs

The output directory contains:

- `chatgpt-liminal-input.json` — valid input for the v0.1 adapter;
- `conversation-normalization.json` — integrity, counts, unresolved handles,
  ignored write events, warnings, and authority boundaries;
- `conversation-normalization-graph.md` — compact causal trace.

Example end-to-end execution:

```bash
python3 tools/chatgpt_conversation_normalizer.py \
  --input examples/chatgpt_conversation_normalizer/self_check.json \
  --output-dir reports/conversation-normalizer

python3 tools/chatgpt_liminal_adapter.py \
  --input reports/conversation-normalizer/chatgpt-liminal-input.json \
  --output-dir reports/conversation-advice
```

## Deterministic safety properties

1. Invalid schemas exit with code `2` and produce no normalized packet.
2. Duplicate claim, source, tool-event, and action identifiers are rejected.
3. Source handles and tool event IDs cannot overlap.
4. Evidence-eligible tool events require a locator.
5. Failed/cancelled writes never become performed actions.
6. Unknown evidence handles are preserved as missing references.
7. Successful irreversible actions retain their authorization and recovery data
   for downstream gating.
8. The same input bytes produce the same normalized JSON and canonical output
   hash.

## Authority boundary

The normalizer has no authority to:

- infer claims or hidden intent;
- mark a source truthful through independent inspection;
- execute, retry, send, publish, deploy, or merge;
- approve delivery;
- update model weights;
- write hidden or persistent model memory.

It is a trace-to-contract adapter, not an autonomous agent.

## Current limit

This version still requires an upstream component to extract explicit claims,
confidence, intent alignment, reversibility, authorization, and recovery plans
from a live assistant session. The extraction step may use a model, but its
output must remain reviewable and must pass this deterministic schema before the
Liminal Adapter evaluates it.
