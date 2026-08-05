# ChatGPT Live Session Exporter v0.3

## Purpose

The Live Session Exporter converts an explicit, complete event log from one
assistant session into `chatgpt-conversation-bundle-v0.2`, which can then pass
through the existing Conversation Normalizer and Liminal Adapter.

```text
explicit live-session events
→ selected user request + selected assistant draft
→ claims + citations + tool outcomes + authorization edges
→ chatgpt-conversation-bundle-v0.2
→ Conversation Normalizer
→ ChatGPT Liminal Adapter
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

This closes the gap between a live session trace and the v0.2 bundle contract.
It does not connect itself to a hosted ChatGPT runtime, inspect hidden messages,
infer claims from prose, or infer authorization from conversational tone.

## Input contract

The CLI accepts `chatgpt-live-session-v0.3`:

```bash
python3 tools/chatgpt_live_session_exporter.py \
  --input examples/chatgpt_live_session_exporter/self_check.json \
  --output-dir reports/live-session
```

Top-level shape:

```json
{
  "schema_version": "chatgpt-live-session-v0.3",
  "session": {
    "id": "session-1",
    "request_event_id": "user-1",
    "draft_event_id": "draft-1",
    "high_stakes": false,
    "requires_current_information": true,
    "capture_complete": true
  },
  "events": []
}
```

`capture_complete` must be `true`. An incomplete event capture is rejected
instead of being exported as if it were a complete audit trail.

Event identifiers and non-negative sequence numbers must be unique. Sequence
numbers establish deterministic ordering and authorization precedence.

## Event types

### `user_message`

```json
{
  "id": "user-1",
  "sequence": 1,
  "type": "user_message",
  "text": "Report the current repository state"
}
```

The event selected by `session.request_event_id` becomes `request.text` in the
conversation bundle. The exporter does not infer a different hidden intent.

### `assistant_draft`

```json
{
  "id": "draft-1",
  "sequence": 5,
  "type": "assistant_draft",
  "response": "The repository contains the adapter.",
  "no_signal": false,
  "intent_alignment": 0.98
}
```

The event selected by `session.draft_event_id` becomes the exported draft.
Claims and actions may reference other drafts in the same event log, but only
records attached to the selected draft are exported. Ignored draft-bound event
IDs remain visible in the export manifest.

### `claim`

```json
{
  "id": "claim-1",
  "sequence": 6,
  "type": "claim",
  "draft_event_id": "draft-1",
  "text": "The repository contains the adapter.",
  "kind": "fact",
  "confidence": 0.99,
  "requires_current_information": true,
  "evidence_event_ids": ["source-1"]
}
```

Supported kinds are `fact`, `reasoning`, `recommendation`, and `uncertainty`.
Claims must already be explicit. The exporter does not extract them from raw
assistant prose.

Evidence references resolve as follows:

- a source event ID becomes that source's handle;
- an evidence-eligible tool event ID remains the tool event ID;
- an unknown or non-evidence event becomes `unresolved:<event-id>`.

Unresolved references are deliberately preserved so the downstream normalizer
and adapter return `VERIFY` rather than silently dropping evidence gaps.

### `source`

```json
{
  "id": "source-1",
  "sequence": 3,
  "type": "source",
  "handle": "main-state",
  "verified": true,
  "freshness": "current",
  "source_kind": "repository",
  "locator": "refs/heads/main@HEAD"
}
```

Source handles must be unique and cannot collide with tool event IDs. The
`verified` flag is explicit upstream metadata; the exporter does not inspect the
locator or independently prove that the source supports a claim.

### `tool_event`

```json
{
  "id": "merge-pr-97",
  "sequence": 4,
  "type": "tool_event",
  "tool": "GitHub",
  "operation": "merge pull request 97",
  "status": "success",
  "effect": "write",
  "evidence_eligible": true,
  "freshness": "current",
  "locator": "pull/97#merged",
  "reversible": false,
  "recovery_plan": "Revert the merge commit"
}
```

Supported statuses are `success`, `failure`, and `cancelled`. Supported effects
are `read`, `write`, and `none`.

The exporter does not execute or retry the event. It only records the explicit
outcome. Successful write events later become performed actions in the
Conversation Normalizer; failed or cancelled writes do not.

### `user_authorization`

```json
{
  "id": "user-go",
  "sequence": 2,
  "type": "user_authorization",
  "text": "Go",
  "authorized_event_ids": ["merge-pr-97"]
}
```

Authorization is an explicit graph edge, not a language-model inference.

For an authorization to be valid:

1. the target event must exist;
2. the target must be a `tool_event` or `proposed_action`;
3. the authorization sequence must be lower than the target sequence.

A late authorization is rejected. A user message that merely sounds positive is
not treated as authorization unless represented by this event type and an exact
target ID.

### `proposed_action`

```json
{
  "id": "proposal-1",
  "sequence": 8,
  "type": "proposed_action",
  "draft_event_id": "draft-1",
  "description": "Open a pull request",
  "reversible": true,
  "recovery_plan": null
}
```

A prior `user_authorization` event may target the proposed action. The exporter
then sets `user_authorized` in the bundle; it does not execute the action.

### `contradiction`

```json
{
  "id": "contradiction-1",
  "sequence": 9,
  "type": "contradiction",
  "draft_event_id": "draft-1",
  "text": "The draft claims both merged and not merged"
}
```

Contradictions attached to the selected draft are preserved for the downstream
adapter, where they produce `REVISE`.

## Outputs

The output directory contains:

- `chatgpt-conversation-bundle.json` — valid v0.2 normalizer input;
- `live-session-export.json` — selected events, counts, hashes, authorization
  edges, unresolved evidence, ignored draft records, warnings, and authority;
- `live-session-export-graph.md` — compact causal trace.

End-to-end usage:

```bash
python3 tools/chatgpt_live_session_exporter.py \
  --input examples/chatgpt_live_session_exporter/self_check.json \
  --output-dir reports/live-session

python3 tools/chatgpt_conversation_normalizer.py \
  --input reports/live-session/chatgpt-conversation-bundle.json \
  --output-dir reports/normalized

python3 tools/chatgpt_liminal_adapter.py \
  --input reports/normalized/chatgpt-liminal-input.json \
  --output-dir reports/advice
```

## Deterministic safety properties

1. Incomplete capture fails closed.
2. Duplicate event IDs and sequence numbers are rejected.
3. Request and draft selectors must point to correctly typed events.
4. Claim/action/contradiction events must reference an existing assistant draft.
5. Authorization targets must exist, be authorizable, and occur later.
6. Source handles cannot collide with tool event IDs.
7. Unknown evidence references remain visible and reach `VERIFY`.
8. Failed writes cannot become performed actions.
9. Input bytes and canonical output receive SHA-256 integrity records.
10. Identical input produces identical bundle and manifest content.

## Authority boundary

The exporter has no authority to:

- access hidden messages, chain-of-thought, or model state;
- infer claims, confidence, authorization, or source truth;
- browse, execute, retry, send, publish, merge, or deploy;
- approve delivery;
- modify model weights;
- write hidden or persistent model memory.

It is an event-log exporter, not an autonomous agent and not a production safety
boundary.

## Current limit

A host integration must still emit the explicit v0.3 event log. The exporter
cannot attach itself to ChatGPT or another assistant runtime from inside this
repository. A future host adapter may capture visible messages and tool results,
but claim annotations, confidence, and authorization edges must remain explicit
and reviewable before this deterministic exporter accepts them.
