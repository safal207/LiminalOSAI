# ChatGPT Session Recorder SDK v0.4

## Purpose

The Session Recorder SDK writes explicit visible-session events while an agent or
host application is working. It produces a tamper-evident journal that can be
sealed and exported as `chatgpt-live-session-v0.3`.

```text
host application / agent
→ Session Recorder SDK v0.4
→ hash-chained session journal
→ sealed chatgpt-live-session-v0.3
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

It does not attach itself to ChatGPT, inspect hidden messages, capture
chain-of-thought, infer claims, infer authorization from prose, execute tools,
or verify source truth.

## Python SDK

The SDK has no third-party dependencies:

```python
from sdk.liminal_session_recorder import SessionRecorder

recorder = SessionRecorder.create(
    "reports/session-journal.json",
    session_id="session-1",
    high_stakes=False,
    requires_current_information=True,
)

recorder.record_user_message(event_id="user-1", text="Go")
recorder.record_authorization(
    event_id="auth-1",
    text="Go",
    authorized_event_ids=["merge-pr-1"],
)
recorder.record_tool_event(
    event_id="merge-pr-1",
    tool="GitHub",
    operation="merge pull request 1",
    status="success",
    effect="write",
    evidence_eligible=True,
    freshness="current",
    locator="pull/1#merged",
    reversible=False,
    recovery_plan="Revert the merge commit",
)
recorder.record_assistant_draft(
    event_id="draft-1",
    response="The authorized merge completed.",
    no_signal=False,
    intent_alignment=0.99,
)
recorder.record_claim(
    event_id="claim-1",
    draft_event_id="draft-1",
    text="The merge completed.",
    kind="fact",
    confidence=0.99,
    requires_current_information=True,
    evidence_event_ids=["merge-pr-1"],
)

recorder.seal(request_event_id="user-1", draft_event_id="draft-1")
recorder.export_live_session("reports/chatgpt-live-session.json")
```

Convenience methods are provided for every v0.3 event type:

- `record_user_message`
- `record_assistant_draft`
- `record_claim`
- `record_source`
- `record_tool_event`
- `record_authorization`
- `record_proposed_action`
- `record_contradiction`

`append_event()` is also available for bounded JSON objects. Unknown fields are
rejected so callers cannot silently place raw tool arguments, credentials, or
unbounded result payloads into the audit journal.

## CLI

Create a journal:

```bash
python3 tools/chatgpt_session_recorder.py init \
  --journal reports/session-journal.json \
  --session-id session-1 \
  --no-high-stakes \
  --requires-current-information
```

Append an event from a JSON file or standard input:

```bash
python3 tools/chatgpt_session_recorder.py append \
  --journal reports/session-journal.json \
  --event event.json
```

The caller must not provide `sequence`; the recorder owns sequence assignment.

Seal and export:

```bash
python3 tools/chatgpt_session_recorder.py seal \
  --journal reports/session-journal.json \
  --request-event-id user-1 \
  --draft-event-id draft-1

python3 tools/chatgpt_session_recorder.py export \
  --journal reports/session-journal.json \
  --output reports/chatgpt-live-session.json
```

Verify journal integrity:

```bash
python3 tools/chatgpt_session_recorder.py verify \
  --journal reports/session-journal.json
```

Contract failures return exit code `2`.

## Journal contract

The journal schema is `chatgpt-session-journal-v0.4`.

Each entry contains:

```json
{
  "previous_entry_sha256": "...",
  "event": {
    "id": "user-1",
    "sequence": 1,
    "type": "user_message",
    "text": "Go"
  },
  "entry_sha256": "..."
}
```

The entry hash is calculated over the canonical JSON form of the previous hash
and event. `head_sha256` must equal the last entry hash.

When sealed, the recorder also hashes the selected request, selected draft,
session flags, and chain head into `seal_sha256`. Editing an event, sequence,
selector, session flag, chain link, or hash makes verification fail closed.

## Atomicity and locking

Every mutation:

1. creates an exclusive adjacent `.lock` file;
2. validates the complete existing journal and hash chain;
3. writes a temporary file in the same directory;
4. flushes it with `fsync`;
5. atomically replaces the journal.

A concurrent writer receives an error rather than interleaving records. The SDK
does not automatically remove a lock left behind by a terminated process,
because guessing that a lock is stale could permit unsafe concurrent writes.

## Authorization boundary

A user message is never treated as permission by itself. Authorization must be a
separate `user_authorization` event with exact target IDs.

At seal time the SDK verifies that:

- every target exists;
- every target is a `tool_event` or `proposed_action`;
- authorization occurs before the target event.

Late, unknown, or non-authorizable edges fail closed.

## Safety properties

1. Sequence numbers are recorder-owned and contiguous.
2. Event IDs are unique.
3. Unknown event fields are rejected.
4. Journals are hash-chained and tamper-evident.
5. Writes use an exclusive lock and atomic replacement.
6. Incomplete journals cannot be exported.
7. Sealed journals cannot accept more events.
8. Request and draft selectors are protected by the seal hash.
9. Authorization remains explicit and ordered.
10. Source handles cannot collide with tool event IDs.
11. Identical inputs produce identical journal content; no implicit timestamps are added.
12. The fixed authority map denies execution, delivery, deployment, merge,
    model-weight updates, and hidden-memory writes.

## Data-minimization limit

The bounded event schema prevents arbitrary tool payloads from being recorded,
but text fields can still contain sensitive information supplied by the host.
The host remains responsible for redacting secrets, personal data, and private
content before calling the SDK.

## Current limit

A host application must explicitly call the SDK. This repository cannot inject
the recorder into hosted ChatGPT sessions. A future host adapter can wrap visible
message and tool APIs, but claims, confidence values, evidence references, and
authorization edges must remain explicit and reviewable.
