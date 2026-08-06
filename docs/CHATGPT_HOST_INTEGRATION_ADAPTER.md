# ChatGPT Host Integration Adapter v0.5

## Purpose

The Host Integration Adapter is a zero-dependency Python boundary between a
host application and the existing Liminal session pipeline.

It records visible tool-call lifecycle boundaries while the host performs the
actual work:

```text
visible user message / explicit authorization
→ tool_call_started in host trace
→ host executes its own tool
→ recorder tool_event with the real outcome
→ tool_call_finished in host trace
→ Session Recorder v0.4
→ Live Session Exporter v0.3
→ Conversation Normalizer v0.2
→ Liminal Adapter v0.1
→ ALLOW | REVISE | VERIFY | NO_SIGNAL
```

The adapter does not attach itself to hosted ChatGPT, inspect hidden messages,
execute tools on its own, infer authorization from words such as “go”, or invent
a tool result. The host supplies the callable behavior and explicitly declares
the observed final outcome.

## Python API

```python
from sdk.liminal_host_adapter import HostIntegrationAdapter, ToolCallSpec

adapter = HostIntegrationAdapter.create(
    "reports/host-trace.json",
    recorder_path="reports/session-journal.json",
    session_id="session-1",
    high_stakes=False,
    requires_current_information=True,
)

adapter.record_user_message(event_id="user-1", text="Create the artifact")

call_spec = ToolCallSpec(
    call_id="write-1",
    tool="LocalFileHost",
    operation="write artifact",
    effect="write",
    evidence_eligible=True,
    freshness="current",
    reversible=True,
    recovery_plan="Delete the generated file",
)

adapter.record_authorization(
    event_id="auth-1",
    text="Go",
    authorized_event_ids=[call_spec.call_id],
)

with adapter.tool_call(call_spec) as call:
    artifact.write_text("done\n")  # the host owns this execution
    call.succeed(locator=str(artifact))
```

The context manager writes the host start record before entering the block. It
writes the recorder tool event and host finish record only after `succeed`,
`fail`, or `cancel` receives the explicit outcome.

If the block raises an exception before an outcome is recorded, the adapter
records a `failure` outcome with the exception class as the locator and re-raises
the original exception. A normal exit without an explicit outcome fails closed
and leaves the call pending for deliberate completion or cancellation.

## Explicit authorization

Write effects require a prior recorder event:

```text
user_authorization → exact tool call ID → tool_call_started → tool_event
```

The adapter scans only structured `user_authorization` events. It never treats a
positive-sounding message as permission. Read and `none` effects do not require
an authorization edge because the downstream normalizer does not turn them into
performed write actions.

The authorization event must already exist when the call starts. The recorder
later validates again that the authorization sequence precedes the final tool
event.

## Host trace

The adapter creates `chatgpt-host-tool-trace-v0.5` next to the v0.4 recorder
journal. It contains a SHA-256 chain of two record types.

### Start record

```json
{
  "type": "tool_call_started",
  "sequence": 1,
  "call_id": "write-1",
  "tool": "LocalFileHost",
  "operation": "write artifact",
  "effect": "write",
  "evidence_eligible": true,
  "freshness": "current",
  "reversible": true,
  "recovery_plan": "Delete the generated file",
  "authorization_event_ids": ["auth-1"],
  "recorder_head_before": "..."
}
```

### Finish record

```json
{
  "type": "tool_call_finished",
  "sequence": 2,
  "call_id": "write-1",
  "status": "success",
  "locator": "reports/artifact.txt",
  "recorder_event_id": "write-1",
  "recorder_head_after": "..."
}
```

Each host trace entry contains `previous_entry_sha256` and `entry_sha256`.
Tampering with metadata, authorization references, ordering, status, locator, or
recorder hashes makes verification fail.

## Correlation rules

1. Only one tool call may be pending in v0.5.
2. No visible recorder event may be inserted while a tool call is pending.
3. The recorder head at completion must equal the head captured at start.
4. The final recorder event ID must equal the tool call ID.
5. Tool, operation, effect, freshness, reversibility, recovery plan, status, and
   locator must match across the host trace and recorder journal.
6. A write call must retain at least one exact prior authorization edge.
7. A completed recorder tool event must immediately follow its host start state.

These constraints deliberately trade concurrency for a simple, auditable
single-call lifecycle. A later version may support correlated parallel calls
with independent recorder lanes.

## Crash recovery

A process may stop after the recorder accepted the final `tool_event` but before
the host finish record was persisted. `recover_tool_call(call_id)` repairs only
this narrow gap.

Recovery succeeds only when:

- exactly one matching recorder event exists;
- it immediately follows the recorder head captured at start;
- it is still the latest recorder event;
- all immutable tool metadata matches the start record.

The adapter never guesses an outcome when the recorder event is absent.

## Visible-session pass-through

The adapter exposes pass-through methods for the v0.4 recorder:

- `record_user_message`
- `record_assistant_draft`
- `record_claim`
- `record_source`
- `record_authorization`
- `record_proposed_action`
- `record_contradiction`
- `append_visible_event`

They are blocked while a tool call is pending to avoid ambiguous interleaving.
After all calls complete, `seal` and `export_live_session` continue into the
existing pipeline.

## CLI

```bash
python3 tools/chatgpt_host_adapter.py init \
  --trace reports/host-trace.json \
  --journal reports/session-journal.json \
  --session-id session-1 \
  --requires-current-information

python3 tools/chatgpt_host_adapter.py append \
  --trace reports/host-trace.json \
  --event user-message.json

python3 tools/chatgpt_host_adapter.py start \
  --trace reports/host-trace.json \
  --spec tool-call.json

# The host performs the real tool call here.

python3 tools/chatgpt_host_adapter.py finish \
  --trace reports/host-trace.json \
  --call-id write-1 \
  --status success \
  --locator reports/artifact.txt

python3 tools/chatgpt_host_adapter.py verify \
  --trace reports/host-trace.json
```

Additional commands are `recover`, `seal`, and `export`.

## Deterministic safety properties

1. Unknown fields and invalid enum values fail closed.
2. Caller-supplied tool outcomes are recorded exactly; none are generated from
   prose.
3. Write calls cannot start without explicit prior authorization.
4. Duplicate call IDs and multiple pending calls are rejected.
5. Recorder mutation during a pending call blocks completion.
6. Evidence-eligible outcomes require a locator.
7. Host trace tampering breaks the hash chain.
8. Cross-file metadata or hash mismatches fail verification.
9. Pending calls block session seal and normal export.
10. Crash recovery is bounded to one exact recorder/trace persistence gap.

## Authority boundary

The adapter has no authority to:

- access hidden messages, chain-of-thought, or model state;
- infer claims, confidence, authorization, or source truth;
- own or independently initiate tool execution;
- fabricate success, failure, cancellation, or evidence locators;
- approve response delivery;
- send, publish, merge, deploy, or submit externally;
- modify model weights;
- write hidden or persistent model memory.

The host remains responsible for redacting sensitive text before recording and
for enforcing any product-specific permissions around the real tool executor.
