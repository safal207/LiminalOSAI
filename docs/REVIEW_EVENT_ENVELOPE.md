# Review Event Envelope v0.1

## Purpose

`Review Event Envelope v0.1` is the transport format for evidence-backed external-review state transitions.

It converts an external interaction — for example an acknowledgement, routing statement, technical counterexample, independent reproduction, or explicit validation — into a bounded event that can be checked before it changes the External Validation Graph.

The envelope is intended for later ProofPath/CML ingestion. It does **not** turn an email or reviewer name into validation by itself.

## Event types

| Event type | Transition target |
|---|---|
| `review.sent` | `SENT` |
| `review.acknowledged` | `ACKNOWLEDGED` |
| `review.routed` | `ROUTED` |
| `review.technical_feedback` | `TECHNICAL_FEEDBACK` |
| `review.reproduced` | `REPRODUCED` |
| `review.validated` | `VALIDATED` |

The validator requires `event_type` and `transition.to` to agree.

## Minimal envelope

```json
{
  "schema_version": "review-event-envelope/v0.1",
  "event_id": "rev-openai-20260808-routed-001",
  "event_type": "review.routed",
  "occurred_at": "2026-08-08T18:46:59Z",
  "claim_id": "PSAG-001",
  "subject": {
    "organization": "OpenAI",
    "target_id": "openai-preparedness"
  },
  "transition": {
    "from": "SENT",
    "to": "ROUTED"
  },
  "evidence": {
    "kind": "external_correspondence",
    "reference": "OpenAI Support case #12892239",
    "summary": "Support explicitly stated that the material would be passed to the appropriate internal team for review.",
    "public": false
  },
  "repository": {
    "repository": "safal207/LiminalOSAI",
    "pr": 174,
    "commit": null
  },
  "provenance": {
    "recorded_by": "Alexey Safonov",
    "source": "external_correspondence"
  }
}
```

## Evidence escalation rules

The envelope deliberately requires stronger structures for stronger claims:

- `review.sent`, `review.acknowledged`, `review.routed`: a concrete evidence reference and summary are required.
- `review.technical_feedback`: the evidence summary must describe substantive technical content, not receipt alone.
- `review.reproduced`: `external_reproducer` and `reproduction_reference` are required.
- `review.validated`: all reproduction fields plus `validation_reference` are required.

These checks do not prove that the external evidence is true. They prevent unsupported status labels from being accepted merely because a JSON field was changed.

## Transition discipline

A review event is append-only evidence. The current state should be derived from the ordered event stream rather than manually overwritten.

```text
external interaction
      |
      v
Review Event Envelope
      |
      +--> structural validation
      +--> event_type / transition consistency
      +--> evidence-strength checks
      +--> target / claim binding
      |
      v
ProofPath evidence event
      |
      v
CML append-only transition
      |
      v
External Validation Graph / EEW recomputation
```

## Privacy boundary

`evidence.public=false` means the public repository records only the minimum attributable reference needed to justify the state transition. Private email bodies, addresses, message IDs, credentials, or confidential reviewer material should not be copied into the public event artifact.

## Canonical files

- Schema: [`review_event_envelope.v0.1.schema.json`](./review_event_envelope.v0.1.schema.json)
- Validator: [`../tools/validate_review_event.py`](../tools/validate_review_event.py)
- Examples: [`../examples/review_events/`](../examples/review_events/)

## Non-claims

A valid envelope means only that the event is structurally admissible under the v0.1 evidence rules. It does not mean the reviewer endorses the project, the claim is true, or the architecture is safe.
