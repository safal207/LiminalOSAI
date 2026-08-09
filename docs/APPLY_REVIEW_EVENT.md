# Apply Review Event v0.1

## Purpose

`tools/apply_review_event.py` is the fail-closed bridge between a validated Review Event Envelope and the canonical External Validation Graph.

It exists to remove manual status editing from the normal workflow.

```text
external response
  -> Review Event Envelope
  -> structural/evidence validation
  -> exact canonical-state check
  -> allowed-transition check
  -> candidate graph
  -> EEW recomputation
  -> full graph validation
  -> dry-run diff
  -> explicit --write
  -> reviewable Git commit / PR
```

The tool does **not** send email, fetch private correspondence, create external evidence, or decide that an organization validated the project. It only applies an evidence event that already satisfies the envelope rules.

## Default: dry-run

```bash
python3 tools/apply_review_event.py path/to/event.json
```

Dry-run is the default. The command prints the exact candidate diff and leaves the canonical graph unchanged.

Machine-readable summary:

```bash
python3 tools/apply_review_event.py path/to/event.json --json
```

## Explicit write

```bash
python3 tools/apply_review_event.py path/to/event.json --write
```

`--write` modifies only the checked-out canonical graph file after all checks pass. The resulting file is still expected to be reviewed through Git and CI; `--write` is not an external publication or validation action.

## Fail-closed rules

A new state transition is applied only when all of the following hold:

1. the Review Event Envelope is structurally valid;
2. `claim_id` matches the canonical graph;
3. the review target already exists;
4. organization and target identity match the canonical target;
5. `transition.from` equals the target's exact current canonical status;
6. `(from, to)` is listed in `allowed_transitions`;
7. evidence strength satisfies the destination status requirements;
8. EEW is recomputed from canonical status weights;
9. the resulting graph passes `validate_external_graph.py`.

The event cannot provide or override its own status weight.

## Replay semantics

Historical events may be replayed safely.

If `event.transition.to` is already the target's current canonical status, the application becomes an idempotent no-op **only if the event's evidence reference is already represented by the target**.

This is why the existing OpenAI `review.routed` event can be replayed without adding weight twice.

An unrelated event that merely names the same status is rejected.

## Stale and regressive events

If the graph has already advanced beyond an event, the stale event is rejected rather than silently changing history.

```text
canonical: TECHNICAL_FEEDBACK
incoming:  ROUTED
result:    REJECT
```

Likewise, an event with an incorrect `transition.from` is rejected even when the destination status would otherwise be stronger.

## Evidence projection into the graph

When a transition is accepted, the applier updates the target with the minimum public review state:

- status and canonical status weight;
- evidence summary and reference;
- repository PR/commit link;
- event id/type/time metadata;
- technical-feedback reference when applicable;
- reproduction evidence when applicable;
- validation evidence when applicable.

Private correspondence bodies, addresses, message IDs, credentials, and confidential reviewer material are not copied into the graph.

## Score semantics

The tool recomputes:

```text
EEW = 100 * sum(canonical status weights) / target count
```

EEW remains a review-maturity score only. It is not a safety probability, endorsement measure, or scientific confidence score.

## Recommended operator flow

For a future reply from OpenAI, Anthropic, Meta, OpenSSF, OWASP, Invariant Labs, or another existing target:

1. create a Review Event Envelope from the minimum attributable evidence;
2. run `validate_review_event.py` / event tests;
3. run `apply_review_event.py` in dry-run mode;
4. inspect the candidate diff and EEW change;
5. use `--write` only when the event is correctly represented;
6. commit the graph + event together;
7. let `External Validation Graph Gate` verify the complete transition.

This keeps the evidence path reviewable and prevents a status label from becoming stronger merely because it was edited by hand.
