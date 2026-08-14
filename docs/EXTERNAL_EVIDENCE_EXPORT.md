# External Evidence Export v0.1

## Purpose

The External Validation Graph tracks **review maturity**. It does not grant execution authority.

That distinction must remain machine-readable when review evidence leaves LiminalOSAI for ProofPath, CML, or another consumer.

```text
external review event
  -> External Validation Graph
  -> EEW / review maturity
  -> evidence export
  -> ProofPath / CML

NOT:
external validation
  -> implicit authorization
  -> execution
```

The canonical exporter is:

`tools/export_external_validation_evidence.py`

## Negative authority contract

Every accepted export must preserve exactly:

```json
{
  "classification": "EVIDENCE_ONLY",
  "authorization_transfer": "NONE",
  "execution_authorized": false,
  "policy_mutation_authorized": false,
  "capability_granted": false,
  "durable_authority_granted": false,
  "requires_separate_authorization_contract": true
}
```

This is intentionally independent of review maturity.

The invariant is:

```text
EEW in [0, 100]
AND review_status in {SENT, ACKNOWLEDGED, ROUTED,
                      TECHNICAL_FEEDBACK, REPRODUCED, VALIDATED}

=> authorization_transfer == NONE
=> execution_authorized == false
```

Even:

```text
all targets = VALIDATED
EEW = 100/100
```

still means only that the reviewed claim has reached the graph's strongest evidence state. It does not create a capability or authorize a governed effect.

## Why this exists

Earlier External Validation Graph artifacts were already careful in prose:

- EEW was not a safety-confidence probability;
- `SENT`, `ACKNOWLEDGED`, and `ROUTED` were not endorsements;
- `VALIDATED` required explicit evidence;
- the review-event applier was dry-run and fail-closed.

However, the ProofPath/CML mapping exported status/evidence without carrying the **negative authorization fact** as a required machine field.

Current LiminalOSAI/TRCP makes the separation stronger by modelling `AUTHORIZATION` as its own causal node. The export contract now matches that parent model.

## Export shape

The exporter emits:

```text
schema_version
source_graph_schema
claim_id
updated_at
review_maturity
  score_id
  target_count
  weighted_sum
  score_percent
  reproduced_targets
  validated_targets
targets[]
authority_boundary
downstream.proofpath
downstream.cml
export_sha256
```

The export is deterministic and content-hashed. The SHA binds the exact evidence state and negative authority boundary together.

## ProofPath boundary

ProofPath may record these transitions as attributable evidence events, but the export says explicitly:

```text
event_classification = EVIDENCE_ONLY
authorization_transfer = NONE
may_infer_authority = false
```

A later ProofPath capability that wants to participate in an authorization decision must carry a separate, explicit authorization contract. Review maturity cannot substitute for it.

## CML boundary

CML may persist the review state as append-only evidence memory:

```text
memory_semantics = EVIDENCE_STATE_ONLY
authorization_transfer = NONE
may_influence_authorization_without_separate_contract = false
```

Memory can inform reasoning. It cannot silently become current authority.

## Validation

```bash
python3 tools/export_external_validation_evidence.py \
  --output reports/external-validation-evidence.json

python3 -m unittest tests/test_external_validation_export.py -v
```

The regression suite includes a synthetic fully validated graph with `EEW=100`. The export must still carry zero authority.

## FCRP-SELF-009

```text
Idea:
  evidence informs authorization but is not authorization

First Meaningful Divergence:
  machine-readable downstream mapping carried evidence state
  without carrying the negative authorization fact

Symptom:
  downstream could infer permission from strong maturity

Refactor Point:
  cross-repository evidence export boundary

Fix:
  EVIDENCE_ONLY + authorization_transfer=NONE
  + fail-closed exporter + EEW=100 regression
```

Machine-readable case:

`benchmarks/fcrp-self-009.json`
