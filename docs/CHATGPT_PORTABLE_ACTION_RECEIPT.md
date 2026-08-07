# Portable Action Receipt v1.2

## Purpose

Portable Action Receipt v1.2 turns one terminal, identity-bound LiminalOSAI
transaction into a digest-first evidence object that can be verified outside the
process that executed the GitHub calls.

```text
human intent digest
+ Signed Governance Capsule v1.0
+ Identity / IdP / KMS bundle v1.1
+ exact v0.8 action and authorization evidence
+ final v0.9 policy / approval / journal roots
+ CI and exact-head observation
+ recovery posture
→ signed Portable Action Receipt v1.2
→ independent offline verification
```

The receipt is **post-execution evidence**. It is not a command, capability,
approval, credential, replay token, or permission to repeat the action.

## Canonical schema

- receipt: `liminal-portable-action-receipt-v1.2`
- verification: `liminal-portable-action-receipt-verification-v1.2`
- signature algorithm: `ed25519-openssl-v1`
- signature domain: `LIMINAL-PORTABLE-ACTION-RECEIPT-V1.2\0`
- redaction profile: `liminal-digest-only-redaction-v1.2`

The receipt embeds the complete v1.0 governance capsule and v1.1 identity bundle.
Independent verification therefore requires the receipt plus the verifier's
retained governance and identity trust stores; it does not require access to the
executing process, recorder files, connector credentials, or raw tool payloads.

## What is bound

The signed claims bind:

- receipt issuer, subject, tenant, organization, roles, session digest, key and audience;
- intent ID and SHA-256, but not raw intent text;
- transaction ID and repository;
- source and result Git object IDs;
- policy, snapshot, plan and approval-ledger roots;
- the capsule-time transaction-journal anchor;
- the final transaction-journal head;
- both capsule-time and final engine-evidence roots;
- governance capsule, IdP assertion, KMS attestation, identity bundle and identity-verification roots;
- one digest-only `ActionEvidence` per observed step;
- an ordered actions root;
- bounded CI / exact-head evidence;
- recovery posture;
- explicit capability and containment boundaries.

Capability Broker and containment are not implemented by v1.2. Their fields are
therefore encoded as `not_implemented` with an all-zero SHA-256 root. A receipt
may not silently promote an absent future layer into an observed claim.

## Action evidence

Each action record includes:

- step, call and action IDs;
- read/write effect;
- request and resolved-argument SHA-256 roots;
- runtime status;
- digest of the result locator;
- connected-runtime receipt, raw-response and normalized-payload digests;
- recorder and host-trace roots;
- checkpoint expectation result;
- reconciliation flag;
- a small allow-list of safe GitHub bindings such as commit SHA, expected merge
  head, branch name, repository, PR number, path and ref.

Raw connector responses and arbitrary argument maps are not embedded.

A write action is invalid unless it carries explicit hash evidence for at least
one recorded `user_authorization` event that named the same call ID. The receipt
therefore cannot manufacture write authorization after execution.

## Historical verification

IdP assertions, KMS attestations and governance capsules are intentionally
short-lived. A durable receipt must remain verifiable after those windows end.

v1.2 signs `execution_verified_at_unix`, which is the historical instant at which
the embedded identity/KMS/capsule chain was valid and checked. Offline receipt
verification revalidates that chain at the signed historical instant. The
receipt itself must have been signed while the governance signing key was valid
and not revoked.

This is historical evidence verification, not renewal of the expired authority.
`fresh_authorization` is always `false`.

## CI and exact-head evidence

The verifier does not claim that every receipt contains CI evidence. The CI gate
has an explicit `observed` flag.

An exact-head claim is accepted only when:

1. a successful `get_commit_combined_status` action explicitly expected
   `state=success` for one exact commit object ID;
2. a successful `merge_pull_request` action recorded `expected_head_sha`;
3. those two object IDs are exactly equal.

Without that chain the receipt does not claim `exact_head_verified=true`.

## Recovery boundary

The receipt preserves the terminal transaction state and recovery report digest.
It explicitly rejects claims of automatic rollback or automatic replay of a
pending write. A terminal receipt may therefore describe manual recovery needs,
but it cannot turn recovery evidence into new execution authority.

## Ecosystem projections

### ProofPath

`project_proofpath_authorization_records` emits provider-neutral
`org.proofpath.authorization-record.v0.1` records for the **original write
authorizations only**.

The records are exported as `CONSUMED` and their claim boundary says explicitly
that they do not prove execution and grant no fresh authority. Post-execution
outcomes remain receipt observations rather than ProofPath authorization facts.

### Causal Memory Layer

`project_cml_memory_pack` emits `cml-memory-pack-v1` with:

- `merge_authority=false`;
- `execution_authority=false`;
- `contains_private_data=false`;
- a situation → action → outcome graph;
- the portable receipt root as evidence;
- declared redactions for raw intent, tool arguments and connector responses.

The pack is advisory memory. Importing it cannot authorize a tool call.

### LiminalDB

`project_liminaldb_event_inputs` emits inputs compatible with
`org.liminaldb.trustworthy-transition-ledger.v0.1`:

```text
authorization
→ observation(s)
→ response_integrity
→ continuity_snapshot
```

The projection keeps authority, execution, response integrity, causal validity
and continuity posture independent. v1.2 deliberately emits no causal-audit
claim: causal validity remains `NOT_EVALUATED`.

`ProjectionLedger` in this repository is only a small conformance harness for
append → snapshot → reopen → full-replay equality. It is not LiminalDB and must
not be represented as production LiminalDB persistence.

### RINSE

`project_rinse_trace_event` creates a minimal immutable source trace whose ID is
bound to the receipt SHA-256. `build_rinse_supersession_fixture` then demonstrates
two different interpretation records that both reference that same source trace.

The interpretation may change. The source receipt must not.

## Independent verification

```bash
python3 tools/chatgpt_portable_action_receipt.py verify \
  --receipt portable-action-receipt.json \
  --governance-trust-store governance-trust-store.json \
  --identity-trust-store identity-trust-store.json \
  --expected-repository safal207/LiminalOSAI \
  --expected-source-head <git-object-id> \
  --expected-result-head <git-object-id>
```

Projection examples:

```bash
python3 tools/chatgpt_portable_action_receipt.py project \
  --receipt portable-action-receipt.json \
  --format proofpath

python3 tools/chatgpt_portable_action_receipt.py project \
  --receipt portable-action-receipt.json \
  --format cml \
  --source-commit <40-char-source-commit>

python3 tools/chatgpt_portable_action_receipt.py project \
  --receipt portable-action-receipt.json \
  --format liminaldb

python3 tools/chatgpt_portable_action_receipt.py project \
  --receipt portable-action-receipt.json \
  --format rinse-supersession
```

Contract, trust, signature, tamper, schema and I/O failures exit with status `2`.

## Explicit non-claims

v1.2 does not:

- grant fresh or replay authorization;
- prove a human identity beyond retained v1.1 signed provider evidence;
- contact a live IdP or invoke a real KMS/HSM;
- acquire or store connector credentials;
- expose private keys, bearer tokens, cookies, arbitrary tool arguments or raw connector responses;
- execute, merge, deploy, roll back or deliver;
- implement Capability Broker or containment;
- make CML memory authoritative;
- make LiminalDB persistence authoritative;
- make a RINSE interpretation source truth;
- convert ProofPath post-execution evidence into pre-execution authorization.

## Security invariant

> A portable receipt may preserve evidence that authority existed and was
> consumed. It may never become authority merely because it is portable,
> signed, remembered, persisted, or reinterpreted.
