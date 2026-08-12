# TRCP Evidence Replay Benchmark v0.1

## Claim

The TRCP (trusted replay checkpoint) pipeline produces **stable,
independently verifiable, tamper-evident receipts** for contract-state
workloads: a receipt changes exactly when the evidence it covers changes, and
any single drift in the bound evidence is detectable by an independent
verifier that does not share the producer's state.

Benchmark result:

```
21/21 scenarios · 12/12 tampers · 100% hash stability · 0 false confirmations
```

## Scope

- `LOCAL_ONLY / SYNTHETIC_ONLY` — no network, no providers, no real targets.
- Contract under test: an escrow state machine (`sdk/liminal_trcp/consumer.py`):
  states `CREATED → FUNDED → RELEASE_REQUESTED → RELEASED | REFUNDED`, actors
  `buyer` / `seller`, payout-conservation and terminal-state-exclusivity
  invariants.
- Pipeline: local fixture → normalized workload evidence → TRCP bundle →
  independent replay receipt (`scripts/benchmark_trcp_contract.py`).

## How to run

```sh
python3 scripts/benchmark_trcp_contract.py
```

The script:

1. runs every scenario twice and compares three evidence hashes across runs;
2. applies 12 adversarial mutations to an otherwise-valid bundle;
3. fails (exit 1) on any expectation mismatch;
4. writes the full record set to `artifacts/trcp-contract-benchmark.json`
   (gitignored; generated output).

Every scenario record stores both runs (`evidence` + `second_evidence`),
per-key hash equality, actual vs expected violations, and whether a finding
was present. Determinism is defined per scenario as: the three evidence hashes
are equal across runs **and** the actual replay result is `PASS`.

## Scenario classes (21)

| class | count | meaning | expected violations | example path |
|---|---|---|---|---|
| `clean` | 5 | valid transitions, no violations, no finding | `[]` | `FUNDED, RELEASE_REQUESTED, RELEASED` |
| `illegal` | 13 | rejected transition or unauthorized actor | `transition-validation` / `authorization` | `RELEASE_REQUESTED` from `CREATED`; seller `release` after buyer-funded path |
| `invariant` | 3 | terminal states reached with broken conservation/exclusivity | `payout-conservation` / `terminal-state-exclusivity` | `FUNDED, REFUNDED, RELEASED` |

Seller scenarios use **per-step actor schedules** so the named action
(`release`, `refund`, `request`, deep-release) is actually reached before the
authorization failure is asserted.

## Invariants checked

- `transition-validation` — requested action must be valid from the current
  contract state.
- `authorization` — requested actor must be authorized for the action.
- `payout-conservation` — released + refunded amounts may not exceed the
  funded payout.
- `terminal-state-exclusivity` — at most one terminal state may be reached
  (no release after refund and vice versa).

## Evidence binding

- `workload_sha256` = canonical SHA-256 of `{schema, requested_path,
  actor(s), result}` where `result` carries the final state and every
  recorded step and violation.
- The TRCP bundle binds workload evidence, authorization, scope, task,
  provider runs, failover decision, and the trace hash chain.
- The receipt binds the bundle digest plus the verification outcome
  (`BUNDLE_INTEGRITY`, `WORKLOAD_EVIDENCE_BINDING`,
  `AUTHORIZATION_CONTINUITY`, `TRACE_HASH_CHAIN`, `VERIFICATION_CLOSURE`).

## Independent verification

The receiver does not share the producer's process state. It verifies the
consistency of the evidence chain — workload hash binding, bundle integrity,
provider-run hashes, trace hash chain, authorization continuity, and
verification closure — so that **no single piece of evidence can be altered
without breaking the chain**. The benchmark proves this against 12 adversarial
mutations: every one is rejected with the expected failed check, and no
expected-FAIL record is ever confirmed as `PASS` (0 false confirmations).

Boundary: the receiver does not re-execute the escrow state machine, and it
does not defend against a fully dishonest producer that coherently recomputes
the whole chain (workload hash, task fixture, provider metadata, bundle hash)
after changing a result. v0.1 guarantees consistency/binding under mutation —
the final-state tamper is detected because the dependent references are left
stale. Producer-independent re-execution requires the receiver to hold its own
workload executor; that is a separate layer, not claimed here.

Both runs are recorded per scenario (`evidence` + `second_evidence`), and
`workload_sha256`, `bundle_sha256`, `receipt_sha256` are identical across two
independent runs (63/63 hash comparisons stable).

## Limits

- Synthetic fixtures and mock providers; this measures the evidence contract,
  not real-chain execution.
- Evidence consistency/binding under mutation, not producer-independent
  re-execution (see "Independent verification").
- Timing is observational only — determinism is proven on hashes, never on
  wall-clock.
