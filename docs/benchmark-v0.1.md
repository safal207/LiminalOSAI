# TRCP Evidence Replay Benchmark v0.1

## Claim

The TRCP (trusted replay checkpoint) pipeline produces **stable,
independently replayable, tamper-evident receipts** for contract-state
workloads: a receipt changes exactly when the evidence it covers changes, and
tampering with any bound evidence is detectable by an independent verifier.

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

## Independent replay

The receiver does not trust the consumer or the provider. It rebuilds the
workload from the evidence and compares hashes; provider claims are verified
against the workload digest. The benchmark proves this twice per scenario:

- `workload_sha256`, `bundle_sha256`, `receipt_sha256` are identical across
  two independent runs (63/63 hash comparisons stable);
- the same receipts would not exist for a tampered bundle — 12/12 mutations
  are rejected with the expected failed check, and no expected-FAIL record is
  ever confirmed as `PASS` (0 false confirmations).

## Limits

- Synthetic fixtures and mock providers; this measures the evidence contract,
  not real-chain execution.
- Timing is observational only — determinism is proven on hashes, never on
  wall-clock.
