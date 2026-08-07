# Pilot 001 — Governed GitHub Documentation Change

## Status

This document is the protected effect used by the first real LiminalOSAI governed GitHub pilot.

The change is intentionally low risk and reversible: it adds documentation only and does not deploy code, rotate secrets, alter infrastructure, change billing, or mutate production state.

## Human intent

Demonstrate that one real repository change can be governed by the current LiminalOSAI authority stack and can fail closed before a protected effect when required state is stale or missing.

## Target chain

```text
human intent
→ identity / KMS evidence
→ signed governance capsule
→ policy + approval
→ capability broker
→ exact write authorization
→ bounded GitHub change
→ pull request
→ CI + exact-head gate
→ merge or safe stop
→ portable action receipt
→ independent verification
→ durable replay
```

## Bounded effect

- repository: `safal207/LiminalOSAI`
- effect: documentation-only change
- target file: `docs/PILOT_001.md`
- deployment authority: none
- secret access: none
- network mediation claim: none
- autonomous rollback claim: none

## Pilot gates

The dedicated pilot CI must verify:

1. Capability Broker default-denies an operation without a live capability.
2. A valid scoped capability may authorize the bounded documentation action while remaining separate from execution.
3. Revocation causes the same action to fail closed.
4. The identity / KMS and signed-governance contract suites remain green.
5. Portable Action Receipt generation and independent verification remain green.
6. Projection-ledger reopen and replay equality remain true.
7. A deliberately injected stale-head comparison is rejected before merge.
8. No private key, bearer token, GitHub token, or credential-shaped material is persisted in the pilot evidence artifact.

## Interpretation boundary

A green pilot demonstrates one verified low-risk vertical slice. It does **not** establish enterprise security certification, kernel isolation, production egress mediation, live IdP/KMS integration, autonomous deployment safety, or universal correctness.

## Decision rule

- `PROCEED` if the bounded real workflow reaches an exact-head merge with all gates green and an independently verifiable evidence bundle.
- `REVISE` if the workflow is correct but the setup or explanation burden is materially too high.
- `HOLD` if the technical chain works but no repeated operational use is identified.
- `STOP` if the authority chain cannot fail closed or the governance overhead exceeds the value of the selected workflow.
