# GitHub Bridge PR #102 Reconciliation Audit

## Decision

Historical PR #102 must not be merged directly. Its branch diverged from the v0.6-era baseline while v0.7, v0.8, v0.9, v1.0, the canonical roadmap, and the causal execution plan were added to `main`.

The code review findings remain materially relevant, so the seven-file delta was re-applied as a fresh commit whose only parent is the current v1.0 `main` commit.

## Compared state

- Historical PR: #102
- Historical head: `dd627b2906e8921ffb277a50e57212fca4e9e68c`
- Historical merge base: `5be6e7a343c51c7c1a49c228c771c703eb8332ac`
- Current baseline used for reconciliation: `83ea6cfcc1799387ef3bfd3d8432483c0e6d4318`
- Fresh reconciliation commit: `621fca0c37394d5108155ed10042fe61d6011aa3`

## Classification

| Historical change | Classification | Current-baseline action |
|---|---|---|
| Roll back bridge-created host trace and recorder journal when config persistence fails | Still missing and safe | Re-applied with focused regression coverage |
| Compute executor result digest before host completion | Still missing and required | Re-applied |
| Persist `payload_sha256` in the hash-chained host finish record | Still missing and required | Re-applied |
| Verify persisted digest equals the executor result before issuing a receipt | Still missing and required | Re-applied |
| Record deterministic exception-type digest for executor exceptions | Still missing and safe | Re-applied |
| Fail closed when bridge evidence export contains completed calls without payload digests | Still missing and required | Re-applied |
| Accept historical host traces that predate the optional digest field | Required compatibility behavior | Re-applied |
| Add strict SHA-256 validation and normalization | Still missing and safe | Re-applied |
| Expose `payload_sha256_by_call` in host verification | Still missing and required | Re-applied |
| Rename ambiguous `O` policy alias | Lint-only, harmless | Re-applied as `NO_OPTIONAL` |
| Rename test variable that shadowed the policy alias | Lint-only, harmless | Re-applied |
| Set job-level repository `PYTHONPATH` in bridge CI | Still useful for path-invoked scripts | Re-applied |
| Add rollback, persistence, exception, tamper, legacy-export and full-session tests | Still missing | Re-applied |

## Compatibility assessment

The reconciliation is backward-compatible at the public SDK boundary:

- new `payload_sha256` parameters are optional;
- historical finish records without the field remain parseable;
- existing authority fields and execution ownership remain unchanged;
- the bridge still does not own GitHub connector execution;
- policy approval still does not replace exact write authorization;
- no merge, deployment, credential, delivery, or hidden-memory authority is added.

The intentionally stricter behavior is limited to GitHub bridge evidence export: a completed GitHub call without a persisted result digest is no longer eligible for export as verified GitHub evidence.

## Files re-applied

1. `.github/workflows/github-agent-bridge-ci.yml`
2. `sdk/liminal_github_bridge/_bridge.py`
3. `sdk/liminal_github_bridge/_operations.py`
4. `sdk/liminal_host_adapter/_adapter.py`
5. `sdk/liminal_host_adapter/_core.py`
6. `sdk/liminal_host_adapter/_trace.py`
7. `tests/test_chatgpt_github_agent_bridge.py`

## Validation gate

The fresh PR must pass all workflows triggered by the current repository graph, including the GitHub bridge, host adapter, Session Recorder, connected runtime, orchestrator, policy, governance capsule, Core CI, and downstream compatibility checks.

After successful exact-head merge:

1. close historical PR #102 as superseded;
2. close issue #110;
3. record the final merge SHA and workflow results;
4. proceed to v1.1 identity work in #111.
