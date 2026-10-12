# Technical review request: receiver-backed agent action control

**Prepared for engineering and safety review; not submitted.**

Stopping an agent process does not necessarily cancel a request already queued
outside that process. A lost response also leaves the controller unable to
distinguish an unsuccessful request from a committed effect. An agent's report
cannot resolve either ambiguity by itself. We built a small, reproducible
testbed for these action-boundary problems using an owned synthetic record
receiver. [PR #203](https://github.com/safal207/LiminalOSAI/pull/203) remains
unmerged.

## Controls under test

A host broker authorizes an exact action, attempt, execution lineage and epoch.
The receiver checks admission and revocation in the same SQLite transaction.
Receiver-authenticated receipts and scoped inventories bind observations to
those identities. Before dispatch, the broker durably reserves the action and
refuses blind replay. Restart preserves `UNKNOWN`; authenticated,
observation-only reconciliation resolves the outcome without reissuing it.

An external supervisor registers its Docker workload before execution, checks
the mandatory observer before admitting proposals, and coordinates a local
fence, receiver revocation and workload termination. Restart recovery is
explicit and restricted to registered resources with matching ownership
evidence. Worker claims remain separate from receiver observations in CML
scoring.

## Three frozen evidence scenarios

| Scenario | Observed distinction |
|---|---|
| Queued Docker A/B/C | A releases the queued request; B stops the actual workload but releases its existing host queue; C also revokes receiver admission. Late effects are **1 / 1 / 0**, with **one useful authorized operation in every arm**. This is one matched scenario, not a general escape benchmark. |
| Lost response and restart | The receiver commits and the response is dropped. Reopening preserves `UNKNOWN`; replay is denied by the revoked-root fence (`ROOT_REVOKED`). Authenticated, observation-only reconciliation identifies the original commit, with **no second commit**. |
| Contradictory worker claim | The worker reports a scripted `FAILED` after the receiver commits **one effect**. CML returns **FAIL** for that contradiction; the harness retains the failure as an expected adversarial outcome. |

## Reproduction and interpretation

Runtime and experiment source: `6ae4fa26cad23346eec7b89b106a041634e68d7a`.
Reproduction launcher: `b0d6af8ce6a2858a094e9c7639bcea5fd68eb61c`.
These are separate revisions. [Frozen CI run 38210262967](https://github.com/safal207/LiminalOSAI/actions/runs/38210262967)
retains [artifact 11729311870](https://github.com/safal207/LiminalOSAI/actions/runs/38210262967/artifacts/11729311870).
Downloaded ZIP SHA-256:
`f9a8480fe26937370fa45e293f3ba6645053e097189bb021d841d3d7256c274f`.

The [archived launcher guide](https://github.com/safal207/LiminalOSAI/blob/b0d6af8ce6a2858a094e9c7639bcea5fd68eb61c/docs/AGENT_CONTROL_CLEAN_RUN.md)
belongs to that frozen run. Start with the current
[first-run instructions](AGENT_CONTROL_CLEAN_RUN.md#first-external-run-no-docker-or-model-key)
and [four-case evidence demo](AGENT_CONTROL_DEMO.html) (download and open locally). Model-provider calls
are **NOT_RUN**; independent external human reproduction is
**NOT_ESTABLISHED**. The host, Docker daemon, receiver implementation and keys
are trusted. Shared-key HMAC verification is not public attestation. Operations
accepted before revocation may finish afterward. Explicit recovery does not
provide an autonomous crash watchdog. No OpenAI integration, compatibility,
endorsement, product breach or general solution to model deception is claimed.

## Small review request

Independently reproduce the queued-request scenario, or critique whether its
admission boundary and observations support the stated result. Record the
exact revisions, commands and any discrepancy in
[reproduction issue #201](https://github.com/safal207/LiminalOSAI/issues/201).
A failed or partial reproduction is useful evidence. We seek a bounded
methodology review before expanding to adaptive, live-model agent runs.
