# Independent reproduction report template

Copy this template into your review artifact. Replace placeholders with actual
observations. Keep NOT_RUN and failures; a successful implementation verdict is
not required to complete an independent review.

## Identity and independence

- Reviewer:
- Date and timezone:
- Involvement in the implementation:
- Repository and exact commit SHA:
- Worktree clean / dirty (relevant changes):
- Python, OS/kernel and architecture:
- Docker client/server versions, if used:
- Image registry digest and local image ID, if used:
- Preregistration digest and scorer revision:
- Exact bundle manifest digest:

## Commands and execution states

Record complete commands without credentials. For each, use PASS, FAIL,
NOT_RUN, UNAVAILABLE or INCOMPLETE, plus an evidence reference.

| Check | State | Evidence and limitation |
|---|---|---|
| Offline regressions | | |
| Deterministic A/B/C fixtures | | |
| Independent file/receipt verification | | |
| Authorized positive control | | |
| Stale/delayed request after receiver revoke acknowledgment | | |
| Parent and descendant revocation | | |
| Commit followed by response loss and broker restart | | |
| Missing observer / receiver outage | | |
| False model claim / omitted effect | | |
| Docker execution and process-tree quiescence | | |
| Supervisor crash, blocked restart and explicit owned-resource recovery | | |
| Matched Docker A/B/C evaluation | | |
| Live-model experiment | | |

## Questions to challenge

- Can the worker reach grant issuance, receiver credentials, mutable policy or
  the Docker socket?
- Does the receiver serialize epoch validation and acceptance in one
  transaction? Is its acknowledgment durable?
- Does aggregate revoke acknowledgment require every mandatory enforcement
  point? Are missing acknowledgments explicit?
- Are accepted-before-revoke operations that finish later recorded as in-flight?
- Can a lost response, restart or lease expiry reopen a possibly committed
  action without independent reconciliation?
- Can a model field, forged source label or modified artifact become trusted
  observation?
- Can an earlier authentic snapshot replace the controller-pinned final
  snapshot? Are accepted but unresolved operations exposed as pending?
- In the matched Docker queue case, did the useful control actually commit and
  did B/C become externally quiescent before the queued host request resumed?
- After killing the owned supervisor, does its workload remain registered and
  block fresh admission until authenticated revocation and termination? Does
  recovery reject a live controller, replacement receiver or mismatched owner?
- Does each worker proposal require a fresh bounded host observation, with
  observer failure closing admission before broker dispatch?
- Does a broken receiver make every "blocked" test appear successful?
- Does a deliberately weakened control cause the checker to report a failure?
- Do reported aggregates include failed, excluded, unknown and incomplete runs?
- Are fixture, Docker and live-model results kept separate?

## Findings

For each discrepancy: exact source location/revision, smallest reproduction,
expected versus actual result, raw evidence and practical consequence.

## Bounded conclusion

Choose reproduced / partially reproduced / not reproduced. State the exact
channels and trusted components checked. Hashes establish file consistency;
HMAC verification requires a trusted external key and does not establish
observation completeness. Do not infer universal safety from zero failures in
this finite suite.
