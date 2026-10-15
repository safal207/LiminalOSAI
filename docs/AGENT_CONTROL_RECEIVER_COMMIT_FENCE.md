# Receiver-owned STOP and commit ordering (G03)

G03 adds a final receiver boundary to the existing fixed-policy Docker worker,
bounded STDIO bridge and owned synthetic loopback endpoint. The receiver uses
one SQLite database and one write transaction to order its irreversible STOP
fence against insertion of a synthetic effect and its terminal receipt.

This is an experimental draft-stack profile. Its new Docker capture is required
by CI; local packet, loopback and process-crash tests do not establish that the
Docker matrix ran. No live LLM, model training, arbitrary destination, arbitrary
shell, production deployment or general agent-containment claim follows.

## The ordering contract

The authority still admits an exact host grant through a fresh signed BEGIN.
The gateway repeats G02's mandatory readiness check after BEGIN and before the
endpoint POST. G03 adds an independently keyed receiver control route and an
immutable receiver root/execution enrollment. The worker receives no credentials.

| Receiver transaction wins first | Durable facts | Terminal observation |
| --- | --- | --- |
| Commit | One synthetic effect and a signed COMMITTED receipt commit together. A later STOP transaction writes the fence. | COMMITTED remains truthful after STOP; it does not become a zero-effect result. |
| STOP | A sticky root fence commits before STOP returns its signed FENCED ACK. An admitted POST later commits a signed NO_EFFECT receipt and no effect row. | NO_EFFECT settles the original consumed permit as DENIED; it does not renew a permit or retry POST. |
| Neither outcome is observed | Transport failure, absent query or missing ACK provides no terminal proof. | UNKNOWN retains the reservation; aggregate STOP stays UNKNOWN or STOP_PENDING until all required facts are obtained. |

`BEGIN IMMEDIATE` serializes both receiver operations. A shared durable transition
counter supplies signed `terminal_sequence` and `fence_sequence`. COMMITTED must
precede that root's later fence; NO_EFFECT must follow and name the exact signed
fence digest. The response leaves the receiver only after SQLite COMMIT completes.
The synthetic effect and terminal receipt are in the same transaction; checking a
separate authority database immediately before insertion would not provide this
ordering and is not used as the final fence.

Authorization expiry remains the authority's BEGIN admission condition. An
already consumed, delayed permit can reach final commit after its grant expires
if receiver STOP has not won. G03 does not claim a second final expiry gate.

## Exact retries, uncertainty and restart

The receiver binds action, attempt, reservation, authorization, root, execution,
epoch and the exact signed BEGIN request/response. It rejects identifier or
payload reuse with different content. Enrollment cannot move an execution to
another root or reopen a fenced root. Query and exact cached OBSERVED replay
recheck the current terminal, lineage and actual effect row.

An exact commit retry returns the original signed terminal receipt, including a
COMMITTED receipt after STOP. The gateway's recovery path queries and settles;
it does not dispatch a second POST for a consumed permit. A lost NO_EFFECT reply
first produces UNKNOWN and later becomes known only through the signed receiver
receipt. UNKNOWN query results contain neither a receipt nor an effect count.

The dedicated `external_agent_receiver_bridge.py` preserves a signed receiver
NO_EFFECT result with an effect count of zero in the host callback record. It
checks the receipt signature and exact action binding; the gateway and authority
still own grant binding and settlement. The legacy G02 bridge remains unchanged.

Separate tests kill a receiver process after staging the write but before COMMIT,
then reopen the same store. Both staged rows and the transition increment roll
back. A process crash after a committed operation can be recovered through an
exact retry or query with the same configuration. These tests cover process death
and trusted local SQLite persistence, not power loss, storage faults, rollback of
trusted state, compromised keys or independently administered failure domains.
The Docker matrix itself does not run a receiver crash/restart scenario.

## Aggregate STOP and captured evidence

The host durably closes local admission, requests the receiver fence outside the
gateway operation lock, then closes both external authority roots and reconciles.
A verified ACK is monotonic for this immutable root; aggregation uses one detached
ACK snapshot. Shared endpoint clients retain per-thread signed call evidence, so
a concurrent operator STOP and gateway query cannot exchange audit packets.

STOPPED additionally requires both fresh signed external roots STOPPED, no
pending reservations, completed command/effect/observation callbacks, reaped
attach CLI processes, positive owned-process quiescence and signed lifecycle
receipts. A receiver fence alone proves none of these other facts. Every actual
POST also needs one recorded G02 READY observation bound to its exact BEGIN
request, response and action. The host diagnostics and Docker observations are
unsigned; they are trusted fixture observations, not independent signatures.

The parent collector reads receiver SQL directly. It captures roots, execution
bindings, request caches/counters, signed fences/terminals and actual effect rows.
After completed STOP it joins the host watcher before the final evidence/SQL
snapshot, preventing late control writes from creating an incomplete capture.
This collection step grants no new execution route.

`scripts/verify_external_agent_receiver_evidence.py` uses public Ed25519 and the
existing independent offline Docker/STDIO predicates. It imports no runtime
receipt, authority, supervisor or receiver decision helper. It reconstructs:

- Exact source inputs, immutable Docker image/container IDs, lifecycle receipts,
  closed-channel launch configuration and the 15-route inventory.
- Signed authority BEGIN and terminal dispositions, separating never-issued
  BEGIN denials from issued permits settled with signed NO_EFFECT.
- Operator enrollment, signed ACKs, gateway packets, durable request counters,
  unique transition sequences and receiver root/execution ancestry.
- A one-to-one match between COMMITTED receipts and actual effect rows, with no
  effect row for NO_EFFECT and an exact preceding signed fence.
- Callback completion, retained lost-response UNKNOWN observations and positive
  final cleanup for every owned container and host child process.

The preregistered real-Docker matrix contains 14 worker containers, 8 admitted
POSTs, 6 synthetic effects, 2 NO_EFFECT terminals, 14 root fences and 8 post-BEGIN
READY observations. These are acceptance expectations; a result is evidence only
when the fresh report and standalone checker both pass at the same exact source.
Capture mutation tests run again after the real report exists in CI.

## Review and reproduce

Use a clean checkout of the reviewed G03 commit and a Linux Docker daemon. The
original PR218 commit is the base of this profile, not a G03 implementation.
No model credentials are needed. The immutable image is recorded alongside the
report; changing it changes the reproduced environment.

```bash
python3 -m venv /tmp/liminal-g03-venv
/tmp/liminal-g03-venv/bin/python -m pip --isolated install \
  -r experiments/agent_control/observer-requirements.txt
export PYTHONPATH=sdk
export PYTHONDONTWRITEBYTECODE=1
export EXPECTED_SOURCE_SHA="$(git rev-parse HEAD)"
export LIMINAL_EXTERNAL_AGENT_RECEIVER_REQUIRE_DOCKER=1
export LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE=/tmp/liminal-g03-report.json
WORKER_IMAGE=python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
docker pull --platform linux/amd64 "$WORKER_IMAGE"
export LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE="$(docker image inspect --format '{{.Id}}' "$WORKER_IMAGE")"
/tmp/liminal-g03-venv/bin/python -B -m unittest \
  tests.test_agent_control_external_agent_receiver \
  tests.test_agent_control_external_agent_receiver_integration \
  tests.test_agent_control_external_agent_receiver_evidence.ReceiverPacketEvidenceTests
/tmp/liminal-g03-venv/bin/python -B -m unittest tests.test_agent_control_external_agent_receiver_runtime
/tmp/liminal-g03-venv/bin/python -B -m unittest \
  tests.test_agent_control_external_agent_receiver_evidence.ReceiverCaptureMutationTests
/tmp/liminal-g03-venv/bin/python scripts/verify_external_agent_receiver_evidence.py \
  "$LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE" --expected-source-sha "$EXPECTED_SOURCE_SHA"
```

Without an explicit immutable image, local runtime is NOT_RUN; the required flag
makes its absence a hard failure. Once runtime is requested, an unavailable
daemon or image fails. Expected-source verification also requires
an unchanged clean checkout. For a downloaded report, supply
`--expected-report-sha256` to bind the exact bytes. Optional caller-supplied public
pin and latest-anchor files improve enrollment scope; fixture pins and local
signatures alone do not establish an independently enrolled latest authority tip.

## Full repository profile requirements

The receiver-required gateway profile also requires its exact matching receiver
operator client when constructing the coordinator. Omitting that client is
rejected before creating coordinator state; a local STOP cannot substitute for
the signed receiver fence. Legacy G02 coordinator construction remains unchanged.

An authenticated, subject-bound authority refusal before issuing a permit remains
DENIED on exact execute retries and reconciliation, even without an endpoint
receipt. This does not manufacture a receiver NO_EFFECT receipt, a known effect
count, or a settled dispatched effect. COMMITTED without receiver proof remains
UNKNOWN, and dispatched COMMITTED/NO_EFFECT outcomes still require valid signed
receiver receipts. Signed loopback/SQLite regressions cover both contracts;
readiness is supplied as an explicit unit-test snapshot for the denial control,
so those regressions do not claim Docker containment measurements.

The updated main test runner discovers all repository tests and fails on skips.
Running the focused G03 commands above is not a passing `make validate` result.
The inherited draft stack also contains separate required Docker profiles:

| Input | Runtime scope |
| --- | --- |
| `LIMINAL_AGENT_CONTROL_DOCKER_IMAGE` | Base containment, fault and recovery tests |
| `LIMINAL_OBSERVER_DOCKER_IMAGE` | Observer lifecycle and receiver-source tests |
| `LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE` | External command runtime and captured evidence tests |
| `LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE` | G02 and G03 fixed worker runtimes |

These inputs must name explicit locally available immutable image IDs appropriate
to their fixtures. Signing dependencies and a working Docker daemon are also
required. Evidence output paths for each profile remain separate. G03's CI job
reruns the evidence suite after its real report exists, then runs the standalone
checker with the exact source SHA. The G02 job keeps its own runtime and checker.
An exhaustive generic gate needs all of its runtime prerequisites; no skipped
runtime is a success and no dedicated-profile result replaces the full gate.

Receiver STOP ordering applies only to this receiver-owned synthetic SQLite
insert. Trusted host/operator/receiver/authority processes, local stores, keys,
Docker daemon and source/image provenance are explicit trust inputs. Kernel
escape resistance, host compromise, database rollback, remote business effects,
live-model behavior and general containment remain outside the result.

The [four-space assurance graph](CONTAINMENT_ASSURANCE_GRAPH.md) links these
bounded controls to ideas, project structure, observations and time. Its checker
does not grant execution authority; the ordinary orientation/idea profile is
explicitly not connected to the G03 runtime.
