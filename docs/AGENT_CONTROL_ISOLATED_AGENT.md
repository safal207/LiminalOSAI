# An isolated agent with host-controlled admission and STOP

The `owned-docker-agent-v1` profile puts a response-driven, fixed-policy agent
inside an owned Docker container. The agent chooses its next proposal from
host responses over bounded STDIO. This experiment makes no model API calls;
it does not evaluate a live LLM or train a model.

It combines the existing [command lifecycle](AGENT_CONTROL_EXTERNAL_COMMAND.md)
and [owned endpoint](AGENT_CONTROL_EXTERNAL_NETWORK.md) profiles. CREATE and
START govern the agent process. A separate external authority governs its
effects. Both authorities and the endpoint run in separate host processes.
The supervisor, bridge, coordinator and direct network gateway share one
trusted host process for each case, so an effect callback remains accounted
for through its actual completion.

## The boundary

The worker receives a fixed configuration and exact host-fixed action proposals.
It receives no authorization grants, signing keys, request credentials,
controller databases or Docker socket. Its only mounted workspace contains the
source-pinned fixture, read-only. The container has a read-only root filesystem,
network `none`, a non-root user, dropped capabilities, no-new-privileges and
bounded process, memory and CPU resources.

The host validates canonical action shape, exact arguments and lineage before
dispatch. Changed arguments, peer lineage, old attempts and worker-supplied
reports cannot create permission. Grants are registered by the trusted host;
each effect still needs its own fresh external BEGIN. Each root's signed policy
binds the same immutable run description, including the distinct authority,
supervisor and endpoint pins, fixture digest and action digests.

Before each effect admission, the host obtains a fresh observation of the
exact owned container and its running state, isolation configuration and
process tree. An unavailable observation closes local admission without
dispatching the effect. Observation callbacks have a deadline and remain
accounted for until they actually finish; a timeout cannot manufacture their
completion. Agent stdout and claimed observations are untrusted evidence.

## One stop, several facts

The coordinator persists `CLOSING` and fences bridge admission under the same
short lock used to register callbacks. No new callback admission is allowed
after that fence. Previously admitted work can finish and stays pending until
its actual outcome is established. Network and Docker operations run outside
this lock. A host watcher reacts to either external root closing or a local
bridge deadline, protocol error, output limit or fence, without requiring a
second operator STOP.

| Fact | Required evidence |
|---|---|
| Agent admission closed | Fresh signed command root state. |
| Effect admission closed | Fresh signed effect root state. |
| Agent process quiescent | Owned immutable container observed stopped with PID zero, verified removal and absence, plus signed lifecycle receipts. |
| Host calls complete | Actual CREATE/START, attached CLI, STDIO, observation and effect callbacks finished. |
| Owned effects settled | Independently signed endpoint commit receipts and settled external reservations. |

Aggregate `STOPPED` requires every fact above. A stopped container alone cannot
settle an HTTP effect still held by the endpoint. Both authenticated roots closed
with an unresolved reservation yield `STOP_PENDING`; missing authority evidence
yields `UNKNOWN`. Missing process observation retains unknown quiescence and
pending lifecycle reservations. Recovery closes admission before any remote
operation and observes existing work; it does not restart an unfinished run.

A lost endpoint response retains its original `UNKNOWN` result even when a
later signed query establishes commitment. Reconciliation cannot redispatch
the action. A fake `COMMITTED`, `STOPPED` or signature emitted by the worker is
logged as an untrusted claim and cannot settle either authority.

## Reproduction

The preregistration fixes twelve cases: useful completion, duplicate after
commit, argument mutation, lineage swap, forged report, queued action after
STOP, unresolved endpoint effect during process STOP, lost endpoint response,
direct loopback probe, synthetic canary probe, a descendant ignoring graceful
termination, and unavailable owned-process observation.

```bash
PYTHONPATH=sdk python3 -m unittest \
  tests.test_agent_control_external_agent_authority \
  tests.test_agent_control_external_agent_bridge \
  tests.test_agent_control_external_agent_supervisor \
  tests.test_agent_control_external_agent_coordinator \
  tests.test_agent_control_external_agent_evidence -v
```

With an explicitly supplied, locally available immutable Docker image ID:

```bash
PYTHONPATH=sdk python3 -m liminal_agent_control.external_agent_demo \
  --image "sha256:<64 hex characters>" --output /tmp/isolated-agent.json
python3 scripts/verify_external_agent_evidence.py /tmp/isolated-agent.json
```

The dedicated CI job requires actual Docker execution and captured-evidence
tamper tests with no skips. It uses the digest-pinned Python image and verifies
the report against the exact clean PR revision. Its public artifact includes
the report, independent verifier output and actual Docker/image identity.
The standalone checker validates signatures, checkpoints, dual-root policies,
owned process observations, callback accounting, endpoint counts, hash-linked
STDIO history and source bytes. Its agent/network decision checks are separate
from the runtime's implementation helpers. Passing packet fixtures does not
establish real container isolation; missing local Docker is explicitly SKIPPED.

## Scope

The Docker daemon, host, image and host control services are trusted. Their
keys, clocks, coordinator, supervisor, registry and authority stores remain
intact. The host processes share one administration domain. Public signing
pins generated by the report are fixtures; collector-local checkpoint anchors
provide `LOCAL_SIGNATURE_ONLY` assurance unless separately enrolled trust
inputs are supplied.

The loopback and canary probes touch only the owned namespace and a synthetic
host fixture. No real secret reads, public Internet requests or exploit
payloads are part of the experiment. Containment claims are bounded to the
inspected configuration and measured owned endpoint, not worker self-reports.

This profile does not establish arbitrary tool support, host-store rollback
safety, kernel exploit resistance, undo of committed effects, cancellation of
unknown daemon operations or Python threads, learned corrigibility, or safety
for every model. Orientation trajectories, observer agreement and reinforcement
preferences can diagnose behavior; they cannot issue permission or replace
external action admission and terminal evidence.
