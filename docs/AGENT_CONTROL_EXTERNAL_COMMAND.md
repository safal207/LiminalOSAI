# External STOP for one owned Docker command

The `owned-docker-command-v1` experiment extends external admission to the
creation and start of a fixed, harmless Docker workload. It reuses the durable
external authority, `SupervisorRegistry`, Docker ownership checks and isolated
execution plan. It is a separate profile from records and owned HTTP effects.

## Two stages, one lifecycle

A worker submits an exact proposal. Only the trusted host can register its
immutable grant. CREATE and START have separate action/attempt identities and
separate fresh external BEGIN requests. START also binds the original CREATE
reservation, the full command specification and the positively observed
immutable container ID. Parent validation and one-start consumption occur under
the authority's writer lock. STOP between CREATE and START denies START.

CREATE consumption is durable before Docker is invoked. Its reservation stays
pending through the entire workload lifecycle, including any admitted START.
The trusted supervisor owns its separate durable state, registry lease, signing
key and callback journal outside the worker dispatcher's rollback domain.
An identical proposal, worker restart or restored proposal cache cannot dispatch
again. Recovery observes and settles an existing operation.

The first profile supports only the pinned fixture source, immutable local image,
read-only workspace and root filesystem, network `none`, no injected environment,
non-root user, dropped capabilities, no-new-privileges and bounded PID/memory/CPU
limits. The worker API exposes no general shell or Docker control.

## Terminal evidence

| Fact | Evidence required |
|---|---|
| Admission closed | Signed external root state for the current epoch. |
| Callback finished | Durable completion from the actual create/start exchange and no live associated callback. |
| Create confirmed | Positive owned object with immutable ID, matching image, labels and isolation configuration. |
| Start confirmed | Positive owned running state or nonzero Docker `StartedAt` for the admitted START. |
| Process quiescent | Fresh owned stopped observation with PID zero, followed by verified removal and absence of that ID. |
| Business effects | `NOT_ESTABLISHED`; lifecycle settlement does not establish them. |

Admission closure, callback completion, launch observation and process
quiescence are distinct facts. A lost Docker response, elapsed timeout, dead CLI,
empty registry or missing container never proves that an uncertain create has
finished. A supervisor restart with an unfinished callback journal retains
uncertainty; it cannot manufacture callback completion.

The independently pinned supervisor signs a `QUIESCENT` receipt only after:

1. The original create has positive ownership and immutable-ID evidence.
2. Every associated host callback has actually finished.
3. Any admitted START has positive launch evidence.
4. A fresh observation confirms the exact owned object stopped with PID zero,
   followed by removal and confirmed absence of that immutable ID.

The receipt binds the exact stage, action, authorization, reservation, command
specification, image, container, ownership and observation digest. It is persisted
before FINISH. Records HMAC and network endpoint receipts cannot settle command
reservations. A changed supervisor pin cannot reopen existing authority state.

The shared authority ledger internally uses `COMMITTED` for an authenticated
terminal reservation. In this profile that means lifecycle settlement. It is
not a command success result, business effect count or proof of undo. Receipts
retain `business_effects=NOT_ESTABLISHED` and the structured status `QUIESCENT`.

External STOP closes new admission immediately. It remains `STOP_PENDING` while
any issued stage lacks its terminal proof. Cleanup targets the pinned owned
container even during an authority outage; outage cannot authorize fresh work.
Missing inspection or ambiguous launch preserves UNKNOWN and pending state.

## Validation and reproducibility

The preregistration fixes ten scenarios: positive completion, changed binding,
STOP before create, STOP between stages, pending launch, lost delivery and
dispatcher restart, dispatcher state restoration, descendant cleanup,
unavailable observation, and authority restart/outage.

```bash
PYTHONPATH=sdk python3 -m unittest \
  tests.test_agent_control_external_command_authority \
  tests.test_agent_control_external_command_supervisor \
  tests.test_agent_control_external_command_evidence -v
```

With an explicitly supplied, locally available immutable image ID:

```bash
PYTHONPATH=sdk python3 -m liminal_agent_control.external_command_demo \
  --image "sha256:<64 hex characters>" --output /tmp/command-stop.json
python3 scripts/verify_external_command_evidence.py /tmp/command-stop.json
```

The dedicated CI job uses the existing digest-pinned Python image, resolves its
immutable Docker image ID, requires actual Docker runtime cases without skips,
and independently verifies the resulting report at the exact clean revision.
The offline checker validates public authority signatures and checkpoints,
supervisor terminal signatures, bindings, callback and process observations,
case outcomes, cleanup and source bytes. It does not import the implementation's
command decision helpers. Fixture unit tests do not establish real containment.

If Docker is unavailable locally, the real runtime is explicitly NOT_RUN or
SKIPPED; only actual CI execution can supply that evidence. Public fixture pins
and a collector-local checkpoint anchor remain `report_fixture` and
`LOCAL_SIGNATURE_ONLY` unless separately enrolled trust inputs are supplied.

## Scope

Authority, supervisor and dispatcher are separate processes on one trusted
host. The Docker daemon, host, immutable image, fixture source and supervisor
observations are trusted. Only the worker dispatcher's proposal-cache database
is restored. Supervisor/registry/authority databases, keys and clocks stay intact.
Supervisor state rollback is unsupported and is not tested as a safe operation.
The dispatcher is a host harness receiving untrusted proposals. HTTP role
credentials are separated and tested, but the experiment does not establish
OS isolation between these host processes or separate administration domains.
The fixed workload's restricted Docker configuration is a separate boundary.

This does not establish arbitrary command support, exactly-once arbitrary
effects, rollback of prior effects, kernel exploit resistance, universal process
control, cancellation of unknown daemon requests or Python threads, live LLM
behavior, learned corrigibility or model training. Orientation, reinforcement
preferences and observer agreement remain diagnostics and cannot issue permits.
The records-only preference fixture needs an explicit command knowledge mapping
before it can score these lifecycle facts.

Docker's documented [start attachment](https://docs.docker.com/reference/cli/docker/container/start/),
[kill](https://docs.docker.com/reference/cli/docker/container/kill/) and
[forced removal](https://docs.docker.com/reference/cli/docker/container/rm/)
describe the CLI operations used here. The experiment still requires actual
owned-object observations and callback evidence; command invocation alone is
not its terminal proof.
