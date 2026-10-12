# Isolated observers and pinned evidence sources

The signed ring authenticates observer statements. This experiment adds a
runtime boundary around each signer and a separate, persisted source-binding
boundary around its evidence. A trusted host starts three restricted Docker
containers and installs their public keys before the execution is seeded.
Each container generates its own private key inside its private temporary
filesystem. The protocol exports no private key and cannot replace an enrolled
key silently after a restart.

## What each observer can read

| Role | Collector input | Observer mount |
|---|---|---|
| Reality | Actual owned receiver records and the corresponding observed state | Its reality evidence directory, read-only |
| Continuity | The recorded event chain, exported to a separate audit source | Its continuity evidence directory, read-only |
| Projection | Installed policy, center schedule and exact bounded projection | Its projection evidence directory, read-only |

The directories and source IDs are distinct. A container receives only its own
directory and read-only SDK code. It receives no authority database, broker key,
other observer directory, host Docker socket or general workspace mount.
Source exports in this bounded experiment are prepared by the same trusted host.
They represent separate collection and access paths, not independent ownership
or a guarantee that the host cannot fabricate all three sources.

## A source is bound before the reply

The host installs an immutable source profile before seeds, tickets, actions or
challenges. Every enrolled observer has one distinct source ID. For each exact
challenge, the host collects and pins a packet before asking for a signature:

```json
{
  "source_id": "receiver-source",
  "role": "reality",
  "request_digest": "SHA256 of the exact challenge",
  "observed_at": 100.0,
  "payload": {"role-specific": "bounded public evidence"}
}
```

`ObserverSourceStore.bind(request, packet)` persists the exact packet digest,
profile and nonce association. The container reads that packet from its own
mount, evaluates the role evidence and signs the digest of the entire packet.
The existing signed-ingestion transaction requires the pinned digest. A later
file substitution, a foreign source ID or a response using another packet
cannot become accepted evidence merely because the signature is valid.

Admission and callback stages recheck the persisted source binding and current
authority-clock age after reopening the database. Source expiry can stop a
previously admitted action before its next callback. A verified VETO remains a
permanent hold after its evidence ages; old evidence never becomes permission.

## Container boundaries

Containers use an immutable local image ID, a non-root user, no network, a
read-only root filesystem, dropped capabilities and no privilege escalation.
Memory, CPU, process count, input/output and response duration are bounded. The
only writable mount is a small private `/tmp` tmpfs; the key is not a host bind
mount. The trusted adapter uses a fixed worker entry point and does not expose
Docker commands to agents.

Failure to start, obtain the expected public identity, read a bounded packet or
receive a valid response supplies no endorsement. Timeout handling removes the
named container and verifies removal; killing only the attached Docker CLI is
insufficient. Cleanup failure is reported as failure rather than successful
containment. Removing/replacing a container does not replace its enrolled key.

The actual Docker demonstration checks prohibited reads and writes from inside
the containers, in addition to inspecting the requested configuration. It checks
cross-source access, authority/socket absence, read-only source files, separate
keys and failure holding the receiver boundary. It never returns private key
bytes from a probe.

Docker shares the host kernel. The daemon, host, selected image and SDK code are
trusted. These checks establish the exercised container restrictions; they do
not prove prevention of every kernel/runtime escape or resilience to a hostile
Docker administrator. Shared-host collectors remain a stated common dependency.

## Run the experiment

Only the build step obtains dependencies. Observer containers run without
network access; the demonstration makes no model calls or external effects.

```bash
python3 -m venv /tmp/liminal-isolated-observers-venv
/tmp/liminal-isolated-observers-venv/bin/python -m pip install \
  -r experiments/agent_control/observer-requirements.txt
docker build --platform linux/amd64 \
  -f experiments/agent_control/observer.Dockerfile \
  --iidfile /tmp/liminal-observer-image-id \
  experiments/agent_control
LIMINAL_OBSERVER_DOCKER_IMAGE=$(cat /tmp/liminal-observer-image-id) \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk \
  /tmp/liminal-isolated-observers-venv/bin/python -m unittest \
  tests/test_agent_control_observer_sources.py \
  tests/test_agent_control_observer_container.py \
  tests/test_agent_control_observer_container_gate.py -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk \
  /tmp/liminal-isolated-observers-venv/bin/python \
  -m liminal_agent_control.observer_container_demo \
  --image "$(cat /tmp/liminal-observer-image-id)" \
  --output artifacts/isolated-observers/report.json
```

Actual Docker tests require the explicit image variable. Their absence is a
skip/NOT_RUN, never evidence of container isolation. CI builds from the pinned
Python base, resolves and records the derived image ID, and runs the actual
container cases. The report binds source commit/tree, Python input hashes,
image identity, public signatures, probe results, actual effect counts and
verified cleanup. Existing roots retain their earlier profiles; an installed
source profile is mandatory on the governed boundary.

The new suite contains 79 tests: 30 source-binding tests, 25 container-adapter
and source-verifier tests, and 24 effect-boundary tests. One of the latter executes
the actual Docker demonstration and is explicitly skipped without the image.
Local validation ran 1169 total tests: 1162 passed and seven Docker-only tests
were skipped. Actual containment results must come from the dedicated Docker CI
job or an independently executed reproduction.

## References and inherited limits

The parent LiminalOSAI tree is
`ab40827158e9b8be028856501380d60bb214de9b`. This extends its signed ring and
reuses the defensive container settings from
`adapters/docker/liminal_docker_executor.py`; it adds no authority to model
proposals or diagnostic results.

The container settings follow the official [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/)
and [tmpfs mount documentation](https://docs.docker.com/engine/storage/tmpfs/),
checked on 12 October 2026. No certification or universal containment claim is
made from these settings.

An already accepted receiver action may still complete after a later STOP,
revocation or VETO. Its actual result remains history. The new source and
container boundaries hold subsequent transitions; they do not undo effects.
