# Isolated Execution Broker — container-enforced process MVP

## Purpose

This layer turns the v1.3 reference mediation decision for `process.execute` into one concrete container-backed execution path.

```text
process.execute request
→ exact RuntimeOperation
→ exact IsolatedExecutionPlan digest
→ Runtime Mediator / Capability Broker
→ trusted Docker adapter
→ hardened container
→ digest-only execution observation
→ Runtime Mediation receipt
→ Isolated Execution receipt
→ causal trajectory
```

## Enforced container profile

The trusted Docker adapter launches a validated immutable image ID with:

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- non-root `65534:65534`
- PID limit `64`
- memory limit `256m`
- CPU limit `1.0`
- bounded `/tmp` tmpfs with `nosuid,nodev,noexec`
- `/workspace` mounted read-only

The SDK requires an immutable Docker image ID in `sha256:<64 hex>` form. Mutable tags are rejected.

## Authority split

`liminal_isolated_execution` is model-facing governance code. It imports no subprocess/socket/filesystem mutation API and cannot invoke Docker directly.

`adapters/docker/liminal_docker_executor.py` is a **trusted host adapter**. Its shared `run_docker_plan` entry point receives a validated `IsolatedExecutionPlan`, constructs an argv list, and invokes Docker with `shell=False`. Normal execution, wheel materialization and isolation probes use this same lifecycle boundary.

Access to the Docker daemon is therefore a privileged control-plane boundary and must not be exposed directly to the governed agent.

## Exact-plan binding

The runtime operation's `payload_sha256` must equal the digest derived from the exact container plan:

```text
immutable image ID
+ argv digest
+ host workspace digest
+ timeout
+ isolation profile digest
→ plan_sha256
→ payload_sha256
```

Changing image, arguments, workspace or isolation profile after authorization therefore invalidates the execution request before backend dispatch.

## Output boundary

Normal execution discards raw stdout/stderr. The governance receipt contains only bounded safe metadata digests and the process exit result. Executor errors are reduced by Runtime Mediator to an error-type digest.

Wheel receipts and the isolation self-test capture stdout with a 64 KiB limit enforced while reading. The reader accepts at most one additional byte to detect overflow, then aborts the session. Workload stderr is discarded. The self-test does not expose a general command execution interface.

## Session lifecycle

Every run starts with a fresh host-assigned name and a recorded daemon identity. The adapter creates an inert container with `--restart no` and session/plan labels, requires an acknowledged full container ID, validates its image and ownership, and only then starts that ID. The name is used for discovery after an unacknowledged create; start, pause and removal target immutable IDs. The process-tree backend also pins the daemon and container ID when attaching.

A client exit does not establish workload completion. Success requires an observed `exited` state with the same exit code, followed by removal and confirmed absence of that ID on the same daemon. A same-name replacement is not removed. Control-plane stdout/stderr are bounded, including inspection and cleanup; workload stderr is discarded. Each control operation has a finite timeout. Cleanup has its own bounds beyond the plan's create/start deadline.

Timeout, client death, malformed control responses, daemon outage and cleanup failure retain the trusted session identity in `DockerExecutionError.session`. An unacknowledged create remains `UNKNOWN` even after a current absence observation or removal of a late-created inert container: the original pending request cannot be proven cancelled. Recovery through `reconcile_docker_session` never starts a container.

`DockerExecutor` and the wheel executor accept an optional trusted `session_observer`. It receives an immutable `DockerSessionIdentity` before create and again after ID acknowledgement, before start. A recorder failure before create prevents dispatch; a failure after create triggers cleanup and an `UNKNOWN` result. For a single trusted writer, an operator can append each `identity.as_document()` to a private pre-created journal and flush/fsync it before returning:

```python
def record_session(identity):
    with journal_path.open("a", encoding="utf-8") as journal:
        journal.write(json.dumps(identity.as_document(), sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

executor = DockerExecutor(session_observer=record_session)
```

The caller owns journal permissions, durable storage, restart recovery and retention. Without that recorder, an abrupt Python process/host crash can lose the in-memory identity and bypass cleanup. The fixture below kills a Docker client and restarts a dedicated daemon; it does not test a Python adapter process or host crash.

`ExecutionOutcomeUnknown` is preserved through Runtime Mediator and the epoch, objective, causal and durable effect wrappers. Receipts report `UNKNOWN`, authority remains consumed, and the durable fence retains its reservation (`EFFECT_UNKNOWN_RESERVATION_STUCK`). Runtime consumers must reconcile the recorded session and effect before authorizing retries or clearing reservations. A verified container removal alone does not reconstruct a lost workload result. Successful receipt bodies and hashes keep their existing format.

`tests/test_docker_adapter_lifecycle.py` uses local Python subprocesses as a fake Docker CLI. It checks ownership, bounded output, late creation, client death, same-name replacement and uncertainty propagation, but does not establish Docker/kernel containment. `tests/fixtures/isolated_executor/docker_failure_probe.py` adds six CI scenarios with a real, separately owned daemon: normal completion, lost create response, delayed create delivery, Docker client death, delayed start against a removed ID with a same-name sentinel, and daemon stop/restart. Delays and response loss are explicitly injected at the trusted CLI transport boundary. The fixture only stops its own daemon, loads the locally built immutable image ID, and emits facts checked by an independent verifier; the report is bounded diagnostic evidence, not an attestation against a malicious host.

The [isolation workflow](../.github/workflows/isolated-execution-broker.yml) runs these scenarios and uploads `docker-failure-lifecycle` evidence bound to the tested checkout and image ID. All six owned-daemon scenarios, their standalone fact verifier, isolation probes and governed execution passed in [CI run 38538316272](https://github.com/safal207/LiminalOSAI/actions/runs/38538316272), associated with PR head `5aa119b03eed5189726dceb7b01bdf96ba488a94`. Pull-request CI tests its recorded merge checkout; this source identity is retained in the artifact. Local fake-CLI tests are not a substitute for that run. Earlier probes remain recorded in [CI run 38481395912](https://github.com/safal207/LiminalOSAI/actions/runs/38481395912) for revision `5f4843a975244e4844c6b0c0f77c6b6e1a82635d`.

## Runtime configuration probes

The isolation CI workflow builds a minimal fixture image and checks that the container reports:

1. UID `65534` rather than root;
2. `NoNewPrivs: 1`;
3. `CapEff: 0000000000000000`;
4. the root mount marked read-only;
5. the `/workspace` mount marked read-only;
6. only the loopback network interface under `network=none`.

These are observations of runtime configuration, not live outbound-network or filesystem-write attempts.

## Explicit nonclaims

This is concrete container-runtime enforcement for `process.execute`, but it is **not** a VM boundary and does not prove resistance to Docker/container-runtime/kernel vulnerabilities.

Separate [wheel materialization](OFFLINE_WHEEL_MATERIALIZER.md), [credential injection](BOUND_CREDENTIAL_BROKER.md) and [atomic file replacement](ATOMIC_FILE_MUTATION_BROKER.md) profiles describe their own trusted adapters and limits.

Repository branch protection remains separately blocked by #134.
