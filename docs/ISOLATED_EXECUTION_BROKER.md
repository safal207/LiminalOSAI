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

Every run has a fresh host-assigned container name. Client exit is followed by an inspection of that exact name; a surviving container is forcibly removed and the run is rejected. Timeout, output overflow and execution errors also trigger exact-session removal and an absence check. Cleanup failures propagate instead of producing a successful containment claim.

`tests/test_docker_adapter_lifecycle.py` uses local Python subprocesses as a fake Docker CLI to check ownership, bounded output and failure handling. These tests do not exercise a Docker daemon or establish container/kernel containment. Real-daemon validation of this refactor remains pending the matching CI run.

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
