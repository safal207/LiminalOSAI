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

`adapters/docker/liminal_docker_executor.py` is a **trusted host adapter**. It is the only component in this MVP that starts the Docker CLI. It receives only a validated `IsolatedExecutionPlan`, constructs an argv list, and invokes Docker with `shell=False`.

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

The CI-only isolation self-test captures output only for small trusted probes and does not expose a general command execution interface.

## Runtime negative probes

CI builds a minimal fixture image and verifies the actual container sees:

1. UID `65534` rather than root;
2. `NoNewPrivs: 1`;
3. `CapEff: 0000000000000000`;
4. the root mount marked read-only;
5. write attempts under `/workspace` rejected;
6. an outbound network attempt rejected under `network=none`.

## Explicit nonclaims

This is concrete container-runtime enforcement for `process.execute`, but it is **not** a VM boundary and does not prove resistance to Docker/container-runtime/kernel vulnerabilities.

It does not yet provide dedicated OS-backed adapters for package installation, credential retrieval or arbitrary file mutation. Those remain mediated at v1.3 but are not upgraded by this MVP to the same container-backed claim.

Repository branch protection remains separately blocked by #134.
