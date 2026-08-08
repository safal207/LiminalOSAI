# Bound Package Installation Broker MVP

Tracked by: #146

## Purpose

The package broker governs one exact **offline** package materialization attempt.
It does not call `pip`, `npm`, `apt`, Docker, sockets or host filesystem APIs.
The actual installer process must pass the existing isolated execution stack as
a separate authority decision.

```text
package intent
→ PackageInstallRequest
→ host-provisioned exact staged-plan binding
→ registry + package==version
→ artifact SHA-256
→ dependency-plan SHA-256 + dependency count
→ staged-manifest SHA-256
→ package.install capability
→ deterministic installer plan
→ immutable installer image
→ process.execute capability
→ RuntimeMediator
→ IsolatedExecutionBroker
→ network=none + read-only workspace/root
→ ephemeral /tmp materialization
→ digest-only receipt
```

## Two independent gates

A successful package capability decision does **not** execute anything.
Execution additionally requires `process.execute` for:

- executable: `/usr/local/bin/liminal-pkg-installer`;
- working directory: `/workspace`;
- argument profile: `bound-package-install-v0.1`.

The `IsolatedExecutionBroker` binds the deterministic argv and immutable
installer image into its payload digest before the process capability is used.

## Host-staged exact plan

`registry` is provenance only. The MVP performs no live registry lookup or
network download. Before broker exposure, the trusted host creates an immutable
`PackageWorkspaceBinding` that pins **every** materialization input:

- opaque binding ID;
- host workspace path, represented externally only by the binding root;
- registry provenance;
- normalized `package==version` coordinate;
- artifact SHA-256;
- dependency-plan SHA-256;
- staged-manifest SHA-256;
- bounded dependency count;
- immutable installer image `sha256:<digest>`.

Broker construction rebuilds and revalidates every binding and rejects a forged
or inconsistent `binding_sha256`.

A model request references the binding ID and repeats the expected staged plan.
The broker compares registry, coordinate, artifact digest, dependency-plan
digest, manifest digest and dependency count **before** consuming
`package.install`. Any mismatch returns `BLOCK`, issues no process request, and
does not spend the package capability.

This distinction matters: `CapabilityBroker.authorize()` binds the action digest
as evidence, but action fields are not themselves a host-staging oracle. The
workspace binding is the trusted source of the exact install inputs.

## Exact package capability

The package capability is requested for:

- the exact registry; and
- the exact normalized coordinate `package==version`.

Even after the host-staged plan matches, the capability can still independently
block that coordinate. Artifact, dependency-plan, manifest and dependency-count
roots are additionally bound into the capability action digest.

## Deterministic isolated installer

The caller cannot choose the installer executable, output target, argument
profile, image, network mode or hardening flags. The argv is built exclusively
from the validated host binding and fixed constants.

The broker reuses the existing default `IsolationProfile`:

- `network=none`;
- read-only container root;
- read-only `/workspace` bind mount;
- all Linux capabilities dropped;
- no-new-privileges;
- non-root uid/gid;
- bounded pids, memory and CPU;
- writable tmpfs only at `/tmp`, with `nosuid,nodev,noexec`;
- package materialization target fixed at `/tmp/liminal-site-packages`.

The package files are ephemeral and disappear with the container. The MVP does
not persist them to the host or authorize execution of installed package code.

## Receipt semantics

The package receipt binds the exact request root, workspace binding root, package
plan root, package-capability receipt, isolated-execution receipt, immutable
installer image, artifact/dependency/manifest roots, dependency count and final
package/process outcomes. Verification is exact-schema and digest checked.

Raw host workspace paths and package-manager output are not embedded. Package
name/version are carried transitively through the request, binding, plan and
capability receipt roots rather than exposed as raw receipt fields.

## Replay and timing

Call IDs are atomically single-use inside the broker. The broker uses a trusted
host clock; the request has no caller-controlled execution timestamp. A replayed
call is blocked before another package capability use or isolated execution.

## Explicit nonclaims

This MVP is not a package supply-chain authenticity oracle. It does not prove
that a staged artifact was legitimately published by the registry owner, does
not resolve dependencies, does not fetch packages, does not persist a runtime
environment, and does not itself implement the trusted installer image.
Authenticity depends on trusted staging plus the exact artifact/manifest/
dependency-plan roots.

The container runtime and immutable installer image remain trusted execution
infrastructure. A later profile can add signed provenance and a concrete package
materializer without weakening this offline authority split.
