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
→ host-provisioned staged workspace binding
→ exact registry provenance
→ exact package coordinate
→ artifact SHA-256
→ dependency-plan SHA-256
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

The `IsolatedExecutionBroker` binds the exact deterministic argv and immutable
installer image into its payload digest before the process capability is used.

## Offline-first design

`registry` is provenance only. The MVP performs no live registry lookup or
network download. The trusted host stages a read-only workspace before broker
construction. The binding contains:

- opaque binding ID;
- host workspace path (kept inside the host-provisioned object; receipts contain only its digest via the binding root);
- staged manifest SHA-256;
- immutable installer image `sha256:<digest>`.

The model request references only the binding ID and expected manifest digest.
A mismatch blocks before package capability consumption.

## Exact install intent

Each request binds:

- call ID;
- subject and policy root;
- workspace binding ID;
- registry provenance;
- normalized package name;
- exact version;
- artifact SHA-256;
- dependency-plan SHA-256;
- staged-manifest SHA-256;
- bounded dependency count.

The version and all digests are included in the request root, package plan root,
capability action root and deterministic isolated installer argv. No caller can
choose the installer executable, output target, argument profile, image, network
mode or container hardening flags.

## Isolation profile

The package broker reuses the existing default `IsolationProfile`:

- `network=none`;
- read-only container root;
- read-only `/workspace` bind mount;
- all Linux capabilities dropped;
- no-new-privileges;
- non-root uid/gid;
- bounded pids, memory and CPU;
- writable tmpfs only at `/tmp`, with `nosuid,nodev,noexec`;
- package materialization target fixed at `/tmp/liminal-site-packages`.

The package files are therefore ephemeral and disappear with the container. The
MVP does not persist them to the host or execute imported/installed package code.

## Receipt semantics

The package receipt binds:

- exact request SHA-256;
- workspace binding SHA-256;
- package plan SHA-256;
- package capability receipt SHA-256;
- isolated execution receipt SHA-256;
- package decision;
- process admission decision;
- execution outcome;
- immutable installer image;
- artifact, dependency-plan and staged-manifest digests.

Receipt verification is exact-schema and digest checked. Raw host workspace
paths and package-manager output are not embedded.

## Replay and timing

Call IDs are atomically single-use inside the broker. The broker uses a trusted
host clock; the request has no caller-controlled execution timestamp. A replayed
call is blocked before another package capability use or isolated execution.

## Explicit nonclaims

This MVP is not a package supply-chain authenticity oracle. It does not prove
that a staged artifact was legitimately published by the registry owner, does
not resolve dependencies, does not fetch packages, does not persist a runtime
environment, and does not execute installed package code. Authenticity depends
on trusted staging plus the exact artifact/manifest/dependency-plan digests.

The Docker/container runtime and immutable installer image remain trusted
execution infrastructure. A later profile can add signed provenance (for
example Sigstore/TUF-style evidence) without weakening this offline authority
split.
