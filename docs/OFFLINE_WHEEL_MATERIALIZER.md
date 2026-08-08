# Concrete Offline Wheel Materializer MVP

Tracked by: #149

## Purpose

This is the first concrete package materialization backend under the Bound
Package Installation Broker. It takes one exact host-staged Python wheel and
materializes it inside the isolated container's ephemeral `/tmp` filesystem.

It does **not** fetch packages, resolve dependencies, persist an environment, run
build hooks, import the installed package, or execute package scripts.

```text
PackageInstallBroker
→ package.install ALLOW
→ exact deterministic installer argv
→ process.execute ALLOW
→ IsolatedExecutionBroker
→ WheelMaterializingDockerExecutor
→ immutable installer image
→ /usr/local/bin/liminal-pkg-installer
→ staged plan verification
→ wheel audit + RECORD sha256/size verification
→ fixed tmpfs materialization
→ digest-only materialization receipt
→ ExecutionObservation digest
→ isolated execution receipt
→ package receipt
```

## Staged workspace contract

The read-only `/workspace` must contain exactly one top-level `.whl` plus:

- `manifest.json`
- `dependency-plan.json`

The manifest has exact schema `liminal-staged-wheel-manifest-v0.1` and binds:

- registry provenance;
- normalized package name;
- exact version;
- exact wheel filename;
- wheel artifact SHA-256;
- dependency-plan SHA-256;
- dependency count.

The dependency plan has exact schema `liminal-offline-dependency-plan-v0.1`.
This MVP verifies its digest and dependency count only. It does not resolve or
materialize dependencies.

## Wheel validation

Before any output file is created, the adapter verifies:

1. wheel is a regular top-level staged file, not a symlink;
2. wheel bytes equal the authorized artifact SHA-256;
3. wheel filename matches the authorized package/version coordinate;
4. archive member count, per-file size, total size and compression ratio are bounded;
5. encrypted and unsupported-compression members are rejected;
6. absolute paths, traversal, dot/empty components, backslashes and case-fold path collisions are rejected;
7. symlinks and special files are rejected;
8. `.data/scripts/` and `.pth` execution vectors are rejected;
9. exactly one `.dist-info` root exists and matches package/version;
10. METADATA `Name` and `Version` match the authorized coordinate;
11. WHEEL metadata uses the supported 1.x wheel format;
12. RECORD contains the exact archive file set;
13. RECORD self-entry has empty hash/size;
14. every other file has a `sha256=` hash and size and both match the archive bytes.

RECORD verification establishes internal wheel consistency only. It does not
prove who published the wheel or that the contents are non-malicious.

## Materialization

The CLI accepts only the deterministic arguments emitted by #146 and requires:

- `--offline`
- `--no-execute-installed-code`
- fixed target `/tmp/liminal-site-packages`

The adapter creates that one target under `/tmp`, which is already a bounded
`nosuid,nodev,noexec` tmpfs in the existing isolation profile. Archive output is
written using dirfd + `O_NOFOLLOW`, directories use mode `0755`, and files are
normalized to `0644`; archive executable/setuid/setgid/sticky modes are never
preserved.

The output manifest contains only path digests, file SHA-256 values, sizes and
normalized mode. The public receipt contains only the output manifest digest,
counts and trusted input roots.

## Docker receipt bridge

`WheelMaterializingDockerExecutor` reuses the existing hardened Docker argv. It
captures one bounded JSON line from the immutable installer image, validates the
materialization receipt and checks it against the exact plan arguments. Raw
stdout is discarded after verification. The `ExecutionObservation` contains only
receipt/audit/output-manifest digests and counts.

This means the package receipt is transitively bound to the concrete materializer
result through the existing RuntimeMediator and IsolatedExecutionBroker receipt
chain.

## Explicit nonclaims

This MVP is not:

- a general Python installer;
- a dependency resolver;
- a PyPI client;
- an sdist/build backend;
- a package publisher-authenticity oracle;
- malware detection;
- persistence of an installed environment;
- execution of installed code.

The host staging process, immutable installer image, Docker/container runtime and
kernel remain trusted infrastructure. A future layer can add signed provenance
such as Sigstore/TUF-style evidence before staging without weakening this
offline-first execution boundary.
