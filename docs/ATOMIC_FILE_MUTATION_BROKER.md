# Atomic File Mutation Broker MVP

Tracked by: #144

## Purpose

This layer binds one admitted filesystem mutation to one exact existing regular
file replacement. The model-facing broker does not import host filesystem
mutation APIs and never receives a host root path. A trusted POSIX adapter owns
the actual file descriptor operations.

```text
model / agent intent
→ exact FileMutationRequest
→ immutable host-provisioned FileRootBinding
→ filesystem.write_outside_workspace capability
→ short-lived one-time mutation lease
→ authenticated trusted adapter
→ dirfd + O_NOFOLLOW walk
→ verify existing regular target
→ compare expected-before SHA-256
→ verify desired bytes SHA-256 + length
→ same-directory exclusive temp write + fsync
→ second compare-before
→ atomic os.replace
→ directory fsync
→ post-write digest + ownership + mode verification
→ digest-only execution receipt
```

## MVP scope

Supported:

- replacement of one **existing regular file**;
- exact logical path capability binding;
- exact expected-before SHA-256;
- exact desired-content SHA-256 and bounded byte length;
- one-time, short-lived lease;
- containment/revoke/expiry re-check before trusted adapter access;
- Linux/POSIX no-follow directory descriptor traversal;
- same-directory atomic replacement;
- preservation of the target uid/gid and ordinary `rwx` permission bits;
- trusted internal temporary-file creation solely as the atomic-replace implementation detail.

Not supported:

- creating a new **target** file;
- deleting a target file;
- arbitrary rename/move;
- directory mutation;
- following symlinks;
- preserving setuid, setgid, or sticky privilege bits on the replacement inode;
- preserving ACLs or extended attributes in this MVP;
- wildcard path authority;
- network/process/credential authority.

## Authority split

### Model-facing broker

The `sdk/liminal_file_mutation_broker` package:

- has no `os`, `pathlib`, `shutil` or tempfile filesystem mutation authority;
- receives immutable logical root bindings at host construction time;
- uses a host-controlled clock;
- atomically replay-protects call IDs and leases;
- requires the existing `filesystem.write_outside_workspace` capability;
- emits only digest/path-reference evidence;
- authenticates the trusted adapter before releasing the raw relative path.

### Trusted POSIX adapter

`adapters/filesystem/liminal_atomic_file_replacer.py` is explicitly trusted host
code. It receives the host root mapping and adapter credential out of band. It
may open and replace files only after consuming an admitted lease.

The adapter:

1. verifies authorized content length and SHA-256 before root access;
2. fails closed if required POSIX `O_NOFOLLOW` / `O_DIRECTORY` flags are unavailable;
3. opens the root directory without following symlinks;
4. walks every parent with `O_DIRECTORY | O_NOFOLLOW` via `dir_fd`;
5. opens the target with `O_NOFOLLOW` and requires a regular file;
6. compares the target digest to `expected_before_sha256` and records uid/gid plus ordinary mode bits;
7. creates and writes a same-directory exclusive internal temporary file;
8. preserves uid/gid fail-closed, preserves ordinary `rwx` bits only, strips setuid/setgid/sticky bits, then fsyncs the temporary file;
9. re-checks target digest, type and ownership immediately before replacement;
10. calls `os.replace` with source/destination dirfds;
11. fsyncs the parent directory and verifies final digest, uid/gid and absence of privileged mode bits.

ACLs and extended attributes are intentionally not copied by this MVP. A target
whose security semantics depend on ACL/xattr metadata should not be routed
through this adapter until a later metadata-preserving profile is implemented.

The trusted adapter authority metadata distinguishes internal temporary creation
from target-file creation: the former is required by the implementation, while
the latter remains forbidden by this MVP.

Raw file bytes and raw host paths do not appear in governance receipts.

## Concurrency and stale writes

The broker serializes its own call-ID/lease transitions. The adapter performs a
second before-digest check immediately before `os.replace`, which detects normal
stale-write races. This is not a kernel-level compare-and-swap primitive: a
privileged or unauthorized host writer that races after the final check remains
inside the host/kernel trust boundary.

## Failure behavior

There are two distinct failure shapes.

### Before trusted lease consumption

These raise an exception and produce **no execution receipt**, because the
trusted filesystem adapter has not been admitted:

- non-bytes content;
- wrong adapter credential;
- unknown, expired, replayed lease;
- containment active at consumption;
- revoked/expired source capability;
- host clock regression.

The target filesystem is not accessed through the adapter in these cases.

### After trusted lease consumption

The lease is permanently consumed. Failures return a `FAILED` digest-only
execution receipt and never reactivate the lease:

- desired content hash/length mismatch — filesystem remains unchanged;
- host root mapping missing — filesystem remains unchanged;
- required POSIX no-follow flags unavailable — filesystem remains unchanged;
- stale before digest — target remains unchanged;
- symlink/non-regular/missing target or parent — target remains unchanged;
- inability to preserve uid/gid before replacement — target remains unchanged;
- write/fsync/second-check failures — target remains unchanged when failure occurs before `os.replace`;
- post-write digest, ownership or privileged-mode verification failure — the atomic replacement already occurred and the operator should treat this as an integrity incident.

Authorization-stage failures such as bad logical paths, missing/scope-mismatched
capabilities, unknown root bindings, replayed call IDs, or containment return a
`BLOCK` authorization receipt and issue no lease.

## Explicit nonclaims

This is not a general filesystem sandbox, not a VM boundary, and not protection
against a malicious kernel or privileged host process. It does not preserve ACLs
or extended attributes, and it does not replace Git, repository permissions,
branch protection or code review. The host root mapping, trusted adapter
credential and kernel/filesystem implementation remain trusted control-plane
authority.
