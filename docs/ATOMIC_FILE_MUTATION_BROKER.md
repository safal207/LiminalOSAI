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
→ post-write digest + mode verification
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
- trusted internal temporary-file creation solely as the atomic-replace implementation detail.

Not supported:

- creating a new **target** file;
- deleting a target file;
- arbitrary rename/move;
- directory mutation;
- following symlinks;
- preserving setuid, setgid, or sticky privilege bits on the replacement inode;
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
2. opens the root directory without following symlinks;
3. walks every parent with `O_DIRECTORY | O_NOFOLLOW` via `dir_fd`;
4. opens the target with `O_NOFOLLOW` and requires a regular file;
5. compares the target digest to `expected_before_sha256`;
6. creates and writes a same-directory exclusive internal temporary file;
7. preserves ordinary `rwx` permission bits only, stripping setuid/setgid/sticky bits, then fsyncs the temporary file;
8. re-checks the target digest immediately before replacement;
9. calls `os.replace` with source/destination dirfds;
10. fsyncs the parent directory and verifies the final digest and absence of privileged mode bits.

The trusted adapter authority metadata therefore distinguishes internal temporary
creation from target-file creation: the former is required by the implementation,
while the latter remains forbidden by this MVP.

Raw file bytes and raw host paths do not appear in governance receipts.

## Concurrency and stale writes

The broker serializes its own call-ID/lease transitions. The adapter performs a
second before-digest check immediately before `os.replace`, which detects normal
stale-write races. This is not a kernel-level compare-and-swap primitive: a
privileged or unauthorized host writer that races after the final check remains
inside the host/kernel trust boundary.

## Failure behavior

- bad path → no lease;
- missing/scope-mismatched capability → no lease;
- containment → no lease / no adapter reference;
- revoked or expired source capability → no adapter reference;
- wrong adapter credential → lease remains unconsumed;
- expired/replayed lease → no adapter reference;
- content hash/length mismatch → lease consumed, filesystem unchanged;
- stale before digest → lease consumed, target unchanged;
- symlink/non-regular target → lease consumed, target unchanged;
- post-write digest or privileged-mode verification failure → FAILED digest-only evidence; operator should
  treat this as an integrity incident because the atomic replacement already
  occurred.

## Explicit nonclaims

This is not a general filesystem sandbox, not a VM boundary, and not protection
against a malicious kernel or privileged host process. It does not replace Git,
repository permissions, branch protection or code review. The host root mapping,
trusted adapter credential and kernel/filesystem implementation remain trusted
control-plane authority.
