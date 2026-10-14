# Local journal writer and recovery contracts

The approval ledger, visible-session recorder, transaction checkpoint journal,
host trace and portable projection harness coordinate cooperative writers on
one local filesystem. Their schemas, hash payloads and accepted-entry order
remain unchanged. None grants tool authority by writing a record.

## Writer contracts

| Journal | Mutation boundary | Contention | Readers / checkpoint behavior |
| --- | --- | --- | --- |
| `ApprovalLedger` | One sibling lock spans read, snapshot-bound validation and complete-document replacement | Raises `PolicyError`; an accepted denial remains a veto | A reader validates one complete old or new document against the policy snapshot |
| `SessionRecorder` | One sibling lock spans create, append or seal and complete-document replacement | Raises `RecorderError`; sealed journals reject append | Each read validates the full event and seal hash chains |
| `TransactionJournal` | One sibling lock spans create or append and complete-document replacement | Raises `TransactionError` | Read validates the full checkpoint chain; a pending external operation still requires explicit reconciliation |
| Host trace | One sibling lock spans each trace mutation and complete-document replacement | Raises `HostAdapterError` | Trace and session recorder are separately committed files; there is no cross-file transaction |
| `ProjectionLedger` | The `projection-ledger.jsonl.lock` file spans replay, validation and atomic journal replacement; snapshot publication uses that same lock | Raises `ReceiptError` | Readers see a complete old or new journal. Snapshots are verified checkpoints of an exact journal prefix |
| `SQLiteGovernanceStore` | SQLite `BEGIN IMMEDIATE` transaction and generation/world compare-and-swap | SQLite serialization plus stale-generation/reservation rejection | WAL and `synchronous=FULL`; a killed effect writer leaves a reservation until explicit reconciliation |

Successful file replacement requires writing and flushing a temporary file,
`fsync` of that file, `os.replace` within the same directory, and successful
`fsync` of the parent directory. Directory-open or directory-sync failures
propagate; they are never silently converted into success. This requires a local
filesystem and platform supporting directory `fsync`. Provision the journal's
parent directory hierarchy durably before starting writers: flushing the final
parent does not itself acknowledge creation of new ancestors. This contract
does not cover network filesystems, hardware that ignores synchronization,
privileged writers, or filesystem aliases that bypass the same lock pathname.

Locks intentionally remain on disk after abrupt process death. Normal setup
failures close their descriptor and remove only the lock created by that
attempt. A contending process never removes someone else's lock. PID values are
diagnostic and are not evidence that mutation has stopped.

## Failure and uncertain outcomes

| Boundary | Observable state | Required handling |
| --- | --- | --- |
| Before temporary data is synchronized / before replacement | The previous accepted journal remains intact; an abrupt death can leave a temporary file and lock | Preserve evidence; verify the existing journal before any recovery |
| Replacement completed, directory synchronization failed or the process died before acknowledgment | The new complete journal may already be visible; persistence after a host/power failure is unconfirmed | Treat the operation as uncertain, re-read and verify the exact event/head; do not blindly retry an append, authorization or external effect |
| File and directory synchronized and mutation returned | The returned entry is recorded in the synchronized journal | Keep its ID/head as the acknowledgment; normal later appends preserve it |
| Existing journal or checkpoint is malformed or has divergent hashes | Validation fails before a new append is published | Do not truncate, rewrite the head or discard accepted denials to regain readiness |

These tests exercise process death and injected I/O faults. They are not a
physical power-loss test and do not prove hardware persistence behavior.

## Portable checkpoint compatibility

Appending a receipt after `write_snapshot()` is valid. On reopen, the entire
current journal is validated first, including the suffix after the checkpoint;
then the snapshot's count, head, receipt order and projection digest must equal
full replay of its exact prefix. A self-consistent snapshot for a different
prefix is rejected, as are negative, boolean, non-integer and beyond-tip counts.

`verify_snapshot()` preserves the hash-bound checkpoint fields. Its
additional result fields distinguish checkpoint equality from current equality:

- `checkpoint_replay_equal`: true only after the snapshot matches its exact prefix;
- `replay_equal`: true only if that checkpoint also reaches the current journal tip;
- `current_entry_count` and `current_head_sha256`: current full-replay state.

Existing latest-tip checkpoints retain `replay_equal == True`. Older valid
checkpoints return `False` for that flag and remain usable on reopen. These extra
verification result fields are not part of the on-disk snapshot or its digest.
Historical journal bytes, including existing whitespace and line endings, are
preserved on append. Atomic replacement copies the whole journal, so this small
conformance harness uses O(n) replay and copied bytes per append; it is not a
production database or an unbounded-log performance claim.

## Manual recovery of a persistent lock

1. Stop all services, processes and containers using the exact journal, prevent
   new writers from starting, and maintain exclusive access throughout recovery.
   Confirm that mutations have ended. An old PID, missing open descriptor or lock
   age cannot establish this: the descriptor normally closes before mutation.
2. Preserve the journal, exact sibling lock, temporary files and relevant
   snapshots or operation receipts. Verify the full chain and any checkpoint
   against their original plan/policy/session inputs. Retain accepted denials.
3. If verification fails, keep the evidence and lock in place; recover from a
   separately verified copy with explicit reconciliation. Do not automatically
   drop a partial suffix or infer that an external effect did not occur.
4. Once all writers are proven stopped and the accepted state is verified,
   remove only the exact sibling `.lock` file. Inspect temporary files as
   evidence; they are not automatically promoted to journal state.
5. Re-read and verify the journal and readiness before restarting writers.
   Lock removal never authorizes a tool call, replays a pending write or clears
   a durable effect reservation. Reconcile uncertain IDs/results explicitly.

If exclusive maintenance cannot be established, leave the lock and writers
stopped. SQLite reservations use their explicit reconciliation API; deleting a
file lock does not alter SQLite coordination state.

## Reproducible validation

`python -m unittest tests.test_local_journal_reliability` covers faults before
replacement, file-sync failures, failures after replacement at directory open
and sync, descriptor cleanup, real process-shared contention across all five
file journals, recorder process death before/after replacement, retained denial
vetoes, projection ancestry and wire-byte preservation, and checkpoint tampering
including corrupt suffixes. Existing full replay/digest and durable-governance
crash tests remain part of `make validate`.
