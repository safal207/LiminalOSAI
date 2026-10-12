# External STOP and local rollback resistance

This is a records-only extension to the owned agent-control pilot. The external
authority database, signing key, clock and operator live outside the receiver's
local database rollback domain. The experiment runs the authority and receiver
in separate processes on one trusted host. It does not demonstrate separately
administered infrastructure or protection against a hostile host administrator.

## Boundary and acknowledgement

The `external_governed_v1` receiver requires both the existing local session
policy and an exact one-shot external permit. Its external identity, endpoint
and authentication-key digests are immutable receiver metadata. Reopening it
without the external controller, or with changed configuration, fails closed.
The external request key differs from the broker and receipt keys. The external
operator key is unavailable to the receiver and worker.

The initial profile supports atomic `commit` only. Separate `accept`, `finalize`
and receiver-side `revoke` are refused. The operator sends STOP directly to the
external authority. These restrictions avoid pretending that the old two-stage
API already has the new distributed acceptance protocol.

| Root state | New admission | Previously issued permits |
|---|---|---|
| ACTIVE | Allowed after all checks | Tracked until terminal evidence |
| STOPPING | Closed; epoch advanced | Some remain unresolved |
| STOPPED | Closed | All have terminal evidence |

Root states and action states are separate records. `STOP_PENDING` means that
new external permits are blocked but earlier permits remain unresolved.
`STOPPED` means there are no unresolved permits. An issued permit is never
reissued, even for an identical request. Timeout, missing local data, expiry and
crash are not proof that a permit was unused. There is no automatic pending
timeout or negative recovery after a crashed receiver in this initial version.

The receiver takes its local write lock before requesting the external permit.
It accepts and commits the actual harmless record in one local SQLite
transaction, then reports the exact signed terminal receipt externally. FINISH
is strictly after local COMMIT. Thus a delayed local commit holds STOP in its
pending state. An ambiguous local commit also leaves the external permit
pending. The two databases do not participate in a distributed atomic transaction.

Lost BEGIN responses return UNKNOWN and never trigger another execution.
Lost FINISH responses can be repaired using the stored actual receiver receipt.
`query` performs this observation/settlement without dispatching another effect.
UNKNOWN receipts use an unknown effect count rather than asserting zero.

## What local restoration cannot restore

Restoring a prior receiver database does not reset the external root epoch,
STOP state, consumed action ID, consumed attempt ID or cumulative action budget.
Grant expiry is checked on the external authority's clock after its write lock,
so a restored receiver clock cannot renew an old grant. New roots require
explicit operator provisioning; a stopped root cannot be resurrected.

The reference service bounds concurrent connections and durable root, execution
and recorded-action counts. Fresh attempts beyond capacity receive no permit and
append no denial record. Existing observations, STOP and terminal settlement
remain available at capacity; reaching a storage budget cannot discard a permit.

Authority initialization is explicit. Normal service restart opens existing
state and rejects missing, partial or mismatched storage instead of silently
bootstrapping a new active authority.

These properties assume the external authority remains intact. Rolling back
that authority itself requires an independently held latest checkpoint anchor.
The evidence verifier can check such an anchor, but this change does not deploy
a remote anchor service or protect restored process memory.

## Evidence and repository reuse

The authority appends domain-separated Ed25519 checkpoints in the same
transaction as its mutations. Each checkpoint binds the previous digest,
global sequence, root epoch, state digest and relevant action/receipt digests.
The exported chain has no raw arguments or private keys. With no separately
trusted latest anchor, verification explicitly reports `LOCAL_SIGNATURE_ONLY`.
An anchored chain is evidence and never an execution grant.

The rollback experiment adapts the scenario from
`RESONANCE@278b3c400151e4b08a69fe1d8b2cdeea7faef5eb`, but exercises the actual
receiver acceptance boundary. It retains an unsafe local-only control to
demonstrate that the restored snapshot can revive a local grant.

Authority generations and terminal consumption follow the reviewed ATMAN and
Causal-Cell invariants. The digest-only governance-envelope body is compatible
with the declared LiminalDB bridge fields. Native Rust signing, checkpoint
predecessor linkage in that bridge and a deployed LiminalDB mirror are not
executed or claimed by this package. The controller's linked journal is the
implemented evidence boundary for this experiment.

CI checks out `ContractGraph-QA@38755bb5f056ea6f9a1c5a2b0c52401fb1d70021` for
independent trajectory evaluation. The adapter consumes actual issued permits
and authenticated terminal evidence. Failed or duplicate admission requests
are not represented as side-effect executions. That evaluator checks the
supplied bounded trace, not all effects outside this receiver.

## Reproduce

Install the pinned `experiments/agent_control/observer-requirements.txt`, then:

```sh
PYTHONPATH=sdk python3 -m unittest \
  tests/test_agent_control_external_authority.py \
  tests/test_agent_control_external_checkpoint.py \
  tests/test_agent_control_external_receiver.py \
  tests/test_agent_control_external_stop_evidence.py \
  tests/test_agent_control_external_stop_runtime.py -v
```

The runtime test runs distinct service processes with temporary fixture keys,
records actual effects, stops the receiver before database restoration and
exports public evidence when `LIMINAL_EXTERNAL_STOP_EVIDENCE` is set.
The required CI job rejects skipped runtime cases and verifies source identity.

## Remaining scope

This package does not establish full mediation of arbitrary shell, filesystem,
network or third-party tool effects. Legacy receiver profiles remain legacy;
they do not gain external rollback resistance. Existing orientation and observer
policies still apply locally, but their complete state is not externally anchored
by this change. A harmony/drift score or observer verdict grants no authority.
General recovery of crashed permits needs a separately fenced receiver and
independent evidence before negative reconciliation can be added.
