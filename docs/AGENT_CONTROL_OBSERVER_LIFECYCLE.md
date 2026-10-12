# Managed observer lifecycle and independent recovery

The isolated-observer pilot previously removed services in `stop()` and `finally`.
A controller killed with `SIGKILL` cannot run those handlers. This managed path
registers the complete three-role ring durably and starts a separate watchdog
before the first Docker create request. It composes the existing session STOP,
bounded Docker transport and immutable observer enrollment; it does not grant
agent actions or replace source/authentication checks.

## Managed host path

```python
from liminal_agent_control.observer_lifecycle import ObserverRingSupervisor

# authority is an existing SessionAuthority with a live root and host heartbeat.
# image_id is the immutable ID of the prebuilt observer image.
with ObserverRingSupervisor(
    authority, root_id,
    registry_path="/owned/observer-ring.sqlite",
    image_id=image_id,
    source_directories={
        "reality": "/owned/reality",
        "continuity": "/owned/continuity",
        "projection": "/owned/projection",
    },
    lifetime_seconds=30,
) as ring:
    enrollments = ring.enrollments
    # The trusted caller installs immutable ObserverAuthStore/ObserverSourceStore
    # profiles. Observations remain proposals, never grants.
    # Use only this root's challenges through ring.services[role].attest(...).
```

The supervisor pins all three roles, source directories, planned names and key
IDs. `REGISTERED` precedes any Docker work; `CREATE_PENDING` is committed before
create. A positive exact image/ownership-label check pins the immutable container
ID before attach. Enrollment fixes the public key once. The managed adapter
checks watchdog/root health before launch and before/after an attestation.
Different root challenges are refused. No automatic key or root replacement is
performed. A completed ring retains its root identity and cannot be re-created.

The watchdog runs in a separate process session with closed inherited file
descriptors. A positive exact READY acknowledgment precedes first launch. A
non-inheritable controller flock detects controller loss without trusting a
worker heartbeat or relying on PID identity alone. Root expiry, ring lifetime,
registry closing and observation failures also trigger bounded recovery. The
watchdog never renews the authority lease. Existing-only database connections
refuse lost files rather than creating empty authority or registry state.

## Recovery contract

Before STOP or Docker requests, recovery validates the immutable registry record
and exact authority database. It attempts permanent admission closure, then
closes the registry against later create/enrollment transitions. Verified STOP
is recorded separately from compute cleanup. If authority closure is unavailable,
only positively owned compute cleanup may proceed; the verdict stays INCOMPLETE
and `admission_closed=false`.

Only exact registered container IDs with the expected image and all ownership
labels are removed. Names are discovery handles; renamed owned IDs remain
addressable, and a reused name never authorizes deleting a foreign container.
Daemon errors, changed image/labels, wrong IDs and partial removal remain
INCOMPLETE. Successful Docker listing after removal establishes current absence
of the pinned ID. Three completed children plus verified root closure are
required for RECOVERED. Cleanup never reopens admission.

A lost create acknowledgment stays `CREATE_PENDING`, even if the watchdog finds
and removes the exact owned candidate. That proves removal of the observed
candidate; it does not prove that an in-flight daemon create can never complete
later. Such a ring stays CLOSING/INCOMPLETE and blocks a new ring in that registry.
There is no heuristic adoption, deletion of evidence or automatic retry to make
the result green. Resolving that uncertainty needs an explicit host reconciliation
contract and new authority, outside this increment.

Docker calls have bounded output and deadlines; recovery has a shared finite
Docker-call budget. A waiting supervisor never starts fallback recovery while its
watchdog is still running. A timeout is not proof of cancellation or absence.

## Verification

```bash
PYTHONPATH=sdk python3 -m unittest \
  tests/test_agent_control_observer_registry.py \
  tests/test_agent_control_observer_lifecycle.py -v

# Build experiments/agent_control/observer.Dockerfile and select its local ID.
LIMINAL_OBSERVER_DOCKER_IMAGE=sha256:<local-image-id> \
  PYTHONPATH=sdk python3 -m unittest \
  tests/test_agent_control_observer_lifecycle_runtime.py -v
```

CI requires both real Docker scenarios to execute with zero skips:

1. Kill the controller after three services enroll. An independent watchdog
   commits root closure, removes the three pinned IDs, preserves an unrelated
   fixture container, and rejects renewal/key-profile/root replacement.
2. Kill after real Docker create completes but before its acknowledgment reaches
   the adapter. The watchdog removes the positively owned candidate while keeping
   CREATE_PENDING/INCOMPLETE; two never-submitted children complete independently.

The runtime artifact binds source commit, source file hashes, image ID, actual
container IDs, watchdog PID and recovery observations. Unit tests separately
cover record/database substitution, reused names, wrong ownership, missing
stores, daemon failure, partial cleanup and watchdog health/readiness.

## Scope

Only `ObserverRingSupervisor` provides this managed lifecycle. Direct
`DockerObserver` and the earlier multi-root fixture demo remain unmanaged pilot
interfaces. This increment does not install an operating-system service manager
or gate every production connector. Killing controller and watchdog together,
host/kernel/daemon compromise, consistent whole-database rollback, external
source independence and secret redaction are outside the claim. All three
observers still share a trusted host. STOP does not undo effects accepted before
the receiver commitment boundary. No live-model or semantic safety claim follows
from these lifecycle tests.
