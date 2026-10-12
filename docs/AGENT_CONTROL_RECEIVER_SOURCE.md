# Receiver-owned source signatures

The isolated observer pilot previously authenticated the observer but trusted
the collector's `receiver_snapshot_verified_by_host=True` assertion about the
receiver export. A coherent fabricated export could satisfy that fixture check.
This increment authenticates the receiver source itself for explicitly pinned
reality observers. A collector cannot substitute its own key, relabel an old
statement for a new nonce, or change signed records while preserving SUPPORT.

## Trust and data flow

The trusted provisioning caller starts `ReceiverSourceProcess` for an existing
governed receiver and obtains a public issuer pin over that controlled process
channel. The child generates its own ephemeral Ed25519 key. No private signing
key is returned, persisted in the controller, supplied through stdin or mounted
in the observer container. The child exposes only a bounded challenge-to-export
protocol, with no sign-arbitrary-payload or write-action operation.

`ReceiverSourceIssuer.issue()` reads actual receiver records, pending acceptances
and the global cutoff in one SQLite read transaction. It checks the receiver's
existing identity, governed enforcement profile, root/execution epoch, session,
policy/objective and each stored receipt HMAC before signing. Missing/corrupt
data, orphan or mismatched effects and oversized exports are refused. An open
pending acceptance is reported as such, not presented as a committed effect.

The statement uses the domain `liminal-receiver-source-v1` and binds the exact
observer challenge digest, which includes nonce, root, execution, epoch, action,
projection, policy, objective and observer/key identities. The signed body also
binds issuer/key/source/receiver identity, issue/expiry times and the digest of
the exact export. These are point-in-time, scoped receiver observations, not
proof that no effects occurred anywhere outside this receiver.

The public issuer pin is supplied through two trusted paths:

1. The immutable `ObserverSourceStore` profile, before seeds/challenges/actions.
2. The reality observer's fixed command configuration, outside its source packet.

Both compare the exact signed export with the collector's presented records and
snapshot. `host_verified`, an attacker public key in the payload, a different
source label, numeric type substitution and unsupported roles cannot replace
those pins. SourceStore rechecks the signature at bind, observer ingestion and
every effect/stage boundary, including restart. Historical retries preserve the
original binding and expiry; a valid ingested VETO remains a permanent signal.

## Provisioning example

```python
from liminal_agent_control.receiver_source_service import ReceiverSourceProcess
from liminal_agent_control.observer_lifecycle import ObserverRingSupervisor

with ReceiverSourceProcess(
    db_path=receiver.db_path.resolve(),
    broker_key_file="/owned/private/broker.key",
    receipt_key_file="/owned/private/receipt.key",
    issuer_id="receiver-issuer",
    source_id="reality-collector",
    key_id="receiver-source-key",
    expected_receiver_id=receiver.receiver_id,
    max_age_seconds=5,
) as issuer:
    pin = issuer.enrollment
    with ObserverRingSupervisor(
        authority, root_id, registry_path="/owned/ring.sqlite",
        image_id=image_id, source_directories=role_directories,
        source_issuers={"reality": pin},
    ) as ring:
        # Install observer auth keys and this immutable source profile before seed.
        source_profile = {
            "sources": [
                {"observer_id": "reality-observer", "source_id": "reality-collector", "issuer": pin},
                {"observer_id": "continuity-observer", "source_id": "continuity-collector"},
                {"observer_id": "projection-observer", "source_id": "projection-collector"},
            ],
            "max_source_age_seconds": 5,
        }
        # After auth + source installation, seed and create a current challenge.
        # statement = issuer.issue(request)
        # packet.observed_at = statement['issued_at'] (preserve the exact JSON type).
        # packet.payload includes receiver_source_statement and its exact export.
```

Source/receiver key files are private regular files with mode 0600. The receiver
HMAC key stays on the receiver/provisioning side; observers receive only public
records and the public Ed25519 pin. Both source and ring-watchdog launches use isolated Python
with a fixed absolute SDK bootstrap so an inherited working-directory package
cannot select the child implementation. The current host-selected SDK itself
remains trusted.

Issuer capture time and the authority clock must use compatible time coordinates
in this mode; the executed demo uses live wall clocks, while unit tests may inject
an explicitly artificial clock. Signed expiry is no later than challenge expiry
and is capped by the configured issuer/source age policy. A valid cached statement
is not continuous source liveness: it can remain fresh until its finite expiry.
No newly requested statement after source loss can satisfy the signed-source gate.

## Executed verification contract

```bash
PYTHONPATH=sdk python3 -m unittest \
  tests/test_agent_control_receiver_source.py \
  tests/test_agent_control_source_issuer_profile.py \
  tests/test_agent_control_receiver_source_observer.py \
  tests/test_agent_control_receiver_source_service.py -v

# Select an already built immutable observer image; this never pulls an image.
LIMINAL_OBSERVER_DOCKER_IMAGE=sha256:<local-image-id> \
  PYTHONPATH=sdk python3 -m unittest \
  tests/test_agent_control_receiver_source_runtime.py -v
```

CI requires the real Docker experiment with zero skips. Eight separately managed
rings exercise one real permitted effect and seven denials: forged host assertion,
missing signature, attacker key, altered existing real record, old nonce, expired
source after SUPPORT, and source outage before issuance. Every denied candidate
has zero new effects. The existing-record case starts with one genuine committed
record and proves its count stays one, rather than claiming the total is zero.
All 24 observer containers and eight source children must be cleaned/reaped.

The evidence binds exact commit/tree, source hashes, immutable image, issuer and
observer public keys, source statements, actual receiver outcomes and managed
watchdog cleanup. Separate real-process tests cover hostile cwd, key rotation,
no arbitrary-sign API, private file safety, protocol bounds and source timeout.

## Remaining boundaries

This is source authentication and process/key separation on one trusted host.
It does not establish independently administered source ownership, honest-host
truth, capture completeness outside the receiver, or an external anti-rollback
anchor. Continuity and projection remain the earlier collector exports. Issuer
restart changes the key and requires new authorized root enrollment; deleting or
editing an old immutable profile is not recovery. Legacy profiles without an
issuer pin remain explicitly legacy and cannot satisfy an issuer-required root.

The signed record export contains its real arguments. Sensitive workloads need
an issuer-side redaction/schema contract; editing a signed export in the collector
is a detectable mutation, not redaction. The demo uses harmless owned data, no
external network and zero model calls. Existing commitment semantics apply:
STOP does not undo effects accepted earlier.
