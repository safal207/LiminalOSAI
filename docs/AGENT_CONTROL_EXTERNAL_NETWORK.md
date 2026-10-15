# External STOP for one owned loopback endpoint

This profile extends one-shot external admission to a real HTTP request that
creates one synthetic record in an owned endpoint. It is deliberately separate
from the records receiver and the strict public-address egress gateway. It
supports a fixed POST to `http://127.0.0.1:<port>/v1/record`, a fixed JSON content
type, and a body containing only `synthetic_marker`. Redirects, forwarding,
arbitrary headers, secret lookup and automatic retries are outside this profile.

## Authority and effect boundary

The operator creates a root and execution lineage in an independent authority
database, pinned to the owned endpoint identity and public signing key. The host
stores an exact action/grant pair in the gateway. Workers can request execution
of that action; the worker role cannot create or change a grant.

The gateway obtains BEGIN from the external authority immediately before its
single HTTP dispatch. The authority durably consumes the action and attempt IDs
before returning a one-shot PERMITTED response. Repeating BEGIN returns UNKNOWN
or CONSUMED; neither response permits another dispatch. Gateway database rollback
cannot erase that external consumption.

The endpoint verifies both the gateway request authentication and the signed,
exact-request-bound external BEGIN packet. It binds the reservation, action,
attempt, execution, epoch, grant, exact URL and body. One SQLite transaction
stores a synthetic record, its terminal receipt and its durable deduplication
identity. The terminal response is released only after that transaction commits.
Repeated requests for the same immutable identity return the old receipt and
cannot create another effect.

Only the endpoint's Ed25519 COMMITTED receipt with an exact effect count of one
can settle a network reservation. The external authority pins that endpoint key
independently of its own signer and rejects records-profile HMAC receipts,
cross-profile receipts, incorrect bindings and unsupported zero-effect claims.
The endpoint key stays outside the gateway and authority processes.

`receiver_id` in the grant identifies the actual effect receiver, the endpoint.
Execution lineage and the gateway role credentials bind the dispatch route; these
identities must not be represented as model-generated authority. Public artifacts
contain request bodies without credential HMACs, public signatures, terminal
receipts and synthetic observations. They contain no private signing keys or
live credentials.

## STOP and unknown outcomes

External STOP closes new admission and increments the root epoch. It returns
STOP_PENDING while any issued reservation lacks authenticated endpoint terminal
evidence. It returns STOPPED after all those reservations are settled.

STOPPED is scoped to external admission and the owned endpoint's synthetic
effect model. It is not proof that every HTTP callback, socket or process has
terminated. Endpoint deduplication prevents a late duplicate of an already
settled operation from creating a new effect while the endpoint database remains
intact. An old permit with no terminal endpoint receipt remains pending even if
no effect is currently visible; it might still reach the endpoint later.

A missing BEGIN acknowledgement causes no dispatch. A missing transport response
leaves the remote result UNKNOWN, including when an independent observer sees a
committed effect. Reconciliation queries the existing operation and may submit
its authenticated terminal receipt to FINISH. It never redispatches the request.
A missing FINISH acknowledgement is resolved by observation or repeated
settlement of the same immutable receipt, rather than another effect.

Gateway results preserve `remote_outcome`, `settlement_status` and the local
`dispatch_finished` diagnostic separately. A lost FINISH acknowledgement can
therefore yield status UNKNOWN with remote_outcome COMMITTED and effect_count
one: the authenticated endpoint effect is known, but authority settlement has
not yet been confirmed to this caller. A lost endpoint response has no such
proof and keeps effect_count unknown. The records-only reinforcement fixture
must not be applied to these distinct axes without an explicit mapping.

The endpoint supplies no DENIED/zero-effect terminal. Absence from a snapshot,
an HTTP error, a timeout and current socket closure cannot prove that a previously
issued request will never commit. Unknown outcomes therefore retain consumed
capacity and can keep STOP_PENDING indefinitely.

## State and configuration assumptions

The gateway database is the rollback target. The external authority and endpoint
databases, keys, clocks and trusted host remain intact and outside that rollback
domain. Missing state is reopened as missing, rather than silently initialized.
Persisted profile, key and endpoint configuration is checked at public
boundaries. A network-profile authority database cannot be reopened through the
records-only implementation.

The gateway has no local-clock authorization source. Restoring its database
tests old grants and consumption; grant expiry is enforced using the external
authority clock. The experiment must not claim a local-clock rollback test where
no such clock exists.

This is an explicit owned-loopback test policy. The public egress gateway's
address restrictions are not relaxed, and no fake public DNS result is used to
route to a private endpoint. Direct worker sockets and unrelated tools require
their own actual isolation and mediation. This SDK does not establish kernel
isolation, full network mediation or a terminal contract for arbitrary APIs.

## Reproduction and verification

The preregistered experiment uses separate controller, gateway and endpoint
processes, actual HTTP requests, endpoint SQLite inventories and actual gateway
backup/restore. Fault instrumentation is stated explicitly: BEGIN and FINISH
delivery faults occur after real signed authority responses; transport-response
loss occurs after an actual endpoint commit. A host-owned barrier holds an
accepted request before commit so STOP_PENDING can be measured.

```bash
PYTHONPATH=sdk python3 -m liminal_agent_control.external_network_demo --output /tmp/network-stop.json
python3 scripts/verify_external_network_evidence.py /tmp/network-stop.json
```

Use the repository's pinned signing dependency. An expected clean source SHA
binds the experiment and checker to that checkout. The offline checker verifies
public authority responses, endpoint signatures, exact action/grant/receipt
bindings, checkpoint continuity, actual bounded effect inventories, the twelve
case measurements, source bytes and process cleanup. It does not reuse the
gateway's or authority's admission decision helper.

The authority and endpoint public pins in the fixture are collector supplied.
Local signature verification does not establish independent key enrollment,
an independently retained latest checkpoint anchor, or completeness of effects
outside the supplied endpoint inventories. No live model, learned corrigibility,
production deployment or universal containment is measured.

Reinforcement preferences and observer agreement remain non-authorizing. A
successful bounded UNKNOWN case indicates that the fixture preserved uncertainty,
not that the agent completed its task. The command/process lifecycle extension
remains a separate step in
[AGENT_CONTROL_EFFECT_BOUNDARIES_PLAN.md](AGENT_CONTROL_EFFECT_BOUNDARIES_PLAN.md).
