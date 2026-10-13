# Guarding effect dispatch after BEGIN

The concrete isolated-agent fixture uses `ClosedChannelEffectGateway` to repeat
the existing launch gate after a fresh, signed external BEGIN and before
entering the endpoint POST callback. It is a sender-side admission rule for
the same fixed fixture, bounded STDIO bridge and owned synthetic endpoint.

## The next transition

The closed-channel launcher checks watchdog health and the durable fence before
bridge admission. The authority BEGIN then crosses HTTP and consumes a one-shot
reservation. Previously the gateway proceeded directly to the endpoint callback.
Health or fence state could change during that interval without another check.

The bounded guard checks the actual bound launch gate at direct execute admission
and again after PERMITTED/PENDING, immediately before endpoint callback admission.
It does not grant execution authority: the exact host grant and fresh signed
BEGIN remain necessary. The mandatory check wraps the trusted fault hook, so
clearing that hook cannot remove enforcement. Its callable and component graph
are bound by the launch gate.

The gateway persists a distinct configuration schema with a static dispatch
descriptor and run-binding digest. The legacy `NetworkGateway` cannot reopen
that state. The live launch gate binds once after graph construction. Its digest
is not embedded in the gateway configuration because the launch contract already
hashes the bridge and gateway configuration; such a dependency would be cyclic.

## Failure and recovery

A post-BEGIN refusal closes local bridge admission through the durable coordinator
fence without waiting for network or Docker cleanup. It returns UNKNOWN with the
original reservation, no receipt, unknown effect count and `dispatch_finished=false`.
The endpoint callback has not been entered. An exception in the trusted fault
hook must take this same failure path.

Failure also closes the gateway's own dispatch admission for its lifetime.
Restored health or credentials cannot reopen it, and the launch gate separately
honors an already-fenced bridge. This matters when changed configuration makes
the coordinator's durable closure unavailable before the watcher reconciles.

This does not create an externally accepted no-effect receipt. The current
authority only settles a valid endpoint-signed COMMITTED receipt, so a blocked
post-BEGIN reservation stays pending and aggregate STOP stays STOP_PENDING.
Local counters showing zero POSTs cannot manufacture terminal DENIED or STOPPED.
The watcher performs separate containment/reconciliation work when available.

Read-only reconciliation and valid receipt settlement remain available after
STOP or watchdog failure. A recovered gate, repeated execute or reopened gateway
does not reuse the consumed permit to send another POST. Lost BEGIN responses
remain unresolved; a delivered POST with a lost response is settled by signed
endpoint query without reposting.

## Evidence and validation

The gateway journals bounded dispatch observations in its durable evidence store.
Each records the exact action, reservation and signed BEGIN packet digests at
the guard decision. These observations are trusted-host diagnostics, without an
independent live signature. The standalone report checker independently rebuilds
the descriptor, validates these bindings and matches each successful dispatch
to the actual endpoint request census and signed committed receipt.

Mandatory regressions use a real signed loopback authority and HTTP endpoint.
Explicit host-health/component doubles test post-BEGIN fence, health and route
loss, persistence downgrade, lost responses and recovery. They are not Docker
or kernel-containment evidence. One regression shuts down the actual coordinator
watcher after signed BEGIN; existing watcher tests cover its readiness lifecycle.
The twelve-case actual Docker matrix still requires
real execution without skips, including `pending_effect_stop`: its POST already
reached the endpoint before STOP, so one effect may finish and settle afterward.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdk python3 -m unittest \
  tests.test_agent_control_external_agent_effect_gateway -v
```

## Completion contract and limits

The owner is the trusted host of this isolated fixture. Inputs are the exact
source revision, immutable run/route configuration, explicit host grant,
fresh signed BEGIN, durable admission fence and fresh completed watcher cycle.
The originating user request authorizes reversible repository changes and a
reviewable draft PR. Merge, deployment and live-model execution are separate
transitions. Rollback is a separate branch/revert, never a control-store restore.

Completion requires fresh CI at the published head, the real Docker report,
downloaded-artifact verification and adversarial verifier replay. Missing or
contradictory evidence leaves the transition unverified. An invalid transition
that must remain rejected is a new endpoint callback when the mandatory
post-BEGIN readiness check observes a closed fence or an unready watchdog.

The successful check is endpoint callback admission. STOP after that admission
may still race transport initiation or endpoint commit. This does not atomically
serialize remote STOP with transport, cancel an admitted HTTP request or add a
receiver-owned final commit fence. That stronger guarantee requires a separate
durable receiver protocol and signed terminal no-effect evidence.

The host, daemon, image, clocks and stores remain trusted. No live LLM or training
is run. Host-process crash survival, user namespace isolation, kernel escape
resistance and externally trusted latest checkpoint anchors remain unestablished.
