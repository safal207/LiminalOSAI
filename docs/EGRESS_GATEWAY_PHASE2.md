# Liminal Egress Gateway — Phase 2 MVP

## Purpose

Phase 2 adds a defensive HTTP(S) mediation boundary on top of the Phase 1 Capability Broker.

```text
network.connect_domain capability
→ request envelope
→ normalized destination/method/call admission (one committed use)
→ DNS resolution + public-address validation
→ revalidate the same live use before each callback
→ external secret injection
→ pinned-IP transport with original-host TLS verification
→ redirect revalidation
→ digest-only network execution receipt
```

## Security invariants

- Default deny when no live `network.connect_domain` capability matches.
- Missing, revoked, expired, exhausted or wrong-destination authority is rejected before any DNS resolver, secret provider or transport callback.
- Only HTTP(S) URLs with explicit DNS hostnames are accepted.
- IP-literal destinations are denied.
- DNS results are checked before transport and on every redirect hop.
- DNS answers must be globally reachable; shared address space (`100.64.0.0/10`, including IPv4-mapped IPv6), loopback, private, link-local, multicast, unspecified and reserved addresses are denied. A mixed answer containing any denied address is rejected in full.
- HTTPS cannot redirect to HTTP.
- Each admitted redirect hop consumes exactly one use **before** resolution. Stage revalidation does not consume a second use, even for a one-use capability. A failed DNS/transport attempt is not refunded because admitted external work may already have occurred.
- Capability scope binds normalized IDNA hostname, protocol and port. Pre-I/O admission binds call ID, method, URL/body digests and redirect hop. The final receipt binds that admission receipt to the DNS and redirect-chain digests; the pre-DNS decision cannot claim to contain DNS evidence that did not yet exist.
- Secret values are resolved only at the injected transport boundary. Receipts retain only a digest of secret-reference metadata, never secret IDs or values.
- Requests with secret references cannot redirect to another scheme/hostname/port, even when a network grant allows both origins. Same-origin redirects revalidate authority before resolving/injecting again. Other cross-origin redirects drop **all** caller headers so unlabelled custom credentials are not forwarded. Routing/framing headers are transport-owned.
- Direct socket attempts exposed through `DirectSocketGuard` fail closed.

## Receipt

A successful request emits `liminal-network-execution-receipt-v0.1` containing only digest-safe evidence:

- call ID, subject and policy root;
- method;
- requested/final URL digests;
- request digest;
- Capability Broker decision receipt root;
- DNS and redirect-chain roots;
- response metadata root and status;
- secret-reference metadata root;
- explicit authority boundary.

The receipt does not contain raw URL text, request headers, response values, secret values, bearer tokens, cookies or connector credentials.

## Host integration boundary

This package does not install a firewall, proxy rule, seccomp/AppArmor policy, eBPF hook or container network namespace policy. System-wide default deny requires the host to:

1. route outbound HTTP(S) through `EgressGateway`;
2. prevent or intercept direct socket creation;
3. provide trusted DNS and transport callbacks;
4. provide secret values only through an external resolver;
5. preserve the emitted receipts in the evidence chain.

`DirectSocketGuard` is a reference fail-closed hook, not an OS-level network control.

### Trusted transport

`adapters/network/liminal_pinned_http_transport.py` supplies `PinnedHTTPTransport`
outside the model-facing SDK. It connects a raw socket to one of the gateway's
validated literal IP addresses, without `getaddrinfo`, environment proxies,
automatic redirects or retries. HTTPS uses the original normalized hostname
for SNI and certificate/hostname verification through a default verifying SSL
context. Caller-controlled Host/framing headers cannot change the destination.
All returned response data is reduced to metadata and a body digest.

The adapter defaults to a 10-second **per-socket-operation** timeout and a 1 MiB
response bound. A body provider may supply bytes by digest; the adapter checks
the digest before opening a socket. Without it only the empty-body digest is
accepted. A socket-operation timeout is not a total wall-clock deadline.

An arbitrary injected transport remains trusted code and could ignore the
validated addresses. Use this adapter or independently verify another adapter's
IP pinning, TLS and redirect behavior. The gateway cannot prove a callback's
implementation from its returned metadata.

### Clock and revocation between stages

`EgressGateway` uses a trusted wall clock by default. The request timestamp is
evidence metadata only; it cannot backdate or forward-date capability validity.
Offline fixtures explicitly inject `clock=lambda: 120` (or their fixture time);
production callers must not expose the clock provider to the agent.

Before each DNS, secret-provider and transport callback, `CapabilityBroker.live_use`
rechecks the exact committed receipt, current grant state and current expiry.
It does not select another grant or consume another use. The clock is read after
the broker lock is acquired, so waiting for an earlier callback cannot preserve
a stale expiry check. `EpochBoundCapabilityBroker` also checks runtime binding
at every stage and revokes stale authority.

Stage dispatch and revocation share a reentrant lock. A **completed** revocation
prevents subsequent callbacks. An already-admitted synchronous callback may
finish first, and a blocked callback delays revocation: this provides neither
bounded revoke latency nor cancellation of in-flight network I/O. Trusted
callbacks must use bounded operations and must not wait for another thread's
revocation while holding the stage lock. Independent host egress closure and
process termination remain necessary for a hard stop. Runtime-state mutation
must also be serialized by the trusted host; an epoch digest does not intercept
arbitrary host mutations.

### Offline regression evidence

The initial missing-grant callback-counter test failed on the previous order
with `['resolver']`; the fixed path requires an empty callback list. The suite
also checks wrong/expired/revoked/exhausted grants, denied redirects, one-use
accounting, revocation/expiry/epoch drift between stages, concurrent one-use
admission, credential origin binding, pinned IPv4/IPv6 destinations, TLS hostname
verification and rejection, response bounds and zero secondary DNS resolution.

```sh
python -m unittest tests.test_egress_gateway_phase2 tests.test_egress_admission_order tests.test_pinned_http_transport tests.test_capability_broker_phase1 tests.test_runtime_mediation_v1_3 tests.test_epoch_bound_capability tests.test_objective_integrity_guard -v
```

These are offline callback and adapter contract tests with local fakes/mocks;
they do not establish live DNS behavior, kernel containment or escape resistance.

## Non-claims

Phase 2 does not grant capabilities, discover secrets, execute shell commands, install packages, deploy, merge, roll back or perform containment. It does not claim protection from network bypass when the host allows unmediated socket access outside the gateway.
