# Liminal Egress Gateway — Phase 2 MVP

## Purpose

Phase 2 adds a defensive HTTP(S) mediation boundary on top of the Phase 1 Capability Broker.

```text
network.connect_domain capability
→ request envelope
→ DNS resolution + public-address validation
→ destination/method/call binding
→ Capability Broker decision
→ external secret injection
→ injected transport
→ redirect revalidation
→ digest-only network execution receipt
```

## Security invariants

- Default deny when no live `network.connect_domain` capability matches.
- Only HTTP(S) URLs with explicit DNS hostnames are accepted.
- IP-literal destinations are denied.
- DNS results are checked before transport and on every redirect hop.
- Loopback, private, link-local, multicast, unspecified and reserved addresses are denied.
- HTTPS cannot redirect to HTTP.
- Every redirect target is re-resolved and consumes a fresh capability-use decision.
- Capability scope binds domain, protocol and port; gateway request evidence additionally binds call ID, method, URL digest, body digest and DNS digest.
- Secret values are resolved only at the injected transport boundary. Receipts retain only a digest of secret-reference metadata, never secret IDs or values.
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

## Non-claims

Phase 2 does not grant capabilities, discover secrets, execute shell commands, install packages, deploy, merge, roll back or perform containment. It does not claim protection from network bypass when the host allows unmediated socket access outside the gateway.
