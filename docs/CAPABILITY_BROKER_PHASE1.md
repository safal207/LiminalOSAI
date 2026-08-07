# Capability Broker — Phase 1 MVP

## Purpose

Phase 1 turns the Phase 0 capability contract into a real default-deny lifecycle decision layer.

```text
CapabilityContract
→ admit
→ grant event
→ authorize(action)
→ ALLOW | BLOCK
→ use-count update
→ revoke | expire
→ deterministic receipt
→ causal runtime event chain
```

## What the broker enforces

For every authorization decision it checks:

- exact subject;
- exact capability type;
- policy SHA-256;
- normalized requested scope;
- `not_before_unix` and `expires_at_unix`;
- current active/revoked/expired state;
- bounded `max_uses`;
- parent admission and delegation bounds when a parent capability is declared.

A missing matching capability produces `BLOCK` by default.

## Scope

Requested scope must be equal to or narrower than the admitted grant. Repository identity must match exactly. Requested refs, paths, domains, protocols, ports, executables and other list-valued scope members must be subsets of the grant. Numeric child-process bounds may only narrow.

## Lifecycle

```text
admit → active
active → use (bounded)
active → revoked
active → expired
revoked / expired → never active again
```

Each grant/use/deny/revoke/expire decision emits a Phase 0 `CausalRuntimeEvent`, linked by `previous_causal_event_sha256`.

Every decision also emits `liminal-capability-decision-receipt-v0.1` binding:

- capability ID when present;
- subject and capability type;
- policy root;
- requested scope;
- action digest;
- decision and reason codes;
- use count before/after;
- exact causal event hash;
- broker head hash.

## Authority boundary

The Phase 1 broker has authority to manage its own admitted capability lifecycle and make allow/block decisions. It does **not**:

- execute tools or commands;
- mediate HTTP, sockets or DNS;
- access secret material;
- control processes;
- perform containment;
- grant GitHub write authorization by itself;
- merge, deploy or roll back.

An `ALLOW` receipt is permission evidence for a caller that is separately responsible for enforcement and execution.

## Delegation note

Phase 0 intentionally fails closed on delegation. A child capability must reference an admitted active parent; the broker requires that parent to be explicitly marked delegable and rejects children that broaden type, policy, scope, expiry or use bounds. The current Phase 0 contract profile does not provide a special root-delegation authority object, so delegation remains conservative until that contract is versioned explicitly.

## Non-goals

- Phase 2 egress gateway;
- syscall/eBPF/seccomp enforcement;
- credential broker;
- autonomous containment;
- production distributed broker persistence;
- distributed concurrency / consensus.

The MVP is an in-process deterministic reference implementation designed to prove lifecycle semantics before lower-level runtime mediation.
