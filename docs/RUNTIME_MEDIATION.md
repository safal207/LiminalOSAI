# Runtime Mediation Reference Layer v1.3

## Purpose

The runtime mediation layer gives a host one explicit fail-closed admission path for sensitive runtime effects.

```text
runtime operation
→ typed operation
→ capability authorization
→ specialized mediator where required
→ injected host callback
→ digest-only observation
→ mediation receipt
→ causal trajectory
```

## Covered operation classes

- process execution
- child-process creation
- package installation
- writes outside the workspace
- credential use
- runtime configuration
- HTTP(S) network egress through the existing Egress Gateway

## Security invariants

1. Missing, revoked, expired or scope-mismatched capabilities block before the host callback.
2. Containment blocks new mediated operations before the callback or Egress Gateway transport.
3. The mediation package imports no subprocess, socket or filesystem mutation API and contains no package installer or credential store client.
4. Host callbacks return only `ExecutionObservation` with a result digest. Raw command output, file content and secret values are not recorded in receipts.
5. Executor exceptions are reduced to a digest of the exception type; exception text is excluded.
6. Network requests are delegated to `liminal_egress_gateway`; runtime mediation does not implement a second egress policy engine.
7. Every mediation result emits a hash-bound trajectory event. Successful effects become `ALLOW`; denied or failed effects become `BLOCK` so failed execution does not inflate the successful-action trajectory.
8. Filesystem writes currently project to Phase 3's generic write signal (`repository.write`) while preserving the exact runtime kind in hashed metadata. A future causal-event schema may add a dedicated filesystem kind.

## Containment integration

`enter_containment()` consumes an incident-receipt digest and closes the reference gate. `exit_containment()` consumes a human-release-receipt digest. Verification of the human release remains the responsibility of the Phase 4 containment authority; this layer does not mint or approve releases.

## Explicit non-goals

This module is **not** seccomp, eBPF, AppArmor, a network namespace, a container runtime hook, a credential daemon or an operating-system sandbox.

A host that exposes unmediated subprocess, filesystem, package, credential or socket APIs can still bypass this reference layer. Production bypass resistance therefore requires host/runtime integration and OS-level controls. Repository branch protection is separately tracked in #134.

## Next hardening step

The next implementation should bind this reference admission path to an isolated execution broker or container/runtime hook and then prove that a direct bypass attempt is rejected outside the Python library boundary.
