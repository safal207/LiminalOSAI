# Causal Escalation Detector — Phase 3

Phase 3 detects risky composition of individually permitted actions.

```text
verified events
→ temporal hash chain
→ ordered action graph
→ capability / privilege deltas
→ deterministic rule matches
→ cumulative risk
→ ALLOW | REVISE | BLOCK | CONTAIN recommendation
```

The detector is deliberately deterministic. It does not use a model score or hidden heuristic. Every escalation names the exact rule IDs and contributing event IDs.

## Example

```text
package.install                  locally allowed
→ network.connect_domain         locally allowed
→ credential.access              locally allowed
→ process.spawn_child            locally allowed
──────────────────────────────────────────────
composed trajectory              CONTAIN recommendation
```

The point is not that any one event is malicious. The combined trajectory increases effective power.

## Inputs

`TrajectoryEvent` binds:

- event ID and monotonic sequence;
- observation time;
- normalized action kind;
- local decision;
- subject and optional capability ID;
- privilege before/after;
- metadata digest;
- previous event digest;
- deterministic event digest.

Malformed, tampered, reordered, time-regressing, or disconnected chains fail closed.

## Rules

Phase 3 ships a small non-weaponized reference rule set for combinations involving package installation, new egress, credential access, child-process creation, and runtime reconfiguration.

Rules are intentionally transparent and versionable. They describe governance risk patterns, not exploitation instructions.

## Risk decisions

- `<20` → `ALLOW`
- `20–49` → `REVISE`
- `50–79` → `BLOCK`
- `80–100` → `CONTAIN`

Privilege growth and peak active-capability growth add bounded deterministic risk.

## Decision receipt

Every result binds:

- final recommendation;
- risk score;
- matched rule IDs;
- exact contributing event IDs;
- privilege delta;
- peak capability count;
- human-readable explanation;
- graph SHA-256;
- decision receipt SHA-256.

## Replay

Replaying the same verified event documents produces the same receipt. Semantic or hash tampering causes verification failure.

## Authority boundary

Phase 3 is analysis only. It does not:

- grant or revoke capabilities;
- execute tools;
- open network connections;
- read credential values;
- freeze or terminate processes;
- execute containment;
- merge, deploy, roll back, or release a contained runtime.

Phase 4 consumes the `CONTAIN` recommendation and implements the actual containment lifecycle.
