# Phase 5 — Adversarial Benchmark

This benchmark measures the existing post-sandbox governance stack on deterministic, synthetic, non-weaponized trajectories.

## It measures

- detection event index and latency in events;
- benign false-CONTAIN rate;
- containment success for expected-CONTAIN scenarios;
- evidence completeness;
- replay integrity;
- deterministic report hashing.

## Safety boundary

The corpus contains no live exploits, external network calls, credential material, shell escape instructions, deployment operations, or repository mutation. Event metadata is synthetic and digest-bound.

## Initial corpus

Benign controls cover ordinary repository/runtime actions. Risk scenarios cover safe abstractions of package→egress, egress→credential, runtime-config→credential, credential→child-process, and composed multi-step escalation.

## Acceptance targets

- replay integrity = 100%;
- evidence completeness = 100%;
- expected CONTAIN → Phase 4 REVIEW = 100%;
- benign false-CONTAIN = 0%;
- every non-ALLOW decision includes matched rules and contributing event IDs.

The benchmark is evidence-only and adds no new runtime authority.
