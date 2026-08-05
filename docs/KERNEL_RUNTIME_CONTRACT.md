# Kernel Runtime Contract

Status: first validated stage of the pulse-kernel decomposition.

## Why this exists

The previous decomposition attempts in PRs #88 and #89 copied large sections of `core/pulse_kernel.c` into parallel modules without making those modules the runtime source of truth. That produced duplicate option structures, dead CLI branches, undefined symbols, generated binaries in Git, and APIs with no implementation.

This change takes a smaller, reviewable step. It extracts the contracts that can be made independent and tested before the monolith is rewired:

- strict prefix and numeric parsing;
- rejection of NaN, infinity, overflow, and trailing garbage;
- safe phase-shift parsing for `--phase-shift-<module>deg=<value>`;
- delay-scale sanitization and final bounds;
- one canonical exhale-stage planner;
- deterministic trace parsing and reporting.

## Runtime rule

A stage is selected once by `kernel_plan_sequence`. A future dispatcher must execute the returned stages without applying a second, conflicting enablement gate.

Canonical order:

```text
anticipation
-> awareness
-> collective
-> affinity
-> mirror
-> introspect
-> harmony
-> astro
-> kiss
-> gate
-> vse
-> dream
```

`awareness` and `gate` are mandatory. `harmony` is included whenever introspection or dream processing requires it. Disabled optional stages are not force-enabled by an ordering flag.

## Safety invariants

1. CLI numeric values must consume the complete input string.
2. NaN and infinity are invalid configuration, not valid floating-point options.
3. Invalid delay multipliers fall back to `1.0`.
4. The final delay is checked for finiteness and clamped to explicit bounds.
5. Module names that do not fit the destination buffer are rejected, never truncated.
6. Generated build outputs remain outside version control.

## Validation

```bash
make
make check
make test
```

The dedicated runtime-contract test covers the defects found during review of PR #89. GitHub Actions runs the full repository build, smoke checks, and tests with both GCC and Clang.

## Deliberate boundary

`core/pulse_kernel.c` remains the active runtime implementation in this stage. The new contract modules are not presented as a completed decomposition.

The next wiring change should be a separate PR that:

1. replaces the matching local helpers in `core/pulse_kernel.c` with these tested contracts;
2. removes duplicate definitions rather than keeping parallel copies;
3. preserves behavior with characterization tests;
4. moves state through an explicit runtime context instead of adding new global `extern` declarations;
5. proves exact-head equivalence through CI traces before deleting the old paths.
