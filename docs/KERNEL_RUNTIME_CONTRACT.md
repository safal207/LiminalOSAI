# Kernel Runtime Contract

Status: validated contract primitives are used by the production entrypoints.
Semantic option parsing now lives in the production-wired
`core/runtime/pulse_options.c` and `core/runtime/substrate_options.c` modules.
The pulse scheduler, substrate state transitions and selected trace rendering
also have explicit boundaries. Module interaction and initialization remain in
the orchestrators; this stage retains existing semantic behavior.

## Why this exists

The previous decomposition attempts in PRs #88 and #89 copied large sections of `core/pulse_kernel.c` into parallel modules without making those modules the runtime source of truth. That produced duplicate option structures, dead CLI branches, undefined symbols, generated binaries in Git, and APIs with no implementation.

The replacement proceeds in reviewable stages:

- strict prefix, finite-float, signed-integer, and unsigned-integer parsing;
- rejection of NaN, infinity, overflow, and trailing garbage;
- safe phase-shift contract parsing for a future semantic parser migration;
- delay-scale sanitization and final bounds;
- one canonical exhale-stage planner;
- deterministic trace parsing and reporting;
- black-box characterization of the real production binary;
- a production entry guard that validates critical numeric values before runtime side effects.

## Production entry rule

`core/pulse_kernel.c` is compiled with its entrypoint renamed to `pulse_kernel_core_main`. The actual process `main` lives in `core/runtime/pulse_kernel_entry.c`.

Both this entrypoint and `liminal_substrate.c` use the profile-aware guard
in `core/runtime/kernel_cli_guard.c`. Shared scalar options use the same strict
numeric primitives; substrate-specific scalar options receive equivalent
validation before initialization. The guard also validates the production
composite forms: affinity configuration, KISS thresholds, substrate tuning
ranges, pulse vitality thresholds and `--phase-shift=module:degrees`.
Numeric fields must be finite and completely consumed before the existing
semantic parser runs. Correct values retain their aliases, endpoint ordering,
duplicate-field handling and clamping.

Configuration lists longer than their 127-byte parser capacity and phase
module names longer than 31 bytes fail instead of being truncated. Tuning
integer ranges and seeds must fit `int`; `idx:` selectors and base-0 entangle
contexts must fit `uint32_t`. Both runtime profiles retain `--allow=now` and
its case variants alongside strictly validated numeric allowances.
Phase degrees use bounded modulo normalization; very large finite inputs no
longer enter a nonterminating subtraction loop. Malformed fields that previously
fell back to defaults are now rejected with exit status `2`.

The entry guard:

1. validates critical numeric syntax and finiteness with the shared contract helpers;
2. rejects invalid guarded values with exit status `2` before runtime initialization or stdout output;
3. passes valid `argc/argv` unchanged to the existing semantic parser;
4. does not construct a second `kernel_options` object;
5. does not reinterpret valid values or change legacy clamping behavior.

Unknown non-numeric options still follow the characterized legacy behavior until
a dedicated semantic CLI migration changes that compatibility contract.

## Known unavailable options

The following options are explicitly rejected instead of being silently accepted as no-ops:

- `--cm-snapshot-interval=<value>` — the legacy branch has an invalid hand-counted prefix length and cannot apply a non-empty value;
- `--phase-shift-<module>deg=<value>` — the legacy suffix/value split does not apply the advertised form reliably.

Both contracts remain covered by helper-level tests. They should be re-enabled only in the PR that migrates their semantic handling to the production parser.

## Runtime sequence rule

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

`awareness` and `gate` are mandatory. `harmony` is included whenever introspection or dream processing requires it. Disabled optional stages are not force-enabled by the contract planner.

The production monolith still has characterized legacy `--strict-order` semantics; changing that behavior requires a dedicated migration PR and an explicit test update.

## Safety invariants

1. Guarded CLI numeric values consume the complete input string.
2. NaN and infinity are invalid configuration, not valid floating-point options.
3. Invalid guarded values produce no runtime stdout side effects.
4. Invalid delay multipliers fall back to `1.0`.
5. The final delay is checked for finiteness and clamped to explicit bounds.
6. Module names that do not fit the destination buffer are rejected, never truncated.
7. Generated build outputs remain outside version control.
8. Known broken options fail explicitly rather than pretending to succeed.

## Validation

```bash
make
make check
make test
make verify-core
```

Validation includes:

- production CLI black-box tests;
- runtime contract unit tests;
- strict GCC and Clang builds;
- smoke checks;
- ASan and UBSan build/check/test;
- repository hygiene tests;
- Evidence Advisor regression checks.

## Deliberate boundary

The option schemas in `pulse_options.h` and `substrate_options.h` are each defined
once. The old parser and schema bodies have been removed from the orchestrators;
their replacements are linked into both production binaries through `Makefile`.
The actual pulse scheduler invokes bound stage functions in inhale, reflect,
exhale, delay and optional health-observation order. Substrate state remains
caller-owned and selected trace writers consume read-only snapshots.

[C orchestrator boundaries](C_ORCHESTRATOR_BOUNDARIES.md) records the exact
characterization profile and remaining ownership limits. The next semantic
migration should:

1. move one coherent group of option fields and branches at a time;
2. use the existing characterization suite as the behavior baseline;
3. remove each superseded legacy branch in the same change;
4. replace hand-counted prefixes with contract helpers;
5. keep help rendering separate from parsing;
6. move shared state through an explicit runtime context rather than broad globals;
7. prove exact-head equivalence or explicitly document each intended behavior change.
