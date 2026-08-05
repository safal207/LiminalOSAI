# Kernel refactor protocol

LiminalOSAI contains a large C11 runtime with many interacting modules. Kernel decomposition must preserve behavior and remain buildable after every commit.

## Current baseline

The repository now has tested runtime-contract primitives for strict numeric parsing, safe delay scaling, canonical stage ordering, and deterministic trace parsing. Those primitives are not yet wired into `core/pulse_kernel.c`; the monolith remains the production source of truth until an explicit characterization-backed wiring change lands.

## Non-negotiable rules

1. **One source of truth.** A production option, state object, parser, or loop may not have parallel legacy and extracted implementations.
2. **No dead translation units.** Every committed `core/**/*.c` file must be referenced by the build system and exercised by CI or an explicit contract-test target.
3. **No hidden linkage.** Extracted modules must not use `extern` to reach file-local (`static`) state. Shared mutable state moves through an explicit context structure or a narrow API.
4. **Headers are contracts.** Every declared public function must have an implementation in the same PR, and public headers must include the standard types they use.
5. **Generated artifacts stay generated.** Build outputs, test executables, logs, traces, archives, and object files are never committed.
6. **Input parsing is fail-closed.** Unknown flags, malformed values, overflow, NaN, and infinity produce a diagnostic and a non-zero result. Prefix lengths must not be hand-counted.
7. **Tests exercise production code.** A test-only parser or loop implementation is contract evidence, not proof that the production runtime has been migrated.
8. **Every merge head is green.** GCC, Clang, strict warnings, repository hygiene, unit tests, smoke tests, ASan, and UBSan must pass before merge.

## Required decomposition sequence

### Stage 1 — Characterize the current runtime

- Add black-box CLI tests for defaults, valid flags, malformed values, unknown flags, and dry-run behavior.
- Capture current exhale ordering, trace shape, and pulse-delay bounds.
- Compare exact outputs or normalized traces before moving production code.

### Stage 2 — Adopt the shared option types

- Move only `kernel_options` and related enums to one self-contained header.
- Include that header from the existing runtime.
- Remove the old duplicate definitions in the same commit.
- Prove defaults and structure assumptions through production-path tests.

### Stage 3 — Wire the strict parser helpers

- Replace hand-counted prefixes with the tested runtime helper.
- Reject partial input, overflow, NaN, and infinity.
- Keep help rendering separate from parsing; a reusable parser must not terminate the process.
- Remove each superseded legacy helper in the same change that adopts its replacement.

### Stage 4 — Introduce `KernelContext`

- Move shared mutable kernel state into an explicit context object.
- Pass the context to initialization, delay, inhale, reflect, exhale, and finalization functions.
- Do not expose internal state through broad globals.

### Stage 5 — Extract the pulse loop

- Move one phase at a time while preserving ordering and output.
- Keep stage inclusion and dispatch decisions in one place.
- Guard all numeric factors before multiplication, division, casts, or sleep calculations.
- Use the canonical sequence contract and compare normalized traces against the baseline.

### Stage 6 — Remove compatibility code

- Delete adapters, duplicate declarations, unused helpers, and legacy paths.
- Run the complete CI matrix and long-run diagnostics.

## Pull request boundaries

A PR should contain one independently reviewable stage. Parser migration, loop extraction, generated binaries, unrelated reporting, and broad formatting changes must not be mixed together.

## Merge checklist

- [ ] Branch starts from current `main`.
- [ ] `make clean && make` succeeds with GCC and Clang.
- [ ] Strict warning validation passes.
- [ ] `make check`, `make test`, and `make verify-core` pass.
- [ ] ASan and UBSan execute smoke and C unit tests.
- [ ] No generated or binary files are tracked.
- [ ] No unresolved critical or major review thread remains.
- [ ] Every new core translation unit is referenced by `Makefile`.
- [ ] Tests distinguish contract-only code from production-wired code.
- [ ] PR title and body describe the actual behavior change.
