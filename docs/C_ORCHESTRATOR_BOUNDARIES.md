# C orchestrator boundaries

## Purpose and scope

The runtime should coordinate enabled research modules while keeping argument
interpretation, scalar cycle transitions and output formatting independently
inspectable. Previously, `pulse_kernel.c` and `liminal_substrate.c` combined all
of these responsibilities in 3,513 and 3,894 lines respectively after the
preceding CLI validation fix.

This stage moves live responsibilities behind narrow headers. It retains the
numeric entry guard, defaults, clamping and feature dependencies. The subsequent
review corrections to ten value-option prefixes are described below. It does not introduce
a second parser, copy mutable module globals into a new parallel context, or
change when trace output becomes visible.

| Boundary | Production implementation | Ownership and retained behavior |
| --- | --- | --- |
| Pulse options | `core/runtime/pulse_options.*` | One schema and parser; defaults, repeated flags, clamping, module dependencies and environment fallback retain their meaning. Entry validation runs first. |
| Substrate options | `core/runtime/substrate_options.*` | One schema and parser; replay and tuning selectors remain available to the orchestrator without exposing module state. |
| Numeric values | `core/runtime/runtime_values.h`, `options_defaults.h` | Shared existing clamp/fallback operations and mirror defaults. Strict input validation remains a separate entry responsibility. |
| Pulse scheduling | `core/runtime/pulse_loop.*` | Stack-owned descriptor binds live stages once. The scheduler owns only its counter and preserves inhale → reflect → exhale → delay → optional health observation, using one-based observation numbers. Zero limit remains unlimited. |
| Substrate state | `core/runtime/substrate_state.*` | The caller owns each state object. Initialization, pulse, reflection, rest and memory transitions preserve arithmetic and invocation order; these functions perform no I/O or allocation. |
| Selected trace output | `core/runtime/runtime_trace.*` | Writers take an explicit output stream and read-only state. Memory Soil output, substrate analysis events and shutdown output retain their byte formats. Streams remain caller-owned. |
| Module orchestration | `core/pulse_kernel.c`, `core/liminal_substrate.c` | Initialization, interaction order, module globals, LIP/replay/tuning execution and cleanup continue to have one live implementation. |

After extraction, the two orchestrators contain 2,305 and 2,435 lines. The overall
system has more explicit contracts; line movement is not evidence of a speedup.

## Characterization before and after the move

`tools/characterize_c_runtime.py` executes the actual built binaries. On Linux it
compiles a temporary `LD_PRELOAD` library that fixes time to epoch 1760000000,
seeds `rand` and makes sleep calls return immediately. No runtime source or
binary is replaced with a test implementation.

The comparison covers two binaries, seven scenarios and seeds 42, 1234 and
98765: **42 exact cases**. Scenarios include default and strict dry runs,
reversed bounds, default cycles, enabled interacting modules with VSE/QEL, and
real pulse synchronization traces for phase shifts +390.25 and −390.25. The
substrate retains its characterized ignored-unknown-option behavior for those
pulse-only flags. Every case
compares exit status, stdout, stderr and all generated file hashes. The moved
parser preserves the bounded `fmodf` phase normalization from the preceding CLI
fix; both ordinary phase traces match the old implementation.

```bash
make
python3 tools/characterize_c_runtime.py --binary-dir build --output before.json
# Build the candidate with the same compiler and flags, then compare:
python3 tools/characterize_c_runtime.py --binary-dir build --output after.json --compare before.json
```

The fixed-clock profile measures reproducible state transitions and formatting.
It does not exercise actual sleeping, timer progression, network peers, clock
adjustments, or crash recovery. Ordinary CLI/smoke tests continue to run the
production binaries without the characterization library.

## Validation and measurement

The additional `runtime_boundaries` C executable exercises the linked production
scheduler, independent state objects, cycle crossing, saturation, trace format
and non-mutating trace snapshots. It also calls the production option parsers
to check all ten repaired value options and emotional-source fallback behavior.
`make validate` includes this executable with the existing eight C executables
and all discovered Python tests. Two original Python
tests also challenge the characterization controller: a changed trace fails
comparison, a binary rebuild with identical behavior succeeds, and a candidate
cannot overwrite its comparison baseline by reusing the output path. Two further
controls run genuinely blocked compiler/measurement processes with descendants
and verify bounded failure, termination of owned process groups and direct-child
reaping.

After integrating the CLI validation commit, strict GCC validation and the
GCC AddressSanitizer/UndefinedBehaviorSanitizer profile each passed **1,031 Python
tests and nine C executables**, with no skipped tests. Local ASan used
`detect_leaks=0` because leak inspection is unavailable in this environment;
CI retains its leak checks. Clang was unavailable locally and requires CI
verification against the final published revision.

The committed [measurement record](benchmarks/c-orchestrator-boundaries.json)
compares baseline `724ff8cf6ec238adeb110ae1c0632c314d727a1c` with the frozen
candidate C source at `4c410e6f02ca166f37dec28433666bf48dfa9660`. It contains
binary fingerprints, fingerprints for all tracked C sources and headers,
exact characterization hashes and raw local resource samples. The candidate
core tree is `dfb85e3a2ae0a7fd6a91a519dfc0cb9c87e827d6`. This record is frozen
historical evidence for the extraction, not a fingerprint or measurement of
the subsequent review-fix source. Both historical measurement
binaries used clean GCC `-Os` builds with the same build
flags. Seven samples per binary execute 1,024 cycles with the enabled-module
fixture and controlled clocks/sleep. Child-process CPU time and peak resident
memory are recorded with Linux `wait4`; wall time includes process startup and
file I/O. These are synthetic local observations, not production throughput or
latency claims. The observed medians were:

| Binary | CPU seconds before / after | Peak RSS KiB before / after |
| --- | --- | --- |
| Pulse | 0.4589 / 0.4784 | 12,032 / 12,160 |
| Substrate | 0.6057 / 0.5330 | 12,288 / 12,416 |

The CPU sample ranges overlap; the pulse median increases while the substrate
median decreases. Peak RSS rises by 128 KiB for each process in this sample.
These observations record the interface tradeoff without a speedup claim.

Binary text grew from 126,494 to 127,894 bytes for pulse and from 111,829 to
112,794 bytes for substrate. Mutable data size stayed the same; substrate BSS
alignment grew by 32 bytes. The explicit module interfaces therefore have a
small binary-size cost. The scheduler and state transitions introduce no heap
allocation of their own.

## Full-review corrections

Full review of `a6a7f9301b6d66e9580ab513fb73c64e53d425c1` identified
two independently confirmed defects. Ten legacy comparisons counted beyond the
end of a value-option prefix, causing valid nonempty values to miss their parser
branches. Those comparisons and value offsets now use `sizeof("--option=") - 1`.
The existing numeric validation, defaults, clamps, feature dependencies and
handling of unknown options remain in their original paths. The public numeric
entry guard still rejects the unavailable pulse snapshot option; the direct
parser repair does not make it a new public feature.

The characterization shim compiler and resource-measurement child previously
had no deadline. Both now have a 20-second parent-clock deadline. Each starts
in its own session; failure kills its owned process group and gives direct-child
reaping a separate one-second deadline. Successful measurement still reads CPU
and peak RSS from `wait4` for that child. The polling interval is at most one
millisecond, so wall-time granularity differs from the historical controller.
The existing 20-second trace-case timeout is unchanged.

The [review-fix record](benchmarks/c-orchestrator-review-fixes.json) binds the new
controller, all 108 tracked C/build inputs, the new core tree and both real
binaries to a fresh capture. Both the unchanged baseline binaries and the
candidate were captured by this same updated controller. All 42 existing cases
match exactly; these fixtures do not exercise the ten newly repaired flags,
which have separate production-parser regression assertions. Seven fresh
resource samples per binary and revision are retained as descriptive local
observations, without a speedup claim.

The old source fails the ten-value regression and both bounded-process controls;
the corrected source passes them. Ordinary GCC `make validate` and the strict
ASan/UBSan build each pass **1,033 Python tests and nine C executables**, with
zero skips. Local ASan still uses `detect_leaks=0`; the unchanged CI sanitizer
job retains `detect_leaks=1`. Final published-head GCC, Clang and sanitizer CI
results belong in the PR evidence and are not inferred from these local runs.

## Remaining boundaries

The runtime still has process-global module state and is not reentrant. The
substrate state object alone does not make concurrent whole-runtime invocation
safe. Astro, collective and several other module-specific log streams remain
owned by their existing modules; this stage extracts selected formatting only.

The next ownership migration should move one coherent module group through an
explicit context, with characterization of initialization, shutdown and repeated
invocation. A semantic CLI migration should separately replace legacy prefix
handling and unknown-option behavior, rather than combining that behavior
change with another large relocation.
