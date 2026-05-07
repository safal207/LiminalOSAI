# Experimental Scope

Status: reviewer-facing experimental scope note.

Scope: this document clarifies what LiminalOSAI is, what it is not, how reviewers can run it, and how it relates to the broader Liminal Evidence Stack without overstating maturity or claims.

## One-sentence claim

LiminalOSAI is an experimental C11 cognitive-runtime sandbox for exploring small interacting subsystems such as awareness, coherence, memory, consent gates, anticipation, reflection, metabolic flow, collective memory, and trace-oriented diagnostics.

## What this project is

LiminalOSAI is best understood as a research sandbox and organism metaphor runtime.

It explores how many small subsystems can interact inside a pulse-driven runtime:

```text
pulse -> signal metabolism -> awareness/coherence -> reflection -> memory/trace -> diagnostics
```

It is valuable as a place to test concepts, runtime metaphors, trace-producing subsystems, and minimal C-level implementations of liminal/cognitive ideas.

## What this project is not

LiminalOSAI is not currently:

- a production operating system,
- an AGI system,
- a cognitive science proof,
- a safety enforcement layer,
- a production agent runtime,
- a clinical/emotional assessment tool,
- a replacement for observability platforms,
- a stable SDK/API surface,
- a security boundary.

The project should be reviewed as an experimental runtime sandbox, not as a mature production system.

## Reviewer path

The repository builds two binaries:

- `build/pulse_kernel` — main pulse/orchestration binary.
- `build/liminal_core` — substrate runner for diagnostics.

Build:

```bash
make
```

Smoke checks:

```bash
make check
```

Unit tests:

```bash
make test
```

Representative runs:

```bash
./build/pulse_kernel --dry-run --limit=2
./build/liminal_core --substrate --limit=2 --trace
```

Diagnostics:

```bash
make rebirth
make report
make report-metabolic
make long-run-diagnostics
```

## Current evidence matrix

| Evidence asset | Reviewer question | Path / command | Current status |
| --- | --- | --- | --- |
| Build path | Can the C runtime compile? | `make` | Implemented |
| Smoke checks | Can both binaries run short diagnostics? | `make check` | Implemented |
| Unit tests | Are selected small modules testable? | `make test` | Implemented |
| Deep audit | Is technical debt documented? | `docs/DEEP_AUDIT_2026-04-24.md` | Documented |
| Phoenix diagnostics | Can the system produce self-report style output? | `make rebirth`, `make report` | Implemented path |
| Metabolic diagnostics | Can metabolic flow be reported? | `make report-metabolic` | Implemented path |
| Long-run diagnostics | Can longer traces be generated? | `make long-run-diagnostics` | Implemented path |
| Layer map | Are conceptual layers documented? | `README.md` L0-L30 map | Documented |

## What is currently implemented

- C11 pulse kernel and substrate runner.
- Many small experimental modules: awareness, coherence, dream, metabolic, affinity, mirror, collective memory, symbiosis, empathic, reflection, anticipation, consent gate, and others.
- CLI flags for tracing, diagnostics, health scans, synchronization, dream, metabolic, collective graph, affinity/consent, mirror, introspection, council/ensemble, and memory modes.
- Smoke-check target in `Makefile`.
- Unit-test target for selected modules.
- Deep technical audit report.
- Diagnostic report scripts and long-run trace paths.

## Why the experimental boundary matters

LiminalOSAI contains powerful metaphors and many subsystems, but reviewers should not confuse metaphor density with production maturity.

The safest framing is:

```text
experimental runtime sandbox -> trace-producing subsystem experiments -> possible ideas for stricter future artifacts
```

This keeps the project useful without making claims it cannot yet support.

## Relationship to the Liminal Evidence Stack

LiminalOSAI is adjacent to the formal evidence stack.

- **PythiaLabs:** formal pre-execution gate for high-risk agent actions.
- **DRP:** formal decision-record protocol.
- **LTP:** formal trace replay/admissibility layer.
- **CML:** formal causal-lineage audit layer.
- **TTM DB:** append-only ground-truth trace substrate.
- **LiminalDB:** reactive/adaptive storage and evidence substrate.
- **LiminalOSAI:** experimental runtime sandbox for cognitive/liminal subsystem ideas.

Short version:

```text
The evidence stack is the formal reviewer path.
LiminalOSAI is the experimental lab bench.
```

## What LiminalOSAI can contribute

Even though it is not a formal safety layer, LiminalOSAI can contribute:

- experimental subsystem designs,
- C-level runtime patterns,
- trace-producing diagnostics,
- small module tests,
- metaphors that may later be hardened into stricter specs,
- runtime stress patterns for memory/coherence/reflection experiments.

## Non-claims

LiminalOSAI currently does not claim:

- production readiness,
- safety enforcement,
- verified cognition,
- clinical validity,
- AGI capability,
- cognitive science validation,
- stable API compatibility,
- complete observability or tracing coverage,
- security certification.

## Suggested reviewer checklist

A reviewer can ask:

- Can it build locally?
- Can smoke checks run?
- Are small modules testable?
- Is technical debt documented?
- Are experimental claims separated from formal safety claims?
- Is the relationship to the formal evidence stack clear?

## Research / hardening roadmap

Near-term work can focus on:

1. **Runtime decomposition** — continue splitting large orchestration files into parse/init/loop/reporting units.
2. **Quality gates** — expand `make check`, `make test`, and optional sanitizer profiles.
3. **Trace export** — standardize diagnostic output into machine-readable trace records.
4. **Module contracts** — define input/output contracts for small subsystems.
5. **Evidence stack bridge** — export selected runtime traces into TTM DB / LTP-compatible forms.
6. **Scope discipline** — keep README metaphors, but pair them with explicit non-claims and reproducible commands.

## Current strongest positioning

Use this formulation in reviewer-facing contexts:

```text
LiminalOSAI is an experimental C11 cognitive-runtime sandbox for exploring pulse-driven subsystems, trace-producing diagnostics, and organism-inspired runtime metaphors. It is not a production OS or safety enforcement layer; it is a lab bench for ideas that may later be formalized into stricter evidence-stack artifacts.
```

## Short version

```text
LiminalOSAI is the lab bench.
The Liminal Evidence Stack is the formal reviewer path.
```
