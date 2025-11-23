# LiminalOSAI

Experimental C11 sandbox combining many small cognitive-leaning subsystems (awareness, coherence, dream, metabolic flow, affinity, mirror, collective graphs, phoenix rebirth, etc.). The project builds two binaries:

- build/pulse_kernel: main orchestrator
- build/liminal_core: substrate runner for long diagnostics

## Build

- Dependencies: gcc, make, python3
- Compile: make
- Clean artifacts: make clean

## Run (common flags)

./build/pulse_kernel [flags]

- Visibility: --trace, --symbols, --reflect, --awareness, --coherence
- Safety/health: --health-scan, --scan-report, --limit=<n>
- Synchrony: --sync, --sync-trace, --phases=<4-16>
- Dream: --dream, --dreamsync, --dream-log, --dream-threshold=<0-1>
- Metabolic: --metabolic, --metabolic-trace, --vitality-threshold=<rest[:creative]>
- Collective graph: --collective, --collective-trace, --collective-memory, --cm-trace, --cm-path=<path>, --cm-snapshot-interval=<n>
- Affinity & consent: --affinity, --affinity-profile=care:0.6,respect:0.7,presence:0.5, --bond-trace, --allow-align-consent=<0-1>
- Mirror clamps: --amp-min=<f>, --amp-max=<f>, --tempo-min=<f>, --tempo-max=<f>, --mirror-softness=<f>, --mirror-trace, --mirror
- Introspection/harmony: --introspect, --harmony, --dry-run (print pipeline without running)
- Anticipation v2: --ant2, --ant2-trace, --ant2-gain=<f>
- Council & ensemble: --council, --council-log, --council-threshold=<0-1>, --ensemble-strategy=median|avg|leader, --group-target=<0-1>
- Symbiosis/empathic: --human-bridge[=off], --human-trace, --human-source=keyboard|stdin|sine, --human-gain=<f>, --empathic, --empathic-trace, --empathy-gain=<f>, --emotion-source=audio|stdin, --memory, --memory-trace, --emotion-trace=<path>, --recognition-threshold=<0-1>
- Other modules: --metabolic, --vse, --kiss, --trs, --astro, --qel, --strict-order

See core/pulse_kernel.c for the full flag list and defaults.

## Diagnostics & reports

- Phoenix rebirth self-run: make rebirth
- Phoenix trace report: make report
- Metabolic report: make report-metabolic
- Long substrate diagnostic (60 cycles, writes logs & summary): make long-run-diagnostics

## Layout

- Core loop: core/pulse_kernel.c
- Modules: core/ (astro, kiss, consent gate, etc.), affinity/, anticipation/, awareness/, coherence/, collective/, dream/, metabolic/, mirror/, reflection/, symbol/, synchrony/, symbiosis/, empathic/, memory/
- Docs: docs/ (phoenix layer manifest, timezone note); reports: phoenix_report.py, metabolic_report.py

## Notes

- Logs land in logs/; persistent memories in soil/
- Most flags clamp to safe ranges; --dry-run prints the pipeline order without running cycles
- Heavy long-run diagnostics write into diagnostics/traces/

## License

MIT. See LICENSE.
