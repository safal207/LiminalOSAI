# C11 runtime guide

The original C11 research runtime explores pulse-driven subsystem interactions,
traces and diagnostic reports. Conceptual names such as awareness and coherence
are runtime vocabulary; they do not establish cognition or a security guarantee.

[Back to the project](../README.md) · [Documentation](README.md)

## Build and first run

Requirements: GCC (or a compatible C compiler), Make and Python 3. Complete
repository validation also uses Git and the OpenSSL executable with Ed25519
support. CI uses Python 3.12. The build produces the research binaries
`build/pulse_kernel` and `build/liminal_core`.

```bash
make
make check
./build/pulse_kernel --dry-run --limit=2
./build/liminal_core --substrate --limit=2 --trace
```

Run the complete baseline with `make validate`. It builds both binaries, runs
short smoke checks, all C test executables and every automatically discovered
`tests/test_*.py` module. The runner rejects empty discovery, import failures,
failed assertions and skipped tests, and prints its execution counts.

`make test` runs C and Python regressions without the smoke checks. For focused
work, use `make test-c` or
`make test-python PYTHON_TESTS=tests/test_pulse_kernel_cli.py`;
`make validate` always discovers the
full Python suite even if `PYTHON_TESTS` is set. Repository hygiene is available
separately through `make test-repo` and is also included in full discovery.

Object and test dependencies track header changes automatically. Run
`make clean` before changing the compiler or build flags so existing objects
cannot retain a previous build profile.

## Runtime options

```bash
./build/pulse_kernel [flags]
```

- **Visibility:** `--trace`, `--symbols`, `--reflect`, `--awareness`, `--coherence`
- **Diagnostic health scans:** `--health-scan`, `--scan-report`, `--limit=<n>`
- **Synchrony:** `--sync`, `--sync-trace`, `--phases=<4-16>`
- **Dream:** `--dream`, `--dreamsync`, `--dream-log`, `--dream-threshold=<0-1>`
- **Metabolic:** `--metabolic`, `--metabolic-trace`, `--vitality-threshold=<rest[:creative]>`
- **Collective graph:** `--collective`, `--collective-trace`, `--collective-memory`, `--cm-trace`, `--cm-path=<path>`, `--cm-snapshot-interval=<n>`
- **Affinity & consent:** `--affinity`, `--affinity-profile=care:0.6,respect:0.7,presence:0.5`, `--bond-trace`, `--allow-align-consent=<0-1>`
- **Mirror clamps:** `--amp-min=<f>`, `--amp-max=<f>`, `--tempo-min=<f>`, `--tempo-max=<f>`, `--mirror-softness=<f>`, `--mirror-trace`, `--mirror`
- **Introspection/harmony:** `--introspect`, `--harmony`, `--dry-run (print pipeline without running)`
- **Anticipation v2:** `--ant2`, `--ant2-trace`, `--ant2-gain=<f>`
- **Council & ensemble:** `--council`, `--council-log`, `--council-threshold=<0-1>`, `--ensemble-strategy=median|avg|leader`, `--group-target=<0-1>`
- **Symbiosis/empathic:** `--human-bridge[=off]`, `--human-trace`, `--human-source=keyboard|stdin|sine`, `--human-gain=<f>`, `--empathic`, `--empathic-trace`, `--empathy-gain=<f>`, `--emotion-source=audio|stdin`, `--memory`, `--memory-trace`, `--emotion-trace=<path>`, `--recognition-threshold=<0-1>`
- **Other modules:** `--metabolic`, `--vse`, `--kiss`, `--trs`, `--astro`, `--qel`, `--strict-order`

See [`core/pulse_kernel.c`](../core/pulse_kernel.c) and the runtime sources for option parsing and defaults.

## Diagnostics & reports

- Phoenix rebirth self-run: make rebirth
- Phoenix trace report: make report
- Metabolic report: make report-metabolic

Plots use the optional Matplotlib dependency. Diagnostic report targets are
separate from validation; a missing trace or plot is not a passed test.
- Long substrate diagnostic (60 cycles, writes logs & summary): make long-run-diagnostics


## Research and contracts

- [Conceptual L0–L30 map](LIMINAL_LAYER_MAP.md)
- [Compact layer index](layers-overview.md)
- [Kernel runtime contract](KERNEL_RUNTIME_CONTRACT.md)
- [Kernel refactor protocol](KERNEL_REFACTOR_PROTOCOL.md)
- [Historical technical audit](deep_audit_2026-04-24.md)
