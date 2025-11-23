# Phoenix Layer — Regenerative Core

The phoenix layer keeps a run from collapsing by watching drift/health, snapshotting a seed, and relaunching the core with gentle mutations.

## Overview
- Detect instability via health echo and coherence drift.
- Snapshot a seed {PID, delay, coherence, awareness} into Memory Soil.
- Rebirth: stop the failing run, reload the last seed, apply small mutations, and restart pulse_kernel.
- Log divergence between the prior and reborn run for later tuning.

## Components

### Seed Registry
- Captures PID, coherence, drift, awareness and delay during stable windows.
- Writes seeds to Memory Soil for reuse.
- Keeps a short ring so the most recent stable seed is always available.

### Phoenix Watcher
- Reads health echo; if collapse is detected, flags the rebirth path.
- Emits lightweight trace lines for diagnostics.
- Can be toggled with the phoenix CLI switches.

### Adaptive Rebirth
- Loads the last seed, applies controlled mutations, and reinitializes the kernel.
- Replays affinity consent gates and warms up before resuming.
- Records divergence into `phoenix_trace`.

### CLI controls
```bash
make clean && make
./build/pulse_kernel --limit=30 \
  --trace --symbols --reflect \
  --phoenix --mutate --rebirth
```

## Flow (simplified)
Stable ? Seed registry snapshot ? Watcher detects collapse ? Rebirth reloads+mutates ? Divergence logged ? New stable run.

## Manifest
Configuration lives in `docs/phoenix.yaml`.
