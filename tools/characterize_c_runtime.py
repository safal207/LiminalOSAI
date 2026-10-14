#!/usr/bin/env python3
"""Compare real C binaries under fixed clocks, random seeds and no-op sleeps.

This Linux-only characterization records exact stdout, stderr and generated file
hashes. It does not measure production latency: time and sleep are controlled to
make state transitions and output formatting reproducible. The binaries remain
unmodified; a temporary shared library controls only the process environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROCESS_TIMEOUT_SECONDS = 20.0
PROCESS_REAP_TIMEOUT_SECONDS = 1.0

SHIM = r"""
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

__attribute__((constructor)) static void seed_runtime(void)
{
    const char *seed = getenv("LIMINAL_CHARACTERIZATION_SEED");
    srand(seed ? (unsigned int)strtoul(seed, NULL, 10) : 42U);
}

time_t time(time_t *out)
{
    const time_t fixed = 1760000000;
    if (out) { *out = fixed; }
    return fixed;
}

int clock_gettime(clockid_t id, struct timespec *out)
{
    (void)id;
    out->tv_sec = 1760000000;
    out->tv_nsec = 0;
    return 0;
}

int gettimeofday(struct timeval *out, void *zone)
{
    (void)zone;
    out->tv_sec = 1760000000;
    out->tv_usec = 0;
    return 0;
}

int nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)request;
    if (remaining) { remaining->tv_sec = 0; remaining->tv_nsec = 0; }
    return 0;
}

unsigned int sleep(unsigned int seconds)
{
    (void)seconds;
    return 0U;
}
"""

CASES: dict[str, tuple[str, ...]] = {
    "dry-default": ("--dry-run",),
    "dry-strict": ("--dry-run", "--strict-order", "--dream"),
    "bounds": (
        "--dry-run", "--amp-min=1.4", "--amp-max=0.7",
        "--tempo-min=1.3", "--tempo-max=0.85", "--trs-alpha=9",
    ),
    "cycle-default": ("--limit=4", "--trace"),
    "cycle-phase-positive": (
        "--limit=8", "--trace", "--sync", "--sync-trace",
        "--phase-shift=awareness:390.25",
    ),
    "cycle-phase-negative": (
        "--limit=8", "--trace", "--sync", "--sync-trace",
        "--phase-shift=awareness:-390.25",
    ),
    "cycle-modules": (
        "--limit=16", "--trace", "--introspect", "--harmony", "--dream",
        "--anticipation2", "--affinity", "--allow-align=0.9", "--astro",
        "--astro-trace", "--kiss", "--kiss-warmup=0", "--vse", "--vse-trace",
        "--qel", "--qel-retro=0.7", "--entangle-ctx=0x10", "--trs",
        "--trs-adapt", "--empathic", "--anticipation", "--memory",
    ),
}


def digest(data: bytes) -> dict[str, int | str]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    # The compiler and measured child each own a new session. Kill the group
    # so compiler helpers and descendants cannot keep inherited pipes alive.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    # Avoid Popen's context manager and an unbounded communicate after timeout.
    process.wait(timeout=PROCESS_REAP_TIMEOUT_SECONDS)


def _run_captured(command: list[str], *, cwd: Path | None = None,
                  env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        cwd=cwd, env=env,
    )
    try:
        stdout, stderr = process.communicate(timeout=PROCESS_TIMEOUT_SECONDS)
    except BaseException:
        _kill_and_reap(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _compile_shim(command: list[str]) -> None:
    result = _run_captured(command)
    result.check_returncode()


def _wait4_bounded(process: subprocess.Popen[bytes]) -> resource.struct_rusage:
    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    try:
        while True:
            # wait4 retains CPU and peak RSS for this child only; polling adds
            # a wall-clock deadline without reaping it through Popen.poll().
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                return usage
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, PROCESS_TIMEOUT_SECONDS)
            time.sleep(min(0.001, remaining))
    except BaseException:
        _kill_and_reap(process)
        raise


def capture(binary_directory: Path, compiler: str, repetitions: int = 0,
            measure_cycles: int = 1024) -> dict[str, object]:
    if sys.platform != "linux":
        raise SystemExit("fixed-clock characterization requires Linux LD_PRELOAD")
    binaries = {
        name: (binary_directory / name).resolve(strict=True)
        for name in ("pulse_kernel", "liminal_core")
    }
    with tempfile.TemporaryDirectory(prefix="liminal-characterization-") as temporary:
        temporary_root = Path(temporary)
        source = temporary_root / "clock.c"
        library = temporary_root / "clock.so"
        source.write_text(SHIM, encoding="utf-8")
        _compile_shim(
            [compiler, "-std=c11", "-shared", "-fPIC", str(source), "-o", str(library)],
        )
        records = []
        measurements = []
        for name, binary in binaries.items():
            for case, arguments in CASES.items():
                for seed in (42, 1234, 98765):
                    with tempfile.TemporaryDirectory(dir=temporary_root) as run_directory:
                        run_root = Path(run_directory)
                        (run_root / "logs").mkdir()
                        (run_root / "soil").mkdir()
                        profile = ("--substrate",) if name == "liminal_core" else ()
                        env = os.environ.copy()
                        # Omit inherited runtime overrides and preload libraries.
                        for key in tuple(env):
                            if key.startswith("LIMINAL_") or key in ("LD_PRELOAD", "LD_AUDIT"):
                                del env[key]
                        env.update(
                            LD_PRELOAD=str(library),
                            LIMINAL_CHARACTERIZATION_SEED=str(seed),
                            TZ="UTC", LC_ALL="C",
                        )
                        result = _run_captured(
                            [str(binary), *profile, *arguments], cwd=run_root, env=env,
                        )
                        if result.returncode != 0:
                            raise RuntimeError(
                                f"{name}/{case}/{seed} exited {result.returncode}: "
                                f"{result.stderr.decode(errors='replace')}"
                            )
                        files = {
                            path.relative_to(run_root).as_posix(): digest(path.read_bytes())
                            for path in sorted(run_root.rglob("*")) if path.is_file()
                        }
                        records.append({
                            "binary": name, "case": case, "seed": seed,
                            "arguments": [*profile, *arguments],
                            "exit_code": result.returncode,
                            "stdout": digest(result.stdout), "stderr": digest(result.stderr),
                            "files": files,
                        })
            for sample in range(repetitions):
                with tempfile.TemporaryDirectory(dir=temporary_root) as run_directory:
                    run_root = Path(run_directory)
                    (run_root / "logs").mkdir()
                    (run_root / "soil").mkdir()
                    env = os.environ.copy()
                    for key in tuple(env):
                        if key.startswith("LIMINAL_") or key in ("LD_PRELOAD", "LD_AUDIT"):
                            del env[key]
                    env.update(LD_PRELOAD=str(library), LIMINAL_CHARACTERIZATION_SEED="42",
                               TZ="UTC", LC_ALL="C")
                    profile = ("--substrate",) if name == "liminal_core" else ()
                    arguments = (f"--limit={measure_cycles}", *CASES["cycle-modules"][1:])
                    start = time.perf_counter()
                    process = subprocess.Popen(
                        [str(binary), *profile, *arguments], cwd=run_root, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    usage = _wait4_bounded(process)
                    wall_seconds = time.perf_counter() - start
                    if process.returncode != 0:
                        raise RuntimeError(f"measurement {name}/{sample} exited {process.returncode}")
                    measurements.append({
                        "binary": name, "sample": sample, "cycles": measure_cycles,
                        "user_seconds": usage.ru_utime,
                        "system_seconds": usage.ru_stime,
                        "wall_seconds": wall_seconds,
                        "peak_rss_kib": usage.ru_maxrss,
                    })
        return {
            "profile": "linux-fixed-clock-seeded-no-sleep-v1",
            "binaries": {name: digest(path.read_bytes()) for name, path in binaries.items()},
            "cases": records,
            "measurements": measurements,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--measure-repetitions", type=int, default=0)
    parser.add_argument("--measure-cycles", type=int, default=1024)
    args = parser.parse_args()
    if args.measure_repetitions < 0:
        parser.error("--measure-repetitions must be nonnegative")
    if args.measure_cycles < 1:
        parser.error("--measure-cycles must be positive")
    if args.compare and args.output.resolve() == args.compare.resolve():
        parser.error("--output must differ from --compare to preserve the baseline")
    # Read the baseline before executing or writing the candidate. A caller
    # cannot turn a changed result into a match by overwriting its evidence.
    baseline = json.loads(args.compare.read_text(encoding="utf-8")) if args.compare else None
    result = capture(args.binary_dir.resolve(strict=True), args.cc,
                     args.measure_repetitions, args.measure_cycles)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if baseline is not None:
        if result["profile"] != baseline["profile"] or result["cases"] != baseline["cases"]:
            print("runtime output or generated files changed", file=sys.stderr)
            return 1
        print(f"{len(result['cases'])} exact runtime cases match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
