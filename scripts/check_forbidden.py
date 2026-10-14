#!/usr/bin/env python3
"""Run a forbidden-content grep scan, accepting only the clean exit status.

Usage: python3 scripts/check_forbidden.py -- [grep flags] pattern paths...
The original grep pattern and operands are preserved. Matches and scanner
diagnostics are suppressed so this security check does not export their content.
"""

from __future__ import annotations

import subprocess
import sys


def main(arguments: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    if not arguments:
        print("forbidden-content scan requires grep arguments", file=sys.stderr)
        return 2
    # These are the options used by repository scanners. Require a pattern and
    # explicit input operands; grep's implicit stdin is not a source scan.
    offset = 0
    for argument in arguments:
        if argument == "--":
            offset += 1
            break
        if argument == "--binary-files=without-match" or argument.startswith("--exclude="):
            offset += 1
        elif argument.startswith("-") and argument != "-":
            if not set(argument[1:]) <= set("RrniEF"):
                print("forbidden-content scan has an unsupported option", file=sys.stderr)
                return 2
            offset += 1
        else:
            break
    if len(arguments) - offset < 2 or "-" in arguments[offset + 1:]:
        print("forbidden-content scan requires a pattern and explicit inputs", file=sys.stderr)
        return 2
    try:
        result = subprocess.run(
            ["grep", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("forbidden-content scanner unavailable or timed out", file=sys.stderr)
        return 2
    if result.returncode == 1:
        return 0
    if result.returncode == 0:
        print("forbidden-content scan detected a prohibited match", file=sys.stderr)
        return 1
    print("forbidden-content scan failed to inspect its inputs", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
