#!/usr/bin/env python3
"""Run discovered or selected unittest suites with explicit completeness checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests", nargs="*", help="optional module names or test paths")
    parser.add_argument("--start-directory", type=Path, default=ROOT / "tests")
    parser.add_argument("--top-level-directory", type=Path)
    args = parser.parse_args(arguments)
    sys.path.insert(0, str(ROOT))
    loader = unittest.TestLoader()
    try:
        if args.tests:
            names = [name.removesuffix(".py").replace("/", ".") for name in args.tests]
            suite = loader.loadTestsFromNames(names)
        else:
            suite = loader.discover(
                str(args.start_directory), pattern="test_*.py",
                top_level_dir=str(args.top_level_directory) if args.top_level_directory else None,
            )
    except (ImportError, OSError) as exc:
        print(f"test discovery failed: {exc}", file=sys.stderr)
        return 1
    discovered = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    complete = discovered > 0 and result.testsRun == discovered
    passed = complete and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    summary = {
        "schema": "liminal-python-validation-v1",
        "status": "PASS" if passed else "FAIL",
        "discovered": discovered,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
