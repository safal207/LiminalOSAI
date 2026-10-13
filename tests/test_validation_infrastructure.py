from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "check_forbidden.py"
RUNNER = ROOT / "scripts" / "run_python_tests.py"


class ForbiddenContentScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def scan(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCANNER), "--", *arguments],
            capture_output=True, text=True, env=env, check=False, timeout=10,
        )

    def test_clean_input_passes(self) -> None:
        path = self.directory / "safe.txt"
        path.write_text("ordinary fixture\n")
        self.assertEqual(self.scan("-nE", "forbidden", str(path)).returncode, 0)

    def test_match_fails_without_exporting_matching_material(self) -> None:
        path = self.directory / "fixture.txt"
        marker = "synthetic-prohibited-fixture-marker"
        path.write_text(marker + "\n")
        result = self.scan("-nE", marker, str(path))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_missing_input_is_scanner_error(self) -> None:
        self.assertEqual(self.scan("-nE", "forbidden", str(self.directory / "missing")).returncode, 2)

    def test_implicit_standard_input_cannot_satisfy_source_scan(self) -> None:
        self.assertEqual(self.scan("-E", "forbidden").returncode, 2)
        self.assertEqual(self.scan("-E", "forbidden", "-").returncode, 2)

    def test_invalid_expression_is_scanner_error(self) -> None:
        path = self.directory / "safe.txt"
        path.write_text("ordinary\n")
        self.assertEqual(self.scan("-E", "[", str(path)).returncode, 2)

    def test_missing_executable_is_scanner_error(self) -> None:
        env = dict(os.environ, PATH=str(self.directory))
        self.assertEqual(self.scan("-E", "forbidden", str(self.directory), env=env).returncode, 2)

    def test_first_match_cannot_be_masked_by_later_clean_scan(self) -> None:
        path = self.directory / "fixture.txt"
        path.write_text("forbidden\n")
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c",
             '"$1" "$2" -- -E forbidden "$3"\n"$1" "$2" -- -E absent "$3"',
             "strict-scanner-test", sys.executable, str(SCANNER), str(path)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 1)


class StrictPythonValidationTests(unittest.TestCase):
    def run_fixture(self, source: str | None) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        with tempfile.TemporaryDirectory() as directory:
            if source is not None:
                (Path(directory) / "test_fixture.py").write_text(source)
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--start-directory", directory,
                 ],
                capture_output=True, text=True, check=False, timeout=10,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            )
        return result, json.loads(result.stdout)

    def test_real_assertion_passes_and_reports_count(self) -> None:
        result, summary = self.run_fixture(
            "import unittest\nclass Fixture(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(2 + 2, 4)\n"
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["discovered"], summary["tests_run"]), ("PASS", 1, 1))

    def test_zero_discovery_fails(self) -> None:
        result, summary = self.run_fixture(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["tests_run"]), ("FAIL", 0))

    def test_skipped_assertion_fails_validation(self) -> None:
        result, summary = self.run_fixture(
            "import unittest\nclass Fixture(unittest.TestCase):\n"
            "    @unittest.skip('fixture dependency absent')\n"
            "    def test_value(self): self.fail('never exercised')\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["skipped"]), ("FAIL", 1))

    def test_expected_failure_cannot_satisfy_validation(self) -> None:
        result, summary = self.run_fixture(
            "import unittest\nclass Fixture(unittest.TestCase):\n"
            "    @unittest.expectedFailure\n"
            "    def test_value(self): self.fail('expected fixture failure')\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["expected_failures"]), ("FAIL", 1))

    def test_import_failure_fails_validation(self) -> None:
        result, summary = self.run_fixture("raise ImportError('synthetic fixture import error')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["errors"]), ("FAIL", 1))

    def test_failed_assertion_fails_validation(self) -> None:
        result, summary = self.run_fixture(
            "import unittest\nclass Fixture(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(2 + 2, 5)\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((summary["status"], summary["failures"]), ("FAIL", 1))
