from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "characterize_c_runtime.py"
SPEC = importlib.util.spec_from_file_location("liminal_c_characterization", TOOL)
assert SPEC is not None and SPEC.loader is not None
CHARACTERIZATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHARACTERIZATION)


class CharacterizationEvidenceTests(unittest.TestCase):
    def test_same_output_path_is_rejected_without_overwriting_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "before.json"
            baseline.write_text("preserved baseline\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(TOOL), "--binary-dir", directory,
                 "--output", str(baseline), "--compare", str(baseline)],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("preserve the baseline", result.stderr)
            self.assertEqual(baseline.read_text(encoding="utf-8"), "preserved baseline\n")

    def test_changed_trace_is_rejected_while_binary_rebuild_alone_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            baseline = {"profile": "test-profile", "cases": [{"stdout": "original"}],
                        "binaries": {"sha256": "before"}, "measurements": []}
            before.write_text(json.dumps(baseline), encoding="utf-8")
            original_bytes = before.read_bytes()
            arguments = [str(TOOL), "--binary-dir", directory,
                         "--output", str(after), "--compare", str(before)]
            candidate = {**baseline, "binaries": {"sha256": "rebuilt"}}
            for observed, expected in (
                (candidate, 0),
                ({**candidate, "cases": [{"stdout": "changed"}]}, 1),
            ):
                with self.subTest(expected=expected), patch.object(
                    CHARACTERIZATION, "capture", return_value=observed
                ), patch.object(sys, "argv", arguments), contextlib.redirect_stdout(
                    io.StringIO()
                ), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(CHARACTERIZATION.main(), expected)
                self.assertEqual(before.read_bytes(), original_bytes)
                self.assertEqual(json.loads(after.read_text(encoding="utf-8")), observed)


if __name__ == "__main__":
    unittest.main()
