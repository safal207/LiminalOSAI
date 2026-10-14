from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import select
import signal
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
    def _assert_real_hang_is_bounded(self, *, stage: str) -> None:
        self.assertIn(stage, ("compiler", "measurement", "exact-case"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pids = root / "pids.json"
            hanging_program = """import json, os, subprocess, sys
ready_read, ready_write = os.pipe()
child = subprocess.Popen([sys.executable, '-c', 'import os, sys; read_fd, write_fd = os.pipe(); os.write(int(sys.argv[1]), b"R"); os.read(read_fd, 1)', str(ready_write)], pass_fds=(ready_write,))
os.close(ready_write)
assert os.read(ready_read, 1) == b"R", 'descendant did not reach the blocking fixture'
os.close(ready_read)
with open(os.environ['CHARACTERIZATION_TEST_PIDS'], 'w') as stream:
    json.dump([os.getpid(), child.pid], stream)
read_fd, write_fd = os.pipe()
os.read(read_fd, 1)
"""
            compiler = root / "hanging-compiler"
            compiler.write_text(f"#!{sys.executable}\n{hanging_program}", encoding="utf-8")
            compiler.chmod(0o700)
            for name in ("pulse_kernel", "liminal_core"):
                binary = root / name
                binary.write_text(
                    f"#!{sys.executable}\nimport sys\n"
                    f"if {stage == 'exact-case'!r} or '--limit=73' in sys.argv:\n"
                    + "\n".join("    " + line for line in hanging_program.splitlines())
                    + "\nelse:\n    print('fixed trace')\n", encoding="utf-8",
                )
                binary.chmod(0o700)
            harness = (
                "import importlib.util, os, pathlib, select, subprocess, sys\n"
                f"spec = importlib.util.spec_from_file_location('characterization', {str(TOOL)!r})\n"
                "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
                "module.PROCESS_TIMEOUT_SECONDS = 0.5\n"
                "module.CASES = {'cycle-modules': ('--limit=4', '--trace')}\n"
                + (
                    # Also shorten the old hard-coded run timeout so the
                    # negative control reaches its actual descendant cleanup.
                    "original_run = subprocess.run\n"
                    "def shortened_case_run(*args, **kwargs):\n"
                    "    kwargs['timeout'] = module.PROCESS_TIMEOUT_SECONDS\n"
                    "    return original_run(*args, **kwargs)\n"
                    "module.subprocess.run = shortened_case_run\n"
                    if stage == "exact-case" else ""
                )
                + "try:\n"
                f"    module.capture(pathlib.Path({str(root)!r}), "
                f"{str(compiler) if stage == 'compiler' else 'gcc'!r}, "
                f"repetitions={1 if stage == 'measurement' else 0}, measure_cycles=73)\n"
                "except subprocess.TimeoutExpired:\n"
                "    import json\n"
                f"    child_pids = json.loads(pathlib.Path({str(pids)!r}).read_text())\n"
                "    try:\n"
                "        os.kill(child_pids[0], 0)\n"
                "    except ProcessLookupError:\n"
                "        pass\n"
                "    else:\n"
                "        raise AssertionError('direct child was not reaped')\n"
                "    try:\n"
                "        descriptor = os.pidfd_open(child_pids[1])\n"
                "    except ProcessLookupError:\n"
                "        pass\n"
                "    else:\n"
                "        try:\n"
                "            assert select.select([descriptor], [], [], 1)[0], 'timed-out descendant is still running before harness exit'\n"
                "        finally:\n"
                "            os.close(descriptor)\n"
                "    print('bounded timeout')\n"
                "else:\n"
                "    raise AssertionError('hanging child unexpectedly completed')\n"
            )
            environment = os.environ.copy()
            environment["CHARACTERIZATION_TEST_PIDS"] = str(pids)
            process = subprocess.Popen(
                [sys.executable, "-c", harness], env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            )
            try:
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    self.fail("characterization hung beyond its child deadline")
                self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
                self.assertEqual(stdout, b"bounded timeout\n")
                child_pids = json.loads(pids.read_text(encoding="utf-8"))
                with self.assertRaises(ProcessLookupError, msg="direct child was not reaped"):
                    os.kill(child_pids[0], 0)
                for pid in child_pids:
                    try:
                        descriptor = os.pidfd_open(pid)
                    except ProcessLookupError:
                        continue
                    try:
                        # A readable pidfd denotes exit, including an adopted
                        # zombie, without depending on the mounted /proc view.
                        self.assertTrue(select.select([descriptor], [], [], 1)[0],
                                        f"timed-out descendant {pid} is still running")
                    finally:
                        os.close(descriptor)
            finally:
                # The outer harness also bounds the unfixed implementation, and
                # cleans both shared and newly separated child process groups.
                if pids.exists():
                    for pid in json.loads(pids.read_text(encoding="utf-8")):
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=2)

    def test_hanging_shim_compiler_and_descendant_are_terminated(self) -> None:
        self._assert_real_hang_is_bounded(stage="compiler")

    def test_hanging_measurement_and_descendant_are_terminated(self) -> None:
        self._assert_real_hang_is_bounded(stage="measurement")

    def test_hanging_exact_case_and_descendant_are_terminated(self) -> None:
        self._assert_real_hang_is_bounded(stage="exact-case")

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
