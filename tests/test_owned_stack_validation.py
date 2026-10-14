"""Preparation failure boundaries; these tests do not establish Docker execution."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("owned_stack_preparation", ROOT / "scripts/prepare_owned_stack_validation.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class OwnedStackValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "repo"
        self.root.mkdir()
        self.output = self.directory / "preparation"

    def owned_sources(self):
        (self.root / "sdk/liminal_agent_control").mkdir(parents=True)
        for name in PREPARE.REQUIRED_SOURCES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source placeholder\n")

    def test_checkout_without_owned_sdk_does_not_spawn_or_change_environment(self):
        with patch.object(PREPARE, "command") as command:
            result = PREPARE.prepare(self.root, self.output)
        self.assertEqual(result["status"], "NOT_APPLICABLE")
        self.assertNotIn("PASS", result["status"])
        command.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_incomplete_owned_tree_is_not_treated_as_absent(self):
        (self.root / "sdk/liminal_agent_control").mkdir(parents=True)
        with patch.object(PREPARE, "command") as command:
            with self.assertRaisesRegex(ValueError, "source input missing"):
                PREPARE.prepare(self.root, self.output)
        command.assert_not_called()

    def test_preexisting_capture_directory_and_in_repo_output_are_rejected(self):
        self.owned_sources()
        self.output.mkdir()
        (self.output / "receiver.json").write_text('{"status":"old-capture"}')
        with patch.object(PREPARE, "command") as command:
            with self.assertRaisesRegex(ValueError, "fresh output directory"):
                PREPARE.prepare(self.root, self.output)
            with self.assertRaisesRegex(ValueError, "outside the checkout"):
                PREPARE.prepare(self.root, self.root / "reports")
        command.assert_not_called()

    def test_unavailable_daemon_is_failure_before_venv_or_capture(self):
        self.owned_sources()
        with patch.object(PREPARE, "command", side_effect=["a" * 40, "", FileNotFoundError("docker")]):
            with self.assertRaises(FileNotFoundError):
                PREPARE.prepare(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_dirty_source_cannot_generate_ready_evidence(self):
        self.owned_sources()
        with patch.object(PREPARE, "command", side_effect=["a" * 40, " M changed.py"]):
            with self.assertRaisesRegex(ValueError, "clean source checkout"):
                PREPARE.prepare(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_runtime_exit_zero_without_capture_does_not_advance_to_ready(self):
        self.owned_sources()
        calls = []
        def command(argv, **kwargs):
            args = list(map(str, argv))
            calls.append(args)
            if args[:3] == ["git", "rev-parse", "HEAD"]:
                return "a" * 40
            if args[:2] == ["git", "status"]:
                return ""
            if args[:2] == ["docker", "info"]:
                return "synthetic-daemon"
            if args[:3] == ["docker", "image", "inspect"]:
                return "sha256:" + ("c" * 64 if args[-1].startswith("sha256:") else "b" * 64)
            if args[:2] == ["docker", "build"]:
                Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "c" * 64)
            return None
        with patch.object(PREPARE, "command", side_effect=command):
            with self.assertRaisesRegex(ValueError, "did not produce its required actual capture"):
                PREPARE.prepare(self.root, self.output)
        self.assertFalse((self.output / "preparation.json").exists())
        self.assertTrue(any("tests/test_agent_control_external_agent_receiver_runtime.py" in args for args in calls))
        self.assertFalse(any("-c" in args for args in calls))

    def test_image_tags_and_short_ids_are_rejected(self):
        for value in ("python:latest", "sha256:abcd", "sha256:" + "A" * 64, "x\nsha256:" + "a" * 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREPARE.immutable_image(value)
        self.assertEqual(PREPARE.immutable_image("sha256:" + "a" * 64), "sha256:" + "a" * 64)

    def test_failed_preparation_never_exports_ci_environment(self):
        env = self.directory / "github-env"
        paths = self.directory / "github-path"
        with patch.object(PREPARE, "prepare", side_effect=subprocess.CalledProcessError(1, ["docker", "info"])):
            with patch.object(PREPARE, "export_environment") as export:
                status = PREPARE.main(["--output-directory", str(self.output), "--github-env", str(env), "--github-path", str(paths)])
        self.assertEqual(status, 1)
        export.assert_not_called()
        self.assertFalse(env.exists())
        self.assertFalse(paths.exists())

    def test_multiline_environment_is_rejected_before_any_field_is_written(self):
        env = self.directory / "github-env"
        with self.assertRaises(ValueError):
            PREPARE.export_environment({"SAFE": "value", "UNSAFE": "value\nINJECTED=1"}, "/tmp/venv/bin", github_env=env)
        self.assertFalse(env.exists())

    def test_capture_check_requires_nine_explicit_tests_in_fresh_process(self):
        # Exercise the completeness check itself against an isolated short suite;
        # a missing/renamed capture test cannot become READY_FOR_VALIDATION.
        package = self.directory / "tests"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "test_agent_control_external_agent_receiver_evidence.py").write_text(
            "import unittest\nclass ReceiverCaptureMutationTests(unittest.TestCase):\n"
            "    def test_only_one(self): pass\n")
        capture = self.directory / "capture.json"
        capture.write_text(json.dumps({"synthetic": True}))
        import os
        import sys
        result = subprocess.run([sys.executable, "-c", PREPARE.CAPTURE_CLASS_CHECK], cwd=self.directory,
            env={**os.environ, "PYTHONPATH": str(self.directory), "LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE": str(capture)},
            capture_output=True, text=True, timeout=10, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("all nine", result.stderr)


if __name__ == "__main__":
    unittest.main()
