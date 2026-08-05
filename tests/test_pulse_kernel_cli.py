from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "pulse_kernel"
ARROW = "→"


class PulseKernelCliCharacterizationTests(unittest.TestCase):
    """Black-box contract tests for the production pulse-kernel entrypoint."""

    @classmethod
    def setUpClass(cls) -> None:
        if not BINARY.is_file():
            raise AssertionError(
                f"production binary is missing: {BINARY}; run `make` before this suite"
            )

    def run_kernel(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BINARY), "--dry-run", *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> list[str]:
        self.assertEqual(
            result.returncode,
            0,
            f"stderr:\n{result.stderr}\nstdout:\n{result.stdout}",
        )
        self.assertEqual(result.stderr, "")
        return [line.rstrip() for line in result.stdout.splitlines() if line.strip()]

    def assert_rejected(
        self,
        result: subprocess.CompletedProcess[str],
        argument: str,
    ) -> None:
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid numeric value", result.stderr)
        self.assertIn(argument, result.stderr)

    def assert_unavailable(
        self,
        result: subprocess.CompletedProcess[str],
        argument: str,
    ) -> None:
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("option is unavailable", result.stderr)
        self.assertIn("production parser migration", result.stderr)
        self.assertIn(argument, result.stderr)

    def line_with_prefix(self, lines: list[str], prefix: str) -> str:
        matches = [line for line in lines if line.startswith(prefix)]
        self.assertEqual(matches, matches[:1], f"duplicate {prefix!r} lines: {matches}")
        self.assertEqual(len(matches), 1, f"missing {prefix!r} line in {lines}")
        return matches[0]

    def test_default_dry_run_contract(self) -> None:
        lines = self.assert_success(self.run_kernel())
        self.assertEqual(
            lines,
            [
                "trs config: enabled=no alpha=0.300 warmup=5",
                "trs adapt: enabled=no alpha-range=[0.100, 0.600] "
                "target-delta=0.0150 kp=0.400 ki=0.050 kd=0.100",
                "liminal_core dry run",
                f"pipeline: awareness{ARROW}gate",
                "mirror clamps: amp=[0.50, 1.20] tempo=[0.80, 1.20]",
            ],
        )

    def test_optional_modules_preserve_canonical_relative_order(self) -> None:
        lines = self.assert_success(
            self.run_kernel("--mirror", "--introspect", "--dream")
        )
        self.assertEqual(
            self.line_with_prefix(lines, "pipeline: "),
            f"pipeline: awareness{ARROW}mirror{ARROW}introspect"
            f"{ARROW}harmony{ARROW}gate{ARROW}dream",
        )

    def test_strict_order_currently_enables_every_non_dream_stage(self) -> None:
        lines = self.assert_success(self.run_kernel("--strict-order"))
        pipeline = self.line_with_prefix(lines, "pipeline: ")
        self.assertEqual(
            pipeline,
            f"pipeline: ant2{ARROW}awareness{ARROW}collective{ARROW}affinity"
            f"{ARROW}mirror{ARROW}introspect{ARROW}harmony{ARROW}astro"
            f"{ARROW}kiss{ARROW}gate{ARROW}vse",
        )
        self.assertNotIn(f"{ARROW}dream", pipeline)

    def test_explicit_mirror_bounds_are_reported(self) -> None:
        lines = self.assert_success(
            self.run_kernel(
                "--amp-min=0.60",
                "--amp-max=1.10",
                "--tempo-min=0.90",
                "--tempo-max=1.05",
            )
        )
        self.assertEqual(
            self.line_with_prefix(lines, "mirror clamps: "),
            "mirror clamps: amp=[0.60, 1.10] tempo=[0.90, 1.05]",
        )

    def test_reversed_mirror_bounds_are_normalized(self) -> None:
        lines = self.assert_success(
            self.run_kernel(
                "--amp-min=1.40",
                "--amp-max=0.70",
                "--tempo-min=1.30",
                "--tempo-max=0.85",
            )
        )
        self.assertEqual(
            self.line_with_prefix(lines, "mirror clamps: "),
            "mirror clamps: amp=[0.70, 1.40] tempo=[0.85, 1.30]",
        )

    def test_non_finite_mirror_value_is_rejected_before_runtime_side_effects(self) -> None:
        argument = "--amp-min=nan"
        self.assert_rejected(self.run_kernel(argument), argument)

    def test_negative_limit_is_rejected(self) -> None:
        argument = "--limit=-1"
        self.assert_rejected(self.run_kernel(argument), argument)

    def test_overflowing_limit_is_rejected(self) -> None:
        argument = "--limit=18446744073709551616"
        self.assert_rejected(self.run_kernel(argument), argument)

    def test_trailing_numeric_garbage_is_rejected(self) -> None:
        for argument in (
            "--limit=2cycles",
            "--scan-interval=5x",
            "--target=0.5garbage",
            "--gate-open=0.7oops",
            "--trs-alpha=0.3tail",
        ):
            with self.subTest(argument=argument):
                self.assert_rejected(self.run_kernel(argument), argument)

    def test_non_finite_core_float_is_rejected(self) -> None:
        for argument in ("--target=nan", "--group-target=inf", "--gate-bias=-inf"):
            with self.subTest(argument=argument):
                self.assert_rejected(self.run_kernel(argument), argument)

    def test_scan_interval_must_be_positive_u32(self) -> None:
        for argument in ("--scan-interval=0", "--scan-interval=4294967296"):
            with self.subTest(argument=argument):
                self.assert_rejected(self.run_kernel(argument), argument)

    def test_known_silent_noop_options_are_explicitly_unavailable(self) -> None:
        for argument in (
            "--cm-snapshot-interval=7",
            "--phase-shift-awarenessdeg=90",
        ):
            with self.subTest(argument=argument):
                self.assert_unavailable(self.run_kernel(argument), argument)

    def test_valid_zero_limit_preserves_dry_run_contract(self) -> None:
        baseline = self.assert_success(self.run_kernel())
        zero_limit = self.assert_success(self.run_kernel("--limit=0"))
        self.assertEqual(zero_limit, baseline)

    def test_unknown_option_is_currently_ignored(self) -> None:
        baseline = self.assert_success(self.run_kernel())
        unknown = self.assert_success(self.run_kernel("--definitely-unknown-option"))
        self.assertEqual(unknown, baseline)

    def test_repeated_flags_do_not_duplicate_pipeline_stages(self) -> None:
        lines = self.assert_success(
            self.run_kernel("--mirror", "--mirror", "--dream", "--dream")
        )
        pipeline = self.line_with_prefix(lines, "pipeline: ")
        self.assertEqual(pipeline.count("mirror"), 1)
        self.assertEqual(pipeline.count("dream"), 1)


if __name__ == "__main__":
    unittest.main()
