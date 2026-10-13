from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "build" / "liminal_core"


class LiminalSubstrateCliCharacterizationTests(unittest.TestCase):
    """Exercise the actual substrate entrypoint before initialization and dispatch."""

    @classmethod
    def setUpClass(cls) -> None:
        if not BINARY.is_file():
            raise AssertionError(f"production binary is missing: {BINARY}; run `make` first")

    def run_substrate(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="liminal-substrate-cli-") as directory:
            result = subprocess.run(
                [str(BINARY), "--dry-run", *arguments],
                cwd=directory,
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 2:
                self.assertEqual(list(Path(directory).iterdir()), [])
            return result

    def successful_lines(self, *arguments: str) -> list[str]:
        result = self.run_substrate(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout.splitlines()

    def assert_rejected(self, argument: str) -> None:
        result = self.run_substrate("--qel", "--introspect", argument)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("liminal_core: invalid numeric value", result.stderr)
        self.assertIn(argument, result.stderr)

    def test_default_output_is_preserved(self) -> None:
        self.assertEqual(
            self.successful_lines(),
            [
                "trs config: enabled=no alpha=0.300 warmup=5",
                "trs adapt: enabled=no alpha-range=[0.100, 0.600] "
                "target-delta=0.0150 kp=0.400 ki=0.050 kd=0.100",
                "erb config: enabled=no pre=24 post=32 spike=0.060",
                "liminal_core dry run",
                "pipeline: awareness→gate",
                "mirror clamps: amp=[0.50, 1.20] tempo=[0.80, 1.20]",
            ],
        )

    def test_optional_stage_dependencies_and_duplicates_are_preserved(self) -> None:
        lines = self.successful_lines("--introspect", "--dream", "--introspect", "--dream")
        self.assertIn("pipeline: awareness→introspect→harmony→gate→dream", lines)

    def test_bounds_normalization_and_clamping_are_preserved(self) -> None:
        lines = self.successful_lines(
            "--amp-min=1.4", "--amp-max=0.7", "--tempo-min=1.3", "--tempo-max=0.85",
            "--trs-alpha=9", "--trs-warmup=-5",
        )
        self.assertIn("mirror clamps: amp=[0.70, 1.40] tempo=[0.85, 1.30]", lines)
        self.assertIn("trs config: enabled=no alpha=0.800 warmup=0", lines)

    def test_unknown_options_and_zero_limit_are_preserved(self) -> None:
        baseline = self.successful_lines()
        self.assertEqual(self.successful_lines("--unknown-option"), baseline)
        self.assertEqual(self.successful_lines("--limit=0"), baseline)

    def test_named_allowance_and_hex_context_remain_valid(self) -> None:
        for argument in ("--allow=now", "--allow=NOW", "--allow=0.25", "--entangle-ctx=0x10"):
            with self.subTest(argument=argument):
                self.successful_lines(argument)

    def test_malformed_scalar_floats_are_rejected(self) -> None:
        prefixes = (
            "erb-spike", "erb-replay-speed", "ant2-gain", "allow-align",
            "amp-min", "amp-max", "tempo-min", "tempo-max", "qel-retro",
            "astro-rate", "astro-tone", "astro-mem", "kiss-alpha", "gate-open",
            "gate-close", "gate-hyst", "gate-bias", "flow-alpha", "flow-gamma",
            "vse-temp", "vse-intent", "vse-importance", "vse-allow", "vse-lambda-p",
            "vse-lambda-x", "allow-hold", "allow", "trs-alpha", "trs-alpha-min",
            "trs-alpha-max", "trs-target-delta", "trs-kp", "trs-ki", "trs-kd",
            "dream-rate", "dream-decay", "bridge-plasticity", "bridge-retention",
            "bridge-recovery", "empathy-gain", "recognition-threshold",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assert_rejected(f"--{prefix}=0.5garbage")

    def test_nonfinite_empty_and_overflowing_floats_are_rejected(self) -> None:
        for argument in (
            "--gate-open=nan", "--qel-retro=inf", "--amp-min=-inf",
            "--trs-alpha=1e999", "--flow-alpha=", "--gate-bias=garbage",
        ):
            with self.subTest(argument=argument):
                self.assert_rejected(argument)

    def test_malformed_integer_arguments_are_rejected(self) -> None:
        prefixes = (
            "limit", "lip-port", "lip-interval", "erb-pre", "erb-post",
            "tune-trials", "tune-refine", "tune-max-runs", "tune-seed", "tune-count",
            "kiss-warmup", "kiss-refrac", "gate-warmup", "gate-refrac", "trs-warmup",
            "dream-cycles",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assert_rejected(f"--{prefix}=2garbage")

    def test_unsigned_and_overflow_boundaries_are_rejected(self) -> None:
        for argument in (
            "--limit=-1", "--limit= -1", "--lip-port=\t-1", "--lip-interval=-1",
            "--limit=18446744073709551616", "--tune-seed=9223372036854775808",
            "--erb-replay=idx:1tail", "--tune-source=idx:-1",
            "--entangle-ctx=-1", "--entangle-ctx=0x10tail",
        ):
            with self.subTest(argument=argument):
                self.assert_rejected(argument)


if __name__ == "__main__":
    unittest.main()
