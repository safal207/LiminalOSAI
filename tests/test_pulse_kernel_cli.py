from __future__ import annotations

import json
import subprocess
import tempfile
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

    def run_kernel(self, *arguments: str, dry_run: bool = True, timeout: float = 10) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="pulse-kernel-cli-") as directory:
            result = subprocess.run(
                [str(BINARY), *(["--dry-run"] if dry_run else []), *arguments],
                cwd=directory,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            if result.returncode == 2:
                self.assertEqual(list(Path(directory).iterdir()), [])
            return result

    def assert_composite_rejected(self, argument: str) -> None:
        result = self.run_kernel(
            "--limit=1", "--qel", "--introspect", "--kiss", "--astro-trace",
            argument, dry_run=False, timeout=2,
        )
        self.assert_rejected(result, argument)

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

    def test_every_recognized_scalar_rejects_numeric_suffix_before_initialization(self) -> None:
        # Inventory of actual scalar branches, excluding the explicitly
        # unavailable cm-snapshot option and separately tested composites.
        options = (
            "allow-align", "allow-hold", "allow", "amp-max", "amp-min", "ant2-gain",
            "astro-mem", "astro-rate", "astro-tone", "council-threshold", "dream-threshold",
            "empathy-gain", "entangle-ctx", "gate-bias", "gate-close", "gate-hyst", "gate-open",
            "gate-refrac", "gate-warmup", "group-target", "kiss-alpha", "kiss-refrac", "kiss-warmup",
            "limit", "mirror-soft", "phases", "qel-retro", "recognition-threshold", "resonance-gain",
            "scan-interval", "target", "tempo-max", "tempo-min", "trs-alpha-max", "trs-alpha-min",
            "trs-alpha", "trs-kd", "trs-ki", "trs-kp", "trs-target-delta", "trs-warmup", "vse-allow",
            "vse-importance", "vse-intent", "vse-lambda-p", "vse-lambda-x", "vse-temp",
        )
        for option in options:
            with self.subTest(option=option):
                self.assert_composite_rejected(f"--{option}=2garbage")

    def test_newly_shared_float_scalars_reject_empty_nonfinite_and_overflow(self) -> None:
        for option in ("allow", "empathy-gain", "recognition-threshold"):
            for value in ("", "nan", "inf", "-inf", "1e999", "1e-999", "nowjunk"):
                with self.subTest(option=option, value=value):
                    self.assert_composite_rejected(f"--{option}={value}")

    def test_context_rejects_malformed_negative_and_uint32_overflow(self) -> None:
        for value in ("", "nan", "inf", "1e999", "1.5", "-1", " -1", "0x10tail",
                      "4294967296", "0x100000000", "040000000000", "18446744073709551616"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--entangle-ctx={value}")

    def test_named_allowance_and_representable_contexts_remain_valid(self) -> None:
        baseline = self.assert_success(self.run_kernel("--vse"))
        for value in ("now", "NOW", "nOw", "0.25", "-2"):
            with self.subTest(value=value):
                self.assertEqual(self.assert_success(self.run_kernel(f"--allow={value}")), baseline)
        for value in ("0", "0x10", "4294967295", "0xffffffff", "037777777777", "+0xffffffff"):
            with self.subTest(value=value):
                self.assert_success(self.run_kernel(f"--entangle-ctx={value}"))

    def test_hex_uint32_context_boundary_is_recorded_without_narrowing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulse-context-control-") as directory:
            (Path(directory) / "logs").mkdir()
            result = subprocess.run(
                [str(BINARY), "--limit=1", "--qel", "--introspect", "--entangle-ctx=0xffffffff"],
                cwd=directory, capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (Path(directory) / "logs" / "qel_raw.jsonl").read_text().splitlines()]
            self.assertTrue(rows)
            self.assertTrue(all(row["ctx"] == 4294967295 for row in rows))

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

    def test_malformed_keyed_numeric_lists_reject_before_initialization(self) -> None:
        for option, key in (("affinity-cfg", "care"), ("kiss-thr", "trust")):
            for value in ("", ",,,", key, f"{key}:", ":0.5", f"{key}:0.5junk",
                          f"{key}:nan", f"{key}:inf", f"{key}:1e999", f"{key}:1e-999",
                          f"{key}:0.5:0.7", f"{key}:0.5,malformed"):
                with self.subTest(option=option, value=value):
                    self.assert_composite_rejected(f"--{option}={value}")

    def test_keyed_parser_buffer_boundary_is_explicit(self) -> None:
        for option, key in (("affinity-cfg", "care"), ("kiss-thr", "trust")):
            valid = key + ":" + "0" * (126 - len(key) - 1) + "1"
            self.assertEqual(len(valid), 127)
            with self.subTest(option=option):
                self.assert_success(self.run_kernel(f"--{option}={valid}"))
                self.assert_composite_rejected(f"--{option}={valid},ignored:0.5junk")

    def test_vitality_composite_rejects_bad_components_before_initialization(self) -> None:
        for value in ("", "nan", "inf", "1e999", "0.2junk", ":0.5", "0.2:", "0.2,",
                      "0.2:bad", "0.2:nan", "0.2:1e999", "0.2:0.8junk", "0.2:0.8:1"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--vitality-threshold={value}")

    def test_phase_composite_rejects_bad_degrees_before_initialization(self) -> None:
        for value in ("", "awareness", ":30", "awareness:", "awareness:inf", "awareness:nan",
                      "awareness:1e999", "awareness:30junk", "awareness:30:40", "x" * 32 + ":30"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--phase-shift={value}")

    def test_valid_composite_arity_aliases_duplicates_and_order_remain_compatible(self) -> None:
        baseline = self.assert_success(self.run_kernel("--strict-order"))
        for argument in (
            "--affinity-cfg=,care:-2,,respect:3,care:0.5,presence:0.25,ignored:0.2,",
            "--kiss-thr=trust:2,tr:0.25, presence:0.5,harm:0.75,harmony:0.8",
            "--kiss-thr= tr: +0.25 ,presence:0.5 ,harmony:0.8 ",
            "--affinity-cfg=care: +0.25 ,respect:0.5,presence:0.75 ",
            "--vitality-threshold=0.2", "--vitality-threshold=-1:2",
            "--vitality-threshold=+0.2: 0.8 ",
            "--vitality-threshold=0.8,0.2", "--phase-shift=awareness:-390.25",
            "--phase-shift=awareness:720.25", "--phase-shift=ignored:30",
        ):
            with self.subTest(argument=argument):
                self.assertEqual(self.assert_success(self.run_kernel("--strict-order", argument)), baseline)

    def test_huge_finite_phase_wraps_without_looping(self) -> None:
        baseline = self.assert_success(self.run_kernel("--sync"))
        for value in ("1e38", "-1e38", "-0.000001", "390.25", "-390.25"):
            with self.subTest(value=value):
                result = self.run_kernel("--sync", f"--phase-shift=awareness:{value}", timeout=2)
                self.assertEqual(self.assert_success(result), baseline)

    def test_valid_keyed_thresholds_still_commit_one_owned_runtime_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pulse-kiss-control-") as directory:
            result = subprocess.run(
                [str(BINARY), "--limit=1", "--introspect", "--kiss", "--kiss-warmup=0",
                 "--kiss-alpha=1", "--kiss-thr=trust:2,tr:0,presence:-1,harmony:0"],
                cwd=directory, capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (Path(directory) / "logs" / "kiss.log").read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["t"], rows[0]["fired"]), (1, True))


if __name__ == "__main__":
    unittest.main()
