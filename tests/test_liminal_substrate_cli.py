from __future__ import annotations

import json
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

    def run_substrate(self, *arguments: str, dry_run: bool = True, timeout: float = 10) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="liminal-substrate-cli-") as directory:
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
        result = self.run_substrate(
            "--substrate", "--limit=1", "--qel", "--introspect", "--kiss", "--astro-trace",
            "--tune-save=should-not-exist.json", argument, dry_run=False, timeout=2,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("liminal_core: invalid numeric value", result.stderr)
        self.assertIn(argument, result.stderr)

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
        for argument in ("--allow=now", "--allow=NOW", "--allow=nOw", "--allow=0.25",
                         "--entangle-ctx=0x10", "--entangle-ctx=4294967295", "--entangle-ctx=0xffffffff",
                         "--entangle-ctx=037777777777", "--entangle-ctx=+0xffffffff"):
            with self.subTest(argument=argument):
                self.successful_lines(argument)

    def test_shared_float_scalars_reject_empty_nonfinite_and_overflow(self) -> None:
        for option in ("allow", "empathy-gain", "recognition-threshold"):
            for value in ("", "nan", "inf", "-inf", "1e999", "1e-999", "nowjunk"):
                with self.subTest(option=option, value=value):
                    self.assert_composite_rejected(f"--{option}={value}")

    def test_context_rejects_malformed_negative_and_uint32_overflow(self) -> None:
        for value in ("", "nan", "inf", "1e999", "1.5", "-1", " -1", "0x10tail",
                      "4294967296", "0x100000000", "040000000000", "18446744073709551616"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--entangle-ctx={value}")

    def test_tune_seed_rejects_int_narrowing_overflow(self) -> None:
        for value in ("2147483648", "-2147483649", "4294967296"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--tune-seed={value}")
        for value in ("-2147483648", "2147483647", "-1", "42"):
            with self.subTest(value=value):
                self.successful_lines(f"--tune-seed={value}")

    def test_hex_uint32_context_boundary_is_recorded_without_narrowing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-context-control-") as directory:
            (Path(directory) / "logs").mkdir()
            result = subprocess.run(
                [str(BINARY), "--substrate", "--limit=1", "--qel", "--introspect", "--entangle-ctx=0xffffffff"],
                cwd=directory, capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (Path(directory) / "logs" / "qel_raw.jsonl").read_text().splitlines()]
            self.assertTrue(rows)
            self.assertTrue(all(row["ctx"] == 4294967295 for row in rows))

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

    def test_malformed_float_ranges_reject_before_initialization(self) -> None:
        for option in ("tune-alpha", "tune-align"):
            for value in ("", ":0.5", "0.5:", "bad:0.5", "0.5:bad", "nan:0.5",
                          "0.5:inf", "1e999:0.5", "0.5:1e999", "1e-999:0.5",
                          "0.5:0.8junk", "0.5:0.8:1", "0.5 :0.8"):
                with self.subTest(option=option, value=value):
                    self.assert_composite_rejected(f"--{option}={value}")

    def test_integer_range_rejects_suffixes_nonfinite_and_narrowing_overflow(self) -> None:
        for value in ("", ":1", "1:", "1.5:2", "1:2.5", "1:2junk", "nan:2", "1:inf",
                      "2147483648:1", "1:-2147483649", "9223372036854775808:2",
                      "1:9223372036854775808", "1:2:3"):
            with self.subTest(value=value):
                self.assert_composite_rejected(f"--tune-warm={value}")

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
                self.successful_lines(f"--{option}={valid}")
                self.assert_composite_rejected(f"--{option}={valid},ignored:0.5junk")

    def test_composite_indices_reject_uint32_narrowing_overflow(self) -> None:
        for option in ("erb-replay", "tune-source"):
            with self.subTest(option=option):
                self.assert_composite_rejected(f"--{option}=idx:4294967296")
        self.successful_lines("--erb-replay=idx:4294967295")

    def test_valid_composite_ranges_lists_and_order_remain_compatible(self) -> None:
        baseline = self.successful_lines("--strict-order")
        for argument in (
            "--tune-alpha=0.6:0.1", "--tune-align=-2:5", "--tune-warm=100:-100",
            "--tune-alpha=+0.1: 0.6 ", "--tune-align=0.4: 0.8 ",
            "--tune-warm=-2147483648:2147483647", "--tune-warm=+2: 10 ",
            "--affinity-cfg=,care:-2,,respect:3,care:0.5,presence:0.25,ignored:0.2,",
            "--kiss-thr=trust:2,tr:0.25, presence:0.5,harm:0.75,harmony:0.8",
            "--kiss-thr= tr: +0.25 ,presence:0.5 ,harmony:0.8 ",
            "--affinity-cfg=care: +0.25 ,respect:0.5,presence:0.75 ",
        ):
            with self.subTest(argument=argument):
                self.assertEqual(self.successful_lines("--strict-order", argument), baseline)

    def test_tuning_range_clamps_and_sorting_preserve_actual_saved_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-tune-control-") as directory:
            recorded = subprocess.run(
                [str(BINARY), "--substrate", "--limit=1", "--erb", "--erb-pre=0",
                 "--erb-post=0", "--erb-spike=0", "--introspect"],
                cwd=directory, capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            self.assertTrue((Path(directory) / "logs" / "erb_index.jsonl").is_file())
            profiles = []
            ranges = (
                ("--tune-alpha=5:-2", "--tune-warm=100:-100", "--tune-align=5:-2"),
                ("--tune-alpha=0.01:0.95", "--tune-warm=0:10", "--tune-align=0:1"),
            )
            for index, arguments in enumerate(ranges):
                target = Path(directory) / f"owned-profile-{index}.json"
                result = subprocess.run(
                    [str(BINARY), "--tune", "--tune-trials=1", "--tune-refine=0", "--tune-max-runs=1",
                     "--tune-seed=42", *arguments, f"--tune-save={target}"],
                    cwd=directory, capture_output=True, text=True, check=False, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                profiles.append(target.read_bytes())
            self.assertEqual(profiles[0], profiles[1])
            self.assertEqual(json.loads(profiles[0])["trs_warmup"], 6)

    def test_valid_keyed_thresholds_still_commit_one_owned_runtime_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="substrate-kiss-control-") as directory:
            result = subprocess.run(
                [str(BINARY), "--substrate", "--limit=1", "--introspect", "--kiss", "--kiss-warmup=0",
                 "--kiss-alpha=1", "--kiss-thr=trust:2,tr:0,presence:-1,harmony:0"],
                cwd=directory, capture_output=True, text=True, check=False, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in (Path(directory) / "logs" / "kiss.log").read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["t"], rows[0]["fired"]), (1, True))


if __name__ == "__main__":
    unittest.main()
