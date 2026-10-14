"""Ensure benchmark source identity cannot disagree with the measured SDK."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "tools" / "benchmark_workload_snapshot.py"


class BenchmarkSourceTests(unittest.TestCase):
    def test_target_checkout_is_reported_with_its_actual_sdk(self):
        result = subprocess.run(
            [sys.executable, str(BENCHMARK), "--repo", str(ROOT),
             "--samples", "1", "--iterations", "1", "--rows", "1"],
            capture_output=True, text=True, timeout=20, check=True,
        )
        document = json.loads(result.stdout)
        self.assertEqual(Path(document["sdk_file"]), ROOT / "sdk/liminal_trcp/sdk.py")
        self.assertRegex(document["source"], r"^[0-9a-f]{40}$")

    def test_cached_sdk_from_another_checkout_is_rejected_before_measurement(self):
        # Import the current checkout first, then request a different target in
        # the same process. sys.path priority alone cannot evict cached modules.
        script = (
            "import sys; from pathlib import Path; "
            "from sdk.liminal_trcp import sdk; "
            "from tools import benchmark_workload_snapshot as benchmark; "
            "sys.argv=['benchmark', '--repo', sys.argv[1], '--samples', '1', "
            "'--iterations', '1', '--rows', '1']; benchmark.main()"
        )
        with tempfile.TemporaryDirectory() as target:
            result = subprocess.run(
                [sys.executable, "-c", script, target], cwd=ROOT,
                capture_output=True, text=True, timeout=20, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("imported TRCP SDK is outside --repo", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
