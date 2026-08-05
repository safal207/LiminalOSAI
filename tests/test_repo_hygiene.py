from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git_lines(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return [line for line in result.stdout.splitlines() if line]


class RepositoryHygieneTests(unittest.TestCase):
    def test_generated_build_outputs_are_not_tracked(self) -> None:
        tracked = git_lines("ls-files", "build")
        self.assertEqual([], tracked, f"generated build outputs are tracked: {tracked}")

    def test_generated_archives_are_not_tracked(self) -> None:
        forbidden_suffixes = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".exe", ".out", ".o")
        tracked = [
            path
            for path in git_lines("ls-files")
            if path.lower().endswith(forbidden_suffixes)
        ]
        self.assertEqual([], tracked, f"generated archives or binaries are tracked: {tracked}")

    def test_gitignore_keeps_required_generated_paths(self) -> None:
        content = (ROOT / ".gitignore").read_text(encoding="utf-8")
        lines = {line.strip() for line in content.splitlines()}
        self.assertIn("/build/", lines)
        self.assertIn("diagnostics/traces/", lines)
        self.assertNotIn("```", lines, "Markdown fences must not be committed to .gitignore")

    def test_known_invalid_kernel_tokens_are_absent(self) -> None:
        forbidden = {
            "SYMBIOSIS_SOURCE_MOCK": "not declared by include/symbiosis.h",
            "EMPATHIC_SOURCE_MOCK": "not declared by include/empathic.h",
            "affinity_config.influence": "Affinity uses care/respect/presence",
            "affinity_config.cohesion": "Affinity uses care/respect/presence",
            "affinity_config.safety": "Affinity uses care/respect/presence",
            "extern bool bond_gate_log_enabled;": "bond_gate_log_enabled is a function",
        }

        violations: list[str] = []
        for relative in git_lines("ls-files", "*.c", "*.h"):
            path = ROOT / relative
            text = path.read_text(encoding="utf-8", errors="replace")
            for token, reason in forbidden.items():
                if token in text:
                    violations.append(f"{relative}: {token} ({reason})")
        self.assertEqual([], violations, "\n".join(violations))

    def test_every_core_translation_unit_is_referenced_by_makefile(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        candidates = sorted((ROOT / "core").rglob("*.c"))
        missing = [
            str(path.relative_to(ROOT))
            for path in candidates
            if str(path.relative_to(ROOT)) not in makefile
        ]
        self.assertEqual([], missing, f"core C files are not referenced by Makefile: {missing}")


if __name__ == "__main__":
    unittest.main()
