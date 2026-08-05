from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "trace_visualizer.py"
SPEC = importlib.util.spec_from_file_location("trace_visualizer", MODULE_PATH)
assert SPEC and SPEC.loader
trace_visualizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace_visualizer)


class TraceVisualizerTests(unittest.TestCase):
    def test_parses_prefixed_json_trace(self) -> None:
        point = trace_visualizer.parse_trace_line(
            'trace_event: {"cycle": 3, "coherence": 0.7, "resonance": 0.4, "dream_sync": 0.6}'
        )
        self.assertIsNotNone(point)
        assert point is not None
        self.assertEqual(point.cycle, 3)
        self.assertEqual(point.source, "json")
        self.assertAlmostEqual(point.coherence, 0.7)
        self.assertAlmostEqual(point.awareness, 0.4)
        self.assertAlmostEqual(point.vitality, 0.6)

    def test_parses_legacy_trace(self) -> None:
        point = trace_visualizer.parse_trace_line(
            "[trace] cycle=8 breath=0.71 resonance=0.55 vitality=0.62 balance=-0.2 bond=0.9"
        )
        self.assertIsNotNone(point)
        assert point is not None
        self.assertEqual(point.cycle, 8)
        self.assertEqual(point.source, "legacy")
        self.assertAlmostEqual(point.awareness, 0.71)
        self.assertAlmostEqual(point.coherence, 0.55)
        self.assertAlmostEqual(point.metabolic_balance, -0.2)
        self.assertAlmostEqual(point.affinity_bond, 0.9)

    def test_prefers_json_for_duplicate_cycle(self) -> None:
        points = trace_visualizer.parse_trace_lines(
            [
                "[trace] cycle=4 breath=0.1 resonance=0.2",
                'trace_event: {"cycle": 4, "awareness": 0.9, "coherence": 0.8}',
                "[trace] cycle=4 breath=0.3 resonance=0.4",
            ]
        )
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].source, "json")
        self.assertAlmostEqual(points[0].awareness, 0.9)
        self.assertAlmostEqual(points[0].coherence, 0.8)

    def test_rejects_missing_or_non_finite_metrics(self) -> None:
        self.assertIsNone(trace_visualizer.parse_trace_line("cycle=2 no metrics here"))
        self.assertIsNone(trace_visualizer.parse_trace_line('{"cycle": 2, "coherence": NaN}'))
        self.assertIsNone(trace_visualizer.parse_trace_line('{"cycle": -1, "coherence": 0.4}'))

    def test_extracts_and_summarizes_metrics(self) -> None:
        points = trace_visualizer.parse_trace_lines(
            [
                "cycle=1 awareness=0.2 coherence=0.5",
                "cycle=2 awareness=0.6 coherence=0.7",
            ]
        )
        metrics = trace_visualizer.extract_metrics(points)
        summary = trace_visualizer.summarize(metrics)
        self.assertEqual(summary["awareness"]["count"], 2)
        self.assertAlmostEqual(summary["awareness"]["average"], 0.4)
        self.assertAlmostEqual(summary["coherence"]["minimum"], 0.5)
        self.assertAlmostEqual(summary["coherence"]["maximum"], 0.7)

    def test_file_parser_and_json_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trace.log"
            path.write_text(
                "cycle=1 awareness=0.3\n"
                "ignored line\n"
                'event: {"cycle": 2, "coherence": 0.8}\n',
                encoding="utf-8",
            )
            points = trace_visualizer.parse_trace_file(path)
            self.assertEqual(len(points), 2)
            serialized = json.dumps([point.as_dict() for point in points])
            self.assertIn('"cycle": 1', serialized)
            self.assertIn('"coherence": 0.8', serialized)
            self.assertNotIn('"source"', serialized)


if __name__ == "__main__":
    unittest.main()
