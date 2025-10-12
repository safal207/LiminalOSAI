"""Long-run diagnostics report for Liminal core traces."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Sequence


TRACE_PATTERN = re.compile(r"trace_event:\s*(\{.*\})")


@dataclass
class TracePoint:
    cycle: int
    coherence: float
    resonance: float
    sync_quality: float
    anticipation_level: float
    micro_pattern: float
    prediction_trend: float
    dream_sync: float

    @classmethod
    def from_json(cls, data: dict) -> "TracePoint":
        return cls(
            cycle=int(data.get("cycle", 0)),
            coherence=float(data.get("coherence", 0.0)),
            resonance=float(data.get("resonance", 0.0)),
            sync_quality=float(data.get("sync_quality", 0.0)),
            anticipation_level=float(data.get("anticipation_level", 0.0)),
            micro_pattern=float(data.get("micro_pattern", 0.0)),
            prediction_trend=float(data.get("prediction_trend", 0.0)),
            dream_sync=float(data.get("dream_sync", 0.0)),
        )


def load_trace(path: str) -> List[TracePoint]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Trace log not found: {path}")

    points: List[TracePoint] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            match = TRACE_PATTERN.search(line)
            if not match:
                continue
            try:
                payload = json.loads(match.group(1))
                points.append(TracePoint.from_json(payload))
            except (json.JSONDecodeError, ValueError):
                continue

    return points


def coherence_deltas(points: Sequence[TracePoint]) -> List[float]:
    deltas: List[float] = []
    for previous, current in zip(points, points[1:]):
        deltas.append(current.coherence - previous.coherence)
    return deltas


def summarise_deltas(deltas: Sequence[float]) -> str:
    if not deltas:
        return "No coherence transitions recorded."

    mean_delta = sum(deltas) / float(len(deltas))
    variance = sum((value - mean_delta) ** 2 for value in deltas) / float(len(deltas))
    std_dev = math.sqrt(variance)
    min_delta = min(deltas)
    max_delta = max(deltas)

    lines = [
        "Coherence deltas:",
        f"  samples: {len(deltas)}",
        f"  mean: {mean_delta:+.4f}",
        f"  std-dev: {std_dev:.4f}",
        f"  min/max: {min_delta:+.4f} / {max_delta:+.4f}",
    ]

    for index, value in enumerate(deltas, start=1):
        lines.append(f"    Δ{index:02d}: {value:+.4f}")

    return "\n".join(lines)


def build_heatmap(points: Sequence[TracePoint], bins: int = 6) -> List[List[int]]:
    grid = [[0 for _ in range(bins)] for _ in range(bins)]
    for point in points:
        anticipation = max(0.0, min(0.999, point.anticipation_level))
        trend = max(0.0, min(0.999, point.prediction_trend))
        row = int((1.0 - trend) * bins)
        col = int(anticipation * bins)
        row = min(max(row, 0), bins - 1)
        col = min(max(col, 0), bins - 1)
        grid[row][col] += 1
    return grid


def format_heatmap(grid: Sequence[Sequence[int]]) -> str:
    if not grid:
        return "No anticipation samples." 

    max_count = max((value for row in grid for value in row), default=0)
    if max_count == 0:
        max_count = 1

    lines = ["Anticipation heatmap (trend ↓, anticipation →):"]
    for row in grid:
        cells = []
        for value in row:
            intensity = int(round((value / max_count) * 8))
            cells.append(" ░▒▓█"[min(intensity, 4)])
        lines.append("".join(cells))
    return "\n".join(lines)


def predictability_coefficient(deltas: Sequence[float]) -> float:
    if not deltas:
        return 0.0
    mean_delta = sum(deltas) / float(len(deltas))
    variance = sum((value - mean_delta) ** 2 for value in deltas) / float(len(deltas))
    std_dev = math.sqrt(variance)
    return max(0.0, 1.0 - min(1.0, std_dev))


def render_summary(points: Sequence[TracePoint]) -> str:
    lines: List[str] = []
    deltas = coherence_deltas(points)
    lines.append(summarise_deltas(deltas))
    lines.append("")
    lines.append(format_heatmap(build_heatmap(points)))
    lines.append("")
    coefficient = predictability_coefficient(deltas)
    lines.append(f"Predictability coefficient: {coefficient:.4f}")
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise long-run Liminal core traces.")
    parser.add_argument("--input", required=True, help="Path to the captured trace log.")
    parser.add_argument("--output", help="Where to persist the human-readable summary.")
    parser.add_argument("--json", help="Optional path to persist structured metrics as JSON.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    points = load_trace(args.input)
    if not points:
        print("⚠️ No trace_event entries found. Did the run include --trace?")
        return 1

    summary = render_summary(points)
    print(summary)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(summary)

    if args.json:
        deltas = coherence_deltas(points)
        payload = {
            "cycles": [point.cycle for point in points],
            "coherence": [point.coherence for point in points],
            "coherence_deltas": deltas,
            "predictability": predictability_coefficient(deltas),
        }
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
