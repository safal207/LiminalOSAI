#!/usr/bin/env python3
"""Parse LiminalOSAI traces, print summaries, and optionally export or plot them."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Iterable, Optional

METRIC_NAMES = (
    "awareness",
    "coherence",
    "vitality",
    "metabolic_balance",
    "collective_pulse",
    "affinity_bond",
    "mirror_gain",
    "astro_tone",
)

_NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"


class TracePoint:
    def __init__(self, cycle: int, source: str, **metrics: Optional[float]) -> None:
        self.cycle = cycle
        self.source = source
        for name in METRIC_NAMES:
            setattr(self, name, metrics.get(name))

    def merge_missing(self, other: "TracePoint") -> None:
        for name in METRIC_NAMES:
            if getattr(self, name) is None:
                value = getattr(other, name)
                if value is not None:
                    setattr(self, name, value)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"cycle": self.cycle}
        for name in METRIC_NAMES:
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result


def _finite_number(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _json_object_from_line(line: str) -> Optional[dict[str, object]]:
    start = line.find("{")
    end = line.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(line[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_metric(line: str, *names: str) -> Optional[float]:
    for name in names:
        match = re.search(rf"\b{re.escape(name)}\b\s*[:=]\s*({_NUMBER})", line, re.IGNORECASE)
        if match:
            value = float(match.group(1))
            if math.isfinite(value):
                return value
    return None


def parse_trace_line(line: str) -> Optional[TracePoint]:
    payload = _json_object_from_line(line)
    if payload is not None and "cycle" in payload:
        cycle_value = payload.get("cycle")
        if isinstance(cycle_value, bool) or not isinstance(cycle_value, int) or cycle_value < 0:
            return None
        metrics = {name: _finite_number(payload.get(name)) for name in METRIC_NAMES}
        if metrics["awareness"] is None:
            metrics["awareness"] = _finite_number(payload.get("resonance"))
        if metrics["vitality"] is None:
            metrics["vitality"] = _finite_number(payload.get("dream_sync"))
        if any(value is not None for value in metrics.values()):
            return TracePoint(cycle_value, "json", **metrics)

    cycle_match = re.search(r"\bcycle\b\s*[:=]?\s*(\d+)", line, re.IGNORECASE)
    if not cycle_match:
        return None

    metrics = {
        "awareness": _extract_metric(line, "awareness", "breath"),
        "coherence": _extract_metric(line, "coherence", "resonance"),
        "vitality": _extract_metric(line, "vitality"),
        "metabolic_balance": _extract_metric(line, "metabolic_balance", "balance"),
        "collective_pulse": _extract_metric(line, "collective_pulse"),
        "affinity_bond": _extract_metric(line, "affinity_bond", "bond"),
        "mirror_gain": _extract_metric(line, "mirror_gain"),
        "astro_tone": _extract_metric(line, "astro_tone"),
    }
    if not any(value is not None for value in metrics.values()):
        return None
    return TracePoint(int(cycle_match.group(1)), "legacy", **metrics)


def parse_trace_lines(lines: Iterable[str]) -> list[TracePoint]:
    by_cycle: dict[int, TracePoint] = {}
    cycle_order: list[int] = []

    for line in lines:
        point = parse_trace_line(line.strip())
        if point is None:
            continue

        existing = by_cycle.get(point.cycle)
        if existing is None:
            by_cycle[point.cycle] = point
            cycle_order.append(point.cycle)
            continue

        if existing.source == "json" and point.source != "json":
            continue
        if point.source == "json" and existing.source != "json":
            by_cycle[point.cycle] = point
            continue

        existing.merge_missing(point)

    return [by_cycle[cycle] for cycle in cycle_order]


def parse_trace_file(path: Path) -> list[TracePoint]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return parse_trace_lines(handle)


def extract_metrics(points: Iterable[TracePoint]) -> dict[str, list[tuple[int, float]]]:
    metrics: dict[str, list[tuple[int, float]]] = {name: [] for name in METRIC_NAMES}
    for point in points:
        for name in METRIC_NAMES:
            value = getattr(point, name)
            if value is not None:
                metrics[name].append((point.cycle, value))
    return metrics


def summarize(metrics: dict[str, list[tuple[int, float]]]) -> dict[str, dict[str, float | int]]:
    summary: dict[str, dict[str, float | int]] = {}
    for name, samples in metrics.items():
        if not samples:
            continue
        values = [value for _, value in samples]
        summary[name] = {
            "count": len(values),
            "minimum": min(values),
            "maximum": max(values),
            "average": sum(values) / len(values),
        }
    return summary


def plot_metrics(metrics: dict[str, list[tuple[int, float]]], output: Optional[Path]) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("plotting requires matplotlib") from exc

    active = [(name, samples) for name, samples in metrics.items() if samples]
    if not active:
        raise ValueError("trace contains no plottable metrics")

    figure, axes = plt.subplots(len(active), 1, figsize=(11, max(3, len(active) * 2.5)), squeeze=False)
    for axis, (name, samples) in zip(axes[:, 0], active):
        axis.plot([cycle for cycle, _ in samples], [value for _, value in samples])
        axis.set_title(name.replace("_", " ").title())
        axis.set_xlabel("Cycle")
        axis.set_ylabel("Value")
        axis.grid(True, alpha=0.3)
    figure.tight_layout()
    if output is None:
        plt.show()
    else:
        figure.savefig(output, dpi=150, bbox_inches="tight")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_file", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--plot", action="store_true")
    parser.add_argument("--plot-output", type=Path)
    args = parser.parse_args()

    if not args.trace_file.is_file():
        parser.error(f"trace file not found: {args.trace_file}")

    points = parse_trace_file(args.trace_file)
    if not points:
        parser.error("no valid trace points found")

    metrics = extract_metrics(points)
    summary = summarize(metrics)
    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.json_output:
        args.json_output.write_text(
            json.dumps([point.as_dict() for point in points], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.plot:
        plot_metrics(metrics, args.plot_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
