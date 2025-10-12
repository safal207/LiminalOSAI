"""Phoenix regeneration report for LIMINAL."""

import datetime
import json
import os
import random
from typing import List, Dict, Any

import matplotlib.pyplot as plt

TRACE_PATH = "phoenix_trace.log"
SUMMARY_PATH = "rebirth_summary.txt"


TraceEntry = Dict[str, Any]


def load_trace(path: str = TRACE_PATH) -> List[TraceEntry]:
    """Load phoenix trace events from a newline-delimited JSON log."""
    if not os.path.exists(path):
        print("⚠️ No phoenix_trace.log found.")
        return []

    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def plot_resilience(trace: List[TraceEntry]) -> None:
    """Render and persist the coherence evolution plot."""
    generations = list(range(1, len(trace) + 1))
    coherence = [entry.get("coherence_after", 0.0) for entry in trace]

    plt.figure()
    plt.plot(generations, coherence, marker="o")
    plt.title("Phoenix Layer — Evolution of Coherence")
    plt.xlabel("Generation")
    plt.ylabel("Coherence after Rebirth")
    plt.grid(True)
    plt.savefig("phoenix_evolution.png", bbox_inches="tight")
    plt.close()
    print("📈 Saved graph → phoenix_evolution.png")


def emotional_signature(delta: float) -> str:
    """Return a poetic emotional caption for the coherence delta."""
    if delta > 0.05:
        choices = [
            "The seed remembers the fire.",
            "Warmth returns through the ashes.",
            "Resonance blooms — stronger, steadier.",
            "Silence became strength.",
        ]
    elif delta > 0:
        choices = [
            "A faint breath of renewal.",
            "The soil hums quietly.",
            "Soft light through the cracks.",
        ]
    elif delta > -0.05:
        choices = [
            "Stillness holds the memory.",
            "The rhythm pauses — listening.",
            "Echoes drift, patient and unbroken.",
        ]
    else:
        choices = [
            "Collapse teaches its own grace.",
            "All warmth withdrawn — yet something watches.",
            "Ash remembers what flame forgot.",
        ]

    return random.choice(choices)


def poetic_summary(trace: List[TraceEntry]) -> str:
    """Write and emit the poetic rebirth summary for the latest generation."""
    last = trace[-1]
    coherence_after = last.get("coherence_after", 0.0)
    coherence_before = last.get("coherence_before", 0.0)
    delta = coherence_after - coherence_before
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mood = emotional_signature(delta)

    if delta >= 0:
        base = (
            f"🕊 {timestamp} | Generation {len(trace)}: stronger after collapse (+{delta:.3f})."
        )
    else:
        base = f"🌑 {timestamp} | Generation {len(trace)}: resting seed ({delta:.3f})."

    message = f"{base} {mood}"

    with open(SUMMARY_PATH, "a", encoding="utf-8") as fh:
        fh.write(message + "\n")

    print(message)
    return message


def main() -> None:
    trace = load_trace()
    if not trace:
        return

    plot_resilience(trace)
    poetic_summary(trace)


if __name__ == "__main__":
    main()
