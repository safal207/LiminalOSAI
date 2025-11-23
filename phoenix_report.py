"""Phoenix regeneration report for LIMINAL."""

import datetime
import json
import math
import os
import random
import struct
import wave
from typing import Any, Dict, List

try:  # Optional plotting dependency
    import matplotlib.pyplot as plt  # type: ignore

    PLOT_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    plt = None  # type: ignore
    PLOT_AVAILABLE = False

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
    """Render and persist the coherence evolution plot, or fallback to ASCII."""
    if not trace:
        return

    generations = list(range(1, len(trace) + 1))
    coherence = [entry.get("coherence_after", 0.0) for entry in trace]

    if PLOT_AVAILABLE and plt is not None:
        plt.figure()
        plt.plot(generations, coherence, marker="o")
        plt.title("Phoenix Layer — Evolution of Coherence")
        plt.xlabel("Generation")
        plt.ylabel("Coherence after Rebirth")
        plt.grid(True)
        plt.savefig("phoenix_evolution.png", bbox_inches="tight")
        plt.close()
        print("📈 Saved graph → phoenix_evolution.png")
    else:
        ascii_plot(coherence)


def ascii_plot(coherence: List[float]) -> None:
    """Textual fallback visualisation for coherence evolution."""
    if not coherence:
        return

    print("\n🧩 ASCII Coherence Spectrum:")
    max_value = max(coherence) or 1.0
    for idx, value in enumerate(coherence, start=1):
        bar_length = int((value / max_value) * 40)
        bar = "█" * max(bar_length, 1)
        print(f"{idx:>2} | {bar} {value:.3f}")
    print("")


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


def sound_of_cycle(trace: List[TraceEntry], filename: str = "phoenix_breath.wav") -> None:
    """Create an audio pulse representing the coherence of each generation."""
    if not trace:
        return

    sample_rate = 44_100
    duration = 0.25  # seconds per generation
    amplitude = 16_000
    frames: List[bytes] = []

    for entry in trace:
        coherence = entry.get("coherence_after", 0.5)
        frequency = 200 + coherence * 800
        total_samples = int(sample_rate * duration)

        for i in range(total_samples):
            breath = math.sin(2 * math.pi * frequency * i / sample_rate)
            fade = 0.5 * (1 - math.cos(2 * math.pi * i / total_samples))
            sample = int(amplitude * breath * fade)
            frames.append(struct.pack("<h", sample))

    with wave.open(filename, "w") as wav_file:
        wav_file.setparams((1, 2, sample_rate, 0, "NONE", "not compressed"))
        wav_file.writeframes(b"".join(frames))

    print(f"🎵 Saved audio trace → {filename}")


def main() -> None:
    trace = load_trace()
    if not trace:
        return

    plot_resilience(trace)
    sound_of_cycle(trace)
    poetic_summary(trace)


if __name__ == "__main__":
    main()
