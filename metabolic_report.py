"""metabolic_report.py — визуализация энергетического потока LIMINAL."""

import json
import os
from typing import List, Dict, Any

import matplotlib.pyplot as plt

TRACE_PATH = "metabolic_trace.log"


def load_trace(path: str = TRACE_PATH) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        print("⚠️ no metabolic_trace.log found.")
        return []

    data: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
                data.append(record)
                continue
            except json.JSONDecodeError:
                pass

            parts: Dict[str, str] = {}
            for token in raw.split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                parts[key] = value
            if not parts:
                continue
            try:
                intake = float(parts.get("in", "0"))
                output = float(parts.get("out", "0"))
                vitality = float(parts.get("vit", parts.get("vitality", "0")))
            except ValueError:
                continue
            balance = intake - output
            data.append({
                "intake": intake,
                "output": output,
                "balance": balance,
                "vitality": vitality,
            })
    return data


def plot_metabolism(data: List[Dict[str, Any]]) -> None:
    if not data:
        return

    x = list(range(len(data)))
    intake = [entry.get("intake", 0.0) for entry in data]
    output = [entry.get("output", 0.0) for entry in data]
    vitality = [entry.get("vitality", 0.0) for entry in data]

    fig, ax1 = plt.subplots()
    ax1.plot(x, intake, label="intake", color="green", alpha=0.7)
    ax1.plot(x, output, label="output", color="red", alpha=0.7)
    ax1.set_xlabel("Cycle")
    ax1.set_ylabel("Energy flow")
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.plot(x, vitality, label="vitality", color="blue", linewidth=2)
    ax2.set_ylabel("Vitality (0..1)")
    ax2.set_ylim(0.0, 1.05)
    ax2.legend(loc="lower right")

    plt.title("LIMINAL — Metabolic Flow")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("metabolic_pulse.png")
    print("📈 Saved graph → metabolic_pulse.png")


def main() -> None:
    data = load_trace()
    if not data:
        return
    plot_metabolism(data)


if __name__ == "__main__":
    main()
