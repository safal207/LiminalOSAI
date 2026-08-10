#!/usr/bin/env python3
"""Print the deterministic TRCP demo trace as canonical JSON."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sdk.liminal_trcp import run_default_scenario


def main() -> None:
    print(json.dumps(run_default_scenario(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
