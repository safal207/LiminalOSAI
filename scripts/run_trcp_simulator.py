#!/usr/bin/env python3
"""Print the deterministic TRCP demo trace as canonical JSON."""
import json

from sdk.liminal_trcp import run_default_scenario


def main() -> None:
    print(json.dumps(run_default_scenario(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
