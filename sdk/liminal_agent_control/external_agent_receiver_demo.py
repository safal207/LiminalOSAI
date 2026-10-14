"""Required real Docker matrix for the owned receiver STOP/commit fence.

Uses the original source-pinned deterministic worker. Receiver fence and effect
share one SQLite transaction; no model calls or arbitrary destinations exist.
The legacy isolated-agent experiment remains the default in its own module.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .external_agent_demo import (
    RECEIVER_SCHEMA as SCHEMA, RECEIVER_CASE_IDS as CASE_IDS, RECEIVER_DESIGN as DESIGN,
    FIXTURE, _sources as _base_sources, run_demo as _base_run_demo,
)
from .external_stop_demo import _write_json


def _sources() -> dict[str, str]:
    return _base_sources(receiver_fence=True)


def run_demo(*, image: str | None = None, docker_binary: str = "docker") -> dict[str, Any]:
    return _base_run_demo(image=image, docker_binary=docker_binary, receiver_fence=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker-image", "--image", dest="docker_image")
    args = parser.parse_args()
    report = run_demo(image=args.docker_image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, report)
    print(json.dumps({"passed": report["passed"], "source": report["source"],
        "report": str(args.output.resolve())}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
