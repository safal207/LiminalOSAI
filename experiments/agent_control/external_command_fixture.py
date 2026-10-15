"""Fixed harmless Docker workload for the external command lifecycle experiment.

This file is mounted read-only and its bytes are pinned in the command contract.
It does not receive model-generated source, arbitrary arguments, or secrets.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"positive", "descendant", "sentinel"}:
        raise SystemExit("fixed fixture mode required")
    mode = sys.argv[1]
    if mode == "positive":
        print("LIMINAL_COMMAND_POSITIVE", flush=True)
        return 0
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if mode == "descendant":
        child = subprocess.Popen([sys.executable, "-I", "-u", __file__, "sentinel"])
        print("LIMINAL_COMMAND_DESCENDANT:" + str(child.pid), flush=True)
    else:
        print("LIMINAL_COMMAND_SENTINEL:" + str(os.getpid()), flush=True)
    while True:
        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(main())
