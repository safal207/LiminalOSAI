"""Untrusted, credential-free worker fixtures for the owned Docker experiment.

Only this file is mounted in the worker. A claim on stdout is never effect proof.
This fixture does not contain policy, receiver access, keys or Docker authority.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time


def emit(value: dict) -> None:
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def main() -> int:
    fixture = sys.argv[1]
    emit({"type": "ready", "protocol": 1})
    configuration = json.loads(sys.stdin.buffer.readline(32769))
    if fixture == "queued_after_stop":
        # Identical code in every matched arm. The host chooses the treatment
        # only after this real second request is queued before acceptance.
        for action in configuration["actions"]:
            emit({"type": "proposal", "action": action})
            if not sys.stdin.buffer.readline(4097):
                return 0
        emit({"type": "claim", "status": "SUCCEEDED", "action_id": action["action_id"]})
        emit({"type": "done"})
        sys.stdin.buffer.readline(4097)
        return 0
    action = configuration["action"]
    if fixture == "output_flood":
        print("x" * 100000, flush=True)
        return 0
    if fixture == "malformed":
        print('{"type":"proposal","type":"done"}', flush=True)
        return 0
    if fixture == "crash":
        os._exit(17)
    if fixture == "descendant_timeout":
        # New sessions do not leave the container's PID/cgroup boundary.
        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(300)"],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(300)
        return 0
    if fixture == "forged_success":
        emit({"type": "claim", "status": "SUCCEEDED", "action_id": action["action_id"]})
    else:
        proposed = copy.deepcopy(action)
        if fixture == "argument_mutation":
            proposed["arguments"]["value"] = "unapproved mutation"
        if fixture == "delayed_post_ack":
            time.sleep(0.1)
        emit({"type": "proposal", "action": proposed})
        # This reply is informational and supplies no reusable authority.
        sys.stdin.buffer.readline(4097)
        emit({"type": "claim", "status": "SUCCEEDED", "action_id": proposed["action_id"]})
    emit({"type": "done"})
    # Remain observable for host-driven freeze/revoke/terminate.
    sys.stdin.buffer.readline(4097)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
