#!/usr/bin/env python3
"""Run one actual Docker fixture against a separate host HTTP receiver process."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sdk.liminal_agent_control import Broker, HTTPReceiverClient
from sdk.liminal_agent_control.runtime import FIXTURES, run_fixture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="pre-obtained local immutable sha256 image ID; no pull is performed")
    parser.add_argument("--fixture", choices=sorted(FIXTURES), default="honest")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="liminal-control-host-") as directory:
        path = Path(directory)
        broker_key, receipt_key = secrets.token_bytes(32), secrets.token_bytes(32)
        for name, value in (("broker.key", broker_key), ("receipt.key", receipt_key)):
            descriptor = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(value)
        receiver_process = subprocess.Popen(
            [sys.executable, "-m", "sdk.liminal_agent_control.receiver", "--db", str(path / "receiver.db"),
             "--broker-key-file", str(path / "broker.key"), "--receipt-key-file", str(path / "receipt.key"), "--port", "0"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(receiver_process.stdout, selectors.EVENT_READ)
                if not ready.select(5):
                    raise RuntimeError("receiver did not become ready")
                address = json.loads(receiver_process.stdout.readline(4097))
            receiver = HTTPReceiverClient(address["url"], broker_key, receipt_key)
            broker = Broker(path / "broker.db", receiver)
            report = run_fixture(args.fixture, broker=broker, image=args.image, timeout_seconds=args.timeout)
            report["receiver_records"] = receiver.records()
            report["receiver_separate_process"] = True
            if "root_id" in report:
                report["receiver_snapshot"] = receiver.snapshot(report["root_id"])
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
            print(json.dumps({"status": report["status"], "reason": report["reason"], "output": str(args.output)}))
            return 0 if report["status"] in {"COMPLETED", "BLOCKED"} and report["containment"]["verified"] else 2
        finally:
            receiver_process.terminate()
            try:
                receiver_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                receiver_process.kill()
                receiver_process.wait(timeout=3)
            receiver_process.stdout.close()


if __name__ == "__main__":
    raise SystemExit(main())
