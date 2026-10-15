"""Independently launched host watchdog for durable session admission.

Launch this CLI as a separate host service/process, outside the controller's
process group and worker container. Nothing here installs or auto-starts it.
It never renews a lease. Expiry closes receiver admission in the shared authority
database; optional recovery concerns only the matching, registered Docker work.
"""
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any, Callable

from .authority import ControlError, require_key, validate_id
from .brakes_store import SessionAuthority
from .runtime import BoundedHostCall, recover_workloads


TERMINAL_STATES = frozenset({"STOPPED", "EXPIRED", "CLOCK_UNSAFE"})


def _positive(value: float, name: str, maximum: float) -> float:
    if (isinstance(value, bool) or not isinstance(value, (float, int))
            or not math.isfinite(value) or not 0 < value <= maximum):
        raise ControlError(f"invalid {name}")
    return float(value)


def run_watchdog(authority: SessionAuthority, root_id: str, *,
                 poll_interval_seconds: float = 0.05, max_wait_seconds: float = 60,
                 recovery: Callable[[], dict[str, Any]] | None = None,
                 recovery_timeout_seconds: float = 30) -> dict[str, Any]:
    """Observe lease loss, persist closure, then optionally recover owned work.

    max_wait bounds the polling phase; reaching it requests a permanent STOP.
    SQLite observation/STOP waits are independently bounded at one second.
    A bounded wait never establishes that a callback/thread was cancelled.
    Failure to observe or persist closure is reported as unverified. No worker
    message or heartbeat is accepted, and there is no automatic release.
    """
    validate_id(root_id, "root_id")
    poll = _positive(poll_interval_seconds, "poll_interval_seconds", 5)
    wait = _positive(max_wait_seconds, "max_wait_seconds", 86400)
    recovery_wait = _positive(recovery_timeout_seconds, "recovery_timeout_seconds", 300)
    started = time.monotonic()
    deadline = started + wait
    report: dict[str, Any] = {
        "schema": "liminal.agent-control.watchdog.v1", "root_id": root_id,
        "status": "INCOMPLETE", "reason": None, "admission_closed": False,
        "workload_verified": False, "session": None, "poll_count": 0,
        "pending_reservations": None, "external_effect_completion_verified": False,
        "recovery": None, "recovery_call": None, "authority_call": None,
        "scope": "shared local authority database and optional owned Docker registry",
    }
    while True:
        timed_out = time.monotonic() >= deadline
        callback = (lambda: authority.stop(root_id, reason="WATCHDOG_DEADLINE")) if timed_out else lambda: authority.status(root_id)
        call = BoundedHostCall(callback, name="liminal-watchdog-authority")
        try:
            snapshot = call.result_before(time.monotonic() + 1.0)
        except Exception:
            report.update(reason="AUTHORITY_OBSERVATION_UNAVAILABLE", authority_call=call.observation())
            break
        report["poll_count"] += 1
        report["session"] = snapshot
        if (type(snapshot) is not dict or snapshot.get("root_id") != root_id
                or snapshot.get("control_profile") != "durable-session-v1"):
            report["reason"] = "SESSION_NOT_VERIFIED"
            break
        if snapshot.get("status") in TERMINAL_STATES:
            report.update(status="ADMISSION_CLOSED", admission_closed=True,
                          reason=snapshot.get("stop_reason") or snapshot["status"],
                          pending_reservations=bool(snapshot.get("pending_action_count", 0)
                                                    or snapshot.get("pending_stage_count", 0)))
            break
        if snapshot.get("status") != "ACTIVE":
            report["reason"] = "SESSION_STATE_INVALID"
            break
        time.sleep(min(poll, max(0.0, deadline - time.monotonic())))

    # Configured cleanup is separately authorized and root-bound. Even when
    # authority observation fails, attempt it to reduce surviving compute;
    # never upgrade admission_closed from a cleanup result.
    if recovery is not None:
        call = BoundedHostCall(recovery, name="liminal-watchdog-recovery")
        try:
            result = call.result_before(time.monotonic() + recovery_wait)
            # Recovery proves process state separately from admission closure.
            # An empty registry establishes no observed workload postcondition.
            recovered = result.get("recovered") if type(result) is dict else None
            verified = (type(result) is dict and result.get("status") == "RECOVERED"
                        and result.get("admission_allowed") is True
                        and type(recovered) is list and bool(recovered)
                        and all(type(item) is dict and item.get("root_id") == root_id
                                and type(item.get("containment")) is dict
                                and item["containment"].get("verified") is True
                                and item["containment"].get("zero_survivors") is True for item in recovered))
            report["recovery"] = result
            report["workload_verified"] = bool(verified)
        except Exception:
            report["recovery"] = {"status": "UNKNOWN", "reason": "RECOVERY_UNAVAILABLE_OR_TIMED_OUT"}
        report["recovery_call"] = call.observation()
    report["elapsed_seconds"] = time.monotonic() - started
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority-db", type=Path, required=True)
    parser.add_argument("--root-id", required=True)
    parser.add_argument("--poll-interval", type=float, default=0.05)
    parser.add_argument("--max-wait", type=float, default=60)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--broker-db", type=Path)
    parser.add_argument("--broker-key-file", type=Path)
    parser.add_argument("--receipt-key-file", type=Path)
    parser.add_argument("--docker-binary", default="docker")
    parser.add_argument("--recovery-timeout", type=float, default=30)
    args = parser.parse_args(argv)
    recovery_args = (args.registry, args.broker_db, args.broker_key_file, args.receipt_key_file)
    if any(x is not None for x in recovery_args) and not all(x is not None for x in recovery_args):
        parser.error("registry recovery requires registry, broker database and both key files")
    if not args.authority_db.is_file() or any(path is not None and not path.is_file() for path in recovery_args):
        parser.error("authority and optional recovery input files must already exist")
    inputs = (args.authority_db, *recovery_args)
    if any(path is not None and args.output.resolve() == path.resolve() for path in inputs):
        parser.error("output must differ from authority, registry, broker and key files")
    recovery = None
    authority = SessionAuthority(args.authority_db)
    if args.registry is not None:
        from .broker import Broker
        from .receiver import Receiver
        receiver = Receiver(args.authority_db, require_key(args.broker_key_file.read_bytes()),
                            require_key(args.receipt_key_file.read_bytes()), admission_controller=authority)
        broker = Broker(args.broker_db, receiver)
        recovery = lambda: recover_workloads(args.registry, broker=broker, docker_binary=args.docker_binary,
                                            expected_root_id=args.root_id)
    report = run_watchdog(authority, args.root_id,
                          poll_interval_seconds=args.poll_interval, max_wait_seconds=args.max_wait,
                          recovery=recovery, recovery_timeout_seconds=args.recovery_timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # The watchdog output is host diagnostics, never a worker-owned control file.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0 if report["admission_closed"] and (recovery is None or report["workload_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
