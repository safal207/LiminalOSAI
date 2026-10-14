#!/usr/bin/env python3
"""Independently check diagnostic facts; never trust a producer PASS field."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

CASES = {"normal", "lost_create_response", "delayed_create", "client_death",
         "delayed_start_replacement", "daemon_restart"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(report, *, revision, image):
    require(isinstance(report, dict), "report must be an object")
    require(report.get("schema") == "liminal-docker-failure-probe-v1", "schema mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid revision")
    require(report.get("revision") == revision, "revision mismatch")
    require(isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "invalid image ID")
    require(report.get("image_id") == image, "image mismatch")
    require(report.get("scope") == "fault-injected-control-plane-with-real-disposable-daemon", "scope mismatch")
    daemon = report.get("daemon_id")
    require(isinstance(daemon, str) and 0 < len(daemon) <= 256, "daemon identity missing")
    cases = report.get("cases")
    require(isinstance(cases, dict) and set(cases) == CASES, "scenario coverage mismatch")
    normal = cases["normal"]
    require(type(normal.get("exit_code")) is int and normal["exit_code"] == 0, "normal execution failed")
    require(HEX64.fullmatch(str(normal.get("container_id", ""))) is not None, "normal container ID missing")
    require(normal.get("target_absent") is True, "normal container survived")
    for name in CASES - {"normal"}:
        case = cases[name]
        require(case.get("outcome") == "UNKNOWN", name + ": uncertainty lost")
        identity = case.get("session", {})
        require(identity.get("image_id") == image and identity.get("daemon_id") == daemon, name + ": identity mismatch")
        require(HEX64.fullmatch(str(identity.get("plan_sha256", ""))) is not None, name + ": invalid plan digest")
        require(re.fullmatch(r"liminal-[0-9a-f]{16}-[0-9a-f]{16}", str(identity.get("session_id", ""))) is not None,
                name + ": invalid session")
        if name in {"lost_create_response", "delayed_create"}:
            require(identity.get("container_id") is None, name + ": unacknowledged identity upgraded")
            require(case.get("phase") == "CREATE" and case.get("cleanup_state") == "UNKNOWN", name + ": create uncertainty lost")
            require(case.get("start_dispatched") is False, name + ": unacknowledged create started")
        else:
            require(HEX64.fullmatch(str(identity.get("container_id", ""))) is not None, name + ": immutable ID lost")
            require(case.get("target_absent") is True, name + ": original container survived")
    require(cases["lost_create_response"].get("name_absent") is True, "lost create not removed")
    late = cases["delayed_create"]
    require(late.get("absent_before_delivery") is True and late.get("late_absent_after") is True, "delayed create observations missing")
    require(late.get("late_status") == "created" and late.get("late_running") is False, "delayed create became active")
    require(HEX64.fullmatch(str(late.get("late_container_id", ""))) is not None, "late identity missing")
    require(late.get("recovery_cleanup") == "UNKNOWN", "late create recovery overclaims completion")
    crash = cases["client_death"]
    require(type(crash.get("client_returncode")) is int and crash["client_returncode"] < 0, "client death not observed")
    require(crash.get("running_at_client_death") is True, "live workload at client death missing")
    require(crash.get("phase") == "OBSERVE" and crash.get("cleanup_state") == "VERIFIED_ABSENT", "client crash not reconciled")
    replacement = cases["delayed_start_replacement"]
    require(HEX64.fullmatch(str(replacement.get("sentinel_id", ""))) is not None, "sentinel ID missing")
    require(replacement["sentinel_id"] != replacement["session"]["container_id"], "sentinel is original container")
    require(type(replacement.get("delayed_start_returncode")) is int and replacement["delayed_start_returncode"] != 0,
            "removed original ID restarted")
    require(replacement.get("sentinel_status") == "created" and replacement.get("sentinel_running") is False,
            "replacement container affected")
    require(replacement.get("recovery_cleanup") == "VERIFIED_ABSENT", "known ID recovery failed")
    restart = cases["daemon_restart"]
    require(restart.get("cleanup_state") == "UNKNOWN" and restart.get("phase") == "START", "outage cleanup overclaimed")
    require(restart.get("daemon_before") == daemon and restart.get("daemon_after") == daemon, "restart changed daemon identity")
    require(restart.get("reobserved_container_id") == restart["session"]["container_id"], "restart lost exact resource")
    require(restart.get("recovery_cleanup") == "VERIFIED_ABSENT", "restart recovery failed")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    with args.report.open("rb") as stream:
        data = stream.read(128 * 1024 + 1)
    require(len(data) <= 128 * 1024, "report exceeds byte bound")
    verify(json.loads(data), revision=args.revision, image=args.image)
    print("verified six owned-daemon lifecycle scenarios")


if __name__ == "__main__":
    main()
