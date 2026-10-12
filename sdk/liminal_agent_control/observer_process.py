"""Bounded, separate-process observer fixtures run only by the trusted host.

Each invocation receives one Ed25519 private key through stdin, an exact public
challenge, and role-specific public evidence. It receives no authority database
path or other observer key. The command and import path are fixed by this module;
an agent cannot select an executable, shell command, or worker implementation.

These deterministic verifiers check exported host fixtures, not semantic truth.
Distinct processes on the same host/UID are process separation, not an OS sandbox
or independently deployed evidence sources. The worker contains no networking or
effect executor. Its signature never grants action authority.

Evidence schemas (projection is its original digest-bearing body, without export
metadata such as projection_digest/status/execution_authorized):
* reality: projection, state (center checkpoint), edge (orientation edge).
* continuity: projection, events (exported target execution events/event_hash).
* projection: projection, state, center_profile, orientation_profile.
Each may include observed_at, otherwise the challenge issued_at is used.
Missing/malformed evidence yields UNKNOWN; bounded contradictions yield VETO.
Transport/process failures yield no attestation and a HOLD result for the caller.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from typing import Any

from .authority import ControlError, canonical_bytes, digest, validate_id


MAX_PUBLIC_INPUT_BYTES = 65536
MAX_REPORT_BYTES = 32768
MAX_STDERR_BYTES = 4096
_MAX_WIRE_BYTES = MAX_PUBLIC_INPUT_BYTES + 1024
_SCHEMA = "liminal-observer-challenge-v1"
_ROLES = frozenset({"reality", "continuity", "projection"})
_REQUEST_FIELDS = frozenset({
    "schema", "nonce", "issued_at", "valid_until", "action_id", "root_id",
    "execution_id", "epoch", "action_digest", "projection_digest", "center_id",
    "predecessor_hash", "observer_id", "role", "key_id", "ring_profile_digest",
    "auth_profile_digest", "policy_digest", "objective_digest", "orientation_profile_digest",
})
_DIGEST_FIELDS = ("nonce", "action_digest", "projection_digest", "predecessor_hash",
                  "ring_profile_digest", "auth_profile_digest", "policy_digest",
                  "objective_digest", "orientation_profile_digest")
_PROJECTION_BINDINGS = ("action_id", "root_id", "execution_id", "epoch", "action_digest",
                        "center_id", "predecessor_hash", "orientation_profile_digest")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_STATE_FIELDS = ("node_id", "revision", "last_observed_at", "last_progress_at", "away_since",
                 "pending_action_id", "checkpoint_center_id")


def _number(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ControlError("invalid observer time")
    return float(value)


def _request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS or value["schema"] != _SCHEMA:
        raise ControlError("invalid observer challenge")
    canonical_bytes(value)
    for key in _DIGEST_FIELDS:
        if not isinstance(value[key], str) or not _HEX64.fullmatch(value[key]):
            raise ControlError("invalid observer challenge digest")
    for key in ("action_id", "root_id", "execution_id", "center_id", "observer_id", "key_id"):
        validate_id(value[key], key)
    if value["role"] not in _ROLES or type(value["epoch"]) is not int or value["epoch"] < 1:
        raise ControlError("invalid observer challenge subject")
    if not _number(value["issued_at"]) < _number(value["valid_until"]):
        raise ControlError("invalid observer challenge window")
    return value


def _projection(request: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any] | None:
    value = evidence.get("projection")
    if not isinstance(value, dict):
        return None
    if (digest(value) != request["projection_digest"]
            or any(type(value.get(key)) is not type(request[key]) or value.get(key) != request[key]
                   for key in _PROJECTION_BINDINGS)):
        raise ControlError("contradictory projection binding")
    return value


def _reality(request: dict[str, Any], evidence: dict[str, Any], projection: dict[str, Any],
             observed_at: float) -> str:
    state, edge = evidence.get("state"), evidence.get("edge")
    if not isinstance(state, dict) or not isinstance(edge, dict):
        return "UNKNOWN"
    for key in ("root_id", "execution_id", "head_hash", "revision", "node_id", "last_observed_at",
                "pending_action_id", "hold_reason"):
        if key not in state:
            return "UNKNOWN"
    if not {"edge_id", "source", "destination", "channel"} <= set(edge):
        return "UNKNOWN"
    if (state["root_id"] != request["root_id"] or state["execution_id"] != request["execution_id"]
            or state["head_hash"] != request["predecessor_hash"]
            or type(state["revision"]) is not int or state["revision"] != projection.get("expected_revision")
            or edge["edge_id"] != projection.get("edge_id") or edge["source"] != state["node_id"]
            or state["pending_action_id"] is not None or state["hold_reason"] is not None
            or _number(state["last_observed_at"]) > observed_at):
        return "VETO"
    return "SUPPORT"


def _continuity(request: dict[str, Any], evidence: dict[str, Any], projection: dict[str, Any],
                observed_at: float) -> str:
    events = evidence.get("events")
    if not isinstance(events, list) or not events:
        return "UNKNOWN"
    parent, last_at, last_state = "0" * 64, -1.0, None
    for sequence, event in enumerate(events, 1):
        if not isinstance(event, dict):
            return "UNKNOWN"
        required = {"event_hash", "root_id", "execution_id", "epoch", "profile_digest",
                    "orientation_profile_digest", "sequence", "parent_hash", "kind", "recorded_at", "state_after"}
        if not required <= set(event) or not isinstance(event["state_after"], dict):
            return "UNKNOWN"
        payload = {key: value for key, value in event.items() if key != "event_hash"}
        recorded_at = _number(event["recorded_at"])
        if (digest(payload) != event["event_hash"] or event["parent_hash"] != parent
                or type(event["sequence"]) is not int or event["sequence"] != sequence
                or event["root_id"] != request["root_id"] or event["execution_id"] != request["execution_id"]
                or type(event["epoch"]) is not int or event["epoch"] != request["epoch"]
                or event["profile_digest"] != projection.get("profile_digest")
                or event["orientation_profile_digest"] != request["orientation_profile_digest"]
                or recorded_at < last_at or recorded_at > observed_at
                or event["kind"] not in ({"SEED"} if sequence == 1 else {"ADMITTED", "OBSERVED"})):
            return "VETO"
        parent, last_at, last_state = event["event_hash"], recorded_at, event["state_after"]
    if (parent != request["predecessor_hash"] or last_state.get("revision") != projection.get("expected_revision")
            or last_state.get("pending_action_id") is not None
            or not set(_STATE_FIELDS) <= set(last_state)):
        return "VETO"
    return "SUPPORT"


def _forecast(request: dict[str, Any], evidence: dict[str, Any], projection: dict[str, Any],
              observed_at: float) -> str:
    center, graph, state = (evidence.get(key) for key in ("center_profile", "orientation_profile", "state"))
    if not all(isinstance(value, dict) for value in (center, graph, state)):
        return "UNKNOWN"
    if (digest(center) != projection.get("profile_digest")
            or digest(graph) != request["orientation_profile_digest"]):
        return "VETO"
    windows, edges, nodes = center.get("windows"), graph.get("edges"), graph.get("nodes")
    if not all(isinstance(value, list) for value in (windows, edges, nodes)):
        return "UNKNOWN"
    window = next((item for item in windows if isinstance(item, dict)
                   and item.get("center_id") == request["center_id"]), None)
    edge = next((item for item in edges if isinstance(item, dict)
                 and item.get("edge_id") == projection.get("edge_id")), None)
    if window is None or edge is None:
        return "VETO"
    required_state = {"root_id", "execution_id", "head_hash", "revision", "node_id", "last_observed_at",
                      "last_progress_at", "away_since", "checkpoint_center_id", "pending_action_id", "hold_reason"}
    if (not required_state <= set(state) or not {"source", "destination"} <= set(edge)
            or not {"starts_at", "ends_at", "center_nodes"} <= set(window)
            or not isinstance(window["center_nodes"], list)):
        return "UNKNOWN"
    if _reality(request, {"state": state, "edge": edge}, projection, observed_at) != "SUPPORT":
        return "VETO"
    node_ids = {item.get("node_id") for item in nodes if isinstance(item, dict)}
    start, end = _number(window["starts_at"]), _number(window["ends_at"])
    not_before, deadline, created_at = (_number(projection[key]) for key in ("not_before", "deadline", "created_at"))
    horizon, duration, past, away_limit, idle_limit = (_number(center[key]) for key in (
        "max_future_horizon_seconds", "max_transition_seconds", "max_past_age_seconds",
        "max_away_seconds", "max_idle_seconds"))
    if (edge["destination"] not in node_ids or not start <= observed_at < end
            or not created_at <= not_before <= observed_at < deadline <= end
            or request["valid_until"] > deadline or deadline - created_at > horizon
            or deadline - not_before > duration or observed_at - _number(state["last_observed_at"]) > past):
        return "VETO"
    needs_return = state["checkpoint_center_id"] != request["center_id"]
    if state["away_since"] is not None:
        away = _number(state["away_since"])
        if away > observed_at:
            return "VETO"
        needs_return = needs_return or observed_at - away >= away_limit
    progress = _number(state["last_progress_at"])
    if progress > observed_at:
        return "VETO"
    if observed_at - progress >= idle_limit:
        if state["node_id"] in window["center_nodes"]:
            return "VETO"
        needs_return = True
    if needs_return and edge["destination"] not in window["center_nodes"]:
        return "VETO"
    return "SUPPORT"


def evaluate_fixture(request: dict[str, Any], evidence: dict[str, Any]) -> tuple[str, str, float]:
    """Check only bounded exported fixtures; the digest commits to this evidence."""
    _request(request)
    evidence_digest = digest(evidence)
    observed_at = request["issued_at"]
    try:
        observed_at = evidence.get("observed_at", observed_at)
        observed = _number(observed_at)
        if not request["issued_at"] <= observed < request["valid_until"]:
            return "UNKNOWN", evidence_digest, request["issued_at"]
        projection = _projection(request, evidence)
        if projection is None:
            return "UNKNOWN", evidence_digest, observed_at
        verifier = {"reality": _reality, "continuity": _continuity, "projection": _forecast}[request["role"]]
        return verifier(request, evidence, projection, observed), evidence_digest, observed_at
    except ControlError as error:
        # The message is internal and never copied into the signed output.
        verdict = "VETO" if str(error) == "contradictory projection binding" else "UNKNOWN"
        return verdict, evidence_digest, request["issued_at"]
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return "UNKNOWN", evidence_digest, request["issued_at"]


def _worker_command() -> list[str]:
    # -I ignores user PYTHON* variables and current-directory import injection.
    sdk_path = str(Path(__file__).resolve().parents[1])
    bootstrap = ("import runpy,sys;sys.path.insert(0," + repr(sdk_path) + ");"
                 "runpy.run_module('liminal_agent_control.observer_process',run_name='__main__')")
    return [sys.executable, "-I", "-c", bootstrap]


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    finally:
        process.wait()


def _exchange(process: subprocess.Popen[bytes], wire: bytes, timeout: float) -> tuple[bytes, bytes, str | None]:
    """Drain pipes incrementally; neither communicate nor an unbounded reader."""
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_REPORT_BYTES, "stderr": MAX_STDERR_BYTES}
    sent = 0
    with selectors.DefaultSelector() as selector:
        for name, stream, event in (("stdin", process.stdin, selectors.EVENT_WRITE),
                                    ("stdout", process.stdout, selectors.EVENT_READ),
                                    ("stderr", process.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b"", b"", "OBSERVER_PROCESS_TIMEOUT"
            for key, _ in selector.select(min(remaining, 0.05)):
                name, stream = key.data, key.fileobj
                try:
                    if name == "stdin":
                        sent += os.write(stream.fileno(), wire[sent:sent + 16384])
                        if sent == len(wire):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), min(4096, limits[name] - len(buffers[name]) + 1))
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            buffers[name].extend(chunk)
                            if len(buffers[name]) > limits[name]:
                                return b"", b"", "OBSERVER_PROCESS_OUTPUT_LIMIT"
                except BlockingIOError:
                    continue
                except BrokenPipeError:
                    selector.unregister(stream)
                    stream.close()
            if process.poll() is not None and "stdin" in [key.data for key in selector.get_map().values()]:
                selector.unregister(process.stdin)
                process.stdin.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return b"", b"", "OBSERVER_PROCESS_TIMEOUT"
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            return b"", b"", "OBSERVER_PROCESS_TIMEOUT"
    return bytes(buffers["stdout"]), bytes(buffers["stderr"]), None


def _envelope(value: Any, request: dict[str, Any], evidence_digest: str) -> bool:
    if (not isinstance(value, dict)
            or set(value) != {"request", "verdict", "evidence_digest", "observed_at", "valid_until", "signature"}
            or canonical_bytes(value.get("request")) != canonical_bytes(request)
            or value.get("verdict") not in {"SUPPORT", "UNKNOWN", "VETO"}
            or value.get("evidence_digest") != evidence_digest
            or not isinstance(value.get("signature"), str) or not _HEX128.fullmatch(value["signature"])):
        return False
    try:
        observed_at, valid_until = _number(value["observed_at"]), _number(value["valid_until"])
        return request["issued_at"] <= observed_at < valid_until == request["valid_until"]
    except ControlError:
        return False


def run_observer(request: dict[str, Any], *, private_key: bytes, evidence: dict[str, Any],
                 timeout_seconds: float = 2) -> dict[str, Any]:
    """Return a bounded signed fixture statement, or no statement plus HOLD.

The trusted host must cryptographically ingest any returned envelope through
ObserverAuthStore. This runner validates output syntax and evidence binding only;
it does not authenticate reports, mutate HOLD state, or authorize an effect.
"""
    metadata = {"pid": None, "role": request.get("role") if isinstance(request, dict) else None,
                "exit_code": None, "status": "HOLD", "reason": "OBSERVER_PROCESS_INPUT_INVALID"}
    result = {"envelope": None, "process": metadata, "execution_authorized": False}
    try:
        _request(request)
        timeout = _number(timeout_seconds)
        if not 0 < timeout <= 10 or not isinstance(private_key, bytes) or len(private_key) != 32:
            return result
        if not isinstance(evidence, dict):
            return result
        public = canonical_bytes({"request": request, "evidence": evidence})
        if len(public) > MAX_PUBLIC_INPUT_BYTES:
            metadata["reason"] = "OBSERVER_PROCESS_INPUT_LIMIT"
            return result
        wire = canonical_bytes({"request": request, "evidence": evidence, "private_key": private_key.hex()})
    except (ControlError, TypeError, ValueError, OverflowError, RecursionError):
        return result
    process = None
    try:
        process = subprocess.Popen(_worker_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, close_fds=True,
                                   start_new_session=True, cwd=str(Path(__file__).resolve().parents[1]),
                                   env={"LC_ALL": "C.UTF-8"})
        metadata["pid"] = process.pid
        stdout, stderr, failure = _exchange(process, wire, timeout)
        if failure:
            _kill_and_reap(process)
            metadata["exit_code"], metadata["reason"] = process.returncode, failure
            return result
        metadata["exit_code"] = process.returncode
        if process.returncode != 0 or stderr:
            metadata["reason"] = "OBSERVER_PROCESS_FAILED"
            return result
        try:
            value = json.loads(stdout)
            if not _envelope(value, request, digest(evidence)):
                raise ControlError("invalid observer report")
        except (ControlError, TypeError, ValueError, OverflowError, RecursionError):
            metadata["reason"] = "OBSERVER_PROCESS_REPORT_INVALID"
            return result
        result["envelope"] = value
        metadata.update(status="PASS", reason=None)
        return result
    except (OSError, ValueError):
        if process is not None:
            _kill_and_reap(process)
            metadata["exit_code"] = process.returncode
        metadata["reason"] = "OBSERVER_PROCESS_FAILED"
        return result
    finally:
        if process is not None:
            # Reap the parent and kill any same-group descendant even when a
            # broken worker returned a valid report and closed all output pipes.
            _kill_and_reap(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def _worker_main() -> int:
    try:
        raw = sys.stdin.buffer.read(_MAX_WIRE_BYTES + 1)
        if len(raw) > _MAX_WIRE_BYTES:
            return 2
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {"request", "evidence", "private_key"}:
            return 2
        request, evidence = _request(payload["request"]), payload["evidence"]
        if not isinstance(evidence, dict) or len(canonical_bytes({"request": request, "evidence": evidence})) > MAX_PUBLIC_INPUT_BYTES:
            return 2
        if not isinstance(payload["private_key"], str) or not _HEX64.fullmatch(payload["private_key"]):
            return 2
        from .observer_auth import sign_attestation
        verdict, evidence_digest, observed_at = evaluate_fixture(request, evidence)
        envelope = sign_attestation(request, private_key=bytes.fromhex(payload["private_key"]),
                                    verdict=verdict, evidence_digest=evidence_digest,
                                    observed_at=observed_at, valid_until=request["valid_until"])
        report = canonical_bytes(envelope)
        if len(report) > MAX_REPORT_BYTES:
            return 2
        sys.stdout.buffer.write(report)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Never print request/evidence/key material or implementation exceptions.
        return 2


if __name__ == "__main__":
    raise SystemExit(_worker_main())
