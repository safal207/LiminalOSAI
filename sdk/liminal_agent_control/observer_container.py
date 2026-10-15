"""Trusted-host Docker observers with keys created inside separate containers.

The host selects a prebuilt immutable image, fixed SDK code and one public source
directory per role. No private key crosses the enrollment/attestation protocol.
The Docker daemon and host collector remain trusted; this is container isolation,
not VM isolation, independence of source ownership, or a Docker-escape proof.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid
from typing import Any

from .authority import ControlError, canonical_bytes, digest, validate_id
from .observer_process import (_exchange, _kill_and_reap, _number, _request,
                               evaluate_fixture, MAX_REPORT_BYTES, MAX_STDERR_BYTES)


MAX_CHALLENGE_BYTES = 16384
MAX_SOURCE_BYTES = 262144
PRIVATE_KEY_PATH = "/tmp/observer-private/key.bin"
SOURCE_DIRECTORY = "/evidence"
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = frozenset({"reality", "continuity", "projection"})
_BOOTSTRAP = ("import runpy,sys;sys.path.insert(0,'/sdk');"
              "runpy.run_module('liminal_agent_control.observer_container',run_name='__main__')")


def _directory(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or str(path) != str(path.resolve(strict=True)) or not path.is_dir():
        raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    # Reject symlink components even when '..' or a root link resolves to the same
    # textual target, and reject current source entries that Docker could follow.
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    for entry in path.iterdir():
        if (entry.is_symlink() or not entry.is_file()
                or re.fullmatch(r"[0-9a-f]{64}\.json", entry.name) is None
                or entry.stat().st_size > MAX_SOURCE_BYTES):
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    if any(char in str(path) for char in (",", "\n", "\r", "\x00")):
        raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    return path


def validate_source_directories(directories: list[str | Path] | tuple[str | Path, ...]
                                | dict[str, str | Path]) -> list[Path]:
    """Validate the whole provisioned ring before starting any service.

    A single adapter cannot discover sibling mounts. The trusted provisioning
    caller must submit every role directory here; all must be distinct and no
    directory may contain another role directory or the SDK source tree.
    """
    if isinstance(directories, dict):
        values = list(directories.values())
    elif isinstance(directories, (list, tuple)):
        values = list(directories)
    else:
        raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    if not 1 <= len(values) <= 256:
        raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
    result = [_directory(value) for value in values]
    sdk = Path(__file__).resolve().parents[1]
    for index, first in enumerate(result):
        if first == sdk or first in sdk.parents or sdk in first.parents:
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
        for second in result[index + 1:]:
            if first == second or first in second.parents or second in first.parents:
                raise ControlError("OBSERVER_CONTAINER_SOURCE_OVERLAP")
    return result


def _receiver_export(request: dict[str, Any], payload: dict[str, Any], *,
                     issuer_pin: dict[str,str] | None = None, now: float | None = None) -> str:
    """Check receiver exports without receiving a receiver private key.

    The source binding pins the collector's complete packet, including its host
    verification assertion. This observer checks export consistency; it does not
    independently authenticate the receiver in legacy mode or equate graph revisions with the
    count of records (other channels have different effect evidence).
    A fixed issuer pin instead requires a challenge-bound receiver signature;
    it never trusts the collector's verification flag or a packet-carried key.
    """
    records, snapshot = payload.get("receiver_records"), payload.get("receiver_snapshot")
    if issuer_pin is not None:
        from .receiver_source import verify_source_statement
        statement=verify_source_statement(request,payload.get('receiver_source_statement'),issuer_pin,
                                          now=time.time() if now is None else now)
        if (canonical_bytes({'receiver_records':records,'receiver_snapshot':snapshot})
                != canonical_bytes(statement['export'])):
            raise ControlError('RECEIVER_SOURCE_EXPORT_MISMATCH')
    if (not isinstance(records, list) or not isinstance(snapshot, dict)
            or (issuer_pin is None and payload.get("receiver_snapshot_verified_by_host") is not True)):
        return "UNKNOWN"
    fields = {"schema", "root_id", "execution_id", "epoch", "complete", "receipts",
              "accepted_action_ids", "receiver_id", "cutoff", "signature", "key_id",
              "enforcement_profile", "observed_at"}
    if (not fields <= set(snapshot) or not isinstance(snapshot["receipts"], list)
            or not isinstance(snapshot["accepted_action_ids"], list)
            or type(snapshot["epoch"]) is not int or type(snapshot["cutoff"]) is not int
            or snapshot["cutoff"] < 0 or not isinstance(snapshot["receiver_id"], str)
            or not snapshot["receiver_id"]):
        return "UNKNOWN"
    if (not isinstance(snapshot["signature"], str) or not _HEX64.fullmatch(snapshot["signature"])
            or snapshot["key_id"] != "receiver-hmac-v1" or snapshot["enforcement_profile"] != "governed_v1"):
        return "UNKNOWN"
    # Receiver wall-clock metadata is distinct from the controlled authority
    # clock. Require a finite timestamp, without conflating their age domains.
    _number(snapshot["observed_at"])
    if (snapshot["schema"] != "liminal.agent-control.snapshot.v1"
            or snapshot["root_id"] != request["root_id"]
            or snapshot["execution_id"] != request["execution_id"] or snapshot["epoch"] != request["epoch"]):
        return "VETO"
    if snapshot["complete"] is not True:
        return "UNKNOWN"
    accepted = snapshot["accepted_action_ids"]
    if any(not isinstance(item, str) or not item for item in accepted):
        return "UNKNOWN"
    if len(set(accepted)) != len(accepted):
        return "VETO"
    if accepted:
        return "UNKNOWN"  # Accepted effects still lack a committed observation.
    scoped = {}
    for record in records:
        if (not isinstance(record, dict) or not {"action", "arguments", "receipt"} <= set(record)
                or not isinstance(record["action"], dict) or not isinstance(record["receipt"], dict)
                or not isinstance(record["arguments"], dict)):
            return "UNKNOWN"
        action, receipt = record["action"], record["receipt"]
        if not {"root_id", "execution_id", "epoch", "action_id", "attempt_id", "arguments"} <= set(action):
            return "UNKNOWN"
        if (action["root_id"], action["execution_id"], action["epoch"]) != (
                request["root_id"], request["execution_id"], request["epoch"]):
            continue
        if not isinstance(action["action_id"], str) or not action["action_id"] or action["action_id"] in scoped:
            return "VETO"
        if (type(action["epoch"]) is not int
                or canonical_bytes(record["arguments"]) != canonical_bytes(action["arguments"])
                or receipt.get("schema") != "liminal.agent-control.receipt.v1"
                or receipt.get("status") != "COMMITTED" or type(receipt.get("effect_count")) is not int
                or receipt["effect_count"] != 1 or receipt.get("action_digest") != digest(action)
                or receipt.get("receiver_id") != snapshot["receiver_id"]
                or any(type(receipt.get(field)) is not type(action[field]) or receipt.get(field) != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            return "VETO"
        scoped[action["action_id"]] = receipt
    observed = {}
    for receipt in snapshot["receipts"]:
        if not isinstance(receipt, dict) or not isinstance(receipt.get("action_id"), str):
            return "UNKNOWN"
        action_id = receipt["action_id"]
        if action_id in observed or action_id not in scoped or canonical_bytes(receipt) != canonical_bytes(scoped[action_id]):
            return "VETO"
        observed[action_id] = receipt
    if set(observed) != set(scoped) or snapshot["cutoff"] < len(observed):
        return "VETO"
    return "SUPPORT"


def evaluate_source_packet(request: dict[str, Any], packet: dict[str, Any], *,
                           issuer_pin: dict[str,str] | None = None,
                           now: float | None = None) -> tuple[str, str, float]:
    """Require each role's collected source before a fixture can give SUPPORT."""
    from .observer_sources import validate_source_packet
    packet = validate_source_packet(request, packet)
    if issuer_pin is not None and request['role']!='reality':
        raise ControlError('RECEIVER_SOURCE_ROLE_MISMATCH')
    payload = packet["payload"]
    fixture_verdict, _, observed_at = evaluate_fixture(request, payload)
    source_verdict = "UNKNOWN"
    try:
        if request["role"] == "reality":
            if issuer_pin is not None:
                from .receiver_source import validate_issuer_pin
                pin=validate_issuer_pin(issuer_pin)
                statement=payload.get('receiver_source_statement')
                if (packet['source_id']!=pin['source_id'] or not isinstance(statement,dict)
                        or canonical_bytes(packet['observed_at'])!=canonical_bytes(statement.get('issued_at'))):
                    raise ControlError('RECEIVER_SOURCE_BINDING_MISMATCH')
            source_verdict = _receiver_export(request, payload,issuer_pin=issuer_pin,now=now)
        elif request["role"] == "continuity":
            if payload.get("collector_kind") == "append-only exported audit copy":
                source_verdict = "SUPPORT"
        elif request["role"] == "projection":
            if payload.get("collector_kind") == "installed immutable policy export":
                source_verdict = "SUPPORT"
    except (ControlError, TypeError, ValueError, OverflowError, RecursionError):
        source_verdict = "UNKNOWN"
    verdict = ("VETO" if "VETO" in (fixture_verdict, source_verdict)
               else "SUPPORT" if fixture_verdict == source_verdict == "SUPPORT" else "UNKNOWN")
    if issuer_pin is not None:
        observed_at = max(observed_at,_number(packet['observed_at']))
    return verdict, digest(packet), observed_at


class DockerObserver:
    """One enrollment and persistent service; replacement requires new enrollment.

    The Docker executable is a trusted-host setting, never an agent tool argument.
    The caller must authenticate and bind source statements through the authority
    stores before any effect. This adapter does not mutate authority or execute
    agent actions. Provisioning must call validate_source_directories with the
    complete ring before starting its first service.
    """

    def __init__(self, *, image_id: str, observer_id: str, role: str, key_id: str,
                 source_directory: str | Path, timeout_seconds: float = 5,
                 docker_binary: str = "docker", source_issuer: dict[str,str] | None = None) -> None:
        if not isinstance(image_id, str) or not _IMAGE.fullmatch(image_id) or role not in _ROLES:
            raise ControlError("OBSERVER_CONTAINER_CONFIGURATION_INVALID")
        validate_id(observer_id, "observer_id")
        validate_id(key_id, "key_id")
        self._source_issuer=None
        if source_issuer is not None:
            from .receiver_source import validate_issuer_pin
            if role!='reality':
                raise ControlError('RECEIVER_SOURCE_ROLE_MISMATCH')
            self._source_issuer=validate_issuer_pin(source_issuer)
        timeout = _number(timeout_seconds)
        if not 0 < timeout <= 30:
            raise ControlError("OBSERVER_CONTAINER_CONFIGURATION_INVALID")
        if not isinstance(docker_binary, str) or not docker_binary or any(c in docker_binary for c in "\n\r\x00"):
            raise ControlError("OBSERVER_CONTAINER_CONFIGURATION_INVALID")
        resolved_binary = shutil.which(docker_binary)
        if resolved_binary is None:
            raise ControlError("OBSERVER_CONTAINER_DOCKER_UNAVAILABLE")
        self.docker_binary = str(Path(resolved_binary).resolve())
        self.image_id, self.observer_id, self.role, self.key_id = image_id, observer_id, role, key_id
        self.source_directory = _directory(source_directory)
        self.sdk_directory = Path(__file__).resolve().parents[1]
        if (self.sdk_directory == self.source_directory
                or self.sdk_directory in self.source_directory.parents
                or self.source_directory in self.sdk_directory.parents):
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNSAFE")
        self.timeout_seconds = timeout
        self.container_name = "liminal-observer-" + uuid.uuid4().hex
        self.container_id: str | None = None
        self.enrollment: dict[str, str] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._started = False
        self._closed = False
        self.last_cleanup: dict[str, Any] | None = None
        self.lifecycle: Any = None  # Installed only by the trusted managed ring.

    @property
    def source_issuer(self) -> dict[str,str] | None:
        return None if self._source_issuer is None else json.loads(canonical_bytes(self._source_issuer))

    def create_command(self) -> list[str]:
        """Reviewable fixed host command; no agent-provided flags or commands."""
        labels = ([] if self.lifecycle is None else [argument for key, value in self.lifecycle.labels().items()
                   for argument in ("--label", key + "=" + value)])
        issuer = ([] if self._source_issuer is None else
                  ['--source-issuer',canonical_bytes(self._source_issuer).decode()])
        return [self.docker_binary, "create", "-i", "--name", self.container_name, *labels,
                "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--user=65532:65532", "--pids-limit=16",
                "--memory=128m", "--memory-swap=128m", "--cpus=0.25",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700",
                "--mount=type=bind,src=" + str(self.sdk_directory) + ",dst=/sdk,readonly",
                "--mount=type=bind,src=" + str(self.source_directory) + ",dst=/evidence,readonly",
                "--entrypoint=/usr/local/bin/python", self.image_id,
                "-I", "-c", _BOOTSTRAP, "--container-worker",
                "--observer-id=" + self.observer_id, "--role=" + self.role, "--key-id=" + self.key_id, *issuer]

    @staticmethod
    def _spawn(command: list[str]) -> subprocess.Popen[bytes]:
        return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, close_fds=True,
                                start_new_session=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})

    def _command(self, command: list[str]) -> tuple[int | None, bytes, str | None]:
        process = None
        try:
            process = self._spawn(command)
            output, stderr, failure = _exchange(process, b"", self.timeout_seconds)
            if failure:
                return None, b"", failure
            return process.returncode, output, None if not stderr else "OBSERVER_CONTAINER_CLI_ERROR"
        except (OSError, ValueError):
            return None, b"", "OBSERVER_CONTAINER_CLI_ERROR"
        finally:
            if process is not None:
                _kill_and_reap(process)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()

    def _line(self, wire: bytes | None = None) -> bytes:
        process = self._process
        if process is None or process.poll() is not None:
            raise ControlError("OBSERVER_CONTAINER_NOT_RUNNING")
        deadline, sent = time.monotonic() + self.timeout_seconds, 0
        output, errors = bytearray(), bytearray()
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if wire is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControlError("OBSERVER_CONTAINER_TIMEOUT")
                line = None
                for selected, _ in selector.select(min(remaining, 0.05)):
                    name, stream = selected.data, selected.fileobj
                    try:
                        if name == "stdin":
                            sent += os.write(stream.fileno(), wire[sent:sent + 4096])
                            if sent == len(wire):
                                selector.unregister(stream)
                        else:
                            target, limit = (output, MAX_REPORT_BYTES) if name == "stdout" else (errors, MAX_STDERR_BYTES)
                            chunk = os.read(stream.fileno(), min(4096, limit - len(target) + 1))
                            if not chunk:
                                raise ControlError("OBSERVER_CONTAINER_NOT_RUNNING")
                            target.extend(chunk)
                            if len(target) > limit:
                                raise ControlError("OBSERVER_CONTAINER_OUTPUT_LIMIT")
                            if name == "stdout" and b"\n" in output:
                                line, trailing = bytes(output).split(b"\n", 1)
                                if trailing:
                                    raise ControlError("OBSERVER_CONTAINER_REPORT_INVALID")
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError) as exc:
                        raise ControlError("OBSERVER_CONTAINER_NOT_RUNNING") from exc
                if errors:
                    raise ControlError("OBSERVER_CONTAINER_CLI_ERROR")
                if line is not None:
                    if wire is not None and sent != len(wire):
                        raise ControlError("OBSERVER_CONTAINER_REPORT_INVALID")
                    if process.poll() is not None:
                        raise ControlError("OBSERVER_CONTAINER_NOT_RUNNING")
                    return line
                if process.poll() is not None:
                    raise ControlError("OBSERVER_CONTAINER_NOT_RUNNING")

    def start(self) -> dict[str, str]:
        if self._started or self._closed:
            raise ControlError("OBSERVER_CONTAINER_RESTART_FORBIDDEN")
        self._started = True
        try:
            _directory(self.source_directory)
            if self.lifecycle is not None:
                self.lifecycle.prepare()
            code, output, failure = self._command(self.create_command())
            container_id = output.decode("ascii", errors="strict").strip()
            if code != 0 or failure or not _HEX64.fullmatch(container_id):
                raise ControlError("OBSERVER_CONTAINER_CREATE_FAILED")
            self.container_id = container_id
            if self.lifecycle is not None:
                self.lifecycle.created(container_id)
            self._process = self._spawn([self.docker_binary, "start", "-a", "-i", container_id])
            enrollment = json.loads(self._line())
            if (not isinstance(enrollment, dict)
                    or set(enrollment) != {"observer_id", "role", "key_id", "public_key"}
                    or enrollment["observer_id"] != self.observer_id or enrollment["role"] != self.role
                    or enrollment["key_id"] != self.key_id or not isinstance(enrollment["public_key"], str)
                    or not _HEX64.fullmatch(enrollment["public_key"])):
                raise ControlError("OBSERVER_CONTAINER_ENROLLMENT_INVALID")
            self.enrollment = enrollment
            if self.lifecycle is not None:
                self.lifecycle.enrolled(enrollment)
            return dict(enrollment)
        except (ControlError, OSError, ValueError, TypeError, UnicodeError) as exc:
            self.stop()
            reason = str(exc) if isinstance(exc, ControlError) else "OBSERVER_CONTAINER_START_FAILED"
            if not self.last_cleanup["removed"]:
                reason += "/OBSERVER_CONTAINER_CLEANUP_UNVERIFIED"
            raise ControlError(reason) from exc

    def attest(self, request: dict[str, Any]) -> dict[str, Any]:
        metadata = {"container_id": self.container_id, "status": "HOLD", "reason": "OBSERVER_CONTAINER_INPUT_INVALID"}
        result = {"envelope": None, "process": metadata, "execution_authorized": False}
        try:
            if self.lifecycle is not None:
                self.lifecycle.check(request)
            _request(request)
            wire = canonical_bytes(request)
            if (len(wire) > MAX_CHALLENGE_BYTES or request["observer_id"] != self.observer_id
                    or request["role"] != self.role or request["key_id"] != self.key_id):
                return result
        except (ControlError, TypeError, ValueError, OverflowError, RecursionError):
            if self.lifecycle is not None:
                self.stop()
            return result
        if self._closed or self.enrollment is None:
            metadata["reason"] = "OBSERVER_CONTAINER_NOT_RUNNING"
            return result
        try:
            response = json.loads(self._line(wire + b"\n"))
            if (not isinstance(response, dict) or set(response) != {"envelope", "status", "reason", "execution_authorized"}
                    or response["execution_authorized"] is not False):
                raise ControlError("OBSERVER_CONTAINER_REPORT_INVALID")
            if response["status"] == "HOLD" and response["envelope"] is None:
                metadata["reason"] = "OBSERVER_CONTAINER_SOURCE_UNAVAILABLE"
                return result
            from .observer_auth import _verify
            from .observer_process import _envelope
            envelope = response["envelope"]
            if (response["status"] != "PASS" or response["reason"] is not None
                    or not isinstance(envelope, dict) or not isinstance(envelope.get("evidence_digest"), str)
                    or not _HEX64.fullmatch(envelope["evidence_digest"])
                    or not _envelope(envelope, request, envelope["evidence_digest"])):
                raise ControlError("OBSERVER_CONTAINER_REPORT_INVALID")
            _verify(envelope, self.enrollment["public_key"])
            if self.lifecycle is not None:
                self.lifecycle.check(request)
            result["envelope"] = envelope
            metadata.update(status="PASS", reason=None)
            return result
        except (ControlError, OSError, TypeError, ValueError, OverflowError, RecursionError) as exc:
            metadata["reason"] = str(exc) if isinstance(exc, ControlError) else "OBSERVER_CONTAINER_REPORT_INVALID"
            cleanup = self.stop()
            metadata["cleanup_verified"] = cleanup["removed"]
            return result

    def stop(self) -> dict[str, Any]:
        """Remove by random name even if attach/create CLI already exited."""
        self._closed = True
        if self._process is not None:
            _kill_and_reap(self._process)
            for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if self.lifecycle is not None:
            self.last_cleanup = self.lifecycle.close()
            return dict(self.last_cleanup)
        self._command([self.docker_binary, "rm", "--force", self.container_name])
        code, output, failure = self._command([self.docker_binary, "container", "ls", "--all",
            "--filter", "name=^/" + self.container_name + "$", "--format", "{{.ID}}"])
        removed = code == 0 and failure is None and not output.strip()
        self.last_cleanup = {"container_id": self.container_id, "removed": removed, "execution_authorized": False}
        return dict(self.last_cleanup)


def _source_packet(request: dict[str, Any]) -> dict[str, Any]:
    """Read a nonce-named regular file, never a request-selected source path."""
    nonce = request["nonce"]
    if not isinstance(nonce, str) or not _HEX64.fullmatch(nonce):
        raise ControlError("OBSERVER_CONTAINER_SOURCE_UNAVAILABLE")
    path = str(Path(SOURCE_DIRECTORY) / (nonce + ".json"))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNAVAILABLE")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ControlError("OBSERVER_CONTAINER_SOURCE_UNAVAILABLE")
        from .observer_sources import validate_source_packet
        return validate_source_packet(request, json.loads(raw))
    finally:
        os.close(fd)


def _new_private_key() -> tuple[bytes, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes_raw()
    directory = Path(PRIVATE_KEY_PATH).parent
    os.mkdir(directory, 0o700)
    fd = os.open(PRIVATE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, private_key)
    finally:
        os.close(fd)
    return private_key, key.public_key().public_bytes_raw().hex()


def _container_worker(observer_id: str, role: str, key_id: str,
                       source_issuer: dict[str,str] | None = None) -> int:
    try:
        validate_id(observer_id, "observer_id")
        validate_id(key_id, "key_id")
        if role not in _ROLES:
            return 2
        if source_issuer is not None:
            from .receiver_source import validate_issuer_pin
            if role!='reality':
                return 2
            source_issuer=validate_issuer_pin(source_issuer)
        private_key, public_key = _new_private_key()
        enrollment = {"observer_id": observer_id, "role": role, "key_id": key_id, "public_key": public_key}
        sys.stdout.buffer.write(canonical_bytes(enrollment) + b"\n")
        sys.stdout.buffer.flush()
        for _ in range(1024):
            raw = sys.stdin.buffer.readline(MAX_CHALLENGE_BYTES + 2)
            if not raw:
                return 0
            if len(raw) > MAX_CHALLENGE_BYTES + 1 or not raw.endswith(b"\n"):
                return 2
            response = {"envelope": None, "status": "HOLD", "reason": "SOURCE_UNAVAILABLE", "execution_authorized": False}
            try:
                request = _request(json.loads(raw))
                if (request["observer_id"] != observer_id or request["role"] != role or request["key_id"] != key_id):
                    raise ControlError("observer identity mismatch")
                packet = _source_packet(request)
                verdict, evidence_digest, observed_at = evaluate_source_packet(request, packet,issuer_pin=source_issuer)
                from .observer_auth import sign_attestation
                envelope = sign_attestation(request, private_key=private_key, verdict=verdict,
                    evidence_digest=evidence_digest, observed_at=observed_at, valid_until=request["valid_until"])
                response.update(envelope=envelope, status="PASS", reason=None)
            except (ControlError, OSError, TypeError, ValueError, OverflowError, RecursionError):
                pass  # Never disclose source contents, paths, key bytes or errors.
            report = canonical_bytes(response)
            if len(report) > MAX_REPORT_BYTES:
                return 2
            sys.stdout.buffer.write(report + b"\n")
            sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fixed isolated observer service")
    parser.add_argument("--container-worker", action="store_true", required=True)
    parser.add_argument("--observer-id", required=True)
    parser.add_argument("--role", required=True, choices=sorted(_ROLES))
    parser.add_argument("--key-id", required=True)
    parser.add_argument('--source-issuer',type=json.loads,default=None)
    args = parser.parse_args()
    raise SystemExit(_container_worker(args.observer_id, args.role, args.key_id,args.source_issuer))
