"""Loopback-only external STOP service and pinned, challenge-bound clients.

Receiver and operator keys have different roles. Responses are Ed25519 signed
under an authority-specific domain and bound to the complete fresh request;
receiver-source evidence signatures cannot authorize actions here. Deploy the
service, its keys and database under an owner inaccessible to workers.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .authority import ControlError, canonical_bytes, digest, require_key
from .external_authority import ExternalAuthorityStore, _hex, _time, validate_authority_pin
from .observer_auth import _crypto


REQUEST_SCHEMA = "liminal-external-authority-request-v1"
RESPONSE_SCHEMA = "liminal-external-authority-response-v1"
REQUEST_DOMAIN = b"liminal-external-authority-request-v1\x00"
RESPONSE_DOMAIN = b"liminal-external-authority-response-v1\x00"
MAX_REQUEST_BYTES = 32768
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_REQUEST_FIELDS = {"schema", "role", "operation", "nonce", "payload", "signature"}
_RESPONSE_FIELDS = {"schema", "authority_id", "key_id", "operation", "request_digest", "issued_at", "result", "signature"}
_RECEIVER_OPERATIONS = {"begin", "finish", "query"}
_OPERATOR_OPERATIONS = {"create_root", "bind_execution", "stop", "status", "checkpoints"}


def _request_signature(body: dict[str, Any], key: bytes) -> str:
    return hmac.new(require_key(key), REQUEST_DOMAIN + canonical_bytes(body), hashlib.sha256).hexdigest()


def verify_authority_response(request: dict[str, Any], response: Any, pin: dict[str, str]) -> dict[str, Any]:
    """Authenticate an exact fresh challenge; only authority time governs grants.

    No caller-local clock is a permission source. A random nonce prevents old
    signed responses from satisfying a new challenge; network timeout bounds a
    single request. Live client results alone are used, never restored packets.
    """
    pin = validate_authority_pin(pin)
    if (not isinstance(response, dict) or set(response) != _RESPONSE_FIELDS
            or len(canonical_bytes(response)) > MAX_RESPONSE_BYTES
            or response["schema"] != RESPONSE_SCHEMA
            or response["authority_id"] != pin["authority_id"] or response["key_id"] != pin["key_id"]
            or response["operation"] != request["operation"]
            or response["request_digest"] != digest({k: v for k, v in request.items() if k != "signature"})
            or not isinstance(response["result"], dict)):
        raise ControlError("EXTERNAL_AUTHORITY_RESPONSE_BINDING_MISMATCH")
    _hex(response["signature"], 128)
    _time(response["issued_at"])
    _, public = _crypto()
    body = {k: v for k, v in response.items() if k != "signature"}
    try:
        public.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(
            bytes.fromhex(response["signature"]), RESPONSE_DOMAIN + canonical_bytes(body))
    except Exception as exc:
        raise ControlError("EXTERNAL_AUTHORITY_RESPONSE_SIGNATURE_INVALID") from exc
    return json.loads(canonical_bytes(response["result"]))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ControlError("EXTERNAL_AUTHORITY_REDIRECT_FORBIDDEN")


class HTTPExternalAuthorityClient:
    def __init__(self, url: str, request_key: bytes, pin: dict[str, str], *, timeout: float = 3,
                 role: str = "receiver") -> None:
        parsed = urlparse(url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_INVALID")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ControlError("EXTERNAL_AUTHORITY_TIMEOUT_INVALID")
        if role not in ("receiver", "admin"):
            raise ControlError("EXTERNAL_AUTHORITY_ROLE_INVALID")
        self.url = url.rstrip("/")
        self._request_key = require_key(request_key)
        self._pin = validate_authority_pin(pin)
        self.timeout, self.role = float(timeout), role
        # Public authenticated evidence for bounded pilots/offline verification.
        # Request HMACs are credentials, so only response packets are retained.
        self._responses: list[dict[str, Any]] = []
        self._evidence: list[dict[str, Any]] = []
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def pin(self) -> dict[str, str]:
        return dict(self._pin)

    @property
    def request_key(self) -> bytes:
        """Trusted receiver configuration only; never publish this property."""
        return self._request_key

    @property
    def responses(self) -> list[dict[str, Any]]:
        return json.loads(canonical_bytes(self._responses))

    @property
    def evidence(self) -> list[dict[str, Any]]:
        return json.loads(canonical_bytes(self._evidence))

    @property
    def last_statement(self) -> dict[str, Any] | None:
        return None if not self._responses else json.loads(canonical_bytes(self._responses[-1]))

    def _call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        allowed = _RECEIVER_OPERATIONS if self.role == "receiver" else _OPERATOR_OPERATIONS
        if operation not in allowed:
            raise ControlError("EXTERNAL_AUTHORITY_ROLE_DENIED")
        body = {"schema": REQUEST_SCHEMA, "role": self.role, "operation": operation,
                "nonce": secrets.token_hex(32), "payload": payload}
        packet = {**body, "signature": _request_signature(body, self._request_key)}
        wire = canonical_bytes(packet)
        if len(wire) > MAX_REQUEST_BYTES:
            raise ControlError("EXTERNAL_AUTHORITY_REQUEST_TOO_LARGE")
        request = Request(self.url + "/v1/authority", data=wire, method="POST", headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as incoming:
                if incoming.status != 200 or incoming.geturl() != self.url + "/v1/authority":
                    raise ControlError("EXTERNAL_AUTHORITY_RESPONSE_INVALID")
                raw = incoming.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ControlError("EXTERNAL_AUTHORITY_RESPONSE_TOO_LARGE")
            response = json.loads(raw)
            result = verify_authority_response(packet, response, self._pin)
            self._responses.append(response)
            self._evidence.append({"request": body, "response": response})
            if len(self._responses) > 1024:
                self._responses.pop(0)
                self._evidence.pop(0)
            if result.get("status") == "ERROR":
                raise ControlError(result.get("reason", "EXTERNAL_AUTHORITY_REFUSED"))
            return result
        except ControlError:
            raise
        except (HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            raise ControlError("EXTERNAL_AUTHORITY_UNAVAILABLE") from exc

    def begin(self, action: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any]:
        return self._call("begin", {"action": action, "authorization": authorization})

    def finish(self, reservation_id: str, receipt: dict[str, Any]) -> dict[str, Any]:
        return self._call("finish", {"reservation_id": reservation_id, "receipt": receipt})

    def query(self, action_id: str) -> dict[str, Any]:
        return self._call("query", {"action_id": action_id})

    def create_root(self, root_id: str, receiver_id: str, policy_digest: str, max_actions: int,
                    lifetime_seconds: float) -> dict[str, Any]:
        return self._call("create_root", {"root_id": root_id, "receiver_id": receiver_id,
            "policy_digest": policy_digest, "max_actions": max_actions, "lifetime_seconds": lifetime_seconds})

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        return self._call("bind_execution", {"root_id": root_id, "execution_id": execution_id,
                                             "parent_execution_id": parent_execution_id})

    def stop(self, root_id: str) -> dict[str, Any]:
        return self._call("stop", {"root_id": root_id})

    def status(self, root_id: str) -> dict[str, Any]:
        return self._call("status", {"root_id": root_id})

    def checkpoints(self) -> list[dict[str, Any]]:
        result = self._call("checkpoints", {})
        return result["entries"]


def _dispatch(store: ExternalAuthorityStore, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "begin": {"action", "authorization"}, "finish": {"reservation_id", "receipt"},
        "query": {"action_id"}, "create_root": {"root_id", "receiver_id", "policy_digest", "max_actions", "lifetime_seconds"},
        "bind_execution": {"root_id", "execution_id", "parent_execution_id"},
        "stop": {"root_id"}, "status": {"root_id"}, "checkpoints": set(),
    }
    if operation not in fields or not isinstance(payload, dict) or set(payload) != fields[operation]:
        raise ControlError("EXTERNAL_AUTHORITY_REQUEST_INVALID")
    if operation == "checkpoints":
        return {"status": "CHECKPOINTS", "entries": store.checkpoints(), "execution_authorized": False}
    return getattr(store, operation)(**payload)


def make_server(store: ExternalAuthorityStore, operator_key: bytes, receiver_key: bytes, *, port: int = 0) -> ThreadingHTTPServer:
    operator_key, receiver_key = require_key(operator_key), require_key(receiver_key)
    if len({operator_key, receiver_key, store._receipt_key, store._private_bytes}) != 4:
        raise ControlError("EXTERNAL_AUTHORITY_KEYS_MUST_DIFFER")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ControlError("EXTERNAL_AUTHORITY_PORT_INVALID")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def _write(self, code: int, payload: dict[str, Any]):
            raw = canonical_bytes(payload)
            if len(raw) > MAX_RESPONSE_BYTES:
                code, raw = 503, b'{"status":"UNAVAILABLE"}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            packet = None
            try:
                if self.path != "/v1/authority" or self.headers.get("Transfer-Encoding") is not None:
                    raise ControlError("EXTERNAL_AUTHORITY_REQUEST_INVALID")
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1:
                    raise ControlError("EXTERNAL_AUTHORITY_REQUEST_INVALID")
                size = int(lengths[0])
                if not 0 < size <= MAX_REQUEST_BYTES:
                    raise ControlError("EXTERNAL_AUTHORITY_REQUEST_TOO_LARGE")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ControlError("EXTERNAL_AUTHORITY_REQUEST_INVALID")
                packet = json.loads(raw)
                if (not isinstance(packet, dict) or set(packet) != _REQUEST_FIELDS
                        or packet["schema"] != REQUEST_SCHEMA or packet["role"] not in ("admin", "receiver")):
                    raise ControlError("EXTERNAL_AUTHORITY_REQUEST_INVALID")
                _hex(packet["nonce"])
                _hex(packet["signature"])
                body = {k: v for k, v in packet.items() if k != "signature"}
                key = operator_key if packet["role"] == "admin" else receiver_key
                if not hmac.compare_digest(packet["signature"], _request_signature(body, key)):
                    raise ControlError("EXTERNAL_AUTHORITY_AUTHENTICATION_FAILED")
                allowed = _OPERATOR_OPERATIONS if packet["role"] == "admin" else _RECEIVER_OPERATIONS
                if packet["operation"] not in allowed:
                    raise ControlError("EXTERNAL_AUTHORITY_ROLE_DENIED")
            except Exception:
                self._write(403, {"status": "REFUSED"})
                return
            try:
                result = _dispatch(store, packet["operation"], packet["payload"])
            except ControlError as exc:
                result = {"status": "ERROR", "reason": str(exc)}
            except Exception:
                result = {"status": "ERROR", "reason": "EXTERNAL_AUTHORITY_UNAVAILABLE"}
            response = {"schema": RESPONSE_SCHEMA, **{k: store.pin()[k] for k in ("authority_id", "key_id")},
                        "operation": packet["operation"], "request_digest": digest(body),
                        "issued_at": _time(store._clock()), "result": result}
            response["signature"] = store._private_key.sign(RESPONSE_DOMAIN + canonical_bytes(response)).hex()
            self._write(200, response)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 16

        def __init__(self, *args, **kwargs):
            self._slots = threading.BoundedSemaphore(16)
            super().__init__(*args, **kwargs)

        def process_request(self, request, client_address):
            if not self._slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self._slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._slots.release()

    return Server(("127.0.0.1", port), Handler)


def _private_key_file(path: str | Path, *, length: int | None = None) -> bytes:
    path = Path(path)
    try:
        if (not path.is_absolute() or path != path.resolve(strict=True)
                or any(p.is_symlink() for p in (path, *path.parents))):
            raise ControlError("EXTERNAL_AUTHORITY_PRIVATE_FILE_UNSAFE")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 32 <= info.st_size <= 1024:
                raise ControlError("EXTERNAL_AUTHORITY_PRIVATE_FILE_UNSAFE")
            raw = stream.read(1025)
        if length is not None and len(raw) != length:
            raise ControlError("EXTERNAL_AUTHORITY_PRIVATE_FILE_UNSAFE")
        return raw
    except (OSError, ValueError) as exc:
        raise ControlError("EXTERNAL_AUTHORITY_PRIVATE_FILE_UNSAFE") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--key-id", required=True)
    for field in ("signing-key-file", "receipt-key-file", "operator-key-file", "receiver-key-file"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--profile", choices=("records", "owned-loopback-network-v1", "owned-docker-command-v1", "owned-docker-agent-v1"), default="records")
    parser.add_argument("--endpoint-pin-file", type=Path)
    parser.add_argument("--supervisor-pin-file", type=Path)
    args = parser.parse_args()
    try:
        if args.initialize and args.db.exists():
            raise ControlError("EXTERNAL_AUTHORITY_INITIALIZATION_REQUIRES_NEW_STATE")
        options = dict(authority_id=args.authority_id, key_id=args.key_id,
            private_key=_private_key_file(args.signing_key_file, length=32),
            receipt_key=_private_key_file(args.receipt_key_file), create=args.initialize)
        if args.profile == "records":
            if args.endpoint_pin_file is not None or args.supervisor_pin_file is not None:
                raise ControlError("EXTERNAL_AUTHORITY_PROFILE_CONFIGURATION_INVALID")
            store = ExternalAuthorityStore(args.db, **options)
        elif args.profile == "owned-loopback-network-v1":
            from .external_network_authority import ExternalNetworkAuthorityStore
            if args.supervisor_pin_file is not None:
                raise ControlError("EXTERNAL_AUTHORITY_PROFILE_CONFIGURATION_INVALID")
            if args.endpoint_pin_file is None:
                raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_PIN_REQUIRED")
            with args.endpoint_pin_file.open("rb") as stream:
                pin_wire = stream.read(4097)
            if len(pin_wire) > 4096:
                raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_PIN_INVALID")
            try:
                endpoint_pin = json.loads(pin_wire)
            except (ValueError, UnicodeError) as exc:
                raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_PIN_INVALID") from exc
            store = ExternalNetworkAuthorityStore(args.db, endpoint_pin=endpoint_pin, **options)
        else:
            from .external_command_authority import ExternalCommandAuthorityStore
            if args.endpoint_pin_file is not None:
                raise ControlError("EXTERNAL_AUTHORITY_PROFILE_CONFIGURATION_INVALID")
            if args.supervisor_pin_file is None:
                raise ControlError("EXTERNAL_AUTHORITY_SUPERVISOR_PIN_REQUIRED")
            with args.supervisor_pin_file.open("rb") as stream:
                pin_wire = stream.read(4097)
            if len(pin_wire) > 4096:
                raise ControlError("EXTERNAL_AUTHORITY_SUPERVISOR_PIN_INVALID")
            try:
                supervisor_pin = json.loads(pin_wire)
            except (ValueError, UnicodeError) as exc:
                raise ControlError("EXTERNAL_AUTHORITY_SUPERVISOR_PIN_INVALID") from exc
            if args.profile == "owned-docker-agent-v1":
                from .external_agent_authority import ExternalAgentAuthorityStore
                store = ExternalAgentAuthorityStore(args.db, supervisor_pin=supervisor_pin, **options)
            else:
                store = ExternalCommandAuthorityStore(args.db, supervisor_pin=supervisor_pin, **options)
        server = make_server(store, _private_key_file(args.operator_key_file), _private_key_file(args.receiver_key_file), port=args.port)
        print(json.dumps({"url": "http://127.0.0.1:" + str(server.server_address[1]), "pin": store.pin()}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    except (ControlError, OSError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
