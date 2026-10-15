"""Separately owned synthetic endpoint for the bounded loopback POST profile.

Only this endpoint signs proof of an actual atomic SQLite record. Gateway
completion and an absent endpoint row cannot prove that a network effect did
not happen. Its durable database and Ed25519 key must stay outside the gateway
rollback domain. This reference endpoint performs no arbitrary HTTP callback.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .authority import ControlError, canonical_bytes, connect, digest, require_key, validate_id
from .external_authority import _hex, _time, validate_authority_pin
from .external_authority_service import (
    REQUEST_SCHEMA as AUTHORITY_REQUEST_SCHEMA, _private_key_file, verify_authority_response,
)
from .external_network_protocol import (validate_endpoint_pin, validate_network_action, verify_endpoint_receipt,
    validate_endpoint_base_url, validate_network_authorization, verify_network_receipt)
from .observer_auth import _crypto


REQUEST_SCHEMA = "liminal-external-network-request-v1"
RESPONSE_SCHEMA = "liminal-external-network-response-v1"
REQUEST_DOMAIN = b"liminal-external-network-request-v1\x00"
RESPONSE_DOMAIN = b"liminal-external-network-response-v1\x00"
RECEIPT_DOMAIN = b"liminal-external-network-receipt-v1\x00"
MAX_PACKET_BYTES = 65536
MAX_EFFECTS = 1024
PROFILE = "owned-loopback-network-v1"
_REQUEST_FIELDS = {"schema", "role", "operation", "nonce", "payload", "signature"}
_RESPONSE_FIELDS = {"schema", "endpoint_id", "key_id", "operation", "request_digest", "result", "signature"}
_TABLES = {"network_endpoint_meta", "network_endpoint_effects"}


def endpoint_url(url: Any) -> str:
    """One exact IPv4 loopback origin; no resolver, redirects or extra headers."""
    return validate_endpoint_base_url(url)


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _decode(raw: bytes) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ControlError("NETWORK_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        canonical_bytes(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ControlError("NETWORK_PACKET_INVALID") from exc


def _request_signature(body: dict[str, Any], key: bytes) -> str:
    return hmac.new(require_key(key), REQUEST_DOMAIN + canonical_bytes(body), hashlib.sha256).hexdigest()


def _authorization(action: dict[str, Any], value: Any, identity: str) -> dict[str, Any]:
    return validate_network_authorization(action, value, identity)


def bind_receipt(receipt: Any, pin: dict[str, str], action: dict[str, Any],
                 authorization: dict[str, Any], reservation_id: str) -> dict[str, Any]:
    return verify_network_receipt(receipt, pin, action, authorization, reservation_id)


class NetworkEndpointStore:
    def __init__(self, db_path: str | Path, *, endpoint_id: str, key_id: str, private_key: bytes,
                 authority_pin: dict[str, str], endpoint_url: str, gateway_key: bytes,
                 create: bool = True) -> None:
        validate_id(endpoint_id, "endpoint_id")
        validate_id(key_id, "key_id")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ControlError("NETWORK_ENDPOINT_SIGNING_KEY_INVALID")
        self.gateway_key = require_key(gateway_key)
        if private_key == gateway_key:
            raise ControlError("NETWORK_ENDPOINT_KEYS_MUST_DIFFER")
        private, _ = _crypto()
        self._private_bytes = private_key
        self._private_key = private.from_private_bytes(private_key)
        self._pin = validate_endpoint_pin({"endpoint_id": endpoint_id, "key_id": key_id,
            "public_key": self._private_key.public_key().public_bytes_raw().hex()})
        self.authority_pin = validate_authority_pin(authority_pin)
        if self.authority_pin["public_key"] == self._pin["public_key"]:
            raise ControlError("NETWORK_ENDPOINT_KEYS_MUST_DIFFER")
        self.url = validate_endpoint_base_url(endpoint_url)
        self.db_path = Path(db_path).absolute()
        if any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("NETWORK_ENDPOINT_DATABASE_UNSAFE")
        if not self.db_path.exists():
            if not create:
                raise ControlError("NETWORK_ENDPOINT_STATE_MISSING")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.db_path.open("xb"):
                    pass
            except FileExistsError as exc:
                raise ControlError("NETWORK_ENDPOINT_INITIALIZATION_RACE") from exc
            self.db_path.chmod(0o600)
            with connect(self.db_path, create=False) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE network_endpoint_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE network_endpoint_effects(
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_id TEXT UNIQUE NOT NULL, attempt_id TEXT UNIQUE NOT NULL,
                        reservation_id TEXT UNIQUE NOT NULL, root_id TEXT NOT NULL,
                        action_digest TEXT NOT NULL, authorization_digest TEXT NOT NULL,
                        body_json TEXT NOT NULL, body_digest TEXT NOT NULL,
                        committed_at REAL NOT NULL, receipt_json TEXT NOT NULL,
                        permit_request_json TEXT NOT NULL, permit_json TEXT NOT NULL,
                        permit_digest TEXT NOT NULL
                    );
                """)
                db.executemany("INSERT INTO network_endpoint_meta VALUES (?,?)", (
                    ("configuration", self._configuration()), ("commit_request_count", "0"),
                    ("query_request_count", "0")))
        with self._connection():
            pass

    def _configuration(self) -> str:
        return canonical_bytes({"schema": "liminal-network-endpoint-store-v1", "profile": PROFILE,
            "pin": validate_endpoint_pin(self._pin), "authority_pin": validate_authority_pin(self.authority_pin),
            "url": endpoint_url(self.url), "gateway_key_digest": hashlib.sha256(require_key(self.gateway_key)).hexdigest(),
            "private_key_digest": hashlib.sha256(self._private_bytes).hexdigest()}).decode()

    def _connection(self):
        if not self.db_path.is_file() or any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("NETWORK_ENDPOINT_STATE_MISSING")
        db = connect(self.db_path, create=False)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM network_endpoint_meta")}
            if tables != _TABLES or set(meta) != {"configuration", "commit_request_count", "query_request_count"} or meta["configuration"] != self._configuration():
                raise ControlError("NETWORK_ENDPOINT_CONFIGURATION_IMMUTABLE")
            for field in ("commit_request_count", "query_request_count"):
                if not meta[field].isdigit() or int(meta[field]) > 2**63 - 1:
                    raise ControlError("NETWORK_ENDPOINT_COUNTER_INVALID")
            return db
        except Exception:
            db.close()
            raise

    def pin(self) -> dict[str, str]:
        with self._connection():
            return dict(self._pin)

    def _count(self, operation: str) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            key = operation + "_request_count"
            count = int(db.execute("SELECT value FROM network_endpoint_meta WHERE key=?", (key,)).fetchone()[0])
            if count >= 2**63 - 1:
                raise ControlError("NETWORK_ENDPOINT_COUNTER_CAPACITY")
            db.execute("UPDATE network_endpoint_meta SET value=? WHERE key=?", (str(count + 1), key))

    def commit(self, action: Any, authorization: Any, permit_request: Any, permit: Any, *,
               before_commit: Callable[[], None] | None = None) -> dict[str, Any]:
        self._count("commit")
        action = validate_network_action(action)
        authorization = _authorization(action, authorization, self._pin["endpoint_id"])
        # Freeze both authenticated packets before validation or fault hooks.
        # Python equality equates 150 and 150.0, but their canonical signatures
        # and grant digests differ; wire binding is exact canonical JSON.
        permit_request, permit = _copy(permit_request), _copy(permit)
        if action["arguments"]["url"] != self.url + "/v1/record":
            raise ControlError("NETWORK_ENDPOINT_URL_BINDING_MISMATCH")
        if (not isinstance(permit_request, dict)
                or set(permit_request) != {"schema", "role", "operation", "nonce", "payload"}
                or permit_request["schema"] != AUTHORITY_REQUEST_SCHEMA
                or permit_request["role"] != "receiver" or permit_request["operation"] != "begin"
                or canonical_bytes(permit_request["payload"]) != canonical_bytes({"action": action, "authorization": authorization})):
            raise ControlError("NETWORK_ENDPOINT_PERMIT_REQUEST_MISMATCH")
        _hex(permit_request["nonce"])
        result = verify_authority_response(permit_request, permit, self.authority_pin)
        if (result.get("status") != "PERMITTED" or result.get("outcome") is not None
                or result.get("action_digest") != digest(action)
                or result.get("receiver_id") != self._pin["endpoint_id"]
                or any(type(result.get(field)) is not type(action[field]) or result.get(field) != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("NETWORK_ENDPOINT_PERMIT_BINDING_MISMATCH")
        reservation_id = validate_id(result.get("reservation_id"), "reservation_id")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM network_endpoint_effects WHERE action_id=? OR attempt_id=? OR reservation_id=?",
                (action["action_id"], action["attempt_id"], reservation_id)).fetchall()
            if rows:
                if (len(rows) != 1 or rows[0]["action_digest"] != digest(action)
                        or rows[0]["authorization_digest"] != digest(authorization)
                        or rows[0]["reservation_id"] != reservation_id
                        or rows[0]["permit_digest"] != digest(permit)):
                    raise ControlError("NETWORK_ENDPOINT_REUSE_MISMATCH")
                return _copy(json.loads(rows[0]["receipt_json"]))
            if db.execute("SELECT COUNT(*) FROM network_endpoint_effects").fetchone()[0] >= MAX_EFFECTS:
                raise ControlError("NETWORK_ENDPOINT_CAPACITY")
            if before_commit is not None:
                before_commit()
            committed_at = _time(time.time())
            receipt = {"schema": "liminal.external-network.receipt.v1", "status": "COMMITTED",
                "endpoint_id": self._pin["endpoint_id"], "key_id": self._pin["key_id"],
                "reservation_id": reservation_id,
                **{field: action[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
                "action_digest": digest(action), "authorization_digest": digest(authorization),
                "body_digest": digest(action["arguments"]["body"]), "committed_at": committed_at,
                "effect_count": 1}
            receipt["signature"] = self._private_key.sign(RECEIPT_DOMAIN + canonical_bytes(receipt)).hex()
            db.execute("""INSERT INTO network_endpoint_effects(action_id,attempt_id,reservation_id,root_id,
                action_digest,authorization_digest,body_json,body_digest,committed_at,receipt_json,
                permit_request_json,permit_json,permit_digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (action["action_id"], action["attempt_id"], reservation_id, action["root_id"], digest(action),
                 digest(authorization), canonical_bytes(action["arguments"]["body"]).decode(),
                 receipt["body_digest"], committed_at, canonical_bytes(receipt).decode(),
                 canonical_bytes(permit_request).decode(), canonical_bytes(permit).decode(), digest(permit)))
        return _copy(receipt)

    def query(self, action_id: str, reservation_id: str) -> dict[str, Any]:
        self._count("query")
        validate_id(action_id, "action_id")
        validate_id(reservation_id, "reservation_id")
        with self._connection() as db:
            row = db.execute("SELECT receipt_json FROM network_endpoint_effects WHERE action_id=? AND reservation_id=?",
                (action_id, reservation_id)).fetchone()
        return {"status": "UNKNOWN" if row is None else "OBSERVED", "action_id": action_id,
            "reservation_id": reservation_id, "effect_count": None if row is None else 1,
            "receipt": None if row is None else json.loads(row[0])}

    def inventory(self) -> dict[str, Any]:
        with self._connection() as db:
            db.execute("BEGIN")
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM network_endpoint_meta")}
            rows = db.execute("SELECT * FROM network_endpoint_effects ORDER BY sequence").fetchall()
            return {"endpoint_id": self._pin["endpoint_id"], "pin": dict(self._pin), "url": self.url,
                "commit_request_count": int(meta["commit_request_count"]),
                "query_request_count": int(meta["query_request_count"]),
                "effects": [{**{field: row[field] for field in ("sequence", "action_id", "attempt_id", "root_id", "reservation_id", "body_digest", "committed_at")},
                             "body": json.loads(row["body_json"])} for row in rows],
                "receipts": [json.loads(row["receipt_json"]) for row in rows],
                "requests": [{"action_id": row["action_id"], "permit_request": json.loads(row["permit_request_json"]),
                    "permit": json.loads(row["permit_json"]), "permit_digest": row["permit_digest"]} for row in rows]}


def verify_endpoint_response(request: dict[str, Any], response: Any, pin: dict[str, str]) -> dict[str, Any]:
    pin = validate_endpoint_pin(pin)
    if (not isinstance(response, dict) or set(response) != _RESPONSE_FIELDS
            or response["schema"] != RESPONSE_SCHEMA
            or response["endpoint_id"] != pin["endpoint_id"] or response["key_id"] != pin["key_id"]
            or response["operation"] != request["operation"] or response["request_digest"] != digest({k: v for k, v in request.items() if k != "signature"})
            or not isinstance(response["result"], dict) or len(canonical_bytes(response)) > MAX_PACKET_BYTES):
        raise ControlError("NETWORK_ENDPOINT_RESPONSE_BINDING_MISMATCH")
    _hex(response["signature"], 128)
    _, public = _crypto()
    try:
        public.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(bytes.fromhex(response["signature"]),
            RESPONSE_DOMAIN + canonical_bytes({k: v for k, v in response.items() if k != "signature"}))
    except Exception as exc:
        raise ControlError("NETWORK_ENDPOINT_RESPONSE_SIGNATURE_INVALID") from exc
    return _copy(response["result"])


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ControlError("NETWORK_REDIRECT_FORBIDDEN")


class HTTPNetworkEndpointClient:
    def __init__(self, url: str, request_key: bytes, pin: dict[str, str], *, timeout: float = 3) -> None:
        self.url, self.request_key, self._pin = endpoint_url(url), require_key(request_key), validate_endpoint_pin(pin)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ControlError("NETWORK_TIMEOUT_INVALID")
        self.timeout = float(timeout)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())
        self._evidence: list[dict[str, Any]] = []

    def pin(self) -> dict[str, str]:
        return dict(self._pin)

    @property
    def evidence(self) -> list[dict[str, Any]]:
        return _copy(self._evidence)

    def _call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {"schema": REQUEST_SCHEMA, "role": "gateway", "operation": operation,
            "nonce": secrets.token_hex(32), "payload": payload}
        packet = {**body, "signature": _request_signature(body, self.request_key)}
        wire = canonical_bytes(packet)
        if len(wire) > MAX_PACKET_BYTES:
            raise ControlError("NETWORK_PACKET_TOO_LARGE")
        url = self.url + ("/v1/record" if operation == "commit" else "/v1/query")
        request = Request(url, data=wire, method="POST", headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as incoming:
                if incoming.status != 200 or incoming.geturl() != url:
                    raise ControlError("NETWORK_ENDPOINT_RESPONSE_INVALID")
                raw = incoming.read(MAX_PACKET_BYTES + 1)
            if len(raw) > MAX_PACKET_BYTES:
                raise ControlError("NETWORK_PACKET_TOO_LARGE")
            response = _decode(raw)
            result = verify_endpoint_response(body, response, self._pin)
            self._evidence.append({"request": body, "response": response})
            if len(self._evidence) > 1024:
                self._evidence.pop(0)
            if result.get("status") == "ERROR":
                raise ControlError(result.get("reason", "NETWORK_ENDPOINT_REFUSED"))
            return result
        except ControlError:
            raise
        except (HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            raise ControlError("NETWORK_ENDPOINT_UNAVAILABLE") from exc

    def commit(self, action: dict[str, Any], authorization: dict[str, Any],
               permit_request: dict[str, Any], permit: dict[str, Any]) -> dict[str, Any]:
        return self._call("commit", {"action": action, "authorization": authorization,
            "permit_request": permit_request, "permit": permit})

    def query(self, action_id: str, reservation_id: str) -> dict[str, Any]:
        return self._call("query", {"action_id": action_id, "reservation_id": reservation_id})


class BoundedLoopbackServer(ThreadingHTTPServer):
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


def make_endpoint_server(store: NetworkEndpointStore, *, port: int,
                         before_commit: Callable[[], None] | None = None,
                         drop_commit_response: bool = False,
                         query_unavailable: bool = False) -> ThreadingHTTPServer:
    if type(port) is not int or endpoint_url(f"http://127.0.0.1:{port}") != store.url:
        raise ControlError("NETWORK_ENDPOINT_SERVER_BINDING_MISMATCH")
    fault_lock = threading.Lock()
    drop_remaining = int(bool(drop_commit_response))

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def _write(self, code, value):
            raw = canonical_bytes(value)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            nonlocal drop_remaining
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if (self.path not in ("/v1/record", "/v1/query") or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Type") != "application/json" or len(lengths) != 1):
                    raise ControlError("NETWORK_REQUEST_INVALID")
                size = int(lengths[0])
                if not 0 < size <= MAX_PACKET_BYTES:
                    raise ControlError("NETWORK_REQUEST_TOO_LARGE")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ControlError("NETWORK_REQUEST_INVALID")
                packet = _decode(raw)
                if (not isinstance(packet, dict) or set(packet) != _REQUEST_FIELDS
                        or packet["schema"] != REQUEST_SCHEMA or packet["role"] != "gateway"
                        or packet["operation"] != ("commit" if self.path == "/v1/record" else "query")):
                    raise ControlError("NETWORK_REQUEST_INVALID")
                _hex(packet["nonce"])
                _hex(packet["signature"])
                body = {key: value for key, value in packet.items() if key != "signature"}
                with store._connection():
                    pass
                if not hmac.compare_digest(packet["signature"], _request_signature(body, store.gateway_key)):
                    raise ControlError("NETWORK_AUTHENTICATION_FAILED")
            except Exception:
                self._write(403, {"status": "REFUSED"})
                return
            try:
                payload = packet["payload"]
                expected = ({"action", "authorization", "permit_request", "permit"}
                    if packet["operation"] == "commit" else {"action_id", "reservation_id"})
                if not isinstance(payload, dict) or set(payload) != expected:
                    raise ControlError("NETWORK_PAYLOAD_INVALID")
                if packet["operation"] == "commit":
                    receipt = store.commit(**payload, before_commit=before_commit)
                    result = {"status": "OBSERVED", "action_id": receipt["action_id"],
                        "reservation_id": receipt["reservation_id"], "effect_count": 1, "receipt": receipt}
                    with fault_lock:
                        if drop_remaining:
                            drop_remaining -= 1
                            self.close_connection = True
                            return
                else:
                    result = store.query(**payload)
                    if query_unavailable:
                        result = {"status": "UNKNOWN", **payload, "effect_count": None, "receipt": None}
            except ControlError as exc:
                result = {"status": "ERROR", "reason": str(exc)}
            except Exception:
                result = {"status": "ERROR", "reason": "NETWORK_ENDPOINT_UNAVAILABLE"}
            response = {"schema": RESPONSE_SCHEMA, "endpoint_id": store._pin["endpoint_id"],
                "key_id": store._pin["key_id"], "operation": packet["operation"],
                "request_digest": digest(body), "result": result}
            response["signature"] = store._private_key.sign(RESPONSE_DOMAIN + canonical_bytes(response)).hex()
            try:
                self._write(200, response)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return BoundedLoopbackServer(("127.0.0.1", port), Handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--endpoint-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--authority-pin-file", type=Path, required=True)
    parser.add_argument("--gateway-key-file", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--no-initialize", action="store_true")
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--drop-first-commit-response", action="store_true")
    parser.add_argument("--query-unavailable", action="store_true")
    parser.add_argument("--barrier-reached-file", type=Path)
    parser.add_argument("--barrier-release-file", type=Path)
    args = parser.parse_args()
    try:
        if args.initialize and (args.no_initialize or args.db.exists()):
            raise ControlError("NETWORK_INITIALIZATION_REQUIRES_NEW_STATE")
        if bool(args.barrier_reached_file) != bool(args.barrier_release_file):
            raise ControlError("NETWORK_BARRIER_CONFIGURATION_INVALID")
        store = NetworkEndpointStore(args.db, endpoint_id=args.endpoint_id, key_id=args.key_id,
            private_key=_private_key_file(args.private_key_file, length=32),
            authority_pin=_decode(args.authority_pin_file.read_bytes()),
            endpoint_url=f"http://127.0.0.1:{args.port}",
            gateway_key=_private_key_file(args.gateway_key_file), create=args.initialize)
        def barrier():
            args.barrier_reached_file.write_text("reached\n")
            deadline = time.monotonic() + 30
            while not args.barrier_release_file.exists():
                if time.monotonic() >= deadline:
                    raise ControlError("NETWORK_TEST_BARRIER_TIMEOUT")
                time.sleep(0.01)
        server = make_endpoint_server(store, port=args.port,
            before_commit=barrier if args.barrier_reached_file else None,
            drop_commit_response=args.drop_first_commit_response, query_unavailable=args.query_unavailable)
        ready = {"url": store.url, "pin": store.pin(), "profile": PROFILE}
        if args.ready_file:
            args.ready_file.write_bytes(canonical_bytes(ready))
        print(json.dumps(ready), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    except (ControlError, OSError, ValueError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
