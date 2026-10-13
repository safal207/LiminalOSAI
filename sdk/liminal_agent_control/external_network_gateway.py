"""Host-authorized, one-shot gateway for the owned synthetic network endpoint.

An operator stores the exact proposal and grant before a worker can execute.
Every execution asks the external authority once; only its fresh PERMITTED
response can produce one POST. Reconciliation only queries and settles proof.
The gateway's callback status and local rollback never authorize another POST.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

from .authority import ControlError, canonical_bytes, connect, digest, require_key, validate_id
from .external_authority import _hex
from .external_authority_service import HTTPExternalAuthorityClient, _private_key_file
from .external_network_endpoint import (
    HTTPNetworkEndpointClient, BoundedLoopbackServer, _NoRedirect, _copy, _decode, bind_receipt,
)
from .external_network_protocol import (
    NETWORK_PROFILE, validate_endpoint_base_url, validate_network_action, validate_network_authorization,
)


REQUEST_SCHEMA = "liminal-network-gateway-request-v1"
RESPONSE_SCHEMA = "liminal-network-gateway-response-v1"
REQUEST_DOMAIN = b"liminal-network-gateway-request-v1\x00"
RESPONSE_DOMAIN = b"liminal-network-gateway-response-v1\x00"
MAX_PACKET_BYTES = 2 * 1024 * 1024
MAX_GRANTS = 1024
MAX_EVIDENCE = 8192
_TABLES = {"network_gateway_meta", "network_gateway_grants", "network_gateway_evidence"}
_ROLE_OPERATIONS = {"admin": {"authorize", "identity", "inventory"}, "worker": {"execute", "reconcile"}}


class NetworkGateway:
    def __init__(self, db_path: str | Path, *, gateway_id: str,
                 external_controller: HTTPExternalAuthorityClient,
                 endpoint_client: HTTPNetworkEndpointClient, operator_key: bytes, worker_key: bytes,
                 create: bool = True, drop_begin_response: bool = False,
                 drop_finish_response: bool = False) -> None:
        validate_id(gateway_id, "gateway_id")
        self.gateway_id = gateway_id
        self.external_controller, self.endpoint_client = external_controller, endpoint_client
        self.operator_key, self.worker_key = require_key(operator_key), require_key(worker_key)
        self._lock = threading.RLock()
        self._drop_begin_response, self._drop_finish_response = bool(drop_begin_response), bool(drop_finish_response)
        self.db_path = Path(db_path).absolute()
        if any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("NETWORK_GATEWAY_DATABASE_UNSAFE")
        configuration = self._configuration()
        if not self.db_path.exists():
            if not create:
                raise ControlError("NETWORK_GATEWAY_STATE_MISSING")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.db_path.open("xb"):
                    pass
            except FileExistsError as exc:
                raise ControlError("NETWORK_GATEWAY_INITIALIZATION_RACE") from exc
            self.db_path.chmod(0o600)
            with connect(self.db_path, create=False) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE network_gateway_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE network_gateway_grants(
                        action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                        action_digest TEXT NOT NULL, authorization_digest TEXT NOT NULL,
                        action_json TEXT NOT NULL, authorization_json TEXT NOT NULL,
                        status TEXT NOT NULL, reservation_id TEXT, receipt_json TEXT
                    );
                    CREATE TABLE network_gateway_evidence(
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        source TEXT NOT NULL, packet_json TEXT NOT NULL
                    );
                """)
                db.execute("INSERT INTO network_gateway_meta VALUES ('configuration',?)", (configuration,))
        with self._connection():
            pass

    def _configuration(self) -> str:
        if (not isinstance(self.external_controller, HTTPExternalAuthorityClient)
                or self.external_controller.role != "receiver"
                or not isinstance(self.endpoint_client, HTTPNetworkEndpointClient)):
            raise ControlError("NETWORK_GATEWAY_CONFIGURATION_IMMUTABLE")
        authority, endpoint = self.external_controller, self.endpoint_client
        keys = (require_key(self.operator_key), require_key(self.worker_key),
                require_key(authority.request_key), require_key(endpoint.request_key))
        if len(set(keys)) != len(keys):
            raise ControlError("NETWORK_GATEWAY_KEYS_MUST_DIFFER")
        # Revalidate the live endpoint configuration before every public action.
        validate_endpoint_base_url(endpoint.url)
        parsed = urlparse(authority.url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None
                or not 1 <= parsed.port <= 65535 or parsed.path or parsed.query or parsed.fragment
                or authority.url != f"http://127.0.0.1:{parsed.port}"):
            raise ControlError("NETWORK_GATEWAY_AUTHORITY_ENDPOINT_INVALID")
        return canonical_bytes({"schema": "liminal-network-gateway-store-v1", "profile": NETWORK_PROFILE,
            "gateway_id": self.gateway_id, "authority_url": authority.url,
            "authority_pin": authority.pin(), "authority_role": authority.role,
            "endpoint_url": endpoint.url, "endpoint_pin": endpoint.pin(),
            "operator_key_digest": hashlib.sha256(keys[0]).hexdigest(),
            "worker_key_digest": hashlib.sha256(keys[1]).hexdigest(),
            "authority_request_key_digest": hashlib.sha256(keys[2]).hexdigest(),
            "endpoint_request_key_digest": hashlib.sha256(keys[3]).hexdigest()}).decode()

    def _connection(self):
        if not self.db_path.is_file() or any(path.is_symlink() for path in (self.db_path, *self.db_path.parents)):
            raise ControlError("NETWORK_GATEWAY_STATE_MISSING")
        db = connect(self.db_path, create=False)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM network_gateway_meta")}
            if tables != _TABLES or set(meta) != {"configuration"} or meta["configuration"] != self._configuration():
                raise ControlError("NETWORK_GATEWAY_CONFIGURATION_IMMUTABLE")
            return db
        except Exception:
            db.close()
            raise

    def identity(self) -> dict[str, Any]:
        with self._connection():
            return {"gateway_id": self.gateway_id, "profile": NETWORK_PROFILE,
                "authority_pin": self.external_controller.pin(), "authority_url": self.external_controller.url,
                "endpoint_pin": self.endpoint_client.pin(), "endpoint_url": self.endpoint_client.url,
                "execution_authorized": False}

    def authorize(self, action: Any, authorization: Any) -> dict[str, Any]:
        """Operator-only exact grant storage; HTTP workers cannot call this."""
        with self._lock, self._connection() as db:
            action = validate_network_action(action)
            authorization = validate_network_authorization(action, authorization, self.endpoint_client.pin()["endpoint_id"])
            if action["arguments"]["url"] != self.endpoint_client.url + "/v1/record":
                raise ControlError("NETWORK_GATEWAY_ENDPOINT_BINDING_MISMATCH")
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM network_gateway_grants WHERE action_id=? OR attempt_id=?",
                (action["action_id"], action["attempt_id"])).fetchall()
            if rows:
                if (len(rows) != 1 or rows[0]["action_digest"] != digest(action)
                        or rows[0]["authorization_digest"] != digest(authorization)):
                    raise ControlError("NETWORK_GATEWAY_GRANT_IMMUTABLE")
            else:
                if db.execute("SELECT COUNT(*) FROM network_gateway_grants").fetchone()[0] >= MAX_GRANTS:
                    raise ControlError("NETWORK_GATEWAY_GRANT_CAPACITY")
                db.execute("INSERT INTO network_gateway_grants VALUES (?,?,?,?,?,?,'AUTHORIZED',NULL,NULL)",
                    (action["action_id"], action["attempt_id"], digest(action), digest(authorization),
                     canonical_bytes(action).decode(), canonical_bytes(authorization).decode()))
            return {"status": "AUTHORIZED", "action_id": action["action_id"],
                "action_digest": digest(action), "authorization_digest": digest(authorization),
                "execution_authorized": False}

    def _grant(self, action_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        validate_id(action_id, "action_id")
        with self._connection() as db:
            row = db.execute("SELECT * FROM network_gateway_grants WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                return None
            action = validate_network_action(json.loads(row["action_json"]))
            authorization = validate_network_authorization(action, json.loads(row["authorization_json"]),
                self.endpoint_client.pin()["endpoint_id"])
            if (row["action_id"] != action["action_id"] or row["attempt_id"] != action["attempt_id"]
                    or row["action_digest"] != digest(action) or row["authorization_digest"] != digest(authorization)
                    or action["arguments"]["url"] != self.endpoint_client.url + "/v1/record"):
                raise ControlError("NETWORK_GATEWAY_GRANT_CORRUPT")
            return action, authorization

    def _save_evidence(self, source: str, packet: dict[str, Any]) -> None:
        # Only public request bodies and signed responses enter the durable log.
        if set(packet) != {"request", "response"} or "signature" in packet["request"]:
            raise ControlError("NETWORK_GATEWAY_PRIVATE_EVIDENCE_FORBIDDEN")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM network_gateway_evidence").fetchone()[0] >= MAX_EVIDENCE:
                raise ControlError("NETWORK_GATEWAY_EVIDENCE_CAPACITY")
            db.execute("INSERT INTO network_gateway_evidence(source,packet_json) VALUES (?,?)",
                (source, canonical_bytes(packet).decode()))

    def _call(self, source: str, operation: str, *args) -> dict[str, Any]:
        with self._connection():
            pass
        client = self.external_controller if source == "authority" else self.endpoint_client
        previous = client.evidence[-1] if client.evidence else None
        try:
            result = getattr(client, operation)(*args)
        finally:
            current = client.evidence[-1] if client.evidence else None
            if current is not None and current != previous:
                self._save_evidence(source, current)
        if source == "authority" and operation == "begin" and self._drop_begin_response:
            self._drop_begin_response = False
            raise ControlError("NETWORK_TEST_BEGIN_RESPONSE_LOST")
        if source == "authority" and operation == "finish" and self._drop_finish_response:
            self._drop_finish_response = False
            raise ControlError("NETWORK_TEST_FINISH_RESPONSE_LOST")
        return result

    def _state(self, action_id: str, status: str, reservation_id: str | None,
               receipt: dict[str, Any] | None = None) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE network_gateway_grants SET status=?,reservation_id=?,receipt_json=? WHERE action_id=?",
                (status, reservation_id, None if receipt is None else canonical_bytes(receipt).decode(), action_id))

    @staticmethod
    def _result(action_id: str, status: str, reason: str, reservation_id: str | None = None,
                receipt: dict[str, Any] | None = None, *, dispatch_finished: bool = False,
                settlement_status: str | None = None) -> dict[str, Any]:
        return {"status": status, "reason": reason, "action_id": action_id,
            "reservation_id": reservation_id, "effect_count": 1 if receipt is not None else None,
            "remote_outcome": "COMMITTED" if receipt is not None else None,
            "receipt": receipt, "dispatch_finished": dispatch_finished,
            "settlement_status": settlement_status, "execution_authorized": False}

    def _bind_authority_result(self, result: dict[str, Any], action: dict[str, Any]) -> str:
        if (result.get("action_digest") != digest(action)
                or result.get("receiver_id") != self.endpoint_client.pin()["endpoint_id"]
                or any(type(result.get(field)) is not type(action[field]) or result.get(field) != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("NETWORK_GATEWAY_AUTHORITY_BINDING_MISMATCH")
        return validate_id(result.get("reservation_id"), "reservation_id")

    def _settle(self, action: dict[str, Any], authorization: dict[str, Any], reservation_id: str,
                receipt: Any, *, dispatch_finished: bool) -> dict[str, Any]:
        receipt = bind_receipt(receipt, self.endpoint_client.pin(), action, authorization, reservation_id)
        self._state(action["action_id"], "COMMITTED_PROOF", reservation_id, receipt)
        try:
            result = self._call("authority", "finish", reservation_id, receipt)
            self._bind_authority_result(result, action)
            if (result.get("status") != "SETTLED" or result.get("outcome") != "COMMITTED"
                    or result.get("receipt") != receipt):
                raise ControlError("NETWORK_GATEWAY_SETTLEMENT_BINDING_MISMATCH")
        except ControlError as exc:
            return self._result(action["action_id"], "UNKNOWN", str(exc), reservation_id, receipt,
                dispatch_finished=dispatch_finished, settlement_status="UNKNOWN")
        self._state(action["action_id"], "COMMITTED", reservation_id, receipt)
        return self._result(action["action_id"], "COMMITTED", "ENDPOINT_COMMITTED_AND_SETTLED", reservation_id,
            receipt, dispatch_finished=dispatch_finished, settlement_status="SETTLED")

    def _before_endpoint_commit(self, action: dict[str, Any], authorization: dict[str, Any],
                                reservation_id: str, permit_pair: dict[str, Any]) -> None:
        """Protected admission hook; legacy network-v1 keeps its frozen behavior.

        A separately persisted guarded profile can require a final host check.
        This hook precedes the dispatch try/finally so a blocked dispatch never
        claims that an endpoint callback was invoked or finished.
        """
        return None

    def execute(self, proposed: Any) -> dict[str, Any]:
        """One fresh BEGIN, at most one endpoint POST, no operation retry."""
        with self._lock:
            with self._connection():
                pass
            proposed = validate_network_action(proposed)
            granted = self._grant(proposed["action_id"])
            if granted is None or granted[0] != proposed:
                return self._result(proposed["action_id"], "DENIED", "NETWORK_EXACT_HOST_GRANT_REQUIRED")
            action, authorization = granted
            reservation_id = None
            dispatch_finished = False
            try:
                result = self._call("authority", "begin", action, authorization)
                if result.get("status") == "DENIED":
                    self._state(action["action_id"], "DENIED", result.get("reservation_id"))
                    return self._result(action["action_id"], "DENIED", result.get("reason", "AUTHORITY_DENIED"), result.get("reservation_id"))
                reservation_id = self._bind_authority_result(result, action)
                if result.get("status") != "PERMITTED":
                    if result.get("outcome") == "COMMITTED" and result.get("status") == "CONSUMED":
                        receipt = bind_receipt(result.get("receipt"), self.endpoint_client.pin(), action, authorization, reservation_id)
                        self._state(action["action_id"], "COMMITTED", reservation_id, receipt)
                        return self._result(action["action_id"], "COMMITTED", "AUTHORITY_TERMINAL_OBSERVED", reservation_id,
                            receipt, settlement_status="SETTLED")
                    self._state(action["action_id"], "UNKNOWN", reservation_id)
                    return self._result(action["action_id"], "UNKNOWN", "NETWORK_NO_NEW_PERMIT", reservation_id,
                        settlement_status="UNKNOWN")
                self._state(action["action_id"], "PENDING", reservation_id)
                pair = self.external_controller.evidence[-1]
                self._before_endpoint_commit(action, authorization, reservation_id, pair)
                # The endpoint verifies the exact signed BEGIN request challenge;
                # a retained packet is never used as a gateway execution source.
                try:
                    observation = self._call("endpoint", "commit", action, authorization, pair["request"], pair["response"])
                finally:
                    # This local callback completion, including timeout/error,
                    # says nothing about whether the remote effect committed.
                    dispatch_finished = True
                if (set(observation) != {"status", "action_id", "reservation_id", "effect_count", "receipt"}
                        or observation.get("status") != "OBSERVED" or observation.get("action_id") != action["action_id"]
                        or observation.get("reservation_id") != reservation_id or type(observation.get("effect_count")) is not int
                        or observation.get("effect_count") != 1):
                    raise ControlError("NETWORK_GATEWAY_ENDPOINT_OBSERVATION_INVALID")
                return self._settle(action, authorization, reservation_id, observation.get("receipt"), dispatch_finished=True)
            except ControlError as exc:
                try:
                    self._state(action["action_id"], "UNKNOWN", reservation_id)
                except Exception:
                    # A configuration/storage fault can prevent this journal
                    # update. It cannot justify losing a consumed reservation,
                    # retrying POST, or repairing a differently bound store.
                    pass
                return self._result(action["action_id"], "UNKNOWN", str(exc), reservation_id,
                    dispatch_finished=dispatch_finished, settlement_status="UNKNOWN")

    def reconcile(self, action_id: str) -> dict[str, Any]:
        """Read external state and endpoint proof; never invoke endpoint commit."""
        with self._lock:
            with self._connection():
                pass
            granted = self._grant(action_id)
            if granted is None:
                return self._result(action_id, "UNKNOWN", "NETWORK_HOST_GRANT_NOT_AVAILABLE", settlement_status="UNKNOWN")
            action, authorization = granted
            reservation_id = None
            try:
                external = self._call("authority", "query", action_id)
                if external.get("reason") == "NOT_OBSERVED" and external.get("reservation_id") is None:
                    return self._result(action_id, "UNKNOWN", "NETWORK_NOT_OBSERVED", settlement_status="UNKNOWN")
                reservation_id = self._bind_authority_result(external, action)
                if external.get("outcome") == "COMMITTED" and external.get("status") == "CONSUMED":
                    receipt = bind_receipt(external.get("receipt"), self.endpoint_client.pin(), action, authorization, reservation_id)
                    self._state(action_id, "COMMITTED", reservation_id, receipt)
                    return self._result(action_id, "COMMITTED", "AUTHORITY_TERMINAL_OBSERVED", reservation_id,
                        receipt, settlement_status="SETTLED")
                if external.get("outcome") == "DENIED":
                    return self._result(action_id, "DENIED", external.get("reason", "AUTHORITY_DENIED"), reservation_id)
                if external.get("status") != "UNKNOWN" or external.get("outcome") is not None:
                    raise ControlError("NETWORK_GATEWAY_AUTHORITY_OUTCOME_INVALID")
                observation = self._call("endpoint", "query", action_id, reservation_id)
                if (set(observation) != {"status", "action_id", "reservation_id", "effect_count", "receipt"}
                        or observation.get("status") != "OBSERVED" or observation.get("action_id") != action_id
                        or observation.get("reservation_id") != reservation_id
                        or type(observation.get("effect_count")) is not int or observation.get("effect_count") != 1):
                    return self._result(action_id, "UNKNOWN", "NETWORK_ENDPOINT_OUTCOME_UNKNOWN", reservation_id,
                        settlement_status="UNKNOWN")
                return self._settle(action, authorization, reservation_id, observation.get("receipt"), dispatch_finished=False)
            except ControlError as exc:
                self._state(action_id, "UNKNOWN", reservation_id)
                return self._result(action_id, "UNKNOWN", str(exc), reservation_id, settlement_status="UNKNOWN")

    def inventory(self) -> dict[str, Any]:
        with self._lock, self._connection() as db:
            db.execute("BEGIN")
            grants = db.execute("SELECT * FROM network_gateway_grants ORDER BY action_id").fetchall()
            evidence = db.execute("SELECT * FROM network_gateway_evidence ORDER BY sequence").fetchall()
            return {**self.identity(), "actions": [{"action": json.loads(row["action_json"]),
                "authorization": json.loads(row["authorization_json"]), "status": row["status"],
                "reservation_id": row["reservation_id"],
                "receipt": None if row["receipt_json"] is None else json.loads(row["receipt_json"])} for row in grants],
                "authority_evidence": [json.loads(row["packet_json"]) for row in evidence if row["source"] == "authority"],
                "endpoint_evidence": [json.loads(row["packet_json"]) for row in evidence if row["source"] == "endpoint"]}


def _signature(body: dict[str, Any], key: bytes, domain: bytes) -> str:
    return hmac.new(require_key(key), domain + canonical_bytes(body), hashlib.sha256).hexdigest()


class HTTPNetworkGatewayClient:
    def __init__(self, url: str, key: bytes, *, role: str = "worker", timeout: float = 5) -> None:
        self.url = validate_endpoint_base_url(url)
        self.key = require_key(key)
        if role not in _ROLE_OPERATIONS:
            raise ControlError("NETWORK_GATEWAY_ROLE_INVALID")
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ControlError("NETWORK_GATEWAY_TIMEOUT_INVALID")
        self.role, self.timeout = role, float(timeout)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if operation not in _ROLE_OPERATIONS[self.role]:
            raise ControlError("NETWORK_GATEWAY_ROLE_DENIED")
        body = {"schema": REQUEST_SCHEMA, "role": self.role, "operation": operation,
            "nonce": secrets.token_hex(32), "payload": payload}
        packet = {**body, "signature": _signature(body, self.key, REQUEST_DOMAIN)}
        wire = canonical_bytes(packet)
        if len(wire) > 32768:
            raise ControlError("NETWORK_GATEWAY_REQUEST_TOO_LARGE")
        url = self.url + "/v1/gateway"
        try:
            with self._opener.open(Request(url, data=wire, method="POST", headers={"Content-Type": "application/json"}), timeout=self.timeout) as incoming:
                if incoming.status != 200 or incoming.geturl() != url:
                    raise ControlError("NETWORK_GATEWAY_RESPONSE_INVALID")
                raw = incoming.read(MAX_PACKET_BYTES + 1)
            if len(raw) > MAX_PACKET_BYTES:
                raise ControlError("NETWORK_GATEWAY_RESPONSE_TOO_LARGE")
            response = _decode(raw)
            if (not isinstance(response, dict) or set(response) != {"schema", "operation", "request_digest", "result", "signature"}
                    or response["schema"] != RESPONSE_SCHEMA or response["operation"] != operation
                    or response["request_digest"] != digest(body) or not isinstance(response["result"], dict)):
                raise ControlError("NETWORK_GATEWAY_RESPONSE_BINDING_MISMATCH")
            _hex(response["signature"])
            expected = _signature({k: v for k, v in response.items() if k != "signature"}, self.key, RESPONSE_DOMAIN)
            if not hmac.compare_digest(response["signature"], expected):
                raise ControlError("NETWORK_GATEWAY_RESPONSE_AUTHENTICATION_FAILED")
            if response["result"].get("status") == "ERROR":
                raise ControlError(response["result"].get("reason", "NETWORK_GATEWAY_REFUSED"))
            return _copy(response["result"])
        except ControlError:
            raise
        except (HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            raise ControlError("NETWORK_GATEWAY_UNAVAILABLE") from exc

    def authorize(self, action: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any]:
        return self._call("authorize", {"action": action, "authorization": authorization})

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._call("execute", {"action": action})

    def reconcile(self, action_id: str) -> dict[str, Any]:
        return self._call("reconcile", {"action_id": action_id})

    def inventory(self) -> dict[str, Any]:
        return self._call("inventory", {})

    def identity(self) -> dict[str, Any]:
        return self._call("identity", {})


def make_gateway_server(gateway: NetworkGateway, *, port: int = 0) -> ThreadingHTTPServer:
    if type(port) is not int or not 0 <= port <= 65535:
        raise ControlError("NETWORK_GATEWAY_PORT_INVALID")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def _write(self, code, value):
            raw = canonical_bytes(value)
            if len(raw) > MAX_PACKET_BYTES:
                code, raw = 503, b'{"status":"UNAVAILABLE"}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if (self.path != "/v1/gateway" or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Type") != "application/json" or len(lengths) != 1):
                    raise ControlError("NETWORK_GATEWAY_REQUEST_INVALID")
                size = int(lengths[0])
                if not 0 < size <= 32768:
                    raise ControlError("NETWORK_GATEWAY_REQUEST_TOO_LARGE")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ControlError("NETWORK_GATEWAY_REQUEST_INVALID")
                packet = _decode(raw)
                if (not isinstance(packet, dict) or set(packet) != {"schema", "role", "operation", "nonce", "payload", "signature"}
                        or packet["schema"] != REQUEST_SCHEMA or packet["role"] not in _ROLE_OPERATIONS):
                    raise ControlError("NETWORK_GATEWAY_REQUEST_INVALID")
                _hex(packet["nonce"])
                _hex(packet["signature"])
                with gateway._connection():
                    pass
                key = gateway.operator_key if packet["role"] == "admin" else gateway.worker_key
                body = {k: v for k, v in packet.items() if k != "signature"}
                if (packet["operation"] not in _ROLE_OPERATIONS[packet["role"]]
                        or not hmac.compare_digest(packet["signature"], _signature(body, key, REQUEST_DOMAIN))):
                    raise ControlError("NETWORK_GATEWAY_AUTHENTICATION_FAILED")
            except Exception:
                self._write(403, {"status": "REFUSED"})
                return
            try:
                payload = packet["payload"]
                expected = {"authorize": {"action", "authorization"}, "execute": {"action"},
                    "reconcile": {"action_id"}, "identity": set(), "inventory": set()}
                if not isinstance(payload, dict) or set(payload) != expected[packet["operation"]]:
                    raise ControlError("NETWORK_GATEWAY_PAYLOAD_INVALID")
                if packet["operation"] == "execute":
                    result = gateway.execute(payload["action"])
                else:
                    result = getattr(gateway, packet["operation"])(**payload)
            except ControlError as exc:
                result = {"status": "ERROR", "reason": str(exc)}
            except Exception:
                result = {"status": "ERROR", "reason": "NETWORK_GATEWAY_UNAVAILABLE"}
            response = {"schema": RESPONSE_SCHEMA, "operation": packet["operation"],
                "request_digest": digest(body), "result": result}
            response["signature"] = _signature(response, key, RESPONSE_DOMAIN)
            try:
                self._write(200, response)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return BoundedLoopbackServer(("127.0.0.1", port), Handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--authority-url", required=True)
    parser.add_argument("--authority-pin-file", type=Path, required=True)
    parser.add_argument("--authority-request-key-file", type=Path, required=True)
    parser.add_argument("--endpoint-url", required=True)
    parser.add_argument("--endpoint-pin-file", type=Path, required=True)
    parser.add_argument("--endpoint-request-key-file", type=Path, required=True)
    parser.add_argument("--operator-key-file", type=Path, required=True)
    parser.add_argument("--worker-key-file", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--no-initialize", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--drop-begin-response", action="store_true")
    parser.add_argument("--drop-finish-response", action="store_true")
    args = parser.parse_args()
    try:
        if args.initialize and (args.no_initialize or args.db.exists()):
            raise ControlError("NETWORK_INITIALIZATION_REQUIRES_NEW_STATE")
        authority = HTTPExternalAuthorityClient(args.authority_url,
            _private_key_file(args.authority_request_key_file), _decode(args.authority_pin_file.read_bytes()))
        endpoint = HTTPNetworkEndpointClient(args.endpoint_url,
            _private_key_file(args.endpoint_request_key_file), _decode(args.endpoint_pin_file.read_bytes()))
        gateway = NetworkGateway(args.db, gateway_id=args.gateway_id, external_controller=authority,
            endpoint_client=endpoint, operator_key=_private_key_file(args.operator_key_file),
            worker_key=_private_key_file(args.worker_key_file), create=args.initialize,
            drop_begin_response=args.drop_begin_response, drop_finish_response=args.drop_finish_response)
        server = make_gateway_server(gateway, port=args.port)
        ready = {"url": "http://127.0.0.1:" + str(server.server_address[1]), **gateway.identity()}
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
