"""Separately owned receiver whose STOP fence and effect share one transaction.

The only effect is an insert of a synthetic marker in this receiver's SQLite
database. BEGIN IMMEDIATE orders that insert against the durable root fence.
The signing key, request keys and database belong outside the worker/gateway
rollback domain. This bounded fixture makes no general network-effect claim.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request

from .authority import ControlError, canonical_bytes, connect, digest, require_key, validate_id
from .external_authority import _hex, _time, validate_authority_pin
from .external_authority_service import (
    REQUEST_SCHEMA as AUTHORITY_REQUEST_SCHEMA, _private_key_file, verify_authority_response,
)
from .external_network_endpoint import BoundedLoopbackServer, HTTPNetworkEndpointClient, _decode
from .external_network_protocol import validate_endpoint_base_url, validate_endpoint_pin
from .external_agent_receiver_protocol import (
    RECEIVER_PROFILE, RECEIVER_PATH, RECEIVER_RECEIPT_SCHEMA, RECEIVER_RECEIPT_DOMAIN,
    RECEIVER_FENCE_SCHEMA, RECEIVER_FENCE_DOMAIN, _copy, bind_receipt,
    validate_receiver_action, validate_receiver_authorization, verify_receiver_fence,
    receipt_matches_action,
)
from .observer_auth import _crypto


PROFILE = RECEIVER_PROFILE
REQUEST_SCHEMA = "liminal-external-agent-receiver-request-v1"
RESPONSE_SCHEMA = "liminal-external-agent-receiver-response-v1"
REQUEST_DOMAIN = b"liminal-external-agent-receiver-request-v1\x00"
RESPONSE_DOMAIN = b"liminal-external-agent-receiver-response-v1\x00"
STOP_CHALLENGE_DOMAIN = b"liminal-external-agent-receiver-stop-challenge-v1\x00"
MAX_PACKET_BYTES = 65536
MAX_ROOTS = 128
MAX_EXECUTIONS = 1024
MAX_TERMINALS = 1024
MAX_REQUESTS = 8192
_REQUEST_FIELDS = {"schema", "role", "operation", "nonce", "payload", "signature"}
_RESPONSE_FIELDS = {"schema", "endpoint_id", "key_id", "operation", "request_digest", "result", "signature"}
_ROLES = {"gateway": {"commit", "query"}, "operator": {"create_root", "bind_execution", "stop"}}
_PATHS = {"commit": RECEIVER_PATH, "query": "/v1/query", "create_root": "/v1/receiver-control",
          "bind_execution": "/v1/receiver-control", "stop": "/v1/receiver-control"}
_PAYLOADS = {"commit": {"action", "authorization", "permit_request", "permit"},
    "query": {"action_id", "reservation_id"}, "create_root": {"root_id", "epoch"},
    "bind_execution": {"root_id", "execution_id", "epoch", "parent_execution_id"},
    "stop": {"root_id", "epoch"}}
_TABLES = {"receiver_meta", "receiver_roots", "receiver_executions", "receiver_fences",
           "receiver_terminals", "receiver_effects", "receiver_requests"}


def _request_signature(body: dict[str, Any], key: bytes) -> str:
    return hmac.new(require_key(key), REQUEST_DOMAIN + canonical_bytes(body), hashlib.sha256).hexdigest()


def _epoch(value: Any) -> int:
    if type(value) is not int or not 1 <= value < 2**63:
        raise ControlError("RECEIVER_EPOCH_INVALID")
    return value


class ReceiverFenceStore:
    """Immutable profile, separately owned keys and receiver-local lineage.

    A COMMITTED terminal and its effect, or a NO_EFFECT terminal and its fence
    binding, commit atomically. Terminal retries never create a second effect.
    Public control methods are for trusted callers; HTTP controls require the
    separate operator key. Returned FENCED acknowledgements follow COMMIT.
    """

    def __init__(self, db_path: str | Path, *, endpoint_id: str, key_id: str, private_key: bytes,
                 authority_pin: dict[str, str], endpoint_url: str, gateway_key: bytes,
                 operator_key: bytes, create: bool = True) -> None:
        validate_id(endpoint_id, "endpoint_id")
        validate_id(key_id, "key_id")
        if type(private_key) is not bytes or len(private_key) != 32:
            raise ControlError("RECEIVER_SIGNING_KEY_INVALID")
        self.gateway_key, self.operator_key = require_key(gateway_key), require_key(operator_key)
        if len({private_key, self.gateway_key, self.operator_key}) != 3:
            raise ControlError("RECEIVER_KEYS_MUST_DIFFER")
        private, _ = _crypto()
        self._private_bytes = private_key
        self._private_key = private.from_private_bytes(private_key)
        self._pin = validate_endpoint_pin({"endpoint_id": endpoint_id, "key_id": key_id,
            "public_key": self._private_key.public_key().public_bytes_raw().hex()})
        self.authority_pin = validate_authority_pin(authority_pin)
        if self.authority_pin["public_key"] == self._pin["public_key"]:
            raise ControlError("RECEIVER_KEYS_MUST_DIFFER")
        self.url = validate_endpoint_base_url(endpoint_url)
        self.db_path = Path(db_path).absolute()
        if any(p.is_symlink() for p in (self.db_path, *self.db_path.parents)):
            raise ControlError("RECEIVER_DATABASE_UNSAFE")
        if not self.db_path.exists():
            if not create:
                raise ControlError("RECEIVER_STATE_MISSING")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.db_path.open("xb"):
                    pass
            except FileExistsError as exc:
                raise ControlError("RECEIVER_INITIALIZATION_RACE") from exc
            self.db_path.chmod(0o600)
            with connect(self.db_path, create=False) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE receiver_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE receiver_roots(root_id TEXT PRIMARY KEY,epoch INTEGER NOT NULL,
                        fenced INTEGER NOT NULL CHECK(fenced IN (0,1)));
                    CREATE TABLE receiver_executions(execution_id TEXT PRIMARY KEY,
                        root_id TEXT NOT NULL REFERENCES receiver_roots(root_id),epoch INTEGER NOT NULL,
                        parent_execution_id TEXT REFERENCES receiver_executions(execution_id));
                    CREATE TABLE receiver_fences(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        root_id TEXT UNIQUE NOT NULL REFERENCES receiver_roots(root_id),
                        epoch INTEGER NOT NULL,fence_json TEXT NOT NULL,fence_digest TEXT NOT NULL);
                    CREATE TABLE receiver_terminals(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_id TEXT UNIQUE NOT NULL,attempt_id TEXT UNIQUE NOT NULL,
                        reservation_id TEXT UNIQUE NOT NULL,root_id TEXT NOT NULL REFERENCES receiver_roots(root_id),
                        execution_id TEXT NOT NULL REFERENCES receiver_executions(execution_id),epoch INTEGER NOT NULL,
                        action_digest TEXT NOT NULL,authorization_digest TEXT NOT NULL,permit_digest TEXT UNIQUE NOT NULL,
                        action_json TEXT NOT NULL,authorization_json TEXT NOT NULL,
                        permit_request_json TEXT NOT NULL,permit_json TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('COMMITTED','NO_EFFECT')),receipt_json TEXT NOT NULL);
                    CREATE TABLE receiver_effects(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        reservation_id TEXT UNIQUE NOT NULL REFERENCES receiver_terminals(reservation_id),
                        body_json TEXT NOT NULL,body_digest TEXT NOT NULL);
                    CREATE TABLE receiver_requests(nonce TEXT PRIMARY KEY,request_digest TEXT NOT NULL,
                        request_json TEXT NOT NULL,result_json TEXT NOT NULL);
                """)
                db.executemany("INSERT INTO receiver_meta VALUES (?,?)", (
                    ("configuration", self._configuration()), ("transition_sequence", "0"),
                    *((operation + "_request_count", "0") for operation in _PATHS)))
        with self._connection():
            pass

    def _configuration(self) -> str:
        keys = (require_key(self.gateway_key), require_key(self.operator_key), self._private_bytes)
        if len(set(keys)) != 3:
            raise ControlError("RECEIVER_KEYS_MUST_DIFFER")
        pin = validate_endpoint_pin(self._pin)
        authority = validate_authority_pin(self.authority_pin)
        if pin["public_key"] != self._private_key.public_key().public_bytes_raw().hex():
            raise ControlError("RECEIVER_CONFIGURATION_IMMUTABLE")
        if authority["public_key"] == pin["public_key"]:
            raise ControlError("RECEIVER_KEYS_MUST_DIFFER")
        return canonical_bytes({"schema": "liminal-agent-receiver-store-v1", "profile": PROFILE,
            "pin": pin, "authority_pin": authority, "url": validate_endpoint_base_url(self.url),
            "gateway_key_digest": hashlib.sha256(keys[0]).hexdigest(),
            "operator_key_digest": hashlib.sha256(keys[1]).hexdigest(),
            "private_key_digest": hashlib.sha256(keys[2]).hexdigest()}).decode()

    @contextmanager
    def _connection(self):
        if not self.db_path.is_file() or any(p.is_symlink() for p in (self.db_path, *self.db_path.parents)):
            raise ControlError("RECEIVER_STATE_MISSING")
        db = connect(self.db_path, create=False)
        try:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM receiver_meta")}
            if (tables != _TABLES or set(meta) != {"configuration", "transition_sequence", *(op + "_request_count" for op in _PATHS)}
                    or meta["configuration"] != self._configuration()):
                raise ControlError("RECEIVER_CONFIGURATION_IMMUTABLE")
            for name, value in meta.items():
                if name != "configuration" and (not value.isdigit() or not 0 <= int(value) < 2**63):
                    raise ControlError("RECEIVER_COUNTER_INVALID")
            with db:
                yield db
        finally:
            db.close()

    def pin(self) -> dict[str, str]:
        with self._connection():
            return dict(self._pin)

    def _permit(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = validate_receiver_action(payload["action"])
        authorization = validate_receiver_authorization(action, payload["authorization"], self._pin["endpoint_id"])
        request, permit = _copy(payload["permit_request"]), _copy(payload["permit"])
        if action["arguments"]["url"] != self.url + RECEIVER_PATH:
            raise ControlError("RECEIVER_URL_BINDING_MISMATCH")
        if (type(request) is not dict or set(request) != {"schema", "role", "operation", "nonce", "payload"}
                or request["schema"] != AUTHORITY_REQUEST_SCHEMA or request["role"] != "receiver"
                or request["operation"] != "begin"
                or canonical_bytes(request["payload"]) != canonical_bytes({"action": action, "authorization": authorization})):
            raise ControlError("RECEIVER_PERMIT_REQUEST_MISMATCH")
        _hex(request["nonce"])
        result = verify_authority_response(request, permit, self.authority_pin)
        if (result.get("status") != "PERMITTED" or result.get("outcome") is not None
                or result.get("action_digest") != digest(action)
                or result.get("receiver_id") != self._pin["endpoint_id"]
                or any(type(result.get(field)) is not type(action[field]) or result.get(field) != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("RECEIVER_PERMIT_BINDING_MISMATCH")
        return {"action": action, "authorization": authorization, "permit_request": request, "permit": permit,
                "reservation_id": validate_id(result.get("reservation_id"), "reservation_id")}

    def _root(self, db: sqlite3.Connection, root_id: Any, epoch: Any) -> sqlite3.Row:
        validate_id(root_id, "root_id")
        _epoch(epoch)
        row = db.execute("SELECT * FROM receiver_roots WHERE root_id=?", (root_id,)).fetchone()
        if row is None or row["epoch"] != epoch:
            raise ControlError("RECEIVER_ROOT_BINDING_MISMATCH")
        return row

    def _fence(self, db: sqlite3.Connection, root: sqlite3.Row) -> dict[str, Any] | None:
        row = db.execute("SELECT * FROM receiver_fences WHERE root_id=?", (root["root_id"],)).fetchone()
        if not root["fenced"]:
            if row is not None:
                raise ControlError("RECEIVER_FENCE_CORRUPT")
            return None
        if row is None:
            raise ControlError("RECEIVER_FENCE_CORRUPT")
        fence = json.loads(row["fence_json"])
        if (not verify_receiver_fence(fence, self._pin) or fence["root_id"] != root["root_id"]
                or fence["epoch"] != root["epoch"] or fence["fence_sequence"] != row["sequence"]
                or digest(fence) != row["fence_digest"]):
            raise ControlError("RECEIVER_FENCE_CORRUPT")
        return fence

    def _terminal(self, db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        receipt = json.loads(row["receipt_json"])
        action, authorization = json.loads(row["action_json"]), json.loads(row["authorization_json"])
        validated = self._permit({"action": action, "authorization": authorization,
            "permit_request": json.loads(row["permit_request_json"]), "permit": json.loads(row["permit_json"])})
        if (not receipt_matches_action(receipt, action, authorization, row["reservation_id"], self._pin)
                or any(row[field] != action[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                or row["action_digest"] != digest(action) or row["authorization_digest"] != digest(authorization)
                or row["status"] != receipt["status"] or row["permit_digest"] != digest(validated["permit"])
                or row["sequence"] != receipt["terminal_sequence"]
                or validated["reservation_id"] != row["reservation_id"]
                or receipt["terminal_at"] < validated["permit"]["issued_at"]):
            raise ControlError("RECEIVER_TERMINAL_CORRUPT")
        self._root(db, row["root_id"], row["epoch"])
        self._execution(db, row["execution_id"], row["root_id"], row["epoch"])
        effect = db.execute("SELECT * FROM receiver_effects WHERE reservation_id=?", (row["reservation_id"],)).fetchone()
        if receipt["status"] == "COMMITTED":
            if (effect is None or effect["body_digest"] != receipt["body_digest"]
                    or canonical_bytes(json.loads(effect["body_json"])) != canonical_bytes(action["arguments"]["body"])):
                raise ControlError("RECEIVER_EFFECT_CORRUPT")
            fence = self._fence(db, self._root(db, row["root_id"], row["epoch"]))
            if fence is not None and receipt["terminal_sequence"] >= fence["fence_sequence"]:
                raise ControlError("RECEIVER_COMMIT_ORDER_CORRUPT")
        else:
            fence = self._fence(db, self._root(db, row["root_id"], row["epoch"]))
            if (effect is not None or fence is None or digest(fence) != receipt["fence_digest"]
                    or receipt["terminal_at"] < fence["fenced_at"]
                    or receipt["terminal_sequence"] <= fence["fence_sequence"]):
                raise ControlError("RECEIVER_NO_EFFECT_CORRUPT")
        return receipt

    @staticmethod
    def _execution(db: sqlite3.Connection, execution_id: str, root_id: str, epoch: int) -> sqlite3.Row:
        """Validate the complete persisted ancestry, including cycles/deletion."""
        seen: set[str] = set()
        first = None
        while execution_id is not None:
            if execution_id in seen or len(seen) >= MAX_EXECUTIONS:
                raise ControlError("RECEIVER_EXECUTION_BINDING_MISMATCH")
            seen.add(execution_id)
            execution = db.execute("SELECT * FROM receiver_executions WHERE execution_id=?", (execution_id,)).fetchone()
            if execution is None or execution["root_id"] != root_id or execution["epoch"] != epoch:
                raise ControlError("RECEIVER_EXECUTION_BINDING_MISMATCH")
            if first is None:
                first = execution
            execution_id = execution["parent_execution_id"]
        return first

    @staticmethod
    def _next_sequence(db: sqlite3.Connection) -> int:
        current = int(db.execute("SELECT value FROM receiver_meta WHERE key='transition_sequence'").fetchone()[0])
        if current >= 2**63 - 2:
            raise ControlError("RECEIVER_SEQUENCE_CAPACITY")
        sequence = current + 1
        db.execute("UPDATE receiver_meta SET value=? WHERE key='transition_sequence'", (str(sequence),))
        return sequence

    def _mutate(self, db: sqlite3.Connection, operation: str, payload: dict[str, Any],
                before_commit: Callable[[], None] | None) -> dict[str, Any]:
        if operation == "create_root":
            root_id, epoch = validate_id(payload["root_id"], "root_id"), _epoch(payload["epoch"])
            row = db.execute("SELECT * FROM receiver_roots WHERE root_id=?", (root_id,)).fetchone()
            if row is not None:
                if row["epoch"] != epoch or row["fenced"]:
                    raise ControlError("RECEIVER_ROOT_IMMUTABLE")
            else:
                if db.execute("SELECT COUNT(*) FROM receiver_roots").fetchone()[0] >= MAX_ROOTS:
                    raise ControlError("RECEIVER_ROOT_CAPACITY")
                db.execute("INSERT INTO receiver_roots VALUES (?,?,0)", (root_id, epoch))
            return {"status": "ROOT_CREATED", "root_id": root_id, "epoch": epoch}
        if operation == "bind_execution":
            root = self._root(db, payload["root_id"], payload["epoch"])
            execution_id = validate_id(payload["execution_id"], "execution_id")
            parent = payload["parent_execution_id"]
            if parent is not None:
                validate_id(parent, "parent_execution_id")
                parent_row = db.execute("SELECT * FROM receiver_executions WHERE execution_id=?", (parent,)).fetchone()
                if parent_row is None or parent_row["root_id"] != root["root_id"] or parent_row["epoch"] != root["epoch"]:
                    raise ControlError("RECEIVER_PARENT_BINDING_MISMATCH")
            existing = db.execute("SELECT * FROM receiver_executions WHERE execution_id=?", (execution_id,)).fetchone()
            if existing is not None:
                if (existing["root_id"], existing["epoch"], existing["parent_execution_id"]) != (root["root_id"], root["epoch"], parent):
                    raise ControlError("RECEIVER_EXECUTION_IMMUTABLE")
            else:
                if root["fenced"]:
                    raise ControlError("RECEIVER_ROOT_FENCED")
                if db.execute("SELECT COUNT(*) FROM receiver_executions").fetchone()[0] >= MAX_EXECUTIONS:
                    raise ControlError("RECEIVER_EXECUTION_CAPACITY")
                db.execute("INSERT INTO receiver_executions VALUES (?,?,?,?)", (execution_id, root["root_id"], root["epoch"], parent))
            return {"status": "BOUND", **payload}
        if operation == "stop":
            root = self._root(db, payload["root_id"], payload["epoch"])
            fence = self._fence(db, root)
            if fence is None:
                sequence = self._next_sequence(db)
                db.execute("INSERT INTO receiver_fences(sequence,root_id,epoch,fence_json,fence_digest) VALUES (?,?,?,'','')",
                    (sequence, root["root_id"], root["epoch"]))
                fence = {"schema": RECEIVER_FENCE_SCHEMA, "status": "FENCED", **self._identity(),
                    "root_id": root["root_id"], "epoch": root["epoch"], "fence_sequence": sequence,
                    "fenced_at": _time(time.time())}
                fence["signature"] = self._private_key.sign(RECEIVER_FENCE_DOMAIN + canonical_bytes(fence)).hex()
                db.execute("UPDATE receiver_fences SET fence_json=?,fence_digest=? WHERE sequence=?",
                    (canonical_bytes(fence).decode(), digest(fence), sequence))
                db.execute("UPDATE receiver_roots SET fenced=1 WHERE root_id=?", (root["root_id"],))
            return fence
        if operation == "query":
            action_id = validate_id(payload["action_id"], "action_id")
            reservation_id = validate_id(payload["reservation_id"], "reservation_id")
            row = db.execute("SELECT * FROM receiver_terminals WHERE action_id=? AND reservation_id=?",
                (action_id, reservation_id)).fetchone()
            receipt = None if row is None else self._terminal(db, row)
            return {"status": "UNKNOWN" if receipt is None else "OBSERVED", **payload,
                "effect_count": None if receipt is None else receipt["effect_count"], "receipt": receipt}
        action, authorization = payload["action"], payload["authorization"]
        reservation_id = payload["reservation_id"]
        rows = db.execute("SELECT * FROM receiver_terminals WHERE action_id=? OR attempt_id=? OR reservation_id=? OR permit_digest=?",
            (action["action_id"], action["attempt_id"], reservation_id, digest(payload["permit"]))).fetchall()
        if rows:
            if (len(rows) != 1 or rows[0]["action_digest"] != digest(action)
                    or rows[0]["authorization_digest"] != digest(authorization)
                    or rows[0]["reservation_id"] != reservation_id or rows[0]["permit_digest"] != digest(payload["permit"])
                    or canonical_bytes(json.loads(rows[0]["permit_request_json"])) != canonical_bytes(payload["permit_request"])):
                raise ControlError("RECEIVER_REUSE_MISMATCH")
            return self._terminal(db, rows[0])
        root = self._root(db, action["root_id"], action["epoch"])
        self._execution(db, action["execution_id"], action["root_id"], action["epoch"])
        fence = self._fence(db, root)
        if db.execute("SELECT COUNT(*) FROM receiver_terminals").fetchone()[0] >= MAX_TERMINALS:
            raise ControlError("RECEIVER_TERMINAL_CAPACITY")
        at = _time(time.time())
        if at < payload["permit"]["issued_at"] or (fence is not None and at < fence["fenced_at"]):
            raise ControlError("RECEIVER_CLOCK_BINDING_MISMATCH")
        sequence = self._next_sequence(db)
        receipt = {"schema": RECEIVER_RECEIPT_SCHEMA, **self._identity(), "reservation_id": reservation_id,
            **{field: action[field] for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": digest(action), "authorization_digest": digest(authorization),
            "body_digest": digest(action["arguments"]["body"]), "terminal_at": at,
            "terminal_sequence": sequence,
            "status": "COMMITTED" if fence is None else "NO_EFFECT", "effect_count": 1 if fence is None else 0,
            "fence_digest": None if fence is None else digest(fence),
            "reason": "EFFECT_COMMITTED" if fence is None else "RECEIVER_FENCED"}
        receipt["signature"] = self._private_key.sign(RECEIVER_RECEIPT_DOMAIN + canonical_bytes(receipt)).hex()
        db.execute("""INSERT INTO receiver_terminals(sequence,action_id,attempt_id,reservation_id,root_id,execution_id,epoch,
            action_digest,authorization_digest,permit_digest,action_json,authorization_json,permit_request_json,
            permit_json,status,receipt_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sequence, action["action_id"], action["attempt_id"], reservation_id, action["root_id"], action["execution_id"],
             action["epoch"], digest(action), digest(authorization), digest(payload["permit"]), canonical_bytes(action).decode(),
             canonical_bytes(authorization).decode(), canonical_bytes(payload["permit_request"]).decode(),
             canonical_bytes(payload["permit"]).decode(), receipt["status"], canonical_bytes(receipt).decode()))
        if fence is None:
            db.execute("INSERT INTO receiver_effects(reservation_id,body_json,body_digest) VALUES (?,?,?)",
                (reservation_id, canonical_bytes(action["arguments"]["body"]).decode(), receipt["body_digest"]))
        # This hook holds the write transaction after staging the terminal and
        # effect. STOP must wait; a crash here rolls both staged rows back.
        # The outside hook holds no transaction, so STOP can win instead.
        if before_commit is not None:
            before_commit()
        return receipt

    def _identity(self) -> dict[str, str]:
        return {"endpoint_id": self._pin["endpoint_id"], "key_id": self._pin["key_id"]}

    def _execute(self, operation: str, payload: Any, *, request: dict[str, Any] | None = None,
                 before_transaction: Callable[[], None] | None = None,
                 before_commit: Callable[[], None] | None = None) -> dict[str, Any]:
        payload = _copy(payload)
        if operation not in _PAYLOADS or type(payload) is not dict or set(payload) != _PAYLOADS[operation]:
            raise ControlError("RECEIVER_PAYLOAD_INVALID")
        request = None if request is None else _copy(request)
        validated = self._permit(payload) if operation == "commit" else payload
        if operation == "commit" and before_transaction is not None:
            before_transaction()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if request is not None:
                existing = db.execute("SELECT * FROM receiver_requests WHERE nonce=?", (request["nonce"],)).fetchone()
                if existing is not None:
                    if existing["request_digest"] != digest(request) or existing["request_json"] != canonical_bytes(request).decode():
                        raise ControlError("RECEIVER_REQUEST_NONCE_REUSED")
                    result = json.loads(existing["result_json"])
                    # An exact retry is observation of the original operation.
                    # Durable terminals/fences are rechecked before returning.
                    if operation == "commit":
                        row = db.execute("SELECT * FROM receiver_terminals WHERE reservation_id=?", (validated["reservation_id"],)).fetchone()
                        if row is None or canonical_bytes(self._terminal(db, row)) != canonical_bytes(result):
                            raise ControlError("RECEIVER_REQUEST_CACHE_CORRUPT")
                    if operation == "stop":
                        fence = self._fence(db, self._root(db, payload["root_id"], payload["epoch"]))
                        if canonical_bytes(fence) != canonical_bytes(result):
                            raise ControlError("RECEIVER_REQUEST_CACHE_CORRUPT")
                    if operation == "query":
                        if result.get("status") == "UNKNOWN":
                            if (set(result) != {"status", "action_id", "reservation_id", "effect_count", "receipt"}
                                    or result["effect_count"] is not None or result["receipt"] is not None
                                    or any(result[field] != payload[field] for field in ("action_id", "reservation_id"))):
                                raise ControlError("RECEIVER_REQUEST_CACHE_CORRUPT")
                        else:
                            row = db.execute("SELECT * FROM receiver_terminals WHERE action_id=? AND reservation_id=?",
                                (payload["action_id"], payload["reservation_id"])).fetchone()
                            if (row is None or result.get("status") != "OBSERVED"
                                    or canonical_bytes(self._terminal(db, row)) != canonical_bytes(result.get("receipt"))
                                    or result.get("effect_count") != result["receipt"]["effect_count"]
                                    or any(result.get(field) != payload[field] for field in ("action_id", "reservation_id"))):
                                raise ControlError("RECEIVER_REQUEST_CACHE_CORRUPT")
                    return _copy(result)
                count = db.execute("SELECT COUNT(*) FROM receiver_requests").fetchone()[0]
                # Ordinary requests, including fresh-nonce repetitions of an
                # existing STOP, cannot spend the first-fence reserve. Exact
                # cached replay was handled above without allocating a row.
                # A root can transition to fenced only once, so at most one
                # reserved request per known root can be added after the pool
                # fills; total request growth remains bounded.
                if count >= MAX_REQUESTS:
                    if operation != "stop":
                        raise ControlError("RECEIVER_REQUEST_CAPACITY")
                    root = self._root(db, payload["root_id"], payload["epoch"])
                    if self._fence(db, root) is not None or count >= MAX_REQUESTS + MAX_ROOTS:
                        raise ControlError("RECEIVER_REQUEST_CAPACITY")
            key = operation + "_request_count"
            count = int(db.execute("SELECT value FROM receiver_meta WHERE key=?", (key,)).fetchone()[0])
            if count >= 2**63 - 1:
                raise ControlError("RECEIVER_COUNTER_CAPACITY")
            db.execute("UPDATE receiver_meta SET value=? WHERE key=?", (str(count + 1), key))
            result = self._mutate(db, operation, validated, before_commit)
            if request is not None:
                db.execute("INSERT INTO receiver_requests VALUES (?,?,?,?)",
                    (request["nonce"], digest(request), canonical_bytes(request).decode(), canonical_bytes(result).decode()))
        # SQLite FULL synchronous COMMIT completes before this acknowledgement.
        return _copy(result)

    def create_root(self, root_id: str, epoch: int = 1) -> dict[str, Any]:
        return self._execute("create_root", {"root_id": root_id, "epoch": epoch})

    def bind_execution(self, root_id: str, execution_id: str, epoch: int = 1,
                       parent_execution_id: str | None = None) -> dict[str, Any]:
        return self._execute("bind_execution", {"root_id": root_id, "execution_id": execution_id,
            "epoch": epoch, "parent_execution_id": parent_execution_id})

    def stop(self, root_id: str, epoch: int = 1) -> dict[str, Any]:
        return self._execute("stop", {"root_id": root_id, "epoch": epoch})

    def commit(self, action: Any, authorization: Any, permit_request: Any, permit: Any, *,
               before_transaction: Callable[[], None] | None = None,
               before_commit: Callable[[], None] | None = None) -> dict[str, Any]:
        return self._execute("commit", {"action": action, "authorization": authorization,
            "permit_request": permit_request, "permit": permit}, before_transaction=before_transaction,
            before_commit=before_commit)

    def query(self, action_id: str, reservation_id: str) -> dict[str, Any]:
        return self._execute("query", {"action_id": action_id, "reservation_id": reservation_id})

    def handle_authenticated_request(self, request: dict[str, Any], *,
                 before_transaction: Callable[[], None] | None = None,
                 before_commit: Callable[[], None] | None = None) -> dict[str, Any]:
        return self._execute(request["operation"], request["payload"], request=request,
            before_transaction=before_transaction, before_commit=before_commit)

    def inventory(self) -> dict[str, Any]:
        with self._connection() as db:
            db.execute("BEGIN")
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM receiver_meta")}
            roots = db.execute("SELECT * FROM receiver_roots ORDER BY root_id").fetchall()
            fences = [fence for root in roots if (fence := self._fence(db, root)) is not None]
            terminals = db.execute("SELECT * FROM receiver_terminals ORDER BY sequence").fetchall()
            receipts = [self._terminal(db, row) for row in terminals]
            effects = db.execute("SELECT * FROM receiver_effects ORDER BY sequence").fetchall()
            return {**self._identity(), "pin": dict(self._pin), "profile": PROFILE, "url": self.url,
                "transition_sequence": int(meta["transition_sequence"]),
                **{op + "_request_count": int(meta[op + "_request_count"]) for op in _PATHS},
                "roots": [dict(row) for row in roots],
                "executions": [dict(row) for row in db.execute("SELECT * FROM receiver_executions ORDER BY execution_id")],
                "fences": fences, "terminals": receipts, "receipts": receipts,
                "effects": [{"sequence": row["sequence"], "reservation_id": row["reservation_id"],
                    "body": json.loads(row["body_json"]), "body_digest": row["body_digest"]} for row in effects],
                "requests": [{"action_id": row["action_id"], "permit_request": json.loads(row["permit_request_json"]),
                    "permit": json.loads(row["permit_json"]), "permit_digest": row["permit_digest"]} for row in terminals],
                "authenticated_requests": [{"request": json.loads(row["request_json"]),
                    "request_digest": row["request_digest"], "result": json.loads(row["result_json"])}
                    for row in db.execute("SELECT * FROM receiver_requests ORDER BY rowid")]}


def verify_receiver_response(request: dict[str, Any], response: Any, pin: Any) -> dict[str, Any]:
    request, response, pin = _copy(request), _copy(response), validate_endpoint_pin(pin)
    if (type(response) is not dict or set(response) != _RESPONSE_FIELDS or response["schema"] != RESPONSE_SCHEMA
            or response["endpoint_id"] != pin["endpoint_id"] or response["key_id"] != pin["key_id"]
            or response["operation"] != request["operation"]
            or response["request_digest"] != digest({k: v for k, v in request.items() if k != "signature"})
            or type(response["result"]) is not dict):
        raise ControlError("RECEIVER_RESPONSE_BINDING_MISMATCH")
    _hex(response["signature"], 128)
    _, public = _crypto()
    try:
        public.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(bytes.fromhex(response["signature"]),
            RESPONSE_DOMAIN + canonical_bytes({k: v for k, v in response.items() if k != "signature"}))
    except Exception as exc:
        raise ControlError("RECEIVER_RESPONSE_SIGNATURE_INVALID") from exc
    return _copy(response["result"])


class HTTPReceiverFenceClient(HTTPNetworkEndpointClient):
    """Separate operator controls with restart-recoverable exact STOP requests.

    STOP uses a context-bound challenge so a lost first ACK can be replayed at
    the receiver's storage ceiling. Every retry still performs HTTP and checks
    the receiver's signed response; no local result substitutes for that proof.
    """

    def __init__(self, url: str, request_key: bytes, pin: dict[str, str], *, timeout: float = 3,
                 operator_key: bytes | None = None) -> None:
        super().__init__(url, request_key, pin, timeout=timeout)
        self._call_local = threading.local()
        self._evidence_lock = threading.RLock()
        self.operator_key = None if operator_key is None else require_key(operator_key)
        if self.operator_key is not None and self.operator_key == self.request_key:
            raise ControlError("RECEIVER_KEYS_MUST_DIFFER")

    @property
    def evidence(self) -> list[dict[str, Any]]:
        with self._evidence_lock:
            return super().evidence

    def _stop_nonce(self, payload: dict[str, Any]) -> str:
        if type(payload) is not dict or set(payload) != _PAYLOADS["stop"]:
            raise ControlError("RECEIVER_PAYLOAD_INVALID")
        validate_id(payload["root_id"], "root_id")
        context = {"schema": REQUEST_SCHEMA, "role": "operator", "operation": "stop",
            "endpoint_url": validate_endpoint_base_url(self.url),
            "endpoint_pin": validate_endpoint_pin(self._pin),
            "root_id": payload["root_id"], "epoch": _epoch(payload["epoch"])}
        return hmac.new(require_key(self.operator_key),
            STOP_CHALLENGE_DOMAIN + canonical_bytes(context), hashlib.sha256).hexdigest()

    def _call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._call_local.pair = None
        if operation not in _PATHS:
            raise ControlError("RECEIVER_OPERATION_INVALID")
        role = "gateway" if operation in _ROLES["gateway"] else "operator"
        key = self.request_key if role == "gateway" else self.operator_key
        if key is None:
            raise ControlError("RECEIVER_OPERATOR_KEY_REQUIRED")
        body = {"schema": REQUEST_SCHEMA, "role": role, "operation": operation,
            "nonce": self._stop_nonce(payload) if operation == "stop" else secrets.token_hex(32),
            "payload": _copy(payload)}
        packet = {**body, "signature": _request_signature(body, key)}
        wire = canonical_bytes(packet)
        if len(wire) > MAX_PACKET_BYTES:
            raise ControlError("RECEIVER_PACKET_TOO_LARGE")
        url = validate_endpoint_base_url(self.url) + _PATHS[operation]
        request = Request(url, data=wire, method="POST", headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as incoming:
                if incoming.status != 200 or incoming.geturl() != url:
                    raise ControlError("RECEIVER_RESPONSE_INVALID")
                raw = incoming.read(MAX_PACKET_BYTES + 1)
            if len(raw) > MAX_PACKET_BYTES:
                raise ControlError("RECEIVER_PACKET_TOO_LARGE")
            response = _decode(raw)
            result = verify_receiver_response(body, response, self._pin)
            pair = {"request": body, "response": response}
            self._call_local.pair = _copy(pair, 2 * MAX_PACKET_BYTES)
            with self._evidence_lock:
                # Exact STOP replay has the same authenticated pair. Keep the
                # per-call proof above, while preserving unique capture nonces.
                # Conflicting signed responses remain visible, never collapsed.
                duplicate = operation == "stop" and any(
                    canonical_bytes(item) == canonical_bytes(pair) for item in self._evidence)
                if not duplicate:
                    self._evidence.append(_copy(pair, 2 * MAX_PACKET_BYTES))
                    if len(self._evidence) > 1024:
                        self._evidence.pop(0)
            if result.get("status") == "ERROR":
                raise ControlError(result.get("reason", "RECEIVER_REFUSED"))
            return result
        except ControlError:
            raise
        except (HTTPError, URLError, OSError, ValueError, TypeError) as exc:
            raise ControlError("RECEIVER_UNAVAILABLE") from exc

    def last_call_evidence(self) -> dict[str, Any] | None:
        """The current thread's authenticated call, detached from shared history.

        A transport or verification failure leaves None; a signed refusal is
        retained. Concurrent STOP/query/commit calls cannot replace this pair.
        """
        pair = getattr(self._call_local, "pair", None)
        return None if pair is None else _copy(pair, 2 * MAX_PACKET_BYTES)

    def create_root(self, root_id: str, epoch: int = 1) -> dict[str, Any]:
        return self._call("create_root", {"root_id": root_id, "epoch": epoch})

    def bind_execution(self, root_id: str, execution_id: str, epoch: int = 1,
                       parent_execution_id: str | None = None) -> dict[str, Any]:
        return self._call("bind_execution", {"root_id": root_id, "execution_id": execution_id,
            "epoch": epoch, "parent_execution_id": parent_execution_id})

    def stop(self, root_id: str, epoch: int = 1) -> dict[str, Any]:
        return self._call("stop", {"root_id": root_id, "epoch": epoch})


def make_receiver_server(store: ReceiverFenceStore, *, port: int,
                         before_transaction: Callable[[], None] | None = None,
                         before_commit: Callable[[], None] | None = None,
                         drop_commit_response: bool = False, drop_stop_response: bool = False,
                         query_unavailable: bool = False) -> ThreadingHTTPServer:
    if type(port) is not int or validate_endpoint_base_url(f"http://127.0.0.1:{port}") != store.url:
        raise ControlError("RECEIVER_SERVER_BINDING_MISMATCH")
    fault_lock = threading.Lock()
    remaining = {"commit": int(bool(drop_commit_response)), "stop": int(bool(drop_stop_response))}

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
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if (self.path not in set(_PATHS.values()) or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Type") != "application/json" or len(lengths) != 1):
                    raise ControlError("RECEIVER_REQUEST_INVALID")
                size = int(lengths[0])
                if not 0 < size <= MAX_PACKET_BYTES:
                    raise ControlError("RECEIVER_PACKET_TOO_LARGE")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ControlError("RECEIVER_REQUEST_INVALID")
                packet = _decode(raw)
                if (type(packet) is not dict or set(packet) != _REQUEST_FIELDS or packet["schema"] != REQUEST_SCHEMA
                        or type(packet["role"]) is not str or packet["role"] not in _ROLES
                        or type(packet["operation"]) is not str or packet["operation"] not in _ROLES[packet["role"]]
                        or self.path != _PATHS[packet["operation"]]):
                    raise ControlError("RECEIVER_REQUEST_INVALID")
                _hex(packet["nonce"])
                _hex(packet["signature"])
                body = {k: v for k, v in packet.items() if k != "signature"}
                with store._connection():
                    pass
                key = store.gateway_key if packet["role"] == "gateway" else store.operator_key
                if not hmac.compare_digest(packet["signature"], _request_signature(body, key)):
                    raise ControlError("RECEIVER_AUTHENTICATION_FAILED")
            except Exception:
                self._write(403, {"status": "REFUSED"})
                return
            try:
                result = store.handle_authenticated_request(body, before_transaction=before_transaction,
                    before_commit=before_commit)
                if packet["operation"] == "commit":
                    receipt = result
                    result = {"status": "OBSERVED", "action_id": receipt["action_id"],
                        "reservation_id": receipt["reservation_id"], "effect_count": receipt["effect_count"], "receipt": receipt}
                elif packet["operation"] == "query" and query_unavailable:
                    result = {"status": "UNKNOWN", **packet["payload"], "effect_count": None, "receipt": None}
                with fault_lock:
                    if remaining.get(packet["operation"], 0):
                        remaining[packet["operation"]] -= 1
                        self.close_connection = True
                        return
            except ControlError as exc:
                result = {"status": "ERROR", "reason": str(exc)}
            except Exception:
                result = {"status": "ERROR", "reason": "RECEIVER_UNAVAILABLE"}
            response = {"schema": RESPONSE_SCHEMA, **store._identity(), "operation": packet["operation"],
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
    parser.add_argument("--operator-key-file", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--no-initialize", action="store_true")
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--drop-first-commit-response", action="store_true")
    parser.add_argument("--drop-first-stop-response", action="store_true")
    parser.add_argument("--query-unavailable", action="store_true")
    parser.add_argument("--barrier-phase", choices=("outside", "inside"), default="outside")
    parser.add_argument("--barrier-reached-file", type=Path)
    parser.add_argument("--barrier-release-file", type=Path)
    args = parser.parse_args()
    try:
        if args.initialize and (args.no_initialize or args.db.exists()):
            raise ControlError("RECEIVER_INITIALIZATION_REQUIRES_NEW_STATE")
        if bool(args.barrier_reached_file) != bool(args.barrier_release_file):
            raise ControlError("RECEIVER_BARRIER_CONFIGURATION_INVALID")
        store = ReceiverFenceStore(args.db, endpoint_id=args.endpoint_id, key_id=args.key_id,
            private_key=_private_key_file(args.private_key_file, length=32),
            authority_pin=_decode(args.authority_pin_file.read_bytes()),
            endpoint_url=f"http://127.0.0.1:{args.port}", gateway_key=_private_key_file(args.gateway_key_file),
            operator_key=_private_key_file(args.operator_key_file), create=args.initialize)
        barrier_lock, barrier_used = threading.Lock(), False
        def barrier():
            nonlocal barrier_used
            with barrier_lock:
                if barrier_used:
                    return
                barrier_used = True
            args.barrier_reached_file.write_text("reached\n")
            deadline = time.monotonic() + 30
            while not args.barrier_release_file.exists():
                if time.monotonic() >= deadline:
                    raise ControlError("RECEIVER_TEST_BARRIER_TIMEOUT")
                time.sleep(0.01)
        server = make_receiver_server(store, port=args.port,
            before_transaction=barrier if args.barrier_reached_file and args.barrier_phase == "outside" else None,
            before_commit=barrier if args.barrier_reached_file and args.barrier_phase == "inside" else None,
            drop_commit_response=args.drop_first_commit_response, drop_stop_response=args.drop_first_stop_response,
            query_unavailable=args.query_unavailable)
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
