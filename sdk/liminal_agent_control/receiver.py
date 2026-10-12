"""Owned receiver: linearizable authority acceptance and harmless record writes.

The HTTP service listens only on loopback. All operations require the trusted
broker key. A separate key authenticates observations. Neither key belongs in
an untrusted worker. The unfenced constructor option is a labeled test baseline.
"""
from __future__ import annotations

import argparse
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener

from .authority import (AuthorityStore, ControlError, canonical_bytes, connect, digest,
                        require_key, sign_document, validate_action, validate_id, verify_receipt)
from .brakes_store import SessionAuthority


class Receiver:
    @classmethod
    def open_existing(cls, db_path: str | Path, broker_key: bytes, receipt_key: bytes) -> "Receiver":
        """Bind a governed receiver for read-only source export without initialization.

        This constructs no schema or identity. The source service only exposes
        its challenge-bound issuer, never this receiver's mutating methods.
        """
        path = Path(db_path)
        if (not path.is_absolute() or str(path) != str(path.resolve(strict=True))
                or not path.is_file() or any(p.is_symlink() for p in (path, *path.parents))):
            raise ControlError("RECEIVER_SOURCE_DATABASE_UNSAFE")
        request_key, observation_key = require_key(broker_key), require_key(receipt_key)
        if request_key == observation_key:
            raise ControlError("request and receipt authentication keys must differ")
        with connect(path, create=False) as db:
            meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM receiver_meta")}
            if meta.get("enforcement_profile") != "governed_v1":
                raise ControlError("RECEIVER_SOURCE_GOVERNED_RECEIVER_REQUIRED")
            validate_id(meta.get("receiver_id"), "receiver_id")
            db.execute("SELECT action_id FROM accepted LIMIT 1")
            db.execute("SELECT action_id FROM effects LIMIT 1")
        result = cls.__new__(cls)
        result.db_path = path
        result.broker_key, result.receipt_key = request_key, observation_key
        result.admission_controller = SessionAuthority(path, create=False)
        result.authority = AuthorityStore.__new__(AuthorityStore)
        result.authority.db_path = path
        result.receiver_id = meta["receiver_id"]
        result.enforce_epoch, result.enforcement_profile = True, "governed_v1"
        return result

    def __init__(self, db_path: str | Path, broker_key: bytes, receipt_key: bytes, *,
                 enforce_epoch: bool = True, admission_controller: SessionAuthority | None = None) -> None:
        self.broker_key = require_key(broker_key)
        self.receipt_key = require_key(receipt_key)
        if self.broker_key == self.receipt_key:
            raise ControlError("request and receipt authentication keys must differ")
        if admission_controller is not None:
            if (not isinstance(admission_controller, SessionAuthority) or not enforce_epoch
                    or Path(db_path).resolve() != admission_controller.db_path.resolve()):
                raise ControlError("governed receiver requires the same authority database and epoch enforcement")
        self.admission_controller = admission_controller
        self.authority = AuthorityStore(db_path)
        self.db_path = self.authority.db_path
        self.enforce_epoch = enforce_epoch
        self.enforcement_profile = ("governed_v1" if admission_controller is not None
                                    else "guarded" if enforce_epoch else "baseline_unfenced")
        with connect(self.db_path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS receiver_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accepted (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT UNIQUE NOT NULL,
                    attempt_id TEXT UNIQUE NOT NULL, action_digest TEXT NOT NULL, action_json TEXT NOT NULL,
                    root_id TEXT NOT NULL, execution_id TEXT NOT NULL, accepted_at REAL NOT NULL,
                    status TEXT NOT NULL, receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS effects (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT UNIQUE NOT NULL,
                    arguments_json TEXT NOT NULL, committed_at REAL NOT NULL
                );
            """)
            db.execute("INSERT OR IGNORE INTO receiver_meta VALUES ('receiver_id',?)", ("receiver:" + secrets.token_hex(12),))
            self.receiver_id = db.execute("SELECT value FROM receiver_meta WHERE key='receiver_id'").fetchone()[0]
            db.execute("INSERT OR IGNORE INTO receiver_meta VALUES ('enforcement_profile',?)", (self.enforcement_profile,))
            if db.execute("SELECT value FROM receiver_meta WHERE key='enforcement_profile'").fetchone()[0] != self.enforcement_profile:
                raise ControlError("receiver enforcement profile is immutable; use a separate baseline database")

    def _signed(self, body: dict[str, Any]) -> dict[str, Any]:
        return sign_document({**body, "receiver_id": self.receiver_id, "observed_at": time.time(),
                              "key_id": "receiver-hmac-v1", "enforcement_profile": self.enforcement_profile}, self.receipt_key)

    def verify_receipt(self, receipt: Any) -> bool:
        return verify_receipt(receipt, self.receipt_key) and receipt.get("receiver_id") == self.receiver_id

    def _receipt(self, action: dict[str, Any] | None, status: str, reason: str, *, accepted_at: float | None = None, action_id: str | None = None) -> dict[str, Any]:
        return self._signed({"schema": "liminal.agent-control.receipt.v1", "status": status, "reason": reason,
            "action_id": action["action_id"] if action else action_id,
            "attempt_id": action["attempt_id"] if action else None,
            "root_id": action["root_id"] if action else None,
            "execution_id": action["execution_id"] if action else None,
            "epoch": action["epoch"] if action else None,
            "action_digest": digest(action) if action else None,
            "effect_count": 1 if status == "COMMITTED" else 0,
            "accepted_epoch": action["epoch"] if accepted_at is not None and action else None,
            "accepted_at": accepted_at})

    def create_root(self, root_id: str, owner_ref: str = "operator") -> dict[str, Any]:
        if self.admission_controller is not None:
            raise ControlError("governed roots require explicit host create_session")
        return self._signed(self.authority.create_root(root_id, owner_ref))

    def identity(self) -> dict[str, Any]:
        return self._signed({"schema": "liminal.agent-control.identity.v1", "status": "IDENTITY"})

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        controller = self.admission_controller or self.authority
        return self._signed(controller.bind_execution(root_id, execution_id, parent_execution_id))

    def revoke(self, root_id: str) -> dict[str, Any]:
        if self.admission_controller is not None:
            state = self.admission_controller.stop(root_id)
            with connect(self.db_path) as db:
                revoked_at = db.execute("SELECT revoked_at FROM roots WHERE root_id=?", (root_id,)).fetchone()[0]
            return self._signed({"status": "REVOKED", "root_id": root_id, "epoch": state["epoch"],
                                 "revoked_at": revoked_at, "session_state": state["state"]})
        return self._signed(self.authority.revoke(root_id))

    def _accept(self, db: Any, action: dict[str, Any], authorization: dict[str, Any] | None = None) -> dict[str, Any]:
        existing = db.execute("SELECT * FROM accepted WHERE action_id=? OR attempt_id=?", (action["action_id"], action["attempt_id"])).fetchone()
        if existing:
            if existing["action_digest"] != digest(action):
                return self._receipt(action, "DENIED", "IDEMPOTENCY_BINDING_MISMATCH")
            return json.loads(existing["receipt_json"])
        if self.admission_controller is not None and authorization is None:
            return self._receipt(action, "DENIED", "GRANT_REQUIRED")
        if authorization is not None:
            if not isinstance(authorization, dict) or set(authorization) != {"action_digest", "policy_version", "expires_at", "receiver_id"}:
                return self._receipt(action, "DENIED", "GRANT_INVALID")
            if authorization["receiver_id"] != self.receiver_id:
                return self._receipt(action, "DENIED", "GRANT_RECEIVER_MISMATCH")
            if authorization["action_digest"] != digest(action):
                return self._receipt(action, "DENIED", "GRANT_BINDING_MISMATCH")
            try:
                validate_id(authorization["policy_version"], "policy_version")
                canonical_bytes(authorization)
                expiry = authorization["expires_at"]
                if type(expiry) not in (int, float) or time.time() >= expiry:
                    return self._receipt(action, "DENIED", "AUTHORIZATION_EXPIRED")
            except ControlError:
                return self._receipt(action, "DENIED", "GRANT_INVALID")
        reason = self.authority.denial(db, action, enforce_epoch=self.enforce_epoch)
        if reason:
            return self._receipt(action, "DENIED", reason)
        if self.admission_controller is not None:
            # Governed grants use the immutable policy digest as their version.
            # Legacy version labels remain supported by the ungoverned profile.
            admission = self.admission_controller.admit_in_transaction(
                db, action, channel="records", policy_digest=authorization["policy_version"])
            if admission["status"] != "ADMITTED":
                return self._receipt(action, "DENIED", admission["reason"])
        accepted_at = time.time()
        receipt = self._receipt(action, "ACCEPTED", "AUTHORITY_ACCEPTED", accepted_at=accepted_at)
        db.execute("INSERT INTO accepted(action_id,attempt_id,action_digest,action_json,root_id,execution_id,accepted_at,status,receipt_json) VALUES (?,?,?,?,?,?,?,?,?)",
                   (action["action_id"], action["attempt_id"], digest(action), canonical_bytes(action).decode(),
                    action["root_id"], action["execution_id"], accepted_at, "ACCEPTED", canonical_bytes(receipt).decode()))
        return receipt

    def accept(self, action: dict[str, Any], *, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
        action = validate_action(action)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            receipt = self._accept(db, action, authorization)
        return receipt

    def _finalize(self, db: Any, action_id: str) -> dict[str, Any]:
        row = db.execute("SELECT * FROM accepted WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            return self._receipt(None, "UNKNOWN", "NOT_OBSERVED", action_id=action_id)
        if row["status"] == "COMMITTED":
            return json.loads(row["receipt_json"])
        action = json.loads(row["action_json"])
        receipt = self._receipt(action, "COMMITTED", "RECORD_COMMITTED", accepted_at=row["accepted_at"])
        db.execute("INSERT INTO effects(action_id,arguments_json,committed_at) VALUES (?,?,?)",
                   (action_id, canonical_bytes(action["arguments"]).decode(), receipt["observed_at"]))
        db.execute("UPDATE accepted SET status='COMMITTED',receipt_json=? WHERE action_id=?", (canonical_bytes(receipt).decode(), action_id))
        if self.admission_controller is not None:
            self.admission_controller.finish_action_in_transaction(db, action_id, outcome="COMMITTED")
            # Observation advances only with this receiver's actual committed
            # effect, in the same transaction; an exception rolls everything back.
            from .orientation import confirm_record_in_transaction
            if db.execute("SELECT 1 FROM orientation_profiles WHERE root_id=?", (action["root_id"],)).fetchone():
                confirm_record_in_transaction(
                    db, action_id, receiver_id=self.receiver_id,
                    receipt_digest=digest(receipt), now=self.admission_controller._now())
        return receipt

    def finalize(self, action_id: str) -> dict[str, Any]:
        """Complete an already accepted effect; revocation is not rollback."""
        validate_id(action_id, "action_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            receipt = self._finalize(db, action_id)
        return receipt

    def commit(self, action: dict[str, Any], *, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
        action = validate_action(action)
        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            receipt = self._accept(db, action, authorization)
            if receipt["status"] == "ACCEPTED":
                receipt = self._finalize(db, action["action_id"])
        return receipt

    def query(self, action_id: str) -> dict[str, Any]:
        validate_id(action_id, "action_id")
        with connect(self.db_path) as db:
            row = db.execute("SELECT receipt_json FROM accepted WHERE action_id=?", (action_id,)).fetchone()
        return json.loads(row[0]) if row else self._receipt(None, "UNKNOWN", "NOT_OBSERVED", action_id=action_id)

    def records(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as db:
            rows = db.execute("SELECT a.action_json,e.arguments_json,a.receipt_json FROM effects e JOIN accepted a USING(action_id) ORDER BY e.sequence").fetchall()
        return [{"action": json.loads(row[0]), "arguments": json.loads(row[1]), "receipt": json.loads(row[2])} for row in rows]

    def snapshot(self, root_id: str, execution_id: str | None = None) -> dict[str, Any]:
        validate_id(root_id, "root_id")
        if execution_id is not None:
            validate_id(execution_id, "execution_id")
        with connect(self.db_path) as db:
            db.execute("BEGIN")
            root = db.execute("SELECT epoch FROM roots WHERE root_id=?", (root_id,)).fetchone()
            if root is None:
                raise ControlError("unknown snapshot root")
            rows = db.execute("SELECT * FROM accepted WHERE root_id=? AND (? IS NULL OR execution_id=?) ORDER BY sequence", (root_id, execution_id, execution_id)).fetchall()
            cutoff = db.execute("SELECT COALESCE(MAX(sequence),0) FROM effects").fetchone()[0]
            result = {"schema": "liminal.agent-control.snapshot.v1", "root_id": root_id, "execution_id": execution_id,
                      "epoch": root[0], "receipts": [json.loads(row["receipt_json"]) for row in rows if row["status"] == "COMMITTED"],
                      "accepted_action_ids": [row["action_id"] for row in rows if row["status"] == "ACCEPTED"],
                      "complete": True, "cutoff": cutoff}
        return self._signed(result)


class HTTPReceiverClient:
    def __init__(self, url: str, broker_key: bytes, receipt_key: bytes, *, timeout: float = 3.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ControlError("receiver URL must be loopback HTTP without credentials or path")
        self.url = url.rstrip("/")
        self.broker_key, self.receipt_key = require_key(broker_key), require_key(receipt_key)
        if self.broker_key == self.receipt_key:
            raise ControlError("request and receipt authentication keys must differ")
        self.timeout = timeout
        self.receiver_id: str | None = None

    def verify_receipt(self, receipt: Any) -> bool:
        return verify_receipt(receipt, self.receipt_key) and (self.receiver_id is None or receipt.get("receiver_id") == self.receiver_id)

    def _call(self, operation: str, **params: Any) -> Any:
        message = sign_document({"operation": operation, "params": params}, self.broker_key)
        request = Request(self.url + "/v1/control", data=canonical_bytes(message), headers={"Content-Type": "application/json"}, method="POST")
        # Environment HTTP proxies must not receive even authenticated pilot traffic.
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise ControlError("receiver redirects are forbidden")

        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=self.timeout) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ControlError("receiver response too large")
        document = json.loads(raw)
        if not self.verify_receipt(document):
            raise ControlError("receiver authentication failed")
        self.receiver_id = document["receiver_id"]
        if document.get("status") == "ERROR":
            raise ControlError(document["reason"])
        if operation == "records":
            return document["records"]
        return document

    def create_root(self, root_id: str, owner_ref: str = "operator") -> dict[str, Any]:
        return self._call("create_root", root_id=root_id, owner_ref=owner_ref)

    def identity(self) -> dict[str, Any]:
        return self._call("identity")

    def bind_execution(self, root_id: str, execution_id: str, parent_execution_id: str | None = None) -> dict[str, Any]:
        return self._call("bind_execution", root_id=root_id, execution_id=execution_id, parent_execution_id=parent_execution_id)

    def revoke(self, root_id: str) -> dict[str, Any]:
        return self._call("revoke", root_id=root_id)

    def accept(self, action: dict[str, Any], *, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._call("accept", action=action, authorization=authorization)

    def finalize(self, action_id: str) -> dict[str, Any]:
        return self._call("finalize", action_id=action_id)

    def commit(self, action: dict[str, Any], *, authorization: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._call("commit", action=action, authorization=authorization)

    def query(self, action_id: str) -> dict[str, Any]:
        return self._call("query", action_id=action_id)

    def records(self) -> list[dict[str, Any]]:
        return self._call("records")

    def snapshot(self, root_id: str, execution_id: str | None = None) -> dict[str, Any]:
        return self._call("snapshot", root_id=root_id, execution_id=execution_id)


def make_server(receiver: Receiver, *, port: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/v1/control":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 65536:
                    self.send_error(413)
                    return
                message = json.loads(self.rfile.read(length))
                if not verify_receipt(message, receiver.broker_key) or set(message) != {"operation", "params", "signature"}:
                    self.send_error(403)
                    return
                operation, params = message["operation"], message["params"]
                if operation not in {"identity", "create_root", "bind_execution", "revoke", "accept", "finalize", "commit", "query", "records", "snapshot"} or not isinstance(params, dict):
                    raise ControlError("unknown operation")
                result = getattr(receiver, operation)(**params)
                if operation == "records":
                    result = receiver._signed({"status": "RECORDS", "records": result})
            except (ValueError, TypeError, ControlError, OverflowError, RecursionError) as exc:
                result = receiver._signed({"status": "ERROR", "reason": str(exc)})
            encoded = canonical_bytes(result)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            try:
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Receiver commit survives a lost response.

        def log_message(self, *_: Any) -> None:
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--broker-key-file", required=True)
    parser.add_argument("--receipt-key-file", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--governed", action="store_true", help="require durable session admission; sessions are created by the host")
    args = parser.parse_args()
    admission = SessionAuthority(args.db) if args.governed else None
    receiver = Receiver(args.db, Path(args.broker_key_file).read_bytes(), Path(args.receipt_key_file).read_bytes(),
                        admission_controller=admission)
    server = make_server(receiver, port=args.port)
    host, port = server.server_address
    print(json.dumps({"host": host, "port": port, "url": f"http://{host}:{port}", "receiver_id": receiver.receiver_id}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
