"""Receiver-owned, challenge-bound public evidence without exporting secrets.

The issuer creates its signing key locally and can only sign a snapshot read
from its configured receiver. It has no operation for signing caller-provided
exports. Run it in the separate trusted receiver/signing process; instantiating
it in the controller process alone does not provide that separation.

An enrolled public key authenticates this receiver's statement, not independent
ownership, an honest host, exhaustive effects outside this receiver, or storage
rollback resistance. Receiver SQLite, provisioning and the issuer clock remain
trusted. Restart generates a new key which requires a new root enrollment.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Callable

from .authority import ControlError, canonical_bytes, connect, digest, validate_action, validate_id
from .observer_auth import _crypto, _hex, _request
from .orientation import _time
from .receiver import Receiver


SOURCE_SCHEMA = "liminal-receiver-source-v1"
SOURCE_DOMAIN = b"liminal-receiver-source-v1\x00"
MAX_STATEMENT_BYTES = 120000
MAX_EXPORT_ROWS = 1024
_PIN_FIELDS = {"issuer_id", "key_id", "public_key", "receiver_id", "source_id"}
_STATEMENT_FIELDS = {"schema", "issuer_id", "key_id", "receiver_id", "source_id", "request_digest",
                     "issued_at", "expires_at", "export_digest", "export", "signature"}
_SNAPSHOT_FIELDS = {"schema", "root_id", "execution_id", "epoch", "receipts", "accepted_action_ids",
                    "complete", "cutoff", "receiver_id", "observed_at", "key_id", "enforcement_profile", "signature"}
_RECEIPT_FIELDS = {"schema", "status", "reason", "action_id", "attempt_id", "root_id", "execution_id",
                   "epoch", "action_digest", "effect_count", "accepted_epoch", "accepted_at", "receiver_id",
                   "observed_at", "key_id", "enforcement_profile", "signature"}


def validate_issuer_pin(value: Any) -> dict[str, str]:
    """Validate a trusted provisioning pin; never take it from the source packet."""
    try:
        if not isinstance(value, dict) or set(value) != _PIN_FIELDS:
            raise ControlError("RECEIVER_SOURCE_PIN_MALFORMED")
        for field in _PIN_FIELDS - {"public_key"}:
            validate_id(value[field], field)
        _hex(value["public_key"], 64)
        return json.loads(canonical_bytes(value))
    except (ControlError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ControlError("RECEIVER_SOURCE_PIN_MALFORMED") from exc


def _receipt(receipt: Any, request: dict[str, Any], receiver_id: str, *, status: str) -> None:
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
    if (receipt["schema"] != "liminal.agent-control.receipt.v1" or receipt["status"] != status
            or receipt["receiver_id"] != receiver_id or receipt["key_id"] != "receiver-hmac-v1"
            or receipt["enforcement_profile"] != "governed_v1"
            or any(type(receipt[field]) is not type(request[field]) or receipt[field] != request[field]
                   for field in ("root_id", "execution_id", "epoch"))
            or type(receipt["effect_count"]) is not int
            or receipt["effect_count"] != (1 if status == "COMMITTED" else 0)
            or type(receipt["accepted_epoch"]) is not int or receipt["accepted_epoch"] != request["epoch"]):
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
    validate_id(receipt["action_id"], "action_id")
    validate_id(receipt["attempt_id"], "attempt_id")
    validate_id(receipt["reason"], "receipt reason")
    _hex(receipt["action_digest"], 64)
    _hex(receipt["signature"], 64)
    _time(receipt["observed_at"])
    _time(receipt["accepted_at"])


def _validate_export(request: dict[str, Any], export: Any, receiver_id: str) -> None:
    """Check signed export consistency without distributing receiver HMAC keys."""
    if not isinstance(export, dict) or set(export) != {"receiver_records", "receiver_snapshot"}:
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
    records, snapshot = export["receiver_records"], export["receiver_snapshot"]
    if (not isinstance(records, list) or len(records) > MAX_EXPORT_ROWS
            or not isinstance(snapshot, dict) or set(snapshot) != _SNAPSHOT_FIELDS
            or snapshot["schema"] != "liminal.agent-control.snapshot.v1"
            or snapshot["receiver_id"] != receiver_id or snapshot["complete"] is not True
            or snapshot["key_id"] != "receiver-hmac-v1" or snapshot["enforcement_profile"] != "governed_v1"
            or any(type(snapshot[field]) is not type(request[field]) or snapshot[field] != request[field]
                   for field in ("root_id", "execution_id", "epoch"))
            or type(snapshot["cutoff"]) is not int or not 0 <= snapshot["cutoff"] < 2**63
            or not isinstance(snapshot["receipts"], list) or len(snapshot["receipts"]) != len(records)
            or not isinstance(snapshot["accepted_action_ids"], list)
            or len(snapshot["accepted_action_ids"]) + len(records) > MAX_EXPORT_ROWS):
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
    _hex(snapshot["signature"], 64)
    _time(snapshot["observed_at"])
    pending = snapshot["accepted_action_ids"]
    for action_id in pending:
        validate_id(action_id, "accepted action_id")
    if len(set(pending)) != len(pending):
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
    observed = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"action", "arguments", "receipt"}:
            raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
        action = validate_action(record["action"])
        receipt = record["receipt"]
        _receipt(receipt, request, receiver_id, status="COMMITTED")
        if (any(type(action[field]) is not type(request[field]) or action[field] != request[field]
                for field in ("root_id", "execution_id", "epoch"))
                or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                       for field in ("action_id", "attempt_id"))
                or receipt["action_digest"] != digest(action)
                or not isinstance(record["arguments"], dict)
                or canonical_bytes(record["arguments"]) != canonical_bytes(action["arguments"])
                or action["action_id"] in observed or action["action_id"] in pending):
            raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
        observed[action["action_id"]] = receipt
    if (snapshot["cutoff"] < len(records)
            or canonical_bytes(snapshot["receipts"]) != canonical_bytes([item["receipt"] for item in records])):
        raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")


def verify_source_statement(request: dict[str, Any], statement: Any, pin: dict[str, str], *,
                            now: float | None = None, max_age_seconds: float | None = None) -> dict[str, Any]:
    """Authenticate against an independently provisioned pin and exact challenge.

    ``now=None`` checks the signed interval but does not claim current freshness;
    persisted admission gates supply their trusted clock. A historical VETO may
    be authenticated at its original ingestion time while remaining a permanent
    stop signal. This function never accepts a public key carried in a packet.
    """
    request = _request(request)
    pin = validate_issuer_pin(pin)
    if request["role"] != "reality":
        raise ControlError("RECEIVER_SOURCE_ROLE_MISMATCH")
    try:
        if (not isinstance(statement, dict) or set(statement) != _STATEMENT_FIELDS
                or len(canonical_bytes(statement)) > MAX_STATEMENT_BYTES
                or statement["schema"] != SOURCE_SCHEMA):
            raise ControlError("RECEIVER_SOURCE_MALFORMED")
        statement = json.loads(canonical_bytes(statement))
        for field in ("issuer_id", "key_id", "receiver_id", "source_id"):
            validate_id(statement[field], field)
            if statement[field] != pin[field]:
                raise ControlError("RECEIVER_SOURCE_PIN_MISMATCH")
        _hex(statement["signature"], 128)
        _hex(statement["request_digest"], 64)
        _hex(statement["export_digest"], 64)
        issued, expiry = _time(statement["issued_at"]), _time(statement["expires_at"])
        if statement["request_digest"] != digest(request):
            raise ControlError("RECEIVER_SOURCE_BINDING_MISMATCH")
        if not request["issued_at"] <= issued < expiry <= request["valid_until"]:
            raise ControlError("RECEIVER_SOURCE_STALE")
        if max_age_seconds is not None:
            age = _time(max_age_seconds)
            if age <= 0 or expiry > issued + age:
                raise ControlError("RECEIVER_SOURCE_STALE")
        if now is not None:
            when = _time(now)
            if not issued <= when < expiry or (max_age_seconds is not None and when - issued > age):
                raise ControlError("RECEIVER_SOURCE_STALE")
        _, public = _crypto()
        body = {key: value for key, value in statement.items() if key != "signature"}
        try:
            public.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(
                bytes.fromhex(statement["signature"]), SOURCE_DOMAIN + canonical_bytes(body))
        except Exception as exc:
            raise ControlError("RECEIVER_SOURCE_SIGNATURE_INVALID") from exc
        if statement["export_digest"] != digest(statement["export"]):
            raise ControlError("RECEIVER_SOURCE_EXPORT_DIGEST_MISMATCH")
        _validate_export(request, statement["export"], pin["receiver_id"])
        return statement
    except ControlError as exc:
        if str(exc).startswith("RECEIVER_SOURCE_") or str(exc) == "OBSERVER_AUTH_CRYPTO_UNAVAILABLE":
            raise
        raise ControlError("RECEIVER_SOURCE_MALFORMED") from exc
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        raise ControlError("RECEIVER_SOURCE_MALFORMED") from exc


class ReceiverSourceIssuer:
    """Own one ephemeral key; only actual receiver snapshots are signable."""

    def __init__(self, receiver: Receiver, *, issuer_id: str, source_id: str, key_id: str,
                 clock: Callable[[], float] = time.time, max_age_seconds: float = 20) -> None:
        if not isinstance(receiver, Receiver) or receiver.enforcement_profile != "governed_v1":
            raise ControlError("RECEIVER_SOURCE_GOVERNED_RECEIVER_REQUIRED")
        if not callable(clock):
            raise ControlError("RECEIVER_SOURCE_CONFIGURATION_INVALID")
        for field, value in (("issuer_id", issuer_id), ("source_id", source_id), ("key_id", key_id)):
            validate_id(value, field)
        max_age = _time(max_age_seconds)
        if not 0 < max_age <= 3600:
            raise ControlError("RECEIVER_SOURCE_CONFIGURATION_INVALID")
        private, _ = _crypto()
        self.__private_key = private.generate()
        self.__receiver = receiver
        self.__clock, self.__max_age = clock, max_age
        self.__pin = {"issuer_id": issuer_id, "key_id": key_id, "source_id": source_id,
                      "receiver_id": receiver.receiver_id,
                      "public_key": self.__private_key.public_key().public_bytes_raw().hex()}

    def enrollment(self) -> dict[str, str]:
        return dict(self.__pin)

    def issue(self, request: dict[str, Any]) -> dict[str, Any]:
        request = _request(request)
        if request["role"] != "reality":
            raise ControlError("RECEIVER_SOURCE_ROLE_MISMATCH")
        issued = _time(self.__clock())
        expiry = min(request["valid_until"], issued + self.__max_age)
        if not request["issued_at"] <= issued < expiry:
            raise ControlError("RECEIVER_SOURCE_STALE")
        receiver = self.__receiver
        try:
            with connect(receiver.db_path, create=False) as db:
                db.execute("BEGIN")
                meta = {row["key"]: row["value"] for row in db.execute("SELECT * FROM receiver_meta")}
                root = db.execute("SELECT * FROM roots WHERE root_id=?", (request["root_id"],)).fetchone()
                execution = db.execute("SELECT * FROM executions WHERE execution_id=?", (request["execution_id"],)).fetchone()
                session = db.execute("SELECT * FROM brakes_sessions WHERE root_id=?", (request["root_id"],)).fetchone()
                if (meta.get("receiver_id") != self.__pin["receiver_id"]
                        or meta.get("enforcement_profile") != "governed_v1"
                        or root is None or root["revoked"] or root["epoch"] != request["epoch"]
                        or execution is None or execution["root_id"] != request["root_id"]
                        or execution["epoch"] != request["epoch"] or session is None or session["state"] != "ACTIVE"
                        or session["policy_digest"] != request["policy_digest"]
                        or session["objective_digest"] != request["objective_digest"]):
                    raise ControlError("RECEIVER_SOURCE_BINDING_MISMATCH")
                if not session["last_now"] <= issued < min(session["hard_deadline"], session["lease_until"]):
                    raise ControlError("RECEIVER_SOURCE_STALE")
                if db.execute("""SELECT 1 FROM effects e LEFT JOIN accepted a USING(action_id)
                                 WHERE a.action_id IS NULL OR a.status!='COMMITTED' LIMIT 1""").fetchone():
                    raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
                rows = db.execute("""SELECT a.*, e.arguments_json, e.sequence AS effect_sequence
                    FROM accepted a LEFT JOIN effects e USING(action_id)
                    WHERE a.root_id=? AND a.execution_id=? ORDER BY a.sequence LIMIT ?""",
                    (request["root_id"], request["execution_id"], MAX_EXPORT_ROWS + 1)).fetchall()
                if len(rows) > MAX_EXPORT_ROWS:
                    raise ControlError("RECEIVER_SOURCE_EXPORT_TOO_LARGE")
                records, pending = [], []
                for row in rows:
                    action = validate_action(json.loads(row["action_json"]))
                    receipt = json.loads(row["receipt_json"])
                    if (row["status"] not in {"ACCEPTED", "COMMITTED"}
                            or row["action_digest"] != digest(action)
                            or row["action_id"] != action["action_id"] or row["attempt_id"] != action["attempt_id"]
                            or not receiver.verify_receipt(receipt)):
                        raise ControlError("RECEIVER_SOURCE_RECEIPT_INVALID")
                    _receipt(receipt, request, receiver.receiver_id, status=row["status"])
                    if (receipt["action_digest"] != digest(action)
                            or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                                   for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                            or row["accepted_at"] != receipt["accepted_at"]):
                        raise ControlError("RECEIVER_SOURCE_RECEIPT_INVALID")
                    if row["status"] == "COMMITTED":
                        if row["effect_sequence"] is None:
                            raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
                        records.append({"action": action, "arguments": json.loads(row["arguments_json"]), "receipt": receipt})
                    else:
                        if row["effect_sequence"] is not None:
                            raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID")
                        pending.append(row["action_id"])
                cutoff = db.execute("SELECT COALESCE(MAX(sequence),0) FROM effects").fetchone()[0]
                snapshot = receiver._signed({"schema": "liminal.agent-control.snapshot.v1",
                    "root_id": request["root_id"], "execution_id": request["execution_id"], "epoch": root["epoch"],
                    "receipts": [row["receipt"] for row in records], "accepted_action_ids": pending,
                    "complete": True, "cutoff": cutoff})
                if not receiver.verify_receipt(snapshot):
                    raise ControlError("RECEIVER_SOURCE_RECEIPT_INVALID")
                export = {"receiver_records": records, "receiver_snapshot": snapshot}
                _validate_export(request, export, receiver.receiver_id)
            finished = _time(self.__clock())
            if not issued <= finished < expiry:
                raise ControlError("RECEIVER_SOURCE_STALE")
            body = {"schema": SOURCE_SCHEMA, **{key: value for key, value in self.__pin.items() if key != "public_key"},
                    "request_digest": digest(request), "issued_at": issued, "expires_at": expiry,
                    "export_digest": digest(export), "export": export}
            if len(canonical_bytes({**body, "signature": "0" * 128})) > MAX_STATEMENT_BYTES:
                raise ControlError("RECEIVER_SOURCE_EXPORT_TOO_LARGE")
            return {**body, "signature": self.__private_key.sign(SOURCE_DOMAIN + canonical_bytes(body)).hex()}
        except ControlError:
            raise
        except (TypeError, ValueError, KeyError, OverflowError, RecursionError, sqlite3.Error) as exc:
            raise ControlError("RECEIVER_SOURCE_EXPORT_INVALID") from exc
