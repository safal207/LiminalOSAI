"""Exact contracts for the owned synthetic receiver with a durable STOP fence.

Only a receiver transaction may prove COMMITTED or NO_EFFECT. An absent query,
transport failure, authority STOP or gateway return value remains UNKNOWN.
This profile performs one synthetic SQLite insert and no arbitrary callback.
"""
from __future__ import annotations

import json
from typing import Any

from .authority import ACTION_FIELDS, ControlError, canonical_bytes, digest, validate_id
from .external_authority import _hex, _time
from .external_network_protocol import (network_action, validate_endpoint_base_url,
    validate_endpoint_pin, validate_network_action, validate_network_authorization)


RECEIVER_PROFILE = "owned-loopback-receiver-fence-v1"
RECEIVER_PATH = "/v1/record"
RECEIVER_RECEIPT_SCHEMA = "liminal.external-agent-receiver.receipt.v1"
RECEIVER_RECEIPT_DOMAIN = b"liminal-external-agent-receiver-receipt-v1\x00"
RECEIVER_FENCE_SCHEMA = "liminal.external-agent-receiver.fence.v1"
RECEIVER_FENCE_DOMAIN = b"liminal-external-agent-receiver-fence-v1\x00"
RECEIVER_RECEIPT_FIELDS = frozenset({"schema", "endpoint_id", "key_id", "reservation_id",
    "action_id", "attempt_id", "root_id", "execution_id", "epoch", "action_digest",
    "authorization_digest", "body_digest", "terminal_at", "status", "effect_count",
    "fence_digest", "terminal_sequence", "reason", "signature"})
RECEIVER_FENCE_FIELDS = frozenset({"schema", "endpoint_id", "key_id", "root_id", "epoch",
    "fence_sequence", "fenced_at", "status", "signature"})


def _copy(value: Any, maximum: int = 65536) -> Any:
    try:
        raw = canonical_bytes(value)
        if len(raw) > maximum:
            raise ControlError("RECEIVER_PACKET_TOO_LARGE")
        return json.loads(raw)
    except (UnicodeError, RecursionError, OverflowError, TypeError, ValueError) as exc:
        raise ControlError("RECEIVER_JSON_INVALID") from exc


def validate_receiver_action(value: Any) -> dict[str, Any]:
    return validate_network_action(value)


def receiver_action(*, root_id: str, execution_id: str, epoch: int, action_id: str,
                    attempt_id: str, endpoint_url: str, marker: str) -> dict[str, Any]:
    return network_action(root_id=root_id, execution_id=execution_id, epoch=epoch,
        action_id=action_id, attempt_id=attempt_id, endpoint_url=endpoint_url, marker=marker)


def validate_receiver_authorization(action: Any, value: Any, endpoint_id: str) -> dict[str, Any]:
    return validate_network_authorization(action, value, endpoint_id)


def receiver_fence_body(fence: Any, pin: Any) -> dict[str, Any]:
    fence, pin = _copy(fence), validate_endpoint_pin(pin)
    if (type(fence) is not dict or set(fence) != RECEIVER_FENCE_FIELDS
            or fence["schema"] != RECEIVER_FENCE_SCHEMA or fence["status"] != "FENCED"
            or fence["endpoint_id"] != pin["endpoint_id"] or fence["key_id"] != pin["key_id"]
            or type(fence["epoch"]) is not int or not 1 <= fence["epoch"] < 2**63
            or type(fence["fence_sequence"]) is not int or not 1 <= fence["fence_sequence"] < 2**63):
        raise ControlError("RECEIVER_FENCE_INVALID")
    validate_id(fence["root_id"], "root_id")
    _time(fence["fenced_at"])
    _hex(fence["signature"], 128)
    return {k: v for k, v in fence.items() if k != "signature"}


def receiver_receipt_body(receipt: Any, pin: Any) -> dict[str, Any]:
    receipt, pin = _copy(receipt), validate_endpoint_pin(pin)
    if (type(receipt) is not dict or set(receipt) != RECEIVER_RECEIPT_FIELDS
            or receipt["schema"] != RECEIVER_RECEIPT_SCHEMA
            or receipt["endpoint_id"] != pin["endpoint_id"] or receipt["key_id"] != pin["key_id"]
            or receipt["status"] not in ("COMMITTED", "NO_EFFECT")
            or type(receipt["terminal_sequence"]) is not int or not 1 <= receipt["terminal_sequence"] < 2**63
            or type(receipt["effect_count"]) is not int
            or receipt["effect_count"] != (1 if receipt["status"] == "COMMITTED" else 0)):
        raise ControlError("RECEIVER_RECEIPT_INVALID")
    for field in ("reservation_id", "action_id", "attempt_id", "root_id", "execution_id"):
        validate_id(receipt[field], field)
    if type(receipt["epoch"]) is not int or not 1 <= receipt["epoch"] < 2**63:
        raise ControlError("RECEIVER_RECEIPT_INVALID")
    for field in ("action_digest", "authorization_digest", "body_digest"):
        _hex(receipt[field])
    _time(receipt["terminal_at"])
    _hex(receipt["signature"], 128)
    if receipt["status"] == "COMMITTED":
        if receipt["fence_digest"] is not None or receipt["reason"] != "EFFECT_COMMITTED":
            raise ControlError("RECEIVER_RECEIPT_INVALID")
    else:
        _hex(receipt["fence_digest"])
        if receipt["reason"] != "RECEIVER_FENCED":
            raise ControlError("RECEIVER_RECEIPT_INVALID")
    return {k: v for k, v in receipt.items() if k != "signature"}


def _verify(value: Any, pin: Any, validator, domain: bytes) -> bool:
    try:
        body = validator(value, pin)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(
            bytes.fromhex(value["signature"]), domain + canonical_bytes(body))
        return True
    except Exception:
        return False


def verify_receiver_fence(fence: Any, pin: Any) -> bool:
    return _verify(fence, pin, receiver_fence_body, RECEIVER_FENCE_DOMAIN)


def verify_receiver_receipt(receipt: Any, pin: Any) -> bool:
    return _verify(receipt, pin, receiver_receipt_body, RECEIVER_RECEIPT_DOMAIN)


def receipt_matches_action(receipt: Any, action: Any, authorization: Any,
                           reservation_id: str, pin: Any) -> bool:
    try:
        action = validate_receiver_action(action)
        authorization = validate_receiver_authorization(action, authorization, pin["endpoint_id"])
        return (verify_receiver_receipt(receipt, pin)
            and receipt["reservation_id"] == reservation_id
            and receipt["action_digest"] == digest(action)
            and receipt["authorization_digest"] == digest(authorization)
            and receipt["body_digest"] == digest(action["arguments"]["body"])
            and all(type(receipt[k]) is type(action[k]) and receipt[k] == action[k]
                    for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")))
    except Exception:
        return False


def bind_receipt(receipt: Any, pin: Any, action: Any, authorization: Any,
                 reservation_id: str) -> dict[str, Any]:
    if not receipt_matches_action(receipt, action, authorization, reservation_id, pin):
        raise ControlError("RECEIVER_RECEIPT_BINDING_MISMATCH")
    return _copy(receipt)
