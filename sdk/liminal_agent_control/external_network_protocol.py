"""Strict shared contract for one synthetic, owned loopback network record.

This is a separate test profile. It does not widen the public egress gateway or
grant permission to arbitrary HTTP destinations, headers, bodies or methods.
"""
from __future__ import annotations

import json
import math
from typing import Any
from urllib.parse import urlparse

from .authority import ACTION_FIELDS, ControlError, canonical_bytes, digest, validate_id

NETWORK_PROFILE = "owned-loopback-network-v1"
NETWORK_RECEIPT_SCHEMA = "liminal.external-network.receipt.v1"
NETWORK_RECEIPT_DOMAIN = b"liminal-external-network-receipt-v1\x00"
NETWORK_RECEIPT_FIELDS = frozenset({"schema", "endpoint_id", "key_id", "reservation_id",
    "action_id", "attempt_id", "root_id", "execution_id", "epoch", "action_digest",
    "authorization_digest", "body_digest", "committed_at", "status", "effect_count", "signature"})


def _hex(value: Any, length: int = 64) -> str:
    if type(value) is not str or len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise ControlError("NETWORK_DIGEST_INVALID")
    return value


def _copy(value: Any, maximum: int = 16384) -> Any:
    try:
        raw = canonical_bytes(value)
        if len(raw) > maximum:
            raise ControlError("NETWORK_PACKET_TOO_LARGE")
        return json.loads(raw)
    except (UnicodeError, RecursionError, OverflowError, TypeError) as exc:
        raise ControlError("NETWORK_JSON_INVALID") from exc


def validate_endpoint_base_url(value: Any) -> str:
    """Require the canonical numeric loopback origin, without an HTTP path."""
    if type(value) is not str or len(value) > 128:
        raise ControlError("NETWORK_ENDPOINT_INVALID")
    try:
        parsed = urlparse(value)
        port = parsed.port
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None
                or not 1 <= port <= 65535 or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or value != "http://127.0.0.1:" + str(port)):
            raise ControlError("NETWORK_ENDPOINT_INVALID")
    except ValueError as exc:
        raise ControlError("NETWORK_ENDPOINT_INVALID") from exc
    return value


def validate_network_action(value: Any) -> dict[str, Any]:
    value = _copy(value)
    if type(value) is not dict or set(value) != ACTION_FIELDS or value["target"] != "network":
        raise ControlError("NETWORK_ACTION_INVALID")
    for field in ("action_id", "attempt_id", "root_id", "execution_id"):
        validate_id(value[field], field)
    if type(value["epoch"]) is not int or not 1 <= value["epoch"] < 2**63:
        raise ControlError("NETWORK_EPOCH_INVALID")
    args = value["arguments"]
    if type(args) is not dict or set(args) != {"method", "url", "body"} or args["method"] != "POST":
        raise ControlError("NETWORK_REQUEST_INVALID")
    url = args["url"]
    if type(url) is not str or not url.endswith("/v1/record"):
        raise ControlError("NETWORK_ENDPOINT_INVALID")
    validate_endpoint_base_url(url[:-len("/v1/record")])
    body = args["body"]
    if type(body) is not dict or set(body) != {"synthetic_marker"}:
        raise ControlError("NETWORK_SYNTHETIC_BODY_REQUIRED")
    validate_id(body["synthetic_marker"], "synthetic_marker")
    return value


def network_action(*, root_id: str, execution_id: str, epoch: int, action_id: str,
                   attempt_id: str, endpoint_url: str, marker: str) -> dict[str, Any]:
    return validate_network_action({"root_id": root_id, "execution_id": execution_id, "epoch": epoch,
        "action_id": action_id, "attempt_id": attempt_id, "target": "network",
        "arguments": {"method": "POST", "url": validate_endpoint_base_url(endpoint_url) + "/v1/record",
                      "body": {"synthetic_marker": marker}}})


def validate_endpoint_pin(value: Any) -> dict[str, str]:
    value = _copy(value, 2048)
    if type(value) is not dict or set(value) != {"endpoint_id", "key_id", "public_key"}:
        raise ControlError("NETWORK_ENDPOINT_PIN_INVALID")
    validate_id(value["endpoint_id"], "endpoint_id")
    validate_id(value["key_id"], "key_id")
    _hex(value["public_key"])
    return value


# Configuration clients pin an origin; the action separately fixes /v1/record.
validate_endpoint_url = validate_endpoint_base_url


def validate_network_authorization(action: Any, value: Any, endpoint_id: str) -> dict[str, Any]:
    action, value = validate_network_action(action), _copy(value, 2048)
    if type(value) is not dict or set(value) != {"action_digest", "policy_version", "expires_at", "receiver_id"}:
        raise ControlError("NETWORK_AUTHORIZATION_INVALID")
    _hex(value["action_digest"])
    _hex(value["policy_version"])
    validate_id(value["receiver_id"], "receiver_id")
    expiry = value["expires_at"]
    if (type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry < 0
            or value["action_digest"] != digest(action) or value["receiver_id"] != endpoint_id):
        raise ControlError("NETWORK_AUTHORIZATION_BINDING_MISMATCH")
    return value


def endpoint_receipt_body(receipt: Any, pin: Any) -> dict[str, Any]:
    """Validate the signed terminal contract; no absent/zero-effect terminal exists."""
    receipt, pin = _copy(receipt), validate_endpoint_pin(pin)
    if type(receipt) is not dict or set(receipt) != NETWORK_RECEIPT_FIELDS:
        raise ControlError("NETWORK_RECEIPT_INVALID")
    if (receipt["schema"] != NETWORK_RECEIPT_SCHEMA or receipt["status"] != "COMMITTED"
            or type(receipt["effect_count"]) is not int or receipt["effect_count"] != 1
            or receipt["endpoint_id"] != pin["endpoint_id"] or receipt["key_id"] != pin["key_id"]):
        raise ControlError("NETWORK_RECEIPT_INVALID")
    for field in ("endpoint_id", "key_id", "reservation_id", "action_id", "attempt_id", "root_id", "execution_id"):
        validate_id(receipt[field], field)
    if type(receipt["epoch"]) is not int or not 1 <= receipt["epoch"] < 2**63:
        raise ControlError("NETWORK_RECEIPT_INVALID")
    for field in ("action_digest", "authorization_digest", "body_digest"):
        _hex(receipt[field])
    _hex(receipt["signature"], 128)
    at = receipt["committed_at"]
    if type(at) not in (int, float) or not math.isfinite(at) or at < 0:
        raise ControlError("NETWORK_RECEIPT_INVALID")
    return {k: v for k, v in receipt.items() if k != "signature"}


def verify_endpoint_receipt(receipt: Any, pin: Any) -> bool:
    try:
        body = endpoint_receipt_body(receipt, pin)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin["public_key"])).verify(
            bytes.fromhex(receipt["signature"]), NETWORK_RECEIPT_DOMAIN + canonical_bytes(body))
        return True
    except Exception:
        return False


def receipt_matches_action(receipt: Any, action: Any, authorization: Any, reservation_id: str,
                           pin: Any) -> bool:
    """Check evidence binding; a True result still carries no new action permission."""
    try:
        action = validate_network_action(action)
        if not verify_endpoint_receipt(receipt, pin):
            return False
        return (receipt["reservation_id"] == reservation_id and receipt["action_digest"] == digest(action)
            and receipt["authorization_digest"] == digest(authorization)
            and receipt["body_digest"] == digest(action["arguments"]["body"])
            and all(type(receipt[k]) is type(action[k]) and receipt[k] == action[k]
                    for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")))
    except Exception:
        return False


def verify_network_receipt(receipt: Any, pin: Any, action: Any, authorization: Any,
                           reservation_id: str) -> dict[str, Any]:
    if not receipt_matches_action(receipt, action, authorization, reservation_id, pin):
        raise ControlError("NETWORK_RECEIPT_BINDING_MISMATCH")
    return _copy(receipt)
