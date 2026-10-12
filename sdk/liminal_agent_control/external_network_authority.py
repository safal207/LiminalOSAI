"""External one-shot authority for the owned loopback POST effect boundary.

Admission and pending/STOP accounting reuse the records authority transaction.
Only a COMMITTED receipt signed by the separately pinned endpoint can settle a
permit. A gateway assertion, timeout or negative local result cannot release it.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

from .authority import ControlError, canonical_bytes, digest
from .external_authority import ExternalAuthorityStore, _time
from .external_network_protocol import (
    validate_endpoint_pin, validate_network_action, verify_endpoint_receipt,
)
from .observer_auth import _crypto


NETWORK_PROFILE = "owned-loopback-network-v1"


class ExternalNetworkAuthorityStore(ExternalAuthorityStore):
    """A network database has an immutable profile and endpoint verification pin.

    The old records metadata remains unchanged. The superclass checks the exact
    metadata inventory on every connection, so neither class can reopen the
    other profile's database or silently repair missing profile configuration.
    """

    def __init__(self, db_path: str | Path, *, endpoint_pin: dict[str, str],
                 authority_id: str, key_id: str, private_key: bytes, receipt_key: bytes,
                 clock: Callable[[], float] = time.time, create: bool = True) -> None:
        self._endpoint_pin = validate_endpoint_pin(endpoint_pin)
        if isinstance(private_key, bytes) and len(private_key) == 32:
            private, _ = _crypto()
            authority_public = private.from_private_bytes(private_key).public_key().public_bytes_raw().hex()
            if self._endpoint_pin["public_key"] == authority_public:
                raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_KEY_MUST_DIFFER")
        super().__init__(db_path, authority_id=authority_id, key_id=key_id,
                         private_key=private_key, receipt_key=receipt_key,
                         clock=clock, create=create)

    def endpoint_pin(self) -> dict[str, str]:
        return dict(self._endpoint_pin)

    def _profile_configuration(self) -> dict[str, str]:
        # Compute current live configuration too: mutating a running object's
        # endpoint pin cannot substitute a new receipt verifier on the same DB.
        return {"profile": NETWORK_PROFILE,
                "endpoint_pin": canonical_bytes(validate_endpoint_pin(self._endpoint_pin)).decode()}

    def _validate_action(self, action: Any) -> dict[str, Any]:
        return validate_network_action(action)

    def create_root(self, root_id: str, receiver_id: str, policy_digest: str, max_actions: int,
                    lifetime_seconds: float) -> dict[str, Any]:
        if receiver_id != self._endpoint_pin["endpoint_id"]:
            raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_IDENTITY_MISMATCH")
        return super().create_root(root_id, receiver_id, policy_digest, max_actions, lifetime_seconds)

    def _verify_terminal_receipt(self, receipt: Any) -> dict[str, Any]:
        if not verify_endpoint_receipt(receipt, self._endpoint_pin):
            raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_RECEIPT_INVALID")
        return json.loads(canonical_bytes(receipt))

    def _bind_terminal_receipt(self, receipt: dict[str, Any], row: sqlite3.Row,
                               root: sqlite3.Row, action: dict[str, Any]) -> str:
        if (receipt["status"] != "COMMITTED"
                or type(receipt["effect_count"]) is not int or receipt["effect_count"] != 1
                or receipt["endpoint_id"] != root["receiver_id"]
                or receipt["endpoint_id"] != self._endpoint_pin["endpoint_id"]
                or receipt["key_id"] != self._endpoint_pin["key_id"]
                or receipt["reservation_id"] != row["reservation_id"]
                or receipt["action_digest"] != row["action_digest"]
                or receipt["authorization_digest"] != row["authorization_digest"]
                or receipt["body_digest"] != digest(action["arguments"]["body"])
                or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("EXTERNAL_AUTHORITY_ENDPOINT_RECEIPT_BINDING_MISMATCH")
        _time(receipt["committed_at"])
        # The complete method, URL and body are covered by action_digest. The
        # endpoint signature asserts its durable commit; the authority checks
        # the independently persisted reservation, action and authorization.
        return "COMMITTED"

    def _terminal_reason_prefix(self) -> str:
        return "AUTHENTICATED_ENDPOINT_"
