"""Dedicated authority settlement profile for the synthetic G03 receiver.

Signed NO_EFFECT settles the already consumed permit as DENIED in the existing
authority journal. It never renews the permit or supplies fresh authorization.
"""
from __future__ import annotations

import json

from .authority import ControlError, canonical_bytes, digest
from .external_authority import _time
from .external_network_authority import ExternalNetworkAuthorityStore
from .external_agent_receiver_protocol import RECEIVER_PROFILE, verify_receiver_receipt


class ExternalAgentReceiverAuthorityStore(ExternalNetworkAuthorityStore):
    def _profile_configuration(self):
        configuration = super()._profile_configuration()
        configuration["profile"] = RECEIVER_PROFILE
        return configuration

    def _verify_terminal_receipt(self, receipt):
        if not verify_receiver_receipt(receipt, self._endpoint_pin):
            raise ControlError("EXTERNAL_AUTHORITY_RECEIVER_RECEIPT_INVALID")
        return json.loads(canonical_bytes(receipt))

    def _bind_terminal_receipt(self, receipt, row, root, action):
        if (receipt["endpoint_id"] != root["receiver_id"]
                or receipt["reservation_id"] != row["reservation_id"]
                or receipt["action_digest"] != row["action_digest"]
                or receipt["authorization_digest"] != row["authorization_digest"]
                or receipt["body_digest"] != digest(action["arguments"]["body"])
                or any(type(receipt[field]) is not type(action[field]) or receipt[field] != action[field]
                       for field in ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))):
            raise ControlError("EXTERNAL_AUTHORITY_RECEIVER_RECEIPT_BINDING_MISMATCH")
        _time(receipt["terminal_at"])
        return "COMMITTED" if receipt["status"] == "COMMITTED" else "DENIED"

    def _terminal_reason_prefix(self):
        return "AUTHENTICATED_RECEIVER_"
