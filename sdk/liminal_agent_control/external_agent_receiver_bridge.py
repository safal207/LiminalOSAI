"""G03 bridge observation format; terminal absence requires a receiver proof."""
from __future__ import annotations
import json
from typing import Any
from .authority import ControlError, canonical_bytes, digest
from .external_agent_bridge import ExternalAgentBridge, _RESULT_FIELDS
from .external_agent_receiver_protocol import RECEIVER_PROFILE, verify_receiver_receipt


class ReceiverFencedAgentBridge(ExternalAgentBridge):
    def __init__(self, **arguments):
        super().__init__(**arguments)
        route = self.configuration().get("effect_gateway_configuration", {})
        if (route.get("schema") != "liminal-receiver-fenced-effect-gateway-store-v1"
                or route.get("profile") != RECEIVER_PROFILE or route.get("receiver_fence", {}).get("required") is not True):
            raise ControlError("AGENT_RECEIVER_BRIDGE_PROFILE_REQUIRED")
        self._receiver_pin = json.loads(canonical_bytes(route["endpoint_pin"]))

    def _public_result(self, action: dict, result: Any) -> dict:
        result = json.loads(canonical_bytes(result))
        if (type(result) is not dict or set(result) != _RESULT_FIELDS or result["action_id"] != action["action_id"]
                or result["execution_authorized"] is not False or result["status"] not in {"COMMITTED", "NO_EFFECT", "UNKNOWN", "DENIED"}
                or type(result["dispatch_finished"]) is not bool or len(canonical_bytes(result)) > self.budget.max_frame_bytes - 512):
            raise ControlError("AGENT_HOST_RESULT_INVALID")
        receipt = result["receipt"]
        if receipt is None:
            if (result["status"] not in {"UNKNOWN", "DENIED"} or result["effect_count"] is not None
                    or result["remote_outcome"] is not None or result["settlement_status"] not in {None, "UNKNOWN"}
                    or result["status"] == "DENIED" and (result["dispatch_finished"] is not False or result["settlement_status"] is not None)):
                raise ControlError("AGENT_RECEIVER_HOST_PROOF_REQUIRED")
            return super()._public_result(action, result)
        if (not verify_receiver_receipt(receipt, self._receiver_pin)
                or receipt["action_digest"] != digest(action) or receipt["body_digest"] != digest(action["arguments"]["body"])
                or any(type(receipt[k]) is not type(action[k]) or receipt[k] != action[k] for k in
                    ("action_id", "attempt_id", "root_id", "execution_id", "epoch"))
                or result["reservation_id"] != receipt["reservation_id"]
                or type(result["effect_count"]) is not int or result["effect_count"] != receipt["effect_count"]
                or result["remote_outcome"] != receipt["status"]
                or result["status"] not in {receipt["status"], "UNKNOWN"}
                or result["settlement_status"] != ("UNKNOWN" if result["status"] == "UNKNOWN" else "SETTLED")):
            raise ControlError("AGENT_RECEIVER_HOST_PROOF_INVALID")
        return result
