"""G02 admission plus a dedicated receiver-owned G03 terminal boundary."""
from __future__ import annotations

import hashlib
import json

from .authority import ControlError, canonical_bytes, require_key
from .external_agent_effect_gateway import ClosedChannelEffectGateway
from .external_agent_receiver_protocol import RECEIVER_PROFILE, bind_receipt


class ReceiverFencedEffectGateway(ClosedChannelEffectGateway):
    def _call(self, source, operation, *args):
        if source != "endpoint":
            return super()._call(source, operation, *args)
        with self._connection():
            pass
        try:
            return getattr(self.endpoint_client, operation)(*args)
        finally:
            pair = self.endpoint_client.last_call_evidence()
            if pair is not None:
                if pair["request"]["role"] != "gateway" or pair["request"]["operation"] != operation:
                    raise ControlError("AGENT_RECEIVER_ENDPOINT_EVIDENCE_INVALID")
                self._save_evidence(source, pair)

    def _configuration(self):
        from .external_agent_receiver import HTTPReceiverFenceClient
        if not isinstance(self.endpoint_client, HTTPReceiverFenceClient):
            raise ControlError("AGENT_RECEIVER_GATEWAY_PROFILE_REQUIRED")
        configuration = json.loads(super()._configuration())
        configuration.update(schema="liminal-receiver-fenced-effect-gateway-store-v1", profile=RECEIVER_PROFILE,
            receiver_fence={"schema": "liminal-agent-receiver-fence-contract-v1", "required": True,
                "linearization": "RECEIVER_SQLITE_TRANSACTION", "terminal_no_effect": "SIGNED_RECEIVER_ONLY",
                "operator_key_digest": hashlib.sha256(require_key(self.endpoint_client.operator_key)).hexdigest(),
                "execution_authorized": False})
        return canonical_bytes(configuration).decode()

    def identity(self):
        identity = super().identity()
        identity["profile"] = RECEIVER_PROFILE
        return identity

    def _bind_endpoint_receipt(self, receipt, action, authorization, reservation_id):
        return bind_receipt(receipt, self.endpoint_client.pin(), action, authorization, reservation_id)

    def _has_terminal_receipt(self, result):
        if result.get("receipt") is not None:
            receipt = result["receipt"]
            if (type(receipt) is not dict or receipt.get("status") not in ("COMMITTED", "NO_EFFECT")
                    or result.get("outcome") != self._terminal_outcome(receipt)):
                raise ControlError("AGENT_RECEIVER_SETTLEMENT_OUTCOME_MISMATCH")
        return (result.get("status") == "CONSUMED" and result.get("outcome") in ("COMMITTED", "DENIED")
                and result.get("receipt") is not None)

    def _terminal_outcome(self, receipt):
        return "COMMITTED" if receipt["status"] == "COMMITTED" else "DENIED"

    def _terminal_status(self, receipt):
        return receipt["status"]

    def _observation_count_valid(self, observation):
        receipt = observation.get("receipt")
        return (type(observation.get("effect_count")) is int and type(receipt) is dict
                and observation["effect_count"] == receipt.get("effect_count")
                and observation["effect_count"] in (0, 1))

    @staticmethod
    def _result(action_id, status, reason, reservation_id=None, receipt=None, *,
                dispatch_finished=False, settlement_status=None):
        result = ClosedChannelEffectGateway._result(action_id, status, reason, reservation_id, receipt,
            dispatch_finished=dispatch_finished, settlement_status=settlement_status)
        if receipt is not None:
            result["effect_count"] = receipt["effect_count"]
            result["remote_outcome"] = receipt["status"]
        return result
