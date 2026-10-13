"""External admission for the separately pinned isolated-agent lifecycle.

CREATE/START parent accounting and terminal settlement retain command-v1's
locked invariants. A distinct profile and receipt domain prevent reopening
either profile's state or using the other's quiescence proofs.
"""
from __future__ import annotations

import json
from typing import Any

from .authority import ControlError, canonical_bytes
from .external_command_authority import ExternalCommandAuthorityStore
from .external_agent_protocol import (
    AGENT_PROFILE, validate_agent_action, validate_agent_supervisor_pin,
    verify_agent_receipt,
)


class ExternalAgentAuthorityStore(ExternalCommandAuthorityStore):
    def _profile_configuration(self) -> dict[str, str]:
        return {"profile": AGENT_PROFILE,
                "supervisor_pin": canonical_bytes(validate_agent_supervisor_pin(self._supervisor_pin)).decode()}

    def _validate_action(self, action: Any) -> dict[str, Any]:
        return validate_agent_action(action)

    def _verify_terminal_receipt(self, receipt: Any) -> dict[str, Any]:
        if not verify_agent_receipt(receipt, self._supervisor_pin):
            raise ControlError("EXTERNAL_AUTHORITY_AGENT_RECEIPT_INVALID")
        return json.loads(canonical_bytes(receipt))

    def _terminal_reason_prefix(self) -> str:
        return "AUTHENTICATED_AGENT_SUPERVISOR_QUIESCENT_"
