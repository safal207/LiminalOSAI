"""Strict public API wrapper for the Phase 2 gateway."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .gateway import EgressBlocked, EgressError, EgressGateway as _BaseGateway, GatewayRequest


class EgressGateway(_BaseGateway):
    def _normalize_request(self, request: GatewayRequest) -> GatewayRequest:
        normalized = super()._normalize_request(request)
        host = urlparse(normalized.url).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise EgressBlocked("IP-literal destinations are denied; use an explicitly scoped DNS hostname")
        for value, name in ((normalized.policy_sha256, "policy_sha256"), (normalized.body_sha256, "body_sha256")):
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise EgressError(f"{name} must be a lowercase SHA-256 digest")
        return normalized
