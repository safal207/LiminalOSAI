"""Capability-bound defensive HTTP(S) egress mediation.

This module never opens sockets by itself. A host injects DNS and transport
callbacks and must route outbound HTTP(S) through this gateway for the deny
boundary to become effective system-wide.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urljoin, urlparse

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import canonical_sha256

RECEIPT_SCHEMA = "liminal-network-execution-receipt-v0.1"
ZERO_SHA256 = "0" * 64
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

GATEWAY_AUTHORITY = {
    "mode": "http_https_egress_mediation_only",
    "network_mediation": True,
    "dns_validation": True,
    "redirect_validation": True,
    "external_secret_injection": True,
    "direct_socket_guard": True,
    "capability_grant": False,
    "credential_discovery": False,
    "secret_value_export": False,
    "shell_execution": False,
    "deployment": False,
    "merge": False,
    "containment_execution": False,
    "os_firewall_installation": False,
}


class EgressError(ValueError):
    pass


class EgressBlocked(EgressError):
    pass


@dataclass(frozen=True)
class GatewayRequest:
    call_id: str
    subject_id: str
    policy_sha256: str
    method: str
    url: str
    headers: Mapping[str, str]
    body_sha256: str
    secret_refs: Mapping[str, str]
    at_unix: int


@dataclass(frozen=True)
class TransportRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body_sha256: str
    resolved_ips: tuple[str, ...]


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: Mapping[str, str]
    body_sha256: str


@dataclass(frozen=True)
class NetworkExecutionReceipt:
    call_id: str
    subject_id: str
    policy_sha256: str
    method: str
    requested_url_sha256: str
    final_url_sha256: str
    request_sha256: str
    capability_receipt_sha256: str
    dns_chain_sha256: str
    redirect_chain_sha256: str
    response_metadata_sha256: str
    status_code: int
    redirect_count: int
    secret_reference_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    at_unix: int
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "call_id": self.call_id,
            "subject_id": self.subject_id,
            "policy_sha256": self.policy_sha256,
            "method": self.method,
            "requested_url_sha256": self.requested_url_sha256,
            "final_url_sha256": self.final_url_sha256,
            "request_sha256": self.request_sha256,
            "capability_receipt_sha256": self.capability_receipt_sha256,
            "dns_chain_sha256": self.dns_chain_sha256,
            "redirect_chain_sha256": self.redirect_chain_sha256,
            "response_metadata_sha256": self.response_metadata_sha256,
            "status_code": self.status_code,
            "redirect_count": self.redirect_count,
            "secret_reference_sha256": self.secret_reference_sha256,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "at_unix": self.at_unix,
            "authority": GATEWAY_AUTHORITY,
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


Resolver = Callable[[str], Sequence[str]]
Transport = Callable[[TransportRequest], TransportResponse]
SecretResolver = Callable[[str], str]


class DirectSocketGuard:
    """Reference fail-closed hook for hosts that expose direct socket attempts."""

    def authorize(self, *, call_id: str, destination: str) -> None:
        if not call_id or not destination:
            raise EgressBlocked("direct socket request is malformed")
        raise EgressBlocked("direct socket access is denied; use Liminal Egress Gateway")


class EgressGateway:
    def __init__(
        self,
        *,
        broker: CapabilityBroker,
        resolver: Resolver,
        transport: Transport,
        secret_resolver: SecretResolver | None = None,
        max_redirects: int = 3,
        allowed_methods: Sequence[str] = tuple(sorted(ALLOWED_METHODS)),
    ) -> None:
        if not isinstance(max_redirects, int) or isinstance(max_redirects, bool) or not 0 <= max_redirects <= 10:
            raise EgressError("max_redirects must be an integer between 0 and 10")
        methods = frozenset(str(item).upper() for item in allowed_methods)
        if not methods or not methods.issubset(ALLOWED_METHODS):
            raise EgressError("allowed_methods contains unsupported method")
        self.broker = broker
        self.resolver = resolver
        self.transport = transport
        self.secret_resolver = secret_resolver
        self.max_redirects = max_redirects
        self.allowed_methods = methods
        self._receipts: list[NetworkExecutionReceipt] = []

    def execute(self, request: GatewayRequest) -> dict[str, Any]:
        normalized = self._normalize_request(request)
        current_url = normalized.url
        dns_chain: list[dict[str, Any]] = []
        redirects: list[dict[str, Any]] = []
        capability_receipt_sha = ZERO_SHA256
        original_scheme = urlparse(current_url).scheme

        for hop in range(self.max_redirects + 1):
            target = _parse_target(current_url)
            if original_scheme == "https" and target["scheme"] != "https":
                raise EgressBlocked("https redirect downgrade is denied")
            resolved_ips = _resolve_public(self.resolver, target["host"])
            dns_entry = {
                "hop": hop,
                "host": target["host"],
                "port": target["port"],
                "resolved_ips": list(resolved_ips),
            }
            dns_chain.append(dns_entry)

            capability = self.broker.authorize(
                subject_id=normalized.subject_id,
                capability_type="network.connect_domain",
                policy_sha256=normalized.policy_sha256,
                requested_scope={
                    "domains": [target["host"]],
                    "protocols": [target["scheme"]],
                    "ports": [target["port"]],
                },
                action={
                    "operation": "egress_http_request",
                    "call_id": normalized.call_id,
                    "method": normalized.method,
                    "destination": f"{target['scheme']}://{target['host']}:{target['port']}",
                    "url_sha256": _sha_text(current_url),
                    "body_sha256": normalized.body_sha256,
                    "dns_sha256": canonical_sha256(dns_entry),
                    "redirect_hop": hop,
                },
                at_unix=normalized.at_unix,
            )
            capability_receipt_sha = capability["receipt_sha256"]
            if capability["decision"] != "ALLOW":
                raise EgressBlocked("network capability denied: " + ",".join(capability["reason_codes"]))

            transport_headers = dict(normalized.headers)
            secret_ids: dict[str, str] = {}
            for header_name, secret_id in normalized.secret_refs.items():
                if self.secret_resolver is None:
                    raise EgressBlocked("secret reference provided without secret resolver")
                secret_ids[header_name.lower()] = secret_id
                transport_headers[header_name] = self.secret_resolver(secret_id)

            response = self.transport(
                TransportRequest(
                    method=normalized.method,
                    url=current_url,
                    headers=transport_headers,
                    body_sha256=normalized.body_sha256,
                    resolved_ips=resolved_ips,
                )
            )
            _validate_transport_response(response)

            location = _redirect_location(response)
            if location is None:
                return self._final_receipt(
                    request=normalized,
                    final_url=current_url,
                    capability_receipt_sha=capability_receipt_sha,
                    dns_chain=dns_chain,
                    redirects=redirects,
                    response=response,
                    secret_ids=secret_ids,
                )
            if hop >= self.max_redirects:
                raise EgressBlocked("redirect limit exceeded")
            next_url = urljoin(current_url, location)
            next_target = _parse_target(next_url)
            redirects.append({
                "hop": hop,
                "from_url_sha256": _sha_text(current_url),
                "to_url_sha256": _sha_text(next_url),
                "to_host": next_target["host"],
                "to_scheme": next_target["scheme"],
                "status_code": response.status_code,
            })
            current_url = next_url

        raise EgressBlocked("unreachable redirect state")

    def receipts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_document() for item in self._receipts)

    def _normalize_request(self, request: GatewayRequest) -> GatewayRequest:
        if not isinstance(request.call_id, str) or not request.call_id.strip():
            raise EgressError("call_id must be non-empty")
        if not isinstance(request.subject_id, str) or not request.subject_id.strip():
            raise EgressError("subject_id must be non-empty")
        if not isinstance(request.policy_sha256, str) or len(request.policy_sha256) != 64:
            raise EgressError("policy_sha256 must be a SHA-256 digest")
        method = str(request.method).upper()
        if method not in self.allowed_methods:
            raise EgressBlocked("HTTP method is not allowed")
        _parse_target(request.url)
        if not isinstance(request.at_unix, int) or isinstance(request.at_unix, bool) or request.at_unix < 0:
            raise EgressError("at_unix must be a non-negative integer")
        headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
                raise EgressError("headers must contain string names and values")
            if key.lower() in {name.lower() for name in request.secret_refs}:
                raise EgressBlocked("secret header must not be supplied in model-visible headers")
            headers[key] = value
        secret_refs: dict[str, str] = {}
        for header_name, secret_id in request.secret_refs.items():
            if not isinstance(header_name, str) or not header_name.strip() or not isinstance(secret_id, str) or not secret_id.strip():
                raise EgressError("secret_refs must map header names to non-empty secret IDs")
            secret_refs[header_name] = secret_id
        return GatewayRequest(
            call_id=request.call_id,
            subject_id=request.subject_id,
            policy_sha256=request.policy_sha256.lower(),
            method=method,
            url=request.url,
            headers=headers,
            body_sha256=request.body_sha256.lower(),
            secret_refs=secret_refs,
            at_unix=request.at_unix,
        )

    def _final_receipt(
        self,
        *,
        request: GatewayRequest,
        final_url: str,
        capability_receipt_sha: str,
        dns_chain: list[dict[str, Any]],
        redirects: list[dict[str, Any]],
        response: TransportResponse,
        secret_ids: Mapping[str, str],
    ) -> dict[str, Any]:
        safe_response = {
            "status_code": response.status_code,
            "header_names": sorted(str(key).lower() for key in response.headers),
            "body_sha256": response.body_sha256,
        }
        request_safe = {
            "call_id": request.call_id,
            "subject_id": request.subject_id,
            "policy_sha256": request.policy_sha256,
            "method": request.method,
            "url_sha256": _sha_text(request.url),
            "header_names": sorted(str(key).lower() for key in request.headers),
            "body_sha256": request.body_sha256,
            "secret_header_names": sorted(str(key).lower() for key in secret_ids),
        }
        base = NetworkExecutionReceipt(
            call_id=request.call_id,
            subject_id=request.subject_id,
            policy_sha256=request.policy_sha256,
            method=request.method,
            requested_url_sha256=_sha_text(request.url),
            final_url_sha256=_sha_text(final_url),
            request_sha256=canonical_sha256(request_safe),
            capability_receipt_sha256=capability_receipt_sha,
            dns_chain_sha256=canonical_sha256(dns_chain),
            redirect_chain_sha256=canonical_sha256(redirects),
            response_metadata_sha256=canonical_sha256(safe_response),
            status_code=response.status_code,
            redirect_count=len(redirects),
            secret_reference_sha256=canonical_sha256(dict(sorted(secret_ids.items()))),
            decision="ALLOW",
            reason_codes=("capability_allow", "dns_public", "transport_completed"),
            at_unix=request.at_unix,
            receipt_sha256="",
        )
        receipt = NetworkExecutionReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        self._receipts.append(receipt)
        return receipt.as_document()


def _parse_target(url: str) -> dict[str, Any]:
    if not isinstance(url, str) or not url.strip() or url != url.strip():
        raise EgressError("url must be a non-empty trimmed string")
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise EgressBlocked("only http and https are supported")
    if parsed.username is not None or parsed.password is not None:
        raise EgressBlocked("userinfo in URL is denied")
    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host or "." not in host:
        raise EgressBlocked("destination must be an explicit DNS hostname")
    if parsed.fragment:
        raise EgressBlocked("URL fragments are not accepted at the gateway boundary")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise EgressBlocked("invalid destination port") from exc
    return {"scheme": scheme, "host": host, "port": port}


def _resolve_public(resolver: Resolver, host: str) -> tuple[str, ...]:
    values = resolver(host)
    if not values:
        raise EgressBlocked("DNS resolution returned no addresses")
    normalized: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError as exc:
            raise EgressBlocked("DNS resolver returned an invalid IP address") from exc
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise EgressBlocked("DNS resolved to a non-public address")
        normalized.append(str(address))
    return tuple(sorted(set(normalized)))


def _validate_transport_response(response: TransportResponse) -> None:
    if not isinstance(response.status_code, int) or isinstance(response.status_code, bool) or not 100 <= response.status_code <= 599:
        raise EgressError("transport response status_code is invalid")
    if not isinstance(response.body_sha256, str) or len(response.body_sha256) != 64:
        raise EgressError("transport response body_sha256 must be a digest")


def _redirect_location(response: TransportResponse) -> str | None:
    if response.status_code not in {301, 302, 303, 307, 308}:
        return None
    for key, value in response.headers.items():
        if str(key).lower() == "location":
            if not isinstance(value, str) or not value.strip():
                raise EgressBlocked("redirect location is malformed")
            return value.strip()
    raise EgressBlocked("redirect status without Location header")


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
