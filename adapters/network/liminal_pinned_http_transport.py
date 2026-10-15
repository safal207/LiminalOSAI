"""Trusted host transport: literal-IP sockets, original-host TLS, no redirects.

The gateway owns admission and DNS validation. This adapter is deliberately
outside the model-facing SDK. It does not consult environment proxy settings or
perform DNS resolution; callbacks supplied to EgressGateway are otherwise trusted.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
from typing import Callable
from urllib.parse import urlsplit

from sdk.liminal_egress_gateway.gateway import (
    ALLOWED_METHODS, EgressBlocked, EgressError, TransportRequest, TransportResponse,
    _HEADER_NAME, _TRANSPORT_HEADERS, _parse_target, _resolve_public,
)


class PinnedHTTPTransport:
    """Send one bounded request to a validated IP, without implicit retries.

    A host may provide body bytes by digest. The bytes are checked before any
    socket is created; without a body provider only the empty-body digest works.
    Each socket operation has a timeout; independent host cancellation remains
    necessary for a strict wall-clock deadline or already in-flight I/O.
    """

    def __init__(self, *, timeout_seconds: float = 10.0,
                 max_response_bytes: int = 1024 * 1024,
                 body_provider: Callable[[str], bytes] | None = None) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 30:
            raise EgressError("transport timeout must be in (0, 30] seconds")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= 16 * 1024 * 1024:
            raise EgressError("response bound must be in 1..16MiB")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.body_provider = body_provider

    def __call__(self, request: TransportRequest) -> TransportResponse:
        target = _parse_target(request.url)
        if request.method not in ALLOWED_METHODS:
            raise EgressBlocked("unsupported transport method")
        # Defense in depth: this callback can also be called by trusted host code.
        addresses = _resolve_public(lambda _: request.resolved_ips, target["host"])
        headers = dict(request.headers)
        for name, value in headers.items():
            if (not isinstance(name, str) or not _HEADER_NAME.fullmatch(name)
                    or name.lower() in _TRANSPORT_HEADERS
                    or not isinstance(value, str) or any(c in value for c in "\r\n\x00")):
                raise EgressBlocked("invalid or transport-owned request header")
        body = self.body_provider(request.body_sha256) if self.body_provider else b""
        if not isinstance(body, bytes) or hashlib.sha256(body).hexdigest() != request.body_sha256:
            raise EgressBlocked("transport body does not match admitted digest")
        address = ipaddress.ip_address(addresses[0])
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sock = None
        connection = None
        try:
            # socket.create_connection would re-enter getaddrinfo even for an IP.
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_seconds)
            destination = (str(address), target["port"], 0, 0) if address.version == 6 else (str(address), target["port"])
            sock.connect(destination)
            if target["scheme"] == "https":
                context = ssl.create_default_context()
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                    raise EgressBlocked("TLS certificate and hostname verification are mandatory")
                sock = context.wrap_socket(sock, server_hostname=target["host"])
            connection = http.client.HTTPConnection(target["host"], target["port"], timeout=self.timeout_seconds)
            connection.sock = sock
            parsed = urlsplit(request.url)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            default_port = 443 if target["scheme"] == "https" else 80
            headers["Host"] = target["host"] + (f":{target['port']}" if target["port"] != default_port else "")
            headers["Connection"] = "close"
            connection.request(request.method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(self.max_response_bytes + 1)
            if len(payload) > self.max_response_bytes:
                raise EgressBlocked("transport response exceeds configured bound")
            return TransportResponse(response.status, dict(response.getheaders()), hashlib.sha256(payload).hexdigest())
        finally:
            if connection is not None:
                connection.close()
            elif sock is not None:
                sock.close()
