"""No-network transport tests: every socket, TLS and HTTP object is mocked."""
import hashlib
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

from adapters.network.liminal_pinned_http_transport import PinnedHTTPTransport
from sdk.liminal_egress_gateway import EgressBlocked, TransportRequest

MODULE = "adapters.network.liminal_pinned_http_transport"
EMPTY = hashlib.sha256(b"").hexdigest()


def transport_request(**changes):
    args = dict(method="GET", url="https://api.example.com/path?q=1", headers={},
                body_sha256=EMPTY, resolved_ips=("93.184.216.34",))
    args.update(changes)
    return TransportRequest(**args)


class PinnedTransportTests(unittest.TestCase):
    def setUp(self):
        self.socket_patch = patch(MODULE + ".socket.socket")
        self.dns_patch = patch(MODULE + ".socket.getaddrinfo", side_effect=AssertionError("unexpected DNS"))
        self.tls_patch = patch(MODULE + ".ssl.create_default_context")
        self.http_patch = patch(MODULE + ".http.client.HTTPConnection")
        self.socket_factory = self.socket_patch.start()
        self.dns = self.dns_patch.start()
        self.tls_factory = self.tls_patch.start()
        self.http_factory = self.http_patch.start()
        for patcher in (self.socket_patch, self.dns_patch, self.tls_patch, self.http_patch):
            self.addCleanup(patcher.stop)
        self.context = self.tls_factory.return_value
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.connection = self.http_factory.return_value
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.getheaders.return_value = [("Content-Type", "text/plain")]
        self.response.read.return_value = b"ok"

    def test_https_pins_literal_ip_and_verifies_original_hostname_without_dns(self):
        result = PinnedHTTPTransport()(transport_request())
        self.socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket = self.socket_factory.return_value
        raw_socket.connect.assert_called_once_with(("93.184.216.34", 443))
        self.context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="api.example.com")
        self.dns.assert_not_called()
        self.connection.request.assert_called_once_with(
            "GET", "/path?q=1", body=b"", headers={"Host": "api.example.com", "Connection": "close"})
        self.assertEqual(result.body_sha256, hashlib.sha256(b"ok").hexdigest())
        self.connection.close.assert_called_once()

    def test_ipv6_pin_and_explicit_port(self):
        PinnedHTTPTransport()(transport_request(url="https://api.example.com:8443/", resolved_ips=("2606:4700:4700::1111",)))
        self.socket_factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket_factory.return_value.connect.assert_called_once_with(("2606:4700:4700::1111", 8443, 0, 0))
        self.assertEqual(self.connection.request.call_args.kwargs["headers"]["Host"], "api.example.com:8443")
        self.dns.assert_not_called()

    def test_tls_verification_failure_never_sends_http(self):
        self.context.wrap_socket.side_effect = ssl.SSLCertVerificationError("test mismatch")
        with self.assertRaises(ssl.SSLCertVerificationError):
            PinnedHTTPTransport()(transport_request())
        self.http_factory.assert_not_called()
        self.socket_factory.return_value.close.assert_called_once()

    def test_unverified_tls_context_is_rejected(self):
        self.context.check_hostname = False
        with self.assertRaises(EgressBlocked):
            PinnedHTTPTransport()(transport_request())
        self.context.wrap_socket.assert_not_called()
        self.http_factory.assert_not_called()

    def test_invalid_addresses_never_open_a_socket(self):
        for addresses in ((), ("127.0.0.1",), ("169.254.169.254",), ("::1",), ("not-an-ip",), ("93.184.216.34", "10.0.0.1")):
            with self.subTest(addresses=addresses), self.assertRaises(EgressBlocked):
                PinnedHTTPTransport()(transport_request(resolved_ips=addresses))
        self.socket_factory.assert_not_called()

    def test_host_override_and_header_injection_are_rejected_before_socket(self):
        for headers in ({"Host": "other.example.com"}, {"X-Test": "a\r\nb"}, {"Transfer-Encoding": "chunked"}):
            with self.subTest(headers=headers), self.assertRaises(EgressBlocked):
                PinnedHTTPTransport()(transport_request(headers=headers))
        self.socket_factory.assert_not_called()

    def test_non_global_shared_addresses_never_open_a_socket(self):
        for addresses in (
            ("100.64.0.1",),
            ("100.100.100.200",),
            ("::ffff:100.100.100.200",),
            ("93.184.216.34", "100.100.100.200"),
            ("2606:4700:4700::1111", "::ffff:100.100.100.200"),
        ):
            with self.subTest(addresses=addresses), self.assertRaisesRegex(EgressBlocked, "non-public address"):
                PinnedHTTPTransport()(transport_request(resolved_ips=addresses))
        self.socket_factory.assert_not_called()
        self.http_factory.assert_not_called()

    def test_body_digest_is_verified_before_socket(self):
        with self.assertRaises(EgressBlocked):
            PinnedHTTPTransport(body_provider=lambda digest: b"wrong")(transport_request())
        self.socket_factory.assert_not_called()

    def test_bound_body_and_response_limit(self):
        body = b"approved test body"
        self.response.read.return_value = b"too large"
        with self.assertRaises(EgressBlocked):
            PinnedHTTPTransport(max_response_bytes=4, body_provider=lambda digest: body)(
                transport_request(method="POST", body_sha256=hashlib.sha256(body).hexdigest()))
        self.assertEqual(self.connection.request.call_args.kwargs["body"], body)
        self.response.read.assert_called_once_with(5)
        self.connection.close.assert_called_once()

    def test_redirect_is_returned_for_gateway_reauthorization_without_following(self):
        self.response.status = 302
        self.response.getheaders.return_value = [("Location", "https://other.example.com/")]
        result = PinnedHTTPTransport()(transport_request())
        self.assertEqual(result.status_code, 302)
        self.assertEqual(self.socket_factory.call_count, 1)
        self.dns.assert_not_called()

    def test_http_is_pinned_too_and_does_not_use_tls_or_proxy_resolution(self):
        with patch.dict("os.environ", {"HTTP_PROXY": "http://proxy.example.invalid:8080"}):
            PinnedHTTPTransport()(transport_request(url="http://api.example.com/"))
        self.socket_factory.return_value.connect.assert_called_once_with(("93.184.216.34", 80))
        self.tls_factory.assert_not_called()
        self.dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
