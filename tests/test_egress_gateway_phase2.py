from __future__ import annotations

import copy
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import (
    DirectSocketGuard,
    EgressBlocked,
    EgressGateway,
    GatewayRequest,
    TransportResponse,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract

POLICY = "a" * 64
BODY = "b" * 64
RESP = "c" * 64


def capability(**overrides):
    values = dict(
        capability_id="cap:network:1",
        capability_type="network.connect_domain",
        subject_id="agent:worker",
        issuer_id="issuer:test",
        scope={"domains": ["api.example.com", "status.example.com"], "protocols": ["https"], "ports": [443]},
        issued_at_unix=100,
        not_before_unix=100,
        expires_at_unix=200,
        max_uses=8,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )
    values.update(overrides)
    return CapabilityContract.build(**values)


def request(**overrides):
    values = dict(
        call_id="call:network:1",
        subject_id="agent:worker",
        policy_sha256=POLICY,
        method="GET",
        url="https://api.example.com/v1/data",
        headers={"accept": "application/json"},
        body_sha256=BODY,
        secret_refs={},
        at_unix=120,
    )
    values.update(overrides)
    return GatewayRequest(**values)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, item):
        self.requests.append(item)
        if not self.responses:
            raise RuntimeError("no response")
        return self.responses.pop(0)


class GatewayTests(unittest.TestCase):
    def broker(self, *, admit=True, cap=None):
        broker = CapabilityBroker()
        if admit:
            broker.admit((cap or capability()).as_document(), at_unix=105)
        return broker

    def gateway(self, *, broker=None, resolver=None, transport=None, secret_resolver=None, max_redirects=3):
        return EgressGateway(
            broker=broker or self.broker(),
            resolver=resolver or (lambda host: ["93.184.216.34"]),
            transport=transport or FakeTransport([TransportResponse(200, {"content-type": "application/json"}, RESP)]),
            secret_resolver=secret_resolver,
            max_redirects=max_redirects,
        )

    def test_default_deny_without_capability(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(broker=self.broker(admit=False)).execute(request())

    def test_allowed_https_request_emits_digest_only_receipt(self):
        result = self.gateway().execute(request())
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["redirect_count"], 0)
        self.assertNotIn("url", result)
        self.assertNotIn("headers", result)

    def test_wrong_domain_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="https://evil.example.net/data"))

    def test_http_downgrade_blocks_against_https_only_capability(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="http://api.example.com/data"))

    def test_wrong_port_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="https://api.example.com:8443/data"))

    def test_disallowed_method_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(method="TRACE"))

    def test_private_ipv4_dns_blocks_before_transport(self):
        transport = FakeTransport([TransportResponse(200, {}, RESP)])
        with self.assertRaises(EgressBlocked):
            self.gateway(resolver=lambda host: ["127.0.0.1"], transport=transport).execute(request())
        self.assertEqual(transport.requests, [])

    def test_private_ipv6_dns_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(resolver=lambda host: ["::1"]).execute(request())

    def test_empty_dns_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(resolver=lambda host: []).execute(request())

    def test_invalid_dns_value_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(resolver=lambda host: ["not-an-ip"]).execute(request())

    def test_redirect_same_allowed_domain_reauthorizes(self):
        transport = FakeTransport([
            TransportResponse(302, {"Location": "/v2/data"}, RESP),
            TransportResponse(200, {}, RESP),
        ])
        result = self.gateway(transport=transport).execute(request())
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(len(self.gateway().broker.receipts()), 1)

    def test_redirect_to_second_allowed_domain_succeeds(self):
        transport = FakeTransport([
            TransportResponse(302, {"Location": "https://status.example.com/health"}, RESP),
            TransportResponse(200, {}, RESP),
        ])
        result = self.gateway(transport=transport).execute(request())
        self.assertEqual(result["redirect_count"], 1)

    def test_redirect_outside_scope_blocks_before_second_transport(self):
        transport = FakeTransport([
            TransportResponse(302, {"Location": "https://evil.example.net/next"}, RESP),
            TransportResponse(200, {}, RESP),
        ])
        with self.assertRaises(EgressBlocked):
            self.gateway(transport=transport).execute(request())
        self.assertEqual(len(transport.requests), 1)

    def test_https_to_http_redirect_downgrade_blocks(self):
        transport = FakeTransport([
            TransportResponse(302, {"Location": "http://api.example.com/next"}, RESP),
        ])
        with self.assertRaises(EgressBlocked):
            self.gateway(transport=transport).execute(request())

    def test_redirect_limit_blocks(self):
        transport = FakeTransport([
            TransportResponse(302, {"Location": "/2"}, RESP),
        ])
        with self.assertRaises(EgressBlocked):
            self.gateway(transport=transport, max_redirects=0).execute(request())

    def test_redirect_without_location_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(transport=FakeTransport([TransportResponse(302, {}, RESP)])).execute(request())

    def test_dns_rechecked_on_redirect(self):
        calls = []
        def resolver(host):
            calls.append(host)
            if len(calls) == 1:
                return ["93.184.216.34"]
            return ["127.0.0.1"]
        transport = FakeTransport([TransportResponse(302, {"Location": "/next"}, RESP)])
        with self.assertRaises(EgressBlocked):
            self.gateway(resolver=resolver, transport=transport).execute(request())
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(len(calls), 2)

    def test_secret_is_injected_only_at_transport_boundary(self):
        seen = {}
        def secret_resolver(secret_id):
            seen["id"] = secret_id
            return "super-secret-value"
        transport = FakeTransport([TransportResponse(200, {}, RESP)])
        result = self.gateway(transport=transport, secret_resolver=secret_resolver).execute(
            request(secret_refs={"authorization": "secret:api-token"})
        )
        self.assertEqual(seen["id"], "secret:api-token")
        self.assertEqual(transport.requests[0].headers["authorization"], "super-secret-value")
        serialized = repr(result)
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("secret:api-token", serialized)

    def test_model_visible_secret_header_collision_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway(secret_resolver=lambda secret_id: "x").execute(
                request(headers={"Authorization": "visible"}, secret_refs={"authorization": "secret:token"})
            )

    def test_secret_without_resolver_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(secret_refs={"authorization": "secret:token"}))

    def test_revoked_capability_blocks(self):
        broker = self.broker()
        broker.revoke("cap:network:1", at_unix=119)
        with self.assertRaises(EgressBlocked):
            self.gateway(broker=broker).execute(request())

    def test_expired_capability_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(at_unix=200))

    def test_policy_mismatch_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(policy_sha256="d" * 64))

    def test_subject_mismatch_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(subject_id="agent:other"))

    def test_direct_socket_guard_always_blocks(self):
        with self.assertRaises(EgressBlocked):
            DirectSocketGuard().authorize(call_id="call:1", destination="93.184.216.34:443")

    def test_url_userinfo_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="https://user:pass@api.example.com/data"))

    def test_url_without_dns_name_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="https://127.0.0.1/data"))

    def test_fragment_blocks(self):
        with self.assertRaises(EgressBlocked):
            self.gateway().execute(request(url="https://api.example.com/data#frag"))

    def test_transport_error_does_not_emit_receipt(self):
        class Broken:
            def __call__(self, item):
                raise RuntimeError("transport down")
        gateway = self.gateway(transport=Broken())
        with self.assertRaises(RuntimeError):
            gateway.execute(request())
        self.assertEqual(gateway.receipts(), ())

    def test_receipt_is_deterministic_for_same_execution_metadata(self):
        one = self.gateway().execute(request())
        two = self.gateway().execute(request())
        self.assertEqual(one["receipt_sha256"], two["receipt_sha256"])

    def test_capability_use_is_consumed_per_redirect_hop(self):
        broker = self.broker(cap=capability(max_uses=1))
        transport = FakeTransport([
            TransportResponse(302, {"Location": "/next"}, RESP),
            TransportResponse(200, {}, RESP),
        ])
        with self.assertRaises(EgressBlocked):
            self.gateway(broker=broker, transport=transport).execute(request())
        state = broker.state_document()["capabilities"][0]
        self.assertEqual(state["use_count"], 1)

    def test_secret_values_do_not_appear_in_gateway_receipts(self):
        gateway = self.gateway(secret_resolver=lambda secret_id: "token-value")
        gateway.execute(request(secret_refs={"authorization": "secret:token"}))
        self.assertNotIn("token-value", repr(gateway.receipts()))
        self.assertNotIn("secret:token", repr(gateway.receipts()))


if __name__ == "__main__":
    unittest.main()
