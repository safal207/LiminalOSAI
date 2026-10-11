"""Offline negative controls for authorization before any egress callback."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

from sdk.liminal_capability_broker import BrokerError, CapabilityBroker
from sdk.liminal_egress_gateway import EgressBlocked, EgressGateway, TransportResponse
from tests.test_egress_gateway_phase2 import RESP, capability, request


class AdmissionOrderTests(unittest.TestCase):
    def gateway(self, *, cap=None, broker=None, resolver=None, secret=None, transport=None, clock=None):
        self.calls = []
        if broker is None:
            broker = CapabilityBroker()
            broker.admit((cap or capability()).as_document(), at_unix=105)
        return EgressGateway(
            broker=broker,
            resolver=resolver or (lambda host: self.calls.append(("dns", host)) or ["93.184.216.34"]),
            secret_resolver=secret or (lambda ref: self.calls.append(("secret", ref)) or "test-token"),
            transport=transport or (lambda item: self.calls.append(("transport", item)) or TransportResponse(200, {}, RESP)),
            clock=clock or (lambda: 120),
        )

    def test_missing_grant_has_zero_external_callbacks(self):
        calls = []
        gateway = EgressGateway(
            broker=CapabilityBroker(),
            resolver=lambda host: calls.append("resolver") or ["93.184.216.34"],
            secret_resolver=lambda ref: calls.append("secret") or "test-token",
            transport=lambda item: calls.append("transport") or TransportResponse(200, {}, RESP),
        )
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual(calls, [])

    def test_denied_grants_have_zero_callbacks(self):
        cases = {
            "expired": {"at_unix": 200},
            "wrong_domain": {"url": "https://denied.example.invalid/"},
            "wrong_port": {"url": "https://api.example.com:444/"},
            "wrong_protocol": {"url": "http://api.example.com/"},
            "wrong_policy": {"policy_sha256": "d" * 64},
            "wrong_subject": {"subject_id": "agent:other"},
            "revoked": {},
            "not_yet_valid": {},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                gateway = self.gateway(cap=capability(not_before_unix=150) if name == "not_yet_valid" else None,
                                       clock=(lambda: 200) if name == "expired" else None)
                if name == "revoked":
                    gateway.broker.revoke("cap:network:1", at_unix=119)
                with self.assertRaises(EgressBlocked):
                    gateway.execute(request(secret_refs={"authorization": "secret:test"}, **changes))
                self.assertEqual(self.calls, [])

    def test_one_use_grant_succeeds_once_without_stage_double_consumption(self):
        gateway = self.gateway(cap=capability(max_uses=1))
        gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual([item[0] for item in self.calls], ["dns", "secret", "transport"])
        self.assertEqual(gateway.broker.state_document()["capabilities"][0]["use_count"], 1)
        self.calls.clear()
        with self.assertRaises(EgressBlocked):
            gateway.execute(request())
        self.assertEqual(self.calls, [])

    def test_denied_redirect_does_not_resolve_second_host(self):
        gateway = self.gateway(transport=lambda item: TransportResponse(302, {"Location": "https://denied.example.invalid/"}, RESP))
        with self.assertRaises(EgressBlocked):
            gateway.execute(request())
        self.assertEqual(self.calls, [("dns", "api.example.com")])
        self.assertEqual(gateway.broker.state_document()["capabilities"][0]["use_count"], 1)

    def test_exhausted_redirect_does_not_resolve_again(self):
        gateway = self.gateway(cap=capability(max_uses=1), transport=lambda item: TransportResponse(302, {"Location": "/next"}, RESP))
        with self.assertRaises(EgressBlocked):
            gateway.execute(request())
        self.assertEqual(self.calls, [("dns", "api.example.com")])

    def test_same_origin_redirect_consumes_exactly_one_use_each(self):
        responses = iter([TransportResponse(302, {"Location": "/next"}, RESP), TransportResponse(200, {}, RESP)])
        gateway = self.gateway(cap=capability(max_uses=2), transport=lambda item: next(responses))
        gateway.execute(request())
        self.assertEqual(gateway.broker.state_document()["capabilities"][0]["use_count"], 2)
        self.assertEqual(self.calls, [("dns", "api.example.com"), ("dns", "api.example.com")])

    def test_revoke_in_resolver_blocks_secrets_and_transport(self):
        def resolver(host):
            self.calls.append(("dns", host))
            gateway.broker.revoke("cap:network:1", at_unix=121)
            return ["93.184.216.34"]
        gateway = self.gateway(resolver=resolver)
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual(self.calls, [("dns", "api.example.com")])

    def test_revoke_in_secret_provider_blocks_remaining_secret_and_transport(self):
        def secret(ref):
            self.calls.append(("secret", ref))
            gateway.broker.revoke("cap:network:1", at_unix=121)
            return "test-token"
        gateway = self.gateway(secret=secret)
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(secret_refs={"authorization": "secret:one", "x-token": "secret:two"}))
        self.assertEqual([item[0] for item in self.calls], ["dns", "secret"])
        self.assertEqual(gateway.receipts(), ())

    def test_expiry_during_dns_prevents_later_callbacks(self):
        now = [120]
        def resolver(host):
            self.calls.append(("dns", host))
            now[0] = 200
            return ["93.184.216.34"]
        gateway = self.gateway(resolver=resolver, clock=lambda: now[0])
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual(self.calls, [("dns", "api.example.com")])

    def test_credential_redirect_is_bound_to_scheme_host_and_port(self):
        for destination in ("https://status.example.com/", "https://api.example.com:8443/", "http://api.example.com/"):
            with self.subTest(destination=destination):
                gateway = self.gateway(transport=lambda item: TransportResponse(302, {"Location": destination}, RESP))
                with self.assertRaises(EgressBlocked):
                    gateway.execute(request(secret_refs={"authorization": "secret:test"}))
                self.assertEqual([item[0] for item in self.calls], ["dns", "secret"])

    def test_cross_origin_redirect_drops_even_unlabelled_custom_headers(self):
        sent = []
        def transport(item):
            sent.append(item)
            return TransportResponse(302, {"Location": "https://status.example.com/"}, RESP) if len(sent) == 1 else TransportResponse(200, {}, RESP)
        gateway = self.gateway(transport=transport)
        gateway.execute(request(headers={"X-Custom-Credential": "test-value"}))
        self.assertEqual(sent[1].headers, {})

    def test_failed_dns_consumes_one_use_without_refund(self):
        gateway = self.gateway(cap=capability(max_uses=1), resolver=lambda host: ["127.0.0.1"])
        with self.assertRaises(EgressBlocked):
            gateway.execute(request())
        self.assertEqual(gateway.broker.state_document()["capabilities"][0]["use_count"], 1)
        self.assertEqual(gateway.receipts(), ())

    def test_initial_and_redirect_ip_literals_and_malformed_names_never_resolve(self):
        for url in ("https://93.184.216.34/", "https://api.example.com:0/", "https://bad%20name.example.com/", "https://bad_name.example.com/", "https://api.example.com/\n"):
            with self.subTest(url=url):
                gateway = self.gateway()
                with self.assertRaises(ValueError):
                    gateway.execute(request(url=url))
                self.assertEqual(self.calls, [])

    def test_normalized_hostname_and_explicit_default_port_work(self):
        gateway = self.gateway()
        gateway.execute(request(url="HTTPS://API.EXAMPLE.COM.:443/path"))
        self.assertEqual(self.calls[0], ("dns", "api.example.com"))

    def test_request_timestamp_cannot_advance_or_backdate_authority(self):
        gateway = self.gateway(cap=capability(not_before_unix=150), clock=lambda: 120)
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(at_unix=160))
        self.assertEqual(self.calls, [])
        gateway = self.gateway(clock=lambda: 200)
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(at_unix=120))
        self.assertEqual(self.calls, [])

    def test_parallel_requests_cannot_both_consume_one_use(self):
        gateway = self.gateway(cap=capability(max_uses=1))
        barrier = Barrier(2)
        def run():
            barrier.wait(timeout=2)
            try:
                gateway.execute(request())
                return "ALLOW"
            except EgressBlocked:
                return "BLOCK"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: run(), range(2)))
        self.assertEqual(sorted(results), ["ALLOW", "BLOCK"])
        self.assertEqual([item[0] for item in self.calls], ["dns", "transport"])

    def test_completed_concurrent_revocation_prevents_new_stage(self):
        gateway = self.gateway()
        gateway.execute(request())
        receipt = gateway.broker.receipts()[-1]
        entered, leave, revoked = Event(), Event(), Event()
        def callback():
            with gateway.broker.live_use(receipt, at_unix=120):
                entered.set()
                self.assertTrue(leave.wait(timeout=2))
        def revoke():
            gateway.broker.revoke("cap:network:1", at_unix=121)
            revoked.set()
        with ThreadPoolExecutor(max_workers=2) as pool:
            active = pool.submit(callback)
            self.assertTrue(entered.wait(timeout=2))
            revocation = pool.submit(revoke)
            # An in-flight trusted callback is admitted before revocation;
            # this is serialization, not cancellation or bounded stop latency.
            self.assertFalse(revoked.wait(timeout=0.02))
            leave.set()
            active.result(timeout=2)
            revocation.result(timeout=2)
        with self.assertRaises(BrokerError):
            with gateway.broker.live_use(receipt, at_unix=122):
                self.fail("callback entered after completed revoke")

    def test_altered_receipt_cannot_revalidate_an_existing_use(self):
        gateway = self.gateway()
        gateway.execute(request())
        receipt = dict(gateway.broker.receipts()[-1], capability_id="cap:other")
        with self.assertRaises(BrokerError):
            with gateway.broker.live_use(receipt, at_unix=120):
                self.fail("altered receipt accepted")

    def test_epoch_bound_broker_rechecks_drift_after_dns(self):
        from sdk.liminal_epoch_bound_capability import EpochBoundCapabilityBroker, EpochBoundCapabilityContract
        from tests.test_epoch_bound_capability import FakeRuntimeProvider
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        bound = EpochBoundCapabilityContract.build(
            base_capability=capability(max_uses=1).as_document(),
            runtime_epoch=provider.epoch, runtime_state_sha256=provider.state)
        broker.admit(bound.as_document(), at_unix=105)
        def resolver(host):
            self.calls.append(("dns", host))
            provider.epoch += 1
            return ["93.184.216.34"]
        gateway = self.gateway(broker=broker, resolver=resolver)
        with self.assertRaises(EgressBlocked):
            gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual(self.calls, [("dns", "api.example.com")])
        state = broker.state_document()["capabilities"][0]
        self.assertEqual(state["status"], "revoked")
        self.assertEqual(state["use_count"], 1)

    def test_epoch_bound_broker_allows_all_stages_with_one_use(self):
        from sdk.liminal_epoch_bound_capability import EpochBoundCapabilityBroker, EpochBoundCapabilityContract
        from tests.test_epoch_bound_capability import FakeRuntimeProvider
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        broker.admit(EpochBoundCapabilityContract.build(
            base_capability=capability(max_uses=1).as_document(),
            runtime_epoch=provider.epoch, runtime_state_sha256=provider.state).as_document(), at_unix=105)
        gateway = self.gateway(broker=broker)
        result = gateway.execute(request(secret_refs={"authorization": "secret:test"}))
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(broker.state_document()["capabilities"][0]["use_count"], 1)


if __name__ == "__main__":
    unittest.main()
