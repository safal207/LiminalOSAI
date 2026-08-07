import threading
import unittest

from adapters.credentials.liminal_credential_injector import (
    AUTHORITY as INJECTOR_AUTHORITY,
    CredentialInjectionError,
    CredentialInjector,
    InjectionObservation,
    verify_injection_receipt,
)
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_credential_broker import (
    AUTHORITY,
    CredentialBinding,
    CredentialBroker,
    CredentialError,
    CredentialUseRequest,
    verify_authorization_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256

P = "a" * 64
SECRET = "SUPER-SECRET-MUST-NEVER-APPEAR"
ADAPTER_TOKEN = "trusted-adapter-token-0123456789abcdef"


class FakeClock:
    def __init__(self, value=20):
        self.value = value

    def __call__(self):
        return self.value

    def set(self, value):
        self.value = value


def credential_capability(*, cid="cap:cred", uses=4, expires=500):
    return CapabilityContract.build(
        capability_id=cid,
        capability_type="credential.access",
        subject_id="agent:a",
        issuer_id="human:owner",
        scope={"credential_ids": ["cred:payments"], "purpose": "payments_api"},
        issued_at_unix=10,
        not_before_unix=10,
        expires_at_unix=expires,
        max_uses=uses,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=P,
    ).as_document()


def binding(**overrides):
    values = dict(
        binding_id="binding:payments",
        credential_id="cred:payments",
        purpose="payments_api",
        protocol="https",
        domain="api.example.com",
        port=443,
        injection_target="http_header:Authorization",
    )
    values.update(overrides)
    return CredentialBinding.build(**values).as_document()


def request(**overrides):
    values = dict(
        call_id="call:1",
        subject_id="agent:a",
        policy_sha256=P,
        credential_id="cred:payments",
        purpose="payments_api",
        protocol="https",
        domain="api.example.com",
        port=443,
        injection_target="http_header:Authorization",
        at_unix=20,
    )
    values.update(overrides)
    return CredentialUseRequest(**values)


class BoundCredentialBrokerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock(20)
        self.cap = CapabilityBroker("broker:credential-tests")
        self.broker = CredentialBroker(
            capability_broker=self.cap,
            bindings=[binding()],
            adapter_token=ADAPTER_TOKEN,
            lease_ttl_seconds=5,
            clock=self.clock,
        )

    def admit(self, **kwargs):
        self.cap.admit(credential_capability(**kwargs), at_unix=20)

    def injector(self, provider_calls, sink_calls, *, provider=None, sink=None, token=ADAPTER_TOKEN):
        if provider is None:
            def provider(credential_id):
                provider_calls.append(credential_id)
                return SECRET
        if sink is None:
            def sink(ctx, secret):
                sink_calls.append((ctx.domain, ctx.injection_target, secret))
                return InjectionObservation.success({"header_injected": True})
        return CredentialInjector(
            broker=self.broker,
            adapter_token=token,
            secret_provider=provider,
            sink=sink,
        )

    def test_authority_metadata_is_read_only_and_not_secret_authority(self):
        self.assertTrue(AUTHORITY["credential_capability_admission"])
        self.assertTrue(AUTHORITY["immutable_host_bindings"])
        self.assertTrue(AUTHORITY["trusted_clock"])
        self.assertTrue(AUTHORITY["atomic_state_transitions"])
        self.assertFalse(AUTHORITY["secret_provider_access"])
        self.assertFalse(AUTHORITY["secret_material_export"])
        self.assertFalse(AUTHORITY["network_authority"])
        self.assertTrue(INJECTOR_AUTHORITY["secret_provider_access"])
        self.assertTrue(INJECTOR_AUTHORITY["adapter_authentication"])
        with self.assertRaises(TypeError):
            AUTHORITY["network_authority"] = True
        with self.assertRaises(TypeError):
            INJECTOR_AUTHORITY["network_authority"] = True

    def test_bindings_are_immutable_after_construction(self):
        self.assertFalse(hasattr(self.broker, "register_binding"))

    def test_duplicate_binding_id_with_different_contract_rejected_at_construction(self):
        other = CredentialBinding.build(
            binding_id="binding:payments", credential_id="cred:payments", purpose="payments_api",
            protocol="https", domain="other.example.com", port=443,
            injection_target="http_header:Authorization",
        ).as_document()
        with self.assertRaisesRegex(CredentialError, "duplicate_binding_id"):
            CredentialBroker(
                capability_broker=self.cap,
                bindings=[binding(), other],
                adapter_token=ADAPTER_TOKEN,
                clock=self.clock,
            )

    def test_valid_use_injects_secret_only_at_trusted_sink(self):
        self.admit()
        provider_calls, sink_calls = [], []
        injector = self.injector(provider_calls, sink_calls)
        receipt = injector.execute(request())
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["injection_outcome"], "SUCCEEDED")
        self.assertEqual(provider_calls, ["cred:payments"])
        self.assertEqual(sink_calls, [("api.example.com", "http_header:authorization", SECRET)])
        self.assertNotIn(SECRET, str(receipt))
        self.assertNotIn("cred:payments", str(receipt))
        verify_injection_receipt(receipt)
        auth = self.broker.receipts()[0]
        self.assertEqual(auth["decision_at_unix"], 20)
        verify_authorization_receipt(auth)

    def test_request_time_is_evidence_not_authority(self):
        self.admit(expires=25)
        self.clock.set(30)
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(at_unix=1))
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertIn("expired", receipt["reason_codes"])
        self.assertEqual(provider_calls, [])

    def test_future_declared_request_time_does_not_extend_lease(self):
        self.admit()
        auth = self.broker.authorize(request(at_unix=999999))
        self.assertEqual(auth["decision"], "ALLOW")
        self.assertEqual(auth["request_declared_at_unix"], 999999)
        self.assertEqual(auth["decision_at_unix"], 20)
        self.assertEqual(auth["lease_expires_at_unix"], 25)

    def test_missing_capability_blocks_before_provider(self):
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request())
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["injection_outcome"], "NOT_INJECTED")
        self.assertEqual(provider_calls, [])
        self.assertEqual(sink_calls, [])

    def test_binding_mismatches_block_before_provider(self):
        self.admit(uses=10)
        cases = [
            {"purpose": "other_purpose"},
            {"domain": "evil.example.com"},
            {"port": 8443},
            {"injection_target": "http_header:X-Api-Key"},
        ]
        for i, changes in enumerate(cases, start=1):
            provider_calls, sink_calls = [], []
            receipt = self.injector(provider_calls, sink_calls).execute(request(call_id=f"call:{i}", **changes))
            self.assertEqual(receipt["reason_codes"], ["binding_mismatch"])
            self.assertEqual(provider_calls, [])
            self.assertEqual(sink_calls, [])

    def test_revoked_capability_blocks_before_provider(self):
        self.admit()
        self.cap.revoke("cap:cred", at_unix=21)
        self.clock.set(22)
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request())
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(provider_calls, [])

    def test_containment_blocks_before_provider(self):
        self.admit()
        self.broker.enter_containment("c" * 64)
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request())
        self.assertEqual(receipt["reason_codes"], ["containment_active"])
        self.assertEqual(provider_calls, [])

    def test_replayed_call_id_never_injects_twice(self):
        self.admit(uses=2)
        provider_calls, sink_calls = [], []
        injector = self.injector(provider_calls, sink_calls)
        first = injector.execute(request())
        second = injector.execute(request())
        self.assertEqual(first["injection_outcome"], "SUCCEEDED")
        self.assertEqual(second["decision"], "BLOCK")
        self.assertEqual(second["reason_codes"], ["replayed_call_id"])
        self.assertEqual(len(provider_calls), 1)
        self.assertEqual(len(sink_calls), 1)

    def test_concurrent_same_call_id_is_atomic(self):
        self.admit(uses=2)
        decisions = []
        barrier = threading.Barrier(3)

        def worker():
            barrier.wait()
            decisions.append(self.broker.authorize(request())["decision"])

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join()
        self.assertEqual(sorted(decisions), ["ALLOW", "BLOCK"])
        self.assertEqual(len(self.broker.receipts()), 2)

    def test_lease_expiry_uses_trusted_clock(self):
        self.admit()
        auth = self.broker.authorize(request(at_unix=999999))
        self.assertEqual(auth["lease_expires_at_unix"], 25)
        self.clock.set(25)
        with self.assertRaisesRegex(CredentialError, "lease_expired"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_revoke_after_authorize_before_consume_blocks(self):
        self.admit()
        auth = self.broker.authorize(request())
        self.cap.revoke("cap:cred", at_unix=21)
        self.clock.set(21)
        with self.assertRaisesRegex(CredentialError, "source_capability_inactive"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_wrong_adapter_token_cannot_consume_or_burn_lease(self):
        self.admit()
        auth = self.broker.authorize(request())
        with self.assertRaisesRegex(CredentialError, "trusted_adapter_auth_failed"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token="x" * 40)
        trusted = self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)
        self.assertEqual(trusted.credential_id, "cred:payments")

    def test_consumed_lease_cannot_be_replayed(self):
        self.admit()
        auth = self.broker.authorize(request())
        self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)
        with self.assertRaisesRegex(CredentialError, "lease_replayed"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], adapter_token=ADAPTER_TOKEN)

    def test_provider_failure_is_digest_only_and_lease_is_consumed(self):
        self.admit()
        provider_calls, sink_calls = [], []

        def provider(credential_id):
            provider_calls.append(credential_id)
            raise RuntimeError(SECRET)

        injector = self.injector(provider_calls, sink_calls, provider=provider)
        receipt = injector.execute(request())
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["injection_outcome"], "FAILED")
        self.assertNotIn(SECRET, str(receipt))
        second = injector.execute(request())
        self.assertEqual(second["decision"], "BLOCK")
        self.assertEqual(provider_calls, ["cred:payments"])

    def test_sink_failure_is_digest_only(self):
        self.admit()
        provider_calls, sink_calls = [], []

        def sink(ctx, secret):
            sink_calls.append(secret)
            raise RuntimeError(SECRET)

        receipt = self.injector(provider_calls, sink_calls, sink=sink).execute(request())
        self.assertEqual(receipt["injection_outcome"], "FAILED")
        self.assertNotIn(SECRET, str(receipt))
        self.assertEqual(sink_calls, [SECRET])

    def test_exhausted_capability_blocks_new_call_before_provider(self):
        self.admit(uses=1)
        provider_calls, sink_calls = [], []
        injector = self.injector(provider_calls, sink_calls)
        injector.execute(request(call_id="call:1"))
        self.clock.set(21)
        second = injector.execute(request(call_id="call:2"))
        self.assertEqual(second["decision"], "BLOCK")
        self.assertIn("use_exhausted", second["reason_codes"])
        self.assertEqual(len(provider_calls), 1)

    def test_plain_http_and_wildcard_bindings_rejected(self):
        with self.assertRaisesRegex(CredentialError, "credential_destination_requires_https"):
            CredentialBinding.build(
                binding_id="b:http", credential_id="cred:x", purpose="p", protocol="http",
                domain="api.example.com", port=80, injection_target="http_header:Authorization",
            )
        with self.assertRaisesRegex(CredentialError, "invalid_domain"):
            CredentialBinding.build(
                binding_id="b:wild", credential_id="cred:x", purpose="p", protocol="https",
                domain="*.example.com", port=443, injection_target="http_header:Authorization",
            )

    def test_authorization_receipt_tamper_and_extra_field_fail(self):
        self.admit()
        receipt = self.broker.authorize(request())
        bad = dict(receipt)
        bad["binding_sha256"] = "f" * 64
        with self.assertRaisesRegex(CredentialError, "authorization_digest_mismatch"):
            verify_authorization_receipt(bad)
        extra = dict(receipt)
        extra["secret"] = SECRET
        raw = dict(extra)
        raw.pop("receipt_sha256")
        extra["receipt_sha256"] = canonical_sha256(raw)
        with self.assertRaisesRegex(CredentialError, "authorization_schema_mismatch"):
            verify_authorization_receipt(extra)

    def test_injection_receipt_tamper_and_extra_field_fail(self):
        self.admit()
        receipt = self.injector([], []).execute(request())
        bad = dict(receipt)
        bad["result_sha256"] = "f" * 64
        with self.assertRaisesRegex(CredentialInjectionError, "injection_digest_mismatch"):
            verify_injection_receipt(bad)
        extra = dict(receipt)
        extra["secret"] = SECRET
        raw = dict(extra)
        raw.pop("receipt_sha256")
        extra["receipt_sha256"] = canonical_sha256(raw)
        with self.assertRaisesRegex(CredentialInjectionError, "injection_schema_mismatch"):
            verify_injection_receipt(extra)

    def test_receipts_never_contain_secret_value(self):
        self.admit()
        injector = self.injector([], [])
        injector.execute(request())
        self.assertNotIn(SECRET, str(self.broker.receipts()))
        self.assertNotIn(SECRET, str(injector.receipts()))


if __name__ == "__main__":
    unittest.main()
