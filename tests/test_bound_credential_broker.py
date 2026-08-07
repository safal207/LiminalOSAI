import unittest

from adapters.credentials.liminal_credential_injector import (
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
        self.cap = CapabilityBroker("broker:credential-tests")
        self.broker = CredentialBroker(capability_broker=self.cap, lease_ttl_seconds=5)
        self.broker.register_binding(binding())

    def admit(self, **kwargs):
        self.cap.admit(credential_capability(**kwargs), at_unix=20)

    def injector(self, provider_calls, sink_calls, *, provider=None, sink=None):
        if provider is None:
            def provider(credential_id):
                provider_calls.append(credential_id)
                return SECRET
        if sink is None:
            def sink(ctx, secret):
                sink_calls.append((ctx.domain, ctx.injection_target, secret))
                return InjectionObservation.success({"header_injected": True})
        return CredentialInjector(broker=self.broker, secret_provider=provider, sink=sink)

    def test_model_facing_authority_has_no_secret_access(self):
        self.assertTrue(AUTHORITY["credential_capability_admission"])
        self.assertFalse(AUTHORITY["secret_provider_access"])
        self.assertFalse(AUTHORITY["secret_material_export"])
        self.assertFalse(AUTHORITY["network_authority"])

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
        verify_authorization_receipt(self.broker.receipts()[0])

    def test_missing_capability_blocks_before_provider(self):
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request())
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["injection_outcome"], "NOT_INJECTED")
        self.assertEqual(provider_calls, [])
        self.assertEqual(sink_calls, [])

    def test_wrong_purpose_blocks_before_provider(self):
        self.admit()
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(purpose="other_purpose"))
        self.assertEqual(receipt["reason_codes"], ["binding_mismatch"])
        self.assertEqual(provider_calls, [])

    def test_wrong_domain_blocks_before_provider(self):
        self.admit()
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(domain="evil.example.com"))
        self.assertEqual(receipt["reason_codes"], ["binding_mismatch"])
        self.assertEqual(provider_calls, [])

    def test_wrong_port_blocks_before_provider(self):
        self.admit()
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(port=8443))
        self.assertEqual(receipt["reason_codes"], ["binding_mismatch"])
        self.assertEqual(provider_calls, [])

    def test_wrong_header_blocks_before_provider(self):
        self.admit()
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(injection_target="http_header:X-Api-Key"))
        self.assertEqual(receipt["reason_codes"], ["binding_mismatch"])
        self.assertEqual(provider_calls, [])

    def test_revoked_capability_blocks_before_provider(self):
        self.admit()
        self.cap.revoke("cap:cred", at_unix=21)
        provider_calls, sink_calls = [], []
        receipt = self.injector(provider_calls, sink_calls).execute(request(at_unix=22))
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

    def test_lease_expiry_blocks_trusted_consumption(self):
        self.admit()
        auth = self.broker.authorize(request())
        self.assertEqual(auth["decision"], "ALLOW")
        with self.assertRaisesRegex(CredentialError, "lease_expired"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], at_unix=26)

    def test_revoke_after_authorize_before_consume_blocks(self):
        self.admit()
        auth = self.broker.authorize(request())
        self.cap.revoke("cap:cred", at_unix=21)
        with self.assertRaisesRegex(CredentialError, "source_capability_inactive"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], at_unix=21)

    def test_consumed_lease_cannot_be_replayed(self):
        self.admit()
        auth = self.broker.authorize(request())
        self.broker.consume_for_trusted_adapter(auth["lease_id"], at_unix=20)
        with self.assertRaisesRegex(CredentialError, "lease_replayed"):
            self.broker.consume_for_trusted_adapter(auth["lease_id"], at_unix=20)

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
        self.assertEqual(provider_calls, ["cred:payments"])
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
        second = injector.execute(request(call_id="call:2", at_unix=21))
        self.assertEqual(second["decision"], "BLOCK")
        self.assertIn("use_exhausted", second["reason_codes"])
        self.assertEqual(len(provider_calls), 1)

    def test_http_binding_rejected(self):
        with self.assertRaisesRegex(CredentialError, "credential_destination_requires_https"):
            CredentialBinding.build(
                binding_id="b:x", credential_id="cred:x", purpose="p", protocol="http",
                domain="api.example.com", port=80, injection_target="http_header:Authorization",
            )

    def test_wildcard_domain_rejected(self):
        with self.assertRaisesRegex(CredentialError, "invalid_domain"):
            CredentialBinding.build(
                binding_id="b:x", credential_id="cred:x", purpose="p", protocol="https",
                domain="*.example.com", port=443, injection_target="http_header:Authorization",
            )

    def test_duplicate_binding_id_with_different_contract_rejected(self):
        other = CredentialBinding.build(
            binding_id="binding:payments", credential_id="cred:payments", purpose="payments_api",
            protocol="https", domain="other.example.com", port=443,
            injection_target="http_header:Authorization",
        ).as_document()
        with self.assertRaisesRegex(CredentialError, "duplicate_binding_id"):
            self.broker.register_binding(other)

    def test_authorization_receipt_tamper_fails(self):
        self.admit()
        receipt = self.broker.authorize(request())
        bad = dict(receipt)
        bad["binding_sha256"] = "f" * 64
        with self.assertRaisesRegex(CredentialError, "authorization_digest_mismatch"):
            verify_authorization_receipt(bad)

    def test_injection_receipt_tamper_fails(self):
        self.admit()
        receipt = self.injector([], []).execute(request())
        bad = dict(receipt)
        bad["result_sha256"] = "f" * 64
        with self.assertRaisesRegex(CredentialInjectionError, "injection_digest_mismatch"):
            verify_injection_receipt(bad)

    def test_receipts_never_contain_secret_value(self):
        self.admit()
        injector = self.injector([], [])
        injector.execute(request())
        self.assertNotIn(SECRET, str(self.broker.receipts()))
        self.assertNotIn(SECRET, str(injector.receipts()))


if __name__ == "__main__":
    unittest.main()
