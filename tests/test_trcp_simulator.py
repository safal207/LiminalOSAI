import unittest

from sdk.liminal_trcp import (
    AuthorizationRecord,
    MockProvider,
    ScopeEnvelope,
    TRCPError,
    TRCPSimulator,
    default_fixture,
    run_default_scenario,
)


class TRCPSimulatorTests(unittest.TestCase):
    def test_default_failover_is_deterministic_and_closes(self):
        first = run_default_scenario()
        second = run_default_scenario()
        self.assertEqual(first, second)
        self.assertEqual(first["report_sha256"], second["report_sha256"])
        self.assertEqual(first["final_state"], "CLOSED")
        self.assertEqual(first["failover_record"]["permission_delta"], "UNCHANGED")
        self.assertEqual(first["finding"]["status"], "CONFIRMED")
        self.assertEqual(first["verification"]["result"], "REPRODUCED")

    def test_failover_never_broadens_scope(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        broader = ScopeEnvelope(
            scope_id="scope:broader",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo", "fixture:other"),
            allowed_actions=("ANALYZE_FIXTURE", "ACTIVE_VALIDATE"),
        )
        with self.assertRaisesRegex(TRCPError, "broaden"):
            simulator.record_failover(fixture["fallback"], fallback_scope=broader)

    def test_expired_authorization_blocks_continuation(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.advance_time(2001)
        with self.assertRaisesRegex(TRCPError, "authorization is not currently valid"):
            simulator.record_failover(fixture["fallback"])

    def test_missing_failover_record_blocks_fallback(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        with self.assertRaisesRegex(TRCPError, "FailoverDecisionRecord"):
            simulator.execute_fallback(fixture["task"], fixture["fallback"])

    def test_provider_specific_output_cannot_mutate_authorization(self):
        fixture = default_fixture()
        fallback = MockProvider(
            "provider:B",
            "mock-model-b",
            "COMPLETED",
            synthetic_finding={
                "finding_class": "SYNTHETIC_BOUNDARY_CHECK",
                "location_reference": "fixture://sample#L1",
                "summary": "Synthetic fixture matches expected marker",
                "severity_claim": "LOW",
                "confidence_claim": "FIXTURE",
                "authorization_id": "auth:provider-attempted-mutation",
                "allowed_actions": ["ACTIVE_VALIDATE"],
            },
            provider_metadata={
                "authorization_id": "auth:provider-attempted-mutation",
                "network_mode": "EXTERNAL",
            },
        )
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.record_failover(fallback)
        simulator.execute_fallback(fixture["task"], fallback)
        report = simulator.report()
        self.assertEqual(report["authorization"]["authorization_id"], "auth:trcp-demo")
        self.assertEqual(report["scope"]["network_mode"], "LOCAL_ONLY")
        self.assertNotIn("authorization_id", report["finding"])
        self.assertNotIn("allowed_actions", report["finding"])

    def test_unverified_finding_cannot_be_confirmed(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        self.assertEqual(simulator.finding["status"], "UNVERIFIED")
        with self.assertRaisesRegex(TRCPError, "without reproduced verification"):
            simulator.confirm_finding()

    def test_non_reproduced_finding_cannot_be_confirmed(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        simulator.verify(reproduced=False)
        self.assertEqual(simulator.finding["status"], "NOT_REPRODUCED")
        with self.assertRaisesRegex(TRCPError, "without reproduced verification"):
            simulator.confirm_finding()

    def test_trace_is_hash_chained(self):
        report = run_default_scenario()
        previous = "0" * 64
        for index, event in enumerate(report["trace"], start=1):
            self.assertEqual(event["sequence"], index)
            self.assertEqual(event["previous_event_sha256"], previous)
            self.assertEqual(len(event["event_sha256"]), 64)
            previous = event["event_sha256"]

    def test_scope_requires_local_only(self):
        authorization = AuthorizationRecord(
            "auth:test",
            "researcher:test",
            "fixture:repo",
            900,
            2000,
            ("STATIC_ANALYSIS",),
        )
        scope = ScopeEnvelope(
            scope_id="scope:test",
            authorization_id="auth:test",
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
            network_mode="EXTERNAL",
        )
        simulator = TRCPSimulator(authorization, scope)
        with self.assertRaisesRegex(TRCPError, "LOCAL_ONLY"):
            simulator.authorize()


if __name__ == "__main__":
    unittest.main()
