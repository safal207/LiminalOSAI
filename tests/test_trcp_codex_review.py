import unittest

from sdk.liminal_trcp import (
    AUTHORITY,
    AuthorizationRecord,
    MockProvider,
    ScopeEnvelope,
    TRCPError,
    TRCPSimulator,
    default_fixture,
)


class TRCPIndependentReviewRegressionTests(unittest.TestCase):
    def _provider(self, outcome: str = "ACCESS_RESTRICTED") -> MockProvider:
        return MockProvider("provider:test", "mock-model", outcome)

    def test_explicitly_prohibited_action_is_rejected(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        task = dict(fixture["task"])
        task["action"] = "LIVE_EXPLOIT"
        with self.assertRaisesRegex(TRCPError, "explicitly prohibited"):
            simulator.execute_primary(task, self._provider())
        self.assertEqual(simulator.state, "SCOPE_INVALID")

    def test_scope_cannot_allow_and_prohibit_same_action(self):
        authorization = AuthorizationRecord(
            "auth:overlap",
            "researcher:test",
            "fixture:repo",
            900,
            3000,
            ("STATIC_ANALYSIS",),
        )
        scope = ScopeEnvelope(
            scope_id="scope:overlap",
            authorization_id=authorization.authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("LIVE_EXPLOIT",),
        )
        simulator = TRCPSimulator(authorization, scope)
        with self.assertRaisesRegex(TRCPError, "both allow and prohibit"):
            simulator.authorize()

    def test_expired_scope_blocks_primary_execution(self):
        authorization = AuthorizationRecord(
            "auth:time-primary",
            "researcher:test",
            "fixture:repo",
            900,
            3000,
            ("STATIC_ANALYSIS",),
        )
        scope = ScopeEnvelope(
            scope_id="scope:time-primary",
            authorization_id=authorization.authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
            expires_at=1100,
        )
        simulator = TRCPSimulator(authorization, scope, now_unix=1000)
        simulator.authorize()
        simulator.advance_time(1101)
        task = {
            "task_id": "task:time-primary",
            "asset_id": "fixture:repo",
            "activity_class": "STATIC_ANALYSIS",
            "action": "ANALYZE_FIXTURE",
            "fixture": "synthetic-safe-fixture-v1",
        }
        with self.assertRaisesRegex(TRCPError, "scope has expired"):
            simulator.execute_primary(task, self._provider())
        self.assertEqual(simulator.state, "SCOPE_INVALID")

    def test_expired_effective_scope_blocks_fallback_execution(self):
        authorization = AuthorizationRecord(
            "auth:time-fallback",
            "researcher:test",
            "fixture:repo",
            900,
            3000,
            ("STATIC_ANALYSIS",),
        )
        scope = ScopeEnvelope(
            scope_id="scope:time-fallback",
            authorization_id=authorization.authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
            expires_at=1500,
        )
        task = {
            "task_id": "task:time-fallback",
            "asset_id": "fixture:repo",
            "activity_class": "STATIC_ANALYSIS",
            "action": "ANALYZE_FIXTURE",
            "fixture": "synthetic-safe-fixture-v1",
        }
        primary = MockProvider("provider:A", "mock-model-a", "ACCESS_RESTRICTED")
        fallback = MockProvider("provider:B", "mock-model-b", "COMPLETED")
        simulator = TRCPSimulator(authorization, scope, now_unix=1000)
        simulator.authorize()
        simulator.execute_primary(task, primary)
        simulator.record_failover(fallback)
        simulator.advance_time(1501)
        with self.assertRaisesRegex(TRCPError, "scope has expired"):
            simulator.execute_fallback(task, fallback)
        self.assertEqual(simulator.state, "SCOPE_INVALID")

    def test_non_reproduced_verification_closes_workflow(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        simulator.verify(reproduced=False)
        self.assertEqual(simulator.finding["status"], "NOT_REPRODUCED")
        self.assertEqual(simulator.state, "CLOSED")

    def test_trace_and_records_follow_simulation_clock_and_authority_is_immutable(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        simulator.advance_time(1500)
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        report = simulator.report()
        clock_event = next(event for event in report["trace"] if event["kind"] == "CLOCK_ADVANCED")
        self.assertEqual(clock_event["observed_at_unix"], 1500)
        self.assertEqual(report["failover_record"]["created_at"], 1500)
        self.assertEqual(report["provider_runs"][-1]["started_at"], 1500)
        self.assertEqual(report["provider_runs"][-1]["ended_at"], 1500)
        self.assertEqual(report["finding"]["created_at"], 1500)
        with self.assertRaises(TypeError):
            AUTHORITY["external_network"] = True


if __name__ == "__main__":
    unittest.main()
