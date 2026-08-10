import unittest

from sdk.liminal_post_sandbox_contracts import canonical_sha256
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
    def _ready_for_failover(self):
        fixture = default_fixture()
        simulator = TRCPSimulator(fixture["authorization"], fixture["scope"])
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        return fixture, simulator

    def test_default_failover_is_deterministic_and_closes(self):
        first = run_default_scenario()
        second = run_default_scenario()
        self.assertEqual(first, second)
        self.assertEqual(first["report_sha256"], second["report_sha256"])
        self.assertEqual(first["final_state"], "CLOSED")
        self.assertEqual(first["failover_record"]["permission_delta"], "UNCHANGED")
        self.assertEqual(first["finding"]["status"], "CONFIRMED")
        self.assertEqual(first["verification"]["result"], "REPRODUCED")
        self.assertIsNone(first["disclosure"])

    def test_failover_never_broadens_scope(self):
        fixture, simulator = self._ready_for_failover()
        broader = ScopeEnvelope(
            scope_id="scope:broader",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo", "fixture:other"),
            allowed_actions=("ANALYZE_FIXTURE", "ACTIVE_VALIDATE"),
        )
        with self.assertRaisesRegex(TRCPError, "broaden"):
            simulator.record_failover(fixture["fallback"], fallback_scope=broader)
        self.assertEqual(simulator.state, "SCOPE_INVALID")

    def test_narrower_fallback_scope_becomes_effective_scope(self):
        fixture = default_fixture()
        original = ScopeEnvelope(
            scope_id="scope:original",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE", "OPTIONAL_STEP"),
        )
        narrower = ScopeEnvelope(
            scope_id="scope:narrower",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
        )
        simulator = TRCPSimulator(fixture["authorization"], original)
        simulator.authorize()
        simulator.execute_primary(fixture["task"], fixture["primary"])
        record = simulator.record_failover(fixture["fallback"], fallback_scope=narrower)
        self.assertEqual(record["permission_delta"], "NARROWER")
        self.assertEqual(simulator.scope.scope_id, "scope:narrower")
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        report = simulator.report()
        self.assertEqual(report["initial_scope"]["scope_id"], "scope:original")
        self.assertEqual(report["scope"]["scope_id"], "scope:narrower")
        self.assertEqual(report["provider_runs"][-1]["scope_id"], "scope:narrower")

    def test_action_removed_by_narrower_scope_is_rejected(self):
        fixture = default_fixture()
        original = ScopeEnvelope(
            scope_id="scope:original",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE", "OPTIONAL_STEP"),
        )
        task = dict(fixture["task"])
        task["action"] = "OPTIONAL_STEP"
        narrower = ScopeEnvelope(
            scope_id="scope:narrower",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
        )
        simulator = TRCPSimulator(fixture["authorization"], original)
        simulator.authorize()
        simulator.execute_primary(task, fixture["primary"])
        simulator.record_failover(fixture["fallback"], fallback_scope=narrower)
        with self.assertRaisesRegex(TRCPError, "outside scope"):
            simulator.execute_fallback(task, fixture["fallback"])
        self.assertEqual(simulator.state, "SCOPE_INVALID")

    def test_expired_authorization_transitions_to_auth_expired(self):
        fixture, simulator = self._ready_for_failover()
        simulator.advance_time(2001)
        with self.assertRaisesRegex(TRCPError, "authorization is not currently valid"):
            simulator.record_failover(fixture["fallback"])
        self.assertEqual(simulator.state, "AUTH_EXPIRED")
        self.assertEqual(simulator.trace[-1]["payload"]["to"], "AUTH_EXPIRED")

    def test_missing_failover_record_blocks_fallback(self):
        fixture, simulator = self._ready_for_failover()
        with self.assertRaisesRegex(TRCPError, "FailoverDecisionRecord"):
            simulator.execute_fallback(fixture["task"], fixture["fallback"])

    def test_provider_specific_output_cannot_mutate_authorization(self):
        fixture, simulator = self._ready_for_failover()
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
        simulator.record_failover(fallback)
        simulator.execute_fallback(fixture["task"], fallback)
        report = simulator.report()
        self.assertEqual(report["authorization"]["authorization_id"], "auth:trcp-demo")
        self.assertEqual(report["scope"]["network_mode"], "LOCAL_ONLY")
        self.assertNotIn("authorization_id", report["finding"])
        self.assertNotIn("allowed_actions", report["finding"])

    def test_unverified_finding_cannot_be_confirmed(self):
        fixture, simulator = self._ready_for_failover()
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        self.assertEqual(simulator.finding["status"], "UNVERIFIED")
        with self.assertRaisesRegex(TRCPError, "without reproduced verification"):
            simulator.confirm_finding()

    def test_non_reproduced_finding_cannot_be_confirmed(self):
        fixture, simulator = self._ready_for_failover()
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        simulator.verify(reproduced=False)
        self.assertEqual(simulator.finding["status"], "NOT_REPRODUCED")
        with self.assertRaisesRegex(TRCPError, "without reproduced verification"):
            simulator.confirm_finding()

    def test_verification_cannot_be_overwritten_or_reversed(self):
        fixture, simulator = self._ready_for_failover()
        simulator.record_failover(fixture["fallback"])
        simulator.execute_fallback(fixture["task"], fixture["fallback"])
        first = simulator.verify(reproduced=False)
        with self.assertRaisesRegex(TRCPError, "already been recorded"):
            simulator.verify(reproduced=True)
        self.assertEqual(simulator.verification, first)
        self.assertEqual(simulator.finding["status"], "NOT_REPRODUCED")

    def test_trace_is_hash_chained(self):
        report = run_default_scenario()
        previous = "0" * 64
        for index, event in enumerate(report["trace"], start=1):
            self.assertEqual(event["sequence"], index)
            self.assertEqual(event["previous_event_sha256"], previous)
            self.assertEqual(len(event["event_sha256"]), 64)
            core = {key: value for key, value in event.items() if key != "event_sha256"}
            self.assertEqual(event["event_sha256"], canonical_sha256(core))
            previous = event["event_sha256"]

    def test_scope_requires_local_only(self):
        authorization = AuthorizationRecord(
            "auth:test", "researcher:test", "fixture:repo", 900, 2000, ("STATIC_ANALYSIS",)
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

    def test_non_synthetic_fallback_requires_human_review(self):
        fixture, simulator = self._ready_for_failover()
        candidate = ScopeEnvelope(
            scope_id="scope:external-data",
            authorization_id=fixture["authorization"].authorization_id,
            allowed_targets=("fixture:repo",),
            allowed_actions=("ANALYZE_FIXTURE",),
            data_handling_class="SENSITIVE",
        )
        with self.assertRaisesRegex(TRCPError, "SYNTHETIC_ONLY"):
            simulator.record_failover(fixture["fallback"], fallback_scope=candidate)
        self.assertEqual(simulator.state, "HUMAN_REVIEW_REQUIRED")

    def test_unapproved_data_handling_requires_human_review(self):
        fixture, simulator = self._ready_for_failover()
        with self.assertRaisesRegex(TRCPError, "human review"):
            simulator.record_failover(fixture["fallback"], data_handling_approved=False)
        self.assertEqual(simulator.state, "HUMAN_REVIEW_REQUIRED")

    def test_unminimized_sensitive_artifacts_require_human_review(self):
        fixture, simulator = self._ready_for_failover()
        with self.assertRaisesRegex(TRCPError, "minimized"):
            simulator.record_failover(fixture["fallback"], sensitive_artifacts_minimized=False)
        self.assertEqual(simulator.state, "HUMAN_REVIEW_REQUIRED")

    def test_required_human_gate_must_be_satisfied(self):
        fixture, simulator = self._ready_for_failover()
        with self.assertRaisesRegex(TRCPError, "human approval"):
            simulator.record_failover(fixture["fallback"], require_human_approval=True)
        self.assertEqual(simulator.state, "HUMAN_REVIEW_REQUIRED")

    def test_human_gate_reference_is_recorded_when_required(self):
        fixture, simulator = self._ready_for_failover()
        record = simulator.record_failover(
            fixture["fallback"],
            require_human_approval=True,
            human_approval_reference="fixture://approval/1",
        )
        self.assertTrue(record["human_approval_required"])
        self.assertEqual(record["human_approval_reference"], "fixture://approval/1")
        self.assertEqual(simulator.state, "FAILOVER_PENDING")


if __name__ == "__main__":
    unittest.main()
