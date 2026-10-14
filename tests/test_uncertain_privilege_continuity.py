"""Unresolved privilege risk survives later events without granting authority."""

import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_escalation import analyze_trajectory, replay
from sdk.liminal_egress_gateway import EgressGateway, GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_runtime_mediation import (
    ExecutionObservation, ExecutionOutcomeUnknown, RuntimeMediator, verify_receipt,
)
from tests.test_runtime_mediation_v1_3 import P, contract, op


CONFIG = {"setting_keys": ["feature.safe_mode"]}
INDEPENDENT = {"setting_keys": ["feature.independent"]}
NETWORK = {"domains": ["api.example.com"], "protocols": ["https"], "ports": [443]}


class UncertainPrivilegeContinuityTests(unittest.TestCase):
    def setUp(self):
        self.broker = CapabilityBroker("broker:privilege-continuity")
        self.mediator = RuntimeMediator(broker=self.broker)

    def admit(self, cid, kind="runtime.configure", scope=CONFIG, *, uses=1):
        self.broker.admit(contract(cid, kind, "agent:a", scope, uses=uses), at_unix=20)

    @staticmethod
    def unknown(_):
        raise ExecutionOutcomeUnknown("private uncertain executor detail")

    @staticmethod
    def failed(_):
        raise RuntimeError("private failed executor detail")

    def initial_unknown(self, *, before=0, after=9):
        self.admit("cap:unknown")
        receipt = self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:unknown", before=before, after=after), self.unknown,
        )
        self.assertEqual(receipt["execution_outcome"], "UNKNOWN")
        self.assertEqual(verify_receipt(receipt), receipt)
        self.assertEqual(self.mediator.trajectory_events()[0].privilege_level_before, before)
        return receipt

    def assert_risk(self, delta=9, score=25):
        events = self.mediator.trajectory_events()
        risk = analyze_trajectory(events)
        self.assertEqual(risk["privilege_delta"], delta)
        self.assertEqual(risk["risk_score"], score)
        self.assertEqual(replay([event.__dict__ for event in events]), risk)
        for event, receipt in zip(events, self.mediator.receipts()):
            self.assertEqual(receipt["trajectory_event_sha256"], event.event_sha256)
            self.assertEqual(verify_receipt(receipt), receipt)
            self.assertNotIn("private", repr(receipt))

    def test_denied_requested_escalation_keeps_prior_risk_without_grant_or_dispatch(self):
        first = self.initial_unknown()
        calls = []
        result = self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:denied", before=0, after=10, at=21),
            lambda operation: calls.append(operation),
        )
        self.assertEqual(result["admission_decision"], "BLOCK")
        self.assertEqual(result["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(calls, [])  # The uncertain callback consumed its only use.
        event = self.mediator.trajectory_events()[-1]
        self.assertEqual((event.decision, event.privilege_level_before, event.privilege_level_after), ("BLOCK", 9, 9))
        self.assertIsNone(event.capability_id)
        self.assertEqual(self.mediator.receipts()[0], first)
        self.assert_risk()

    def test_failed_executor_keeps_prior_risk_and_its_failed_receipt(self):
        self.initial_unknown()
        self.admit("cap:failed", scope=INDEPENDENT)
        result = self.mediator.mediate(
            op("runtime.configure", INDEPENDENT, oid="op:failed", before=0, after=10, at=21), self.failed,
        )
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "FAILED")
        self.assertEqual(result["reason_codes"], ["executor_failed"])
        event = self.mediator.trajectory_events()[-1]
        self.assertEqual((event.decision, event.privilege_level_before, event.privilege_level_after), ("BLOCK", 9, 9))
        self.assert_risk()

    def test_independent_success_and_requested_lowering_do_not_reconcile_prior_unknown(self):
        self.initial_unknown()
        self.admit("cap:success", scope=INDEPENDENT, uses=2)
        calls = []
        for index, before in enumerate((0, 9), start=1):
            operation = op("runtime.configure", INDEPENDENT, oid=f"op:success:{index}", before=before, after=0, at=20 + index)
            result = self.mediator.mediate(
                operation, lambda original: calls.append(original) or ExecutionObservation.success({"changed": True}),
            )
            self.assertEqual(result["execution_outcome"], "SUCCEEDED")
            self.assertIs(calls[-1], operation)  # Projection never expands the host operation.
            event = self.mediator.trajectory_events()[-1]
            self.assertEqual((event.decision, event.privilege_level_before, event.privilege_level_after), ("ALLOW", 9, 9))
            self.assert_risk()
        self.assertEqual(len(calls), 2)

    def test_repeated_unknown_raises_but_cannot_lower_unresolved_floor(self):
        self.initial_unknown(after=3)
        self.assert_risk(delta=3, score=15)
        self.admit("cap:repeated", uses=3)
        for index, (before, after, expected_before, expected_after) in enumerate(
            ((0, 1, 3, 3), (0, 9, 3, 9), (10, 0, 10, 10)), start=1,
        ):
            result = self.mediator.mediate(
                op("runtime.configure", CONFIG, oid=f"op:unknown:{index}", before=before, after=after, at=20 + index),
                self.unknown,
            )
            self.assertEqual(result["execution_outcome"], "UNKNOWN")
            event = self.mediator.trajectory_events()[-1]
            self.assertEqual((event.privilege_level_before, event.privilege_level_after), (expected_before, expected_after))
            self.assert_risk(delta=expected_after, score=min(25, expected_after * 5))

    def test_unknown_decrease_retains_original_baseline_and_prior_privilege(self):
        self.initial_unknown(before=6, after=1)
        result = self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:denied", before=0, after=10, at=21),
            lambda _: self.fail("denied operation dispatched"),
        )
        self.assertEqual(result["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual([(event.privilege_level_before, event.privilege_level_after)
                          for event in self.mediator.trajectory_events()], [(6, 6), (6, 6)])
        self.assert_risk(delta=0, score=0)

    def test_network_events_and_containment_release_do_not_clear_prior_risk(self):
        self.initial_unknown()
        calls = []
        self.mediator.egress_gateway = EgressGateway(
            broker=self.broker, resolver=lambda _: ["93.184.216.34"],
            transport=lambda request: calls.append(request.url) or TransportResponse(204, {}, "e" * 64),
        )
        def request(index):
            return GatewayRequest(f"net:{index}", "agent:a", P, "GET", "https://api.example.com/x", {}, "e" * 64, {}, 20 + index)
        denied = self.mediator.mediate_network(request(1))
        self.assertEqual(denied["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(calls, [])
        self.assert_risk()
        self.admit("cap:network", "network.connect_domain", NETWORK, uses=2)
        self.mediator.enter_containment(incident_receipt_sha256="c" * 64)
        contained = self.mediator.mediate_network(request(2))
        self.assertEqual(contained["reason_codes"], ["containment_active", "network_blocked"])
        self.assertEqual(calls, [])
        self.assert_risk()
        self.mediator.exit_containment(human_release_receipt_sha256="d" * 64)
        succeeded = self.mediator.mediate_network(request(3))
        self.assertEqual(succeeded["execution_outcome"], "SUCCEEDED")
        self.assertEqual(len(calls), 1)
        for event in self.mediator.trajectory_events()[1:]:
            self.assertEqual((event.privilege_level_before, event.privilege_level_after), (9, 9))
        self.assert_risk()

    def test_no_unknown_receipts_events_and_analysis_keep_existing_hashes(self):
        # Captured from the published 782dd408 base before the continuity fix.
        self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:denied", before=2, after=10, at=20),
            lambda _: self.fail("denied operation dispatched"),
        )
        self.broker.admit(contract("cap:config", "runtime.configure", "agent:a", CONFIG, uses=2), at_unix=21)
        self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:success", before=4, after=1, at=22),
            lambda _: ExecutionObservation.success({"changed": True}),
        )
        self.mediator.mediate(
            op("runtime.configure", CONFIG, oid="op:failed", before=1, after=7, at=23), self.failed,
        )
        events = self.mediator.trajectory_events()
        self.assertEqual(canonical_sha256({
            "receipts": self.mediator.receipts(), "events": [event.__dict__ for event in events],
            "analysis": analyze_trajectory(events),
        }), "35cae719581997d425c38a2a2300bd4c096fa63b3e0c2bbd4cf846ac2e1604e0")
        self.assertEqual([(event.decision, event.privilege_level_before, event.privilege_level_after)
                          for event in events], [("BLOCK", 2, 2), ("ALLOW", 4, 1), ("BLOCK", 1, 1)])


if __name__ == "__main__":
    unittest.main()
