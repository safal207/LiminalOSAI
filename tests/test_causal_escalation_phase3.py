from __future__ import annotations

import unittest

from sdk.liminal_causal_escalation import EscalationError, TrajectoryEvent, analyze_trajectory, replay

ZERO = "0" * 64


def make_events(kinds, *, decisions=None, privileges=None, capability_ids=None):
    out = []
    previous = ZERO
    decisions = decisions or ["ALLOW"] * len(kinds)
    privileges = privileges or [(0, 0)] * len(kinds)
    capability_ids = capability_ids or [None] * len(kinds)
    for index, kind in enumerate(kinds, start=1):
        before, after = privileges[index - 1]
        event = TrajectoryEvent.build(
            event_id=f"event:{index}",
            sequence=index,
            observed_at_unix=100 + index,
            kind=kind,
            decision=decisions[index - 1],
            subject_id="user:pilot",
            capability_id=capability_ids[index - 1],
            privilege_level_before=before,
            privilege_level_after=after,
            metadata={"safe": index},
            previous_event_sha256=previous,
        )
        out.append(event)
        previous = event.event_sha256
    return out


class CausalEscalationPhase3Tests(unittest.TestCase):
    def test_single_normal_action_is_allow(self):
        result = analyze_trajectory(make_events(["repository.write"]))
        self.assertEqual("ALLOW", result["decision"])
        self.assertEqual(0, result["risk_score"])

    def test_package_then_network_is_revise(self):
        result = analyze_trajectory(make_events(["package.install", "network.connect_domain"]))
        self.assertEqual("REVISE", result["decision"])
        self.assertIn("R-PACKAGE-EGRESS", result["matched_rules"])

    def test_network_then_credential_is_revise(self):
        result = analyze_trajectory(make_events(["network.connect_domain", "credential.access"]))
        self.assertEqual("REVISE", result["decision"])
        self.assertIn("R-CRED-EGRESS", result["matched_rules"])

    def test_credential_then_child_is_revise(self):
        result = analyze_trajectory(make_events(["credential.access", "process.spawn_child"]))
        self.assertEqual("REVISE", result["decision"])
        self.assertIn("R-CRED-CHILD", result["matched_rules"])

    def test_composed_chain_reaches_contain(self):
        events = make_events([
            "package.install",
            "network.connect_domain",
            "credential.access",
            "process.spawn_child",
        ])
        result = analyze_trajectory(events)
        self.assertEqual("CONTAIN", result["decision"])
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertIn("R-PACKAGE-EGRESS", result["matched_rules"])
        self.assertIn("R-CRED-EGRESS", result["matched_rules"])
        self.assertIn("R-CRED-CHILD", result["matched_rules"])

    def test_blocked_events_do_not_promote_composition(self):
        events = make_events(
            ["package.install", "network.connect_domain", "credential.access"],
            decisions=["ALLOW", "BLOCK", "ALLOW"],
        )
        result = analyze_trajectory(events)
        self.assertNotEqual("CONTAIN", result["decision"])
        self.assertNotIn("R-PACKAGE-EGRESS", result["matched_rules"])

    def test_privilege_delta_increases_risk(self):
        events = make_events(
            ["repository.write", "runtime.configure"],
            privileges=[(0, 0), (0, 6)],
        )
        result = analyze_trajectory(events)
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertEqual(6, result["privilege_delta"])

    def test_capability_growth_increases_risk(self):
        events = make_events(
            ["capability.grant", "capability.grant", "capability.grant", "repository.write"],
            capability_ids=["cap:a", "cap:b", "cap:c", None],
        )
        result = analyze_trajectory(events)
        self.assertEqual(3, result["capability_delta"])
        self.assertGreater(result["risk_score"], 0)

    def test_revoke_reduces_peak_tracking_only_after_peak(self):
        events = make_events(
            ["capability.grant", "capability.grant", "capability.revoke"],
            capability_ids=["cap:a", "cap:b", "cap:a"],
        )
        result = analyze_trajectory(events)
        self.assertEqual(2, result["capability_delta"])

    def test_rule_order_matters(self):
        result = analyze_trajectory(make_events(["credential.access", "network.connect_domain"]))
        self.assertNotIn("R-CRED-EGRESS", result["matched_rules"])

    def test_explanation_names_rules_and_events(self):
        result = analyze_trajectory(make_events(["package.install", "network.connect_domain"]))
        self.assertIn("R-PACKAGE-EGRESS", result["explanation"])
        self.assertIn("event:1", result["explanation"])

    def test_replay_is_deterministic(self):
        events = make_events(["package.install", "network.connect_domain", "credential.access"])
        first = analyze_trajectory(events)
        docs = [event.body() | {"event_sha256": event.event_sha256} for event in events]
        second = replay(docs)
        self.assertEqual(first, second)

    def test_tamper_fails_closed(self):
        events = make_events(["repository.write"])
        doc = events[0].body() | {"event_sha256": events[0].event_sha256}
        doc["kind"] = "credential.access"
        with self.assertRaises(EscalationError):
            replay([doc])

    def test_reordered_sequence_fails_closed(self):
        events = make_events(["repository.write", "runtime.configure"])
        with self.assertRaises(EscalationError):
            analyze_trajectory((events[1], events[0]))

    def test_disconnected_hash_chain_fails_closed(self):
        events = make_events(["repository.write", "runtime.configure"])
        bad = TrajectoryEvent(**{**events[1].__dict__, "previous_event_sha256": ZERO})
        with self.assertRaises(EscalationError):
            analyze_trajectory((events[0], bad))

    def test_time_regression_fails_closed(self):
        events = make_events(["repository.write", "runtime.configure"])
        bad = TrajectoryEvent(**{**events[1].__dict__, "observed_at_unix": 1})
        with self.assertRaises(EscalationError):
            analyze_trajectory((events[0], bad))

    def test_unsupported_event_kind_rejected(self):
        with self.assertRaises(EscalationError):
            TrajectoryEvent.build(
                event_id="event:x", sequence=1, observed_at_unix=1,
                kind="unknown", decision="ALLOW", subject_id="user:x",
                capability_id=None, privilege_level_before=0, privilege_level_after=0,
                metadata={}, previous_event_sha256=ZERO,
            )

    def test_unsupported_decision_rejected(self):
        with self.assertRaises(EscalationError):
            TrajectoryEvent.build(
                event_id="event:x", sequence=1, observed_at_unix=1,
                kind="repository.write", decision="YES", subject_id="user:x",
                capability_id=None, privilege_level_before=0, privilege_level_after=0,
                metadata={}, previous_event_sha256=ZERO,
            )

    def test_privilege_out_of_bounds_rejected(self):
        with self.assertRaises(EscalationError):
            TrajectoryEvent.build(
                event_id="event:x", sequence=1, observed_at_unix=1,
                kind="repository.write", decision="ALLOW", subject_id="user:x",
                capability_id=None, privilege_level_before=0, privilege_level_after=11,
                metadata={}, previous_event_sha256=ZERO,
            )

    def test_receipt_is_stable(self):
        events = make_events(["package.install", "network.connect_domain"])
        a = analyze_trajectory(events)
        b = analyze_trajectory(events)
        self.assertEqual(a["receipt_sha256"], b["receipt_sha256"])

    def test_authority_is_analysis_only(self):
        result = analyze_trajectory(make_events(["repository.write"]))
        authority = result["authority"]
        self.assertFalse(authority["execution"])
        self.assertFalse(authority["containment_execution"])
        self.assertFalse(authority["capability_grant"])


if __name__ == "__main__":
    unittest.main()
