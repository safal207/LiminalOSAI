from __future__ import annotations

import unittest

from sdk.liminal_capability_broker import BROKER_AUTHORITY, BrokerError, CapabilityBroker
from sdk.liminal_post_sandbox_contracts import CapabilityContract

ZERO = "0" * 64
POLICY = "a" * 64
OTHER_POLICY = "b" * 64
RECORDER = "c" * 64


def contract(**overrides):
    values = dict(
        capability_id="cap:repo-write:1",
        capability_type="repository.write",
        subject_id="agent:worker",
        issuer_id="issuer:test",
        scope={
            "repository": "safal207/LiminalOSAI",
            "refs": ["refs/heads/agent/test"],
            "paths": ["README.md", "docs/"],
        },
        issued_at_unix=100,
        not_before_unix=110,
        expires_at_unix=200,
        max_uses=2,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )
    values.update(overrides)
    return CapabilityContract.build(**values)


def authorize(broker, **overrides):
    values = dict(
        subject_id="agent:worker",
        capability_type="repository.write",
        policy_sha256=POLICY,
        requested_scope={
            "repository": "safal207/LiminalOSAI",
            "refs": ["refs/heads/agent/test"],
            "paths": ["docs/"],
        },
        action={"operation": "update_file", "path": "docs/example.md"},
        at_unix=120,
        recorder_event_id="tool:1",
        recorder_entry_sha256=RECORDER,
    )
    values.update(overrides)
    return broker.authorize(**values)


class CapabilityBrokerTests(unittest.TestCase):
    def test_authority_is_decision_only(self):
        self.assertTrue(BROKER_AUTHORITY["capability_grant"])
        self.assertTrue(BROKER_AUTHORITY["capability_use_decision"])
        self.assertFalse(BROKER_AUTHORITY["execution"])
        self.assertFalse(BROKER_AUTHORITY["network_mediation"])
        self.assertFalse(BROKER_AUTHORITY["automatic_github_write_authorization"])

    def test_default_deny_without_capability(self):
        result = authorize(CapabilityBroker())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("default_deny", result["reason_codes"])
        self.assertIsNone(result["capability_id"])

    def test_admit_then_allow_narrower_scope(self):
        broker = CapabilityBroker()
        grant = broker.admit(contract().as_document(), at_unix=105)
        self.assertEqual(grant["decision"], "ALLOW")
        result = authorize(broker)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["use_count_before"], 0)
        self.assertEqual(result["use_count_after"], 1)

    def test_not_before_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, at_unix=109)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("not_yet_valid", result["reason_codes"])

    def test_expired_capability_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, at_unix=200)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("expired", result["reason_codes"])

    def test_expire_due_is_monotonic(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        receipts = broker.expire_due(at_unix=200)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(broker.state_document()["capabilities"][0]["status"], "expired")
        self.assertEqual(broker.expire_due(at_unix=201), ())

    def test_policy_mismatch_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, policy_sha256=OTHER_POLICY)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("policy_mismatch", result["reason_codes"])

    def test_subject_mismatch_default_denies(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, subject_id="agent:other")
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("no_matching_capability", result["reason_codes"])

    def test_capability_type_mismatch_default_denies(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = broker.authorize(
            subject_id="agent:worker", capability_type="repository.read", policy_sha256=POLICY,
            requested_scope={"repository":"safal207/LiminalOSAI","refs":["refs/heads/agent/test"],"paths":["docs/"]},
            action={"operation":"fetch_file"}, at_unix=120,
        )
        self.assertEqual(result["decision"], "BLOCK")

    def test_broader_path_scope_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, requested_scope={
            "repository":"safal207/LiminalOSAI", "refs":["refs/heads/agent/test"], "paths":["sdk/"]
        })
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("scope_mismatch", result["reason_codes"])

    def test_broader_ref_scope_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, requested_scope={
            "repository":"safal207/LiminalOSAI", "refs":["refs/heads/main"], "paths":["docs/"]
        })
        self.assertEqual(result["decision"], "BLOCK")

    def test_other_repository_blocks(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker, requested_scope={
            "repository":"safal207/other", "refs":["refs/heads/agent/test"], "paths":["docs/"]
        })
        self.assertEqual(result["decision"], "BLOCK")

    def test_use_count_exhaustion(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        self.assertEqual(authorize(broker)["decision"], "ALLOW")
        self.assertEqual(authorize(broker, recorder_event_id="tool:2")["decision"], "ALLOW")
        third = authorize(broker, recorder_event_id="tool:3")
        self.assertEqual(third["decision"], "BLOCK")
        self.assertIn("use_exhausted", third["reason_codes"])

    def test_revoke_blocks_future_use(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        broker.revoke("cap:repo-write:1", at_unix=119)
        result = authorize(broker)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("revoked", result["reason_codes"])

    def test_second_revoke_does_not_reactivate(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        self.assertEqual(broker.revoke("cap:repo-write:1", at_unix=119)["decision"], "ALLOW")
        self.assertEqual(broker.revoke("cap:repo-write:1", at_unix=120)["decision"], "BLOCK")

    def test_unknown_revoke_fails(self):
        with self.assertRaises(BrokerError):
            CapabilityBroker().revoke("cap:missing", at_unix=120)

    def test_tampered_contract_rejected(self):
        doc = contract().as_document()
        doc["scope"]["paths"] = ["/"]
        with self.assertRaises(Exception):
            CapabilityBroker().admit(doc, at_unix=105)

    def test_duplicate_id_different_contract_rejected(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        other = contract(scope={
            "repository":"safal207/LiminalOSAI", "refs":["refs/heads/agent/test"], "paths":["README.md"]
        })
        with self.assertRaises(BrokerError):
            broker.admit(other.as_document(), at_unix=106)

    def test_re_admit_same_contract_is_idempotent(self):
        broker = CapabilityBroker()
        doc = contract().as_document()
        broker.admit(doc, at_unix=105)
        result = broker.admit(doc, at_unix=106)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertIn("already_admitted", result["reason_codes"])

    def test_already_expired_contract_not_admitted(self):
        with self.assertRaises(BrokerError):
            CapabilityBroker().admit(contract().as_document(), at_unix=200)

    def test_pre_issue_contract_not_admitted(self):
        with self.assertRaises(BrokerError):
            CapabilityBroker().admit(contract().as_document(), at_unix=99)

    def test_causal_chain_links_every_event(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        authorize(broker)
        broker.revoke("cap:repo-write:1", at_unix=130)
        events = broker.events()
        self.assertEqual(events[0]["previous_causal_event_sha256"], ZERO)
        self.assertEqual(events[1]["previous_causal_event_sha256"], events[0]["event_sha256"])
        self.assertEqual(events[2]["previous_causal_event_sha256"], events[1]["event_sha256"])

    def test_receipt_is_bound_to_causal_head(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        result = authorize(broker)
        self.assertEqual(result["causal_event_sha256"], result["broker_head_sha256"])
        self.assertEqual(result["broker_head_sha256"], broker.head_sha256)

    def test_recorder_pair_validation_is_inherited(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        with self.assertRaises(Exception):
            authorize(broker, recorder_entry_sha256=None)

    def test_state_hash_changes_after_use(self):
        broker = CapabilityBroker()
        broker.admit(contract().as_document(), at_unix=105)
        before = broker.state_document()["state_sha256"]
        authorize(broker)
        after = broker.state_document()["state_sha256"]
        self.assertNotEqual(before, after)

    def test_parent_must_be_admitted_for_child(self):
        child = contract(capability_id="cap:child", parent_capability_id="cap:parent")
        with self.assertRaises(BrokerError):
            CapabilityBroker().admit(child.as_document(), at_unix=105)

    def test_parent_must_explicitly_allow_delegation(self):
        broker = CapabilityBroker()
        parent = contract(capability_id="cap:parent", delegable=False)
        broker.admit(parent.as_document(), at_unix=105)
        child = contract(capability_id="cap:child", parent_capability_id="cap:parent", scope={
            "repository":"safal207/LiminalOSAI", "refs":["refs/heads/agent/test"], "paths":["docs/"]
        })
        with self.assertRaises(BrokerError):
            broker.admit(child.as_document(), at_unix=106)

    def test_network_scope_is_narrowed(self):
        broker = CapabilityBroker()
        net = contract(
            capability_id="cap:network:1", capability_type="network.connect_domain",
            scope={"domains":["api.example.com","status.example.com"],"protocols":["https"],"ports":[443]},
        )
        broker.admit(net.as_document(), at_unix=105)
        result = broker.authorize(
            subject_id="agent:worker", capability_type="network.connect_domain", policy_sha256=POLICY,
            requested_scope={"domains":["api.example.com"],"protocols":["https"],"ports":[443]},
            action={"method":"GET","destination":"api.example.com"}, at_unix=120,
        )
        self.assertEqual(result["decision"], "ALLOW")
        self.assertFalse(result["authority"]["network_mediation"])


if __name__ == "__main__":
    unittest.main()
