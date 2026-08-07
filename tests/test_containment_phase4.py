import hashlib
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_containment import ContainmentBlocked, ContainmentCoordinator
from sdk.liminal_post_sandbox_contracts import CapabilityContract

NOW = 2100000000
POLICY = "a" * 64


def cap(capability_id="cap:1"):
    return CapabilityContract.build(
        capability_id=capability_id,
        capability_type="network.connect_domain",
        subject_id="user:alex",
        issuer_id="issuer:test",
        scope={"domains":["example.com"],"protocols":["https"],"ports":[443]},
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW+600,
        max_uses=3,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    ).as_document()


def contain_receipt():
    return {"decision":"CONTAIN", "receipt_sha256":"b"*64}


class ContainmentTests(unittest.TestCase):
    def coordinator(self, *, fail=False):
        broker=CapabilityBroker("broker:test")
        broker.admit(cap(), at_unix=NOW)
        state={"frozen":False,"egress_closed":False}
        def freeze():
            if fail: raise RuntimeError("freeze")
            state["frozen"]=True
        def close(): state["egress_closed"]=True
        c=ContainmentCoordinator(
            broker=broker,
            freeze_runtime=freeze,
            close_egress=close,
            seal_trace=lambda: hashlib.sha256(b"trace").hexdigest(),
            snapshot_forensics=lambda:{"trace_head_sha256":"c"*64,"broker_head_sha256":broker.head_sha256,"event_count":1,"capability_count":1,"reason_codes":["trajectory"]},
        )
        return c, broker, state

    def test_requires_contain(self):
        c,_,_=self.coordinator()
        with self.assertRaises(ContainmentBlocked):
            c.contain({"decision":"BLOCK","receipt_sha256":"b"*64}, incident_id="incident:1", at_unix=NOW+1)

    def test_full_lifecycle_to_review(self):
        c,broker,state=self.coordinator()
        r=c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        self.assertEqual(r["final_state"],"REVIEW")
        self.assertTrue(state["frozen"])
        self.assertTrue(state["egress_closed"])
        self.assertEqual(broker.state_document()["capabilities"][0]["status"],"revoked")
        self.assertFalse(r["partial_failures"])

    def test_explicit_human_release(self):
        c,_,_=self.coordinator()
        c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        with self.assertRaises(ContainmentBlocked): c.release(human_release_id="", approved=True, at_unix=NOW+2)
        with self.assertRaises(ContainmentBlocked): c.release(human_release_id="human:1", approved=False, at_unix=NOW+2)
        out=c.release(human_release_id="human:1", approved=True, at_unix=NOW+2)
        self.assertEqual(out["final_state"],"RELEASED")

    def test_partial_failure_blocks_release(self):
        c,_,_=self.coordinator(fail=True)
        r=c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        self.assertEqual(r["final_state"],"REVIEW")
        self.assertTrue(r["partial_failures"])
        with self.assertRaises(ContainmentBlocked): c.release(human_release_id="human:1", approved=True, at_unix=NOW+2)

    def test_replay_stable(self):
        c,_,_=self.coordinator()
        c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        self.assertEqual(c.replay(), c.replay())

    def test_snapshot_rejects_raw_fields(self):
        broker=CapabilityBroker("broker:test")
        c=ContainmentCoordinator(broker=broker, freeze_runtime=lambda:None, close_egress=lambda:None, seal_trace=lambda:"d"*64, snapshot_forensics=lambda:{"raw_secret":"nope"})
        r=c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        self.assertIn("snapshot:ContainmentError", r["partial_failures"])

    def test_second_containment_blocked(self):
        c,_,_=self.coordinator()
        c.contain(contain_receipt(), incident_id="incident:1", at_unix=NOW+1)
        with self.assertRaises(ContainmentBlocked): c.contain(contain_receipt(), incident_id="incident:2", at_unix=NOW+2)


if __name__ == "__main__": unittest.main()
