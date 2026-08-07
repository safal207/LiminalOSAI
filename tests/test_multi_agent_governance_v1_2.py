import unittest

from sdk.liminal_causal_escalation import TrajectoryEvent
from sdk.liminal_multi_agent import MultiAgentError, MultiAgentGovernance

P="a"*64

def cap(cid, subject, scope, *, parent=None, expires=200, uses=4):
    return {"capability_id":cid,"subject_id":subject,"capability_type":"network.connect_domain","scope":scope,"issued_at_unix":10,"expires_at_unix":expires,"max_uses":uses,"parent_capability_id":parent,"policy_sha256":P}

def event(i, kind, subject, prev, before=0, after=0):
    return TrajectoryEvent.build(event_id=f"e{i}", sequence=i, observed_at_unix=100+i, kind=kind, decision="ALLOW", subject_id=subject, capability_id=None, privilege_level_before=before, privilege_level_after=after, metadata={"synthetic":True}, previous_event_sha256=prev)

class MultiAgentTests(unittest.TestCase):
    def setUp(self):
        self.g=MultiAgentGovernance(); self.scope={"domains":["api.example.com","logs.example.com"],"protocols":["https"],"ports":[443]}
        self.g.admit_root(cap("root","agent:a",self.scope),at_unix=20)
    def test_narrow_delegation_passes(self):
        r=self.g.delegate(cap("child","agent:b",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root",expires=150,uses=2),at_unix=30); self.assertEqual(r["decision"],"ALLOW")
    def test_scope_widen_fails_closed(self):
        with self.assertRaises(MultiAgentError): self.g.delegate(cap("child","agent:b",{"domains":["evil.example.com"],"protocols":["https"],"ports":[443]},parent="root"),at_unix=30)
    def test_ttl_widen_fails_closed(self):
        with self.assertRaises(MultiAgentError): self.g.delegate(cap("child","agent:b",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root",expires=300),at_unix=30)
    def test_use_widen_fails_closed(self):
        with self.assertRaises(MultiAgentError): self.g.delegate(cap("child","agent:b",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root",uses=9),at_unix=30)
    def test_self_delegation_blocked(self):
        with self.assertRaises(MultiAgentError): self.g.delegate(cap("child","agent:a",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root"),at_unix=30)
    def test_parent_revoke_revokes_child(self):
        self.g.delegate(cap("child","agent:b",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root",expires=150,uses=2),at_unix=30)
        out=self.g.revoke_tree("root",at_unix=40); self.assertEqual(len(out),2); self.assertTrue(all(x["decision"]=="ALLOW" for x in out))
    def test_child_use_after_parent_revoke_is_blocked(self):
        self.g.delegate(cap("child","agent:b",{"domains":["api.example.com"],"protocols":["https"],"ports":[443]},parent="root",expires=150,uses=2),at_unix=30); self.g.revoke_tree("root",at_unix=40)
        r=self.g.authorize(subject_id="agent:b",capability_id="child",requested_scope={"domains":["api.example.com"],"protocols":["https"],"ports":[443]},at_unix=50); self.assertEqual(r["decision"],"BLOCK")
    def test_collective_escalation_and_replay_shape(self):
        e1=event(1,"package.install","agent:a","0"*64); e2=event(2,"network.connect_domain","agent:b",e1.event_sha256); e3=event(3,"credential.access","agent:a",e2.event_sha256,0,1); e4=event(4,"process.spawn_child","agent:b",e3.event_sha256,1,2)
        r1=self.g.analyze_collective((e1,e2,e3,e4)); r2=self.g.analyze_collective((e1,e2,e3,e4)); self.assertEqual(r1["phase3"]["decision"],"CONTAIN"); self.assertEqual(r1["receipt_sha256"],r2["receipt_sha256"]); self.assertEqual(r1["subjects"],["agent:a","agent:b"])
    def test_single_subject_is_not_collective(self):
        e1=event(1,"repository.write","agent:a","0"*64)
        with self.assertRaises(MultiAgentError): self.g.analyze_collective((e1,))

if __name__ == "__main__": unittest.main()
