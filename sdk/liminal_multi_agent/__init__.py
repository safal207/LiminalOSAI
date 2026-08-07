"""Deterministic multi-agent delegation governance for LiminalOS v1.2."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sdk.liminal_causal_escalation import TrajectoryEvent, analyze_trajectory
from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA="liminal-multi-agent-governance-v0.1"
AUTHORITY={"mode":"delegation_governance_only","autonomous_agent_spawn":False,"execution":False,"credential_access":False,"deployment":False,"payments":False,"automatic_release":False}

class MultiAgentError(ValueError): pass

@dataclass(frozen=True)
class Grant:
    capability_id:str; subject_id:str; capability_type:str; scope:Mapping[str,Any]; issued_at_unix:int; expires_at_unix:int; max_uses:int; parent_capability_id:str|None; policy_sha256:str; status:str="active"; use_count:int=0

@dataclass(frozen=True)
class DelegationReceipt:
    parent_capability_id:str; child_capability_id:str; parent_subject_id:str; child_subject_id:str; policy_sha256:str; decision:str; reason_codes:tuple[str,...]; receipt_sha256:str
    def body(self): return {"schema":SCHEMA,"parent_capability_id":self.parent_capability_id,"child_capability_id":self.child_capability_id,"parent_subject_id":self.parent_subject_id,"child_subject_id":self.child_subject_id,"policy_sha256":self.policy_sha256,"decision":self.decision,"reason_codes":list(self.reason_codes),"authority":AUTHORITY}
    def as_document(self): return {**self.body(),"receipt_sha256":self.receipt_sha256}

class MultiAgentGovernance:
    def __init__(self): self._grants={}; self._children={}; self._receipts=[]
    def admit_root(self, document:Mapping[str,Any], *, at_unix:int):
        g=self._parse(document)
        if g.parent_capability_id is not None: raise MultiAgentError("root capability must not have a parent")
        if not (g.issued_at_unix<=at_unix<g.expires_at_unix): raise MultiAgentError("root outside validity window")
        self._grants[g.capability_id]=g; self._children.setdefault(g.capability_id,set())
        return {"decision":"ALLOW","capability_id":g.capability_id,"reason_codes":["root_admitted"]}
    def delegate(self, document:Mapping[str,Any], *, at_unix:int):
        child=self._parse(document)
        if child.parent_capability_id is None: raise MultiAgentError("delegated capability requires parent")
        parent=self._grants.get(child.parent_capability_id)
        if parent is None or parent.status!="active": raise MultiAgentError("delegation parent is not active")
        if child.capability_id==parent.capability_id: raise MultiAgentError("self-delegation is forbidden")
        if child.subject_id==parent.subject_id: raise MultiAgentError("delegation must cross subjects")
        if child.capability_type!=parent.capability_type or child.policy_sha256!=parent.policy_sha256: raise MultiAgentError("child authority differs from parent")
        if child.expires_at_unix>parent.expires_at_unix or child.max_uses>parent.max_uses: raise MultiAgentError("child validity or use bounds exceed parent")
        if not _scope_contains(parent.scope,child.scope): raise MultiAgentError("child scope exceeds parent")
        if not (child.issued_at_unix<=at_unix<child.expires_at_unix): raise MultiAgentError("child outside validity window")
        if self._would_cycle(parent.capability_id,child.capability_id): raise MultiAgentError("delegation cycle is forbidden")
        self._grants[child.capability_id]=child; self._children.setdefault(parent.capability_id,set()).add(child.capability_id); self._children.setdefault(child.capability_id,set())
        base=DelegationReceipt(parent.capability_id,child.capability_id,parent.subject_id,child.subject_id,child.policy_sha256,"ALLOW",("monotonic_narrowing","delegation_admitted"),"")
        item=DelegationReceipt(**{**base.__dict__,"receipt_sha256":canonical_sha256(base.body())}); self._receipts.append(item); return item.as_document()
    def authorize(self, *, subject_id:str, capability_id:str, requested_scope:Mapping[str,Any], at_unix:int):
        g=self._grants.get(capability_id)
        if g is None or g.status!="active" or g.subject_id!=subject_id or at_unix>=g.expires_at_unix or g.use_count>=g.max_uses or not _scope_contains(g.scope,requested_scope): return {"decision":"BLOCK","reason_codes":["default_deny"]}
        self._grants[capability_id]=Grant(**{**g.__dict__,"use_count":g.use_count+1}); return {"decision":"ALLOW","reason_codes":["delegated_scope_match"]}
    def revoke_tree(self, capability_id:str, *, at_unix:int):
        if capability_id not in self._grants: raise MultiAgentError("unknown capability")
        out=[]
        for cid in reversed(self._descendants(capability_id)):
            g=self._grants[cid]; self._grants[cid]=Grant(**{**g.__dict__,"status":"revoked"}); out.append({"capability_id":cid,"decision":"ALLOW","reason_codes":["ancestor_revoke"]})
        return tuple(out)
    def analyze_collective(self, events:Iterable[TrajectoryEvent]):
        ordered=tuple(events); subjects=tuple(sorted({e.subject_id for e in ordered}))
        if len(subjects)<2: raise MultiAgentError("collective analysis requires at least two subjects")
        phase3=analyze_trajectory(ordered); body={"schema":"liminal-multi-agent-collective-decision-v0.1","subjects":list(subjects),"event_count":len(ordered),"phase3":phase3,"authority":AUTHORITY}; return {**body,"receipt_sha256":canonical_sha256(body)}
    def _parse(self,d):
        req={"capability_id","subject_id","capability_type","scope","issued_at_unix","expires_at_unix","max_uses","parent_capability_id","policy_sha256"}
        if set(d)!=req: raise MultiAgentError("grant schema mismatch")
        return Grant(d["capability_id"],d["subject_id"],d["capability_type"],dict(d["scope"]),d["issued_at_unix"],d["expires_at_unix"],d["max_uses"],d["parent_capability_id"],d["policy_sha256"])
    def _descendants(self,root):
        out=[]; stack=[root]; seen=set()
        while stack:
            cur=stack.pop()
            if cur in seen: raise MultiAgentError("delegation cycle detected")
            seen.add(cur); out.append(cur); stack.extend(sorted(self._children.get(cur,()),reverse=True))
        return out
    def _would_cycle(self,parent,child): return child in self._grants and parent in set(self._descendants(child))

def _scope_contains(parent,child):
    for k,v in child.items():
        if k not in parent: return False
        pv=parent[k]
        if isinstance(v,list):
            if not isinstance(pv,list) or not set(v).issubset(set(pv)): return False
        elif v!=pv: return False
    return True

__all__=["AUTHORITY","DelegationReceipt","Grant","MultiAgentError","MultiAgentGovernance","SCHEMA"]
