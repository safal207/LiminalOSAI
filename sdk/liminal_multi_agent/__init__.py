"""Deterministic multi-agent delegation governance for LiminalOS v1.2."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sdk.liminal_capability_broker import CapabilityBroker, BrokerError
from sdk.liminal_causal_escalation import TrajectoryEvent, analyze_trajectory
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256

SCHEMA = "liminal-multi-agent-governance-v0.1"
AUTHORITY = {
    "mode": "delegation_governance_only",
    "autonomous_agent_spawn": False,
    "execution": False,
    "credential_access": False,
    "deployment": False,
    "payments": False,
    "automatic_release": False,
}

class MultiAgentError(ValueError): pass

@dataclass(frozen=True)
class DelegationReceipt:
    delegation_id: str
    parent_capability_id: str
    child_capability_id: str
    parent_subject_id: str
    child_subject_id: str
    policy_sha256: str
    decision: str
    reason_codes: tuple[str, ...]
    broker_head_sha256: str
    receipt_sha256: str
    def body(self) -> dict[str, Any]:
        return {"schema":SCHEMA,"delegation_id":self.delegation_id,"parent_capability_id":self.parent_capability_id,"child_capability_id":self.child_capability_id,"parent_subject_id":self.parent_subject_id,"child_subject_id":self.child_subject_id,"policy_sha256":self.policy_sha256,"decision":self.decision,"reason_codes":list(self.reason_codes),"broker_head_sha256":self.broker_head_sha256,"authority":AUTHORITY}
    def as_document(self) -> dict[str, Any]: return {**self.body(),"receipt_sha256":self.receipt_sha256}

class MultiAgentGovernance:
    def __init__(self, broker: CapabilityBroker | None = None) -> None:
        self.broker = broker or CapabilityBroker("broker:multi-agent")
        self._contracts: dict[str, CapabilityContract] = {}
        self._children: dict[str, set[str]] = {}
        self._receipts: list[DelegationReceipt] = []

    def admit_root(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        c = CapabilityContract.from_document(dict(document))
        if c.parent_capability_id is not None: raise MultiAgentError("root capability must not have a parent")
        out = self.broker.admit(c.as_document(), at_unix=at_unix)
        self._contracts[c.capability_id] = c
        self._children.setdefault(c.capability_id,set())
        return out

    def delegate(self, document: Mapping[str, Any], *, at_unix: int) -> dict[str, Any]:
        child = CapabilityContract.from_document(dict(document))
        if child.parent_capability_id is None: raise MultiAgentError("delegated capability requires parent")
        if child.capability_id == child.parent_capability_id: raise MultiAgentError("self-delegation is forbidden")
        parent = self._contracts.get(child.parent_capability_id)
        if parent is None: raise MultiAgentError("unknown delegation parent")
        if child.subject_id == parent.subject_id: raise MultiAgentError("delegation must cross subjects")
        if self._would_cycle(parent.capability_id, child.capability_id): raise MultiAgentError("delegation cycle is forbidden")
        try:
            result = self.broker.admit(child.as_document(), at_unix=at_unix)
        except BrokerError as exc:
            raise MultiAgentError(str(exc)) from exc
        self._contracts[child.capability_id] = child
        self._children.setdefault(parent.capability_id,set()).add(child.capability_id)
        self._children.setdefault(child.capability_id,set())
        return self._receipt(parent, child, result["decision"], tuple(result["reason_codes"]))

    def revoke_tree(self, capability_id: str, *, at_unix: int) -> tuple[dict[str, Any], ...]:
        if capability_id not in self._contracts: raise MultiAgentError("unknown capability")
        order = self._descendants(capability_id)
        out=[]
        for cap_id in reversed(order): out.append(self.broker.revoke(cap_id, at_unix=at_unix))
        return tuple(out)

    def analyze_collective(self, events: Iterable[TrajectoryEvent]) -> dict[str, Any]:
        ordered=tuple(events)
        subjects=tuple(sorted({e.subject_id for e in ordered}))
        if len(subjects)<2: raise MultiAgentError("collective analysis requires at least two subjects")
        decision=analyze_trajectory(ordered)
        body={"schema":"liminal-multi-agent-collective-decision-v0.1","subjects":list(subjects),"event_count":len(ordered),"phase3":decision,"authority":AUTHORITY}
        return {**body,"receipt_sha256":canonical_sha256(body)}

    def _receipt(self,parent:CapabilityContract,child:CapabilityContract,decision:str,reasons:tuple[str,...])->dict[str,Any]:
        base=DelegationReceipt(f"delegation:{len(self._receipts)+1}",parent.capability_id,child.capability_id,parent.subject_id,child.subject_id,child.policy_sha256,decision,tuple(sorted(set(reasons))),self.broker.head_sha256,"")
        item=DelegationReceipt(**{**base.__dict__,"receipt_sha256":canonical_sha256(base.body())})
        self._receipts.append(item); return item.as_document()
    def _descendants(self,root:str)->list[str]:
        out=[]; stack=[root]; seen=set()
        while stack:
            cur=stack.pop()
            if cur in seen: raise MultiAgentError("delegation cycle detected")
            seen.add(cur); out.append(cur); stack.extend(sorted(self._children.get(cur,()),reverse=True))
        return out
    def _would_cycle(self,parent:str,child:str)->bool:
        if child not in self._contracts: return False
        return parent in set(self._descendants(child))

__all__=["AUTHORITY","DelegationReceipt","MultiAgentError","MultiAgentGovernance","SCHEMA"]
