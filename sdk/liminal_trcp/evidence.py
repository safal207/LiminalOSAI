"""TRCP v0.2 — Provider-neutral evidence adapter.

Takes a completed TRCP v0.1 report and produces a deterministic,
provider-neutral evidence bundle suitable for independent replay verification.

No live providers, no network, no real targets. LOCAL_ONLY / SYNTHETIC_ONLY.
"""
from __future__ import annotations

import copy
from typing import Any

from sdk.liminal_post_sandbox_contracts import canonical_sha256

BUNDLE_SCHEMA = "liminal-trcp-evidence-v0.2"

AUTHORIZATION_NODE = "AUTHORIZATION"
PRIMARY_RUN_NODE = "PRIMARY_RUN"
PROVIDER_FAILURE_NODE = "PROVIDER_FAILURE"
FAILOVER_DECISION_NODE = "FAILOVER_DECISION"
EFFECTIVE_SCOPE_NODE = "EFFECTIVE_SCOPE"
FALLBACK_RUN_NODE = "FALLBACK_RUN"
FINDING_NODE = "FINDING"
VERIFICATION_NODE = "VERIFICATION"
CLOSED_NODE = "CLOSED"


def _stable_edge_id(from_node: str, to_node: str, seq: int) -> str:
    return f"edge:{seq}:{from_node}->{to_node}"


def _build_causal_lineage(report: dict[str, Any]) -> list[dict[str, Any]]:
    auth = report["authorization"]
    auth_ref = auth.get("authorization_id", "unknown")

    edges: list[dict[str, Any]] = []
    seq = 0
    last_node: str | None = None

    def add_edge(from_node: str, to_node: str, relation: str, evidence_ref: str) -> dict[str, Any]:
        nonlocal seq, last_node
        seq += 1
        edge = {
            "edge_id": _stable_edge_id(from_node, to_node, seq),
            "from": from_node,
            "to": to_node,
            "relation": relation,
            "evidence_ref": evidence_ref,
        }
        edges.append(edge)
        last_node = to_node
        return edge

    add_edge(AUTHORIZATION_NODE, PRIMARY_RUN_NODE, "AUTHORIZES", f"ref:{auth_ref}")

    provider_runs = report.get("provider_runs") or []
    if provider_runs:
        primary = provider_runs[0]
        primary_ref = primary.get("record_sha256", "unknown")
        add_edge(PRIMARY_RUN_NODE, PROVIDER_FAILURE_NODE, "CAUSES", f"sha256:{primary_ref}")

    failover = report.get("failover_record")
    if failover is not None:
        failover_ref = failover.get("record_sha256", "unknown")
        add_edge(PROVIDER_FAILURE_NODE, FAILOVER_DECISION_NODE, "CAUSES", f"sha256:{failover_ref}")
        scope_id = failover.get("scope_id", "unknown")
        add_edge(FAILOVER_DECISION_NODE, EFFECTIVE_SCOPE_NODE, "CONSTRAINS", f"ref:{scope_id}")

    if failover is not None and len(provider_runs) >= 2:
        fallback = provider_runs[-1]
        fallback_ref = fallback.get("record_sha256", "unknown")
        add_edge(EFFECTIVE_SCOPE_NODE, FALLBACK_RUN_NODE, "AUTHORIZES", f"sha256:{fallback_ref}")

    finding = report.get("finding")
    if finding is not None and last_node == FALLBACK_RUN_NODE:
        finding_ref = finding.get("record_sha256", "unknown")
        add_edge(FALLBACK_RUN_NODE, FINDING_NODE, "CAUSES", f"sha256:{finding_ref}")

    verification = report.get("verification")
    if verification is not None and last_node == FINDING_NODE:
        verification_ref = verification.get("record_sha256", "unknown")
        add_edge(FINDING_NODE, VERIFICATION_NODE, "CAUSES", f"sha256:{verification_ref}")
        add_edge(VERIFICATION_NODE, CLOSED_NODE, "VERIFIES", f"sha256:{verification_ref}")
    elif finding is not None and last_node == FINDING_NODE:
        add_edge(FINDING_NODE, CLOSED_NODE, "CAUSES", "ref:no-verification")
    elif last_node == FALLBACK_RUN_NODE:
        add_edge(FALLBACK_RUN_NODE, CLOSED_NODE, "CAUSES", "ref:no-finding")
    elif last_node is not None:
        add_edge(last_node, CLOSED_NODE, "CAUSES", "ref:incomplete-path")

    return edges


def build_evidence_bundle(report: dict[str, Any]) -> dict[str, Any]:
    source_report_sha256 = report.get("report_sha256", "")

    authorization = copy.deepcopy(report.get("authorization") or {})
    initial_scope = copy.deepcopy(report.get("initial_scope") or {})
    effective_scope = copy.deepcopy(report.get("scope") or {})

    provider_runs = copy.deepcopy(report.get("provider_runs") or [])

    failover_record = report.get("failover_record")
    failover_decision = copy.deepcopy(failover_record) if failover_record is not None else None

    finding = report.get("finding")
    finding_record = copy.deepcopy(finding) if finding is not None else None

    verification = report.get("verification")
    verification_record = copy.deepcopy(verification) if verification is not None else None

    trace = copy.deepcopy(report.get("trace") or [])

    bundle_body: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "source_report_sha256": source_report_sha256,
        "authorization": authorization,
        "initial_scope": initial_scope,
        "effective_scope": effective_scope,
        "provider_runs": provider_runs,
        "failover_decision": failover_decision,
        "finding": finding_record,
        "verification": verification_record,
        "trace": trace,
        "causal_lineage": [],
    }
    bundle_body["causal_lineage"] = _build_causal_lineage(bundle_body)

    bundle = copy.deepcopy(bundle_body)
    bundle["bundle_sha256"] = canonical_sha256(bundle_body)
    return bundle


__all__ = [
    "BUNDLE_SCHEMA",
    "build_evidence_bundle",
]
