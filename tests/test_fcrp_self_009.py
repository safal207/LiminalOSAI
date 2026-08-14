from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "benchmarks" / "fcrp-self-009.json"
EXPORTER = ROOT / "tools" / "export_external_validation_evidence.py"
GRAPH = ROOT / "docs" / "external_validation_graph.v0.1.yaml"


def test_fcrp_self_009_identifies_cross_repository_export_divergence() -> None:
    case = json.loads(CASE.read_text(encoding="utf-8"))

    assert case["caseId"] == "FCRP-SELF-009"
    assert case["divergence"]["firstMeaningfulDivergence"] == "N1"
    assert case["divergence"]["causePoint"] == "N1"
    assert case["divergence"]["selectedRefactorPoint"] == "N4"
    assert case["navigation"]["direction"] == "UP"
    assert case["expectedProtocolDecision"] == "PASS"


def test_self_009_fix_is_bound_to_machine_readable_negative_authority() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    source = EXPORTER.read_text(encoding="utf-8")
    boundary = graph["export_contract"]

    assert boundary["classification"] == "EVIDENCE_ONLY"
    assert boundary["authorization_transfer"] == "NONE"
    assert boundary["execution_authorized"] is False
    assert boundary["capability_granted"] is False
    assert boundary["durable_authority_granted"] is False
    assert boundary["requires_separate_authorization_contract"] is True
    assert '"authorization_transfer": "NONE"' in source
    assert '"execution_authorized": False' in source
    assert "validate_authority_boundary" in source
