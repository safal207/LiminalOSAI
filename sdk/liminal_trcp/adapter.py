"""TRCP v0.4 — Provider-neutral external consumer adapter contract.

The left block of the TRCP pipeline is an external stateful workload (any
consumer: escrow contracts, delegated spending, inventory reservation,
payout approval, ...). This module defines the stable contract every
consumer adapter implements so that core TRCP only ever performs generic
evidence binding:

    external workload -> normalize() -> canonical workload body
                       -> task()/fixture() -> TRCP task/provider records
                       -> build_workload_evidence() -> consumer evidence
                       -> build_evidence_bundle()/verify_evidence_bundle()
                          (independent binding verification)

``run_external_consumer`` is the full generic pipeline. It never branches
on consumer identity: all consumer-specific behavior lives inside the
adapter (``normalize``, ``task``, ``fixture``, and the optional
``replay_execution`` hook).

Semantic boundary:

- Binding replay: workload/evidence hash binding, task/provider references,
  causal consistency, authorization/scope continuity, trace integrity,
  verification closure, deterministic receipt. This is what
  ``verify_evidence_bundle`` does and what the receipt reports.
- Execution replay: an *optional, separate* adapter hook that re-executes
  the workload inside the synthetic fixture. It is reported independently
  and never influences the binding receipt.

No blockchain, network, credential, or real-target interaction exists here.
LOCAL_ONLY / SYNTHETIC_ONLY.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from sdk.liminal_post_sandbox_contracts import canonical_sha256
from sdk.liminal_trcp import (
    AuthorizationRecord,
    MockProvider,
    ScopeEnvelope,
    TRCPSimulator,
)
from sdk.liminal_trcp.evidence import build_evidence_bundle
from sdk.liminal_trcp.replay import GENERIC_WORKLOAD_EVIDENCE_SCHEMA, verify_evidence_bundle

EXECUTION_REPLAY_NOT_RUN = "NOT_RUN"


@runtime_checkable
class ExternalWorkloadAdapter(Protocol):
    """Provider-neutral contract implemented by every TRCP v0.4 consumer adapter.

    Responsibilities:
    - ``normalize``: turn external input into the canonical workload body
      (the deterministic artifact the workload_sha256 commits to).
    - ``task``: build the TRCP task record, carrying a ``fixture`` reference
      that pins the workload digest (``<fixture>@sha256:<workload_sha256>``).
    - ``fixture``: build authorization / scope / task / primary provider for
      the TRCP simulator run.
    - ``replay_execution`` (optional): execution replay hook that re-runs the
      workload from a normalized workload body and returns its result. Its
      outcome is reported separately from binding replay.
    """

    consumer_type: str

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]: ...

    def task(self, workload_sha256: str) -> dict[str, Any]: ...

    def fixture(self, workload_sha256: str) -> dict[str, Any]: ...

    def replay_execution(self, workload_body: Mapping[str, Any]) -> dict[str, Any] | None: ...


def build_workload_evidence(
    workload_body: Mapping[str, Any],
    task: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce the consumer evidence artifact for a normalized workload body."""
    body = dict(workload_body)
    return {
        **body,
        "task": dict(task),
        "task_fixture": task["fixture"],
        "workload_sha256": canonical_sha256(body),
    }


def _synthetic_finding(result: Mapping[str, Any]) -> dict[str, Any] | None:
    violations = result.get("violations") or []
    if not violations:
        return None
    first = violations[0]
    return {
        "finding_class": "WORKLOAD_INVARIANT_VIOLATION",
        "location_reference": "fixture://external-consumer-workload#L1",
        "summary": f"{first['invariant_id']} violated: {first['expression']}",
        "severity_claim": "HIGH",
        "confidence_claim": "DETERMINISTIC",
    }


def run_external_consumer(
    adapter: ExternalWorkloadAdapter,
    external_input: Mapping[str, Any],
    *,
    execution_replay: bool = False,
) -> dict[str, Any]:
    """Full generic pipeline: external workload -> TRCP -> evidence -> replay.

    Binding replay is always performed and produces the deterministic
    receipt. Execution replay is an optional, separate adapter hook: its
    result is reported under ``execution_replay`` and never feeds the
    binding receipt.
    """
    workload_body = adapter.normalize(external_input)
    workload_sha256 = canonical_sha256(workload_body)

    task = adapter.task(workload_sha256)
    fixture = adapter.fixture(workload_sha256)
    authorization: AuthorizationRecord = fixture["authorization"]
    scope: ScopeEnvelope = fixture["scope"]
    primary: MockProvider = fixture["primary"]
    workload_evidence = build_workload_evidence(workload_body, task)

    reproduction_body = adapter.normalize(external_input)
    reproduced = workload_sha256 == canonical_sha256(reproduction_body)

    fallback = MockProvider(
        "provider:external-fallback",
        "mock-model-b",
        "COMPLETED",
        synthetic_finding=_synthetic_finding(workload_body["result"]),
        provider_metadata={"workload_sha256": workload_sha256},
    )

    simulator = TRCPSimulator(authorization, scope)
    simulator.authorize()
    simulator.execute_primary(task, primary)
    simulator.record_failover(fallback)
    simulator.execute_fallback(task, fallback)
    simulator.verify(reproduced=reproduced)
    if simulator.finding is not None and reproduced:
        simulator.confirm_finding()

    report = simulator.report()
    bundle = build_evidence_bundle(report, consumer_evidence=workload_evidence)
    receipt = verify_evidence_bundle(bundle)

    execution_replay_outcome: dict[str, Any] = {"status": EXECUTION_REPLAY_NOT_RUN}
    hook = getattr(adapter, "replay_execution", None)
    if execution_replay and callable(hook):
        replay_result = hook(workload_body)
        matches = replay_result == workload_body.get("result")
        execution_replay_outcome = {
            "status": "PASS" if matches else "FAIL",
            "matches_binding_result": matches,
            "result": replay_result,
        }

    return {
        "workload": workload_body["result"],
        "workload_body": workload_body,
        "workload_evidence": workload_evidence,
        "reproduction": {
            "workload_sha256": canonical_sha256(reproduction_body),
            "matches_original": reproduced,
        },
        "report": report,
        "bundle": bundle,
        "receipt": receipt,
        "execution_replay": execution_replay_outcome,
    }


__all__ = [
    "EXECUTION_REPLAY_NOT_RUN",
    "ExternalWorkloadAdapter",
    "GENERIC_WORKLOAD_EVIDENCE_SCHEMA",
    "build_workload_evidence",
    "run_external_consumer",
]
