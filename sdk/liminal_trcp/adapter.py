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
``replay_execution`` hook). The pipeline adapts to the primary provider
outcome: a failing primary triggers the failover decision and fallback
run, a completed primary skips failover entirely, and an aborted primary
closes the run without verification.

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
from sdk.liminal_trcp.replay import (
    GENERIC_WORKLOAD_EVIDENCE_SCHEMA,
    WORKLOAD_EVIDENCE_SCHEMAS,
    verify_evidence_bundle,
)

EXECUTION_REPLAY_NOT_RUN = "NOT_RUN"
EXECUTION_REPLAY_UNSUPPORTED = "UNSUPPORTED"


class WorkloadAdapterError(ValueError):
    """Raised when an adapter artifact cannot be bound to TRCP evidence."""


@runtime_checkable
class ExternalWorkloadAdapter(Protocol):
    """Provider-neutral contract implemented by every TRCP v0.4 consumer adapter.

    Responsibilities:
    - ``normalize``: turn external input into the canonical workload body
      (the deterministic artifact the workload_sha256 commits to). The body
      must carry every field registered for its schema in
      ``WORKLOAD_EVIDENCE_SCHEMAS``. The ``result`` value may be any JSON
      value (scalar, list, or mapping); when it is a mapping whose
      ``violations`` entries provide ``invariant_id`` and ``expression``,
      the pipeline derives a synthetic finding from the first violation.
    - ``task``: build the TRCP task record, carrying a ``fixture`` reference
      that pins the workload digest (``<fixture>@sha256:<workload_sha256>``).
    - ``fixture``: build authorization / scope / task / primary provider for
      the TRCP simulator run. The primary provider outcome may be any
      MockProvider outcome: a failover outcome triggers the failover path,
      ``COMPLETED`` completes directly, ``ABORTED_BY_OPERATOR`` aborts.
    - ``replay_execution`` (optional): execution replay hook that re-runs the
      workload from a normalized workload body and returns its result. Its
      outcome is reported separately from binding replay; a hook exception is
      encoded as a FAIL status without affecting the binding receipt.
    """

    consumer_type: str

    def normalize(self, external_input: Mapping[str, Any]) -> dict[str, Any]: ...

    def task(self, workload_sha256: str) -> dict[str, Any]: ...

    def fixture(self, workload_sha256: str) -> dict[str, Any]: ...

    def replay_execution(self, workload_body: Mapping[str, Any]) -> dict[str, Any] | None: ...


def _binding_hash(workload_body: Mapping[str, Any]) -> str:
    """Canonical workload digest over the schema-registered binding fields.

    Uses the exact field projection ``verify_evidence_bundle`` hashes for the
    evidence schema, so the adapter and the verifier can never disagree.
    """
    schema = workload_body.get("schema")
    required = WORKLOAD_EVIDENCE_SCHEMAS.get(schema)
    if required is None:
        raise WorkloadAdapterError(f"unregistered workload evidence schema: {schema!r}")
    missing = [field for field in required if field not in workload_body]
    if missing:
        raise WorkloadAdapterError(
            "workload body missing required binding fields: " + ", ".join(sorted(missing))
        )
    return canonical_sha256({field: workload_body[field] for field in required})


def build_workload_evidence(
    workload_body: Mapping[str, Any],
    task: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce the consumer evidence artifact for a normalized workload body."""
    return {
        **dict(workload_body),
        "task": dict(task),
        "task_fixture": task["fixture"],
        "workload_sha256": _binding_hash(workload_body),
    }


def _synthetic_finding(result: Any) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    violations = result.get("violations") or []
    if not violations:
        return None
    first = violations[0]
    return {
        "finding_class": "WORKLOAD_INVARIANT_VIOLATION",
        "location_reference": "fixture://external-consumer-workload#L1",
        "summary": (
            f"{first.get('invariant_id', 'unknown-invariant')} violated: "
            f"{first.get('expression', 'unspecified')}"
        ),
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
    workload_sha256 = _binding_hash(workload_body)

    task = adapter.task(workload_sha256)
    fixture = adapter.fixture(workload_sha256)
    authorization: AuthorizationRecord = fixture["authorization"]
    scope: ScopeEnvelope = fixture["scope"]
    primary: MockProvider = fixture["primary"]
    workload_evidence = build_workload_evidence(workload_body, task)

    reproduction_body = adapter.normalize(external_input)
    reproduced = workload_sha256 == _binding_hash(reproduction_body)

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
    if simulator.state == "FAILOVER_PENDING":
        simulator.record_failover(fallback)
        simulator.execute_fallback(task, fallback)
    if simulator.state == "VERIFYING":
        simulator.verify(reproduced=reproduced)
        if simulator.finding is not None and reproduced:
            simulator.confirm_finding()

    report = simulator.report()
    bundle = build_evidence_bundle(report, consumer_evidence=workload_evidence)
    receipt = verify_evidence_bundle(bundle)

    execution_replay_outcome: dict[str, Any] = {"status": EXECUTION_REPLAY_NOT_RUN}
    hook = getattr(adapter, "replay_execution", None)
    if execution_replay and not callable(hook):
        execution_replay_outcome = {"status": EXECUTION_REPLAY_UNSUPPORTED}
    elif execution_replay:
        try:
            replay_result = hook(workload_body)
        except Exception as exc:  # noqa: BLE001 - isolated from binding replay
            execution_replay_outcome = {
                "status": "FAIL",
                "error": str(exc),
            }
        else:
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
            "workload_sha256": _binding_hash(reproduction_body),
            "matches_original": reproduced,
        },
        "report": report,
        "bundle": bundle,
        "receipt": receipt,
        "execution_replay": execution_replay_outcome,
    }


__all__ = [
    "EXECUTION_REPLAY_NOT_RUN",
    "EXECUTION_REPLAY_UNSUPPORTED",
    "ExternalWorkloadAdapter",
    "GENERIC_WORKLOAD_EVIDENCE_SCHEMA",
    "WorkloadAdapterError",
    "build_workload_evidence",
    "run_external_consumer",
]
