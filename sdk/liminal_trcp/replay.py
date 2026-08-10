"""TRCP v0.2 — Independent replay verifier.

Validates a provider-neutral evidence bundle without re-running the
originating simulator. The verifier checks invariants from the bundle alone:
causal order, scope monotonicity, authorization continuity, state
transition legality, temporal monotonicity, task identity, finding
trustworthiness, and verification closure.

Deterministic: same bundle -> same receipt -> same receipt_sha256.
LOCAL_ONLY / SYNTHETIC_ONLY. No providers, no network, no real targets.
"""
from __future__ import annotations

from typing import Any

from sdk.liminal_post_sandbox_contracts import canonical_sha256

RECEIPT_SCHEMA = "liminal-trcp-replay-receipt-v0.2"

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "NEW": frozenset({"AUTHORIZED"}),
    "AUTHORIZED": frozenset({"ACTIVE", "AUTH_EXPIRED", "SCOPE_INVALID"}),
    "ACTIVE": frozenset({"VERIFYING", "DEGRADED", "ABORTED"}),
    "DEGRADED": frozenset({"FAILOVER_PENDING"}),
    "FAILOVER_PENDING": frozenset({
        "ACTIVE_ON_FALLBACK",
        "AUTH_EXPIRED",
        "SCOPE_INVALID",
        "HUMAN_REVIEW_REQUIRED",
        "ABORTED",
    }),
    "ACTIVE_ON_FALLBACK": frozenset({"VERIFYING", "AUTH_EXPIRED", "SCOPE_INVALID", "ABORTED"}),
    "VERIFYING": frozenset({"CLOSED"}),
    "AUTH_EXPIRED": frozenset(),
    "SCOPE_INVALID": frozenset(),
    "HUMAN_REVIEW_REQUIRED": frozenset(),
    "ABORTED": frozenset(),
    "CLOSED": frozenset(),
}

TERMINAL_STATES = frozenset({
    "AUTH_EXPIRED",
    "SCOPE_INVALID",
    "HUMAN_REVIEW_REQUIRED",
    "ABORTED",
    "CLOSED",
})


class CheckResult:
    def __init__(self, check_id: str, result: str, detail: str = "") -> None:
        self.check_id = check_id
        self.result = result
        self.detail = detail

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.check_id, "result": self.result}
        if self.detail:
            out["detail"] = self.detail
        return out


def _get_primary_run_id(bundle: dict[str, Any]) -> str | None:
    provider_runs = bundle.get("provider_runs") or []
    if not provider_runs:
        return None
    return provider_runs[0].get("run_id")


def _check_bundle_integrity(bundle: dict[str, Any]) -> CheckResult:
    expected = bundle.get("bundle_sha256", "")
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    actual = canonical_sha256(body)
    if expected == actual:
        return CheckResult("BUNDLE_INTEGRITY", "PASS")
    return CheckResult(
        "BUNDLE_INTEGRITY",
        "FAIL",
        f"bundle_sha256 mismatch: expected={actual}, got={expected}",
    )


def _check_trace_hash_chain(bundle: dict[str, Any]) -> CheckResult:
    trace = bundle.get("trace") or []
    previous = "0" * 64
    for idx, event in enumerate(trace, start=1):
        claimed_prev = event.get("previous_event_sha256", "")
        if claimed_prev != previous:
            return CheckResult(
                "TRACE_HASH_CHAIN",
                "FAIL",
                f"event {idx}: previous_event_sha256 mismatch",
            )
        event_hash = event.get("event_sha256", "")
        core = {k: v for k, v in event.items() if k != "event_sha256"}
        expected_hash = canonical_sha256(core)
        if event_hash != expected_hash:
            return CheckResult(
                "TRACE_HASH_CHAIN",
                "FAIL",
                f"event {idx}: event_sha256 does not match canonical hash",
            )
        claimed_sequence = event.get("sequence", -1)
        if claimed_sequence != idx:
            return CheckResult(
                "TRACE_HASH_CHAIN",
                "FAIL",
                f"event {idx}: sequence discontinuity (got {claimed_sequence})",
            )
        previous = event_hash
    return CheckResult("TRACE_HASH_CHAIN", "PASS")


def _extract_transition_sequence(bundle: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    trace = bundle.get("trace") or []
    transitions: list[tuple[str, str, dict[str, Any]]] = []
    for event in trace:
        if event.get("kind") == "STATE_TRANSITION":
            payload = event.get("payload") or {}
            from_state = payload.get("from", "")
            to_state = payload.get("to", "")
            transitions.append((from_state, to_state, event))
    return transitions


def _check_state_transitions(bundle: dict[str, Any]) -> CheckResult:
    transitions = _extract_transition_sequence(bundle)
    if not transitions:
        return CheckResult("STATE_TRANSITION", "PASS", "no transitions in bundle")

    first_from, first_to, _ = transitions[0]
    if first_from != "NEW":
        return CheckResult(
            "STATE_TRANSITION",
            "FAIL",
            f"first transition must start from NEW, got {first_from}",
        )

    prev_to: str | None = None
    for from_s, to_s, _event in transitions:
        if prev_to is not None and from_s != prev_to:
            return CheckResult(
                "STATE_TRANSITION",
                "FAIL",
                f"disconnected state chain: expected from={prev_to}, got from={from_s}",
            )
        allowed = ALLOWED_TRANSITIONS.get(from_s, frozenset())
        if to_s not in allowed:
            return CheckResult(
                "STATE_TRANSITION",
                "FAIL",
                f"illegal transition: {from_s} -> {to_s}",
            )
        prev_to = to_s

    return CheckResult("STATE_TRANSITION", "PASS")


def _get_trace_event_sequences(trace: list[dict[str, Any]]) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for event in trace:
        kind = event.get("kind", "")
        seq = event.get("sequence", 0)
        result.setdefault(kind, []).append(seq)
    return result


def _check_causal_order(bundle: dict[str, Any]) -> CheckResult:
    trace = bundle.get("trace") or []
    event_seqs = _get_trace_event_sequences(trace)

    state_transition_seqs = event_seqs.get("STATE_TRANSITION", [])
    if state_transition_seqs:
        sim_created_seqs = event_seqs.get("SIMULATOR_CREATED", [])
        if sim_created_seqs and sim_created_seqs[0] > state_transition_seqs[0]:
            return CheckResult(
                "CAUSAL_ORDER",
                "FAIL",
                "SIMULATOR_CREATED after first STATE_TRANSITION",
            )

    primary_run_id = _get_primary_run_id(bundle)
    fallback_run_ids = {run.get("run_id") for run in (bundle.get("provider_runs") or [])[1:]}

    failover_seqs = event_seqs.get("FAILOVER_DECISION_RECORDED", [])
    fallback_run_seqs: list[int] = []
    for event in trace:
        if event.get("kind") == "PROVIDER_RUN_RECORDED":
            payload = event.get("payload") or {}
            run_id = payload.get("run_id", "")
            if run_id and run_id != primary_run_id and run_id in fallback_run_ids:
                fallback_run_seqs.append(event.get("sequence", 0))

    if failover_seqs and fallback_run_seqs:
        if failover_seqs[0] > fallback_run_seqs[0]:
            return CheckResult(
                "CAUSAL_ORDER",
                "FAIL",
                "FAILOVER_DECISION_RECORDED after fallback PROVIDER_RUN_RECORDED",
            )

    finding_seqs = event_seqs.get("FINDING_RECORDED", [])
    verification_seqs = event_seqs.get("VERIFICATION_RECORDED", [])
    if finding_seqs and verification_seqs:
        if finding_seqs[0] > verification_seqs[0]:
            return CheckResult(
                "CAUSAL_ORDER",
                "FAIL",
                "FINDING_RECORDED after VERIFICATION_RECORDED",
            )

    return CheckResult("CAUSAL_ORDER", "PASS")


def _check_temporal_order(bundle: dict[str, Any]) -> CheckResult:
    trace = bundle.get("trace") or []
    prev_ts = None
    for idx, event in enumerate(trace, start=1):
        ts = event.get("observed_at_unix")
        if ts is None:
            return CheckResult(
                "TEMPORAL_ORDER",
                "FAIL",
                f"event {idx}: missing observed_at_unix",
            )
        if prev_ts is not None and ts < prev_ts:
            return CheckResult(
                "TEMPORAL_ORDER",
                "FAIL",
                f"event {idx}: timestamp non-monotonic ({prev_ts} -> {ts})",
            )
        prev_ts = ts
    return CheckResult("TEMPORAL_ORDER", "PASS")


def _check_authorization_continuity(bundle: dict[str, Any]) -> CheckResult:
    auth = bundle.get("authorization") or {}
    auth_id = auth.get("authorization_id", "")
    if not auth_id:
        return CheckResult("AUTHORIZATION_CONTINUITY", "FAIL", "missing authorization_id")

    initial_scope = bundle.get("initial_scope") or {}
    effective_scope = bundle.get("effective_scope") or {}

    if initial_scope.get("authorization_id", "") != auth_id:
        return CheckResult(
            "AUTHORIZATION_CONTINUITY",
            "FAIL",
            "initial_scope.authorization_id mismatch",
        )

    if effective_scope.get("authorization_id", "") != auth_id:
        return CheckResult(
            "AUTHORIZATION_CONTINUITY",
            "FAIL",
            "effective_scope.authorization_id mismatch",
        )

    failover = bundle.get("failover_decision")
    if failover is not None:
        failover_scope_id = failover.get("scope_id", "")
        if effective_scope.get("scope_id", "") != failover_scope_id:
            return CheckResult(
                "AUTHORIZATION_CONTINUITY",
                "FAIL",
                "failover scope_id does not match effective scope_id",
            )

    return CheckResult("AUTHORIZATION_CONTINUITY", "PASS")


def _scope_permission_set(scope: dict[str, Any]) -> dict[str, set[str]] | None:
    if not scope:
        return None
    return {
        "allowed_targets": set(scope.get("allowed_targets") or []),
        "allowed_actions": set(scope.get("allowed_actions") or []),
        "allowed_environments": set(scope.get("allowed_environments") or []),
        "prohibited_actions": set(scope.get("prohibited_actions") or []),
    }


def _check_scope_monotonicity(bundle: dict[str, Any]) -> CheckResult:
    initial = bundle.get("initial_scope") or {}
    effective = bundle.get("effective_scope") or {}

    if not initial or not effective:
        return CheckResult("SCOPE_MONOTONICITY", "PASS", "no scope comparison needed")

    initial_perm = _scope_permission_set(initial)
    effective_perm = _scope_permission_set(effective)

    if initial_perm is None or effective_perm is None:
        return CheckResult("SCOPE_MONOTONICITY", "PASS")

    if not effective_perm["allowed_targets"].issubset(initial_perm["allowed_targets"]):
        diff = effective_perm["allowed_targets"] - initial_perm["allowed_targets"]
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"effective scope broadened targets: {sorted(diff)}",
        )

    if not effective_perm["allowed_actions"].issubset(initial_perm["allowed_actions"]):
        diff = effective_perm["allowed_actions"] - initial_perm["allowed_actions"]
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"effective scope broadened actions: {sorted(diff)}",
        )

    if not effective_perm["allowed_environments"].issubset(initial_perm["allowed_environments"]):
        diff = effective_perm["allowed_environments"] - initial_perm["allowed_environments"]
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"effective scope broadened environments: {sorted(diff)}",
        )

    if not initial_perm["prohibited_actions"].issubset(effective_perm["prohibited_actions"]):
        diff = initial_perm["prohibited_actions"] - effective_perm["prohibited_actions"]
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"effective scope narrowed prohibitions: {sorted(diff)}",
        )

    initial_network = initial.get("network_mode", "")
    effective_network = effective.get("network_mode", "")
    if initial_network == "LOCAL_ONLY" and effective_network != "LOCAL_ONLY":
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"network_mode broadened: {initial_network} -> {effective_network}",
        )

    initial_data = initial.get("data_handling_class", "")
    effective_data = effective.get("data_handling_class", "")
    if initial_data == "SYNTHETIC_ONLY" and effective_data != "SYNTHETIC_ONLY":
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"data_handling_class broadened: {initial_data} -> {effective_data}",
        )

    initial_expiry = initial.get("expires_at", 0)
    effective_expiry = effective.get("expires_at", 0)
    if effective_expiry > initial_expiry:
        return CheckResult(
            "SCOPE_MONOTONICITY",
            "FAIL",
            f"effective scope expiry extended: {initial_expiry} -> {effective_expiry}",
        )

    return CheckResult("SCOPE_MONOTONICITY", "PASS")


def _check_scope_overlap(scope: dict[str, Any], scope_name: str) -> CheckResult | None:
    allowed = set(scope.get("allowed_actions") or [])
    prohibited = set(scope.get("prohibited_actions") or [])
    overlap = allowed & prohibited
    if overlap:
        return CheckResult(
            "PROHIBITED_ACTION",
            "FAIL",
            f"{scope_name} scope has allowed and prohibited overlap: {sorted(overlap)}",
        )
    return None


def _check_prohibited_actions(bundle: dict[str, Any]) -> CheckResult:
    initial_scope = bundle.get("initial_scope") or {}
    effective_scope = bundle.get("effective_scope") or {}

    result = _check_scope_overlap(initial_scope, "initial")
    if result is not None:
        return result

    result = _check_scope_overlap(effective_scope, "effective")
    if result is not None:
        return result

    return CheckResult("PROHIBITED_ACTION", "PASS")


def _check_failover_decision(bundle: dict[str, Any]) -> CheckResult:
    provider_runs = bundle.get("provider_runs") or []
    failover = bundle.get("failover_decision")

    if failover is None:
        if len(provider_runs) >= 2:
            return CheckResult(
                "FAILOVER_DECISION_REQUIRED",
                "FAIL",
                "multiple provider runs but failover decision is missing",
            )
        return CheckResult("FAILOVER_DECISION_REQUIRED", "PASS", "no failover in bundle")

    if len(provider_runs) < 2:
        return CheckResult(
            "FAILOVER_DECISION_REQUIRED",
            "FAIL",
            "failover decision exists but no fallback provider run found",
        )

    trace = bundle.get("trace") or []
    primary_run_id = _get_primary_run_id(bundle)

    fallback_run_ids = {run.get("run_id") for run in provider_runs[1:]}

    failover_event_seq = None
    fallback_run_seq = None
    for event in trace:
        kind = event.get("kind", "")
        seq = event.get("sequence", 0)
        if kind == "FAILOVER_DECISION_RECORDED" and failover_event_seq is None:
            failover_event_seq = seq
        if kind == "PROVIDER_RUN_RECORDED":
            payload = event.get("payload") or {}
            run_id = payload.get("run_id", "")
            if run_id and run_id != primary_run_id and run_id in fallback_run_ids:
                fallback_run_seq = seq

    if failover_event_seq is None:
        return CheckResult(
            "FAILOVER_DECISION_REQUIRED",
            "FAIL",
            "failover decision exists but FAILOVER_DECISION_RECORDED is missing from trace",
        )

    if fallback_run_seq is None:
        return CheckResult(
            "FAILOVER_DECISION_REQUIRED",
            "FAIL",
            "failover decision exists but no identified fallback provider run in trace",
        )

    if failover_event_seq > fallback_run_seq:
        return CheckResult(
            "FAILOVER_DECISION_REQUIRED",
            "FAIL",
            "failover decision recorded after fallback execution",
        )

    return CheckResult("FAILOVER_DECISION_REQUIRED", "PASS")


def _check_task_identity(bundle: dict[str, Any]) -> CheckResult:
    provider_runs = bundle.get("provider_runs") or []
    if len(provider_runs) < 2:
        return CheckResult("TASK_IDENTITY", "PASS", "single provider run")

    primary_hash = provider_runs[0].get("normalized_task_hash", "")
    fallback_hash = provider_runs[-1].get("normalized_task_hash", "")

    if primary_hash != fallback_hash:
        return CheckResult(
            "TASK_IDENTITY",
            "FAIL",
            "fallback normalized_task_hash differs from primary",
        )

    return CheckResult("TASK_IDENTITY", "PASS")


def _check_verification_closure(bundle: dict[str, Any]) -> CheckResult:
    finding = bundle.get("finding")
    verification = bundle.get("verification")

    if finding is None:
        return CheckResult("VERIFICATION_CLOSURE", "PASS", "no finding")

    finding_status = finding.get("status", "")

    if finding_status == "CONFIRMED":
        if verification is None:
            return CheckResult(
                "VERIFICATION_CLOSURE",
                "FAIL",
                "finding is CONFIRMED but no verification exists",
            )
        if verification.get("result") != "REPRODUCED":
            return CheckResult(
                "VERIFICATION_CLOSURE",
                "FAIL",
                f"finding is CONFIRMED but verification result is {verification.get('result')}",
            )

    return CheckResult("VERIFICATION_CLOSURE", "PASS")


def _check_verification_consistency(bundle: dict[str, Any]) -> CheckResult:
    verification = bundle.get("verification")
    finding = bundle.get("finding")

    if verification is None and finding is None:
        return CheckResult("VERIFICATION_CONSISTENCY", "PASS", "no verification or finding")

    if verification is not None and finding is None:
        return CheckResult(
            "VERIFICATION_CONSISTENCY",
            "FAIL",
            "verification exists but no finding",
        )

    if verification is not None and finding is not None:
        verification_id_match = verification.get("finding_id", "") == finding.get("finding_id", "")
        if not verification_id_match:
            return CheckResult(
                "VERIFICATION_CONSISTENCY",
                "FAIL",
                "verification finding_id does not match finding",
            )

    return CheckResult("VERIFICATION_CONSISTENCY", "PASS")


def _check_final_state(bundle: dict[str, Any]) -> CheckResult:
    transitions = _extract_transition_sequence(bundle)
    if not transitions:
        return CheckResult("FINAL_STATE", "PASS", "no transitions")

    last_to_state = transitions[-1][1]

    if last_to_state not in TERMINAL_STATES:
        return CheckResult(
            "FINAL_STATE",
            "FAIL",
            f"final state {last_to_state} is not terminal",
        )

    return CheckResult("FINAL_STATE", "PASS")


CHECK_ORDER = (
    "BUNDLE_INTEGRITY",
    "TRACE_HASH_CHAIN",
    "TEMPORAL_ORDER",
    "STATE_TRANSITION",
    "CAUSAL_ORDER",
    "AUTHORIZATION_CONTINUITY",
    "SCOPE_MONOTONICITY",
    "PROHIBITED_ACTION",
    "FAILOVER_DECISION_REQUIRED",
    "TASK_IDENTITY",
    "VERIFICATION_CLOSURE",
    "VERIFICATION_CONSISTENCY",
    "FINAL_STATE",
)

CHECK_FUNCTIONS: dict[str, Any] = {
    "BUNDLE_INTEGRITY": _check_bundle_integrity,
    "TRACE_HASH_CHAIN": _check_trace_hash_chain,
    "TEMPORAL_ORDER": _check_temporal_order,
    "STATE_TRANSITION": _check_state_transitions,
    "CAUSAL_ORDER": _check_causal_order,
    "AUTHORIZATION_CONTINUITY": _check_authorization_continuity,
    "SCOPE_MONOTONICITY": _check_scope_monotonicity,
    "PROHIBITED_ACTION": _check_prohibited_actions,
    "FAILOVER_DECISION_REQUIRED": _check_failover_decision,
    "TASK_IDENTITY": _check_task_identity,
    "VERIFICATION_CLOSURE": _check_verification_closure,
    "VERIFICATION_CONSISTENCY": _check_verification_consistency,
    "FINAL_STATE": _check_final_state,
}


def verify_evidence_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    source_bundle_sha256 = bundle.get("bundle_sha256", "")
    checks: list[dict[str, Any]] = []
    failed_check_id: str | None = None
    failed_detail: str = ""

    for check_id in CHECK_ORDER:
        check_fn = CHECK_FUNCTIONS[check_id]
        result = check_fn(bundle)
        checks.append(result.as_dict())
        if result.result == "FAIL" and failed_check_id is None:
            failed_check_id = check_id
            failed_detail = result.detail

    overall_result = "FAIL" if failed_check_id is not None else "PASS"

    receipt_body: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "result": overall_result,
        "source_bundle_sha256": source_bundle_sha256,
        "checks": checks,
    }

    if failed_check_id is not None:
        receipt_body["failed_check"] = failed_check_id
        if failed_detail:
            receipt_body["failure_detail"] = failed_detail

    receipt = dict(receipt_body)
    receipt["receipt_sha256"] = canonical_sha256(receipt_body)
    return receipt


__all__ = [
    "RECEIPT_SCHEMA",
    "CHECK_ORDER",
    "verify_evidence_bundle",
    "CheckResult",
]
