"""Additional semantic guards around the v0.8 orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sdk.liminal_github_runtime import ConnectedGitHubRuntime

from ._contracts import (
    TransactionError,
    TransactionPlan,
    TransactionStep,
    identifier,
    repository_name,
    sha256,
    string,
)
from ._journal import TransactionJournal
from ._orchestrator import (
    GitHubTransactionOrchestrator as _BaseOrchestrator,
    _atomic_write_json,
)


class GitHubTransactionOrchestrator(_BaseOrchestrator):
    """Orchestrator with semantic plan and terminal-checkpoint validation."""

    @staticmethod
    def _validate_semantic_plan(plan: TransactionPlan) -> None:
        steps = {step.step_id: step for step in plan.steps}
        for step in plan.steps:
            if step.action != "merge_pull_request":
                continue
            expected_head = step.arguments.get("expected_head_sha")
            matching_gates = [
                steps[gate]
                for gate in step.gate_step_ids
                if steps[gate].action == "get_commit_combined_status"
                and steps[gate].expect.get("state") == "success"
                and steps[gate].arguments.get("commit_sha") == expected_head
            ]
            if not matching_gates:
                raise TransactionError(
                    "merge_pull_request requires a prior CI gate for the same "
                    "checkpoint head and expectation state=success"
                )

    @staticmethod
    def _normalized_plan(
        *,
        transaction_id: str,
        runtime_config_path: str,
        runtime_config_sha256: str,
        repository_full_name: str,
        steps: list[dict[str, Any]],
    ) -> TransactionPlan:
        tx_id = identifier(transaction_id, "transaction_plan.transaction_id")
        runtime_path = string(
            runtime_config_path, "transaction_plan.runtime_config_path"
        )
        runtime_sha = sha256(
            runtime_config_sha256,
            "transaction_plan.runtime_config_sha256",
        )
        repository = repository_name(
            repository_full_name,
            "transaction_plan.repository_full_name",
        )
        if not steps or len(steps) > 64:
            raise TransactionError(
                "transaction_plan.steps must contain 1..64 steps"
            )

        prior: dict[str, TransactionStep] = {}
        known_exports: dict[str, set[str]] = {}
        call_ids: set[str] = set()
        normalized_steps: list[TransactionStep] = []
        for index, step_value in enumerate(steps):
            step = TransactionStep.from_value(
                step_value,
                index=index,
                repository_full_name=repository,
                prior_steps=prior,
                known_exports=known_exports,
            )
            if step.step_id in prior:
                raise TransactionError(
                    f"transaction_plan contains duplicate step_id: {step.step_id}"
                )
            if step.call_id in call_ids:
                raise TransactionError(
                    f"transaction_plan contains duplicate call_id: {step.call_id}"
                )
            prior[step.step_id] = step
            known_exports[step.step_id] = set(step.exports)
            call_ids.add(step.call_id)
            normalized_steps.append(step)

        return TransactionPlan(
            transaction_id=tx_id,
            runtime_config_path=runtime_path,
            runtime_config_sha256=runtime_sha,
            repository_full_name=repository,
            steps=tuple(normalized_steps),
        )

    @classmethod
    def create(
        cls,
        plan_path: str | Path,
        journal_path: str | Path,
        *,
        runtime_config_path: str | Path,
        transaction_id: str,
        repository_full_name: str,
        steps: list[dict[str, Any]],
    ) -> "GitHubTransactionOrchestrator":
        target = Path(plan_path)
        if target.exists():
            raise TransactionError(f"transaction plan already exists: {target}")
        runtime = ConnectedGitHubRuntime(runtime_config_path)
        runtime_summary = runtime.verify(allow_pending=True)
        candidate = cls._normalized_plan(
            transaction_id=transaction_id,
            runtime_config_path=str(runtime_config_path),
            runtime_config_sha256=runtime_summary["config_sha256"],
            repository_full_name=repository_full_name,
            steps=steps,
        )
        cls._validate_semantic_plan(candidate)
        _atomic_write_json(target, candidate.as_document())
        TransactionJournal.create(journal_path, candidate)
        return cls(target, journal_path)

    @property
    def plan(self) -> TransactionPlan:
        value = super().plan
        self._validate_semantic_plan(value)
        return value

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        result = super().verify(allow_pending=allow_pending)
        journal = self.journal.read()
        if journal["entries"]:
            final = journal["entries"][-1]["event"]
            if final["type"] == "transaction_completed":
                if len(journal["entries"]) < 2:
                    raise TransactionError(
                        "transaction_completed lacks a prior checkpoint"
                    )
                previous = journal["entries"][-2]["entry_sha256"]
                if final["final_checkpoint_sha256"] != previous:
                    raise TransactionError(
                        "transaction_completed must bind the prior checkpoint head"
                    )
        return result


__all__ = ["GitHubTransactionOrchestrator"]
