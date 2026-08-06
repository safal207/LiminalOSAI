"""Additional semantic guards around the v0.8 orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sdk.liminal_github_runtime import ConnectedGitHubRuntime

from ._contracts import TransactionError, TransactionPlan
from ._orchestrator import GitHubTransactionOrchestrator as _BaseOrchestrator


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
        runtime = ConnectedGitHubRuntime(runtime_config_path)
        runtime_summary = runtime.verify(allow_pending=True)
        candidate = TransactionPlan.build(
            transaction_id=transaction_id,
            runtime_config_path=str(runtime_config_path),
            runtime_config_sha256=runtime_summary["config_sha256"],
            repository_full_name=repository_full_name,
            steps=steps,
        )
        cls._validate_semantic_plan(candidate)
        return super().create(
            plan_path,
            journal_path,
            runtime_config_path=runtime_config_path,
            transaction_id=transaction_id,
            repository_full_name=repository_full_name,
            steps=steps,
        )

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
