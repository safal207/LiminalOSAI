"""Whole-plan policy and approval gate above Transaction Orchestrator v0.8."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sdk.liminal_github_transaction import GitHubTransactionOrchestrator, TransactionPlan

from ._contracts import (
    AUTHORITY,
    ENGINE_SCHEMA,
    PolicyError,
    PolicySnapshot,
    TransactionPolicy,
    canonical_sha256,
)
from ._ledger import ApprovalLedger


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _read_json(path: Path, name: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{name} is not valid JSON: {exc}") from exc


class GitHubTransactionPolicyEngine:
    """Binds one immutable v0.8 plan to one immutable policy and approval set."""

    def __init__(
        self,
        policy_path: str | Path,
        snapshot_path: str | Path,
        approval_ledger_path: str | Path,
        transaction_plan_path: str | Path,
        transaction_journal_path: str | Path,
    ):
        self.policy_path = Path(policy_path)
        self.snapshot_path = Path(snapshot_path)
        self.approval_ledger = ApprovalLedger(approval_ledger_path)
        self.transaction_plan_path = Path(transaction_plan_path)
        self.transaction_journal_path = Path(transaction_journal_path)

    @classmethod
    def create(
        cls,
        policy_path: str | Path,
        snapshot_path: str | Path,
        approval_ledger_path: str | Path,
        *,
        transaction_plan_path: str | Path,
        transaction_journal_path: str | Path,
        policy_id: str,
        allowed_repositories: list[str],
        rules: list[dict[str, Any]] | None = None,
        max_steps: int = 64,
        max_write_steps: int = 32,
        max_critical_steps: int = 1,
    ) -> "GitHubTransactionPolicyEngine":
        targets = [Path(policy_path), Path(snapshot_path), Path(approval_ledger_path)]
        existing = [str(path) for path in targets if path.exists()]
        if existing:
            raise PolicyError("policy artifacts already exist: " + ", ".join(existing))
        plan = TransactionPlan.from_document(
            _read_json(Path(transaction_plan_path), "transaction plan")
        )
        orchestrator = GitHubTransactionOrchestrator(
            transaction_plan_path, transaction_journal_path
        )
        orchestrator.verify(allow_pending=True)
        policy = TransactionPolicy.build(
            policy_id=policy_id,
            allowed_repositories=allowed_repositories,
            rules=rules,
            max_steps=max_steps,
            max_write_steps=max_write_steps,
            max_critical_steps=max_critical_steps,
        )
        snapshot = PolicySnapshot.evaluate(policy, plan)
        _atomic_write_json(Path(policy_path), policy.as_document())
        _atomic_write_json(Path(snapshot_path), snapshot.as_document())
        ApprovalLedger.create(approval_ledger_path, snapshot)
        return cls(
            policy_path, snapshot_path, approval_ledger_path,
            transaction_plan_path, transaction_journal_path,
        )

    @property
    def policy(self) -> TransactionPolicy:
        return TransactionPolicy.from_document(
            _read_json(self.policy_path, "transaction policy")
        )

    @property
    def plan(self) -> TransactionPlan:
        return TransactionPlan.from_document(
            _read_json(self.transaction_plan_path, "transaction plan")
        )

    @property
    def snapshot(self) -> PolicySnapshot:
        return PolicySnapshot.from_document(
            _read_json(self.snapshot_path, "policy snapshot")
        )

    @property
    def orchestrator(self) -> GitHubTransactionOrchestrator:
        return GitHubTransactionOrchestrator(
            self.transaction_plan_path, self.transaction_journal_path
        )

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        policy = self.policy
        plan = self.plan
        snapshot = self.snapshot
        if snapshot.policy_sha256 != policy.policy_sha256:
            raise PolicyError("policy snapshot is stale for the current policy")
        if snapshot.plan_sha256 != plan.plan_sha256:
            raise PolicyError("policy snapshot is stale for the current transaction plan")
        expected = PolicySnapshot.evaluate(policy, plan)
        if expected.as_document() != snapshot.as_document():
            raise PolicyError("policy snapshot does not match current evaluation")
        approvals = self.approval_ledger.summary(snapshot)
        transaction = self.orchestrator.verify(allow_pending=allow_pending)
        return {
            "schema_version": ENGINE_SCHEMA,
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "plan_sha256": plan.plan_sha256,
            "transaction_id": plan.transaction_id,
            "repository_full_name": plan.repository_full_name,
            "decision": snapshot.decision,
            "denied_reasons": list(snapshot.denied_reasons),
            "risk_summary": dict(snapshot.risk_summary),
            "approval": approvals,
            "transaction": transaction,
            "authority": AUTHORITY,
        }

    def record_approval(
        self,
        *,
        approval_id: str,
        principal_id: str,
        role: str,
        decision: str,
        requirement_id: str,
        evidence_locator: str | None = None,
    ) -> dict[str, Any]:
        self.verify(allow_pending=True)
        return self.approval_ledger.append(
            self.snapshot,
            approval_id=approval_id,
            principal_id=principal_id,
            role=role,
            decision=decision,
            requirement_id=requirement_id,
            evidence_locator=evidence_locator,
        )

    def _require_ready(self) -> dict[str, Any]:
        verification = self.verify()
        if verification["decision"] != "allow":
            raise PolicyError(
                "transaction policy denied the plan: "
                + ", ".join(verification["denied_reasons"])
            )
        status = verification["approval"]["status"]
        if status != "ready":
            pending = verification["approval"]["pending_requirement_ids"]
            denials = verification["approval"]["denial_approval_ids"]
            detail = denials if denials else pending
            raise PolicyError(
                f"transaction approval status is {status}: " + ", ".join(detail)
            )
        return verification

    def prepare_next(self) -> dict[str, Any]:
        verification = self.verify(allow_pending=True)
        prepared = self.orchestrator.prepare_next()
        return {
            "schema_version": ENGINE_SCHEMA,
            "transaction_id": verification["transaction_id"],
            "policy_decision": verification["decision"],
            "approval_status": verification["approval"]["status"],
            "pending_requirement_ids": verification["approval"]["pending_requirement_ids"],
            "next_step": prepared["next_step"],
            "authority": AUTHORITY,
        }

    def authorize_step(self, *, step_id: str, event_id: str, text: str) -> dict[str, Any]:
        self._require_ready()
        return self.orchestrator.authorize_step(
            step_id=step_id, event_id=event_id, text=text
        )

    def run_next(self, connector: Any) -> dict[str, Any]:
        self._require_ready()
        return self.orchestrator.run_next(connector)

    def run(self, connector: Any) -> dict[str, Any]:
        self._require_ready()
        return self.orchestrator.run(connector)

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.orchestrator.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.orchestrator.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.orchestrator.record_claim(**kwargs)

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        self._require_ready()
        return self.orchestrator.seal(
            request_event_id=request_event_id, draft_event_id=draft_event_id
        )

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        self._require_ready()
        return self.orchestrator.export_live_session(output_path)

    def evidence_summary(self) -> dict[str, Any]:
        verification = self.verify(allow_pending=True)
        values = {
            "policy_sha256": verification["policy_sha256"],
            "snapshot_sha256": verification["snapshot_sha256"],
            "plan_sha256": verification["plan_sha256"],
            "approval_ledger_head_sha256": verification["approval"]["head_sha256"],
            "transaction_journal_head_sha256": verification["transaction"]["journal"]["head_sha256"],
        }
        return {
            "schema_version": ENGINE_SCHEMA,
            **values,
            "engine_evidence_sha256": canonical_sha256(values),
            "authority": AUTHORITY,
        }
