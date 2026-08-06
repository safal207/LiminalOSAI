"""Sequential transaction orchestration above ConnectedGitHubRuntime v0.7."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sdk.liminal_github_bridge import GitHubOperation, OPERATION_POLICIES
from sdk.liminal_github_runtime import (
    AUTHORITY as RUNTIME_AUTHORITY,
    RUNTIME_SCHEMA,
    ConnectedGitHubReceipt,
    ConnectedGitHubRuntime,
)
from sdk.liminal_github_runtime._normalizers import (
    connector_tool_for,
    normalize_connector_response,
)

from ._contracts import (
    AUTHORITY,
    ORCHESTRATOR_SCHEMA,
    REFERENCE_KEY,
    TransactionError,
    TransactionPlan,
    TransactionStep,
    canonical_sha256,
    exact_keys,
    identifier,
    mapping,
    scalar,
    sha256,
    string,
)
from ._journal import TransactionJournal


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
        raise TransactionError(f"{name} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TransactionError(f"{name} is not valid JSON: {exc}") from exc


def _resolve_value(value: Any, checkpoints: dict[str, dict[str, Any]]) -> Any:
    if isinstance(value, dict) and REFERENCE_KEY in value:
        if set(value) != {REFERENCE_KEY}:
            raise TransactionError("checkpoint reference contains unsupported keys")
        token = string(value[REFERENCE_KEY], "checkpoint reference")
        step_id, export_name = token.rsplit(".", 1)
        try:
            return copy.deepcopy(checkpoints[step_id][export_name])
        except KeyError as exc:
            raise TransactionError(f"unresolved checkpoint reference: {token}") from exc
    if isinstance(value, dict):
        return {key: _resolve_value(item, checkpoints) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_value(item, checkpoints) for item in value]
    return copy.deepcopy(value)


def _extract_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index < len(current):
                current = current[index]
                continue
        raise TransactionError(f"connector payload is missing output path: {path}")
    return current


class _CapturingInvoker:
    def __init__(self, delegate: Any):
        self.delegate = delegate
        self.raw_response: Any = None

    def preflight(self, tool_name: str) -> None:
        preflight = getattr(self.delegate, "preflight", None)
        if callable(preflight):
            preflight(tool_name)

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        invoke = getattr(self.delegate, "invoke", None)
        if not callable(invoke):
            raise TransactionError("connector must expose invoke(tool_name, arguments)")
        self.raw_response = invoke(tool_name, copy.deepcopy(arguments))
        return copy.deepcopy(self.raw_response)


class GitHubTransactionOrchestrator:
    """Fail-closed ordered execution with immutable plans and checkpoints."""

    def __init__(self, plan_path: str | Path, journal_path: str | Path):
        self.plan_path = Path(plan_path)
        self.journal = TransactionJournal(journal_path)

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
        plan_target = Path(plan_path)
        if plan_target.exists():
            raise TransactionError(f"transaction plan already exists: {plan_target}")
        runtime = ConnectedGitHubRuntime(runtime_config_path)
        runtime_summary = runtime.verify(allow_pending=True)
        plan = TransactionPlan.build(
            transaction_id=transaction_id,
            runtime_config_path=str(runtime_config_path),
            runtime_config_sha256=runtime_summary["config_sha256"],
            repository_full_name=repository_full_name,
            steps=steps,
        )
        _atomic_write_json(plan_target, plan.as_document())
        TransactionJournal.create(journal_path, plan)
        return cls(plan_target, journal_path)

    @property
    def plan(self) -> TransactionPlan:
        return TransactionPlan.from_document(_read_json(self.plan_path, "transaction plan"))

    @property
    def runtime(self) -> ConnectedGitHubRuntime:
        return ConnectedGitHubRuntime(self.plan.runtime_config_path)

    def _step_map(self) -> dict[str, TransactionStep]:
        return {step.step_id: step for step in self.plan.steps}

    def _authorization_ids(self, call_id: str) -> list[str]:
        result: list[str] = []
        for entry in self.runtime.bridge.host.recorder.read()["entries"]:
            event = entry["event"]
            if event["type"] == "user_authorization" and call_id in event["authorized_event_ids"]:
                result.append(event["id"])
        return result

    def _resolved_operation(
        self, step: TransactionStep, checkpoints: dict[str, dict[str, Any]]
    ) -> tuple[GitHubOperation, Any]:
        arguments = _resolve_value(step.arguments, checkpoints)
        operation = GitHubOperation(call_id=step.call_id, action=step.action, arguments=arguments)
        normalized = self.runtime.bridge.validate_operation(operation)
        return operation, normalized

    def _ensure_step_ready(self, step: TransactionStep, summary: dict[str, Any]) -> None:
        successful = set(summary["successful_step_ids"])
        missing_gates = [gate for gate in step.gate_step_ids if gate not in successful]
        if missing_gates:
            raise TransactionError(
                f"step {step.step_id} has unsatisfied gates: " + ", ".join(missing_gates)
            )
        if step.effect == "write" and not self._authorization_ids(step.call_id):
            raise TransactionError(
                f"write step {step.step_id} requires explicit prior authorization "
                f"for call_id {step.call_id}"
            )

    def _next_step(self, summary: dict[str, Any]) -> TransactionStep | None:
        if summary["status"] in {"completed", "aborted"}:
            return None
        if summary["pending_step_ids"]:
            raise TransactionError(
                "pending step blocks replay; reconciliation is required: "
                + ", ".join(summary["pending_step_ids"])
            )
        if summary["failed_step_ids"] or summary["status"] == "halted":
            raise TransactionError(
                "halted transaction cannot continue; create a recovery transaction"
            )
        successful = set(summary["successful_step_ids"])
        for step in self.plan.steps:
            if step.step_id not in successful:
                return step
        return None

    def authorize_step(self, *, step_id: str, event_id: str, text: str) -> dict[str, Any]:
        target = identifier(step_id, "step_id")
        step = self._step_map().get(target)
        if step is None:
            raise TransactionError(f"unknown transaction step: {target}")
        if step.effect != "write":
            raise TransactionError("read steps do not require write authorization")
        return self.runtime.record_authorization(
            event_id=event_id,
            text=text,
            authorized_event_ids=[step.call_id],
        )

    def prepare_next(self) -> dict[str, Any]:
        verification = self.verify()
        summary = verification["journal"]
        step = self._next_step(summary)
        if step is None:
            return {
                "schema_version": ORCHESTRATOR_SCHEMA,
                "transaction_id": self.plan.transaction_id,
                "status": summary["status"],
                "next_step": None,
            }
        successful = set(summary["successful_step_ids"])
        missing_gates = [gate for gate in step.gate_step_ids if gate not in successful]
        if missing_gates:
            raise TransactionError(
                f"step {step.step_id} has unsatisfied gates: " + ", ".join(missing_gates)
            )
        operation, normalized = self._resolved_operation(step, summary["checkpoints"])
        return {
            "schema_version": ORCHESTRATOR_SCHEMA,
            "transaction_id": self.plan.transaction_id,
            "status": summary["status"],
            "next_step": {
                "step_id": step.step_id,
                "call_id": step.call_id,
                "action": step.action,
                "arguments": operation.arguments,
                "request_sha256": normalized.request_sha256,
                "authorization_required": step.effect == "write",
                "authorization_event_ids": self._authorization_ids(step.call_id),
                "gate_step_ids": list(step.gate_step_ids),
            },
        }

    @staticmethod
    def _exports_and_expectations(
        step: TransactionStep, payload: Any
    ) -> tuple[dict[str, Any], bool]:
        exports: dict[str, Any] = {}
        for export_name, path in step.exports.items():
            exports[export_name] = scalar(
                _extract_path(payload, path),
                f"checkpoint export {step.step_id}.{export_name}",
            )
        expectations_met = True
        for path, expected in step.expect.items():
            actual = scalar(_extract_path(payload, path), f"expectation {step.step_id}.{path}")
            if actual != expected:
                expectations_met = False
        return exports, expectations_met

    def _append_finish(
        self,
        *,
        step: TransactionStep,
        request_sha256: str,
        runtime_status: str,
        locator: str | None,
        connected_receipt_sha256: str | None,
        raw_response_sha256: str | None,
        normalized_payload_sha256: str | None,
        exports: dict[str, Any],
        expectations_met: bool,
        reconciled: bool,
        recorder_event_id: str | None,
        recorder_head_sha256: str | None,
        host_trace_head_sha256: str | None,
    ) -> dict[str, Any]:
        return self.journal.append({
            "type": "step_finished",
            "step_id": step.step_id,
            "call_id": step.call_id,
            "action": step.action,
            "request_sha256": request_sha256,
            "runtime_status": runtime_status,
            "locator": locator,
            "connected_receipt_sha256": connected_receipt_sha256,
            "raw_response_sha256": raw_response_sha256,
            "normalized_payload_sha256": normalized_payload_sha256,
            "exports": exports,
            "expectations_met": expectations_met,
            "reconciled": reconciled,
            "recorder_event_id": recorder_event_id,
            "recorder_head_sha256": recorder_head_sha256,
            "host_trace_head_sha256": host_trace_head_sha256,
        })

    def _append_halt(self, step_id: str, reason: str, detail: Any) -> None:
        self.journal.append({
            "type": "transaction_halted",
            "step_id": step_id,
            "reason": reason,
            "detail_sha256": canonical_sha256(detail),
        })

    def _recorder_event(self, call_id: str) -> tuple[dict[str, Any], str] | None:
        journal = self.runtime.bridge.host.recorder.read()
        for entry in journal["entries"]:
            event = entry["event"]
            if event["id"] == call_id:
                return event, entry["entry_sha256"]
        return None

    def run_next(self, connector: Any) -> dict[str, Any]:
        verification = self.verify()
        summary = verification["journal"]
        step = self._next_step(summary)
        if step is None:
            return verification
        self._ensure_step_ready(step, summary)
        operation, normalized = self._resolved_operation(step, summary["checkpoints"])
        tool_name = connector_tool_for(step.action)
        preflight = getattr(connector, "preflight", None)
        if callable(preflight):
            preflight(tool_name)
        elif not callable(getattr(connector, "invoke", None)):
            raise TransactionError("connector must expose invoke(tool_name, arguments)")

        self.journal.append({
            "type": "step_started",
            "step_id": step.step_id,
            "call_id": step.call_id,
            "action": step.action,
            "request_sha256": normalized.request_sha256,
            "resolved_arguments_sha256": canonical_sha256(normalized.arguments),
        })

        capture = _CapturingInvoker(connector)
        try:
            receipt = self.runtime.execute(operation, capture)
        except Exception as exc:
            recorder = self._recorder_event(step.call_id)
            recorder_event = recorder[0] if recorder else None
            recorder_hash = recorder[1] if recorder else None
            host_hash = None
            try:
                host_hash = self.runtime.bridge.host.verify(allow_pending=True)["trace_head_sha256"]
            except Exception:
                pass
            self._append_finish(
                step=step,
                request_sha256=normalized.request_sha256,
                runtime_status=recorder_event["status"] if recorder_event else "failure",
                locator=(
                    recorder_event.get("locator") if recorder_event
                    else f"exception:{type(exc).__module__}.{type(exc).__qualname__}"
                ),
                connected_receipt_sha256=None,
                raw_response_sha256=None,
                normalized_payload_sha256=None,
                exports={},
                expectations_met=False,
                reconciled=False,
                recorder_event_id=recorder_event["id"] if recorder_event else None,
                recorder_head_sha256=recorder_hash,
                host_trace_head_sha256=host_hash,
            )
            self._append_halt(
                step.step_id,
                "connected_execution_exception",
                {
                    "exception_type": f"{type(exc).__module__}.{type(exc).__qualname__}",
                    "message": str(exc)[:1024],
                },
            )
            raise

        normalized_response = normalize_connector_response(
            action=step.action,
            arguments=normalized.arguments,
            request_sha256=normalized.request_sha256,
            raw_response=capture.raw_response,
            max_response_bytes=self.runtime.config.max_response_bytes,
        )
        if (
            normalized_response.raw_response_sha256 != receipt.raw_response_sha256
            or normalized_response.normalized_payload_sha256 != receipt.normalized_payload_sha256
        ):
            raise TransactionError("connected runtime receipt does not match captured response")
        payload = normalized_response.executor_result.payload
        try:
            exports, expectations_met = self._exports_and_expectations(step, payload)
        except TransactionError as exc:
            exports = {}
            expectations_met = False
            checkpoint_error = exc
        else:
            checkpoint_error = None

        receipt_document = receipt.as_dict()
        self._append_finish(
            step=step,
            request_sha256=normalized.request_sha256,
            runtime_status=receipt.status,
            locator=receipt.locator,
            connected_receipt_sha256=canonical_sha256(receipt_document),
            raw_response_sha256=receipt.raw_response_sha256,
            normalized_payload_sha256=receipt.normalized_payload_sha256,
            exports=exports,
            expectations_met=expectations_met,
            reconciled=False,
            recorder_event_id=receipt.recorder_event_id,
            recorder_head_sha256=receipt.recorder_head_sha256,
            host_trace_head_sha256=receipt.host_trace_head_sha256,
        )
        if receipt.status != "success":
            self._append_halt(step.step_id, "github_step_failed", {"status": receipt.status, "locator": receipt.locator})
        elif checkpoint_error is not None:
            self._append_halt(step.step_id, "invalid_checkpoint_output", {"message": str(checkpoint_error)[:1024]})
        elif not expectations_met:
            self._append_halt(step.step_id, "checkpoint_expectation_mismatch", {"expected": step.expect})
        else:
            updated = self.journal.summary()
            if len(updated["successful_step_ids"]) == len(self.plan.steps):
                self.journal.append({
                    "type": "transaction_completed",
                    "completed_step_ids": [item.step_id for item in self.plan.steps],
                    "final_checkpoint_sha256": updated["head_sha256"],
                })
        return self.verify()

    def run(self, connector: Any, *, max_steps: int | None = None) -> dict[str, Any]:
        limit = len(self.plan.steps) if max_steps is None else max_steps
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise TransactionError("max_steps must be a positive integer")
        for _ in range(limit):
            summary = self.journal.summary()
            if summary["status"] in {"completed", "aborted", "halted"}:
                break
            self.run_next(connector)
        return self.verify()

    @staticmethod
    def _receipt_from_document(value: Any) -> ConnectedGitHubReceipt:
        raw = mapping(value, "connected_receipt")
        expected = {
            "schema_version", "call_id", "action", "connector_name",
            "connector_tool", "request_sha256", "raw_response_sha256",
            "normalized_payload_sha256", "status", "locator",
            "bridge_receipt_sha256", "recorder_event_id",
            "recorder_head_sha256", "host_trace_head_sha256", "authority",
        }
        exact_keys(raw, expected, set(), "connected_receipt")
        if raw["schema_version"] != RUNTIME_SCHEMA:
            raise TransactionError(f"connected_receipt.schema_version must be {RUNTIME_SCHEMA}")
        if raw["authority"] != RUNTIME_AUTHORITY:
            raise TransactionError("connected_receipt.authority must remain fixed")
        for key in (
            "request_sha256", "raw_response_sha256", "normalized_payload_sha256",
            "bridge_receipt_sha256", "recorder_head_sha256", "host_trace_head_sha256",
        ):
            raw[key] = sha256(raw[key], f"connected_receipt.{key}")
        for key in (
            "call_id", "action", "connector_name", "connector_tool",
            "status", "locator", "recorder_event_id",
        ):
            raw[key] = string(raw[key], f"connected_receipt.{key}")
        if raw["status"] not in {"success", "failure", "cancelled"}:
            raise TransactionError("connected_receipt.status is invalid")
        return ConnectedGitHubReceipt(**raw)

    def reconcile_pending(self, *, connected_receipt: Any, raw_response: Any) -> dict[str, Any]:
        verification = self.verify(allow_pending=True)
        summary = verification["journal"]
        pending = summary["pending_step_ids"]
        if len(pending) != 1:
            raise TransactionError("reconciliation requires exactly one pending step")
        step = self._step_map()[pending[0]]
        start = summary["starts"][step.step_id]
        _, normalized = self._resolved_operation(step, summary["checkpoints"])
        receipt = self._receipt_from_document(connected_receipt)
        if (
            receipt.call_id != step.call_id or receipt.action != step.action
            or receipt.request_sha256 != normalized.request_sha256
            or receipt.request_sha256 != start["request_sha256"]
        ):
            raise TransactionError("connected receipt does not match pending transaction step")
        normalized_response = normalize_connector_response(
            action=step.action,
            arguments=normalized.arguments,
            request_sha256=normalized.request_sha256,
            raw_response=raw_response,
            max_response_bytes=self.runtime.config.max_response_bytes,
        )
        if (
            normalized_response.raw_response_sha256 != receipt.raw_response_sha256
            or normalized_response.normalized_payload_sha256 != receipt.normalized_payload_sha256
            or normalized_response.executor_result.status != receipt.status
            or normalized_response.executor_result.locator != receipt.locator
        ):
            raise TransactionError("raw response does not match retained connected receipt")
        recorder = self._recorder_event(step.call_id)
        if recorder is None:
            raise TransactionError("pending step has no matching recorder event; refusing reconciliation")
        recorder_event, recorder_hash = recorder
        if (
            recorder_event["status"] != receipt.status
            or recorder_event["locator"] != receipt.locator
            or recorder_hash != receipt.recorder_head_sha256
        ):
            raise TransactionError("recorder event does not match retained connected receipt")
        exports, expectations_met = self._exports_and_expectations(
            step, normalized_response.executor_result.payload
        )
        self._append_finish(
            step=step,
            request_sha256=normalized.request_sha256,
            runtime_status=receipt.status,
            locator=receipt.locator,
            connected_receipt_sha256=canonical_sha256(receipt.as_dict()),
            raw_response_sha256=receipt.raw_response_sha256,
            normalized_payload_sha256=receipt.normalized_payload_sha256,
            exports=exports,
            expectations_met=expectations_met,
            reconciled=True,
            recorder_event_id=receipt.recorder_event_id,
            recorder_head_sha256=receipt.recorder_head_sha256,
            host_trace_head_sha256=receipt.host_trace_head_sha256,
        )
        if receipt.status != "success" or not expectations_met:
            self._append_halt(
                step.step_id,
                "reconciled_step_not_eligible_to_continue",
                {"status": receipt.status, "expectations_met": expectations_met},
            )
        else:
            updated = self.journal.summary()
            if len(updated["successful_step_ids"]) == len(self.plan.steps):
                self.journal.append({
                    "type": "transaction_completed",
                    "completed_step_ids": [item.step_id for item in self.plan.steps],
                    "final_checkpoint_sha256": updated["head_sha256"],
                })
        return self.verify()

    def abort(self, *, reason: str) -> dict[str, Any]:
        summary = self.journal.summary()
        if summary["status"] in {"completed", "aborted"}:
            raise TransactionError(f"cannot abort transaction in state {summary['status']}")
        if summary["pending_step_ids"]:
            raise TransactionError("cannot abort while a tool outcome requires reconciliation")
        self.journal.append({
            "type": "transaction_aborted",
            "reason_sha256": canonical_sha256({"reason": string(reason, "reason")}),
        })
        return self.verify()

    def recovery_report(self) -> dict[str, Any]:
        verification = self.verify(allow_pending=True)
        summary = verification["journal"]
        steps = self._step_map()
        completed = []
        manual_recovery_required = False
        for step_id in summary["successful_step_ids"]:
            step = steps[step_id]
            finish = summary["finishes"][step_id]
            policy = OPERATION_POLICIES[step.action]
            if step.effect == "write":
                manual_recovery_required = True
            completed.append({
                "step_id": step_id,
                "action": step.action,
                "effect": step.effect,
                "reversible": policy.reversible,
                "recovery_plan": policy.recovery_plan,
                "locator": finish["locator"],
            })
        return {
            "schema_version": ORCHESTRATOR_SCHEMA,
            "transaction_id": self.plan.transaction_id,
            "status": summary["status"],
            "completed_steps": completed,
            "pending_step_ids": summary["pending_step_ids"],
            "failed_step_ids": summary["failed_step_ids"],
            "manual_recovery_required": manual_recovery_required,
            "automatic_rollback": False,
            "automatic_pending_write_replay": False,
            "authority": AUTHORITY,
        }

    def verify(self, *, allow_pending: bool = False) -> dict[str, Any]:
        plan = self.plan
        runtime_summary = self.runtime.verify(allow_pending=True)
        if runtime_summary["config_sha256"] != plan.runtime_config_sha256:
            raise TransactionError("runtime config changed after transaction plan creation")
        journal = self.journal.read()
        if (
            journal["transaction_id"] != plan.transaction_id
            or journal["plan_sha256"] != plan.plan_sha256
            or journal["runtime_config_sha256"] != plan.runtime_config_sha256
        ):
            raise TransactionError("journal does not match immutable transaction plan")
        summary = self.journal.summary()
        checkpoints: dict[str, dict[str, Any]] = {}
        recorder_entries = {
            entry["event"]["id"]: entry
            for entry in self.runtime.bridge.host.recorder.read()["entries"]
        }
        for step in plan.steps:
            start = summary["starts"].get(step.step_id)
            finish = summary["finishes"].get(step.step_id)
            if start is None:
                break
            _, normalized = self._resolved_operation(step, checkpoints)
            if (
                start["call_id"] != step.call_id
                or start["action"] != step.action
                or start["request_sha256"] != normalized.request_sha256
                or start["resolved_arguments_sha256"] != canonical_sha256(normalized.arguments)
            ):
                raise TransactionError(f"checkpoint start drift detected for step {step.step_id}")
            if finish is not None:
                recorder_entry = recorder_entries.get(step.call_id)
                if finish["recorder_event_id"] is not None:
                    if recorder_entry is None:
                        raise TransactionError(f"missing recorder event for step {step.step_id}")
                    event = recorder_entry["event"]
                    if (
                        event["type"] != "tool_event"
                        or event["status"] != finish["runtime_status"]
                        or event["locator"] != finish["locator"]
                        or recorder_entry["entry_sha256"] != finish["recorder_head_sha256"]
                    ):
                        raise TransactionError(f"recorder correlation mismatch for step {step.step_id}")
                if finish["runtime_status"] == "success" and finish["expectations_met"]:
                    checkpoints[step.step_id] = dict(finish["exports"])
        started_ids = set(summary["starts"])
        expected_prefix: list[str] = []
        for step in plan.steps:
            if step.step_id in started_ids:
                expected_prefix.append(step.step_id)
            else:
                break
        if started_ids != set(expected_prefix):
            raise TransactionError("journal step order is not a prefix of the immutable plan")
        if checkpoints != summary["checkpoints"]:
            raise TransactionError("journal checkpoint summary mismatch")
        if summary["pending_step_ids"] and not allow_pending:
            raise TransactionError("transaction contains a pending step requiring reconciliation")
        if summary["status"] == "completed":
            completed_ids = set(summary["successful_step_ids"])
            expected_ids = {step.step_id for step in plan.steps}
            if completed_ids != expected_ids:
                raise TransactionError("completed transaction is missing successful steps")
        return {
            "schema_version": ORCHESTRATOR_SCHEMA,
            "transaction_id": plan.transaction_id,
            "plan_sha256": plan.plan_sha256,
            "runtime_config_sha256": plan.runtime_config_sha256,
            "repository_full_name": plan.repository_full_name,
            "step_count": len(plan.steps),
            "journal": summary,
            "runtime": runtime_summary,
            "authority": AUTHORITY,
        }

    def record_user_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.runtime.record_user_message(**kwargs)

    def record_assistant_draft(self, **kwargs: Any) -> dict[str, Any]:
        return self.runtime.record_assistant_draft(**kwargs)

    def record_claim(self, **kwargs: Any) -> dict[str, Any]:
        return self.runtime.record_claim(**kwargs)

    def seal(self, *, request_event_id: str, draft_event_id: str) -> dict[str, Any]:
        verification = self.verify()
        if verification["journal"]["status"] != "completed":
            raise TransactionError("transaction must complete before sealing the visible session")
        return self.runtime.seal(request_event_id=request_event_id, draft_event_id=draft_event_id)

    def export_live_session(self, output_path: str | Path) -> dict[str, Any]:
        verification = self.verify()
        if verification["journal"]["status"] != "completed":
            raise TransactionError("transaction must complete before live-session export")
        return self.runtime.export_live_session(output_path)


__all__ = ["GitHubTransactionOrchestrator"]
