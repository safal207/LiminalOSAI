#!/usr/bin/env python3
"""Offline, public-key-only checks of the bounded external STOP experiment.

This checker deliberately does not import the runtime's authority, checkpoint,
or verification helpers. It checks the supplied artifact and checked-out source;
it cannot establish that an inventory omitted no real-world effects. The declared
public pin and collector anchor are not independently enrolled trust roots.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import subprocess
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "liminal-external-stop-runtime-v1"
CASE_IDS = ("positive", "stop_restore", "terminal_restore", "pending_duplicate",
            "authority_restart", "authority_outage", "split_api_denied", "unsafe_local_restore")
CGQA_COMMIT = "38755bb5f056ea6f9a1c5a2b0c52401fb1d70021"
CGQA_SOURCE_SHA256 = "91debcca877d1ac9373fd1039d0d659947760068621b4c0737aaeb86a3a36e86"
SOURCE_REQUIRED = frozenset({"sdk/liminal_agent_control/receiver.py",
    "sdk/liminal_agent_control/brakes_store.py", "sdk/liminal_agent_control/external_authority.py",
    "sdk/liminal_agent_control/external_authority_service.py",
    "sdk/liminal_agent_control/external_checkpoint.py", "sdk/liminal_agent_control/external_stop_demo.py",
    "experiments/agent_control/preregistration_external_stop.json"})
RESPONSE_FIELDS = {"schema", "authority_id", "key_id", "operation", "request_digest",
                   "issued_at", "result", "signature"}
CHECKPOINT_BODY = {"schema", "authority_id", "signer_id", "key_id", "sequence",
    "previous_digest", "root_id", "epoch", "kind", "state_digest", "action_digest",
    "receipt_digest", "observed_at"}
ACTION_FIELDS = {"action_id", "attempt_id", "root_id", "execution_id", "epoch", "target", "arguments"}
STATE_FIELDS = {"root_id", "receiver_id", "policy_digest", "epoch", "state", "max_actions", "issued_count",
    "lifetime_seconds", "created_at", "expires_at", "stopped_at", "stop_reason", "pending_count",
    "committed_count", "denied_count", "clock_fault", "admission_closed"}


class EvidenceError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceError(reason)


def canonical(value: Any) -> bytes:
    def finite(item: Any, depth: int = 0) -> None:
        require(depth <= 32, "JSON nesting limit")
        if item is None or type(item) in (str, bool):
            return
        if type(item) is int:
            require(abs(item) < 2**63, "integer outside supported range")
            return
        if type(item) is float:
            require(math.isfinite(item), "non-finite JSON value")
            return
        if isinstance(item, list):
            for child in item:
                finite(child, depth + 1)
            return
        require(isinstance(item, dict) and all(isinstance(k, str) for k in item), "invalid JSON value")
        for child in item.values():
            finite(child, depth + 1)
    finite(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hexadecimal(value: Any, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def nonnegative(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _pin(pin: Any) -> Ed25519PublicKey:
    require(isinstance(pin, dict) and set(pin) == {"authority_id", "key_id", "public_key"}, "invalid public pin")
    require(all(isinstance(pin[k], str) and pin[k].strip() for k in ("authority_id", "key_id")), "invalid pin identity")
    require(hexadecimal(pin["public_key"]), "invalid Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin["public_key"]))


def verify_public_response(pair: Any, pin: dict[str, str]) -> dict[str, Any]:
    """The wire request HMAC is excluded from the public request commitment."""
    require(isinstance(pair, dict) and set(pair) == {"request", "response"}, "invalid authority evidence pair")
    request, response = pair["request"], pair["response"]
    require(isinstance(request, dict) and set(request) == {"schema", "role", "operation", "nonce", "payload"},
            "public request must contain exact body fields, without HMAC credentials")
    require(request["schema"] == "liminal-external-authority-request-v1" and hexadecimal(request["nonce"]), "invalid public request")
    require(request["role"] in {"admin", "receiver"} and isinstance(request["payload"], dict), "invalid request role/payload")
    operations = {"begin", "finish", "query"} if request["role"] == "receiver" else {
        "create_root", "bind_execution", "stop", "status", "checkpoints"}
    require(request["operation"] in operations, "operation outside request role")
    require(isinstance(response, dict) and set(response) == RESPONSE_FIELDS, "invalid response fields")
    require(response["schema"] == "liminal-external-authority-response-v1" and
            response["authority_id"] == pin["authority_id"] and response["key_id"] == pin["key_id"] and
            response["operation"] == request["operation"] and response["request_digest"] == sha(request),
            "authority response exact request/pin binding mismatch")
    require(nonnegative(response["issued_at"]) and isinstance(response["result"], dict), "invalid response data")
    require(hexadecimal(response["signature"], 128), "invalid response signature encoding")
    try:
        _pin(pin).verify(bytes.fromhex(response["signature"]),
            b"liminal-external-authority-response-v1\x00" + canonical({k: v for k, v in response.items() if k != "signature"}))
    except Exception as exc:
        raise EvidenceError("authority response signature invalid") from exc
    return response["result"]


def verify_public_chain(entries: Any, pin: dict[str, str], anchor: Any) -> dict[str, Any]:
    require(isinstance(entries, list) and entries, "checkpoint chain missing")
    key = _pin(pin)
    previous, observed, root_epochs = "0" * 64, -1.0, {}
    for seq, entry in enumerate(entries, 1):
        require(isinstance(entry, dict) and set(entry) == CHECKPOINT_BODY | {"signature", "checkpoint_digest"},
                "checkpoint fields invalid")
        require(entry["schema"] == "liminal-external-authority-checkpoint-v1" and
                entry["authority_id"] == pin["authority_id"] and entry["signer_id"] == pin["authority_id"] and
                entry["key_id"] == pin["key_id"], "checkpoint identity mismatch")
        require(type(entry["sequence"]) is int and entry["sequence"] == seq and entry["previous_digest"] == previous,
                "checkpoint chain continuity broken")
        require(type(entry["epoch"]) is int and entry["epoch"] >= max(1, root_epochs.get(entry["root_id"], 1)),
                "checkpoint epoch rollback")
        require(nonnegative(entry["observed_at"]) and entry["observed_at"] >= observed, "checkpoint time rollback")
        require(all(hexadecimal(entry[field]) for field in ("state_digest", "previous_digest", "checkpoint_digest")),
                "checkpoint digest invalid")
        require(all(entry[field] is None or hexadecimal(entry[field]) for field in ("action_digest", "receipt_digest")),
                "checkpoint optional digest invalid")
        require(hexadecimal(entry["signature"], 128), "checkpoint signature encoding invalid")
        signed = {k: v for k, v in entry.items() if k != "checkpoint_digest"}
        require(sha(signed) == entry["checkpoint_digest"], "checkpoint content digest mismatch")
        try:
            key.verify(bytes.fromhex(entry["signature"]), b"liminal-external-authority-checkpoint-v1\x00" +
                       canonical({k: entry[k] for k in CHECKPOINT_BODY}))
        except Exception as exc:
            raise EvidenceError("checkpoint signature invalid") from exc
        previous, observed = entry["checkpoint_digest"], entry["observed_at"]
        root_epochs[entry["root_id"]] = entry["epoch"]
    tip = {"schema": "liminal-external-authority-anchor-v1", **{field: entries[-1][field] for field in
            ("authority_id", "signer_id", "key_id", "sequence", "checkpoint_digest")}}
    require(isinstance(anchor, dict) and canonical(anchor) == canonical(tip), "checkpoint expected-tip anchor mismatch")
    return tip


def _action(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == ACTION_FIELDS and value["target"] == "records" and
            isinstance(value["arguments"], dict) and type(value["epoch"]) is int and value["epoch"] >= 1,
            "invalid bounded record action")
    require(all(isinstance(value[k], str) and value[k].strip() for k in
                ("action_id", "attempt_id", "root_id", "execution_id")), "invalid action identities")
    return value


def _receipt(receipt: Any, action: dict[str, Any], status: str, profile: str = "external_governed_v1") -> None:
    require(isinstance(receipt, dict) and receipt.get("schema") == "liminal.agent-control.receipt.v1" and
            receipt.get("status") == status and receipt.get("enforcement_profile") == profile,
            "receiver receipt status/profile mismatch")
    require(receipt.get("action_digest") == sha(action) and all(type(receipt.get(k)) is type(action[k]) and
            receipt.get(k) == action[k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")),
            "receiver receipt action binding mismatch")
    if status == "UNKNOWN":
        require(receipt.get("effect_count") is None, "unknown outcome was asserted as a definitive effect count")
    else:
        require(type(receipt.get("effect_count")) is int and receipt["effect_count"] == (1 if status == "COMMITTED" else 0),
                "receiver receipt effect count mismatch")


def _records(value: Any, expected: int, action: dict[str, Any] | None = None, profile: str = "external_governed_v1") -> None:
    require(isinstance(value, list) and len(value) == expected, "actual record inventory count mismatch")
    seen = set()
    for record in value:
        require(isinstance(record, dict) and set(record) == {"action", "arguments", "receipt"}, "record inventory fields invalid")
        actual = _action(record["action"])
        require(actual["action_id"] not in seen, "duplicate actual record action")
        seen.add(actual["action_id"])
        require(record["arguments"] == actual["arguments"], "actual record arguments mismatch")
        _receipt(record["receipt"], actual, "COMMITTED", profile)
        if action is not None:
            require(canonical(actual) == canonical(action), "actual inventory does not match expected action")


def _sources(report: dict[str, Any], repo_root: Path, expected_sha: str | None) -> int:
    source, files = report.get("source"), report.get("source_files_sha256")
    require(isinstance(source, dict) and hexadecimal(source.get("commit"), 40) and hexadecimal(source.get("tree"), 40)
            and type(source.get("dirty")) is bool, "source identity invalid")
    if expected_sha is not None:
        require(hexadecimal(expected_sha, 40) and source["commit"] == expected_sha and source["dirty"] is False,
                "expected clean source commit mismatch")
        result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD", "HEAD^{tree}"],
                                capture_output=True, text=True, check=True, timeout=10)
        require(result.stdout.splitlines() == [expected_sha, source["tree"]], "checked-out source identity mismatch")
    require(isinstance(files, dict) and SOURCE_REQUIRED <= set(files), "required source digest inventory missing")
    current = {str(path.relative_to(repo_root)) for folder in ("sdk", "adapters")
               for path in (repo_root / folder).rglob("*.py")}
    require(current <= set(files), "source digest inventory omits transitive Python inputs")
    for name, expected in files.items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and hexadecimal(expected), "unsafe source digest entry")
        actual = repo_root / path
        require(actual.is_file() and actual.resolve().is_relative_to(repo_root.resolve()), "source digest input missing/unsafe")
        require(hashlib.sha256(actual.read_bytes()).hexdigest() == expected, "source file digest mismatch: " + name)
    return len(files)


def _oracle_scenarios(entries: list[dict[str, Any]], actions: dict[str, dict[str, Any]],
                      receipts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Only signed permit/checkpoint events create an acceptance-capable path.

    The dispatch marker means a one-shot permit was issued, not that the local
    receiver actually committed. Signed FINISH binds a terminal receipt; an
    unfinished permit is explicitly ambiguous and remains unresolved.
    """
    scenarios = []
    for name in CASE_IDS[:-1]:
        root = "runtime:" + name
        events, begun, finished = [], set(), set()
        def add(kind: str, action_hash: str, **extra: Any) -> None:
            events.append({"seq": len(events) + 1, "type": kind, "logicalOperationId": action_hash,
                "trajectoryId": root, "segmentId": root + ":receiver", **extra})
        for entry in entries:
            if entry["root_id"] != root:
                continue
            action_hash = entry["action_digest"]
            if entry["kind"] == "BEGIN_PENDING":
                require(action_hash in actions and action_hash not in begun, "duplicate/missing permit operation")
                action = actions[action_hash]
                add("authorize", action_hash, evidenceRef=entry["checkpoint_digest"])
                add("dispatch", action_hash, executionId=action["attempt_id"], agentId=action["execution_id"],
                    evidenceRef=entry["checkpoint_digest"])
                begun.add(action_hash)
            elif entry["kind"] in {"FINISH_COMMITTED", "FINISH_DENIED"}:
                require(action_hash in begun and action_hash not in finished and entry["receipt_digest"] in receipts,
                        "terminal checkpoint lacks preceding unique permit/receipt")
                action, receipt = actions[action_hash], receipts[entry["receipt_digest"]]
                status = entry["kind"].removeprefix("FINISH_")
                _receipt(receipt, action, status)
                outcome = "committed" if status == "COMMITTED" else "no_effect"
                evidence = {"evidenceKind": "ed25519_authority_authenticated_receiver_receipt",
                            "evidenceRef": entry["checkpoint_digest"] + ":" + entry["receipt_digest"]}
                add("reconcile", action_hash, executionId=action["attempt_id"], outcome=outcome,
                    retryAuthorized=False, **evidence)
                add("terminal", action_hash, outcome=outcome, **evidence)
                finished.add(action_hash)
        for action_hash in sorted(begun - finished):
            action = actions[action_hash]
            add("ambiguous", action_hash, executionId=action["attempt_id"])
        if not events:
            # Denied requests are not converted into side-effect executions.
            add("stop", root + ":no-issued-permit")
        scenarios.append({"schema": "cgqa.proof-carrying-agent-trajectory-scenario.v0.1",
            "benchmark": "proof-carrying-agent-trajectories-v0.1", "scenarioId": "external-stop:" + name,
            "trajectoryId": root, "policy": {"name": "external-stop-public-evidence",
                "requirePredecessorProof": True, "requireTerminalEvidence": True}, "events": events})
    return scenarios


def _run_oracle(root: Path, scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    path = root / "contractgraph_qa/agent_trajectory.py"
    require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == CGQA_SOURCE_SHA256,
            "ContractGraph-QA oracle source differs from pinned commit")
    spec = importlib.util.spec_from_file_location("_external_stop_pinned_cgqa_oracle", path)
    require(spec is not None and spec.loader is not None, "oracle import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    results = [module.evaluate_agent_trajectory_scenario(scenario) for scenario in scenarios]
    require(all(result["status"] == "pass" and not result["criticalFailure"] for result in results), "ContractGraph-QA oracle rejected derived trace")
    require(all(result["authority"]["productionAuthorization"] is False and
                result["authority"]["securityCertification"] is False for result in results), "oracle result improperly authorizing")
    return {"status": "PASS", "pinned_commit": CGQA_COMMIT, "source_sha256": CGQA_SOURCE_SHA256,
            "execution_authorized": False, "results": results,
            "adapter_scope": "Signed one-shot permit issuance and receipt-settlement trajectory only; no complete runtime trace claim."}


def verify_report(report: Any, *, repo_root: Path = ROOT, expected_source_sha: str | None = None,
                  contractgraph_root: Path | None = None, expected_authority_pin: dict[str, str] | None = None,
                  trusted_latest_anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    require(isinstance(report, dict) and report.get("schema") == SCHEMA, "runtime evidence schema mismatch")
    canonical(report)
    count = _sources(report, repo_root, expected_source_sha)
    require(report.get("passed") is True and isinstance(report.get("checks"), dict) and report["checks"] and
            all(value is True for value in report["checks"].values()), "runtime declared checks incomplete/failed")
    cases = report.get("outcomes")
    require(isinstance(cases, dict) and set(cases) == set(CASE_IDS), "missing/extra experiment case")
    design = report.get("preregistration")
    require(isinstance(design, dict) and design.get("experiment_id") == SCHEMA and design.get("scenario_ids") == list(CASE_IDS)
            and design.get("model_calls_budget") == 0 and design.get("live_internet") is False, "preregistered experiment mismatch")
    pin = report.get("authority_public_pin")
    _pin(pin)
    if expected_authority_pin is not None:
        _pin(expected_authority_pin)
        require(canonical(pin) == canonical(expected_authority_pin), "caller-supplied authority pin mismatch")
    pairs = report.get("authority_evidence")
    require(isinstance(pairs, list) and pairs, "public exact-request authority evidence missing")
    results, nonces, receipts = [], set(), {}
    for pair in pairs:
        result = verify_public_response(pair, pin)
        require(pair["request"]["nonce"] not in nonces, "duplicate public request nonce/evidence")
        nonces.add(pair["request"]["nonce"])
        results.append((pair["request"], result))
        receipt = result.get("receipt")
        if isinstance(receipt, dict):
            receipts[sha(receipt)] = receipt
    entries = report.get("authority_checkpoints")
    anchor = report.get("checkpoint_anchor")
    tip = verify_public_chain(entries, pin, anchor)
    if trusted_latest_anchor is not None:
        require(canonical(trusted_latest_anchor) == canonical(tip), "caller-supplied latest anchor mismatch")
    require(any(request["operation"] == "checkpoints" and result.get("status") == "CHECKPOINTS" and
                canonical(result.get("entries")) == canonical(entries) for request, result in results),
            "checkpoint export lacks matching authenticated authority response")
    actions = {}
    public_pairs = {canonical(pair) for pair in pairs}
    for name, case in cases.items():
        require(isinstance(case, dict), "invalid case record")
        require(case.get("authority_pin") == pin and case.get("checkpoint_anchor") == anchor and
                canonical(case.get("checkpoint_entries")) == canonical(entries), "case public pin/checkpoint export mismatch")
        require(isinstance(case.get("authority_evidence"), list) and all(canonical(pair) in public_pairs
                for pair in case["authority_evidence"]), "case authority evidence does not belong to public export")
        for field in ("action", "fresh_action"):
            if field in case:
                action = _action(case[field])
                require(action["root_id"] == "runtime:" + name, "case action root mismatch")
                actions[sha(action)] = action
        for field, action_field in (("grant", "action"), ("fresh_grant", "fresh_action")):
            if field in case:
                grant, action = case[field], case[action_field]
                require(isinstance(grant, dict) and set(grant) == {"action_digest", "policy_version", "expires_at", "receiver_id"}
                        and grant["action_digest"] == sha(action) and nonnegative(grant["expires_at"]), "case grant binding invalid")
        for field in ("receipt", "retry_receipt", "committed_receipt", "fresh_receipt"):
            if field in case:
                receipt = case[field]
                grant = case["fresh_grant" if field == "fresh_receipt" else "grant"]
                require(isinstance(receipt, dict) and receipt.get("receiver_id") == grant["receiver_id"],
                        "case receipt receiver differs from exact grant")
                if name != "unsafe_local_restore" and receipt.get("status") == "COMMITTED":
                    require(sha(receipt) in receipts, "case committed receipt lacks exact signed external proof")
    for entry in entries:
        if entry["kind"] in {"BEGIN_PENDING", "BEGIN_DENIED", "FINISH_COMMITTED", "FINISH_DENIED"}:
            require(entry["action_digest"] in actions, "checkpoint action lacks actual case input")
        if entry["kind"].startswith("FINISH_"):
            require(entry["receipt_digest"] in receipts, "checkpoint terminal receipt lacks public authenticated evidence")
    def state(name: str, field: str = "external_state") -> dict[str, Any]:
        supplied = cases[name].get(field)
        matches = [pair for pair in pairs if canonical(pair["response"]["result"]) == canonical(supplied) and
                   pair["request"]["payload"].get("root_id") == "runtime:" + name]
        require(isinstance(supplied, dict) and matches,
                "case external state lacks exact public signed response")
        require(set(supplied) in (STATE_FIELDS | {"status"}, STATE_FIELDS | {"status", "deadline_reached"}),
                "signed state contains undeclared persisted/derived fields")
        persisted = {k: supplied[k] for k in STATE_FIELDS}
        require(type(persisted["clock_fault"]) is bool and type(persisted["admission_closed"]) is bool,
                "signed state boolean invalid")
        persisted["admission_closed"] = supplied["state"] != "ACTIVE" or supplied["clock_fault"]
        if "deadline_reached" in supplied:
            deadline = supplied["deadline_reached"]
            require(deadline is None or type(deadline) is bool, "signed derived deadline field invalid")
            require(deadline is False or supplied["admission_closed"] is True,
                    "signed deadline/fault did not close admission")
            if deadline is True:
                require(any(pair["response"]["issued_at"] >= supplied["expires_at"] for pair in matches),
                        "signed deadline contradicts authority response time")
        else:
            require(supplied["admission_closed"] == persisted["admission_closed"], "signed persisted admission mismatch")
        require(any(entry["root_id"] == "runtime:" + name and entry["state_digest"] ==
                sha(persisted) for entry in entries),
                "signed state does not match a signed checkpoint state digest")
        return supplied
    def inventory(name: str, expected: int, field: str = "records", action_field: str = "action") -> None:
        _records(cases[name].get(field), expected, cases[name].get(action_field) if expected else None)
        for record in cases[name][field]:
            require(sha(record["receipt"]) in receipts, "actual inventory receipt lacks exact signed external proof")
    inventory("positive", 1)
    _receipt(cases["positive"].get("receipt"), cases["positive"]["action"], "COMMITTED")
    s = state("positive")
    require(s.get("committed_count") == 1 and s.get("pending_count") == 0, "positive external settlement missing")
    for name in ("stop_restore", "authority_restart"):
        inventory(name, 0)
        _receipt(cases[name].get("receipt"), cases[name]["action"], "DENIED")
        stopped, current = state(name, "stop_response"), state(name)
        require(stopped.get("status") == "STOPPED" and stopped.get("state") == "STOPPED" and
                stopped.get("pending_count") == 0 and stopped.get("admission_closed") is True and
                type(stopped.get("epoch")) is int and stopped["epoch"] > 1 and
                current.get("state") == "STOPPED" and current.get("epoch") == stopped["epoch"], "external STOP did not survive")
    restored = cases["stop_restore"].get("restored_local_state", {})
    require(restored.get("state") == "ACTIVE" and restored.get("epoch") == 1, "local STOP rollback not demonstrated")
    for name in ("stop_restore", "terminal_restore"):
        for field in ("snapshot", "restore"):
            item = cases[name].get(field, {})
            require(item.get("method") == "sqlite3.Connection.backup" and item.get("receiver_stopped_during_copy") is True
                    and item.get("receiver_identity_preserved") is True, "coherent pinned receiver rollback evidence missing")
        require(cases[name]["restore"].get("controller_database_not_restored") is True, "external store rollback exclusion missing")
    inventory("terminal_restore", 1, "records_before_restore")
    inventory("terminal_restore", 0, "records_before_retry")
    inventory("terminal_restore", 0)
    _receipt(cases["terminal_restore"].get("committed_receipt"), cases["terminal_restore"]["action"], "COMMITTED")
    _receipt(cases["terminal_restore"].get("retry_receipt"), cases["terminal_restore"]["action"], "UNKNOWN")
    s = state("terminal_restore")
    require(s.get("state") == "ACTIVE" and s.get("committed_count") == 1 and s.get("pending_count") == 0,
            "surviving terminal consumption missing")
    inventory("pending_duplicate", 0)
    _receipt(cases["pending_duplicate"].get("retry_receipt"), cases["pending_duplicate"]["action"], "UNKNOWN")
    permit = cases["pending_duplicate"].get("issued_permit")
    require(isinstance(permit, dict) and permit.get("status") == "PERMITTED" and any(request["operation"] == "begin" and
            canonical(result) == canonical(permit) for request, result in results), "actual unresolved permit missing")
    s = state("pending_duplicate", "stop_response")
    require(s.get("status") == "STOP_PENDING" and s.get("state") in {"STOPPING", "STOP_PENDING"} and
            s.get("pending_count") == 1 and s.get("admission_closed") is True, "unresolved permit falsely quiescent")
    inventory("authority_outage", 0, "records_during_outage")
    _receipt(cases["authority_outage"].get("receipt"), cases["authority_outage"]["action"], "UNKNOWN")
    inventory("authority_outage", 1, action_field="fresh_action")
    _receipt(cases["authority_outage"].get("fresh_receipt"), cases["authority_outage"]["fresh_action"], "COMMITTED")
    s = state("authority_outage")
    require(s.get("issued_count") == 1 and s.get("committed_count") == 1, "outage recovery positive control missing")
    inventory("split_api_denied", 0)
    attempts = cases["split_api_denied"].get("attempts")
    require(isinstance(attempts, dict) and set(attempts) == {"accept", "finalize"} and all(
            item.get("status") == "REJECTED" for item in attempts.values()), "split APIs were not denied")
    unsafe = cases["unsafe_local_restore"]
    require(unsafe.get("variant") == "explicit_local_only_unsafe_control", "unsafe baseline label missing")
    _records(unsafe.get("records"), 1, unsafe["action"], "governed_v1")
    _receipt(unsafe.get("receipt"), unsafe["action"], "COMMITTED", "governed_v1")
    for name, expected in {"positive": 1, "stop_restore": 0, "terminal_restore": 0, "pending_duplicate": 0,
                           "authority_restart": 0, "authority_outage": 1, "split_api_denied": 0, "unsafe_local_restore": 1}.items():
        require(type(cases[name].get("accepted_count")) is int and cases[name]["accepted_count"] == expected,
                "actual acceptance inventory mismatch: " + name)
        require(type(cases[name].get("effect_count")) is int and cases[name]["effect_count"] == expected,
                "actual effect inventory mismatch: " + name)
    require(type(cases["authority_outage"].get("outage_accepted_count")) is int and
            cases["authority_outage"]["outage_accepted_count"] == 0 and
            type(cases["authority_outage"].get("outage_effect_count")) is int and
            cases["authority_outage"]["outage_effect_count"] == 0, "outage acceptance/effect inventory missing")
    processes, cleanup = report.get("processes"), report.get("cleanup")
    require(isinstance(processes, list) and processes and isinstance(cleanup, list) and cleanup, "process lifecycle evidence missing")
    pids = {item.get("pid") for item in processes}
    require(all(type(pid) is int and pid > 0 and pid != report.get("controller_pid") for pid in pids), "process separation missing")
    require(pids == {item.get("pid") for item in cleanup} and all(item.get("reaped") is True for item in cleanup), "child process not reaped")
    authority_processes = [item for item in processes if item.get("role") == "external_authority"]
    require(len(authority_processes) >= 3 and authority_processes[0].get("explicit_initialization") is True and
            all(item.get("explicit_initialization") is False for item in authority_processes[1:]) and
            all(item.get("startup", {}).get("pin") == pin for item in authority_processes), "authority restart identity/init evidence missing")
    require({item["pid"] for item in authority_processes}.isdisjoint({item["pid"] for item in processes
            if item.get("role") in {"receiver", "unsafe_local_baseline"}}), "authority and receiver share process identity")
    scope = report.get("scope")
    require(isinstance(scope, dict) and all(scope.get(field) is True for field in
            ("actual_loopback_http", "distinct_authority_receiver_processes", "separate_authority_database", "actual_synthetic_sqlite_effects"))
            and scope.get("private_keys_bundled") is False and scope.get("receiver_receipts_publicly_verifiable") is False
            and type(scope.get("model_calls")) is int and scope["model_calls"] == 0 and
            scope.get("independent_latest_anchor") == "NOT_ESTABLISHED" and scope.get("rust_liminaldb_runtime") == "NOT_RUN",
            "artifact scope overstates evidence or bundles private keys")
    scenarios = _oracle_scenarios(entries, actions, receipts)
    pending = next(scenario for scenario in scenarios if scenario["scenarioId"].endswith(":pending_duplicate"))
    require(any(event["type"] == "ambiguous" for event in pending["events"]) and
            not any(event["type"] == "terminal" for event in pending["events"]), "pending oracle trace fabricated a terminal")
    oracle = _run_oracle(contractgraph_root, scenarios) if contractgraph_root is not None else {
        "status": "NOT_RUN", "execution_authorized": False, "derived_scenarios": scenarios}
    return {"schema": "liminal-external-stop-offline-verification-v1", "status": "PASS",
        "source": report["source"], "source_files_verified": count, "cases_verified": list(CASE_IDS),
        "authority_response_signatures_verified": len(pairs), "checkpoint_signatures_verified": len(entries),
        "checkpoint_tip": tip, "pin_scope": "caller_supplied" if expected_authority_pin is not None else "report_fixture",
        "checkpoint_verification_status": "EXTERNAL_ANCHORED_VERIFIED" if trusted_latest_anchor is not None else "LOCAL_SIGNATURE_ONLY",
        "execution_authorized": False, "contractgraph_qa": oracle,
        "limits": ["Artifact contents and checked-out input hashes only; runtime completeness is not established.",
            "Public pin and latest anchor are supplied by the collector, not independently enrolled.",
            "Receiver receipt HMACs are not publicly verified; signed external receipt bindings are verified.",
            "No native Rust LiminalDB runtime, live model, or production safety certification."]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-report-sha256", help="Expected SHA-256 of the exact report file bytes, obtained independently.")
    parser.add_argument("--authority-pin-file", type=Path, help="Caller-owned Ed25519 authority pin, obtained independently of the report.")
    parser.add_argument("--trusted-latest-anchor-file", type=Path, help="Caller-owned latest checkpoint anchor; never obtain this from the same export to claim freshness.")
    parser.add_argument("--contractgraph-root", type=Path)
    args = parser.parse_args(argv)
    try:
        def unique_object(items):
            value = {}
            for key, item in items:
                require(key not in value, "duplicate JSON object key")
                value[key] = item
            return value
        raw = args.report.read_bytes()
        if args.expected_report_sha256 is not None:
            require(hexadecimal(args.expected_report_sha256) and hashlib.sha256(raw).hexdigest() == args.expected_report_sha256,
                    "exact report SHA-256 mismatch")
        report = json.loads(raw, object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError("non-finite JSON")))
        pin = json.loads(args.authority_pin_file.read_text(), object_pairs_hook=unique_object) if args.authority_pin_file else None
        anchor = json.loads(args.trusted_latest_anchor_file.read_text(), object_pairs_hook=unique_object) if args.trusted_latest_anchor_file else None
        result = verify_report(report, expected_source_sha=args.expected_source_sha, contractgraph_root=args.contractgraph_root,
                               expected_authority_pin=pin, trusted_latest_anchor=anchor)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "FAIL", "execution_authorized": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
