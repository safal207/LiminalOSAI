#!/usr/bin/env python3
"""Independently verify a bounded owned-network STOP artifact offline.

Only generic public Ed25519 and canonical-JSON helpers are reused from the
independent records checker. Runtime, gateway, endpoint, protocol and authority
decision helpers are deliberately not imported. Fixture signatures authenticate
supplied observations; they do not establish complete mediation or freshness of
an independently owned latest checkpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_network_generic_crypto", ROOT / "scripts/verify_external_stop_evidence.py")
assert _SPEC is not None and _SPEC.loader is not None
_CRYPTO = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CRYPTO)
EvidenceError = _CRYPTO.EvidenceError
canonical, sha = _CRYPTO.canonical, _CRYPTO.sha
require, hexadecimal = _CRYPTO.require, _CRYPTO.hexadecimal
verify_public_response, verify_public_chain = _CRYPTO.verify_public_response, _CRYPTO.verify_public_chain

SCHEMA = "liminal-external-network-runtime-v1"
PROFILE = "owned-loopback-network-v1"
CASE_IDS = ("network_positive", "network_binding_swap", "network_stop_before_dispatch",
    "network_pending_dispatch_stop", "network_lost_begin_response", "network_lost_transport_response",
    "network_lost_finish_response", "network_restore_consumed_state", "network_restore_stopped_state",
    "network_authority_restart_outage", "network_ambiguous_endpoint", "network_cross_profile_receipt")
ACTION_FIELDS = {"action_id", "attempt_id", "root_id", "execution_id", "epoch", "target", "arguments"}
GRANT_FIELDS = {"action_digest", "policy_version", "expires_at", "receiver_id"}
RECEIPT_FIELDS = {"schema", "endpoint_id", "key_id", "reservation_id", "action_id", "attempt_id",
    "root_id", "execution_id", "epoch", "action_digest", "authorization_digest", "body_digest",
    "committed_at", "status", "effect_count", "signature"}
RECEIPT_DOMAIN = b"liminal-external-network-receipt-v1\x00"
GATEWAY_RESULT_FIELDS = {"status", "reason", "action_id", "reservation_id", "effect_count", "remote_outcome", "receipt",
    "dispatch_finished", "settlement_status", "execution_authorized"}
STATE_FIELDS = {"root_id", "receiver_id", "policy_digest", "epoch", "state", "max_actions", "issued_count",
    "lifetime_seconds", "created_at", "expires_at", "stopped_at", "stop_reason", "pending_count",
    "committed_count", "denied_count", "clock_fault", "admission_closed"}
SOURCE_REQUIRED = frozenset({"scripts/verify_external_stop_evidence.py",
    "scripts/verify_external_network_evidence.py", "tests/test_agent_control_external_network_evidence.py",
    "tests/test_agent_control_external_network_runtime.py",
    "tests/test_agent_control_external_network_authority.py", "tests/test_agent_control_external_network_endpoint.py",
    "tests/test_agent_control_external_network_gateway.py",
    "experiments/agent_control/preregistration_external_network.json", "docs/AGENT_CONTROL_EXTERNAL_NETWORK.md",
    "README.md", ".github/workflows/agent-control.yml",
    "sdk/liminal_agent_control/external_network_demo.py", "sdk/liminal_agent_control/external_network_protocol.py",
    "sdk/liminal_agent_control/external_network_authority.py", "sdk/liminal_agent_control/external_authority.py",
    "sdk/liminal_agent_control/external_authority_service.py", "sdk/liminal_agent_control/external_checkpoint.py"})
MAX_REPORT_BYTES = 16 * 1024 * 1024


def _id(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9_.:/-]+", value) is not None


def _number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _integer(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def _bounded(value: Any, depth: int = 0) -> None:
    require(depth <= 32, "report nesting limit")
    if isinstance(value, dict):
        require(len(value) <= 2048, "report object limit")
        for key, item in value.items():
            require(type(key) is str and len(key) <= 256, "report key limit")
            require(key.lower() not in {"private_key", "private_key_bytes", "operator_key", "receiver_key",
                "request_key", "request_hmac", "request_hmac_key", "worker_key", "endpoint_request_key",
                "receipt_key", "signing_key", "authorization_header"}, "private credential bundled")
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        require(len(value) <= 4096, "report list limit")
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, str):
        require(len(value) <= 65536, "report string limit")


def _endpoint_pin(pin: Any) -> Ed25519PublicKey:
    require(type(pin) is dict and set(pin) == {"endpoint_id", "key_id", "public_key"}
        and _id(pin["endpoint_id"]) and _id(pin["key_id"]) and hexadecimal(pin["public_key"]),
        "invalid endpoint public pin")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin["public_key"]))


def _action(action: Any) -> dict[str, Any]:
    require(type(action) is dict and set(action) == ACTION_FIELDS and action["target"] == "network"
        and _integer(action["epoch"], 1) and all(_id(action[k]) for k in
        ("action_id", "attempt_id", "root_id", "execution_id")), "invalid exact network action")
    args = action["arguments"]
    require(type(args) is dict and set(args) == {"method", "url", "body"} and args["method"] == "POST",
        "invalid bounded network request")
    url = args["url"]
    require(type(url) is str and len(url) <= 150, "invalid owned endpoint URL")
    try:
        parsed = urlparse(url)
        require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None
            and 1 <= parsed.port <= 65535 and parsed.username is None and parsed.password is None
            and parsed.path == "/v1/record" and not parsed.query and not parsed.fragment
            and url == "http://127.0.0.1:" + str(parsed.port) + "/v1/record", "invalid owned endpoint URL")
    except ValueError as exc:
        raise EvidenceError("invalid owned endpoint URL") from exc
    require(type(args["body"]) is dict and set(args["body"]) == {"synthetic_marker"}
        and _id(args["body"]["synthetic_marker"]), "synthetic marker body invalid")
    require(len(canonical(action)) <= 16384, "network action packet limit")
    return action


def _grant(grant: Any, action: dict[str, Any], pin: dict[str, str]) -> dict[str, Any]:
    require(type(grant) is dict and set(grant) == GRANT_FIELDS and grant["action_digest"] == sha(action)
        and hexadecimal(grant["policy_version"]) and _number(grant["expires_at"])
        and grant["receiver_id"] == pin["endpoint_id"], "network grant binding invalid")
    return grant


def _receipt(receipt: Any, pin: dict[str, str], action: dict[str, Any] | None = None,
             grant: dict[str, Any] | None = None, reservation_id: str | None = None) -> dict[str, Any]:
    require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS
        and receipt["schema"] == "liminal.external-network.receipt.v1" and receipt["status"] == "COMMITTED"
        and type(receipt["effect_count"]) is int and receipt["effect_count"] == 1,
        "endpoint terminal receipt fields/status invalid")
    require(receipt["endpoint_id"] == pin["endpoint_id"] and receipt["key_id"] == pin["key_id"]
        and all(_id(receipt[k]) for k in ("reservation_id", "action_id", "attempt_id", "root_id", "execution_id"))
        and _integer(receipt["epoch"], 1) and _number(receipt["committed_at"])
        and all(hexadecimal(receipt[k]) for k in ("action_digest", "authorization_digest", "body_digest"))
        and hexadecimal(receipt["signature"], 128), "endpoint terminal receipt identity invalid")
    try:
        _endpoint_pin(pin).verify(bytes.fromhex(receipt["signature"]), RECEIPT_DOMAIN +
            canonical({k: v for k, v in receipt.items() if k != "signature"}))
    except Exception as exc:
        raise EvidenceError("endpoint receipt signature invalid") from exc
    if action is not None:
        require(receipt["action_digest"] == sha(action) and receipt["body_digest"] == sha(action["arguments"]["body"])
            and all(type(receipt[k]) is type(action[k]) and receipt[k] == action[k] for k in
            ("action_id", "attempt_id", "root_id", "execution_id", "epoch")), "endpoint receipt exact action/body binding mismatch")
    if grant is not None:
        require(receipt["authorization_digest"] == sha(grant), "endpoint receipt authorization binding mismatch")
    if reservation_id is not None:
        require(receipt["reservation_id"] == reservation_id, "endpoint receipt reservation binding mismatch")
    return receipt


def _sources(report: dict[str, Any], repo_root: Path, expected_sha: str | None) -> int:
    source, files = report.get("source"), report.get("source_files_sha256")
    require(type(source) is dict and set(source) in ({"commit", "tree", "dirty"}, {"commit", "tree", "dirty", "scope"})
        and hexadecimal(source["commit"], 40) and hexadecimal(source["tree"], 40)
        and type(source["dirty"]) is bool, "source identity invalid")
    if expected_sha is not None:
        require(hexadecimal(expected_sha, 40) and source["commit"] == expected_sha and source["dirty"] is False,
            "expected clean source commit mismatch")
        identity = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD", "HEAD^{tree}"],
            capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
        status = subprocess.run(["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True, text=True, check=True, timeout=10).stdout
        require(identity == [expected_sha, source["tree"]] and not status, "checked-out clean source identity mismatch")
    require(type(files) is dict and SOURCE_REQUIRED <= set(files), "required source digest inventory missing")
    current = {str(path.relative_to(repo_root)) for folder in ("sdk", "adapters")
        for path in (repo_root / folder).rglob("*.py")}
    require(current <= set(files), "source digest inventory omits transitive Python inputs")
    for name, expected in files.items():
        path = Path(name)
        require(len(name) <= 256 and not path.is_absolute() and ".." not in path.parts
            and hexadecimal(expected), "unsafe source digest entry")
        actual = repo_root / path
        require(actual.is_file() and actual.resolve().is_relative_to(repo_root.resolve()), "source digest input missing/unsafe")
        require(hashlib.sha256(actual.read_bytes()).hexdigest() == expected, "source file digest mismatch: " + name)
    return len(files)


def _permit(pair: Any, authority_pin: dict[str, str], endpoint_pin: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    result = verify_public_response(pair, authority_pin)
    request = pair["request"]
    require(request["operation"] == "begin" and request["role"] == "receiver"
        and set(request["payload"]) == {"action", "authorization"}, "network permit request role/payload invalid")
    action = _action(request["payload"]["action"])
    grant = _grant(request["payload"]["authorization"], action, endpoint_pin)
    require(result.get("status") == "PERMITTED" and result.get("outcome") is None and result.get("receipt") is None
        and result.get("action_digest") == sha(action) and result.get("receiver_id") == endpoint_pin["endpoint_id"]
        and _id(result.get("reservation_id")) and all(type(result.get(k)) is type(action[k])
        and result[k] == action[k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")),
        "network issued permit exact binding invalid")
    require(pair["response"]["issued_at"] < grant["expires_at"], "issued permit after grant expiry")
    return action, grant, result


def verify_endpoint_pair(pair: Any, endpoint_pin: dict[str, str], authority_pin: dict[str, str]) -> dict[str, Any]:
    require(type(pair) is dict and set(pair) == {"request", "response"}, "endpoint public pair fields invalid")
    request, response = pair["request"], pair["response"]
    require(type(request) is dict and set(request) == {"schema", "role", "operation", "nonce", "payload"}
        and request["schema"] == "liminal-external-network-request-v1" and request["role"] == "gateway"
        and request["operation"] in {"commit", "query"} and hexadecimal(request["nonce"])
        and type(request["payload"]) is dict, "endpoint public request fields/role invalid or HMAC bundled")
    require(type(response) is dict and set(response) == {"schema", "endpoint_id", "key_id", "operation", "request_digest", "result", "signature"}
        and response["schema"] == "liminal-external-network-response-v1"
        and response["endpoint_id"] == endpoint_pin["endpoint_id"] and response["key_id"] == endpoint_pin["key_id"]
        and response["operation"] == request["operation"] and response["request_digest"] == sha(request)
        and hexadecimal(response["signature"], 128) and type(response["result"]) is dict,
        "endpoint response exact request/pin binding mismatch")
    require(len(canonical(request)) <= 65536 and len(canonical(response)) <= 65536, "endpoint public packet limit")
    try:
        _endpoint_pin(endpoint_pin).verify(bytes.fromhex(response["signature"]),
            b"liminal-external-network-response-v1\x00" + canonical({k: v for k, v in response.items() if k != "signature"}))
    except Exception as exc:
        raise EvidenceError("endpoint response signature invalid") from exc
    payload, result = request["payload"], response["result"]
    if request["operation"] == "commit":
        require(set(payload) == {"action", "authorization", "permit_request", "permit"}, "endpoint commit payload invalid")
        action, grant, permit = _permit({"request": payload["permit_request"], "response": payload["permit"]}, authority_pin, endpoint_pin)
        require(canonical(payload["action"]) == canonical(action) and canonical(payload["authorization"]) == canonical(grant),
            "endpoint commit differs from issued exact action/grant")
        action_id, reservation_id = action["action_id"], permit["reservation_id"]
    else:
        require(set(payload) == {"action_id", "reservation_id"} and all(_id(payload[k]) for k in payload), "endpoint query payload invalid")
        action, grant = None, None
        action_id, reservation_id = payload["action_id"], payload["reservation_id"]
    require(set(result) == {"status", "action_id", "reservation_id", "effect_count", "receipt"}
        and result["action_id"] == action_id and result["reservation_id"] == reservation_id,
        "endpoint result exact request binding mismatch")
    if result["status"] == "OBSERVED":
        require(type(result["effect_count"]) is int and result["effect_count"] == 1, "observed endpoint effect count invalid")
        receipt = _receipt(result["receipt"], endpoint_pin, action, grant, reservation_id)
        require(receipt["action_id"] == action_id, "endpoint query receipt action mismatch")
    else:
        require(result["status"] == "UNKNOWN" and request["operation"] == "query"
            and result["effect_count"] is None and result["receipt"] is None,
            "unknown endpoint outcome asserted negative/terminal effect")
    return result


def _inventory(value: Any, endpoint_pin: dict[str, str], authority_pin: dict[str, str],
               permits: dict[str, dict[str, Any]]) -> None:
    fields = {"endpoint_id", "pin", "url", "commit_request_count", "query_request_count", "effects", "receipts", "requests",
        "independent_sqlite_effect_count", "independent_sqlite_action_ids", "independent_sqlite_request_counts", "observation"}
    require(type(value) is dict and set(value) == fields and value["endpoint_id"] == endpoint_pin["endpoint_id"]
        and value["pin"] == endpoint_pin and _integer(value["commit_request_count"])
        and _integer(value["query_request_count"]), "actual endpoint inventory fields/counts invalid")
    require(value["independent_sqlite_request_counts"] == {"commit_request_count": value["commit_request_count"],
        "query_request_count": value["query_request_count"]}, "independent SQLite request counter mismatch")
    require(type(value["effects"]) is list and type(value["receipts"]) is list and type(value["requests"]) is list
        and len(value["effects"]) == len(value["receipts"]) == len(value["requests"]) <= 1024
        and _integer(value["independent_sqlite_effect_count"]) and value["independent_sqlite_effect_count"] == len(value["effects"])
        and value["commit_request_count"] >= len(value["effects"]), "actual SQLite effect inventory count mismatch")
    ids, attempts, reservations = set(), set(), set()
    for seq, (effect, receipt, request) in enumerate(zip(value["effects"], value["receipts"], value["requests"]), 1):
        require(type(request) is dict and set(request) == {"action_id", "permit_request", "permit", "permit_digest"}, "actual request inventory fields invalid")
        pair = {"request": request["permit_request"], "response": request["permit"]}
        action, grant, permit = _permit(pair, authority_pin, endpoint_pin)
        reservation = permit["reservation_id"]
        require(reservation in permits and canonical(pair) == canonical(permits[reservation]["pair"]),
            "actual endpoint effect lacks exported issued permit")
        require(request["action_id"] == action["action_id"] and request["permit_digest"] == sha(request["permit"])
            and action["arguments"]["url"] == value["url"] + "/v1/record", "actual request/endpoint binding mismatch")
        _receipt(receipt, endpoint_pin, action, grant, reservation)
        require(type(effect) is dict and set(effect) == {"sequence", "action_id", "attempt_id", "root_id", "reservation_id", "body_digest", "committed_at", "body"}
            and type(effect["sequence"]) is int and effect["sequence"] == seq
            and effect["body"] == action["arguments"]["body"] and effect["body_digest"] == sha(effect["body"])
            and type(effect["committed_at"]) in (int, float) and effect["committed_at"] == receipt["committed_at"]
            and all(effect[k] == receipt[k] for k in ("action_id", "attempt_id", "root_id", "reservation_id", "body_digest")),
            "actual SQLite row differs from endpoint receipt/action")
        require(effect["action_id"] not in ids and effect["attempt_id"] not in attempts and reservation not in reservations,
            "duplicate endpoint effect identity")
        ids.add(effect["action_id"])
        attempts.add(effect["attempt_id"])
        reservations.add(reservation)
    require(value["independent_sqlite_action_ids"] == sorted(ids), "independent SQLite action inventory mismatch")


def _delta(before: dict[str, Any], after: dict[str, Any], requests: int, effects: int) -> None:
    require(after["effects"][:len(before["effects"])] == before["effects"]
        and after["receipts"][:len(before["receipts"])] == before["receipts"]
        and after["requests"][:len(before["requests"])] == before["requests"], "endpoint inventory history changed")
    require(after["commit_request_count"] - before["commit_request_count"] == requests
        and len(after["effects"]) - len(before["effects"]) == effects
        and after["query_request_count"] >= before["query_request_count"], "measured request/effect delta mismatch")


def verify_report(report: Any, *, repo_root: Path = ROOT, expected_source_sha: str | None = None,
                  expected_authority_pin: dict[str, str] | None = None,
                  expected_endpoint_pin: dict[str, str] | None = None,
                  trusted_latest_anchor: dict[str, Any] | None = None) -> dict[str, Any]:
    require(type(report) is dict and report.get("schema") == SCHEMA, "network runtime evidence schema mismatch")
    _bounded(report)
    require(len(canonical(report)) <= MAX_REPORT_BYTES, "report size limit")
    source_count = _sources(report, repo_root, expected_source_sha)
    cases = report.get("outcomes")
    require(type(cases) is dict and set(cases) == set(CASE_IDS), "missing/extra network experiment case")
    design = report.get("preregistration")
    require(type(design) is dict and design.get("experiment_id") == SCHEMA
        and design.get("scenario_ids") == list(CASE_IDS) and design.get("model_calls_budget") == 0
        and design.get("live_internet") is False and design == json.loads(
            (repo_root / "experiments/agent_control/preregistration_external_network.json").read_text()),
        "preregistered network experiment differs from versioned design")
    require(report.get("passed") is True and type(report.get("checks")) is dict
        and report["checks"] and all(v is True for v in report["checks"].values()), "declared experiment checks incomplete/failed")
    authority_pin, endpoint_pin = report.get("authority_public_pin"), report.get("endpoint_public_pin")
    _CRYPTO._pin(authority_pin)
    _endpoint_pin(endpoint_pin)
    require(authority_pin["public_key"] != endpoint_pin["public_key"], "endpoint and authority share signing identity")
    if expected_authority_pin is not None:
        _CRYPTO._pin(expected_authority_pin)
        require(authority_pin == expected_authority_pin, "caller-supplied authority pin mismatch")
    if expected_endpoint_pin is not None:
        _endpoint_pin(expected_endpoint_pin)
        require(endpoint_pin == expected_endpoint_pin, "caller-supplied endpoint pin mismatch")
    pairs, endpoint_pairs = report.get("authority_evidence"), report.get("endpoint_evidence")
    require(type(pairs) is list and 0 < len(pairs) <= 1024 and type(endpoint_pairs) is list
        and 0 < len(endpoint_pairs) <= 1024, "public request-response evidence missing/oversized")
    public, nonces, permits, action_inputs, grant_inputs, terminal = [], set(), {}, {}, {}, {}
    pair_encodings = set()
    for pair in pairs:
        require(type(pair) is dict and set(pair) == {"request", "response"}, "authority public evidence pair invalid")
        require(len(canonical(pair.get("request"))) <= 32768 and len(canonical(pair.get("response"))) <= 2 * 1024 * 1024,
            "authority public packet limit")
        result = verify_public_response(pair, authority_pin)
        request = pair["request"]
        require(request["nonce"] not in nonces, "duplicate public request nonce/evidence")
        nonces.add(request["nonce"])
        public.append((request, result, pair["response"]))
        pair_encodings.add(canonical(pair))
        if request["operation"] == "begin":
            require(set(request["payload"]) == {"action", "authorization"}, "authority BEGIN payload invalid")
            action = _action(request["payload"]["action"])
            grant = _grant(request["payload"]["authorization"], action, endpoint_pin)
            digest = sha(action)
            require(digest not in grant_inputs or grant_inputs[digest] == grant, "same action changed exact grant")
            action_inputs[digest], grant_inputs[digest] = action, grant
            if result.get("status") == "PERMITTED":
                action, grant, permit = _permit(pair, authority_pin, endpoint_pin)
                require(permit["reservation_id"] not in permits and not any(
                    p["action"]["action_id"] == action["action_id"] or p["action"]["attempt_id"] == action["attempt_id"]
                    for p in permits.values()), "external one-shot permit reissued")
                permits[permit["reservation_id"]] = {"pair": pair, "action": action, "grant": grant,
                    "issued_at": pair["response"]["issued_at"]}
        elif request["operation"] == "finish":
            require(set(request["payload"]) == {"reservation_id", "receipt"}, "authority FINISH payload invalid")
            if result.get("status") == "SETTLED":
                reservation = request["payload"]["reservation_id"]
                require(reservation in permits, "terminal result has no issued reservation")
                p = permits[reservation]
                receipt = _receipt(request["payload"]["receipt"], endpoint_pin, p["action"], p["grant"], reservation)
                require(result.get("receipt") == receipt and result.get("outcome") == "COMMITTED"
                    and result.get("reservation_id") == reservation and result.get("action_digest") == sha(p["action"])
                    and result.get("receiver_id") == endpoint_pin["endpoint_id"] and all(result.get(k) == p["action"][k]
                    for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")), "external terminal proof binding mismatch")
                require(reservation not in terminal or terminal[reservation] == receipt, "terminal receipt changed")
                terminal[reservation] = receipt
    entries, anchor = report.get("authority_checkpoints"), report.get("checkpoint_anchor")
    require(type(entries) is list and len(entries) <= 4096, "checkpoint chain limit")
    tip = verify_public_chain(entries, authority_pin, anchor)
    if trusted_latest_anchor is not None:
        require(canonical(trusted_latest_anchor) == canonical(tip), "caller-supplied latest anchor mismatch")
    require(any(request["operation"] == "checkpoints" and result.get("status") == "CHECKPOINTS"
        and result.get("entries") == entries for request, result, _ in public), "checkpoint export lacks authenticated authority response")
    begin_checkpoints, finish_checkpoints = {}, {}
    for entry in entries:
        if entry["kind"] == "BEGIN_PENDING":
            candidates = [p for p in permits.values() if sha(p["action"]) == entry["action_digest"]]
            require(len(candidates) == 1 and entry["action_digest"] not in begin_checkpoints
                and entry["root_id"] == candidates[0]["action"]["root_id"]
                and entry["epoch"] == candidates[0]["action"]["epoch"], "pending checkpoint lacks unique exact issued permit")
            begin_checkpoints[entry["action_digest"]] = entry
        elif entry["kind"] == "BEGIN_DENIED":
            require(entry["action_digest"] in action_inputs, "denied checkpoint lacks supplied action")
        elif entry["kind"].startswith("FINISH_"):
            require(entry["kind"] == "FINISH_COMMITTED", "network negative terminal checkpoint is forbidden")
            candidates = [(r, receipt) for r, receipt in terminal.items() if sha(receipt) == entry["receipt_digest"]]
            require(len(candidates) == 1 and entry["action_digest"] in begin_checkpoints
                and entry["action_digest"] not in finish_checkpoints, "terminal checkpoint lacks unique permit/authenticated receipt")
            reservation, receipt = candidates[0]
            require(entry["action_digest"] == receipt["action_digest"] and entry["root_id"] == receipt["root_id"]
                and entry["sequence"] > begin_checkpoints[entry["action_digest"]]["sequence"], "checkpoint terminal action order mismatch")
            finish_checkpoints[entry["action_digest"]] = entry
    require(set(begin_checkpoints) == {sha(p["action"]) for p in permits.values()}
        and set(finish_checkpoints) == {receipt["action_digest"] for receipt in terminal.values()},
        "signed permit/terminal checkpoint inventory incomplete")
    endpoint_nonce_set, endpoint_receipts = set(), {}
    for pair in endpoint_pairs:
        result = verify_endpoint_pair(pair, endpoint_pin, authority_pin)
        nonce = pair["request"]["nonce"]
        require(nonce not in endpoint_nonce_set and nonce not in nonces, "duplicate endpoint public challenge")
        endpoint_nonce_set.add(nonce)
        if result["status"] == "OBSERVED":
            receipt = result["receipt"]
            require(receipt["reservation_id"] in permits, "endpoint response has no issued permit")
            p = permits[receipt["reservation_id"]]
            _receipt(receipt, endpoint_pin, p["action"], p["grant"], receipt["reservation_id"])
            endpoint_receipts[sha(receipt)] = receipt
    final_inventory = report.get("endpoint_final_inventory")
    _inventory(final_inventory, endpoint_pin, authority_pin, permits)
    actual_receipts = {sha(receipt): receipt for receipt in final_inventory["receipts"]}
    require(set(endpoint_receipts) <= set(actual_receipts) and all(sha(receipt) in actual_receipts
        for receipt in terminal.values()), "endpoint/external terminal proof lacks actual durable effect inventory")
    for request, result, _ in public:
        receipt = result.get("receipt")
        if receipt is not None:
            require(type(receipt) is dict and sha(receipt) in actual_receipts, "authority returned receipt lacks actual endpoint effect")
            p = permits.get(receipt["reservation_id"])
            require(p is not None, "authority returned receipt without permit")
            _receipt(receipt, endpoint_pin, p["action"], p["grant"], receipt["reservation_id"])
        if result.get("status") == "UNKNOWN":
            require(result.get("outcome") is None and result.get("receipt") is None, "authority unknown was made terminal")

    def signed(value: Any, operation: str | None = None) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
        matches = [(request, result, response) for request, result, response in public
            if canonical(result) == canonical(value) and (operation is None or request["operation"] == operation)]
        require(matches, "case authority observation lacks exact signed response")
        return matches

    def state(name: str, field: str = "external_state") -> dict[str, Any]:
        value = cases[name].get(field)
        matches = signed(value)
        require(type(value) is dict and set(value) in (STATE_FIELDS | {"status"}, STATE_FIELDS | {"status", "deadline_reached"})
            and value["root_id"] == cases[name]["action"]["root_id"]
            and value["receiver_id"] == endpoint_pin["endpoint_id"] and hexadecimal(value["policy_digest"])
            and _integer(value["epoch"], 1) and value["state"] in {"ACTIVE", "STOPPING", "STOPPED"}
            and type(value["clock_fault"]) is bool and type(value["admission_closed"]) is bool
            and all(_integer(value[k]) for k in ("max_actions", "issued_count", "pending_count", "committed_count", "denied_count")),
            "signed external state invalid")
        require(any(request["payload"].get("root_id") == value["root_id"] for request, _, _ in matches), "signed state root request mismatch")
        persisted = {key: value[key] for key in STATE_FIELDS}
        persisted["admission_closed"] = value["state"] != "ACTIVE" or value["clock_fault"]
        require(value["issued_count"] == value["pending_count"] + value["committed_count"], "signed pending accounting mismatch")
        require(any(entry["root_id"] == value["root_id"] and entry["state_digest"] == sha(persisted)
            for entry in entries), "signed state differs from checkpoint state digest")
        if "deadline_reached" in value:
            require(value["deadline_reached"] is False, "bounded network fixture deadline unavailable/reached")
        require(value["admission_closed"] == persisted["admission_closed"], "signed admission closure mismatch")
        return value

    def result(name: str, field: str, status: str, action_field: str = "action") -> dict[str, Any]:
        value = cases[name]["results"].get(field)
        require(type(value) is dict and value.get("status") == status, "gateway outcome mismatch: " + name + ":" + field)
        action = cases[name][action_field]
        require(set(value) == GATEWAY_RESULT_FIELDS
            and value["action_id"] == action["action_id"] and value["execution_authorized"] is False
            and type(value["dispatch_finished"]) is bool and type(value["reason"]) is str,
            "gateway result identity/authority metadata invalid")
        if status == "COMMITTED":
            grant = cases[name]["recovery_authorization" if action_field == "recovery_action" else "authorization"]
            receipt = value.get("receipt")
            _receipt(receipt, endpoint_pin, action, grant, value["reservation_id"])
            require(_id(value["reservation_id"]) and value["reservation_id"] == receipt["reservation_id"]
                and sha(receipt) in actual_receipts and receipt["reservation_id"] in terminal
                and type(value["effect_count"]) is int and value["effect_count"] == 1
                and value["remote_outcome"] == "COMMITTED" and value["settlement_status"] == "SETTLED",
                "gateway committed outcome lacks authenticated actual settlement")
        elif status == "UNKNOWN":
            require(value["effect_count"] is None and value["receipt"] is None and value["remote_outcome"] is None
                and value["settlement_status"] == "UNKNOWN", "gateway UNKNOWN asserted definitive effect count/outcome")
        elif status == "DENIED":
            require(value["effect_count"] is None and value["receipt"] is None and value["remote_outcome"] is None
                and value["dispatch_finished"] is False and value["settlement_status"] is None,
                "gateway denial invented endpoint outcome/completion")
        return value

    snapshot_fields = ("endpoint_before", "endpoint_after", "held_endpoint_inventory", "after_loss", "endpoint_before_restore",
        "outage_endpoint_before", "outage_endpoint_after")
    previous_inventory = None
    for name, case in cases.items():
        require(type(case) is dict and type(case.get("results")) is dict and type(case.get("checks")) is dict
            and case["checks"] and all(v is True for v in case["checks"].values()), "case checks incomplete/failed")
        action = _action(case.get("action"))
        require(action["root_id"] == "runtime:" + name and action["arguments"]["url"] == final_inventory["url"] + "/v1/record",
            "case exact action root/endpoint mismatch")
        grant = _grant(case.get("authorization"), action, endpoint_pin)
        if sha(action) in action_inputs:
            require(action_inputs[sha(action)] == action and grant_inputs[sha(action)] == grant, "case input differs from public BEGIN")
        for field in ("outage_action", "recovery_action"):
            if field in case:
                extra = _action(case[field])
                extra_grant = _grant(case[field.replace("_action", "_authorization")], extra, endpoint_pin)
                require(extra["root_id"] == "runtime:outage_positive_control" and extra["arguments"]["url"] == action["arguments"]["url"],
                    "outage control identity/endpoint mismatch")
                if sha(extra) in action_inputs:
                    require(grant_inputs[sha(extra)] == extra_grant, "outage control grant mismatch")
        for field in snapshot_fields:
            if field in case:
                _inventory(case[field], endpoint_pin, authority_pin, permits)
                require(case[field]["url"] == final_inventory["url"], "snapshot endpoint URL changed")
                require(case[field]["effects"] == final_inventory["effects"][:len(case[field]["effects"])], "snapshot differs from final effect history")
        expected = {
            "network_positive": (1, 1), "network_binding_swap": (0, 0), "network_stop_before_dispatch": (0, 0),
            "network_pending_dispatch_stop": (1, 1), "network_lost_begin_response": (0, 0),
            "network_lost_transport_response": (1, 1), "network_lost_finish_response": (1, 1),
            "network_restore_consumed_state": (1, 1), "network_restore_stopped_state": (0, 0),
            "network_authority_restart_outage": (2, 2), "network_ambiguous_endpoint": (1, 1),
            "network_cross_profile_receipt": (0, 0)}[name]
        _delta(case["endpoint_before"], case["endpoint_after"], *expected)
        require(type(case.get("request_count_delta")) is int and type(case.get("effect_count_delta")) is int
            and (case["request_count_delta"], case["effect_count_delta"]) == expected, "reported delta differs from measured inventory")
        require(case["external_query"] in [value for _, value, _ in public], "case external query not authenticated")
        require(any(request["operation"] == "query" and request["payload"] == {"action_id": action["action_id"]}
            and query == case["external_query"] for request, query, _ in public), "case external query action binding mismatch")
        state(name)
        for gateway_field in ("gateway_inventory", "recovery_gateway_inventory"):
            if gateway_field not in case:
                continue
            gateway = case[gateway_field]
            require(type(gateway) is dict and gateway.get("profile") == PROFILE, "gateway immutable profile inventory mismatch")
            require(type(gateway.get("authority_evidence")) is list and all(canonical(pair) in pair_encodings
                for pair in gateway["authority_evidence"]), "gateway authority evidence absent from public export")
            require(type(gateway.get("endpoint_evidence")) is list and all(pair in endpoint_pairs
                for pair in gateway["endpoint_evidence"]), "gateway endpoint evidence absent from public export")
            require(gateway.get("authority_pin") == authority_pin and gateway.get("endpoint_pin") == endpoint_pin
                and gateway.get("endpoint_url") == final_inventory["url"] and gateway.get("execution_authorized") is False
                and gateway.get("gateway_id") == ("gateway:outage_positive_control" if gateway_field == "recovery_gateway_inventory"
                    else "gateway:" + name), "gateway inventory identity/pins changed")
            require(type(gateway.get("actions")) is list and len(gateway["actions"]) <= 256, "gateway grant inventory missing/oversized")
            expected_gateway_actions = ([case["outage_action"], case["recovery_action"]]
                if gateway_field == "recovery_gateway_inventory" else [action])
            require(len(gateway["actions"]) == len(expected_gateway_actions)
                and {sha(recorded.get("action")) for recorded in gateway["actions"]} == {sha(a) for a in expected_gateway_actions},
                "gateway grant inventory differs from exact case inputs")
            for recorded in gateway["actions"]:
                require(type(recorded) is dict and set(recorded) == {"action", "authorization", "status", "reservation_id", "receipt"},
                    "gateway grant inventory fields invalid")
                own_action = _action(recorded["action"])
                own_grant = _grant(recorded["authorization"], own_action, endpoint_pin)
                require(own_action["arguments"]["url"] == final_inventory["url"] + "/v1/record"
                    and recorded["status"] in {"AUTHORIZED", "PENDING", "UNKNOWN", "COMMITTED_PROOF", "COMMITTED", "DENIED"},
                    "gateway grant status/endpoint invalid")
                if recorded["receipt"] is not None:
                    _receipt(recorded["receipt"], endpoint_pin, own_action, own_grant, recorded["reservation_id"])
                    require(sha(recorded["receipt"]) in actual_receipts, "gateway grant receipt lacks actual endpoint effect")
                if recorded["status"] in {"COMMITTED", "COMMITTED_PROOF"}:
                    require(recorded["receipt"] is not None, "gateway terminal/proof status lacks actual receipt")
                    if recorded["status"] == "COMMITTED":
                        require(recorded["reservation_id"] in terminal, "gateway terminal status lacks external settlement")
                else:
                    require(recorded["receipt"] is None, "gateway nonterminal grant carries contradictory terminal receipt")
    for name in CASE_IDS:
        current = cases[name]
        if previous_inventory is not None:
            require(current["endpoint_before"] == previous_inventory, "case inventory capture continuity broken")
        previous_inventory = current["endpoint_after"]
    require(previous_inventory == final_inventory, "final endpoint inventory differs from final case capture")
    expected_effect_ids = {cases[name]["action"]["action_id"] for name in CASE_IDS if cases[name]["effect_count_delta"] > 0}
    expected_effect_ids.add(cases["network_authority_restart_outage"]["recovery_action"]["action_id"])
    require(final_inventory["independent_sqlite_action_ids"] == sorted(expected_effect_ids), "final effect identities differ from bounded case matrix")

    result("network_positive", "execute", "COMMITTED")
    require(state("network_positive")["committed_count"] == 1 and state("network_positive")["pending_count"] == 0, "positive settlement missing")
    swapped = cases["network_binding_swap"]["results"]
    require(set(swapped) == {"endpoint", "method", "headers", "body"}, "binding swap matrix incomplete")
    for kind, item in swapped.items():
        require(type(item) is dict and set(item) == {"action", "result"} and item["result"].get("status") in {"DENIED", "ERROR"}
            and item["action"] != cases["network_binding_swap"]["action"], "binding swap was not a rejected changed action")
        original, changed = cases["network_binding_swap"]["action"], item["action"]
        require(all(changed[k] == original[k] for k in ACTION_FIELDS - {"arguments"}), "binding swap changed identity instead of request")
        differences = {key for key in set(original["arguments"]) | set(changed["arguments"])
            if original["arguments"].get(key) != changed["arguments"].get(key)}
        require(differences == {{"endpoint": "url", "method": "method", "headers": "headers", "body": "body"}[kind]}, "binding swap target mismatch")
        denied = item["result"]
        if denied["status"] == "ERROR":
            require(set(denied) == {"status", "reason"} and type(denied["reason"]) is str, "invalid rejected worker request observation")
        else:
            require(set(denied) == GATEWAY_RESULT_FIELDS and denied["action_id"] == original["action_id"]
                and denied["execution_authorized"] is False and denied["dispatch_finished"] is False
                and denied["effect_count"] is None and denied["remote_outcome"] is None and denied["receipt"] is None
                and denied["settlement_status"] is None, "rejected binding swap invented authority/outcome")
    require(state("network_binding_swap")["issued_count"] == 0, "binding swap issued a permit")
    for name in ("network_stop_before_dispatch", "network_restore_stopped_state"):
        result(name, "execute", "DENIED")
        stopped, current = state(name, "stop_response"), state(name)
        require(stopped["status"] == "STOPPED" and stopped["state"] == "STOPPED" and stopped["pending_count"] == 0
            and stopped["epoch"] > cases[name]["action"]["epoch"] and current["state"] == "STOPPED"
            and current["epoch"] == stopped["epoch"] and current["issued_count"] == 0, "STOP did not preserve closed admission")
    pending = "network_pending_dispatch_stop"
    _delta(cases[pending]["endpoint_before"], cases[pending]["held_endpoint_inventory"], 1, 0)
    stopped = state(pending, "stop_response")
    require(stopped["status"] == "STOP_PENDING" and stopped["state"] == "STOPPING"
        and stopped["pending_count"] == 1, "STOP acknowledged before held request settled")
    result(pending, "execute", "COMMITTED")
    final = state(pending, "final_stop_state")
    require(final["state"] == "STOPPED" and final["pending_count"] == 0 and final["committed_count"] == 1, "STOP after terminal missing")
    for name in ("network_lost_begin_response", "network_ambiguous_endpoint", "network_cross_profile_receipt"):
        result(name, "execute", "UNKNOWN")
        if name == "network_lost_begin_response":
            result(name, "retry", "UNKNOWN")
        elif name == "network_ambiguous_endpoint":
            result(name, "reconcile", "UNKNOWN")
            matching = [pair for pair in endpoint_pairs if pair["request"]["operation"] == "query"
                and pair["request"]["payload"]["action_id"] == cases[name]["action"]["action_id"]]
            require(len(matching) == 1 and matching[0]["response"]["result"]["status"] == "UNKNOWN",
                "ambiguous endpoint lacks fresh authenticated UNKNOWN query")
        stopped = state(name, "stop_response")
        require(stopped["status"] == "STOP_PENDING" and stopped["state"] == "STOPPING"
            and stopped["issued_count"] == stopped["pending_count"] == 1 and stopped["committed_count"] == 0
            and cases[name]["external_query"].get("outcome") is None and cases[name]["external_query"].get("receipt") is None,
            "unresolved network permit made quiescent or negative")
        require(sha(cases[name]["action"]) not in finish_checkpoints, "unresolved permit given terminal checkpoint")
    lost = "network_lost_transport_response"
    result(lost, "execute", "UNKNOWN")
    require(state(lost, "unresolved_external_state")["pending_count"] == 1, "transport loss lost pending reservation")
    _delta(cases[lost]["endpoint_before"], cases[lost]["after_loss"], 1, 1)
    _delta(cases[lost]["after_loss"], cases[lost]["endpoint_after"], 0, 0)
    result(lost, "reconcile", "COMMITTED")
    lost = "network_lost_finish_response"
    uncertain_settlement = cases[lost]["results"].get("execute")
    require(type(uncertain_settlement) is dict and set(uncertain_settlement) == GATEWAY_RESULT_FIELDS
        and uncertain_settlement.get("status") == "UNKNOWN"
        and uncertain_settlement.get("remote_outcome") == "COMMITTED" and uncertain_settlement.get("effect_count") == 1
        and type(uncertain_settlement.get("effect_count")) is int
        and uncertain_settlement.get("settlement_status") == "UNKNOWN"
        and uncertain_settlement.get("action_id") == cases[lost]["action"]["action_id"]
        and _id(uncertain_settlement.get("reservation_id"))
        and uncertain_settlement.get("execution_authorized") is False
        and type(uncertain_settlement.get("dispatch_finished")) is bool,
        "lost FINISH conflated remote commit with settlement")
    _receipt(uncertain_settlement.get("receipt"), endpoint_pin, cases[lost]["action"], cases[lost]["authorization"],
        uncertain_settlement.get("reservation_id"))
    require(sha(uncertain_settlement["receipt"]) in actual_receipts, "lost FINISH claimed remote commit without actual proof")
    signed(cases[lost]["settled_before_recovery"], "query")
    require(cases[lost]["settled_before_recovery"].get("receipt") in list(actual_receipts.values())
        and cases[lost]["settled_before_recovery"].get("outcome") == "COMMITTED", "lost FINISH lacked durable external terminal")
    _delta(cases[lost]["endpoint_before"], cases[lost]["after_loss"], 1, 1)
    _delta(cases[lost]["after_loss"], cases[lost]["endpoint_after"], 0, 0)
    result(lost, "reconcile", "COMMITTED")
    for name in ("network_restore_consumed_state", "network_restore_stopped_state"):
        for field in ("snapshot", "restore"):
            value = cases[name].get(field)
            require(type(value) is dict and value.get("method") == "sqlite3.Connection.backup"
                and value.get("gateway_stopped_during_copy") is True and value.get("authority_database_not_restored") is True
                and value.get("endpoint_database_not_restored") is True, "coherent gateway-only rollback evidence missing")
        before_restore = cases[name]["restore"].get("gateway_state_before_restore")
        restored_state = cases[name]["restore"].get("gateway_state_after_restore")
        snapshot_state = cases[name]["snapshot"].get("gateway_state_at_snapshot")
        require(type(snapshot_state) is dict and type(restored_state) is dict and type(before_restore) is dict
            and snapshot_state.get("actions") == restored_state.get("actions")
            and len(restored_state.get("actions", [])) == 1 and restored_state["actions"][0]["status"] == "AUTHORIZED"
            and restored_state["actions"][0]["reservation_id"] is None and restored_state["actions"][0]["receipt"] is None
            and restored_state["actions"][0]["action"] == cases[name]["action"]
            and restored_state["actions"][0]["authorization"] == cases[name]["authorization"],
            "actual restored authorization snapshot missing")
        if name == "network_restore_consumed_state":
            require(before_restore.get("actions", [{}])[0].get("status") == "COMMITTED"
                and before_restore["actions"][0].get("receipt") in list(actual_receipts.values()),
                "consumed gateway state was not actually replaced")
    restored = "network_restore_consumed_state"
    result(restored, "execute", "COMMITTED")
    _delta(cases[restored]["endpoint_before"], cases[restored]["endpoint_before_restore"], 1, 1)
    _delta(cases[restored]["endpoint_before_restore"], cases[restored]["endpoint_after"], 0, 0)
    require(cases[restored]["results"]["retry"].get("status") in {"UNKNOWN", "DENIED", "COMMITTED"}
        and state(restored)["committed_count"] == 1 and state(restored)["pending_count"] == 0, "consumed state rollback reopened dispatch")
    result(restored, "retry", cases[restored]["results"]["retry"]["status"])
    restarted = "network_authority_restart_outage"
    result(restarted, "execute", "COMMITTED")
    result(restarted, "retry", "COMMITTED")
    result(restarted, "recovery", "COMMITTED", "recovery_action")
    result(restarted, "outage", "UNKNOWN", "outage_action")
    _delta(cases[restarted]["outage_endpoint_before"], cases[restarted]["outage_endpoint_after"], 0, 0)
    require(cases[restarted]["outage_action"]["action_id"] != cases[restarted]["recovery_action"]["action_id"]
        and cases[restarted]["outage_action"]["attempt_id"] != cases[restarted]["recovery_action"]["attempt_id"]
        and cases[restarted]["results"]["outage"].get("status") == "UNKNOWN"
        and cases[restarted]["results"]["outage"].get("effect_count") is None, "outage recovery reused unknown operation")
    s, previous = state(restarted, "restarted_external_state"), state(restarted, "stop_response")
    require(s["state"] == "STOPPED" and s["epoch"] == previous["epoch"] and s["committed_count"] == 1
        and s["pending_count"] == 0, "authority restart lost STOP/consumption")
    signed(cases[restarted]["restarted_external_query"], "query")
    wrong = cases["network_cross_profile_receipt"]
    for field, receipt_field in (("records_profile_finish", "records_profile_receipt"), ("altered_endpoint_finish", "altered_endpoint_receipt")):
        observation = wrong["results"][field]
        require(observation.get("status") == "ERROR", "cross-profile terminal proof accepted")
        require(any(request["operation"] == "finish" and result == observation
            and request["payload"]["receipt"] == wrong[receipt_field]
            and request["payload"]["reservation_id"] == wrong["external_query"]["reservation_id"]
            for request, result, _ in public), "cross-profile rejection lacks exact authenticated request")

    processes, cleanup = report.get("processes"), report.get("cleanup")
    require(type(processes) is list and type(cleanup) is list and processes and len(processes) <= 128
        and len(cleanup) == len(processes), "process lifecycle evidence missing")
    pids = [item.get("pid") for item in processes]
    require(all(_integer(pid, 1) and pid != report.get("controller_pid") for pid in pids)
        and len(pids) == len(set(pids)), "three service process separation missing")
    require(set(pids) == {item.get("pid") for item in cleanup}
        and all(item.get("reaped") is True for item in cleanup), "service child process not reaped")
    for role, pin in (("external_authority", authority_pin), ("endpoint", endpoint_pin)):
        participants = [item for item in processes if item.get("role") == role]
        require(len(participants) >= (3 if role == "external_authority" else 2)
            and participants[0].get("explicit_initialization") is True
            and all(item.get("explicit_initialization") is False for item in participants[1:])
            and all(item.get("startup", {}).get("pin") == pin for item in participants),
            "service restart identity/init evidence missing: " + role)
        if role == "endpoint":
            require(all(item.get("startup", {}).get("profile") == PROFILE for item in participants), "endpoint startup profile mismatch")
        else:
            require(all("--profile" in item.get("command", []) and item["command"][item["command"].index("--profile") + 1] == PROFILE
                for item in participants), "authority startup profile mismatch")
    require(set(item.get("role") for item in processes) == {"external_authority", "gateway", "endpoint"}
        and len([item for item in processes if item["role"] == "gateway"]) >= 13, "three service roles/matrix not executed")
    for item in processes:
        require(type(item.get("command")) is list and all(type(argument) is str for argument in item["command"]), "process command evidence invalid")
        if item["role"] != "external_authority":
            require("--signing-key-file" not in item["command"] and not any("authority-signing.key" in part for part in item["command"]),
                "authority private key delivered outside controller")
    scope = report.get("scope")
    require(type(scope) is dict and all(scope.get(k) is True for k in ("actual_loopback_http",
        "distinct_authority_gateway_endpoint_processes", "separate_sqlite_databases", "actual_synthetic_sqlite_effects",
        "endpoint_receipts_publicly_verifiable")) and scope.get("private_keys_bundled") is False
        and type(scope.get("model_calls")) is int and scope["model_calls"] == 0
        and all(scope.get(k) == "NOT_RUN" for k in ("external_network", "docker", "command_profile"))
        and all(scope.get(k) == "NOT_ESTABLISHED" for k in ("independent_latest_anchor", "full_worker_socket_mediation",
            "sender_quiescence", "external_human_reproduction")), "artifact scope overstates bounded observations")
    return {"schema": "liminal-external-network-offline-verification-v1", "status": "PASS",
        "source": report["source"], "source_files_verified": source_count, "cases_verified": list(CASE_IDS),
        "authority_response_signatures_verified": len(pairs), "endpoint_response_signatures_verified": len(endpoint_pairs),
        "checkpoint_signatures_verified": len(entries), "endpoint_receipts_verified": len(actual_receipts),
        "one_shot_permits_verified": len(permits), "actual_endpoint_requests": final_inventory["commit_request_count"],
        "actual_endpoint_effects": len(final_inventory["effects"]), "checkpoint_tip": tip,
        "authority_pin_scope": "caller_supplied" if expected_authority_pin is not None else "report_fixture",
        "endpoint_pin_scope": "caller_supplied" if expected_endpoint_pin is not None else "report_fixture",
        "checkpoint_verification_status": "EXTERNAL_ANCHORED_VERIFIED" if trusted_latest_anchor is not None else "LOCAL_SIGNATURE_ONLY",
        "execution_authorized": False, "sender_quiescence": "NOT_ESTABLISHED",
        "limits": ["Only supplied artifact observations and checked-out source inputs are verified; completeness outside the bounded capture is not established.",
            "Fixture public pins are not independent enrollment; HMAC request credentials are intentionally redacted and not publicly reverified.",
            "An authenticated remote COMMITTED receipt proves the owned endpoint record, not completion or quiescence of sender callbacks.",
            "No arbitrary API, unrestricted sockets, kernel containment, command profile, live model training or production safety certification."]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-report-sha256")
    parser.add_argument("--authority-pin-file", type=Path)
    parser.add_argument("--endpoint-pin-file", type=Path)
    parser.add_argument("--trusted-latest-anchor-file", type=Path)
    args = parser.parse_args(argv)
    try:
        def unique(items):
            value = {}
            for key, item in items:
                require(key not in value, "duplicate JSON object key")
                value[key] = item
            return value
        def decode(path: Path, maximum: int) -> Any:
            require(path.is_file() and path.stat().st_size <= maximum, "input file size limit")
            return json.loads(path.read_bytes(), object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("non-finite JSON")))
        if args.expected_report_sha256 is not None:
            require(args.report.stat().st_size <= MAX_REPORT_BYTES and hexadecimal(args.expected_report_sha256)
                and hashlib.sha256(args.report.read_bytes()).hexdigest() == args.expected_report_sha256, "exact report SHA-256 mismatch")
        report = decode(args.report, MAX_REPORT_BYTES)
        result = verify_report(report, expected_source_sha=args.expected_source_sha,
            expected_authority_pin=decode(args.authority_pin_file, 2048) if args.authority_pin_file else None,
            expected_endpoint_pin=decode(args.endpoint_pin_file, 2048) if args.endpoint_pin_file else None,
            trusted_latest_anchor=decode(args.trusted_latest_anchor_file, 2048) if args.trusted_latest_anchor_file else None)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RecursionError) as exc:
        print(json.dumps({"status": "FAIL", "execution_authorized": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
