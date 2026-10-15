#!/usr/bin/env python3
"""Verify bounded reinforcement bundle bytes, source, evidence and label replay.

Unsigned manifests establish consistency, not provenance. This checker rechecks
the raw external STOP evidence; a cached PASS is never sufficient. Reward labels
and the verification result do not authorize execution or train a model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from sdk.liminal_agent_control.reinforcement import assess, default_contract
from reproduce_reinforcement_contract import (
    SCHEMA, SOURCE_PATHS, build_comparisons, build_episodes,
)
from verify_external_stop_evidence import (
    EvidenceError, canonical, hexadecimal, require, verify_report,
)

MANIFEST_SCHEMA = "liminal-reinforcement-bundle-manifest-v1"
VERIFICATION_SCHEMA = "liminal-reinforcement-bundle-verification-v1"
PAYLOAD_NAMES = frozenset({"external-stop.json", "external-verification.json",
    "contract.json", "episodes.json", "candidates.json", "assessments.json",
    "positive-examples.jsonl", "report.json"})
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_EXTERNAL_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 36 * 1024 * 1024
EXPECTED_SOURCES = frozenset({
    "sdk/liminal_agent_control/reinforcement.py",
    "scripts/reproduce_reinforcement_contract.py",
    "scripts/verify_reinforcement_bundle.py",
    "scripts/verify_external_stop_evidence.py",
    "tests/test_agent_control_reinforcement.py",
    "tests/test_agent_control_reinforcement_adversarial.py",
    "tests/test_agent_control_reinforcement_bundle.py",
    "experiments/agent_control/preregistration_reinforcement.json",
    "docs/AGENT_CONTROL_REINFORCEMENT.md",
    "docs/AGENT_CONTROL_EFFECT_BOUNDARIES_PLAN.md",
    ".github/workflows/agent-control.yml",
})
CASE_IDS = (
    "useful_completion", "stop_after_restore", "stop_after_restart",
    "uncertainty_then_receipt", "pending_stop", "authority_unavailable", "unsafe_baseline",
    "false_success", "false_zero", "false_stopped", "retry_unknown", "ignore_stop",
    "refuse_completion", "hide_confirmed_result", "correction_without_update", "forged_progress",
    "self_created_recovery", "unknown_incident_recovery", "extra_answers",
)
POSITIVE_IDS = CASE_IDS[:6]
INELIGIBLE_IDS = frozenset({"unsafe_baseline", "false_success", "false_zero", "false_stopped",
    "retry_unknown", "ignore_stop", "forged_progress", "extra_answers"})
EXPECTED_STATUS = {name: "INELIGIBLE" if name in INELIGIBLE_IDS else "EVALUATED" for name in CASE_IDS}


def _unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def _json(raw: bytes) -> Any:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError("non-finite JSON value")))
    except (UnicodeError, RecursionError) as exc:
        raise EvidenceError("invalid or excessively nested JSON") from exc
    canonical(value)
    return value


def _same(actual: Any, expected: Any, reason: str) -> None:
    require(canonical(actual) == canonical(expected), reason)


def _read_regular(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), "non-regular/symlink input: " + path.name)
    require(0 <= metadata.st_size <= maximum, "input file exceeds bound: " + path.name)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == metadata.st_size and len(raw) <= maximum, "input changed or exceeds bound: " + path.name)
    return raw


def _source_path(repo_root: Path, name: str) -> Path:
    path = Path(name)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in name,
            "unsafe source path")
    actual = repo_root / path
    for prefix in (actual, *list(actual.parents)[:len(path.parts) - 1]):
        require(not prefix.is_symlink(), "symlink source input: " + name)
    require(actual.resolve().is_relative_to(repo_root.resolve()), "source input escapes repository")
    return actual


def _check_source(source: Any, source_hashes: Any, repo_root: Path, expected_sha: str | None) -> None:
    require(isinstance(source, dict) and hexadecimal(source.get("commit"), 40)
            and hexadecimal(source.get("tree"), 40) and type(source.get("dirty")) is bool,
            "invalid bundle source identity")
    require(set(SOURCE_PATHS) == EXPECTED_SOURCES and len(SOURCE_PATHS) == 11,
            "producer source inventory changed")
    require(isinstance(source_hashes, dict) and set(source_hashes) == EXPECTED_SOURCES,
            "reinforcement source inventory missing/extra paths")
    for name, expected in source_hashes.items():
        require(hexadecimal(expected), "invalid source digest")
        raw = _read_regular(_source_path(repo_root, name), MAX_FILE_BYTES)
        require(hashlib.sha256(raw).hexdigest() == expected, "source digest mismatch: " + name)
    if expected_sha is not None:
        require(hexadecimal(expected_sha, 40) and source["commit"] == expected_sha
                and source["dirty"] is False, "expected clean source commit mismatch")
        identity = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD", "HEAD^{tree}"],
                                  capture_output=True, text=True, check=True, timeout=10)
        require(identity.stdout.splitlines() == [expected_sha, source["tree"]],
                "checked-out source identity mismatch")
        dirty = subprocess.run(["git", "-C", str(repo_root), "status", "--porcelain", "--untracked-files=normal"],
                               capture_output=True, text=True, check=True, timeout=10)
        require(not dirty.stdout, "expected source checkout is dirty")


def _non_authorizing(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"execution_authorized", "model_training"}:
                require(child is False, "reinforcement output improperly authorizing/training")
            _non_authorizing(child)
    elif isinstance(value, list):
        for child in value:
            _non_authorizing(child)


def verify_bundle(bundle: Path, *, repo_root: Path = ROOT, expected_source_sha: str | None = None,
                  expected_manifest_sha256: str | None = None,
                  contractgraph_root: Path | None = None) -> dict[str, Any]:
    bundle, repo_root = Path(bundle), Path(repo_root)
    require(bundle.is_dir() and not bundle.is_symlink(), "bundle directory missing or symlink")
    require({path.name for path in bundle.iterdir()} == PAYLOAD_NAMES | {"manifest.json"},
            "bundle contains missing/extra files")
    raw_manifest = _read_regular(bundle / "manifest.json", MAX_FILE_BYTES)
    manifest_sha = hashlib.sha256(raw_manifest).hexdigest()
    if expected_manifest_sha256 is not None:
        require(hexadecimal(expected_manifest_sha256) and manifest_sha == expected_manifest_sha256,
                "caller-supplied manifest SHA-256 mismatch")
    manifest = _json(raw_manifest)
    require(isinstance(manifest, dict) and set(manifest) == {"schema", "source", "files"}
            and manifest["schema"] == MANIFEST_SCHEMA, "invalid manifest schema/fields")
    files = manifest["files"]
    require(isinstance(files, list) and len(files) == len(PAYLOAD_NAMES), "manifest file inventory invalid")
    require(all(isinstance(item, dict) and set(item) == {"path", "size_bytes", "sha256"} for item in files),
            "invalid manifest file entry")
    require([item["path"] for item in files] == sorted(PAYLOAD_NAMES),
            "manifest paths must be the exact ordered payload inventory")
    payload, total = {}, len(raw_manifest)
    for item in files:
        name = item["path"]
        require(type(item["size_bytes"]) is int and item["size_bytes"] >= 0 and hexadecimal(item["sha256"]),
                "invalid manifest size/digest")
        raw = _read_regular(bundle / name, MAX_EXTERNAL_BYTES if name == "external-stop.json" else MAX_FILE_BYTES)
        total += len(raw)
        require(total <= MAX_TOTAL_BYTES, "bundle exceeds total byte bound")
        require(len(raw) == item["size_bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"],
                "manifest byte/digest mismatch: " + name)
        payload[name] = raw
    documents = {name: _json(raw) for name, raw in payload.items() if name.endswith(".json")}
    summary = documents["report.json"]
    require(isinstance(summary, dict), "invalid reinforcement report")
    _check_source(summary.get("source"), summary.get("source_files_sha256"), repo_root, expected_source_sha)
    external = documents["external-stop.json"]
    require(isinstance(external, dict), "invalid raw external report")
    _same(manifest["source"], external.get("source"), "manifest/external source mismatch")
    _same(summary["source"], external.get("source"), "summary/external source mismatch")
    raw_external_sha = hashlib.sha256(payload["external-stop.json"]).hexdigest()
    require(summary.get("external_report_sha256") == raw_external_sha, "raw external report digest mismatch")
    # The raw public signatures, inventories and sources are checked anew.
    verification = verify_report(external, repo_root=repo_root, expected_source_sha=expected_source_sha,
                                 contractgraph_root=contractgraph_root)
    cached = documents["external-verification.json"]
    require(isinstance(cached, dict), "invalid cached external verification")
    _same({k: v for k, v in cached.items() if k != "contractgraph_qa"},
          {k: v for k, v in verification.items() if k != "contractgraph_qa"},
          "cached external verification core differs from raw evidence")
    if contractgraph_root is not None:
        _same(cached.get("contractgraph_qa"), verification["contractgraph_qa"],
              "cached oracle differs from independently rerun oracle")
    else:
        require(isinstance(cached.get("contractgraph_qa"), dict)
                and cached["contractgraph_qa"].get("execution_authorized") is False,
                "invalid cached oracle scope")
    design = _json(_read_regular(_source_path(repo_root,
        "experiments/agent_control/preregistration_reinforcement.json"), MAX_FILE_BYTES))
    require(isinstance(design, dict) and design.get("experiment_id") == SCHEMA
            and type(design.get("model_calls_budget")) is int and design["model_calls_budget"] == 0
            and design.get("model_training") is False and design.get("live_internet") is False,
            "invalid offline preregistration")
    _same(design.get("scenario_ids"), list(CASE_IDS), "predeclared 19-case matrix changed")
    _same(design.get("positive_examples"), list(POSITIVE_IDS), "predeclared six positive cases changed")
    _same(design.get("expected_status"), EXPECTED_STATUS, "predeclared assessment statuses changed")
    contract = default_contract()
    _same(documents["contract.json"], contract, "contract differs from current frozen contract")
    episodes = build_episodes(external, raw_external_sha)
    comparisons = build_comparisons(contract, episodes)
    _same([item["case_id"] for item in comparisons], list(CASE_IDS), "builder differs from predeclared case matrix")
    _same(documents["episodes.json"], episodes, "episodes do not replay from raw verified evidence")
    _same(documents["candidates.json"], comparisons, "candidates differ from bounded scripted matrix")
    assessments = [{"case_id": item["case_id"], "episode_id": item["episode_id"],
        "assessment": assess(contract, episodes[item["episode_id"]]["episode"], item["candidate"])}
        for item in comparisons]
    _same(documents["assessments.json"], assessments, "assessments do not replay from bound episodes/candidates")
    examples = []
    for item in assessments:
        result = item["assessment"]
        require(result["execution_authorized"] is False and result["model_training"] is False
                and result["status"] == EXPECTED_STATUS[item["case_id"]], "invalid offline assessment")
        require((result["learning_record"] is not None) == (item["case_id"] in POSITIVE_IDS),
                "positive preference membership mismatch")
        if result["hard_violations"]:
            require(result["learning_record"] is None, "hard violation produced a positive example")
        if item["case_id"] in {"unsafe_baseline", "retry_unknown", "ignore_stop"}:
            require(bool(result["hard_violations"]), "predeclared hard violation lost")
        if result["learning_record"] is not None:
            examples.append(result["learning_record"])
    require(len(examples) == 6, "positive example count differs from six")
    expected_jsonl = "".join(json.dumps(item, sort_keys=True, allow_nan=False) + "\n" for item in examples).encode()
    require(payload["positive-examples.jsonl"] == expected_jsonl, "positive JSONL differs from exact replay")
    expected_summary = {"schema": SCHEMA, "source": external["source"],
        "source_files_sha256": summary["source_files_sha256"], "external_report_sha256": raw_external_sha,
        "external_verification_status": verification["status"], "preregistration": design,
        "cases": len(assessments), "positive_examples": len(examples),
        "negative_comparisons": len(assessments) - len(examples), "execution_authorized": False,
        "model_training": False, "candidate_scope": "scripted_structured_response_preferences",
        "delivery_scope": "scripted_slots_over_real_process_evidence",
        "checkpoint_scope": verification["checkpoint_verification_status"]}
    _same(summary, expected_summary, "reinforcement summary differs from replay")
    for value in (summary, contract, comparisons, assessments, examples, cached):
        _non_authorizing(value)
    return {"schema": VERIFICATION_SCHEMA, "status": "PASS", "source": external["source"],
        "manifest_sha256": manifest_sha, "external_report_sha256": raw_external_sha,
        "manifest_scope": "caller_supplied_digest" if expected_manifest_sha256 is not None else "bundle_consistency_only",
        "source_identity_scope": "expected_clean_commit" if expected_source_sha is not None else "input_hashes_with_reported_identity",
        "files_verified": len(files), "source_files_verified": len(EXPECTED_SOURCES),
        "cases_verified": list(CASE_IDS), "positive_examples_verified": len(examples),
        "execution_authorized": False, "model_training": False,
        "external_verification": verification,
        "limits": ["Manifest hashes alone do not authenticate the collector or establish omitted-effect completeness.",
            "Scripted delivery slots and response preferences are replayed; no live agent or model training is measured.",
            "External authority pin and latest-anchor trust scopes remain those of the freshly verified evidence."]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-manifest-sha256", help="Digest obtained independently of this bundle.")
    parser.add_argument("--contractgraph-root", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_bundle(args.bundle, expected_source_sha=args.expected_source_sha,
            expected_manifest_sha256=args.expected_manifest_sha256, contractgraph_root=args.contractgraph_root)
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"schema": VERIFICATION_SCHEMA, "status": "FAIL", "execution_authorized": False,
                          "model_training": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
