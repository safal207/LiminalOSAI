"""Run and verify the owned, scripted multi-worker experiment.

No model calls, sockets, containers or external credentials are used. An external
controller key authenticates the collected report; it is never bundled. This is
shared-key evidence authentication, not public producer-independent attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from .authority import canonical_bytes, require_key, sign_document, verify_receipt
from .evaluation import _load_key

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "experiments/agent_control/preregistration_multi_agent.json"
SCHEMA = "liminal-agent-control-multi-agent-v1"
CASE_IDS = ("peer_grant_forgery", "forged_worker_report", "omitted_worker_effect",
            "revoked_fanout", "relay_egress")
FILES = frozenset({"report.json", "preregistration.json", "source-digests.json"})


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _write(path: Path, value: object) -> None:
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def _design() -> dict:
    design = json.loads(DESIGN.read_text())
    if (design.get("experiment_id") != SCHEMA or design.get("scenario_ids") != list(CASE_IDS)
            or design.get("model_calls_budget") != 0 or design.get("live_internet") is not False):
        raise ValueError("multi-agent design differs from executable contract")
    return design


def _source() -> dict:
    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                                capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "dirty": bool(git("status", "--porcelain")),
            "scope": "checked-out source; source-digests.json binds actual Python inputs"}


def _source_digests() -> dict:
    # Include transitive Python reference components, not just the new runner.
    paths = sorted((ROOT / "sdk").rglob("*.py")) + sorted((ROOT / "adapters").rglob("*.py"))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def run_suite(output_root: Path, receipt_key: bytes) -> dict:
    from .multi_agent_scenarios import run_protocol_scenarios
    from .multi_agent_relay import run_relay_scenario
    from .multi_agent_checks import check_cases
    require_key(receipt_key)
    design = _design()
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:12]
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    bundle = output_root / run_id
    bundle.mkdir()
    with tempfile.TemporaryDirectory(prefix="liminal-multi-agent-") as private:
        work = Path(private)
        cases = run_protocol_scenarios(work / "protocol", receipt_key)
        cases.append(run_relay_scenario(work / "relay", receipt_key))
    checks = check_cases(cases, receipt_key)
    sources = _source_digests()
    report = sign_document({"schema": SCHEMA, "run_id": run_id,
        "mode": "deterministic-multi-agent", "created_at": time.time(),
        "source": _source(), "cases": cases, "checks": checks,
        "design_digest": hashlib.sha256(canonical_bytes(design)).hexdigest(),
        "source_digests_digest": hashlib.sha256(canonical_bytes(sources)).hexdigest(),
        "execution": {"live_model": "NOT_RUN", "docker": "NOT_RUN",
            "external_network": "NOT_RUN", "external_human_reproduction": "NOT_ESTABLISHED"},
        "trust": {"collector": "trusted host fixture and independent receiver/sink observations",
            "worker_claims": "untrusted", "key_bundled": False,
            "key_id": hashlib.sha256(receipt_key).hexdigest(),
            "scope": "same-process scripted protocol sessions and offline callback transport",
            "authentication": "HMAC authenticates the collector to the key holder; not public attestation"}}, receipt_key)
    _write(bundle / "report.json", report)
    _write(bundle / "preregistration.json", design)
    _write(bundle / "source-digests.json", sources)
    manifest = {"schema": SCHEMA + ".manifest", "run_id": run_id,
        "files": {name: {"sha256": hashlib.sha256((bundle / name).read_bytes()).hexdigest(),
                         "size": (bundle / name).stat().st_size} for name in sorted(FILES)}}
    _write(bundle / "manifest.json", manifest)
    return {"bundle": str(bundle.resolve()), "run_id": run_id,
            "report_sha256": hashlib.sha256((bundle / "report.json").read_bytes()).hexdigest(),
            "checks": checks, "source": report["source"]}


def verify_bundle(bundle: Path, receipt_key: bytes, *, expected_report_sha256: str | None = None) -> dict:
    """Verify bytes, collector authentication, exact design and recomputed checks.

    An optional out-of-band digest selects a particular run. Without that pin,
    an older authentic complete run is authentic but not proven current.
    """
    from .multi_agent_checks import check_cases
    require_key(receipt_key)
    bundle = Path(bundle)
    errors: list[str] = []
    try:
        if bundle.is_symlink() or not bundle.is_dir():
            raise ValueError("bundle must be a real directory")
        if {path.name for path in bundle.iterdir()} != FILES | {"manifest.json"}:
            raise ValueError("bundle inventory differs from the exact contract")
        if any(path.is_symlink() or not path.is_file() for path in bundle.iterdir()):
            raise ValueError("bundle members must be regular files")
        manifest = json.loads((bundle / "manifest.json").read_text())
        if (manifest.get("schema") != SCHEMA + ".manifest"
                or set(manifest.get("files", {})) != FILES):
            raise ValueError("invalid manifest contract")
        for name in FILES:
            raw = (bundle / name).read_bytes()
            if manifest["files"][name] != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
                errors.append("byte mismatch:" + name)
        report_bytes = (bundle / "report.json").read_bytes()
        if expected_report_sha256 is not None and hashlib.sha256(report_bytes).hexdigest() != expected_report_sha256:
            errors.append("externally pinned report digest mismatch")
        report = json.loads(report_bytes)
        if not verify_receipt(report, receipt_key):
            errors.append("collector authentication failed")
        if (report.get("schema") != SCHEMA or report.get("mode") != "deterministic-multi-agent"
                or not isinstance(report.get("run_id"), str) or not report["run_id"]
                or report["run_id"] != manifest.get("run_id")):
            errors.append("report identity mismatch")
        design = json.loads((bundle / "preregistration.json").read_text())
        sources = json.loads((bundle / "source-digests.json").read_text())
        source = report.get("source")
        if (not isinstance(source, dict) or not _hex(source.get("commit"), 40)
                or not _hex(source.get("tree"), 40) or type(source.get("dirty")) is not bool):
            errors.append("invalid source revision identity")
        if (not isinstance(sources, dict) or not sources or not all(
                isinstance(name, str) and name.startswith(("sdk/", "adapters/"))
                and ".." not in Path(name).parts and name.endswith(".py") and _hex(value, 64)
                for name, value in sources.items())):
            errors.append("invalid source digest inventory")
        if design != _design() or hashlib.sha256(canonical_bytes(design)).hexdigest() != report.get("design_digest"):
            errors.append("registered design mismatch")
        if hashlib.sha256(canonical_bytes(sources)).hexdigest() != report.get("source_digests_digest"):
            errors.append("source digests binding mismatch")
        if report.get("execution") != {"live_model": "NOT_RUN", "docker": "NOT_RUN",
                "external_network": "NOT_RUN", "external_human_reproduction": "NOT_ESTABLISHED"}:
            errors.append("execution scope mismatch")
        checks = check_cases(report["cases"], receipt_key)
        if checks != report.get("checks"):
            errors.append("recomputed checks differ from report")
        if checks.get("status") != "PASS":
            errors.append("experiment checks did not pass")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        errors.append("invalid evidence:" + type(exc).__name__)
    return {"valid": not errors, "errors": errors,
            "current_run_pinned": expected_report_sha256 is not None,
            "scope": "key-authenticated bounded fixture evidence, not public attestation"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--output-root", type=Path, required=True)
    run.add_argument("--receipt-key-file", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--receipt-key-file", type=Path, required=True)
    verify.add_argument("--expected-report-sha256")
    args = parser.parse_args(argv)
    try:
        public_root = args.output_root if args.command == "run" else args.bundle
        if args.receipt_key_file.resolve().is_relative_to(public_root.resolve()):
            raise ValueError("retain the authentication key outside the evidence tree")
        if args.command == "run":
            result = run_suite(args.output_root, _load_key(args.receipt_key_file, create=True))
            good = result["checks"].get("status") == "PASS"
        else:
            result = verify_bundle(args.bundle, _load_key(args.receipt_key_file, create=False),
                                   expected_report_sha256=args.expected_report_sha256)
            good = result["valid"]
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0 if good else 1
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(json.dumps({"status": "ERROR", "error_type": type(exc).__name__,
                          "detail": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
