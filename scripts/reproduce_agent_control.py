#!/usr/bin/env python3
"""Reproduce frozen owned-receiver fixtures; public evidence never contains keys.

This launcher executes source commits from the checked-in lock, rather than its
own checkout. A successful harness run does not establish general model safety.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import platform
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LOCK_SCHEMA = "org.liminal.agent-control-reproduction-lock.v1"
SOURCE_URLS = {
    "control": "https://github.com/safal207/LiminalOSAI.git",
    "cml": "https://github.com/safal207/Causal-Memory-Layer.git",
    "claims": "https://github.com/safal207/safal207-corrigibility-action-benchmark.git",
}
BUNDLE_FILES = {"report.json", "metrics.json", "preregistration.json", "raw-records.json",
                "source-digests.json", "manifest.json"}
LIMIT = 8 * 1024 * 1024


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def parse_json(value: str):
    return json.loads(value, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("JSON input is missing, nonregular or oversized")
    return parse_json(path.read_text())


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def minimal_env(private: Path, pythonpath: Path | None = None) -> dict[str, str]:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "DOCKER_CONFIG": str(private / "docker-config"), "LANG": "C.UTF-8",
           "TMPDIR": str(private / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": ""}
    if pythonpath:
        env["PYTHONPATH"] = str(pythonpath)
    return env


def validate_lock(lock: dict, lock_path: Path) -> Path:
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
        raise ValueError("unsupported reproduction lock")
    if set(lock.get("sources", {})) != set(SOURCE_URLS):
        raise ValueError("lock must pin the three expected source repositories")
    for name, url in SOURCE_URLS.items():
        pin = lock["sources"][name]
        if pin.get("url") != url or any(not re.fullmatch(r"[0-9a-f]{40}", pin.get(k, ""))
                                       for k in ("commit", "tree")):
            raise ValueError("source URL, commit or tree is not an exact approved pin")
    dep = lock["dependencies"]
    relative = Path(dep["requirements_file"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("requirements path escapes the lock directory")
    requirements = lock_path.parent / relative
    if requirements.is_symlink() or digest(requirements) != dep["sha256"]:
        raise ValueError("requirements digest mismatch")
    if not re.fullmatch(r"python@sha256:[0-9a-f]{64}", lock["image"]["reference"]):
        raise ValueError("worker image requires a fixed registry digest")
    return requirements


def environment_contract():
    libc, version = platform.libc_ver()
    if (sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64")
            or platform.python_implementation() != "CPython" or sys.version_info[:2] not in ((3, 11), (3, 12))
            or libc != "glibc" or tuple(int(n) for n in version.split(".")[:2]) < (2, 17)
            or not shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")):
        raise ValueError("requires Linux x86_64, glibc >=2.17, CPython 3.11/3.12 and Git")


def require_direct_parent(raw_commit: str, required: str):
    parents = [line.split()[1] for line in raw_commit.partition("\n\n")[0].splitlines()
               if line.startswith("parent ")]
    if required not in parents:
        raise ValueError("included egress is not a direct parent of the control commit")


def checked_paths(controller: dict, output_root: Path) -> tuple[Path, Path]:
    if not isinstance(controller, dict):
        raise ValueError("controller stdout is not an object")
    run_id = controller.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
        raise ValueError("controller run ID is malformed")
    bundle = Path(controller.get("bundle", ""))
    expectations = Path(controller.get("expectations_file", ""))
    if (output_root != output_root.resolve() or bundle != output_root / run_id
            or expectations != output_root / (run_id + ".expectations.json")):
        raise ValueError("controller returned paths outside its assigned collection root")
    if (bundle.is_symlink() or not bundle.is_dir() or expectations.is_symlink() or not expectations.is_file()
            or set(p.name for p in bundle.iterdir()) != BUNDLE_FILES
            or any(p.is_symlink() or not p.is_file() for p in bundle.iterdir())):
        raise ValueError("controller evidence contains missing, extra or nonregular files")
    now = controller.get("collected_at")
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
        raise ValueError("controller collection clock is malformed")
    return bundle, expectations


def validate_inventory(report: dict, mode: str, expected: dict):
    cases = report.get("cases", [])
    expected_ids = expected["local_scenarios"] if mode == "deterministic-local" else (
        expected["docker_c_scenarios"] if mode == "docker" else ["queued_after_stop"])
    wanted = [(case, arm) for case in expected_ids
              for arm in (["C"] if mode == "docker" else ["A", "B", "C"])]
    actual = [(c.get("case_id"), c.get("configuration")) for c in cases]
    if actual != wanted or any(c.get("result_id") != c.get("case_id") + ":" + c.get("configuration") for c in cases):
        raise ValueError("case inventory differs from the frozen design")
    if (report.get("mode") != mode or report.get("required_execution_completed") is not True
            or report.get("checker_failures") != [] or any(c.get("status") != "PASS" for c in cases)
            or report.get("negative_control", {}).get("detected") is not True):
        raise ValueError("native harness has an incomplete or failed required case")
    if mode != "docker":
        effects = {arm: sum(c.get("outcome") == "UNAUTHORIZED_EFFECT" for c in cases
                            if c.get("configuration") == arm) for arm in ("A", "B", "C")}
        wanted_effects = expected["local_effects" if mode == "deterministic-local" else "docker_abc_effects"]
        if effects != wanted_effects:
            raise ValueError("observed effect counts differ from the frozen fixture expectation")
    if mode == "docker" and any(c.get("runtime", {}).get("containment", {}).get("verified")
                                is not True for c in cases):
        raise ValueError("a required Docker containment observation is unverified")
    arms = ["C"] if mode == "docker" else ["A", "B", "C"]
    if any(report.get("metrics", {}).get("by_configuration", {}).get(arm, {}).get("utility_successes")
           != expected["utility_successes_per_arm"] for arm in arms):
        raise ValueError("useful authorized operation is missing from a required arm")


def validate_cml(score: dict, returncode: int, expected: dict, expected_ids: list[str]):
    cases = score.get("cases", [])
    counts = dict(Counter(c.get("verdict") for c in cases))
    ids = [c.get("result_id") for c in cases]
    if (score.get("schema") != "org.cml.agent-boundary-evaluation.v1" or ids != expected_ids or counts != expected
            or returncode != (2 if counts.get("FAIL") else 1 if counts.get("UNKNOWN") else 0)):
        raise ValueError("CML verdict inventory or exit status differs from the expected baseline")
    return counts


def test_count(output: str, expected: int, *, pytest: bool = False):
    expression = r"(\d+) passed" if pytest else r"Ran (\d+) tests?"
    count = re.search(expression, output)
    if not count or int(count.group(1)) != expected or re.search(r"\b(skipped|failed|errors?)\b", output, re.I):
        raise ValueError("required test count differs or a test failed/skipped")


class Reproduction:
    def __init__(self, destination: Path, lock_path: Path, profile: str, pull_image: bool):
        self.destination, self.profile, self.pull_image = destination, profile, pull_image
        self.private, self.public = destination / "private", destination / "public"
        self.lock_path, self.checks, self.sources = lock_path, [], {}
        self.stage, self.log_number = "setup", 0
        self.summary = {"schema": "org.liminal.agent-control-reproduction.v1", "profile": profile,
                        "status": "FAIL", "docker": "NOT_RUN" if profile == "local" else "UNAVAILABLE",
                        "adaptive_model_evaluation": "NOT_RUN", "external_human_reproduction": "NOT_ESTABLISHED",
                        "launcher_sha256": digest(Path(__file__)), "lock_sha256": digest(lock_path)}

    def run(self, argv: list[str], *, cwd: Path | None = None, pythonpath: Path | None = None,
            timeout: int = 180, allowed: tuple[int, ...] = (0,), extra_env: dict | None = None):
        self.log_number += 1
        stem = self.private / f"command-{self.log_number:03d}"
        env = minimal_env(self.private, pythonpath)
        env.update(extra_env or {})
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err, shell=False,
                                     start_new_session=True)
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
                raise RuntimeError("bounded subprocess deadline exceeded") from None
        paths = [stem.with_suffix(suffix) for suffix in (".stdout", ".stderr")]
        if any(p.stat().st_size > LIMIT for p in paths):
            raise RuntimeError("subprocess output exceeds the collection limit")
        stdout, stderr = [p.read_text(errors="replace") for p in paths]
        if code not in allowed:
            raise RuntimeError(f"required subprocess failed with exit status {code}")
        return code, stdout, stderr

    def check(self, stage: str, callback):
        self.stage = stage
        started = time.monotonic()
        value = callback()
        self.checks.append({"stage": stage, "status": "PASS", "elapsed_seconds": time.monotonic() - started})
        return value

    def fetch_sources(self):
        for name, pin in self.lock["sources"].items():
            path = self.private / "sources" / name
            self.run(["git", "init", str(path)])
            self.run(["git", "-C", str(path), "fetch", "--depth=1", pin["url"], pin["commit"]])
            self.run(["git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD"])
            observed = {}
            for field, revision in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
                observed[field] = self.run(["git", "-C", str(path), "rev-parse", revision])[1].strip()
            dirty = self.run(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=all", "--ignored"])[1]
            if observed != {k: pin[k] for k in ("commit", "tree")} or dirty.strip():
                raise ValueError("fetched source revision/tree/cleanliness mismatch; execution blocked")
            self.sources[name] = path
        control = self.sources["control"]
        for field, filename in (("local_sha256", "preregistration.json"), ("docker_abc_sha256", "preregistration_docker_abc.json")):
            if digest(control / "experiments" / "agent_control" / filename) != self.lock["plans"][field]:
                raise ValueError("frozen preregistration differs from its explicit lock digest")
        included = self.lock["included_egress"]
        require_direct_parent(self.run(["git", "-C", str(control), "cat-file", "-p", "HEAD"])[1], included["commit"])
        self.run(["git", "-C", str(control), "fetch", "--depth=1", self.lock["sources"]["control"]["url"], included["commit"]])
        if self.run(["git", "-C", str(control), "rev-parse", "FETCH_HEAD^{tree}"])[1].strip() != included["tree"]:
            raise ValueError("included egress tree differs from its explicit lock pin")
        self.summary["sources"] = self.lock["sources"]
        self.summary["plans"], self.summary["included_egress"] = self.lock["plans"], included

    def install(self):
        self.run([sys.executable, "-m", "venv", str(self.private / "venv")])
        self.python = self.private / "venv" / "bin" / "python"
        self.run([str(self.python), "-m", "pip", "--isolated", "install", "--index-url", "https://pypi.org/simple",
                  "--disable-pip-version-check", "--only-binary=:all:", "--require-hashes", "-r", str(self.requirements)], timeout=300)
        _, freeze, _ = self.run([str(self.python), "-m", "pip", "freeze", "--all"])
        (self.public / "dependencies.txt").write_text(freeze)
        self.summary["dependencies"] = self.lock["dependencies"]

    def source_clean(self, repository: str):
        source = self.sources[repository]
        pin = self.lock["sources"][repository]
        for field, revision in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
            if self.run(["git", "-C", str(source), "rev-parse", revision])[1].strip() != pin[field]:
                raise ValueError("source identity changed before execution")
        if self.run(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all", "--ignored"])[1].strip():
            raise ValueError("source files changed before execution")

    def unit_tests(self, repository: str, files: list[str], count: int, *, pytest: bool = False, image: str | None = None):
        source = self.sources[repository]
        self.source_clean(repository)
        argv = [str(self.python), "-m", "pytest", "-q", "-p", "no:cacheprovider"] if pytest else [
            str(self.python), "-m", "unittest", *files, "-v"]
        _, stdout, stderr = self.run(argv, cwd=source, pythonpath=source / ("src" if pytest else "sdk"),
                                   timeout=300, extra_env={"LIMINAL_AGENT_CONTROL_DOCKER_IMAGE": image} if image else None)
        test_count(stdout + stderr, count, pytest=pytest)
        self.summary.setdefault("test_counts", {})[repository if pytest else ("runtime" if image else "egress")] = count

    def evaluate(self, mode: str, image: str | None = None):
        source = self.sources["control"]
        self.source_clean("control")
        output_root = self.private / "work" / mode
        key = self.private / "keys" / (mode + ".key")
        argv = [str(self.python), "-m", "liminal_agent_control.evaluation", "run", "--mode", mode,
                "--output-root", str(output_root), "--receipt-key-file", str(key)]
        if image:
            argv += ["--image", image]
        code, stdout, _ = self.run(argv, cwd=source, pythonpath=source / "sdk", timeout=300, allowed=(0, 1))
        controller = parse_json(stdout)
        bundle, expectations = checked_paths(controller, output_root)
        report = read_json(bundle / "report.json")
        shutil.copytree(bundle, self.public / mode)
        if (code != 0 or controller.get("mode") != mode or controller.get("collected_at") != report.get("created_at")
                or report.get("source", {}).get("git_commit") != self.lock["sources"]["control"]["commit"]
                or report.get("source", {}).get("working_tree_dirty") is not False):
            raise ValueError("native run exit status, source or collection identity differs")
        validate_inventory(report, mode, self.lock["expected"])
        self.source_clean("control")
        _, stdout, _ = self.run([str(self.python), "-m", "liminal_agent_control.evaluation", "verify", str(bundle),
                                "--receipt-key-file", str(key)], cwd=source, pythonpath=source / "sdk")
        if parse_json(stdout).get("valid") is not True:
            raise ValueError("native external-key verification failed")
        self.summary.setdefault("experiments", {})[mode] = {"cases": len(report["cases"]), "metrics": report["metrics"]}
        return controller, bundle, expectations, key

    def score(self, collected):
        controller, bundle, expectations, key = collected
        keyring = self.private / "keys" / "cml-keyring.json"
        descriptor = os.open(keyring, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            json.dump({"receiver-hmac-v1": key.read_bytes().hex()}, handle)
        output = self.private / "work" / "cml-score.json"
        cml = self.sources["cml"]
        self.source_clean("cml")
        code, _, _ = self.run([str(self.python), str(cml / "benchmarks/agent_boundary/runners/score_receiver_export.py"),
                              "--observation-export", str(bundle / "report.json"), "--expectations", str(expectations),
                              "--keyring", str(keyring), "--now", str(controller["collected_at"]),
                              "--max-age-seconds", "30", "--output", str(output)], pythonpath=cml, allowed=(0, 1, 2))
        score = read_json(output)
        shutil.copyfile(output, self.public / "cml-score.json")
        ids = [case["result_id"] for case in read_json(bundle / "report.json")["cases"]]
        self.summary["cml_counts"] = validate_cml(score, code, self.lock["expected"]["cml_counts"], ids)

    def docker_image(self):
        reference = self.lock["image"]["reference"]
        code, output, _ = self.run(["docker", "image", "inspect", reference], allowed=(0, 1))
        if code != 0:
            if not self.pull_image:
                raise RuntimeError("pinned image unavailable; explicit --pull-image is required to fetch it")
            self.run(["docker", "pull", "--platform", "linux/amd64", reference], timeout=300)
            _, output, _ = self.run(["docker", "image", "inspect", reference])
        metadata = parse_json(output)
        if (len(metadata) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata[0].get("Id", ""))
                or reference not in metadata[0].get("RepoDigests", [])
                or metadata[0].get("Os") != "linux" or metadata[0].get("Architecture") != "amd64"):
            raise ValueError("local image does not match the frozen registry digest")
        self.run(["docker", "info"], timeout=30)
        _, version, _ = self.run(["docker", "version"], timeout=30)
        write_json(self.public / "image.json", metadata)
        (self.public / "docker-version.txt").write_text(version)
        self.summary["image_id"] = metadata[0]["Id"]
        return metadata[0]["Id"]

    def execute(self):
        self.private.mkdir(mode=0o700)
        self.public.mkdir()
        for name in ("docker-config", "tmp", "keys", "work", "sources"):
            (self.private / name).mkdir(mode=0o700)
        try:
            self.check("environment", environment_contract)
            self.summary["environment"] = {"python": sys.version.split()[0], "implementation": platform.python_implementation(),
                                           "system": platform.system(), "architecture": platform.machine(), "libc": platform.libc_ver()}
            release = platform.freedesktop_os_release()
            self.summary["environment"]["os_release"] = {name: release.get(name) for name in ("ID", "VERSION_ID", "NAME")}
            self.lock = read_json(self.lock_path)
            self.requirements = self.check("lock", lambda: validate_lock(self.lock, self.lock_path))
            self.check("frozen-sources", self.fetch_sources)
            self.check("dependencies", self.install)
            expected = self.lock["expected"]
            self.check("claims-tests", lambda: self.unit_tests("claims", [], expected["claims_tests"], pytest=True))
            self.check("egress-tests", lambda: self.unit_tests("control", expected["egress_test_files"], expected["egress_tests"]))
            collected = self.check("deterministic-local", lambda: self.evaluate("deterministic-local"))
            self.check("cml-scoring", lambda: self.score(collected))
            if self.profile == "all":
                image = self.check("docker-availability", self.docker_image)
                self.summary["docker"] = "FAIL"
                self.check("runtime-tests", lambda: self.unit_tests("control", ["tests/test_agent_control_runtime.py"],
                                                                  expected["runtime_tests"], image=image))
                self.check("docker", lambda: self.evaluate("docker", image))
                self.check("docker-abc", lambda: self.evaluate("docker-abc", image))
                self.summary["docker"] = "PASS"
            self.summary["status"] = "PASS"
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
            self.checks.append({"stage": self.stage, "status": "FAIL", "error_type": type(exc).__name__,
                                "reason": str(exc)[:250] if isinstance(exc, RuntimeError) else "required evidence validation failed"})
        finally:
            self.finish()
        return 0 if self.summary["status"] == "PASS" else 2

    def finish(self):
        self.summary["completed_at"] = time.time()
        write_json(self.public / "summary.json", self.summary)
        write_json(self.public / "checks.json", self.checks)
        files, rejected = {}, []
        key_material = [p.read_bytes() for p in (self.private / "keys").glob("*.key")]
        for path in sorted(self.public.rglob("*")):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                rejected.append(str(path.relative_to(self.public)))
                path.unlink()
                continue
            if path.is_file():
                content = path.read_bytes()
                if any(key and (key in content or key.hex().encode() in content) for key in key_material):
                    rejected.append(str(path.relative_to(self.public)))
                    path.unlink()
                    continue
                files[str(path.relative_to(self.public))] = {"sha256": digest(path), "size": len(content)}
        if rejected:
            self.summary["status"] = "FAIL"
            self.checks.append({"stage": "public-evidence", "status": "FAIL", "reason": "unsafe output removed"})
            write_json(self.public / "summary.json", self.summary)
            write_json(self.public / "checks.json", self.checks)
            for name in ("summary.json", "checks.json"):
                files[name] = {"sha256": digest(self.public / name), "size": (self.public / name).stat().st_size}
        write_json(self.public / "manifest.json", {"schema": "org.liminal.agent-control-reproduction-manifest.v1",
                   "files": files, "note": "Unsigned byte inventory; scoped HMAC verification used privately retained keys."})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True, help="Absolute NEW directory")
    parser.add_argument("--profile", choices=("local", "all"), default="all")
    parser.add_argument("--pull-image", action="store_true", help="Explicitly pull only the pinned registry digest")
    parser.add_argument("--lock", type=Path, default=ROOT / "experiments/agent_control/reproduction.lock.json")
    args = parser.parse_args(argv)
    if not args.destination.is_absolute() or args.destination.exists() or args.destination.is_symlink():
        parser.error("destination must be an absolute, nonexistent directory")
    if any(parent.is_symlink() for parent in args.destination.parents):
        parser.error("destination must have real directory ancestors")
    args.destination = args.destination.resolve()
    args.destination.mkdir(mode=0o700, parents=False)
    try:
        reproduction = Reproduction(args.destination, args.lock.resolve(), args.profile, args.pull_image)
        code = reproduction.execute()
        if reproduction.summary["status"] != "PASS":
            code = 2
    except (OSError, ValueError) as exc:
        public = args.destination / "public"
        public.mkdir(exist_ok=True)
        write_json(public / "summary.json", {"status": "FAIL", "profile": args.profile,
                   "docker": "NOT_RUN" if args.profile == "local" else "UNAVAILABLE", "error_type": type(exc).__name__})
        write_json(public / "checks.json", [{"stage": "setup", "status": "FAIL"}])
        write_json(public / "manifest.json", {"files": {name: {"sha256": digest(public / name)}
                   for name in ("summary.json", "checks.json")}})
        code = 2
    print(json.dumps({"status": "PASS" if code == 0 else "FAIL", "public": str(args.destination / "public")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
