"""Exercise trusted CLI ownership with local subprocesses, without a Docker daemon."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

from adapters.docker.liminal_docker_executor import (
    DockerExecutionError,
    DockerExecutionTimeout,
    DockerExecutor,
    DockerOutputLimitError,
    run_docker_plan,
)
from adapters.packages.liminal_wheel_docker_backend import (
    MAX_RECEIPT_STDOUT_BYTES,
    WheelDockerBackendError,
    WheelMaterializingDockerExecutor,
)
from adapters.packages.liminal_wheel_materializer import (
    WheelMaterializationReceipt,
    canonical_sha256,
)
from sdk.liminal_isolated_execution import IsolatedExecutionPlan
from sdk.liminal_package_install_broker import (
    PackageInstallBroker,
    PackageWorkspaceBinding,
)


FAKE_CLI = r'''
import json
from pathlib import Path
import sys
import time

root = Path(__file__).parent
args = sys.argv[1:]
behavior = json.loads((root / "behavior.json").read_text())
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\n")
if args[0] == "run":
    name = args[args.index("--name") + 1]
    marker = root / name
    marker.touch()
    if behavior.get("stderr_bytes"):
        sys.stderr.buffer.write(b"e" * behavior["stderr_bytes"])
        sys.stderr.buffer.flush()
    output = root / "receipt.bin"
    data = output.read_bytes() if output.exists() else b"x" * behavior.get("stdout_bytes", 0)
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    time.sleep(behavior.get("delay", 0))
    if not behavior.get("survivor"):
        marker.unlink(missing_ok=True)
    sys.exit(behavior.get("exit_code", 0))
name = args[-1]
marker = root / name
if args[0] == "rm":
    if behavior.get("removal_fails"):
        sys.stderr.write("synthetic daemon removal failure")
        sys.exit(1)
    marker.unlink(missing_ok=True)
    sys.exit(0)
if args[0] == "inspect":
    if behavior.get("inspect_fails"):
        sys.stderr.write("synthetic daemon unavailable")
        sys.exit(1)
    if marker.exists():
        sys.exit(0)
    sys.stderr.write("Error: No such container: " + name)
    sys.exit(1)
sys.exit(2)
'''


class DockerAdapterLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "fake-docker"
        self.binary.write_text(f"#!{sys.executable}\n" + FAKE_CLI)
        self.binary.chmod(0o700)
        self.configure()

    def configure(self, **values):
        (self.root / "behavior.json").write_text(json.dumps(values))

    def plan(self, *, timeout=2):
        return IsolatedExecutionPlan.build(
            operation_id="local-cli-regression",
            image_id="sha256:" + "a" * 64,
            argv=("/bin/true",),
            host_workspace=str(self.root),
            timeout_seconds=timeout,
        )

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def assert_named_cleanup(self):
        calls = self.calls()
        run = next(call for call in calls if call[0] == "run")
        name = run[run.index("--name") + 1]
        self.assertIn(["rm", "-f", name], calls)
        self.assertEqual(calls[-1], ["inspect", name])
        self.assertFalse((self.root / name).exists())

    def wheel_plan(self, *, timeout=2):
        binding = PackageWorkspaceBinding.build(
            binding_id="fixture-wheel",
            host_workspace=str(self.root),
            registry="pypi.org",
            package_name="demo-pkg",
            version="1.2.3",
            artifact_sha256="1" * 64,
            dependency_plan_sha256="2" * 64,
            staged_manifest_sha256="3" * 64,
            dependency_count=0,
            installer_image_id="sha256:" + "a" * 64,
        )
        return IsolatedExecutionPlan.build(
            operation_id="wheel-cli-regression",
            image_id=binding.installer_image_id,
            argv=PackageInstallBroker._installer_argv(binding),
            host_workspace=str(self.root),
            timeout_seconds=timeout,
        )

    def test_exact_stdout_limit_and_large_stderr_complete(self):
        self.configure(stdout_bytes=65536, stderr_bytes=1024 * 1024)
        result = run_docker_plan(self.plan(), docker_binary=str(self.binary), stdout_limit=65536)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"x" * 65536)
        self.assertFalse((self.root / result.session_id).exists())
        self.assertEqual(self.calls()[-1], ["inspect", result.session_id])

    def test_stdout_overflow_aborts_and_removes_exact_session(self):
        self.configure(stdout_bytes=65537, delay=10)
        with self.assertRaises(DockerOutputLimitError):
            run_docker_plan(self.plan(), docker_binary=str(self.binary), stdout_limit=65536)
        self.assert_named_cleanup()

    def test_timeout_removes_session_for_captured_and_discarded_output(self):
        for limit in (None, 1024):
            with self.subTest(stdout_limit=limit):
                self.configure(delay=10)
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                with self.assertRaises(DockerExecutionTimeout):
                    run_docker_plan(self.plan(timeout=1), docker_binary=str(self.binary), stdout_limit=limit)
                self.assert_named_cleanup()

    def test_completed_client_with_surviving_session_is_not_success(self):
        self.configure(survivor=True)
        with self.assertRaisesRegex(DockerExecutionError, "surviving execution session"):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assert_named_cleanup()

    def test_failed_removal_is_not_reported_as_verified_cleanup(self):
        self.configure(survivor=True, removal_fails=True)
        with self.assertRaisesRegex(DockerExecutionError, "failed to terminate"):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assertEqual(self.calls()[-1][0], "rm")

    def test_unavailable_inspection_does_not_attest_absence(self):
        self.configure(inspect_fails=True)
        with self.assertRaisesRegex(DockerExecutionError, "survivor verification"):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assertTrue(any(call[0] == "rm" for call in self.calls()))

    def test_discarded_workload_output_preserves_executor_observation(self):
        self.configure(stdout_bytes=1024 * 1024, stderr_bytes=1024 * 1024, exit_code=7)
        result = DockerExecutor(docker_binary=str(self.binary))(self.plan())
        self.assertEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(self.calls()[-1][0], "inspect")

    def test_wheel_timeout_uses_the_same_verified_cleanup(self):
        self.configure(delay=10)
        with self.assertRaisesRegex(WheelDockerBackendError, "container_timeout"):
            WheelMaterializingDockerExecutor(str(self.binary))(self.wheel_plan(timeout=1))
        self.assert_named_cleanup()

    def test_wheel_overflow_uses_the_same_verified_cleanup(self):
        self.configure(stdout_bytes=MAX_RECEIPT_STDOUT_BYTES + 1, delay=10)
        with self.assertRaisesRegex(WheelDockerBackendError, "receipt_too_large"):
            WheelMaterializingDockerExecutor(str(self.binary))(self.wheel_plan())
        self.assert_named_cleanup()

    def test_wheel_accepts_bound_receipt_after_session_is_absent(self):
        receipt = WheelMaterializationReceipt(
            artifact_sha256="1" * 64,
            staged_manifest_sha256="3" * 64,
            dependency_plan_sha256="2" * 64,
            wheel_audit_sha256="4" * 64,
            package_coordinate_sha256=canonical_sha256({"registry": "pypi.org", "package_name": "demo-pkg", "version": "1.2.3"}),
            output_manifest_sha256="5" * 64,
            file_count=4,
            total_bytes=100,
            outcome="SUCCEEDED",
            receipt_sha256="",
        )
        body = receipt.body()
        (self.root / "receipt.bin").write_text(json.dumps({**body, "receipt_sha256": canonical_sha256(body)}) + "\n")
        result = WheelMaterializingDockerExecutor(str(self.binary))(self.wheel_plan())
        self.assertEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(self.calls()[-1][0], "inspect")

    def test_invalid_output_budget_does_not_spawn_cli(self):
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(DockerExecutionError):
                run_docker_plan(self.plan(), docker_binary=str(self.binary), stdout_limit=limit)
        self.assertFalse((self.root / "calls.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
