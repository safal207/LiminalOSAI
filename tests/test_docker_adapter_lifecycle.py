"""Exercise trusted CLI ownership with local subprocesses, without a Docker daemon."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from adapters.docker._bounded_cli import OutputLimitExceeded
from adapters.docker.liminal_docker_executor import (
    DockerExecutionError,
    DockerExecutionTimeout,
    DockerExecutor,
    DockerOutputLimitError,
    DockerReconciliationRequired,
    DockerSessionIdentity,
    DockerProcessTreeBackend,
    _remove_container_verified,
    reconcile_docker_session,
    run_docker_plan,
)
from adapters.packages.liminal_wheel_docker_backend import (
    MAX_RECEIPT_STDOUT_BYTES,
    WheelDockerBackendError,
    WheelDockerOutcomeUnknown,
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
from sdk.liminal_runtime_mediation import ExecutionOutcomeUnknown


FAKE_CLI = r'''
import hashlib
import json
from pathlib import Path
import signal
import os
import sys
import time

root = Path(__file__).parent
args = sys.argv[1:]
behavior = json.loads((root / "behavior.json").read_text())
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\n")
objects = root / "objects"
objects.mkdir(exist_ok=True)
if args[0] == "info":
    if behavior.get("daemon_unavailable"):
        sys.exit(1)
    print(behavior.get("daemon_id", "owned-daemon-1"))
    sys.exit(0)
if args[0] == "create":
    name = args[args.index("--name") + 1]
    image = next(arg for arg in args if arg.startswith("sha256:"))
    plan = next(arg.split("=", 1)[1] for arg in args if arg.startswith("org.liminal.plan="))
    cid = hashlib.sha256(name.encode()).hexdigest()
    obj = {"id": cid, "name": "/" + name, "image": image, "session": name, "plan": plan,
           "status": "created", "running": False, "exit_code": 0}
    (objects / cid).write_text(json.dumps(obj))
    time.sleep(behavior.get("create_delay", 0))
    print(cid)
    sys.exit(0)
reference = args[-1]
path = objects / reference
if not path.exists():
    path = next((p for p in objects.iterdir() if json.loads(p.read_text())["name"] == "/" + reference), path)
if args[0] == "inspect":
    if behavior.get("inspect_fails"):
        sys.stderr.write("synthetic daemon unavailable")
        sys.exit(1)
    if not path.exists():
        sys.stderr.write("Error: No such container: " + reference)
        sys.exit(1)
    obj = json.loads(path.read_text())
    if "{{.State.Pid}}" in " ".join(args):
        print("123 true false")
    else:
        print(json.dumps(obj))
    sys.exit(0)
if args[0] == "rm":
    if behavior.get("removal_fails"):
        sys.stderr.write("synthetic daemon removal failure")
        sys.exit(1)
    path.unlink(missing_ok=True)
    sys.exit(0)
if args[0] == "top":
    print("UID PID PPID CMD\nroot 123 1 fixture")
    sys.exit(0)
if args[0] == "pause":
    sys.exit(0)
if args[0] == "start":
    if not path.exists():
        sys.exit(125)
    obj = json.loads(path.read_text())
    if behavior.get("start_rejected"):
        sys.exit(125)
    obj.update(status="running", running=True)
    path.write_text(json.dumps(obj))
    if behavior.get("client_crash"):
        os.kill(os.getpid(), signal.SIGKILL)
    if behavior.get("stderr_bytes"):
        sys.stderr.buffer.write(b"e" * behavior["stderr_bytes"])
        sys.stderr.buffer.flush()
    output = root / "receipt.bin"
    data = output.read_bytes() if output.exists() else b"x" * behavior.get("stdout_bytes", 0)
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    time.sleep(behavior.get("delay", 0))
    if not behavior.get("survivor"):
        obj.update(status="exited", running=False, exit_code=behavior.get("exit_code", 0))
        path.write_text(json.dumps(obj))
    sys.exit(behavior.get("exit_code", 0))
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
        create = next(call for call in calls if call[0] == "create")
        name = create[create.index("--name") + 1]
        import hashlib
        cid = hashlib.sha256(name.encode()).hexdigest()
        self.assertIn(["rm", "-f", cid], calls)
        self.assertEqual(calls[-2][0], "inspect")
        self.assertEqual(calls[-2][-1], cid)
        self.assertFalse((self.root / "objects" / cid).exists())

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
        self.assertFalse((self.root / "objects" / result.container_id).exists())
        self.assertEqual(self.calls()[-2][-1], result.container_id)

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
        with self.assertRaises(DockerReconciliationRequired):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assert_named_cleanup()

    def test_failed_removal_is_not_reported_as_verified_cleanup(self):
        self.configure(survivor=True, removal_fails=True)
        with self.assertRaises(DockerReconciliationRequired):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assertEqual(self.calls()[-1][0], "rm")

    def test_unavailable_inspection_does_not_attest_absence(self):
        self.configure(inspect_fails=True)
        with self.assertRaises(DockerReconciliationRequired):
            run_docker_plan(self.plan(), docker_binary=str(self.binary))
        self.assertFalse(any(call[0] == "start" for call in self.calls()))

    def test_discarded_workload_output_preserves_executor_observation(self):
        self.configure(stdout_bytes=1024 * 1024, stderr_bytes=1024 * 1024, exit_code=7)
        result = DockerExecutor(docker_binary=str(self.binary))(self.plan())
        self.assertEqual(result.outcome, "SUCCEEDED")
        self.assertEqual(self.calls()[-2][0], "inspect")

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
        self.assertEqual(self.calls()[-2][0], "inspect")

    def owned_object(self, name="owned-session", cid="b" * 64):
        identity = DockerSessionIdentity(name, self.plan().plan_sha256, self.plan().image_id, "owned-daemon-1", cid)
        obj = {"id": cid, "name": "/" + name, "image": identity.image_id,
               "session": name, "plan": identity.plan_sha256, "status": "running",
               "running": True, "exit_code": 0}
        (self.root / "objects").mkdir(exist_ok=True)
        (self.root / "objects" / cid).write_text(json.dumps(obj))
        return identity, obj

    def test_lost_create_response_remains_unknown_and_never_starts(self):
        self.configure(create_delay=10)
        with self.assertRaises(DockerReconciliationRequired) as raised:
            run_docker_plan(self.plan(timeout=1), docker_binary=str(self.binary))
        error = raised.exception
        self.assertEqual(error.phase, "CREATE")
        self.assertEqual(error.cleanup_state, "UNKNOWN")
        self.assertIsNone(error.session.container_id)
        self.assertFalse(any(call[0] == "start" for call in self.calls()))
        self.assertEqual(list((self.root / "objects").iterdir()), [])
        # A daemon may complete an unacknowledged request after initial absence.
        identity, obj = self.owned_object(error.session.session_id)
        obj.update(status="created", running=False, plan=error.session.plan_sha256)
        (self.root / "objects" / identity.container_id).write_text(json.dumps(obj))
        recovery = reconcile_docker_session(error.session, docker_binary=str(self.binary))
        self.assertEqual(recovery["cleanup_state"], "UNKNOWN")
        self.assertEqual(recovery["observed_container_id"], identity.container_id)
        self.assertFalse(any(call[0] == "start" for call in self.calls()))
        self.assertEqual(list((self.root / "objects").iterdir()), [])

    def test_client_crash_and_start_rejection_are_not_workload_success(self):
        for behavior in ({"client_crash": True}, {"start_rejected": True}):
            with self.subTest(behavior=behavior):
                self.configure(**behavior)
                with self.assertRaises(DockerReconciliationRequired) as raised:
                    run_docker_plan(self.plan(), docker_binary=str(self.binary))
                self.assertIsNotNone(raised.exception.session.container_id)
                self.assertEqual(raised.exception.cleanup_state, "VERIFIED_ABSENT")

    def test_recovery_keeps_identity_across_daemon_outage_and_rejects_replacement(self):
        identity, _ = self.owned_object()
        for behavior in ({"daemon_unavailable": True}, {"daemon_id": "replacement-daemon"}):
            with self.subTest(behavior=behavior):
                self.configure(**behavior)
                with self.assertRaises(DockerReconciliationRequired) as raised:
                    reconcile_docker_session(identity, docker_binary=str(self.binary))
                self.assertEqual(raised.exception.session, identity)
                self.assertEqual(raised.exception.cleanup_state, "UNKNOWN")
                self.assertTrue((self.root / "objects" / identity.container_id).exists())
        self.configure()
        recovery = reconcile_docker_session(identity, docker_binary=str(self.binary))
        self.assertEqual(recovery["cleanup_state"], "VERIFIED_ABSENT")

    def test_known_id_cleanup_does_not_remove_same_name_replacement(self):
        identity, _ = self.owned_object()
        (self.root / "objects" / identity.container_id).unlink()
        replacement, _ = self.owned_object(identity.session_id, "c" * 64)
        recovery = reconcile_docker_session(identity, docker_binary=str(self.binary))
        self.assertEqual(recovery["cleanup_state"], "VERIFIED_ABSENT")
        self.assertTrue((self.root / "objects" / replacement.container_id).exists())
        self.assertFalse(any(call[0] == "rm" for call in self.calls()))

    def test_unacknowledged_identity_cannot_remove_unowned_name(self):
        identity, obj = self.owned_object()
        obj["plan"] = "f" * 64
        (self.root / "objects" / identity.container_id).write_text(json.dumps(obj))
        unacknowledged = DockerSessionIdentity(identity.session_id, identity.plan_sha256,
                                              identity.image_id, identity.daemon_id)
        with self.assertRaises(DockerReconciliationRequired):
            reconcile_docker_session(unacknowledged, docker_binary=str(self.binary))
        self.assertTrue((self.root / "objects" / identity.container_id).exists())
        self.assertFalse(any(call[0] == "rm" for call in self.calls()))

    def test_process_tree_operations_pin_original_container_id(self):
        identity, _ = self.owned_object()
        backend = DockerProcessTreeBackend(session_id=identity.session_id, docker_binary=str(self.binary))
        backend.snapshot(identity.session_id)
        backend.freeze(identity.session_id)
        (self.root / "objects" / identity.container_id).unlink()
        replacement, _ = self.owned_object(identity.session_id, "c" * 64)
        backend.terminate(identity.session_id)
        self.assertTrue((self.root / "objects" / replacement.container_id).exists())
        actions = [call for call in self.calls() if call[0] in {"pause", "rm", "top"}]
        self.assertTrue(actions)
        self.assertTrue(all(call[-1] == identity.container_id for call in actions))

    def test_verified_removal_rejects_mutable_names_and_short_ids_before_cli(self):
        identity, _ = self.owned_object()
        (self.root / "objects" / identity.container_id).unlink()
        for reference in (identity.session_id, identity.container_id[:12]):
            with self.subTest(reference=reference):
                replacement, _ = self.owned_object(identity.session_id, "c" * 64)
                with self.assertRaisesRegex(DockerExecutionError, "full container ID"):
                    _remove_container_verified(reference, docker_binary=str(self.binary))
                self.assertFalse((self.root / "calls.jsonl").exists())
                self.assertTrue((self.root / "objects" / replacement.container_id).exists())

    def test_uncertain_backend_receipt_consumes_single_use_authority(self):
        from sdk.liminal_capability_broker import CapabilityBroker
        from sdk.liminal_isolated_execution import IsolatedExecutionBroker, verify_receipt
        from sdk.liminal_post_sandbox_contracts import CapabilityContract
        from sdk.liminal_runtime_mediation import RuntimeMediator
        from tests.test_isolated_execution_broker import operation, P, SCOPE
        capability = CapabilityContract.build(
            capability_id="cap:uncertain", capability_type="process.execute", subject_id="agent:a",
            issuer_id="human:owner", scope=SCOPE, issued_at_unix=10, not_before_unix=10,
            expires_at_unix=500, max_uses=1, delegable=False, parent_capability_id=None, policy_sha256=P)
        broker = CapabilityBroker("broker:uncertain")
        broker.admit(capability.as_document(), at_unix=20)
        isolated = IsolatedExecutionBroker(mediator=RuntimeMediator(broker=broker),
                                          backend=DockerExecutor(str(self.binary)))
        plan = self.plan()
        op = operation(plan, operation_id=plan.operation_id)
        self.configure(client_crash=True, removal_fails=True)
        receipt = isolated.execute(operation=op, plan=plan)
        verify_receipt(receipt)
        self.assertEqual(receipt["execution_outcome"], "UNKNOWN")
        self.assertTrue(receipt["backend_invoked"])
        self.assertNotIn(str(self.root), str(receipt))
        count = len(self.calls())
        retry = isolated.execute(operation=op, plan=plan)
        self.assertEqual(retry["execution_outcome"], "NOT_EXECUTED")
        self.assertFalse(retry["backend_invoked"])
        self.assertEqual(len(self.calls()), count)

    def test_wheel_unverified_success_receipt_is_unknown_with_direct_identity(self):
        for output in (b"", b"not json", b"[]", b"{}", b"\xff"):
            with self.subTest(output=output):
                (self.root / "receipt.bin").write_bytes(output)
                with self.assertRaises(WheelDockerOutcomeUnknown) as raised:
                    WheelMaterializingDockerExecutor(str(self.binary))(self.wheel_plan())
                self.assertEqual(raised.exception.phase, "RECEIPT")
                self.assertEqual(raised.exception.cleanup_state, "VERIFIED_ABSENT")
                self.assertRegex(raised.exception.session.container_id, r"^[a-f0-9]{64}$")

    def test_session_observer_persists_identity_before_start_and_failure_is_unknown(self):
        import os
        journal = self.root / "session.jsonl"
        observed = []
        def persist(identity):
            observed.append(identity)
            with journal.open("a") as stream:
                stream.write(json.dumps(identity.as_document()) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if identity.container_id is not None:
                raise RuntimeError("injected observer failure after durable acknowledgement")
        with self.assertRaises(DockerReconciliationRequired) as raised:
            run_docker_plan(self.plan(), docker_binary=str(self.binary), session_observer=persist)
        identities = [DockerSessionIdentity(**json.loads(line)) for line in journal.read_text().splitlines()]
        self.assertEqual(identities, observed)
        self.assertIsNone(identities[0].container_id)
        self.assertEqual(identities[1], raised.exception.session)
        self.assertFalse(any(call[0] == "start" for call in self.calls()))
        self.assertEqual(raised.exception.cleanup_state, "VERIFIED_ABSENT")
        recovery = reconcile_docker_session(identities[-1], docker_binary=str(self.binary))
        self.assertEqual(recovery["cleanup_state"], "VERIFIED_ABSENT")

    def test_observer_failure_before_create_has_no_container_effect(self):
        def fail(_):
            raise RuntimeError("journal unavailable")
        with self.assertRaisesRegex(RuntimeError, "journal unavailable"):
            run_docker_plan(self.plan(), docker_binary=str(self.binary), session_observer=fail)
        self.assertFalse(any(call[0] == "create" for call in self.calls()))

    def test_invalid_output_budget_does_not_spawn_cli(self):
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(DockerExecutionError):
                run_docker_plan(self.plan(), docker_binary=str(self.binary), stdout_limit=limit)
        self.assertFalse((self.root / "calls.jsonl").exists())

    def daemon_lookup_faults(self):
        return (subprocess.TimeoutExpired(["docker", "info"], 10),
                OutputLimitExceeded("daemon identity output exceeded its limit"),
                FileNotFoundError("Docker binary unavailable"), b"\xff")

    def test_daemon_lookup_failures_are_adapter_errors_without_mutating_cli(self):
        identity, _ = self.owned_object()
        backend = DockerProcessTreeBackend(session_id=identity.session_id,
                                           docker_binary=str(self.binary))
        for fault in self.daemon_lookup_faults():
            for target in ("run_plan", "supervisor_constructor", "supervisor_operation"):
                with self.subTest(fault=type(fault).__name__, target=target):
                    observed = []
                    def broken_cli(argv, **_):
                        if isinstance(fault, bytes):
                            return subprocess.CompletedProcess(argv, 0, fault, b"")
                        raise fault
                    with patch("adapters.docker.liminal_docker_executor.run_cli",
                               side_effect=broken_cli) as cli:
                        with self.assertRaises(DockerExecutionError) as raised:
                            if target == "run_plan":
                                run_docker_plan(self.plan(), session_observer=observed.append)
                            elif target == "supervisor_constructor":
                                DockerProcessTreeBackend(session_id=identity.session_id)
                            else:
                                backend.snapshot(identity.session_id)
                    error = raised.exception
                    self.assertNotIsInstance(error, ExecutionOutcomeUnknown)
                    self.assertIsNone(error.session)
                    self.assertIsNone(error.phase)
                    if isinstance(fault, bytes):
                        self.assertIsInstance(error.__cause__, UnicodeDecodeError)
                    else:
                        self.assertIs(error.__cause__, fault)
                    self.assertEqual(observed, [])
                    self.assertEqual([call.args[0][1] for call in cli.call_args_list], ["info"])
                    self.assertTrue((self.root / "objects" / identity.container_id).exists())

    def test_wheel_daemon_lookup_failures_are_backend_errors_before_create(self):
        for fault in self.daemon_lookup_faults():
            with self.subTest(fault=type(fault).__name__):
                observed = []
                def broken_cli(argv, **_):
                    if isinstance(fault, bytes):
                        return subprocess.CompletedProcess(argv, 0, fault, b"")
                    raise fault
                with patch("adapters.docker.liminal_docker_executor.run_cli",
                           side_effect=broken_cli) as cli:
                    with self.assertRaises(WheelDockerBackendError) as raised:
                        WheelMaterializingDockerExecutor(session_observer=observed.append)(self.wheel_plan())
                error = raised.exception
                self.assertNotIsInstance(error, WheelDockerOutcomeUnknown)
                self.assertIsInstance(error.__cause__, DockerExecutionError)
                if isinstance(fault, bytes):
                    self.assertIsInstance(error.__cause__.__cause__, UnicodeDecodeError)
                else:
                    self.assertIs(error.__cause__.__cause__, fault)
                self.assertEqual(observed, [])
                self.assertEqual([call.args[0][1] for call in cli.call_args_list], ["info"])

    def test_create_transport_failures_remain_unknown_without_starting(self):
        for fault in self.daemon_lookup_faults()[:3]:
            for acknowledged in (False, True):
                with self.subTest(fault=type(fault).__name__, acknowledged=acknowledged):
                    verbs = []
                    def broken_create(argv, **_):
                        verbs.append(argv[1])
                        if argv[1] == "info":
                            if acknowledged and "create" in verbs:
                                raise fault
                            return subprocess.CompletedProcess(argv, 0, b"owned-daemon-1\n", b"")
                        if argv[1] == "create":
                            if acknowledged:
                                return subprocess.CompletedProcess(argv, 0, b"b" * 64 + b"\n", b"")
                            raise fault
                        if argv[1] == "inspect":
                            return subprocess.CompletedProcess(argv, 1, b"", b"No such container")
                        self.fail("unexpected CLI action: " + argv[1])
                    with patch("adapters.docker.liminal_docker_executor.run_cli",
                               side_effect=broken_create):
                        with self.assertRaises(DockerReconciliationRequired) as raised:
                            run_docker_plan(self.plan())
                    error = raised.exception
                    self.assertIsInstance(error, ExecutionOutcomeUnknown)
                    self.assertEqual(error.phase, "CREATE")
                    self.assertEqual(error.cleanup_state, "UNKNOWN")
                    if acknowledged:
                        self.assertIsInstance(error.__cause__, DockerExecutionError)
                        self.assertIs(error.__cause__.__cause__, fault)
                        self.assertEqual(error.session.container_id, "b" * 64)
                        self.assertEqual(verbs, ["info", "create", "info", "info"])
                    else:
                        self.assertIs(error.__cause__, fault)
                        self.assertIsNone(error.session.container_id)
                        self.assertEqual(verbs, ["info", "create", "info", "inspect", "info"])


if __name__ == "__main__":
    unittest.main()
