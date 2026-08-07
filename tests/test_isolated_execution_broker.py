import unittest

from adapters.docker.liminal_docker_executor import build_docker_argv
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_isolated_execution import (
    AUTHORITY,
    IsolationError,
    IsolationProfile,
    IsolatedExecutionBroker,
    IsolatedExecutionPlan,
    verify_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

P = "a" * 64
IMAGE = "sha256:" + "b" * 64
SCOPE = {
    "executables": ["/bin/sh", "/bin/true"],
    "working_directory": "/workspace",
    "argument_profile": "isolated_fixture",
}


def plan(*, operation_id="op:1", argv=("/bin/true",), image_id=IMAGE, workspace="/host/workspace", profile=None):
    return IsolatedExecutionPlan.build(
        operation_id=operation_id,
        image_id=image_id,
        argv=argv,
        host_workspace=workspace,
        profile=profile,
    )


def operation(p, *, operation_id="op:1", kind="process.execute", scope=SCOPE, at=30):
    return RuntimeOperation(
        operation_id=operation_id,
        subject_id="agent:a",
        policy_sha256=P,
        kind=kind,
        scope=scope,
        payload_sha256=p.payload_sha256,
        at_unix=at,
    )


def contract(*, cid="cap:proc", expires=500):
    return CapabilityContract.build(
        capability_id=cid,
        capability_type="process.execute",
        subject_id="agent:a",
        issuer_id="human:owner",
        scope=SCOPE,
        issued_at_unix=10,
        not_before_unix=10,
        expires_at_unix=expires,
        max_uses=8,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=P,
    ).as_document()


class IsolatedExecutionBrokerTests(unittest.TestCase):
    def setUp(self):
        self.broker = CapabilityBroker("broker:isolated-tests")
        self.mediator = RuntimeMediator(broker=self.broker)
        self.calls = []

        def backend(p):
            self.calls.append(p.plan_sha256)
            return ExecutionObservation.success({"backend": "fake-container", "exit_code": 0, "plan_sha256": p.plan_sha256})

        self.isolated = IsolatedExecutionBroker(mediator=self.mediator, backend=backend)

    def admit(self):
        self.broker.admit(contract(), at_unix=20)

    def test_mutable_image_tag_rejected(self):
        with self.assertRaises(IsolationError):
            plan(image_id="alpine:latest")

    def test_weak_profile_rejected(self):
        with self.assertRaises(IsolationError):
            plan(profile=IsolationProfile(network_mode="bridge"))

    def test_workspace_must_be_absolute_and_mount_safe(self):
        with self.assertRaises(IsolationError):
            plan(workspace="relative/path")
        with self.assertRaises(IsolationError):
            plan(workspace="/host/path,evil")

    def test_payload_must_bind_exact_plan(self):
        self.admit()
        p = plan()
        op = RuntimeOperation(
            operation_id="op:1", subject_id="agent:a", policy_sha256=P,
            kind="process.execute", scope=SCOPE, payload_sha256="f" * 64, at_unix=30,
        )
        with self.assertRaises(IsolationError):
            self.isolated.execute(operation=op, plan=p)
        self.assertEqual(self.calls, [])

    def test_non_process_operation_rejected(self):
        p = plan()
        other_scope = {"setting_keys": ["feature.safe_mode"]}
        op = RuntimeOperation(
            operation_id="op:1", subject_id="agent:a", policy_sha256=P,
            kind="runtime.configure", scope=other_scope, payload_sha256=p.payload_sha256, at_unix=30,
        )
        with self.assertRaises(IsolationError):
            self.isolated.execute(operation=op, plan=p)

    def test_executable_must_be_in_capability_scope(self):
        p = plan(argv=("/usr/bin/python3",))
        self.admit()
        with self.assertRaises(IsolationError):
            self.isolated.execute(operation=operation(p), plan=p)
        self.assertEqual(self.calls, [])

    def test_default_deny_never_invokes_backend(self):
        p = plan()
        r = self.isolated.execute(operation=operation(p), plan=p)
        self.assertEqual(r["admission_decision"], "BLOCK")
        self.assertEqual(r["execution_outcome"], "NOT_EXECUTED")
        self.assertFalse(r["backend_invoked"])
        self.assertEqual(self.calls, [])

    def test_valid_capability_invokes_backend_once(self):
        self.admit()
        p = plan()
        r = self.isolated.execute(operation=operation(p), plan=p)
        self.assertEqual(r["admission_decision"], "ALLOW")
        self.assertEqual(r["execution_outcome"], "SUCCEEDED")
        self.assertTrue(r["backend_invoked"])
        self.assertEqual(self.calls, [p.plan_sha256])
        verify_receipt(r)

    def test_revoked_capability_never_invokes_backend(self):
        self.admit()
        self.broker.revoke("cap:proc", at_unix=25)
        p = plan()
        r = self.isolated.execute(operation=operation(p), plan=p)
        self.assertEqual(r["admission_decision"], "BLOCK")
        self.assertEqual(self.calls, [])

    def test_containment_never_invokes_backend(self):
        self.admit()
        self.mediator.enter_containment(incident_receipt_sha256="c" * 64)
        p = plan()
        r = self.isolated.execute(operation=operation(p), plan=p)
        self.assertEqual(r["admission_decision"], "BLOCK")
        self.assertEqual(r["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(self.calls, [])

    def test_receipt_contains_no_raw_argv_or_workspace(self):
        self.admit()
        p = plan(argv=("/bin/sh", "-c", "echo SAFE-FIXTURE"), workspace="/host/private/workspace")
        r = self.isolated.execute(operation=operation(p), plan=p)
        text = str(r)
        self.assertNotIn("SAFE-FIXTURE", text)
        self.assertNotIn("/host/private/workspace", text)
        self.assertIn(p.plan_sha256, text)

    def test_receipt_tamper_fails(self):
        self.admit()
        p = plan()
        r = self.isolated.execute(operation=operation(p), plan=p)
        bad = dict(r)
        bad["plan_sha256"] = "f" * 64
        with self.assertRaises(IsolationError):
            verify_receipt(bad)

    def test_profile_is_deterministic(self):
        self.assertEqual(IsolationProfile().profile_sha256, IsolationProfile().profile_sha256)

    def test_docker_argv_contains_required_hardening(self):
        p = plan()
        argv = build_docker_argv(p)
        joined = " ".join(argv)
        self.assertIn("--network none", joined)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("--security-opt no-new-privileges:true", joined)
        self.assertIn("--user 65534:65534", joined)
        self.assertIn("--pids-limit 64", joined)
        self.assertIn("--memory 256m", joined)
        self.assertIn("--cpus 1.0", joined)
        self.assertIn("/tmp:rw,nosuid,nodev,noexec,size=64m", argv)
        self.assertIn("type=bind,src=/host/workspace,dst=/workspace,readonly", argv)
        self.assertEqual(argv[-2:], [IMAGE, "/bin/true"])

    def test_authority_boundary_is_explicit(self):
        self.assertTrue(AUTHORITY["trusted_backend_dispatch"])
        self.assertTrue(AUTHORITY["network_none"])
        self.assertFalse(AUTHORITY["direct_host_subprocess_execution"])
        self.assertFalse(AUTHORITY["direct_docker_api_access"])
        self.assertFalse(AUTHORITY["vm_isolation"])
        self.assertFalse(AUTHORITY["kernel_or_container_runtime_exploit_resistance"])


if __name__ == "__main__":
    unittest.main()
