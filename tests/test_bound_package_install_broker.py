from __future__ import annotations

import json
import threading
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_isolated_execution import IsolatedExecutionBroker
from sdk.liminal_package_install_broker import (
    ARGUMENT_PROFILE,
    INSTALLER_EXECUTABLE,
    INSTALL_TARGET,
    PackageInstallBroker,
    PackageInstallError,
    PackageInstallRequest,
    PackageWorkspaceBinding,
    verify_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator

POLICY = "a" * 64
ARTIFACT = "b" * 64
DEPENDENCIES = "c" * 64
MANIFEST = "d" * 64
IMAGE = "sha256:" + "e" * 64


class Clock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class CapturingBackend:
    def __init__(self) -> None:
        self.plans = []

    def __call__(self, plan):
        self.plans.append(plan)
        return ExecutionObservation.success({
            "backend": "test-isolated-installer",
            "plan_sha256": plan.plan_sha256,
            "outcome": "materialized-not-executed",
        })


class PackageInstallBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.binding = self._binding()

    def _binding(self, **overrides) -> PackageWorkspaceBinding:
        values = {
            "binding_id": "pkg-workspace:1",
            "host_workspace": "/trusted/staged-packages",
            "registry": "pypi.org",
            "package_name": "demo_pkg",
            "version": "1.2.3",
            "artifact_sha256": ARTIFACT,
            "dependency_plan_sha256": DEPENDENCIES,
            "staged_manifest_sha256": MANIFEST,
            "dependency_count": 3,
            "installer_image_id": IMAGE,
        }
        values.update(overrides)
        return PackageWorkspaceBinding.build(**values)

    def _stack(
        self,
        *,
        package_coordinate: str = "demo-pkg==1.2.3",
        registry: str = "pypi.org",
        package_max_uses: int = 20,
        include_process_capability: bool = True,
        binding: PackageWorkspaceBinding | None = None,
    ):
        capability = CapabilityBroker("cap-broker:package-tests")
        package_contract = CapabilityContract.build(
            capability_id="cap:package",
            capability_type="package.install",
            subject_id="agent:a",
            issuer_id="host:tests",
            scope={"packages": [package_coordinate], "registries": [registry]},
            issued_at_unix=100,
            not_before_unix=100,
            expires_at_unix=10000,
            max_uses=package_max_uses,
            delegable=False,
            parent_capability_id=None,
            policy_sha256=POLICY,
        )
        capability.admit(package_contract.as_document(), at_unix=100)
        if include_process_capability:
            process_contract = CapabilityContract.build(
                capability_id="cap:installer-process",
                capability_type="process.execute",
                subject_id="agent:a",
                issuer_id="host:tests",
                scope={
                    "argument_profile": ARGUMENT_PROFILE,
                    "executables": [INSTALLER_EXECUTABLE],
                    "working_directory": "/workspace",
                },
                issued_at_unix=100,
                not_before_unix=100,
                expires_at_unix=10000,
                max_uses=20,
                delegable=False,
                parent_capability_id=None,
                policy_sha256=POLICY,
            )
            capability.admit(process_contract.as_document(), at_unix=100)
        backend = CapturingBackend()
        mediator = RuntimeMediator(broker=capability)
        isolated = IsolatedExecutionBroker(mediator=mediator, backend=backend)
        broker = PackageInstallBroker(
            capability_broker=capability,
            isolated_execution_broker=isolated,
            workspace_bindings=[binding or self.binding],
            clock=self.clock,
        )
        return capability, backend, broker

    def _request(
        self,
        *,
        call_id: str = "call:pkg:1",
        registry: str = "pypi.org",
        package_name: str = "demo_pkg",
        version: str = "1.2.3",
        artifact_sha256: str = ARTIFACT,
        dependency_plan_sha256: str = DEPENDENCIES,
        staged_manifest_sha256: str = MANIFEST,
        dependency_count: int = 3,
        workspace_binding_id: str = "pkg-workspace:1",
    ) -> PackageInstallRequest:
        return PackageInstallRequest(
            call_id=call_id,
            subject_id="agent:a",
            policy_sha256=POLICY,
            workspace_binding_id=workspace_binding_id,
            registry=registry,
            package_name=package_name,
            version=version,
            artifact_sha256=artifact_sha256,
            dependency_plan_sha256=dependency_plan_sha256,
            staged_manifest_sha256=staged_manifest_sha256,
            dependency_count=dependency_count,
        )

    def test_success_requires_both_package_and_process_capabilities(self):
        _, backend, broker = self._stack()
        receipt = broker.install(self._request())
        self.assertEqual(receipt["package_decision"], "ALLOW")
        self.assertEqual(receipt["process_admission_decision"], "ALLOW")
        self.assertEqual(receipt["execution_outcome"], "SUCCEEDED")
        self.assertEqual(len(backend.plans), 1)
        verify_receipt(receipt)

    def test_exact_version_is_pinned_by_binding_and_capability(self):
        _, backend, broker = self._stack(package_coordinate="demo-pkg==1.2.3")
        receipt = broker.install(self._request(version="1.2.4"))
        self.assertEqual(receipt["package_decision"], "BLOCK")
        self.assertIn("package_coordinate_binding_mismatch", receipt["reason_codes"])
        self.assertEqual(len(backend.plans), 0)

    def test_every_host_staged_materialization_input_is_pinned(self):
        cases = [
            ("registry", {"registry": "packages.example.com"}, "registry_binding_mismatch"),
            ("package", {"package_name": "other-pkg"}, "package_coordinate_binding_mismatch"),
            ("artifact", {"artifact_sha256": "f" * 64}, "artifact_binding_mismatch"),
            ("dependency-plan", {"dependency_plan_sha256": "1" * 64}, "dependency_plan_binding_mismatch"),
            ("manifest", {"staged_manifest_sha256": "2" * 64}, "staged_manifest_mismatch"),
            ("dependency-count", {"dependency_count": 4}, "dependency_count_binding_mismatch"),
        ]
        for label, overrides, reason in cases:
            with self.subTest(label=label):
                capability, backend, broker = self._stack(package_max_uses=1)
                blocked = broker.install(self._request(call_id=f"call:{label}", **overrides))
                self.assertEqual(blocked["package_decision"], "BLOCK")
                self.assertIn(reason, blocked["reason_codes"])
                self.assertEqual(len(backend.plans), 0)
                allowed = broker.install(self._request(call_id=f"call:{label}:good"))
                self.assertEqual(allowed["package_decision"], "ALLOW")
                state = capability.state_document()
                package_state = next(item for item in state["capabilities"] if item["capability_id"] == "cap:package")
                self.assertEqual(package_state["use_count"], 1)

    def test_process_capability_is_separate_and_mandatory(self):
        _, backend, broker = self._stack(include_process_capability=False)
        receipt = broker.install(self._request())
        self.assertEqual(receipt["package_decision"], "ALLOW")
        self.assertEqual(receipt["process_admission_decision"], "BLOCK")
        self.assertEqual(receipt["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(len(backend.plans), 0)

    def test_installer_plan_is_fixed_offline_and_ephemeral(self):
        _, backend, broker = self._stack()
        receipt = broker.install(self._request())
        self.assertEqual(receipt["execution_outcome"], "SUCCEEDED")
        plan = backend.plans[0]
        self.assertEqual(plan.image_id, IMAGE)
        self.assertEqual(plan.profile.network_mode, "none")
        self.assertTrue(plan.profile.read_only_root)
        self.assertEqual(plan.profile.workspace_mode, "ro")
        self.assertNotEqual(plan.profile.uid, 0)
        self.assertEqual(plan.argv[0], INSTALLER_EXECUTABLE)
        self.assertIn("--offline", plan.argv)
        self.assertIn("--no-execute-installed-code", plan.argv)
        self.assertEqual(plan.argv[plan.argv.index("--target") + 1], INSTALL_TARGET)
        self.assertNotIn("pip", plan.argv)
        self.assertNotIn("npm", plan.argv)
        self.assertNotIn("apt", plan.argv)

    def test_staged_digests_are_bound_to_installer_argv(self):
        _, backend, broker = self._stack()
        broker.install(self._request())
        argv = backend.plans[0].argv
        self.assertEqual(argv[argv.index("--artifact-sha256") + 1], ARTIFACT)
        self.assertEqual(argv[argv.index("--dependency-plan-sha256") + 1], DEPENDENCIES)
        self.assertEqual(argv[argv.index("--manifest-sha256") + 1], MANIFEST)
        self.assertEqual(argv[argv.index("--dependency-count") + 1], "3")

    def test_unknown_workspace_binding_blocks(self):
        _, backend, broker = self._stack()
        receipt = broker.install(self._request(workspace_binding_id="pkg-workspace:missing"))
        self.assertEqual(receipt["package_decision"], "BLOCK")
        self.assertEqual(len(backend.plans), 0)

    def test_package_capability_exhaustion_blocks_second_unique_call(self):
        _, backend, broker = self._stack(package_max_uses=1)
        first = broker.install(self._request(call_id="call:first"))
        second = broker.install(self._request(call_id="call:second"))
        self.assertEqual(first["package_decision"], "ALLOW")
        self.assertEqual(second["package_decision"], "BLOCK")
        self.assertEqual(len(backend.plans), 1)

    def test_duplicate_call_id_is_atomic_under_threads(self):
        _, backend, broker = self._stack()
        barrier = threading.Barrier(3)
        decisions: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            result = broker.install(self._request(call_id="call:concurrent"))
            with lock:
                decisions.append(result["package_decision"])

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(decisions), ["ALLOW", "BLOCK"])
        self.assertEqual(len(backend.plans), 1)

    def test_host_clock_is_authoritative(self):
        _, _, broker = self._stack()
        self.clock.value = 321
        receipt = broker.install(self._request())
        self.assertEqual(receipt["at_unix"], 321)

    def test_request_validation_rejects_unbounded_or_ambiguous_coordinates(self):
        _, _, broker = self._stack()
        bad_requests = [
            self._request(version="latest"),
            self._request(package_name="../evil"),
            self._request(registry="https://pypi.org"),
            self._request(dependency_count=257),
        ]
        for request in bad_requests:
            with self.subTest(request=request):
                with self.assertRaises(PackageInstallError):
                    broker.install(request)

    def test_workspace_binding_requires_immutable_installer_image(self):
        with self.assertRaises(PackageInstallError):
            self._binding(installer_image_id="python:latest")

    def test_forged_binding_digest_is_rejected_at_broker_construction(self):
        valid = self.binding
        forged = PackageWorkspaceBinding(**{**valid.__dict__, "binding_sha256": "0" * 64})
        capability = CapabilityBroker("cap-broker:forged-binding")
        backend = CapturingBackend()
        isolated = IsolatedExecutionBroker(mediator=RuntimeMediator(broker=capability), backend=backend)
        with self.assertRaises(PackageInstallError):
            PackageInstallBroker(
                capability_broker=capability,
                isolated_execution_broker=isolated,
                workspace_bindings=[forged],
                clock=self.clock,
            )

    def test_receipts_are_digest_only_and_exact_schema(self):
        _, _, broker = self._stack()
        receipt = broker.install(self._request())
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("/trusted/staged-packages", serialized)
        self.assertNotIn("demo-pkg", serialized)
        verify_receipt(receipt)
        tampered = dict(receipt)
        tampered["raw_workspace"] = "/trusted/staged-packages"
        with self.assertRaises(PackageInstallError):
            verify_receipt(tampered)

    def test_workspace_binding_map_is_immutable(self):
        _, _, broker = self._stack()
        with self.assertRaises(TypeError):
            broker._bindings["evil"] = self.binding  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
