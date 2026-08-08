#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import zipfile

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from adapters.packages.liminal_wheel_docker_backend import WheelMaterializingDockerExecutor
from adapters.packages.liminal_wheel_materializer import (
    DEPENDENCY_PLAN_SCHEMA,
    MANIFEST_SCHEMA,
    canonical_json,
)
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_isolated_execution import IsolatedExecutionBroker
from sdk.liminal_package_install_broker import (
    ARGUMENT_PROFILE,
    INSTALLER_EXECUTABLE,
    PackageInstallBroker,
    PackageInstallRequest,
    PackageWorkspaceBinding,
    verify_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_mediation import RuntimeMediator

POLICY = "a" * 64
PACKAGE = "demo-pkg"
VERSION = "1.2.3"
REGISTRY = "pypi.org"
WHEEL_NAME = "demo_pkg-1.2.3-py3-none-any.whl"


def record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return "sha256=" + encoded


def make_wheel() -> bytes:
    dist = "demo_pkg-1.2.3.dist-info"
    files = {
        "demo_pkg/__init__.py": b"VALUE = 1\n",
        f"{dist}/METADATA": b"Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.2.3\n\n",
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: liminal-docker-self-check\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
    }
    rows = [f"{path},{record_hash(data)},{len(data)}" for path, data in sorted(files.items())]
    record_path = f"{dist}/RECORD"
    rows.append(f"{record_path},,")
    files[record_path] = ("\n".join(rows) + "\n").encode("utf-8")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in files.items():
            zf.writestr(path, data)
    return out.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    if not args.image_id.startswith("sha256:"):
        raise SystemExit("image-id must be immutable sha256")

    with tempfile.TemporaryDirectory(prefix="liminal-wheel-") as workspace:
        # The container is intentionally non-root (uid/gid 65534). Stage the
        # synthetic fixture as host-readable while retaining a read-only mount.
        os.chmod(workspace, 0o755)
        wheel_bytes = make_wheel()
        artifact_sha = hashlib.sha256(wheel_bytes).hexdigest()
        wheel_path = os.path.join(workspace, WHEEL_NAME)
        with open(wheel_path, "wb") as fh:
            fh.write(wheel_bytes)
        os.chmod(wheel_path, 0o444)

        dependency_plan = {"schema": DEPENDENCY_PLAN_SCHEMA, "dependencies": []}
        dependency_bytes = canonical_json(dependency_plan).encode("utf-8")
        dependency_sha = hashlib.sha256(dependency_bytes).hexdigest()
        dependency_path = os.path.join(workspace, "dependency-plan.json")
        with open(dependency_path, "wb") as fh:
            fh.write(dependency_bytes)
        os.chmod(dependency_path, 0o444)

        manifest = {
            "schema": MANIFEST_SCHEMA,
            "registry": REGISTRY,
            "package_name": PACKAGE,
            "version": VERSION,
            "wheel_filename": WHEEL_NAME,
            "artifact_sha256": artifact_sha,
            "dependency_plan_sha256": dependency_sha,
            "dependency_count": 0,
        }
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_path = os.path.join(workspace, "manifest.json")
        with open(manifest_path, "wb") as fh:
            fh.write(manifest_bytes)
        os.chmod(manifest_path, 0o444)

        capability = CapabilityBroker("cap-broker:wheel-docker-self-check")
        package_contract = CapabilityContract.build(
            capability_id="cap:package:wheel-self-check",
            capability_type="package.install",
            subject_id="agent:self-check",
            issuer_id="host:ci",
            scope={"packages": [f"{PACKAGE}=={VERSION}"], "registries": [REGISTRY]},
            issued_at_unix=100,
            not_before_unix=100,
            expires_at_unix=10000,
            max_uses=1,
            delegable=False,
            parent_capability_id=None,
            policy_sha256=POLICY,
        )
        process_contract = CapabilityContract.build(
            capability_id="cap:process:wheel-self-check",
            capability_type="process.execute",
            subject_id="agent:self-check",
            issuer_id="host:ci",
            scope={
                "argument_profile": ARGUMENT_PROFILE,
                "executables": [INSTALLER_EXECUTABLE],
                "working_directory": "/workspace",
            },
            issued_at_unix=100,
            not_before_unix=100,
            expires_at_unix=10000,
            max_uses=1,
            delegable=False,
            parent_capability_id=None,
            policy_sha256=POLICY,
        )
        capability.admit(package_contract.as_document(), at_unix=100)
        capability.admit(process_contract.as_document(), at_unix=100)

        backend = WheelMaterializingDockerExecutor()
        mediator = RuntimeMediator(broker=capability)
        isolated = IsolatedExecutionBroker(mediator=mediator, backend=backend)
        binding = PackageWorkspaceBinding.build(
            binding_id="wheel-workspace:ci",
            host_workspace=workspace,
            registry=REGISTRY,
            package_name=PACKAGE,
            version=VERSION,
            artifact_sha256=artifact_sha,
            dependency_plan_sha256=dependency_sha,
            staged_manifest_sha256=manifest_sha,
            dependency_count=0,
            installer_image_id=args.image_id,
        )
        broker = PackageInstallBroker(
            capability_broker=capability,
            isolated_execution_broker=isolated,
            workspace_bindings=[binding],
            clock=lambda: 101,
        )
        request = PackageInstallRequest(
            call_id="call:wheel-docker-self-check",
            subject_id="agent:self-check",
            policy_sha256=POLICY,
            workspace_binding_id=binding.binding_id,
            registry=REGISTRY,
            package_name=PACKAGE,
            version=VERSION,
            artifact_sha256=artifact_sha,
            dependency_plan_sha256=dependency_sha,
            staged_manifest_sha256=manifest_sha,
            dependency_count=0,
        )
        receipt = broker.install(request)
        verify_receipt(receipt)
        assert receipt["package_decision"] == "ALLOW"
        assert receipt["process_admission_decision"] == "ALLOW"
        assert receipt["execution_outcome"] == "SUCCEEDED"
        isolated_receipt = isolated.receipts()[-1]
        assert isolated_receipt["backend_invoked"] is True
        print("wheel-docker-self-check", canonical_sha256({
            "package_receipt": receipt["receipt_sha256"],
            "isolated_receipt": isolated_receipt["receipt_sha256"],
        }), "PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
