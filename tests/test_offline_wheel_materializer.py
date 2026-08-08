from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile

from adapters.packages.liminal_wheel_materializer import (
    DEPENDENCY_PLAN_SCHEMA,
    MANIFEST_SCHEMA,
    MaterializationRequest,
    TARGET,
    WheelMaterializationError,
    WheelMaterializer,
    canonical_json,
    normalize_member_path,
    verify_audit,
)

PACKAGE = "demo-pkg"
VERSION = "1.2.3"
WHEEL_NAME = "demo_pkg-1.2.3-py3-none-any.whl"


def record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return "sha256=" + encoded


def make_wheel(*, extra: dict[str, bytes] | None = None, bad_record_path: str | None = None, symlink_path: str | None = None) -> bytes:
    dist = "demo_pkg-1.2.3.dist-info"
    files: dict[str, bytes] = {
        "demo_pkg/__init__.py": b"VALUE = 1\n",
        f"{dist}/METADATA": b"Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.2.3\n\n",
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: liminal-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
    }
    if extra:
        files.update(extra)
    rows = []
    for path, data in sorted(files.items()):
        digest = record_hash(data)
        if bad_record_path == path:
            digest = record_hash(b"tampered")
        rows.append(f"{path},{digest},{len(data)}")
    record_path = f"{dist}/RECORD"
    rows.append(f"{record_path},,")
    files[record_path] = ("\n".join(rows) + "\n").encode("utf-8")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in files.items():
            info = zipfile.ZipInfo(path)
            info.compress_type = zipfile.ZIP_DEFLATED
            if symlink_path == path:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            else:
                info.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(info, data)
    return output.getvalue()


class OfflineWheelMaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.wheel_path = os.path.join(self.tmp.name, WHEEL_NAME)
        self.wheel_bytes = make_wheel()
        with open(self.wheel_path, "wb") as fh:
            fh.write(self.wheel_bytes)
        self.artifact_sha = hashlib.sha256(self.wheel_bytes).hexdigest()
        self.materializer = WheelMaterializer()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _audit(self, **overrides):
        args = {
            "wheel_path": self.wheel_path,
            "wheel_filename": WHEEL_NAME,
            "expected_artifact_sha256": self.artifact_sha,
            "expected_distribution_name": PACKAGE,
            "expected_version": VERSION,
        }
        args.update(overrides)
        return self.materializer.audit(**args)

    def test_valid_wheel_audit_verifies_record_hashes(self):
        audit = self._audit()
        self.assertEqual(audit.artifact_sha256, self.artifact_sha)
        self.assertEqual(audit.distribution_name, PACKAGE)
        self.assertEqual(audit.version, VERSION)
        verify_audit(audit.as_document())

    def test_materialization_writes_non_executable_regular_files_only(self):
        target = os.path.join(self.tmp.name, "target")
        os.mkdir(target)
        result = self.materializer.materialize(
            wheel_path=self.wheel_path,
            wheel_filename=WHEEL_NAME,
            target_dir=target,
            expected_artifact_sha256=self.artifact_sha,
            expected_distribution_name=PACKAGE,
            expected_version=VERSION,
        )
        self.assertEqual(result["file_count"], 4)
        extracted = os.path.join(target, "demo_pkg", "__init__.py")
        self.assertTrue(os.path.isfile(extracted))
        self.assertEqual(stat.S_IMODE(os.stat(extracted).st_mode), 0o644)
        self.assertEqual(os.stat(extracted).st_mode & 0o111, 0)

    def test_artifact_digest_mismatch_fails_closed(self):
        with self.assertRaises(WheelMaterializationError):
            self._audit(expected_artifact_sha256="0" * 64)

    def test_filename_coordinate_mismatch_fails_closed(self):
        with self.assertRaises(WheelMaterializationError):
            self._audit(wheel_filename="other_pkg-1.2.3-py3-none-any.whl")
        with self.assertRaises(WheelMaterializationError):
            self._audit(wheel_filename="demo_pkg-9.9.9-py3-none-any.whl")

    def test_record_digest_mismatch_fails_closed(self):
        bad = make_wheel(bad_record_path="demo_pkg/__init__.py")
        path = os.path.join(self.tmp.name, "bad.whl")
        with open(path, "wb") as fh:
            fh.write(bad)
        with self.assertRaises(WheelMaterializationError):
            self.materializer.audit(
                wheel_path=path,
                wheel_filename=WHEEL_NAME,
                expected_artifact_sha256=hashlib.sha256(bad).hexdigest(),
                expected_distribution_name=PACKAGE,
                expected_version=VERSION,
            )

    def test_path_traversal_backslash_and_absolute_paths_rejected(self):
        for path in ("../evil.py", "pkg/../evil.py", "/abs.py", "pkg\\evil.py", "./evil.py"):
            with self.subTest(path=path):
                with self.assertRaises(WheelMaterializationError):
                    normalize_member_path(path)

    def test_zip_slip_member_fails_closed(self):
        bad = make_wheel(extra={"../escape.py": b"nope"})
        path = os.path.join(self.tmp.name, "slip.whl")
        with open(path, "wb") as fh:
            fh.write(bad)
        with self.assertRaises(WheelMaterializationError):
            self.materializer.audit(
                wheel_path=path,
                wheel_filename=WHEEL_NAME,
                expected_artifact_sha256=hashlib.sha256(bad).hexdigest(),
                expected_distribution_name=PACKAGE,
                expected_version=VERSION,
            )

    def test_symlink_member_fails_closed(self):
        bad = make_wheel(extra={"demo_pkg/link": b"target"}, symlink_path="demo_pkg/link")
        path = os.path.join(self.tmp.name, "symlink.whl")
        with open(path, "wb") as fh:
            fh.write(bad)
        with self.assertRaises(WheelMaterializationError):
            self.materializer.audit(
                wheel_path=path,
                wheel_filename=WHEEL_NAME,
                expected_artifact_sha256=hashlib.sha256(bad).hexdigest(),
                expected_distribution_name=PACKAGE,
                expected_version=VERSION,
            )

    def test_scripts_and_pth_vectors_are_rejected(self):
        for extra in (
            {"demo_pkg-1.2.3.data/scripts/tool": b"#!/bin/sh\n"},
            {"evil.pth": b"import os\n"},
        ):
            bad = make_wheel(extra=extra)
            path = os.path.join(self.tmp.name, "vector.whl")
            with open(path, "wb") as fh:
                fh.write(bad)
            with self.assertRaises(WheelMaterializationError):
                self.materializer.audit(
                    wheel_path=path,
                    wheel_filename=WHEEL_NAME,
                    expected_artifact_sha256=hashlib.sha256(bad).hexdigest(),
                    expected_distribution_name=PACKAGE,
                    expected_version=VERSION,
                )

    def test_target_symlink_is_refused(self):
        real = os.path.join(self.tmp.name, "real-target")
        os.mkdir(real)
        link = os.path.join(self.tmp.name, "link-target")
        os.symlink(real, link)
        with self.assertRaises(OSError):
            self.materializer.materialize(
                wheel_path=self.wheel_path,
                wheel_filename=WHEEL_NAME,
                target_dir=link,
                expected_artifact_sha256=self.artifact_sha,
                expected_distribution_name=PACKAGE,
                expected_version=VERSION,
            )

    def test_nonempty_target_is_refused(self):
        target = os.path.join(self.tmp.name, "target-nonempty")
        os.mkdir(target)
        with open(os.path.join(target, "existing"), "wb") as fh:
            fh.write(b"x")
        with self.assertRaises(WheelMaterializationError):
            self.materializer.materialize(
                wheel_path=self.wheel_path,
                wheel_filename=WHEEL_NAME,
                target_dir=target,
                expected_artifact_sha256=self.artifact_sha,
                expected_distribution_name=PACKAGE,
                expected_version=VERSION,
            )

    def test_staged_manifest_and_dependency_plan_bind_every_input(self):
        workspace = self.tmp.name
        dependency = {"schema": DEPENDENCY_PLAN_SCHEMA, "dependencies": [{"name": "dep-a"}]}
        dependency_bytes = canonical_json(dependency).encode("utf-8")
        dependency_sha = hashlib.sha256(dependency_bytes).hexdigest()
        with open(os.path.join(workspace, "dependency-plan.json"), "wb") as fh:
            fh.write(dependency_bytes)
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "registry": "pypi.org",
            "package_name": PACKAGE,
            "version": VERSION,
            "wheel_filename": WHEEL_NAME,
            "artifact_sha256": self.artifact_sha,
            "dependency_plan_sha256": dependency_sha,
            "dependency_count": 1,
        }
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        with open(os.path.join(workspace, "manifest.json"), "wb") as fh:
            fh.write(manifest_bytes)
        req = MaterializationRequest(
            manifest_sha256=manifest_sha,
            registry="pypi.org",
            package_name=PACKAGE,
            version=VERSION,
            artifact_sha256=self.artifact_sha,
            dependency_plan_sha256=dependency_sha,
            dependency_count=1,
            target=TARGET,
        )
        self.materializer.verify_staged_plan(workspace=workspace, wheel_filename=WHEEL_NAME, request=req)
        bad = MaterializationRequest(**{**req.__dict__, "dependency_count": 2})
        with self.assertRaises(WheelMaterializationError):
            self.materializer.verify_staged_plan(workspace=workspace, wheel_filename=WHEEL_NAME, request=bad)


if __name__ == "__main__":
    unittest.main()
