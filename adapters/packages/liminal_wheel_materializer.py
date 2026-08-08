#!/usr/bin/env python3
"""Trusted concrete offline wheel materializer for LiminalOS.

Designed to be installed at `/usr/local/bin/liminal-pkg-installer` inside the
immutable installer image used by the Bound Package Installation Broker. The
adapter never opens the network, resolves dependencies, imports package code, or
executes build/install hooks. It validates a host-staged plan and one exact wheel,
then writes regular non-executable files only into a fixed ephemeral tmpfs target.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "liminal-wheel-materialization-receipt-v0.1"
AUDIT_SCHEMA = "liminal-wheel-audit-v0.1"
MANIFEST_SCHEMA = "liminal-staged-wheel-manifest-v0.1"
DEPENDENCY_PLAN_SCHEMA = "liminal-offline-dependency-plan-v0.1"
WORKSPACE = "/workspace"
TARGET = "/tmp/liminal-site-packages"
MANIFEST_FILE = "manifest.json"
DEPENDENCY_PLAN_FILE = "dependency-plan.json"
MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_METADATA_BYTES = 1024 * 1024

_AUTHORITY_ITEMS = (
    ("mode", "trusted_offline_wheel_materializer"),
    ("filesystem_read", True),
    ("fixed_tmpfs_target_create", True),
    ("ephemeral_target_write", True),
    ("network_access", False),
    ("registry_access", False),
    ("dependency_resolution", False),
    ("subprocess_execution", False),
    ("package_code_execution", False),
    ("build_hooks", False),
    ("sdist_support", False),
    ("record_hash_verification", True),
    ("symlink_follow", False),
    ("special_file_materialization", False),
    ("wheel_scripts_materialization", False),
    ("pth_execution_vector_materialization", False),
    ("archive_permission_preservation", False),
    ("output_files_executable", False),
    ("signature_or_malware_oracle", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_SHA = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9._+!-]{0,127}$")
_NAME = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_REGISTRY = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,189}[a-z0-9])?$")


class WheelMaterializationError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _authority_document() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


def _exact_keys(raw: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(raw) != expected:
        raise WheelMaterializationError(f"{name}_schema_mismatch")


def _sha(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise WheelMaterializationError(f"invalid_{name}")
    return value


def normalize_distribution_name(value: str) -> str:
    if not isinstance(value, str):
        raise WheelMaterializationError("invalid_distribution_name")
    normalized = re.sub(r"[-_.]+", "-", value.strip().lower())
    if not normalized or not _NAME.fullmatch(normalized):
        raise WheelMaterializationError("invalid_distribution_name")
    return normalized


def normalize_version(value: str) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise WheelMaterializationError("invalid_version")
    return value


def normalize_registry(value: str) -> str:
    if not isinstance(value, str):
        raise WheelMaterializationError("invalid_registry")
    normalized = value.lower()
    if "." not in normalized or not _REGISTRY.fullmatch(normalized):
        raise WheelMaterializationError("invalid_registry")
    return normalized


def normalize_member_path(value: str, *, directory: bool | None = None) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise WheelMaterializationError("unsafe_member_path")
    if value.startswith("/") or value.startswith("~") or ":" in value.split("/", 1)[0]:
        raise WheelMaterializationError("unsafe_member_path")
    is_directory = value.endswith("/") if directory is None else directory
    raw = value[:-1] if is_directory and value.endswith("/") else value
    if not raw:
        raise WheelMaterializationError("unsafe_member_path")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise WheelMaterializationError("unsafe_member_path")
    if len(parts) > 128 or len(raw.encode("utf-8")) > 4096:
        raise WheelMaterializationError("unsafe_member_path")
    if any(len(part.encode("utf-8")) > 255 for part in parts):
        raise WheelMaterializationError("unsafe_member_path")
    return "/".join(parts) + ("/" if is_directory else "")


def _zip_entry_kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & 0xFFFF
    type_bits = stat.S_IFMT(mode)
    if info.is_dir() or info.filename.endswith("/"):
        if type_bits not in {0, stat.S_IFDIR}:
            raise WheelMaterializationError("directory_entry_type_mismatch")
        return "directory"
    if type_bits in {0, stat.S_IFREG}:
        return "file"
    if type_bits == stat.S_IFLNK:
        raise WheelMaterializationError("symlink_member_forbidden")
    raise WheelMaterializationError("special_file_member_forbidden")


def _decode_record_sha256(value: str) -> bytes:
    if not value.startswith("sha256="):
        raise WheelMaterializationError("record_hash_algorithm_forbidden")
    encoded = value[len("sha256="):]
    if not encoded:
        raise WheelMaterializationError("record_hash_invalid")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
    except Exception as exc:
        raise WheelMaterializationError("record_hash_invalid") from exc
    if len(decoded) != 32:
        raise WheelMaterializationError("record_hash_invalid")
    return decoded


def _wheel_coordinate_from_filename(filename: str) -> tuple[str, str]:
    if not isinstance(filename, str) or "/" in filename or "\\" in filename or not filename.endswith(".whl"):
        raise WheelMaterializationError("wheel_filename_invalid")
    parts = filename[:-4].split("-")
    if len(parts) not in {5, 6}:
        raise WheelMaterializationError("wheel_filename_unsupported")
    return normalize_distribution_name(parts[0]), normalize_version(parts[1])


@dataclass(frozen=True)
class MaterializationRequest:
    manifest_sha256: str
    registry: str
    package_name: str
    version: str
    artifact_sha256: str
    dependency_plan_sha256: str
    dependency_count: int
    target: str

    def normalized(self) -> "MaterializationRequest":
        if isinstance(self.dependency_count, bool) or not isinstance(self.dependency_count, int) or not 0 <= self.dependency_count <= 256:
            raise WheelMaterializationError("dependency_count_invalid")
        if self.target != TARGET:
            raise WheelMaterializationError("target_must_be_fixed_tmpfs")
        return MaterializationRequest(
            manifest_sha256=_sha(self.manifest_sha256, "manifest_sha256"),
            registry=normalize_registry(self.registry),
            package_name=normalize_distribution_name(self.package_name),
            version=normalize_version(self.version),
            artifact_sha256=_sha(self.artifact_sha256, "artifact_sha256"),
            dependency_plan_sha256=_sha(self.dependency_plan_sha256, "dependency_plan_sha256"),
            dependency_count=self.dependency_count,
            target=self.target,
        )


@dataclass(frozen=True)
class WheelAudit:
    artifact_sha256: str
    distribution_name: str
    version: str
    dist_info_root: str
    member_count: int
    file_count: int
    total_uncompressed_bytes: int
    record_sha256: str
    member_manifest_sha256: str
    audit_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_SCHEMA,
            "artifact_sha256": self.artifact_sha256,
            "distribution_name": self.distribution_name,
            "version": self.version,
            "dist_info_root_sha256": canonical_sha256(self.dist_info_root),
            "member_count": self.member_count,
            "file_count": self.file_count,
            "total_uncompressed_bytes": self.total_uncompressed_bytes,
            "record_sha256": self.record_sha256,
            "member_manifest_sha256": self.member_manifest_sha256,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "audit_sha256": self.audit_sha256}


@dataclass(frozen=True)
class WheelMaterializationReceipt:
    artifact_sha256: str
    staged_manifest_sha256: str
    dependency_plan_sha256: str
    wheel_audit_sha256: str
    package_coordinate_sha256: str
    output_manifest_sha256: str
    file_count: int
    total_bytes: int
    outcome: str
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "artifact_sha256": self.artifact_sha256,
            "staged_manifest_sha256": self.staged_manifest_sha256,
            "dependency_plan_sha256": self.dependency_plan_sha256,
            "wheel_audit_sha256": self.wheel_audit_sha256,
            "package_coordinate_sha256": self.package_coordinate_sha256,
            "output_manifest_sha256": self.output_manifest_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "outcome": self.outcome,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class WheelMaterializer:
    def __init__(self) -> None:
        try:
            self._nofollow = os.O_NOFOLLOW
            self._directory = os.O_DIRECTORY
        except AttributeError as exc:  # pragma: no cover - non-POSIX host
            raise WheelMaterializationError("required_posix_open_flags_unavailable") from exc

    def _read_regular_file(self, path: str, *, maximum: int) -> bytes:
        fd = os.open(path, os.O_RDONLY | self._nofollow)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise WheelMaterializationError("staged_input_not_regular_file")
            if st.st_size > maximum:
                raise WheelMaterializationError("staged_input_too_large")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise WheelMaterializationError("staged_input_too_large")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def select_single_wheel(self, workspace: str) -> tuple[str, str]:
        if workspace != WORKSPACE:
            raise WheelMaterializationError("workspace_must_be_fixed")
        names = os.listdir(workspace)
        wheels: list[tuple[str, str]] = []
        for name in names:
            if name.endswith(".whl"):
                if "/" in name or "\\" in name or "\x00" in name:
                    raise WheelMaterializationError("wheel_filename_invalid")
                path = os.path.join(workspace, name)
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode):
                    raise WheelMaterializationError("wheel_not_regular_file")
                wheels.append((name, path))
        if len(wheels) != 1:
            raise WheelMaterializationError("workspace_requires_exactly_one_wheel")
        return wheels[0]

    def verify_staged_plan(self, *, workspace: str, wheel_filename: str, request: MaterializationRequest) -> tuple[str, str]:
        req = request.normalized()
        manifest_bytes = self._read_regular_file(os.path.join(workspace, MANIFEST_FILE), maximum=MAX_METADATA_BYTES)
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        if manifest_sha != req.manifest_sha256:
            raise WheelMaterializationError("staged_manifest_digest_mismatch")
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except Exception as exc:
            raise WheelMaterializationError("staged_manifest_json_invalid") from exc
        if not isinstance(manifest, dict):
            raise WheelMaterializationError("staged_manifest_schema_mismatch")
        expected_manifest = {
            "schema", "registry", "package_name", "version", "wheel_filename",
            "artifact_sha256", "dependency_plan_sha256", "dependency_count",
        }
        _exact_keys(manifest, expected_manifest, "staged_manifest")
        if manifest.get("schema") != MANIFEST_SCHEMA:
            raise WheelMaterializationError("staged_manifest_schema_mismatch")
        comparisons = (
            normalize_registry(manifest["registry"]) == req.registry,
            normalize_distribution_name(manifest["package_name"]) == req.package_name,
            normalize_version(manifest["version"]) == req.version,
            manifest["wheel_filename"] == wheel_filename,
            _sha(manifest["artifact_sha256"], "manifest_artifact_sha256") == req.artifact_sha256,
            _sha(manifest["dependency_plan_sha256"], "manifest_dependency_plan_sha256") == req.dependency_plan_sha256,
            manifest["dependency_count"] == req.dependency_count and not isinstance(manifest["dependency_count"], bool),
        )
        if not all(comparisons):
            raise WheelMaterializationError("staged_manifest_plan_mismatch")

        dependency_bytes = self._read_regular_file(os.path.join(workspace, DEPENDENCY_PLAN_FILE), maximum=MAX_METADATA_BYTES)
        dependency_sha = hashlib.sha256(dependency_bytes).hexdigest()
        if dependency_sha != req.dependency_plan_sha256:
            raise WheelMaterializationError("dependency_plan_digest_mismatch")
        try:
            dependency_plan = json.loads(dependency_bytes.decode("utf-8"))
        except Exception as exc:
            raise WheelMaterializationError("dependency_plan_json_invalid") from exc
        if not isinstance(dependency_plan, dict) or set(dependency_plan) != {"schema", "dependencies"}:
            raise WheelMaterializationError("dependency_plan_schema_mismatch")
        if dependency_plan.get("schema") != DEPENDENCY_PLAN_SCHEMA or not isinstance(dependency_plan.get("dependencies"), list):
            raise WheelMaterializationError("dependency_plan_schema_mismatch")
        if len(dependency_plan["dependencies"]) != req.dependency_count:
            raise WheelMaterializationError("dependency_count_mismatch")
        return manifest_sha, dependency_sha

    def audit(
        self,
        *,
        wheel_path: str,
        wheel_filename: str,
        expected_artifact_sha256: str,
        expected_distribution_name: str,
        expected_version: str,
    ) -> WheelAudit:
        artifact_sha = _sha(expected_artifact_sha256, "artifact_sha256")
        distribution = normalize_distribution_name(expected_distribution_name)
        version = normalize_version(expected_version)
        filename_distribution, filename_version = _wheel_coordinate_from_filename(wheel_filename)
        if filename_distribution != distribution or filename_version != version:
            raise WheelMaterializationError("wheel_filename_coordinate_mismatch")
        wheel_bytes = self._read_regular_file(wheel_path, maximum=MAX_TOTAL_BYTES)
        if hashlib.sha256(wheel_bytes).hexdigest() != artifact_sha:
            raise WheelMaterializationError("artifact_digest_mismatch")

        try:
            archive = zipfile.ZipFile(io.BytesIO(wheel_bytes), "r")
        except zipfile.BadZipFile as exc:
            raise WheelMaterializationError("invalid_wheel_zip") from exc

        with archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= MAX_MEMBERS:
                raise WheelMaterializationError("archive_member_count_out_of_bounds")
            seen: set[str] = set()
            file_paths: list[str] = []
            member_manifest: list[dict[str, Any]] = []
            total = 0
            dist_info_roots: set[str] = set()

            for info in infos:
                if info.flag_bits & 0x1:
                    raise WheelMaterializationError("encrypted_archive_member_forbidden")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise WheelMaterializationError("archive_compression_method_forbidden")
                kind = _zip_entry_kind(info)
                normalized = normalize_member_path(info.filename, directory=(kind == "directory"))
                collision_key = normalized.casefold()
                if collision_key in seen:
                    raise WheelMaterializationError("duplicate_archive_member")
                seen.add(collision_key)
                if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
                    raise WheelMaterializationError("archive_member_size_out_of_bounds")
                if info.compress_size < 0:
                    raise WheelMaterializationError("archive_compressed_size_invalid")
                if info.file_size and info.compress_size == 0:
                    raise WheelMaterializationError("archive_compression_ratio_out_of_bounds")
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    raise WheelMaterializationError("archive_compression_ratio_out_of_bounds")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise WheelMaterializationError("archive_total_size_out_of_bounds")
                if kind == "directory":
                    continue
                lower = normalized.lower()
                if ".data/scripts/" in f"/{lower}" or lower.endswith(".data/scripts"):
                    raise WheelMaterializationError("wheel_scripts_forbidden")
                if lower.endswith(".pth"):
                    raise WheelMaterializationError("pth_execution_vector_forbidden")
                file_paths.append(normalized)
                member_manifest.append({
                    "path_sha256": canonical_sha256(normalized),
                    "size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                })
                parts = normalized.split("/")
                if len(parts) >= 2 and parts[0].endswith(".dist-info"):
                    dist_info_roots.add(parts[0])

            if len(dist_info_roots) != 1:
                raise WheelMaterializationError("wheel_must_have_exactly_one_dist_info_root")
            dist_info = next(iter(dist_info_roots))
            dist_stub = dist_info[:-len(".dist-info")]
            if "-" not in dist_stub:
                raise WheelMaterializationError("dist_info_coordinate_invalid")
            dist_name, dist_version = dist_stub.rsplit("-", 1)
            if normalize_distribution_name(dist_name) != distribution or normalize_version(dist_version) != version:
                raise WheelMaterializationError("dist_info_coordinate_mismatch")

            metadata_path = f"{dist_info}/METADATA"
            wheel_metadata_path = f"{dist_info}/WHEEL"
            record_path = f"{dist_info}/RECORD"
            required = {metadata_path, wheel_metadata_path, record_path}
            if not required.issubset(set(file_paths)):
                raise WheelMaterializationError("required_wheel_metadata_missing")

            metadata_bytes = self._read_member_bounded(archive, metadata_path, MAX_METADATA_BYTES)
            message = BytesParser(policy=compat32).parsebytes(metadata_bytes)
            if normalize_distribution_name(message.get("Name", "")) != distribution:
                raise WheelMaterializationError("wheel_distribution_name_mismatch")
            if normalize_version(message.get("Version", "")) != version:
                raise WheelMaterializationError("wheel_version_mismatch")

            wheel_metadata = BytesParser(policy=compat32).parsebytes(self._read_member_bounded(archive, wheel_metadata_path, MAX_METADATA_BYTES))
            wheel_version = wheel_metadata.get("Wheel-Version", "")
            if not wheel_version.startswith("1."):
                raise WheelMaterializationError("wheel_metadata_version_unsupported")

            record_bytes = self._read_member_bounded(archive, record_path, MAX_METADATA_BYTES)
            self._validate_record(archive, record_bytes, file_paths, record_path)
            record_sha = hashlib.sha256(record_bytes).hexdigest()
            member_manifest_sha = canonical_sha256(sorted(member_manifest, key=lambda item: item["path_sha256"]))
            base = WheelAudit(
                artifact_sha256=artifact_sha,
                distribution_name=distribution,
                version=version,
                dist_info_root=dist_info,
                member_count=len(infos),
                file_count=len(file_paths),
                total_uncompressed_bytes=total,
                record_sha256=record_sha,
                member_manifest_sha256=member_manifest_sha,
                audit_sha256="",
            )
            return WheelAudit(**{**base.__dict__, "audit_sha256": canonical_sha256(base.body())})

    def materialize(
        self,
        *,
        wheel_path: str,
        wheel_filename: str,
        target_dir: str,
        expected_artifact_sha256: str,
        expected_distribution_name: str,
        expected_version: str,
    ) -> dict[str, Any]:
        audit = self.audit(
            wheel_path=wheel_path,
            wheel_filename=wheel_filename,
            expected_artifact_sha256=expected_artifact_sha256,
            expected_distribution_name=expected_distribution_name,
            expected_version=expected_version,
        )
        target_fd = os.open(target_dir, os.O_RDONLY | self._directory | self._nofollow)
        try:
            if os.listdir(target_fd):
                raise WheelMaterializationError("target_dir_must_be_empty")
            manifest: list[dict[str, Any]] = []
            wheel_bytes = self._read_regular_file(wheel_path, maximum=MAX_TOTAL_BYTES)
            with zipfile.ZipFile(io.BytesIO(wheel_bytes), "r") as archive:
                for info in archive.infolist():
                    kind = _zip_entry_kind(info)
                    normalized = normalize_member_path(info.filename, directory=(kind == "directory"))
                    if kind == "directory":
                        self._ensure_directory_path(target_fd, normalized.rstrip("/"))
                        continue
                    data = self._read_member_bounded(archive, info.filename, MAX_MEMBER_BYTES)
                    if len(data) != info.file_size:
                        raise WheelMaterializationError("archive_member_size_changed")
                    self._write_regular_file(target_fd, normalized, data)
                    manifest.append({
                        "path_sha256": canonical_sha256(normalized),
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "mode": "0644",
                    })
            manifest.sort(key=lambda item: item["path_sha256"])
            output_manifest_sha = canonical_sha256({"schema": "liminal-wheel-output-manifest-v0.1", "files": manifest})
            total_bytes = sum(item["size"] for item in manifest)
            return {
                "audit": audit,
                "output_manifest_sha256": output_manifest_sha,
                "file_count": len(manifest),
                "total_bytes": total_bytes,
            }
        finally:
            os.close(target_fd)

    @staticmethod
    def _read_member_bounded(archive: zipfile.ZipFile, name: str, maximum: int) -> bytes:
        with archive.open(name, "r") as fh:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = fh.read(min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise WheelMaterializationError("archive_member_size_out_of_bounds")
                chunks.append(chunk)
            return b"".join(chunks)

    def _validate_record(self, archive: zipfile.ZipFile, record_bytes: bytes, file_paths: Iterable[str], record_path: str) -> None:
        try:
            text = record_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WheelMaterializationError("record_must_be_utf8") from exc
        reader = csv.reader(io.StringIO(text, newline=""))
        rows: dict[str, tuple[bytes | None, int | None]] = {}
        for row in reader:
            if len(row) != 3:
                raise WheelMaterializationError("record_row_shape_invalid")
            path = normalize_member_path(row[0], directory=False)
            if path in rows:
                raise WheelMaterializationError("record_contains_duplicate_path")
            hash_value, size_value = row[1], row[2]
            if path == record_path:
                if hash_value or size_value:
                    raise WheelMaterializationError("record_self_digest_must_be_empty")
                rows[path] = (None, None)
                continue
            if not hash_value or not size_value:
                raise WheelMaterializationError("record_digest_and_size_required")
            expected_digest = _decode_record_sha256(hash_value)
            try:
                expected_size = int(size_value)
            except ValueError as exc:
                raise WheelMaterializationError("record_size_invalid") from exc
            if expected_size < 0 or expected_size > MAX_MEMBER_BYTES:
                raise WheelMaterializationError("record_size_invalid")
            rows[path] = (expected_digest, expected_size)
        archive_files = set(file_paths)
        if set(rows) != archive_files or record_path not in rows:
            raise WheelMaterializationError("record_member_set_mismatch")
        for path in sorted(archive_files):
            if path == record_path:
                continue
            data = self._read_member_bounded(archive, path, MAX_MEMBER_BYTES)
            expected_digest, expected_size = rows[path]
            if expected_size != len(data) or expected_digest != hashlib.sha256(data).digest():
                raise WheelMaterializationError("record_member_digest_mismatch")

    def _ensure_directory_path(self, root_fd: int, relative: str) -> None:
        if not relative:
            return
        parts = normalize_member_path(relative, directory=False).split("/")
        current = os.dup(root_fd)
        try:
            for part in parts:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | self._directory | self._nofollow, dir_fd=current)
                os.close(current)
                current = nxt
        finally:
            os.close(current)

    def _write_regular_file(self, root_fd: int, relative: str, data: bytes) -> None:
        parts = normalize_member_path(relative, directory=False).split("/")
        current = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | self._directory | self._nofollow, dir_fd=current)
                os.close(current)
                current = nxt
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | self._nofollow, 0o600, dir_fd=current)
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(fd, data[offset:])
                    if written <= 0:
                        raise WheelMaterializationError("short_write")
                    offset += written
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(current)

    def create_fixed_target(self) -> str:
        tmp_fd = os.open("/tmp", os.O_RDONLY | self._directory | self._nofollow)
        try:
            try:
                os.mkdir("liminal-site-packages", 0o700, dir_fd=tmp_fd)
            except FileExistsError as exc:
                raise WheelMaterializationError("fixed_target_already_exists") from exc
            target_fd = os.open("liminal-site-packages", os.O_RDONLY | self._directory | self._nofollow, dir_fd=tmp_fd)
            os.close(target_fd)
        finally:
            os.close(tmp_fd)
        return TARGET


def materialize_bound_request(*, workspace: str, request: MaterializationRequest) -> dict[str, Any]:
    req = request.normalized()
    materializer = WheelMaterializer()
    wheel_filename, wheel_path = materializer.select_single_wheel(workspace)
    manifest_sha, dependency_sha = materializer.verify_staged_plan(workspace=workspace, wheel_filename=wheel_filename, request=req)
    target = materializer.create_fixed_target()
    result = materializer.materialize(
        wheel_path=wheel_path,
        wheel_filename=wheel_filename,
        target_dir=target,
        expected_artifact_sha256=req.artifact_sha256,
        expected_distribution_name=req.package_name,
        expected_version=req.version,
    )
    audit: WheelAudit = result["audit"]
    coordinate_sha = canonical_sha256({"registry": req.registry, "package_name": req.package_name, "version": req.version})
    base = WheelMaterializationReceipt(
        artifact_sha256=audit.artifact_sha256,
        staged_manifest_sha256=manifest_sha,
        dependency_plan_sha256=dependency_sha,
        wheel_audit_sha256=audit.audit_sha256,
        package_coordinate_sha256=coordinate_sha,
        output_manifest_sha256=result["output_manifest_sha256"],
        file_count=result["file_count"],
        total_bytes=result["total_bytes"],
        outcome="SUCCEEDED",
        receipt_sha256="",
    )
    receipt = WheelMaterializationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
    return receipt.as_document()


def verify_audit(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    expected = {
        "schema", "artifact_sha256", "distribution_name", "version", "dist_info_root_sha256",
        "member_count", "file_count", "total_uncompressed_bytes", "record_sha256",
        "member_manifest_sha256", "authority", "audit_sha256",
    }
    if set(raw) != expected:
        raise WheelMaterializationError("wheel_audit_schema_mismatch")
    digest = raw.pop("audit_sha256")
    if raw.get("schema") != AUDIT_SCHEMA or raw.get("authority") != _authority_document():
        raise WheelMaterializationError("wheel_audit_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise WheelMaterializationError("wheel_audit_digest_mismatch")
    return dict(document)


def verify_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    expected = {
        "schema", "artifact_sha256", "staged_manifest_sha256", "dependency_plan_sha256",
        "wheel_audit_sha256", "package_coordinate_sha256", "output_manifest_sha256",
        "file_count", "total_bytes", "outcome", "authority", "receipt_sha256",
    }
    if set(raw) != expected:
        raise WheelMaterializationError("wheel_receipt_schema_mismatch")
    digest = raw.pop("receipt_sha256")
    if raw.get("schema") != SCHEMA or raw.get("authority") != _authority_document():
        raise WheelMaterializationError("wheel_receipt_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise WheelMaterializationError("wheel_receipt_digest_mismatch")
    return dict(document)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LiminalOS concrete offline wheel materializer")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--registry-provenance", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--dependency-plan-sha256", required=True)
    parser.add_argument("--dependency-count", type=int, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--no-execute-installed-code", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.offline or not args.no_execute_installed_code:
        raise WheelMaterializationError("offline_and_no_execute_flags_required")
    receipt = materialize_bound_request(
        workspace=WORKSPACE,
        request=MaterializationRequest(
            manifest_sha256=args.manifest_sha256,
            registry=args.registry_provenance,
            package_name=args.package,
            version=args.version,
            artifact_sha256=args.artifact_sha256,
            dependency_plan_sha256=args.dependency_plan_sha256,
            dependency_count=args.dependency_count,
            target=args.target,
        ),
    )
    sys.stdout.write(canonical_json(receipt) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WheelMaterializationError as exc:
        sys.stderr.write(str(exc) + "\n")
        raise SystemExit(2)


__all__ = [
    "AUDIT_SCHEMA", "AUTHORITY", "DEPENDENCY_PLAN_SCHEMA", "MANIFEST_SCHEMA", "MAX_COMPRESSION_RATIO",
    "MAX_MEMBERS", "MAX_MEMBER_BYTES", "MAX_TOTAL_BYTES", "MaterializationRequest", "SCHEMA", "TARGET",
    "WORKSPACE", "WheelAudit", "WheelMaterializationError", "WheelMaterializationReceipt", "WheelMaterializer",
    "canonical_sha256", "materialize_bound_request", "normalize_distribution_name", "normalize_member_path",
    "normalize_registry", "normalize_version", "verify_audit", "verify_receipt",
]
