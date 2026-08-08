#!/usr/bin/env python3
"""Trusted offline wheel materializer for LiminalOS.

This module is intentionally a trusted filesystem adapter, not model-facing SDK.
It performs no network access, package resolution, subprocess execution, build
hooks, imports, or package-code execution. It verifies one staged wheel archive,
audits its ZIP structure and wheel metadata, then materializes regular files only
beneath an already-existing empty target directory.
"""
from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-wheel-materialization-receipt-v0.1"
AUDIT_SCHEMA = "liminal-wheel-audit-v0.1"
MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200

_AUTHORITY_ITEMS = (
    ("mode", "trusted_offline_wheel_materializer"),
    ("filesystem_read", True),
    ("ephemeral_target_write", True),
    ("target_must_preexist", True),
    ("target_must_be_empty", True),
    ("network_access", False),
    ("registry_access", False),
    ("dependency_resolution", False),
    ("subprocess_execution", False),
    ("package_code_execution", False),
    ("build_hooks", False),
    ("sdist_support", False),
    ("symlink_follow", False),
    ("special_file_materialization", False),
    ("archive_permission_preservation", False),
    ("output_files_executable", False),
    ("signature_or_malware_oracle", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))

_SHA = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9._+!-]{0,127}$")
_NAME = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class WheelMaterializationError(ValueError):
    pass


def _authority_document() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


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


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


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
    wheel_audit_sha256: str
    distribution_name: str
    version: str
    output_manifest_sha256: str
    file_count: int
    total_bytes: int
    outcome: str
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "artifact_sha256": self.artifact_sha256,
            "wheel_audit_sha256": self.wheel_audit_sha256,
            "distribution_name": self.distribution_name,
            "version": self.version,
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

    def audit(
        self,
        *,
        wheel_path: str,
        expected_artifact_sha256: str,
        expected_distribution_name: str,
        expected_version: str,
    ) -> WheelAudit:
        artifact_sha = _sha(expected_artifact_sha256, "artifact_sha256")
        distribution = normalize_distribution_name(expected_distribution_name)
        version = normalize_version(expected_version)
        if not isinstance(wheel_path, str) or not wheel_path.endswith(".whl"):
            raise WheelMaterializationError("wheel_path_must_end_in_whl")
        if _sha256_file(wheel_path) != artifact_sha:
            raise WheelMaterializationError("artifact_digest_mismatch")

        try:
            archive = zipfile.ZipFile(wheel_path, "r")
        except (OSError, zipfile.BadZipFile) as exc:
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
                kind = _zip_entry_kind(info)
                normalized = normalize_member_path(info.filename, directory=(kind == "directory"))
                if normalized in seen:
                    raise WheelMaterializationError("duplicate_archive_member")
                seen.add(normalized)
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
                if kind == "file":
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
            metadata_path = f"{dist_info}/METADATA"
            wheel_metadata_path = f"{dist_info}/WHEEL"
            record_path = f"{dist_info}/RECORD"
            required = {metadata_path, wheel_metadata_path, record_path}
            if not required.issubset(set(file_paths)):
                raise WheelMaterializationError("required_wheel_metadata_missing")

            metadata_bytes = self._read_member_bounded(archive, metadata_path, MAX_MEMBER_BYTES)
            message = BytesParser(policy=compat32).parsebytes(metadata_bytes)
            metadata_name = normalize_distribution_name(message.get("Name", ""))
            metadata_version = normalize_version(message.get("Version", ""))
            if metadata_name != distribution:
                raise WheelMaterializationError("wheel_distribution_name_mismatch")
            if metadata_version != version:
                raise WheelMaterializationError("wheel_version_mismatch")

            record_bytes = self._read_member_bounded(archive, record_path, MAX_MEMBER_BYTES)
            self._validate_record(record_bytes, file_paths)
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
        target_dir: str,
        expected_artifact_sha256: str,
        expected_distribution_name: str,
        expected_version: str,
    ) -> dict[str, Any]:
        audit = self.audit(
            wheel_path=wheel_path,
            expected_artifact_sha256=expected_artifact_sha256,
            expected_distribution_name=expected_distribution_name,
            expected_version=expected_version,
        )
        if not isinstance(target_dir, str) or not os.path.isabs(target_dir):
            raise WheelMaterializationError("target_dir_must_be_absolute")
        target_fd = os.open(target_dir, os.O_RDONLY | self._directory | self._nofollow)
        try:
            if os.listdir(target_fd):
                raise WheelMaterializationError("target_dir_must_be_empty")
            manifest: list[dict[str, Any]] = []
            with zipfile.ZipFile(wheel_path, "r") as archive:
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
                        "path": normalized,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    })
            manifest.sort(key=lambda item: item["path"])
            output_manifest_sha = canonical_sha256(manifest)
            total_bytes = sum(item["size"] for item in manifest)
            base = WheelMaterializationReceipt(
                artifact_sha256=audit.artifact_sha256,
                wheel_audit_sha256=audit.audit_sha256,
                distribution_name=audit.distribution_name,
                version=audit.version,
                output_manifest_sha256=output_manifest_sha,
                file_count=len(manifest),
                total_bytes=total_bytes,
                outcome="SUCCEEDED",
                receipt_sha256="",
            )
            receipt = WheelMaterializationReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
            return receipt.as_document()
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

    @staticmethod
    def _validate_record(record_bytes: bytes, file_paths: Iterable[str]) -> None:
        try:
            text = record_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WheelMaterializationError("record_must_be_utf8") from exc
        reader = csv.reader(io.StringIO(text, newline=""))
        observed: list[str] = []
        for row in reader:
            if len(row) != 3:
                raise WheelMaterializationError("record_row_shape_invalid")
            path = normalize_member_path(row[0], directory=False)
            observed.append(path)
            if row[2] and not row[2].isdigit():
                raise WheelMaterializationError("record_size_invalid")
        if len(observed) != len(set(observed)):
            raise WheelMaterializationError("record_contains_duplicate_path")
        archive_files = set(file_paths)
        if set(observed) != archive_files:
            raise WheelMaterializationError("record_member_set_mismatch")

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
        parent_parts = parts[:-1]
        leaf = parts[-1]
        current = os.dup(root_fd)
        try:
            for part in parent_parts:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                nxt = os.open(part, os.O_RDONLY | self._directory | self._nofollow, dir_fd=current)
                os.close(current)
                current = nxt
            fd = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | self._nofollow,
                0o644,
                dir_fd=current,
            )
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
        "schema", "artifact_sha256", "wheel_audit_sha256", "distribution_name", "version",
        "output_manifest_sha256", "file_count", "total_bytes", "outcome", "authority", "receipt_sha256",
    }
    if set(raw) != expected:
        raise WheelMaterializationError("wheel_receipt_schema_mismatch")
    digest = raw.pop("receipt_sha256")
    if raw.get("schema") != SCHEMA or raw.get("authority") != _authority_document():
        raise WheelMaterializationError("wheel_receipt_schema_mismatch")
    if digest != canonical_sha256(raw):
        raise WheelMaterializationError("wheel_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUDIT_SCHEMA", "AUTHORITY", "MAX_COMPRESSION_RATIO", "MAX_MEMBERS", "MAX_MEMBER_BYTES",
    "MAX_TOTAL_BYTES", "SCHEMA", "WheelAudit", "WheelMaterializationError",
    "WheelMaterializationReceipt", "WheelMaterializer", "normalize_distribution_name",
    "normalize_member_path", "normalize_version", "verify_audit", "verify_receipt",
]
