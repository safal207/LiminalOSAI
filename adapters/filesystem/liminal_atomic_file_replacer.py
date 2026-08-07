#!/usr/bin/env python3
"""Trusted POSIX backend for digest-bound LiminalOS file replacement.

This adapter owns host filesystem authority. It consumes one authenticated file
mutation lease, verifies the exact content and expected-before digest, walks the
path through no-follow directory descriptors, and replaces one existing regular
file atomically within the same directory.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from sdk.liminal_file_mutation_broker import FileMutationBroker, FileMutationError
from sdk.liminal_post_sandbox_contracts import canonical_sha256

SCHEMA = "liminal-file-mutation-execution-receipt-v0.1"

_AUTHORITY_ITEMS = (
    ("mode", "trusted_posix_file_replacement_backend"),
    ("filesystem_access", True),
    ("existing_regular_file_replace", True),
    ("file_create", False),
    ("file_delete", False),
    ("arbitrary_rename", False),
    ("symlink_follow", False),
    ("network_authority", False),
    ("process_authority", False),
    ("secret_material_access", False),
)
AUTHORITY = MappingProxyType(dict(_AUTHORITY_ITEMS))


class AtomicFileReplaceError(RuntimeError):
    pass


def _authority_document() -> dict[str, Any]:
    return dict(_AUTHORITY_ITEMS)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_digest(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class FileMutationExecutionReceipt:
    lease_id_sha256: str
    authorization_receipt_sha256: str
    binding_sha256: str
    relative_path_sha256: str
    before_sha256: str
    after_sha256: str
    content_length: int
    outcome: str
    error_type_sha256: str | None
    receipt_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "lease_id_sha256": self.lease_id_sha256,
            "authorization_receipt_sha256": self.authorization_receipt_sha256,
            "binding_sha256": self.binding_sha256,
            "relative_path_sha256": self.relative_path_sha256,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "content_length": self.content_length,
            "outcome": self.outcome,
            "error_type_sha256": self.error_type_sha256,
            "authority": _authority_document(),
        }

    def as_document(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}


class AtomicFileReplacer:
    def __init__(
        self,
        *,
        broker: FileMutationBroker,
        adapter_token: str,
        host_roots: Mapping[str, str],
    ) -> None:
        if not isinstance(adapter_token, str) or not adapter_token:
            raise AtomicFileReplaceError("invalid_adapter_token")
        roots: dict[str, str] = {}
        for root_id, host_root in dict(host_roots).items():
            if not isinstance(root_id, str) or not root_id:
                raise AtomicFileReplaceError("invalid_root_id")
            if not isinstance(host_root, str) or not os.path.isabs(host_root):
                raise AtomicFileReplaceError("host_root_must_be_absolute")
            roots[root_id] = host_root
        if not roots:
            raise AtomicFileReplaceError("host_roots_required")
        self.broker = broker
        self._adapter_token = adapter_token
        self._host_roots = MappingProxyType(roots)

    def replace(self, *, lease_id: str, content: bytes) -> dict[str, Any]:
        if not isinstance(content, bytes):
            raise AtomicFileReplaceError("content_must_be_bytes")
        ref = self.broker.consume_for_trusted_adapter(lease_id, adapter_token=self._adapter_token)
        before = ref.expected_before_sha256
        after = ref.desired_content_sha256
        common = {
            "lease_id_sha256": canonical_sha256(ref.lease_id),
            "authorization_receipt_sha256": ref.authorization_receipt_sha256,
            "binding_sha256": ref.binding_sha256,
            "relative_path_sha256": canonical_sha256(ref.relative_path),
            "before_sha256": before,
            "after_sha256": after,
            "content_length": ref.content_length,
        }
        try:
            if len(content) != ref.content_length or _sha256_bytes(content) != after:
                raise AtomicFileReplaceError("authorized_content_mismatch")
            host_root = self._host_roots.get(ref.root_id)
            if host_root is None:
                raise AtomicFileReplaceError("unmapped_root_id")
            self._replace_under_root(
                host_root=host_root,
                relative_path=ref.relative_path,
                expected_before_sha256=before,
                desired_content_sha256=after,
                content=content,
                lease_id=ref.lease_id,
            )
            return self._receipt(**common, outcome="SUCCEEDED", error_type_sha256=None)
        except Exception as exc:
            return self._receipt(
                **common,
                outcome="FAILED",
                error_type_sha256=canonical_sha256({"error_type": type(exc).__name__}),
            )

    def _replace_under_root(
        self,
        *,
        host_root: str,
        relative_path: str,
        expected_before_sha256: str,
        desired_content_sha256: str,
        content: bytes,
        lease_id: str,
    ) -> None:
        components = relative_path.split("/")
        if not components or any(part in {"", ".", ".."} for part in components):
            raise AtomicFileReplaceError("invalid_relative_path")

        root_flags = os.O_RDONLY | os.O_DIRECTORY
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(host_root, root_flags | nofollow)
        opened: list[int] = [root_fd]
        parent_fd = root_fd
        temp_name: str | None = None
        try:
            for component in components[:-1]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | nofollow, dir_fd=parent_fd)
                opened.append(next_fd)
                parent_fd = next_fd

            leaf = components[-1]
            target_fd = os.open(leaf, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            try:
                target_stat = os.fstat(target_fd)
                if not stat.S_ISREG(target_stat.st_mode):
                    raise AtomicFileReplaceError("target_not_regular_file")
                first_before = _read_digest(target_fd)
                original_mode = stat.S_IMODE(target_stat.st_mode)
            finally:
                os.close(target_fd)
            if first_before != expected_before_sha256:
                raise AtomicFileReplaceError("stale_before_digest")

            temp_name = f".liminal-tmp-{hashlib.sha256(lease_id.encode('utf-8')).hexdigest()[:24]}"
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                offset = 0
                while offset < len(content):
                    written = os.write(temp_fd, content[offset:])
                    if written <= 0:
                        raise AtomicFileReplaceError("short_write")
                    offset += written
                os.fchmod(temp_fd, original_mode)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)

            # Re-check the named target immediately before replacement. This
            # catches ordinary stale-write races while retaining a no-follow
            # descriptor path. The host/kernel remains part of the trust base.
            check_fd = os.open(leaf, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            try:
                check_stat = os.fstat(check_fd)
                if not stat.S_ISREG(check_stat.st_mode):
                    raise AtomicFileReplaceError("target_changed_type")
                second_before = _read_digest(check_fd)
            finally:
                os.close(check_fd)
            if second_before != expected_before_sha256:
                raise AtomicFileReplaceError("stale_before_digest")

            os.replace(temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            temp_name = None
            os.fsync(parent_fd)

            verify_fd = os.open(leaf, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            try:
                verify_stat = os.fstat(verify_fd)
                if not stat.S_ISREG(verify_stat.st_mode):
                    raise AtomicFileReplaceError("post_replace_not_regular")
                observed_after = _read_digest(verify_fd)
            finally:
                os.close(verify_fd)
            if observed_after != desired_content_sha256:
                raise AtomicFileReplaceError("post_replace_digest_mismatch")
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            for fd in reversed(opened):
                try:
                    os.close(fd)
                except OSError:
                    pass

    @staticmethod
    def _receipt(
        *,
        lease_id_sha256: str,
        authorization_receipt_sha256: str,
        binding_sha256: str,
        relative_path_sha256: str,
        before_sha256: str,
        after_sha256: str,
        content_length: int,
        outcome: str,
        error_type_sha256: str | None,
    ) -> dict[str, Any]:
        base = FileMutationExecutionReceipt(
            lease_id_sha256=lease_id_sha256,
            authorization_receipt_sha256=authorization_receipt_sha256,
            binding_sha256=binding_sha256,
            relative_path_sha256=relative_path_sha256,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            content_length=content_length,
            outcome=outcome,
            error_type_sha256=error_type_sha256,
            receipt_sha256="",
        )
        receipt = FileMutationExecutionReceipt(**{**base.__dict__, "receipt_sha256": canonical_sha256(base.body())})
        return receipt.as_document()


def verify_execution_receipt(document: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(document)
    expected = {
        "schema", "lease_id_sha256", "authorization_receipt_sha256", "binding_sha256",
        "relative_path_sha256", "before_sha256", "after_sha256", "content_length",
        "outcome", "error_type_sha256", "authority", "receipt_sha256",
    }
    if set(raw) != expected:
        raise AtomicFileReplaceError("execution_receipt_schema_mismatch")
    receipt_sha = raw.pop("receipt_sha256")
    if raw.get("schema") != SCHEMA or raw.get("authority") != _authority_document():
        raise AtomicFileReplaceError("execution_receipt_schema_mismatch")
    if receipt_sha != canonical_sha256(raw):
        raise AtomicFileReplaceError("execution_receipt_digest_mismatch")
    return dict(document)


__all__ = [
    "AUTHORITY", "AtomicFileReplaceError", "AtomicFileReplacer", "FileMutationExecutionReceipt",
    "SCHEMA", "verify_execution_receipt",
]
