"""Small durability harness for portable receipt projections.

This is a reference conformance harness, not LiminalDB.  It demonstrates the
append/snapshot/reopen/replay invariant before a native cross-repository adapter
is merged into LiminalDB.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from ._contracts import AUTHORITY, ReceiptError, canonical_sha256, sha256

LEDGER_SCHEMA = "liminal-portable-receipt-projection-ledger-v1.2"
SNAPSHOT_SCHEMA = "liminal-portable-receipt-projection-snapshot-v1.2"


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ReceiptError(f"projection ledger lock already exists: {lock_path}") from exc
    try:
        try:
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        yield
    finally:
        lock_path.unlink(missing_ok=True)


def _atomic_write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(value.encode("utf-8") if isinstance(value, str) else value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _read_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    result: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"projection ledger line {line_number} is invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ReceiptError(f"projection ledger line {line_number} must be an object")
        result.append(value)
    return result


class ProjectionLedger:
    """Hash-chained append-only projection ledger with deterministic snapshot."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.journal_path = self.root / "projection-ledger.jsonl"
        self.snapshot_path = self.root / "projection-ledger.snapshot.json"
        self.root.mkdir(parents=True, exist_ok=True)
        self.verify()
        if self.snapshot_path.exists():
            self.verify_snapshot()

    def append(
        self,
        *,
        source_receipt_sha256: str,
        projection_profile: str,
        projection: Mapping[str, Any],
    ) -> dict[str, Any]:
        with _exclusive_lock(self.journal_path):
            current = self.verify()
            if self.snapshot_path.exists():
                self.verify_snapshot()
            receipt_hash = sha256(source_receipt_sha256, "source_receipt_sha256")
            if receipt_hash in current["receipt_refs"]:
                raise ReceiptError("projection ledger already contains this receipt")
            if not isinstance(projection_profile, str) or not projection_profile.strip():
                raise ReceiptError("projection_profile must be non-empty")
            body = {
                "schema_version": LEDGER_SCHEMA,
                "sequence": current["entry_count"] + 1,
                "source_receipt_sha256": receipt_hash,
                "projection_profile": projection_profile,
                "projection_sha256": canonical_sha256(dict(projection)),
                "previous_entry_sha256": current["head_sha256"],
                "authority": AUTHORITY,
            }
            entry = {**body, "entry_sha256": canonical_sha256(body)}
            prior = self.journal_path.read_bytes() if self.journal_path.exists() else b""
            # Preserve historical wire bytes, including legacy whitespace/newlines.
            separator = b"" if not prior or prior.endswith(b"\n") else b"\n"
            line = (json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
            _atomic_write(self.journal_path, prior + separator + line)
            return entry

    def verify(self) -> dict[str, Any]:
        return self._verify_entries(_read_lines(self.journal_path))

    @staticmethod
    def _verify_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
        previous: str | None = None
        receipt_refs: list[str] = []
        seen_receipts: set[str] = set()
        projection_hashes: list[str] = []
        for index, raw in enumerate(entries, start=1):
            expected_keys = {
                "schema_version", "sequence", "source_receipt_sha256",
                "projection_profile", "projection_sha256", "previous_entry_sha256",
                "authority", "entry_sha256",
            }
            if set(raw) != expected_keys:
                raise ReceiptError(f"projection ledger entry {index} has unsupported fields")
            if raw["schema_version"] != LEDGER_SCHEMA or raw["authority"] != AUTHORITY:
                raise ReceiptError(f"projection ledger entry {index} contract mismatch")
            if raw["sequence"] != index:
                raise ReceiptError("projection ledger sequence mismatch")
            receipt_hash = sha256(raw["source_receipt_sha256"], "projection ledger receipt")
            projection_hash = sha256(raw["projection_sha256"], "projection ledger projection")
            if raw["previous_entry_sha256"] != previous:
                raise ReceiptError("projection ledger ancestry mismatch")
            body = {key: raw[key] for key in raw if key != "entry_sha256"}
            if canonical_sha256(body) != raw["entry_sha256"]:
                raise ReceiptError("projection ledger entry hash mismatch")
            if receipt_hash in seen_receipts:
                raise ReceiptError("projection ledger contains duplicate receipt reference")
            seen_receipts.add(receipt_hash)
            receipt_refs.append(receipt_hash)
            projection_hashes.append(projection_hash)
            previous = raw["entry_sha256"]
        return {
            "schema_version": LEDGER_SCHEMA,
            "entry_count": len(receipt_refs),
            "head_sha256": previous,
            "receipt_refs": receipt_refs,
            "projection_digest": canonical_sha256(projection_hashes),
            "authority_effect": "none",
            "authority": AUTHORITY,
        }

    def write_snapshot(self) -> dict[str, Any]:
        with _exclusive_lock(self.journal_path):
            state = self.verify()
            if self.snapshot_path.exists():
                self.verify_snapshot()
            body = {
                "schema_version": SNAPSHOT_SCHEMA,
                "entry_count": state["entry_count"],
                "head_sha256": state["head_sha256"],
                "receipt_refs": state["receipt_refs"],
                "projection_digest": state["projection_digest"],
                "authority": AUTHORITY,
            }
            snapshot = {**body, "snapshot_sha256": canonical_sha256(body)}
            _atomic_write(
                self.snapshot_path,
                json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            )
            return snapshot

    def verify_snapshot(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ReceiptError("projection snapshot does not exist") from exc
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"projection snapshot is invalid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise ReceiptError("projection snapshot must be an object")
        required = {
            "schema_version", "entry_count", "head_sha256", "receipt_refs",
            "projection_digest", "authority", "snapshot_sha256",
        }
        if set(raw) != required or raw["schema_version"] != SNAPSHOT_SCHEMA or raw["authority"] != AUTHORITY:
            raise ReceiptError("projection snapshot contract mismatch")
        body = {key: raw[key] for key in raw if key != "snapshot_sha256"}
        if canonical_sha256(body) != raw["snapshot_sha256"]:
            raise ReceiptError("projection snapshot digest mismatch")
        entries = _read_lines(self.journal_path)
        current = self._verify_entries(entries)
        count = raw["entry_count"]
        if type(count) is not int or not 0 <= count <= current["entry_count"]:
            raise ReceiptError("projection snapshot entry_count is not a valid journal prefix")
        prefix = self._verify_entries(entries[:count])
        expected = {
            "entry_count": prefix["entry_count"],
            "head_sha256": prefix["head_sha256"],
            "receipt_refs": prefix["receipt_refs"],
            "projection_digest": prefix["projection_digest"],
        }
        actual = {key: raw[key] for key in expected}
        if actual != expected:
            raise ReceiptError("snapshot-assisted state differs from full projection replay prefix")
        return {
            **raw,
            "checkpoint_replay_equal": True,
            "replay_equal": count == current["entry_count"],
            "current_entry_count": current["entry_count"],
            "current_head_sha256": current["head_sha256"],
            "authority_effect": "none",
        }
