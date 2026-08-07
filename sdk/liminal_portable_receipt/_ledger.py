"""Small durability harness for portable receipt projections.

This is a reference conformance harness, not LiminalDB.  It demonstrates the
append/snapshot/reopen/replay invariant before a native cross-repository adapter
is merged into LiminalDB.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from ._contracts import AUTHORITY, ReceiptError, canonical_sha256, sha256

LEDGER_SCHEMA = "liminal-portable-receipt-projection-ledger-v1.2"
SNAPSHOT_SCHEMA = "liminal-portable-receipt-projection-snapshot-v1.2"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
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
        current = self.verify()
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
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.verify()
        return entry

    def verify(self) -> dict[str, Any]:
        previous: str | None = None
        receipt_refs: list[str] = []
        projection_hashes: list[str] = []
        for index, raw in enumerate(_read_lines(self.journal_path), start=1):
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
            if receipt_hash in receipt_refs:
                raise ReceiptError("projection ledger contains duplicate receipt reference")
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
        state = self.verify()
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
        current = self.verify()
        expected = {
            "entry_count": current["entry_count"],
            "head_sha256": current["head_sha256"],
            "receipt_refs": current["receipt_refs"],
            "projection_digest": current["projection_digest"],
        }
        actual = {key: raw[key] for key in expected}
        if actual != expected:
            raise ReceiptError("snapshot-assisted state differs from full projection replay")
        return {**raw, "replay_equal": True, "authority_effect": "none"}
