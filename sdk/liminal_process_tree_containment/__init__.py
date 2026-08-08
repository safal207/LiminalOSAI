"""Compatibility shim for the renamed strict process-lineage evidence profile.

New code should import :mod:`sdk.liminal_process_lineage`. This module grants no
additional authority and intentionally re-exports the same implementation and
unique lineage schemas rather than defining a competing process-tree protocol.
"""
from sdk.liminal_process_lineage import (
    ACTION_SCHEMA,
    AUTHORITY,
    OBSERVATION_SCHEMA,
    SCHEMA,
    ProcessLineageBackend,
    ProcessLineageContainmentReceipt,
    ProcessLineageContainmentSupervisor,
    ProcessLineageError,
    ProcessLineageObservation,
    ProcessNode,
    verify_receipt,
)

# Backward-compatible names for the Docker adapter and any existing callers.
ProcessTreeBackend = ProcessLineageBackend
ProcessTreeContainmentReceipt = ProcessLineageContainmentReceipt
ProcessTreeContainmentSupervisor = ProcessLineageContainmentSupervisor
ProcessTreeError = ProcessLineageError
ProcessTreeObservation = ProcessLineageObservation

__all__ = [
    "ACTION_SCHEMA",
    "AUTHORITY",
    "OBSERVATION_SCHEMA",
    "SCHEMA",
    "ProcessNode",
    "ProcessTreeBackend",
    "ProcessTreeContainmentReceipt",
    "ProcessTreeContainmentSupervisor",
    "ProcessTreeError",
    "ProcessTreeObservation",
    "verify_receipt",
]
