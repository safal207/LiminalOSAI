"""Public API for ChatGPT Host Integration Adapter v0.5."""

from ._adapter import HostIntegrationAdapter, ToolCallHandle
from ._core import AUTHORITY, HOST_TRACE_SCHEMA, HostAdapterError, ToolCallSpec
from ._trace import validate_trace

__all__ = [
    "AUTHORITY",
    "HOST_TRACE_SCHEMA",
    "HostAdapterError",
    "HostIntegrationAdapter",
    "ToolCallHandle",
    "ToolCallSpec",
    "validate_trace",
]
