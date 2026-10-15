"""Owned receiver-backed agent control pilot; trusted-host APIs only."""
from .authority import AuthorityStore, ControlError, canonical_bytes, digest, validate_action, verify_receipt
from .broker import Broker

__all__ = ["AuthorityStore", "ControlError", "Broker", "Receiver", "HTTPReceiverClient", "canonical_bytes", "digest", "validate_action", "verify_receipt"]


def __getattr__(name):
    if name in {"Receiver", "HTTPReceiverClient"}:
        from .receiver import Receiver, HTTPReceiverClient
        return {"Receiver": Receiver, "HTTPReceiverClient": HTTPReceiverClient}[name]
    raise AttributeError(name)
