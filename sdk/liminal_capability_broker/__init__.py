"""Defensive, default-deny capability lifecycle broker for LiminalOS Phase 1.

This package evaluates previously defined capability contracts. It does not execute
commands, access credentials, open network connections, merge code, deploy, or
perform containment.
"""

from .broker import BROKER_AUTHORITY, BrokerError, CapabilityBroker, CapabilityDecisionReceipt

__all__ = ["BROKER_AUTHORITY", "BrokerError", "CapabilityBroker", "CapabilityDecisionReceipt"]
