"""Durable session admission around the host's existing strict egress gateway.

This adapter never opens sockets. The trusted host must make it the only exposed
egress path, own the callbacks and keep its SQLite database/admin methods away
from workers. A returned transport response is not evidence of remote commit.
STOP prevents new stage admission; an already admitted callback can finish later.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict
from threading import RLock
from typing import Any, Callable
from weakref import WeakKeyDictionary

from sdk.liminal_capability_broker import BrokerError, CapabilityBroker
from sdk.liminal_egress_gateway import EgressBlocked, EgressError, EgressGateway, GatewayRequest

from .authority import ACTION_FIELDS, ControlError, canonical_bytes, connect, digest, validate_id
from .brakes_store import SessionAuthority


_INCARNATIONS: WeakKeyDictionary = WeakKeyDictionary()
_INCARNATION_LOCK = RLock()


def _incarnation(broker: CapabilityBroker) -> str:
    """An in-memory broker's quotas/revocations cannot safely survive a restart."""
    with _INCARNATION_LOCK:
        old = _INCARNATIONS.get(broker)
        if old is None or old[0] != os.getpid():
            old = (os.getpid(), f"{os.getpid()}:{uuid.uuid4().hex}")
            _INCARNATIONS[broker] = old
        return old[1]


def request_digest(request: GatewayRequest) -> str:
    """Exact request commitment, including header values and secret references."""
    if not isinstance(request, GatewayRequest):
        raise ControlError("expected GatewayRequest")
    value = asdict(request)
    if len(canonical_bytes(value)) > 16384:
        raise ControlError("egress request exceeds 16 KiB")
    return digest(value)


def network_action(*, root_id: str, execution_id: str, epoch: int, action_id: str,
                   attempt_id: str, request: GatewayRequest) -> dict[str, Any]:
    return {"root_id": root_id, "execution_id": execution_id, "epoch": epoch,
            "action_id": action_id, "attempt_id": attempt_id, "target": "network",
            "arguments": {"request_sha256": request_digest(request)}}


class _PinnedBroker:
    """Prevent selection of another subject's or another host grant's capability."""
    def __init__(self, broker: CapabilityBroker, capability_id: str, contract_digest: str):
        self.broker, self.capability_id, self.contract_digest = broker, capability_id, contract_digest

    def authorize(self, **kwargs: Any) -> dict[str, Any]:
        state = next((cap for cap in self.broker.state_document()["capabilities"]
                      if cap["capability_id"] == self.capability_id), None)
        if state is None or state["contract_sha256"] != self.contract_digest:
            raise EgressBlocked("EXACT_CAPABILITY_MISMATCH")
        receipt = self.broker.authorize(**kwargs)
        if receipt["decision"] != "ALLOW" or receipt["capability_id"] != self.capability_id:
            raise EgressBlocked("EXACT_CAPABILITY_DENIED")
        return receipt


class _StagedGateway(EgressGateway):
    def __init__(self, *, authority: SessionAuthority, action_id: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.authority, self.action_id, self.stage_number = authority, action_id, 0

    def _stage(self, capability: dict[str, Any], request: GatewayRequest, callback: Callable[[], Any]) -> Any:
        # Keep the capability lock through durable stage admission so its revoke
        # ACK cannot precede a new reservation. Release both locks before I/O.
        self.stage_number += 1
        stage_id = f"stage:{self.stage_number}"
        try:
            with self.broker.broker.live_use(capability, at_unix=lambda: self._now(request)):
                admitted = self.authority.begin_stage(self.action_id, stage_id=stage_id)
        except BrokerError as exc:
            raise EgressBlocked("CAPABILITY_NOT_LIVE") from exc
        if admitted["status"] != "ADMITTED":
            raise EgressBlocked(admitted["reason"])
        try:
            result = callback()
        except BaseException:
            self.authority.finish_stage(self.action_id, stage_id, outcome="UNKNOWN")
            raise
        self.authority.finish_stage(self.action_id, stage_id, outcome="RETURNED")
        return result


class SessionEgressGateway:
    """Host-only exact grants, worker proposals, and shared durable root brakes.

    ``authorize`` is an administrative host method, not a worker-facing tool.
    ``execute`` only consumes an existing grant and cannot renew a session.
    A RESERVED/UNKNOWN action is never redispatched, including after restart.
    Each root pins one capability-broker incarnation: process loss/fork or broker
    recreation requires a new root, preserving its otherwise in-memory limits.
    Supported lineage is SessionAuthority execution ancestry with individual
    non-delegable network contracts; capability-parent delegation is not enabled
    here. Freshness checks cover the selected capability and the common root.
    """
    def __init__(self, *, authority: SessionAuthority, broker: CapabilityBroker,
                 resolver: Callable, transport: Callable, secret_resolver: Callable | None = None,
                 max_redirects: int = 3, clock: Callable[[], int] = lambda: int(time.time())):
        self.authority, self.broker = authority, broker
        self.options = dict(resolver=resolver, transport=transport, secret_resolver=secret_resolver,
                            max_redirects=max_redirects, clock=clock)
        # Validate host configuration before a durable grant can be created.
        EgressGateway(broker=broker, **self.options)
        with connect(authority.db_path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS brakes_egress_brokers (
                root_id TEXT PRIMARY KEY REFERENCES brakes_sessions(root_id),
                incarnation TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS brakes_egress_grants (
                action_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                root_id TEXT NOT NULL REFERENCES brakes_sessions(root_id),
                action_digest TEXT NOT NULL, request_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL, capability_id TEXT NOT NULL,
                contract_digest TEXT NOT NULL
            )""")

    def _inputs(self, action: dict[str, Any], request: GatewayRequest) -> tuple[dict[str, Any], GatewayRequest, str]:
        # Freeze mutable caller dictionaries before validation or callbacks.
        if not isinstance(request, GatewayRequest):
            raise ControlError("expected GatewayRequest")
        request = GatewayRequest(**json.loads(canonical_bytes(asdict(request))))
        payload_digest = request_digest(request)
        if not isinstance(action, dict) or set(action) != ACTION_FIELDS:
            raise ControlError("invalid network action fields")
        action = json.loads(canonical_bytes(action))
        for field in ("action_id", "attempt_id", "root_id", "execution_id"):
            validate_id(action[field], field)
        if type(action["epoch"]) is not int or not 1 <= action["epoch"] < 2**63:
            raise ControlError("invalid epoch")
        if (action["target"] != "network" or action["arguments"] != {"request_sha256": payload_digest}
                or request.call_id != action["action_id"] or request.subject_id != action["execution_id"]):
            raise ControlError("NETWORK_ACTION_REQUEST_BINDING_MISMATCH")
        normalized = EgressGateway(broker=self.broker, **self.options)._normalize_request(request)
        return action, normalized, payload_digest

    @staticmethod
    def _blocked(reason: str, action_id: str | None = None) -> dict[str, Any]:
        return {"status": "BLOCKED", "reason": reason, "action_id": action_id,
                "external_effect": "UNKNOWN"}

    def _broker_matches(self, db: Any, root_id: str, *, bind: bool = False) -> bool:
        current = _incarnation(self.broker)
        old = db.execute("SELECT incarnation FROM brakes_egress_brokers WHERE root_id=?", (root_id,)).fetchone()
        if old is None and bind:
            db.execute("INSERT INTO brakes_egress_brokers VALUES (?,?)", (root_id, current))
            return True
        return old is not None and old[0] == current

    def authorize(self, action: dict[str, Any], request: GatewayRequest, *, capability_id: str) -> dict[str, Any]:
        """Persist one immutable host-approved action/request/capability tuple."""
        action, request, payload_digest = self._inputs(action, request)
        validate_id(capability_id, "capability_id")
        cap = next((item for item in self.broker.state_document()["capabilities"]
                    if item["capability_id"] == capability_id), None)
        if cap is None or cap["status"] != "active":
            return self._blocked("CAPABILITY_NOT_ACTIVE", action["action_id"])
        values = (action["action_id"], action["attempt_id"], action["root_id"], digest(action),
                  payload_digest, request.policy_sha256, capability_id, cap["contract_sha256"])
        with connect(self.authority.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            live = self.authority.check_session_in_transaction(db, action["root_id"])
            if live["status"] != "ADMITTED":
                return self._blocked(live["reason"], action["action_id"])
            if live["policy_digest"] != request.policy_sha256 or live["epoch"] != action["epoch"]:
                return self._blocked("POLICY_OR_EPOCH_MISMATCH", action["action_id"])
            if not self._broker_matches(db, action["root_id"], bind=True):
                return self._blocked("BROKER_RESTART_REQUIRES_NEW_ROOT", action["action_id"])
            old = db.execute("SELECT * FROM brakes_egress_grants WHERE action_id=? OR attempt_id=?",
                             (action["action_id"], action["attempt_id"])).fetchone()
            if old is not None and tuple(old) != values:
                return self._blocked("EXACT_GRANT_IMMUTABLE", action["action_id"])
            if old is None:
                db.execute("INSERT INTO brakes_egress_grants VALUES (?,?,?,?,?,?,?,?)", values)
        return {"status": "AUTHORIZED", "action_id": action["action_id"], "request_digest": payload_digest}

    def execute(self, action: dict[str, Any], request: GatewayRequest) -> dict[str, Any]:
        action, request, payload_digest = self._inputs(action, request)
        with connect(self.authority.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            grant = db.execute("SELECT * FROM brakes_egress_grants WHERE action_id=?", (action["action_id"],)).fetchone()
            if grant is None:
                return self._blocked("NO_EXACT_NETWORK_GRANT", action["action_id"])
            if (grant["action_digest"] != digest(action) or grant["request_digest"] != payload_digest
                    or grant["policy_digest"] != request.policy_sha256):
                return self._blocked("EXACT_NETWORK_GRANT_MISMATCH", action["action_id"])
            if not self._broker_matches(db, action["root_id"]):
                return self._blocked("BROKER_RESTART_REQUIRES_NEW_ROOT", action["action_id"])
            admitted = self.authority.admit_in_transaction(
                db, action, channel="egress", payload_digest=payload_digest, policy_digest=request.policy_sha256)
        if admitted["status"] != "ADMITTED":
            return self._blocked(admitted["reason"], action["action_id"])
        gateway = _StagedGateway(authority=self.authority, action_id=action["action_id"],
                                broker=_PinnedBroker(self.broker, grant["capability_id"], grant["contract_digest"]),
                                **self.options)
        try:
            receipt = gateway.execute(request)
        except BaseException as exc:
            self.authority.finish_action(action["action_id"], outcome="UNKNOWN")
            if not isinstance(exc, Exception):
                raise
            if isinstance(exc, (EgressBlocked, EgressError, BrokerError)):
                return self._blocked(str(exc), action["action_id"])
            return {"status": "UNKNOWN", "reason": "CALLBACK_OUTCOME_UNKNOWN", "action_id": action["action_id"],
                    "external_effect": "UNKNOWN"}
        self.authority.finish_action(action["action_id"], outcome="RETURNED")
        return {"status": "RETURNED", "reason": "TRANSPORT_RETURNED", "action_id": action["action_id"],
                "external_effect": "UNKNOWN", "network_receipt": receipt}
