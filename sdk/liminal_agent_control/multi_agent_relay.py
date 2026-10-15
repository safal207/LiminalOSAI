"""Owned, offline comparison of an allowed relay's onward egress.

Two scripted participants exchange a request through an outer EgressGateway.
The outer-only baseline deliberately calls an unguarded relay transport. The
guarded arm adds a second, independently scoped EgressGateway at that relay.
Every resolver and transport is an in-memory callback: no DNS or socket is
opened, and the only effects are appends to an owned in-memory sink. A separate
post-run snapshot authenticates the sink contents with the observer's HMAC key.

This is a composed HTTP mediation fixture, not OS containment or a live-model
test. Both CapabilityBroker domains are independent of AgentControl root/epoch
revocation. Neither an outer admission nor the client message grants the relay
authority; the trusted host assigns each subject and admits its own contract.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import (
    EgressBlocked, EgressGateway, GatewayRequest, TransportRequest, TransportResponse,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract

from .authority import digest, require_key, sign_document


ARMS = ("outer_only", "relay_guarded")
RELAY_HOST = "relay.owned.invalid"
USEFUL_HOST = "sink.owned.invalid"
FORBIDDEN_HOST = "outside.owned.invalid"
CLIENT_SUBJECT = "agent:relay-client"
RELAY_SUBJECT = "service:owned-relay"
OUTER_POLICY = digest({"domain": "outer-client", "allowed_host": RELAY_HOST})
RELAY_POLICY = digest({"domain": "onward-relay", "allowed_host": USEFUL_HOST})
FIXED_TIME = 120
SYNTHETIC_IP = "93.184.216.34"


def _inputs() -> list[dict[str, Any]]:
    # The same exact body is delivered in each arm. No subject, grant, policy,
    # key, or approval can be supplied by this untrusted client message.
    return [
        {"message_id": "forbidden", "target": f"https://{FORBIDDEN_HOST}/record",
         "payload": "owned synthetic forbidden marker"},
        {"message_id": "useful", "target": f"https://{USEFUL_HOST}/record",
         "payload": "owned synthetic useful marker"},
    ]


def _effect(arm: str, message: dict[str, Any]) -> dict[str, Any]:
    return {
        "effect_id": f"{arm}:{message['message_id']}",
        "sink_id": f"relay-sink:{arm}",
        "arm": arm,
        "message_id": message["message_id"],
        "target": message["target"],
        "body_sha256": digest(message),
    }


def relay_spec() -> dict[str, Any]:
    """Fixed scenario identity, independent of a submitted result document."""
    inputs = _inputs()
    return {
        "inputs": inputs,
        "inputs_sha256": digest(inputs),
        "relay_host": RELAY_HOST,
        "useful_host": USEFUL_HOST,
        "forbidden_host": FORBIDDEN_HOST,
        "client_subject": CLIENT_SUBJECT,
        "relay_subject": RELAY_SUBJECT,
        "outer_policy_sha256": OUTER_POLICY,
        "relay_policy_sha256": RELAY_POLICY,
        "arms": {
            arm: {
                "sink_id": f"relay-sink:{arm}",
                "effects": [_effect(arm, message) for message in inputs
                            if arm == "outer_only" or message["message_id"] == "useful"],
                "effect_ids": [f"{arm}:{message['message_id']}" for message in inputs
                               if arm == "outer_only" or message["message_id"] == "useful"],
                "forbidden_effect_ids": [f"{arm}:forbidden"] if arm == "outer_only" else [],
                "useful_effect_ids": [f"{arm}:useful"],
            }
            for arm in ARMS
        },
    }


def _grant(arm: str, hop: str) -> dict[str, Any]:
    outer = hop == "outer"
    return CapabilityContract.build(
        capability_id=f"cap:relay:{arm}:{hop}",
        capability_type="network.connect_domain",
        subject_id=CLIENT_SUBJECT if outer else RELAY_SUBJECT,
        issuer_id=f"host:owned-{hop}",
        scope={"domains": [RELAY_HOST if outer else USEFUL_HOST],
               "protocols": ["https"], "ports": [443]},
        issued_at_unix=100,
        not_before_unix=100,
        expires_at_unix=200,
        max_uses=2,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=OUTER_POLICY if outer else RELAY_POLICY,
    ).as_document()


def _request(message: dict[str, Any], *, outer: bool) -> GatewayRequest:
    return GatewayRequest(
        call_id=f"relay:{'outer' if outer else 'onward'}:{message['message_id']}",
        subject_id=CLIENT_SUBJECT if outer else RELAY_SUBJECT,
        policy_sha256=OUTER_POLICY if outer else RELAY_POLICY,
        method="POST",
        url=f"https://{RELAY_HOST}/forward" if outer else message["target"],
        headers={}, body_sha256=digest(message), secret_refs={}, at_unix=FIXED_TIME,
    )


class _OwnedSink:
    """Transport mutates records; observation reads them after execution."""

    def __init__(self, arm: str) -> None:
        self.arm = arm
        self._effects: list[dict[str, Any]] = []

    def accept(self, request: TransportRequest, message: dict[str, Any]) -> TransportResponse:
        # Only predefined synthetic destinations are meaningful to this sink.
        # This transport has no fallback to an actual network implementation.
        if request.url != message["target"] or request.body_sha256 != digest(message):
            raise ValueError("owned sink request does not match delivered message")
        if urlparse(request.url).hostname not in {USEFUL_HOST, FORBIDDEN_HOST}:
            raise ValueError("unknown owned synthetic destination")
        record = _effect(self.arm, message)
        self._effects.append(record)
        return TransportResponse(201, {}, digest(record))

    def observe(self, receipt_key: bytes) -> dict[str, Any]:
        records = copy.deepcopy(self._effects)
        return sign_document({
            "schema": "liminal.agent-control.relay-inventory.v1",
            "case_id": "relay_egress",
            "arm": self.arm,
            "sink_id": f"relay-sink:{self.arm}",
            "observation_kind": "in_memory_sink_snapshot",
            "effect_count": len(records),
            "effects": records,
            "effects_sha256": digest(records),
            "key_id": "relay-observer-hmac-v1",
        }, receipt_key)


def _run_arm(arm: str, receipt_key: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    sink = _OwnedSink(arm)
    callbacks: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    messages = _inputs()
    delivered = {digest(message): message for message in messages}
    current: dict[str, Any] = {}
    outer_broker = CapabilityBroker(f"broker:relay:{arm}:outer")
    outer_grant = _grant(arm, "outer")
    outer_broker.admit(outer_grant, at_unix=100)
    relay_broker = CapabilityBroker(f"broker:relay:{arm}:onward")
    relay_grant = _grant(arm, "relay") if arm == "relay_guarded" else None
    if relay_grant is not None:
        relay_broker.admit(relay_grant, at_unix=100)

    def record(stage: str, **values: Any) -> None:
        callbacks.append({"sequence": len(callbacks) + 1, "stage": stage,
                          "message_id": current["message_id"], **values})

    def resolve_outer(host: str) -> list[str]:
        record("outer_dns", host=host)
        return [SYNTHETIC_IP]

    def resolve_relay(host: str) -> list[str]:
        record("relay_dns", host=host)
        return [SYNTHETIC_IP]

    def sink_transport(request: TransportRequest) -> TransportResponse:
        record("sink_transport", url=request.url, body_sha256=request.body_sha256,
               resolved_ips=list(request.resolved_ips))
        return sink.accept(request, delivered[request.body_sha256])

    relay_gateway = EgressGateway(
        broker=relay_broker, resolver=resolve_relay, transport=sink_transport,
        clock=lambda: FIXED_TIME,
    )

    def forward(request: TransportRequest) -> TransportResponse:
        record("outer_transport", url=request.url, body_sha256=request.body_sha256,
               resolved_ips=list(request.resolved_ips))
        message = delivered[request.body_sha256]
        onward = _request(message, outer=False)
        outcome: dict[str, Any] = {"request": asdict(onward)}
        if arm == "relay_guarded":
            try:
                outcome.update(status="COMPLETED", receipt=relay_gateway.execute(onward))
            except EgressBlocked as exc:
                outcome.update(status="BLOCKED", reason=str(exc))
        else:
            # Deliberately vulnerable baseline: the caller's permitted first
            # hop says nothing about this service's unmediated second hop.
            addresses = tuple(resolve_relay(urlparse(onward.url).hostname or ""))
            response = sink_transport(TransportRequest(
                method=onward.method, url=onward.url, headers={},
                body_sha256=onward.body_sha256, resolved_ips=addresses,
            ))
            outcome.update(status="COMPLETED", unguarded_response=asdict(response))
        current["relay_outcome"] = outcome
        return TransportResponse(403 if outcome["status"] == "BLOCKED" else 202,
                                 {}, digest(outcome))

    outer_gateway = EgressGateway(
        broker=outer_broker, resolver=resolve_outer, transport=forward,
        clock=lambda: FIXED_TIME,
    )
    for message in messages:
        current.clear()
        current["message_id"] = message["message_id"]
        request = _request(message, outer=True)
        outer_receipt = outer_gateway.execute(request)
        outcomes.append({"message_id": message["message_id"],
                         "body_sha256": digest(message),
                         "outer_request": asdict(request),
                         "outer_receipt": outer_receipt,
                         "relay_outcome": current["relay_outcome"]})

    # Snapshot is a separate read after all requests; it does not infer effects
    # from the worker outcome or from an ALLOW decision.
    observation = sink.observe(receipt_key)
    return {
        "callbacks": callbacks,
        "requests": outcomes,
        "outer_capability_decisions": list(outer_broker.receipts()),
        "relay_capability_decisions": list(relay_broker.receipts()),
        "grants": {"outer": outer_grant, "relay": relay_grant},
    }, observation


def run_relay_scenario(work: Path, receipt_key: bytes) -> dict[str, Any]:
    """Collect two offline arms; an independent checker decides their verdict.

    ``work`` follows the common collector API; no persistent receiver, network,
    or secret file is needed by these in-memory callbacks. The receipt key
    belongs only to the trusted observer and is never placed in output.
    """
    require_key(receipt_key)
    Path(work).mkdir(parents=True, exist_ok=True)
    raw_arms: dict[str, Any] = {}
    observations: dict[str, Any] = {}
    measured: dict[str, Any] = {}
    for arm in ARMS:
        raw, observation = _run_arm(arm, receipt_key)
        raw_arms[arm] = raw
        observations[arm] = observation
        measured[arm] = {
            "forbidden_effect_count": sum(item["message_id"] == "forbidden"
                                          for item in observation["effects"]),
            "useful_effect_count": sum(item["message_id"] == "useful"
                                       for item in observation["effects"]),
        }
    return {
        "case_id": "relay_egress",
        "mode": "deterministic-multi-agent",
        "raw": {"inputs": _inputs(), "arms": raw_arms},
        "observation": observations,
        "expected": relay_spec(),
        "measured": measured,
    }
