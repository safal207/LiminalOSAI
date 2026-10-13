"""Post-BEGIN dispatch admission for the fixed owned-agent effect route.

The external reservation remains consumed if host readiness disappears before
POST. A local blocked observation never proves zero effects or settles that
reservation. Reconciliation and signed receipt settlement remain usable after
STOP, because they cannot invoke the endpoint's commit operation.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from .authority import ControlError, canonical_bytes, digest, validate_id
from .external_agent_coordinator import validate_run_binding
from .external_agent_launch import ClosedChannelLaunchGate
from .external_authority_service import REQUEST_SCHEMA, verify_authority_response
from .external_network_gateway import MAX_EVIDENCE, NetworkGateway
from .external_network_protocol import validate_network_action, validate_network_authorization

DISPATCH_CONTRACT_SCHEMA = "liminal-agent-effect-dispatch-contract-v1"
DISPATCH_BOUNDARY_SCHEMA = "liminal-agent-effect-dispatch-boundary-v1"
DISPATCH_EVENT_SCHEMA = "liminal-agent-effect-dispatch-observation-v1"
DISPATCH_STAGE = "BEFORE_ENDPOINT_POST"
MAX_DISPATCH_EVENTS = 128


def _copy(value: Any) -> Any:
    return json.loads(canonical_bytes(value))


def _identity(callback: Any) -> tuple:
    if not callable(callback):
        raise ControlError("AGENT_EFFECT_GATE_ROUTE_MISSING")
    return (getattr(callback, "__self__", None), getattr(callback, "__func__", callback))


def _reason(error: BaseException) -> str:
    value = str(error)
    if isinstance(error, ControlError) and re.fullmatch(r"[A-Z0-9_]{1,120}", value):
        return value
    return "AGENT_EFFECT_DISPATCH_CHECK_FAILED"


class ClosedChannelEffectGateway(NetworkGateway):
    def __init__(self, *args, run_binding: Any, **kwargs):
        self.run_binding = validate_run_binding(run_binding)
        self._run_binding_bytes = canonical_bytes(self.run_binding)
        body = {"schema": DISPATCH_CONTRACT_SCHEMA, "stage": DISPATCH_STAGE,
            "run_binding_digest": digest(self.run_binding),
            "effect_action_digests": _copy(self.run_binding["effect_action_digests"]),
            "gate_required": True, "failure_outcome": "UNKNOWN_PENDING", "execution_authorized": False}
        self._dispatch_contract_bytes = canonical_bytes({**body, "contract_digest": digest(body)})
        self.launch_gate: ClosedChannelLaunchGate | None = None
        self._bound_gate: ClosedChannelLaunchGate | None = None
        self._bound_coordinator = None
        self._bound_objects: dict[str, Any] = {}
        self._route_refs: dict[tuple[str, str], tuple] = {}
        self._close_callback: Callable | None = None
        self._fence_callback: Callable | None = None
        self._dispatch_closed = False
        self._known_results: dict[str, dict] = {}
        self.before_dispatch_hook: Callable | None = None
        super().__init__(*args, **kwargs)

    def dispatch_contract(self) -> dict:
        binding = validate_run_binding(self.run_binding)
        if canonical_bytes(binding) != self._run_binding_bytes:
            raise ControlError("AGENT_EFFECT_GATE_CONFIGURATION_IMMUTABLE")
        return json.loads(self._dispatch_contract_bytes)

    def _configuration(self) -> str:
        # Gate health/identity is admission state, not store configuration.
        # Keeping it out of this check preserves UNKNOWN journaling and safe
        # reconciliation after the runtime gate disappears or STOP closes it.
        configuration = json.loads(super()._configuration())
        binding = validate_run_binding(self.run_binding)
        if (configuration["authority_pin"] != binding["effect"]["authority_pin"]
                or configuration["endpoint_pin"] != binding["endpoint_pin"]
                or any(action["arguments"]["url"] != configuration["endpoint_url"] + "/v1/record"
                       for action in binding["effect_actions"])):
            raise ControlError("AGENT_EFFECT_GATE_BINDING_MISMATCH")
        configuration.update(schema="liminal-closed-channel-effect-gateway-store-v1",
                             dispatch_gate=self.dispatch_contract())
        return canonical_bytes(configuration).decode()

    def bind_launch_gate(self, gate: ClosedChannelLaunchGate) -> None:
        if self._bound_gate is not None:
            raise ControlError("AGENT_EFFECT_GATE_ALREADY_BOUND")
        if not isinstance(gate, ClosedChannelLaunchGate) or gate._coordinator is None:
            raise ControlError("AGENT_EFFECT_GATE_UNBOUND")
        coordinator = gate._coordinator
        if (coordinator.effect_gateway is not self
                or canonical_bytes(coordinator.run_binding) != self._run_binding_bytes
                or gate.configuration()["run_binding_digest"] != digest(self.run_binding)):
            raise ControlError("AGENT_EFFECT_GATE_BINDING_MISMATCH")
        objects = {"gateway": self, "gate": gate, "coordinator": coordinator,
            "bridge": coordinator.bridge, "authority": self.external_controller, "endpoint": self.endpoint_client,
            "authority_opener": self.external_controller._opener, "endpoint_opener": self.endpoint_client._opener}
        names = {"gateway": ("execute", "_configuration", "_call", "_before_endpoint_commit", "bind_launch_gate"),
            "gate": ("assert_ready", "configuration"),
            "coordinator": ("close_admission", "fence_state", "watcher_health"), "bridge": ("fence",),
            "authority": ("begin", "query", "finish", "_call"),
            "endpoint": ("commit", "query", "_call"),
            "authority_opener": ("open",), "endpoint_opener": ("open",)}
        routes = {(name, method): _identity(getattr(objects[name], method, None))
            for name, methods in names.items() for method in methods}
        self.launch_gate = self._bound_gate = gate
        self._bound_coordinator, self._bound_objects, self._route_refs = coordinator, objects, routes
        self._close_callback, self._fence_callback = coordinator.close_admission, coordinator.bridge.fence
        with self._connection():
            pass

    def _assert_gate_ready(self) -> None:
        if self._dispatch_closed:
            raise ControlError("AGENT_EFFECT_DISPATCH_CLOSED")
        if self._bound_gate is None or self._bound_coordinator is None:
            raise ControlError("AGENT_EFFECT_GATE_UNBOUND")
        if (self.launch_gate is not self._bound_gate
                or self._bound_gate._coordinator is not self._bound_coordinator
                or self._bound_coordinator.effect_gateway is not self
                or self._bound_coordinator.bridge is not self._bound_objects["bridge"]
                or self.external_controller is not self._bound_objects["authority"]
                or self.endpoint_client is not self._bound_objects["endpoint"]
                or self.external_controller._opener is not self._bound_objects["authority_opener"]
                or self.endpoint_client._opener is not self._bound_objects["endpoint_opener"]):
            raise ControlError("AGENT_EFFECT_GATE_IMMUTABLE")
        if any(_identity(getattr(self._bound_objects[name], method, None)) != expected
               for (name, method), expected in self._route_refs.items()):
            raise ControlError("AGENT_EFFECT_GATE_ROUTE_CHANGED")
        with self._connection():
            pass
        self._bound_gate.assert_ready()

    def _close_admission(self) -> None:
        # A broken store can prevent the coordinator's durable close. Retain
        # an independent sticky local fence before either containment callback
        # so fixing credentials/health never reopens this gateway instance.
        self._dispatch_closed = True
        # Use the captured local-only callback. STOP/remote reconciliation may
        # take locks owned by the active effect callback and cannot run here.
        try:
            if self._close_callback is not None:
                self._close_callback("AGENT_EFFECT_DISPATCH_BLOCKED")
        except BaseException:
            pass
        finally:
            if self._fence_callback is not None:
                try:
                    self._fence_callback("AGENT_EFFECT_DISPATCH_BLOCKED")
                except BaseException:
                    pass  # Dispatch remains blocked even if containment faults.

    def execute(self, proposed: Any) -> dict:
        action = validate_network_action(proposed)
        with self._lock:
            known = None
            readable = False
            action_digest = digest(action)
            try:
                with self._connection() as database:
                    known = database.execute("SELECT action_digest,action_json,status,reservation_id,receipt_json FROM network_gateway_grants WHERE action_id=?",
                        (action["action_id"],)).fetchone()
                readable = True
                if known is not None and (known["action_digest"] != action_digest
                        or canonical_bytes(json.loads(known["action_json"])) != canonical_bytes(action)):
                    known = None
                    raise ControlError("AGENT_EFFECT_ACTION_BINDING_MISMATCH")
                self._assert_gate_ready()
                if canonical_bytes(action) not in {canonical_bytes(item) for item in self.run_binding["effect_actions"]}:
                    raise ControlError("AGENT_EFFECT_ACTION_BINDING_MISMATCH")
            except BaseException as error:
                self._close_admission()
                if known is not None and (known["reservation_id"] is not None
                        or known["status"] in {"PENDING", "UNKNOWN", "COMMITTED_PROOF", "COMMITTED"}):
                    receipt = None if known["receipt_json"] is None else json.loads(known["receipt_json"])
                    return self._result(action["action_id"], "UNKNOWN", _reason(error), known["reservation_id"], receipt,
                        settlement_status="UNKNOWN")
                cached = self._known_results.get(action_digest)
                if not readable and cached is not None:
                    return self._result(action["action_id"], "UNKNOWN", _reason(error), cached["reservation_id"],
                        cached["receipt"], settlement_status="UNKNOWN")
                if not readable:
                    return self._result(action["action_id"], "UNKNOWN", _reason(error), settlement_status="UNKNOWN")
                return self._result(action["action_id"], "DENIED", _reason(error))
            result = super().execute(action)
            # Retain already observed subject-bound truth if a later live
            # configuration fault makes the durable store unreadable. This
            # cache never grants or permits re-dispatch and has at most the
            # fixed run's four approved action digests.
            self._known_results[action_digest] = _copy(result)
            return result

    def _validate_dispatch(self, action: Any, authorization: Any, reservation_id: Any,
                           permit_pair: Any) -> None:
        action = validate_network_action(action)
        authorization = validate_network_authorization(action, authorization, self.endpoint_client.pin()["endpoint_id"])
        validate_id(reservation_id, "reservation_id")
        if (canonical_bytes(action) not in {canonical_bytes(item) for item in self.run_binding["effect_actions"]}
                or type(permit_pair) is not dict or set(permit_pair) != {"request", "response"}):
            raise ControlError("AGENT_EFFECT_DISPATCH_BINDING_MISMATCH")
        request = permit_pair["request"]
        if (type(request) is not dict or set(request) != {"schema", "role", "operation", "nonce", "payload"}
                or request["schema"] != REQUEST_SCHEMA or request["role"] != "receiver" or request["operation"] != "begin"
                or canonical_bytes(request["payload"]) != canonical_bytes({"action": action, "authorization": authorization})):
            raise ControlError("AGENT_EFFECT_DISPATCH_PERMIT_MISMATCH")
        result = verify_authority_response(request, permit_pair["response"], self.external_controller.pin())
        if (result.get("status") != "PERMITTED" or result.get("outcome") is not None
                or self._bind_authority_result(result, action) != reservation_id):
            raise ControlError("AGENT_EFFECT_DISPATCH_PERMIT_MISMATCH")

    def _dispatch_event(self, action: dict, reservation_id: str, pair: dict,
                        result: str, reason: str | None) -> None:
        event = {"schema": DISPATCH_EVENT_SCHEMA, "stage": DISPATCH_STAGE,
            "action_digest": digest(action), "reservation_id": reservation_id,
            "permit_request_digest": digest(pair["request"]), "permit_response_digest": digest(pair["response"]),
            "observed_at": time.time(), "result": result, "reason": reason, "execution_authorized": False}
        if (result not in {"READY", "BLOCKED"} or (result == "READY" and reason is not None)
                or (result == "BLOCKED" and (type(reason) is not str or not re.fullmatch(r"[A-Z0-9_]{1,120}", reason)))):
            raise ControlError("AGENT_EFFECT_DISPATCH_EVIDENCE_INVALID")
        validate_id(reservation_id, "reservation_id")
        encoded = canonical_bytes(event)
        if len(encoded) > 4096:
            raise ControlError("AGENT_EFFECT_DISPATCH_EVIDENCE_CAPACITY")
        # Host observations have their own exact schema and only public
        # digests; keep the base request/response credential filter intact.
        with self._connection() as database:
            database.execute("BEGIN IMMEDIATE")
            if (database.execute("SELECT COUNT(*) FROM network_gateway_evidence WHERE source='dispatch_gate'").fetchone()[0] >= MAX_DISPATCH_EVENTS
                    or database.execute("SELECT COUNT(*) FROM network_gateway_evidence").fetchone()[0] >= MAX_EVIDENCE):
                raise ControlError("AGENT_EFFECT_DISPATCH_EVIDENCE_CAPACITY")
            database.execute("INSERT INTO network_gateway_evidence(source,packet_json) VALUES ('dispatch_gate',?)", (encoded.decode(),))

    def _before_endpoint_commit(self, action: dict, authorization: dict, reservation_id: str, permit_pair: dict) -> None:
        frozen = None
        try:
            frozen = _copy({"action": action, "authorization": authorization,
                            "reservation_id": reservation_id, "permit_pair": permit_pair})
            self._validate_dispatch(action, authorization, reservation_id, permit_pair)
            self._assert_gate_ready()
            if self.before_dispatch_hook is not None:
                if not callable(self.before_dispatch_hook):
                    raise ControlError("AGENT_EFFECT_DISPATCH_HOOK_INVALID")
                fault_inputs = _copy(frozen)
                self.before_dispatch_hook(fault_inputs["action"], fault_inputs["authorization"],
                    fault_inputs["reservation_id"], fault_inputs["permit_pair"])
                if canonical_bytes(fault_inputs) != canonical_bytes(frozen):
                    raise ControlError("AGENT_EFFECT_DISPATCH_INPUT_IMMUTABLE")
            self._assert_gate_ready()
            self._dispatch_event(action, reservation_id, permit_pair, "READY", None)
            # Persisting evidence can block on storage. Recheck after that
            # boundary before returning directly to the endpoint dispatch.
            self._assert_gate_ready()
        except BaseException as error:
            reason = _reason(error)
            self._close_admission()
            try:
                if frozen is not None:
                    self._dispatch_event(frozen["action"], frozen["reservation_id"], frozen["permit_pair"], "BLOCKED", reason)
            except BaseException:
                pass  # Missing diagnostics cannot reopen or dispatch a permit.
            raise ControlError(reason) from error

    def inventory(self) -> dict:
        with self._lock:
            result = super().inventory()
            with self._connection() as database:
                events = [json.loads(row[0]) for row in database.execute(
                    "SELECT packet_json FROM network_gateway_evidence WHERE source='dispatch_gate' ORDER BY sequence")]
            result["dispatch_boundary"] = {"schema": DISPATCH_BOUNDARY_SCHEMA,
                "contract_digest": self.dispatch_contract()["contract_digest"],
                "events": events, "execution_authorized": False}
            return result
