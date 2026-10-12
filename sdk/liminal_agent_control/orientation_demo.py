"""Owned records/network trajectory example; no model or external network."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import tempfile
import time

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract

from .authority import digest
from .brakes_egress import SessionEgressGateway, network_action
from .brakes_store import SessionAuthority
from .broker import Broker
from .multi_agent import _source, _source_digests
from .orientation import OrientationStore
from .orientation_guidance import guidance
from .receiver import Receiver


def run_demo() -> dict:
    frames, outcomes, claims = [], {}, []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="liminal-orientation-") as temporary:
        work = Path(temporary)
        authority = SessionAuthority(work / "authority.sqlite")
        policy = digest("owned orientation demonstration")
        authority.create_session("campaign", controller_id="operator", policy_digest=policy,
            objective_digest=digest("bounded owned work with verified checkpoints"),
            max_actions=10, max_executions=2, max_depth=1, max_stages=8,
            lifetime_seconds=120, lease_seconds=60)
        for execution in ("alpha", "beta"):
            authority.bind_execution("campaign", execution)
        receiver = Receiver(authority.db_path, secrets.token_bytes(32), secrets.token_bytes(32),
                            admission_controller=authority)
        broker = Broker(work / "broker.sqlite", receiver)
        graph = OrientationStore(authority)
        profile = {
            "nodes": [
                {"node_id": "center", "space_id": "control", "phase": "verified_checkpoint"},
                {"node_id": "record", "space_id": "owned_records", "phase": "record_observed"},
                {"node_id": "network", "space_id": "owned_sink", "phase": "sink_observed"}],
            "edges": [
                {"edge_id": "write", "source": "center", "destination": "record", "channel": "records"},
                {"edge_id": "review_record", "source": "record", "destination": "center", "channel": "records"},
                {"edge_id": "send", "source": "center", "destination": "network", "channel": "egress"},
                {"edge_id": "drift", "source": "record", "destination": "network", "channel": "egress"},
                {"edge_id": "review_sink", "source": "network", "destination": "center", "channel": "records"}],
            "center_nodes": ["center"], "max_steps": 8, "max_visits": 3,
            "max_away_steps": 1, "max_observation_age_seconds": 30,
            "observers": {"records": receiver.receiver_id, "egress": "owned-sink-observer"},
        }
        installed = graph.install("campaign", profile)
        for execution in ("alpha", "beta"):
            graph.seed("campaign", execution, "center", evidence_digest=digest({"launch": execution}),
                       observed_at=time.time())

        def capture(label):
            snapshot = graph.snapshot("campaign")
            current_authority = authority.status("campaign")
            frames.append({"label": label, "elapsed_seconds": time.monotonic() - started,
                           "graph": snapshot, "authority": current_authority,
                           "guidance": {e: guidance(snapshot, current_authority, e) for e in ("alpha", "beta")}})
            return snapshot

        def record(execution, name, edge, revision):
            action = {"root_id": "campaign", "execution_id": execution, "epoch": 1,
                      "action_id": name, "attempt_id": "attempt:" + name,
                      "target": "records", "arguments": {"owned_marker": name}}
            graph.prepare(action, edge_id=edge, expected_revision=revision)
            broker.authorize(action, policy_version=policy)
            result = broker.dispatch(action)
            outcomes[name] = result
            return result

        capabilities = CapabilityBroker("orientation-egress")
        now = int(time.time())
        for execution in ("alpha", "beta"):
            contract = CapabilityContract.build(capability_id="cap:" + execution,
                capability_type="network.connect_domain", subject_id=execution, issuer_id="operator",
                scope={"domains": ["sink.owned.invalid"], "protocols": ["https"], "ports": [443]},
                issued_at_unix=now, not_before_unix=now, expires_at_unix=now + 120,
                max_uses=4, delegable=False, parent_capability_id=None, policy_sha256=policy)
            capabilities.admit(contract.as_document(), at_unix=now)
        callbacks, sink = [], []

        def transport(request):
            callbacks.append("transport")
            sink.append({"body_sha256": request.body_sha256, "url": request.url, "observed_at": time.time()})
            return TransportResponse(201, {}, digest(sink[-1]))

        gateway = SessionEgressGateway(authority=authority, broker=capabilities,
            resolver=lambda _: callbacks.append("dns") or ["93.184.216.34"], transport=transport)

        def network(execution, name, edge, revision):
            request = GatewayRequest(call_id=name, subject_id=execution, policy_sha256=policy,
                method="POST", url="https://sink.owned.invalid/record", headers={},
                body_sha256=digest(name), secret_refs={}, at_unix=now)
            action = network_action(root_id="campaign", execution_id=execution, epoch=1,
                action_id=name, attempt_id="attempt:" + name, request=request)
            prepared = graph.prepare(action, edge_id=edge, expected_revision=revision)
            gateway.authorize(action, request, capability_id="cap:" + execution)
            result = gateway.execute(action, request)
            outcomes[name] = {"preparation": prepared, **result}
            return action, result

        capture("Оператор подтвердил отдельное начальное состояние каждого агента")
        record("alpha", "alpha:write", "write", 0)
        after_write = capture("Alpha: запись подтверждена. Позиция Beta не изменилась")
        _, drift = network("alpha", "alpha:drift", "drift", 1)
        capture("Alpha: второй шаг без возвращения к центру заблокирован")
        beta_action, returned = network("beta", "beta:send", "send", 0)
        pending = capture("Beta: транспорт ответил, но переход ещё не подтверждён")
        claims.append({"execution_id": "beta", "claim": "I reached the center and finished",
                       "evidence_role": "untrusted_worker_claim", "changes_authority": False})
        after_claim = capture("Заявление агента не меняет наблюдаемую траекторию")
        record("alpha", "alpha:review", "review_record", 1)
        capture("Alpha: возвращение к центру подтверждено. Бюджет не восстановлен")
        # This observer reads the owned sink. In production it must authenticate
        # its own receiver evidence; a model may not invoke this host API.
        observation = {"action_id": beta_action["action_id"], "action_digest": digest(beta_action),
            "root_id": "campaign", "execution_id": "beta", "epoch": 1,
            "profile_digest": installed["profile_digest"], "observed_at": sink[0]["observed_at"],
            "evidence_digest": digest(sink[0]), "observer_id": "owned-sink-observer", "outcome": "CONFIRMED"}
        graph.observe(beta_action["action_id"], observation=observation)
        capture("Beta: наблюдение получателя подтвердило переход")
        record("beta", "beta:review", "review_sink", 1)
        final = capture("Оба агента в центре. Их истории и полномочия остаются отдельными")
        authority.stop("campaign")
        capture("STOP остаётся окончательным, даже если агент находится в центре")
        checks = {
            "useful_records_committed": all(outcomes[k]["status"] == "COMMITTED"
                for k in ("alpha:write", "alpha:review", "beta:review")),
            "drift_blocked": drift["status"] == "BLOCKED",
            "transport_returned_without_remote_claim": returned["status"] == "RETURNED"
                and returned["external_effect"] == "UNKNOWN",
            "claim_cannot_move_state": pending == after_claim,
            "agent_positions_do_not_merge": {s["execution_id"]: s["node_id"] for s in after_write["executions"]}
                == {"alpha": "record", "beta": "center"},
            "pending_does_not_move_observed_position": next(s for s in pending["executions"]
                if s["execution_id"] == "beta")["node_id"] == "center",
            "verified_center_return_keeps_separate_histories": all(s["node_id"] == "center"
                and s["revision"] == 2 and s["steps"] == 2 for s in final["executions"]),
            "owned_effect_inventory": len(receiver.records()) == 3 and len(sink) == 1
                and callbacks == ["dns", "transport"],
            "shared_budget_not_refunded": authority.status("campaign")["action_count"] == 4,
            "stop_terminal": authority.status("campaign")["status"] == "STOPPED",
            "guidance_prefers_reorientation": frames[1]["guidance"]["alpha"]["disposition"] == "RETURN_CANDIDATE",
            "guidance_never_authorizes": all(not g["execution_authorized"] for f in frames for g in f["guidance"].values()),
            "guidance_holds_pending_and_stopped": frames[3]["guidance"]["beta"]["disposition"] == "HOLD"
                and all(g["disposition"] == "HOLD" for g in frames[-1]["guidance"].values()),
        }
        return {"schema": "liminal-agent-orientation-demo-v1", "source": _source(),
            "source_digests": _source_digests(), "profile": profile,
            "profile_digest": installed["profile_digest"], "frames": frames,
            "outcomes": outcomes, "worker_claims": claims, "checks": checks,
            "passed": all(checks.values()), "scope": {
                "mode": "scripted owned records and callback sink",
                "model_calls": 0, "external_network": False, "physical_coordinates": False,
                "production_observer_authentication": "host integration responsibility",
                "orientation_authorizes_actions": False}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--html", type=Path)
    args = parser.parse_args()
    report = run_demo()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    if args.html:
        from .orientation_view import render
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(render(report))
    print(json.dumps({"passed": report["passed"], "checks": report["checks"], "source": report["source"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
