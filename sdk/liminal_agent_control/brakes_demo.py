"""Executable integration example: shared records/egress authority, owned effects.

No model, network socket, secret or container is used here. The CI artifact and
source digests identify this run; this JSON is not an independent attestation.
"""
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
from .receiver import Receiver


def run_demo() -> dict:
    cases = []
    with tempfile.TemporaryDirectory(prefix="liminal-brakes-demo-") as temporary:
        work = Path(temporary)
        for case_id in ("shared_budget", "shared_stop"):
            db = work / (case_id + ".sqlite")
            authority = SessionAuthority(db)
            policy = digest({"case": case_id, "allowed_host": "sink.owned.invalid"})
            authority.create_session(case_id, controller_id="operator", policy_digest=policy,
                objective_digest=digest("Write one owned record and one owned sink entry"),
                max_actions=2 if case_id == "shared_budget" else 4, max_executions=2,
                max_depth=1, max_stages=8, lifetime_seconds=60, lease_seconds=30)
            authority.bind_execution(case_id, "record-worker")
            authority.bind_execution(case_id, "network-worker", "record-worker")
            receiver = Receiver(db, secrets.token_bytes(32), secrets.token_bytes(32),
                                admission_controller=authority)
            broker = Broker(work / (case_id + "-broker.sqlite"), receiver)
            capabilities = CapabilityBroker("owned-egress")
            now = int(time.time())
            contract = CapabilityContract.build(capability_id="cap:owned", subject_id="network-worker",
                capability_type="network.connect_domain", issuer_id="operator",
                scope={"domains": ["sink.owned.invalid"], "protocols": ["https"], "ports": [443]},
                issued_at_unix=now, not_before_unix=now, expires_at_unix=now + 60,
                max_uses=4, delegable=False, parent_capability_id=None, policy_sha256=policy)
            capabilities.admit(contract.as_document(), at_unix=now)
            callbacks, sink = [], []

            def resolve(host):
                callbacks.append({"stage": "dns", "host": host})
                return ["93.184.216.34"]  # synthetic, no actual resolver/socket

            def transport(request):
                callbacks.append({"stage": "transport", "url": request.url})
                sink.append({"url": request.url, "body_sha256": request.body_sha256})
                return TransportResponse(201, {}, digest(sink[-1]))

            gateway = SessionEgressGateway(authority=authority, broker=capabilities,
                                           resolver=resolve, transport=transport)

            def record(name):
                return {"root_id": case_id, "execution_id": "record-worker", "epoch": 1,
                        "action_id": name, "attempt_id": "attempt:" + name,
                        "target": "records", "arguments": {"owned_marker": name}}

            def network(name):
                request = GatewayRequest(call_id=name, subject_id="network-worker", policy_sha256=policy,
                    method="POST", url="https://sink.owned.invalid/record", headers={},
                    body_sha256=digest(name), secret_refs={}, at_unix=now)
                action = network_action(root_id=case_id, execution_id="network-worker", epoch=1,
                    action_id=name, attempt_id="attempt:" + name, request=request)
                gateway.authorize(action, request, capability_id="cap:owned")
                return action, request

            first_record, late_record = record("record:first"), record("record:late")
            broker.authorize(first_record, policy_version=policy)
            broker.authorize(late_record, policy_version=policy)
            first_network, late_network = network("network:first"), network("network:late")
            useful_record = broker.dispatch(first_record)
            useful_network = gateway.execute(*first_network)
            before = {"records": len(receiver.records()), "sink": len(sink), "callbacks": len(callbacks)}
            stopped = authority.stop(case_id) if case_id == "shared_stop" else None
            blocked_record, blocked_network = broker.dispatch(late_record), gateway.execute(*late_network)
            after = {"records": len(receiver.records()), "sink": len(sink), "callbacks": len(callbacks)}
            restarted = SessionAuthority(db)
            restart_status = restarted.status(case_id)
            replay = gateway.execute(*first_network)
            state = authority.status(case_id)
            snapshot = receiver.snapshot(case_id)
            checks = {
                "useful_record_committed": useful_record["status"] == "COMMITTED",
                "useful_transport_returned": useful_network["status"] == "RETURNED",
                "receiver_inventory_authenticated": receiver.verify_receipt(snapshot),
                "owned_effects_observed": before == {"records": 1, "sink": 1, "callbacks": 2},
                "both_late_actions_blocked": blocked_record["status"] == blocked_network["status"] == "BLOCKED",
                "no_late_effect_or_callback": before == after,
                "one_shared_action_counter": state["action_count"] == 2,
                "no_egress_replay": replay["status"] == "BLOCKED" and len(sink) == 1,
                "restart_keeps_state_and_budget": restart_status["status"] == state["status"]
                    and restart_status["action_count"] == 2,
                "expected_terminal_or_exhausted": state["status"] == "STOPPED" if stopped else state["remaining_actions"] == 0,
            }
            cases.append({"case_id": case_id, "checks": checks,
                "status": "PASS" if all(checks.values()) else "FAIL",
                "observations": {"before": before, "after": after, "callbacks": callbacks,
                    "record_late_reason": blocked_record["reason"], "network_late_reason": blocked_network["reason"],
                    "session": state, "receiver_snapshot": snapshot,
                    "network_effect_evidence": "owned in-memory sink only; remote commit UNKNOWN"}})
    return {"schema": "liminal-agent-brakes-demo-v1", "source": _source(),
            "source_digests": _source_digests(), "cases": cases,
            "passed": all(case["status"] == "PASS" for case in cases),
            "scope": {"real_sqlite_admission": True, "scripted_owned_callbacks": True,
                      "model_calls": 0, "network_sockets": 0, "docker": "NOT_RUN",
                      "independent_attestation": False,
                      "process_crash_and_docker_checks": "separate unittest / CI job"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_demo()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"passed": report["passed"], "source": report["source"],
                      "report": str(args.output.resolve())}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
