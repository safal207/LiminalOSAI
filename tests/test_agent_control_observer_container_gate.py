"""Collector bindings must hold at actual record and network effect boundaries."""
from __future__ import annotations

from copy import deepcopy
import os
import tempfile
import unittest
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, digest
from sdk.liminal_agent_control.brakes_egress import SessionEgressGateway, network_action
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import ObserverAuthStore, sign_attestation
from sdk.liminal_agent_control.observer_auth_demo import _commit
from sdk.liminal_agent_control.observer_container import evaluate_source_packet
from sdk.liminal_agent_control.observer_container_demo import (
    ROLES, _audit_export, _packet, _prepare, _request, _setup, _unit_support, run_demo,
)
from sdk.liminal_agent_control.observer_sources import ObserverSourceStore, write_source_packet
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract


class ObserverContainerSourceGateTests(unittest.TestCase):
    """Owned fixture keys here test effect gates; they are not Docker evidence."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="liminal-source-gate-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.now = [100.0]
        self.env = _setup(self.work / "session", self.now)
        self.action = _prepare(self.env)

    def request_packet(self, role=ROLES[0]):
        request = _request(self.env, self.action, role)
        return request, _packet(self.env, self.action, role, request)

    def sign(self, request, packet, *, role=ROLES[0], verdict="SUPPORT", evidence_digest=None):
        return sign_attestation(request, private_key=self.env["private_keys"][role], verdict=verdict,
            evidence_digest=evidence_digest or digest(packet), observed_at=self.now[0], valid_until=request["valid_until"])

    def denied(self, reason="OBSERVER_RING_ROLE_REQUIRED"):
        result = _commit(self.env, self.action)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", reason))
        self.assertEqual(self.env["receiver"].records(), [])
        status = self.env["authority"].status("campaign")
        self.assertEqual((status["action_count"], status["stage_count"]), (0, 0))
        self.assertEqual(self.env["graph"].snapshot("campaign")["occurrences"], [])

    def test_three_bound_sources_allow_one_actual_record(self):
        _unit_support(self.env, self.action)
        result = _commit(self.env, self.action)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(len(self.env["receiver"].records()), 1)
        snapshot = self.env["receiver"].snapshot("campaign", "alpha")
        self.assertTrue(self.env["receiver"].verify_receipt(snapshot))
        self.assertEqual(snapshot["cutoff"], 1)

    def test_signed_statement_without_source_binding_is_rejected(self):
        request, packet = self.request_packet()
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_REQUIRED$"):
            self.env["auth"].ingest(self.sign(request, packet))
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_packet_metadata_is_bound_in_addition_to_payload(self):
        request, packet = self.request_packet()
        self.env["source"].bind(request, packet)
        payload_only = self.sign(request, packet, evidence_digest=digest(packet["payload"]))
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_MISMATCH$"):
            self.env["auth"].ingest(payload_only)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_valid_signer_cannot_replace_payload_after_binding(self):
        request, packet = self.request_packet()
        self.env["source"].bind(request, packet)
        changed = deepcopy(packet)
        changed["payload"]["state"]["node_id"] = "forged-position"
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_MISMATCH$"):
            self.env["auth"].ingest(self.sign(request, changed))
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_foreign_source_identity_cannot_be_registered_for_this_observer(self):
        request, packet = self.request_packet()
        packet["source_id"] = "continuity-collector"
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_MISMATCH$"):
            self.env["source"].bind(request, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_cross_role_packet_is_rejected_before_signature_ingestion(self):
        request, packet = self.request_packet()
        packet.update(role="projection", source_id="projection-collector")
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_MISMATCH$"):
            self.env["source"].bind(request, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_packet_bound_to_other_challenge_is_rejected(self):
        request, packet = self.request_packet()
        other = _request(self.env, self.action, ROLES[0])
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_MISMATCH$"):
            self.env["source"].bind(other, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_stale_source_denies_effect_before_signed_support_expires(self):
        _unit_support(self.env, self.action)
        self.now[0] = 106
        self.denied("OBSERVER_SOURCE_STALE")

    def test_source_expiry_boundary_is_closed(self):
        _unit_support(self.env, self.action)
        self.now[0] = 105
        self.denied("OBSERVER_SOURCE_STALE")

    def test_stale_packet_cannot_be_bound_as_fresh_collection(self):
        request, packet = self.request_packet()
        packet["observed_at"] = 94
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_STALE$"):
            self.env["source"].bind(request, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_future_packet_is_rejected_before_effect(self):
        request, packet = self.request_packet()
        packet["observed_at"] = 101
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_STALE$"):
            self.env["source"].bind(request, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_binding_retry_cannot_extend_collection_lifetime(self):
        packets = {}
        _unit_support(self.env, self.action, packets=packets)
        old = self.env["source"].snapshot("campaign")["bindings"][0]
        self.now[0] = 103
        entry = packets[ROLES[0]]
        retried = self.env["source"].bind(entry["request"], entry["packet"])
        self.assertEqual(retried["expires_at"], old["expires_at"])
        self.assertEqual(retried["bound_at"], old["bound_at"])
        self.now[0] = 105
        self.denied("OBSERVER_SOURCE_STALE")

    def test_binding_is_immutable_when_collector_attempts_changed_packet(self):
        request, packet = self.request_packet()
        self.env["source"].bind(request, packet)
        packet["payload"]["replacement"] = True
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_IMMUTABLE$"):
            self.env["source"].bind(request, packet)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_source_requirement_persists_without_adapter_after_restart(self):
        _unit_support(self.env, self.action, roles=ROLES[1:])
        request, packet = self.request_packet()
        restarted = SessionAuthority(self.env["authority"].db_path, clock=lambda: self.now[0])
        auth = ObserverAuthStore(restarted)
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_REQUIRED$"):
            auth.ingest(self.sign(request, packet))
        self.env["authority"] = restarted
        self.env["receiver"] = Receiver(restarted.db_path, self.env["broker_key"], self.env["receipt_key"],
            admission_controller=restarted)
        self.denied()

    def test_source_expiry_is_rechecked_by_reopened_plain_authority(self):
        _unit_support(self.env, self.action)
        self.now[0] = 106
        restarted = SessionAuthority(self.env["authority"].db_path, clock=lambda: self.now[0])
        self.env["authority"] = restarted
        self.env["receiver"] = Receiver(restarted.db_path, self.env["broker_key"], self.env["receipt_key"],
            admission_controller=restarted)
        self.denied("OBSERVER_SOURCE_STALE")

    def test_valid_source_bound_veto_dominates_all_support_and_remains_latched(self):
        _unit_support(self.env, self.action)
        request, packet = self.request_packet()
        packet["payload"]["contradiction"] = "owned fixture"
        self.env["source"].bind(request, packet)
        self.env["auth"].ingest(self.sign(request, packet, verdict="VETO"))
        self.now[0] = 106
        self.denied("OBSERVER_RING_VETO")

    def test_unbound_signed_veto_cannot_create_execution_hold(self):
        _unit_support(self.env, self.action)
        request, packet = self.request_packet()
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_REQUIRED$"):
            self.env["auth"].ingest(self.sign(request, packet, verdict="VETO"))
        self.assertEqual(self.env["ring"].snapshot("campaign")["execution_holds"], [])
        self.assertEqual(_commit(self.env, self.action)["status"], "COMMITTED")
        self.assertEqual(len(self.env["receiver"].records()), 1)

    def test_role_export_uses_actual_receiver_and_verified_signed_snapshot(self):
        request, packet = self.request_packet()
        payload = packet["payload"]
        self.assertEqual(payload["receiver_records"], self.env["receiver"].records())
        self.assertTrue(payload["receiver_snapshot_verified_by_host"])
        self.assertTrue(self.env["receiver"].verify_receipt(payload["receiver_snapshot"]))
        self.assertEqual(payload["receiver_snapshot"]["root_id"], "campaign")
        self.assertEqual(payload["receiver_snapshot"]["execution_id"], "alpha")
        self.assertEqual(payload["receiver_snapshot"]["cutoff"], 0)

    def test_all_collector_payloads_satisfy_the_actual_container_verifier(self):
        for role in ROLES:
            request, packet = self.request_packet(role)
            verdict, evidence_digest, observed_at = evaluate_source_packet(request, packet)
            self.assertEqual((verdict, evidence_digest, observed_at), ("SUPPORT", digest(packet), 100))

    def test_incomplete_receiver_export_is_signed_unknown_and_denies_actual_effect(self):
        request, packet = self.request_packet()
        del packet["payload"]["receiver_snapshot"]
        verdict, evidence_digest, observed_at = evaluate_source_packet(request, packet)
        self.assertEqual(verdict, "UNKNOWN")
        self.env["source"].bind(request, packet)
        envelope = sign_attestation(request, private_key=self.env["private_keys"][ROLES[0]], verdict=verdict,
            evidence_digest=evidence_digest, observed_at=observed_at, valid_until=request["valid_until"])
        self.env["auth"].ingest(envelope)
        _unit_support(self.env, self.action, roles=ROLES[1:])
        self.denied("OBSERVER_RING_UNKNOWN")

    def test_audit_export_refuses_rewriting_previous_event(self):
        request, packet = self.request_packet(ROLES[1])
        events = packet["payload"]["events"]
        self.assertEqual(_audit_export(self.env["audit_path"], events), events)
        changed = deepcopy(events)
        changed[0]["kind"] = "rewritten"
        with self.assertRaisesRegex(ControlError, "^OBSERVER_COLLECTOR_HISTORY_DIVERGED$"):
            _audit_export(self.env["audit_path"], changed)

    def test_safe_packet_writer_refuses_replacement_and_preserves_original(self):
        request, packet = self.request_packet()
        directory = self.work / "source"
        directory.mkdir()
        path = write_source_packet(directory, request, packet)
        original = path.read_bytes()
        changed = deepcopy(packet)
        changed["payload"]["replacement"] = True
        with self.assertRaisesRegex(ControlError, "^OBSERVER_SOURCE_BINDING_IMMUTABLE$"):
            write_source_packet(directory, request, changed)
        self.assertEqual(path.read_bytes(), original)

    def test_source_expiring_during_dns_blocks_transport_at_next_stage(self):
        policy = self.env["policy"]
        broker = CapabilityBroker()
        broker.admit(CapabilityContract.build(
            capability_id="network-cap", capability_type="network.connect_domain", subject_id="alpha",
            issuer_id="operator", scope={"domains": ["owned.invalid"], "protocols": ["https"], "ports": [443]},
            issued_at_unix=90, not_before_unix=90, expires_at_unix=1000, max_uses=10,
            delegable=False, parent_capability_id=None, policy_sha256=policy).as_document(), at_unix=100)
        request = GatewayRequest(call_id="network", subject_id="alpha", policy_sha256=policy,
            method="POST", url="https://owned.invalid/write", headers={}, body_sha256="f" * 64,
            secret_refs={}, at_unix=100)
        action = network_action(root_id="campaign", execution_id="alpha", epoch=1,
            action_id="network", attempt_id="attempt:network", request=request)
        callbacks = []

        def resolver(host):
            callbacks.append("dns")
            self.now[0] = 106
            return ["93.184.216.34"]

        gateway = SessionEgressGateway(authority=self.env["authority"], broker=broker, resolver=resolver,
            transport=lambda request: callbacks.append("transport") or TransportResponse(200, {}, "f" * 64),
            clock=lambda: int(self.now[0]))
        self.assertEqual(gateway.authorize(action, request, capability_id="network-cap")["status"], "AUTHORIZED")
        self.env["graph"].prepare(action, edge_id="networka", expected_revision=0)
        predecessor = self.env["center"].snapshot("campaign")["states"][0]["head_hash"]
        self.env["center"].record_idea("campaign", "alpha", "network-idea", digest("owned source-expiry proposal"),
            expected_head_hash=predecessor)
        self.env["center"].project(action, edge_id="networka", expected_revision=0,
            predecessor_hash=predecessor, idea_id="network-idea", not_before=100, deadline=110)
        _unit_support(self.env, action)
        result = gateway.execute(action, request)
        self.assertEqual((result["status"], result["reason"]), ("BLOCKED", "OBSERVER_SOURCE_STALE"))
        self.assertEqual(callbacks, ["dns"])
        self.assertEqual(self.env["receiver"].records(), [])
        status = self.env["authority"].status("campaign")
        self.assertEqual((status["action_count"], status["stage_count"]), (1, 1))
        state = self.env["center"].snapshot("campaign")["states"][0]
        self.assertEqual((state["node_id"], state["revision"]), ("center-a", 0))


@unittest.skipUnless(os.environ.get("LIMINAL_OBSERVER_DOCKER_IMAGE"),
                     "explicit local observer Docker image is required")
class ObserverContainerDockerGateTests(unittest.TestCase):
    def test_actual_container_services_sources_isolation_and_cleanup(self):
        report = run_demo(os.environ["LIMINAL_OBSERVER_DOCKER_IMAGE"])
        self.assertTrue(report["passed"], report["checks"])
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(report["image_id"], os.environ["LIMINAL_OBSERVER_DOCKER_IMAGE"])
        self.assertEqual(len(report["containers"]), 3)
        self.assertEqual(len({item["container_id"] for item in report["containers"]}), 3)
        self.assertEqual(report["outcomes"]["positive"]["record_count"], 1)
        for name, outcome in report["outcomes"].items():
            if name != "positive":
                self.assertEqual(outcome["record_count"], 0, name)
        self.assertTrue(all(item["removed"] for item in report["cleanup"]))
        self.assertFalse(report["scope"]["external_network"])
        self.assertEqual(report["scope"]["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
