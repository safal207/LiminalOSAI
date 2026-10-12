"""Signed role evidence must survive verification at the real effect boundary."""
from __future__ import annotations

from copy import deepcopy
import secrets
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.brakes_egress import SessionEgressGateway, network_action
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import ATTESTATION_DOMAIN
from sdk.liminal_agent_control.observer_auth_demo import (
    ROLES, _commit, _evidence, _prepare, _request, _setup, _signed, _support, run_demo,
)
from sdk.liminal_agent_control.observer_process import run_observer
from sdk.liminal_agent_control.observer_ring import ObserverRingStore
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract


class ObserverAuthGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="liminal-auth-gate-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.now = [100.0]
        self.env = _setup(self.work, self.now)
        self.action = _prepare(self.env)

    def no_effects(self):
        self.assertEqual(self.env["receiver"].records(), [])
        status = self.env["authority"].status("campaign")
        self.assertEqual((status["action_count"], status["stage_count"]), (0, 0))
        self.assertEqual(self.env["graph"].snapshot("campaign")["occurrences"], [])

    def denied(self, reason="OBSERVER_RING_ROLE_REQUIRED"):
        result = _commit(self.env, self.action)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", reason))
        self.no_effects()

    def request(self, role=ROLES[0], valid_until=110):
        return _request(self.env, self.action, role, valid_until=valid_until)

    def test_three_signed_roles_allow_one_receiver_effect_and_exact_finalize(self):
        _support(self.env, self.action)
        result = _commit(self.env, self.action)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(len(self.env["receiver"].records()), 1)
        snapshot = self.env["center"].snapshot("campaign")
        self.assertEqual(snapshot["states"][0]["revision"], 1)
        self.assertEqual(self.env["receiver"].finalize(self.action["action_id"]), result)
        self.assertEqual(self.env["center"].snapshot("campaign"), snapshot)
        self.assertEqual(len(self.env["receiver"].records()), 1)

    def test_wrong_private_key_cannot_supply_missing_role(self):
        request = self.request()
        forged = _signed(self.env, request, role=ROLES[0], private_key=secrets.token_bytes(32))
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_SIGNATURE_INVALID$"):
            self.env["auth"].ingest(forged)
        _support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_signature_bit_flip_is_rejected_before_effect(self):
        envelope = _signed(self.env, self.request(), role=ROLES[0])
        signature = envelope["signature"]
        envelope["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_SIGNATURE_INVALID$"):
            self.env["auth"].ingest(envelope)
        _support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_valid_signer_cannot_claim_another_enrolled_identity(self):
        request = self.request()
        request.update(observer_id="continuity-observer", key_id="continuity-key", role="continuity")
        forged = _signed(self.env, request, role=ROLES[0])
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_BINDING_MISMATCH$"):
            self.env["auth"].ingest(forged)
        _support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_one_compromised_signer_cannot_replace_other_required_roles(self):
        _support(self.env, self.action, roles=ROLES[:1])
        self.denied()

    def test_raw_attest_cannot_bypass_installed_authentication(self):
        _support(self.env, self.action, roles=ROLES[:2])
        with self.assertRaisesRegex(ControlError, "^OBSERVER_RING_AUTH_REQUIRED$"):
            self.env["ring"].attest(self.action["action_id"], observer_id="projection-observer",
                verdict="SUPPORT", evidence_digest=digest("forged label"), observed_at=100, valid_until=110)
        self.denied()

    def test_signed_unknown_does_not_count_as_required_support(self):
        _support(self.env, self.action, roles=ROLES[:2])
        self.env["auth"].ingest(_signed(self.env, self.request(ROLES[2]), role=ROLES[2], verdict="UNKNOWN"))
        self.denied("OBSERVER_RING_UNKNOWN")

    def test_expired_signed_support_is_checked_again_at_effect_boundary(self):
        _support(self.env, self.action, valid_until=104)
        self.now[0] = 105
        self.denied("OBSERVER_RING_ATTESTATION_STALE")

    def test_expired_challenge_cannot_be_ingested_later(self):
        envelope = _signed(self.env, self.request(valid_until=104), role=ROLES[0])
        self.now[0] = 105
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_CHALLENGE_STALE$"):
            self.env["auth"].ingest(envelope)
        _support(self.env, self.action, roles=ROLES[1:])
        self.denied()

    def test_exact_retry_preserves_evidence_age_and_cannot_refresh_support(self):
        request = self.request(valid_until=104)
        envelope = _signed(self.env, request, role=ROLES[0])
        old = self.env["auth"].ingest(envelope)
        _support(self.env, self.action, roles=ROLES[1:])
        self.now[0] = 105
        self.assertEqual(self.env["auth"].ingest(envelope), old)
        self.denied("OBSERVER_RING_ATTESTATION_STALE")

    def test_consumed_nonce_cannot_be_reused_for_different_statement(self):
        request = self.request()
        self.env["auth"].ingest(_signed(self.env, request, role=ROLES[0]))
        changed = _signed(self.env, request, role=ROLES[0], verdict="UNKNOWN")
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_CHALLENGE_REPLAY$"):
            self.env["auth"].ingest(changed)
        self.denied()

    def test_signed_request_cannot_be_retargeted_to_another_action(self):
        other = _prepare(self.env, "retarget")
        request = deepcopy(self.request())
        request["action_id"] = other["action_id"]
        with self.assertRaisesRegex(ControlError, "^OBSERVER_AUTH_BINDING_MISMATCH$"):
            self.env["auth"].ingest(_signed(self.env, request, role=ROLES[0]))
        _support(self.env, other, roles=ROLES[1:])
        self.action = other
        self.denied()

    def test_valid_veto_dominates_three_valid_supporting_roles(self):
        _support(self.env, self.action)
        self.env["auth"].ingest(_signed(self.env, self.request(), role=ROLES[0], verdict="VETO"))
        self.denied("OBSERVER_RING_VETO")

    def test_revocation_blocks_existing_signed_support_before_effect(self):
        _support(self.env, self.action)
        self.env["auth"].revoke("campaign", "reality-key", "owned key compromise")
        self.denied("OBSERVER_AUTH_KEY_REVOKED")

    def test_persisted_authentication_survives_plain_authority_restart(self):
        _support(self.env, self.action, roles=ROLES[:2])
        restarted = SessionAuthority(self.env["authority"].db_path, clock=lambda: self.now[0])
        self.env["authority"] = restarted
        self.env["receiver"] = Receiver(restarted.db_path, self.env["broker_key"], self.env["receipt_key"],
            admission_controller=restarted)
        ring = ObserverRingStore(restarted)
        with self.assertRaisesRegex(ControlError, "^OBSERVER_RING_AUTH_REQUIRED$"):
            ring.attest(self.action["action_id"], observer_id="projection-observer", verdict="SUPPORT",
                evidence_digest=digest("fresh runtime bypass"), observed_at=100, valid_until=110)
        self.denied()

    def test_observer_support_does_not_replace_exact_broker_grant(self):
        _support(self.env, self.action)
        result = self.env["receiver"].commit(self.action)
        self.assertEqual((result["status"], result["reason"]), ("DENIED", "GRANT_REQUIRED"))
        self.no_effects()

    def test_signed_support_cannot_restore_stopped_authority(self):
        _support(self.env, self.action)
        self.env["authority"].stop("campaign")
        result = _commit(self.env, self.action)
        self.assertEqual(result["status"], "DENIED")
        self.no_effects()

    def test_actual_observer_timeout_leaves_role_missing_and_effect_count_zero(self):
        _support(self.env, self.action, roles=ROLES[:2])
        role = ROLES[2]
        executed = run_observer(self.request(role), private_key=self.env["private_keys"][role],
            evidence=_evidence(self.env, self.action, role), timeout_seconds=0.000001)
        self.assertIsNone(executed["envelope"])
        self.assertEqual(executed["process"]["status"], "HOLD")
        self.assertEqual(executed["process"]["reason"], "OBSERVER_PROCESS_TIMEOUT")
        self.assertIsInstance(executed["process"]["pid"], int)
        self.denied()

    def test_late_signed_veto_holds_fresh_action_in_same_execution(self):
        _support(self.env, self.action)
        self.now[0] = 111
        fresh = _prepare(self.env, "fresh-after-deadline", deadline=119)
        _support(self.env, fresh, valid_until=119)
        late = self.env["auth"].challenge(self.action["action_id"], "reality-observer", 115)
        self.env["auth"].ingest(_signed(self.env, late, role=ROLES[0], verdict="VETO"))
        self.action = fresh
        self.denied("OBSERVER_RING_VETO")

    def test_key_revoked_after_dns_blocks_transport_at_next_stage(self):
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
            self.env["auth"].revoke("campaign", "reality-key", "revoked during owned DNS callback")
            return ["93.184.216.34"]

        gateway = SessionEgressGateway(authority=self.env["authority"], broker=broker,
            resolver=resolver,
            transport=lambda request: callbacks.append("transport") or TransportResponse(200, {}, "f" * 64),
            clock=lambda: int(self.now[0]))
        self.assertEqual(gateway.authorize(action, request, capability_id="network-cap")["status"], "AUTHORIZED")
        self.env["graph"].prepare(action, edge_id="networka", expected_revision=0)
        predecessor = self.env["center"].snapshot("campaign")["states"][0]["head_hash"]
        self.env["center"].record_idea("campaign", "alpha", "network-idea", digest("owned network proposal"),
            expected_head_hash=predecessor)
        self.env["center"].project(action, edge_id="networka", expected_revision=0,
            predecessor_hash=predecessor, idea_id="network-idea", not_before=100, deadline=110)
        _support(self.env, action)
        before = self.env["center"].snapshot("campaign")["states"][0]
        result = gateway.execute(action, request)
        self.assertEqual((result["status"], result["reason"]), ("BLOCKED", "OBSERVER_AUTH_KEY_REVOKED"))
        self.assertEqual(callbacks, ["dns"])
        self.assertEqual(self.env["receiver"].records(), [])
        status = self.env["authority"].status("campaign")
        self.assertEqual((status["action_count"], status["stage_count"]), (1, 1))
        after = self.env["center"].snapshot("campaign")["states"][0]
        self.assertEqual((after["node_id"], after["revision"]), (before["node_id"], before["revision"]))

    def test_executed_demo_reports_distinct_processes_and_all_exact_denials(self):
        report = run_demo()
        self.assertTrue(report["passed"], report["checks"])
        self.assertTrue(all(report["checks"].values()))
        self.assertEqual(len(report["processes"]), 3)
        self.assertEqual(len({item["pid"] for item in report["processes"]}), 3)
        self.assertEqual(report["outcomes"]["three_processes"]["record_count"], 1)
        success = report["outcomes"]["three_processes"]
        public_keys = {item["key_id"]: item["public_key"]
                       for item in success["authentication"]["profile"]["keys"]}
        self.assertEqual(len(success["envelopes"]), 3)
        for envelope in success["envelopes"]:
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_keys[envelope["request"]["key_id"]]))
            body = {key: value for key, value in envelope.items() if key != "signature"}
            public.verify(bytes.fromhex(envelope["signature"]), ATTESTATION_DOMAIN + canonical_bytes(body))
        for name, outcome in report["outcomes"].items():
            if name != "three_processes":
                self.assertEqual(outcome["record_count"], 0, name)
        self.assertFalse(report["scope"]["external_network"])
        self.assertEqual(report["scope"]["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
