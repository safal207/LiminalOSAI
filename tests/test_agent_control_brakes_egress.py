"""Observe owned callback effects, replay, shared budgets and hung I/O braking."""
from __future__ import annotations

import copy
import multiprocessing
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, connect
from sdk.liminal_agent_control.brakes_egress import SessionEgressGateway, network_action
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract


POLICY = "a" * 64
BODY = "b" * 64


def capability(capability_id="cap:child", *, parent=None, subject="worker", delegable=False, max_uses=20):
    return CapabilityContract.build(
        capability_id=capability_id, capability_type="network.connect_domain", subject_id=subject,
        issuer_id="host", scope={"domains": ["owned.invalid", "redirect.invalid"],
                                 "protocols": ["https"], "ports": [443]},
        issued_at_unix=100, not_before_unix=100, expires_at_unix=200,
        max_uses=max_uses, delegable=delegable, parent_capability_id=parent, policy_sha256=POLICY,
    ).as_document()


def request(number=1, **kwargs):
    return GatewayRequest(call_id=f"net:{number}", subject_id="worker", policy_sha256=POLICY,
                          method="POST", url="https://owned.invalid/write", headers={},
                          body_sha256=BODY, secret_refs={}, at_unix=110, **kwargs)


def action(req):
    return network_action(root_id="root", execution_id=req.subject_id, epoch=1,
                          action_id=req.call_id, attempt_id=f"attempt:{req.call_id}", request=req)


def lost_response_child(db_path, effect_path):
    """A real process commits an owned effect then dies before returning it."""
    authority = SessionAuthority(db_path, clock=lambda: 110)
    broker = CapabilityBroker()
    broker.admit(capability(), at_unix=100)

    def transport(_):
        with sqlite3.connect(effect_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS effects (id INTEGER)")
            db.execute("INSERT INTO effects VALUES (1)")
        os._exit(17)

    gateway = SessionEgressGateway(authority=authority, broker=broker,
                                   resolver=lambda _: ["93.184.216.34"], transport=transport, clock=lambda: 110)
    gateway.authorize(action(request()), request(), capability_id="cap:child")
    gateway.execute(action(request()), request())


class SessionEgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.db"
        self.now = 110
        self.authority = SessionAuthority(self.path, clock=lambda: self.now)
        self.authority.create_session("root", controller_id="host", policy_digest=POLICY,
                                      objective_digest="c" * 64, max_actions=10, max_executions=4,
                                      max_depth=2, max_stages=30, lifetime_seconds=100, lease_seconds=50)
        self.authority.bind_execution("root", "worker")
        self.broker = CapabilityBroker()
        self.broker.admit(capability(), at_unix=100)
        self.calls = []
        self.gateway = self.make_gateway()

    def make_gateway(self, **kwargs):
        options = dict(authority=self.authority, broker=self.broker,
                       resolver=lambda host: self.calls.append(("dns", host)) or ["93.184.216.34"],
                       transport=lambda req: self.calls.append(("transport", req.url)) or TransportResponse(200, {}, BODY),
                       secret_resolver=lambda ref: self.calls.append(("secret", ref)) or "owned-test-value",
                       clock=lambda: self.now)
        options.update(kwargs)
        return SessionEgressGateway(**options)

    def grant(self, req=None, gateway=None):
        req = req or request()
        result = (gateway or self.gateway).authorize(action(req), req, capability_id="cap:child")
        self.assertEqual(result["status"], "AUTHORIZED", result)
        return req

    def limits(self, **changes):
        # Trusted fixture setup only; production session policy is immutable.
        with connect(self.path) as db:
            for field, value in changes.items():
                self.assertIn(field, {"max_actions", "max_stages"})
                db.execute(f"UPDATE brakes_sessions SET {field}=? WHERE root_id='root'", (value,))

    def test_exact_grant_has_real_callbacks_and_never_asserts_external_commit(self):
        req = self.grant()
        result = self.gateway.execute(action(req), req)
        self.assertEqual(result["status"], "RETURNED")
        self.assertEqual(result["external_effect"], "UNKNOWN")
        self.assertEqual([entry[0] for entry in self.calls], ["dns", "transport"])
        status = self.authority.status("root")
        self.assertEqual((status["action_count"], status["stage_count"]), (1, 2))
        replay = self.gateway.execute(action(req), req)
        self.assertEqual(replay["reason"], "ACTION_ALREADY_RESERVED")
        self.assertEqual(len(self.calls), 2)

    def test_unauthorized_proposal_does_not_enter_dns_or_charge_budget(self):
        result = self.gateway.execute(action(request()), request())
        self.assertEqual(result["reason"], "NO_EXACT_NETWORK_GRANT")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.authority.status("root")["action_count"], 0)

    def test_header_value_url_body_secret_and_subject_swaps_cannot_reuse_grant(self):
        req = self.grant()
        alternatives = [replace(req, headers={"X-Route": "other"}), replace(req, body_sha256="d" * 64),
                        replace(req, url="https://redirect.invalid/write"),
                        replace(req, secret_refs={"Authorization": "different-reference"}),
                        replace(req, subject_id="other-worker")]
        for changed in alternatives:
            with self.subTest(changed=changed):
                result = self.gateway.execute(action(changed), changed)
                self.assertEqual(result["reason"], "EXACT_NETWORK_GRANT_MISMATCH")
        self.assertEqual(self.calls, [])
        malformed = copy.deepcopy(action(req))
        malformed["arguments"] = {"unrelated": True}
        with self.assertRaisesRegex(ControlError, "BINDING_MISMATCH"):
            self.gateway.execute(malformed, req)

    def test_grant_is_immutable_and_capability_cannot_be_swapped(self):
        req = self.grant()
        self.broker.admit(capability("cap:other"), at_unix=100)
        result = self.gateway.authorize(action(req), req, capability_id="cap:other")
        self.assertEqual(result["reason"], "EXACT_GRANT_IMMUTABLE")
        self.broker.revoke("cap:child", at_unix=110)
        result = self.gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "EXACT_CAPABILITY_DENIED")
        self.assertEqual(self.calls, [])

    def test_restart_cannot_substitute_capability_contract_with_same_id(self):
        req = self.grant()
        replacement = CapabilityBroker()
        replacement.admit(capability(subject="someone-else"), at_unix=100)
        result = self.make_gateway(broker=replacement).execute(action(req), req)
        self.assertEqual(result["reason"], "BROKER_RESTART_REQUIRES_NEW_ROOT")
        self.assertEqual(self.calls, [])

    def test_recreated_broker_cannot_reset_narrower_quota_or_revocation(self):
        for revoked in (False, True):
            with self.subTest(revoked=revoked):
                root = "root" if not revoked else "revoked-root"
                if revoked:
                    self.authority.create_session(root, controller_id="host", policy_digest=POLICY,
                                                  objective_digest="c" * 64, max_actions=10, max_executions=1,
                                                  max_depth=0, max_stages=30, lifetime_seconds=100, lease_seconds=50)
                    self.authority.bind_execution(root, "revoked-worker")
                subject = "worker" if not revoked else "revoked-worker"
                broker = CapabilityBroker()
                contract = capability(subject=subject, max_uses=1)
                broker.admit(contract, at_unix=100)
                gateway = self.make_gateway(broker=broker)
                requests = [replace(request(10 + n + 10 * int(revoked)), subject_id=subject) for n in (1, 2, 3)]
                actions = [dict(action(req), root_id=root) for req in requests]
                for act, req in zip(actions[:2], requests[:2]):
                    self.assertEqual(gateway.authorize(act, req, capability_id="cap:child")["status"], "AUTHORIZED")
                if revoked:
                    broker.revoke("cap:child", at_unix=110)
                else:
                    self.assertEqual(gateway.execute(actions[0], requests[0])["status"], "RETURNED")
                replacement = CapabilityBroker()
                replacement.admit(contract, at_unix=100)
                restarted = self.make_gateway(broker=replacement)
                before = len(self.calls)
                self.assertEqual(restarted.execute(actions[1], requests[1])["reason"], "BROKER_RESTART_REQUIRES_NEW_ROOT")
                self.assertEqual(restarted.authorize(actions[2], requests[2], capability_id="cap:child")["reason"],
                                 "BROKER_RESTART_REQUIRES_NEW_ROOT")
                self.assertEqual(len(self.calls), before)

    def test_root_stop_blocks_child_execution_with_still_live_capability(self):
        self.authority.bind_execution("root", "child-worker", parent_execution_id="worker")
        broker = CapabilityBroker()
        broker.admit(capability(subject="child-worker"), at_unix=100)
        gateway = self.make_gateway(broker=broker)
        req = self.grant(replace(request(), subject_id="child-worker"), gateway=gateway)
        self.authority.stop("root")
        result = gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "OPERATOR_STOP")
        self.assertEqual(self.calls, [])
        self.assertTrue(all(cap["status"] == "active" for cap in broker.state_document()["capabilities"]))

    def test_stop_during_dns_prevents_secret_and_transport_stages(self):
        def resolver(host):
            self.calls.append(("dns", host))
            self.authority.stop("root")
            return ["93.184.216.34"]
        gateway = self.make_gateway(resolver=resolver)
        req = self.grant(replace(request(), secret_refs={"Authorization": "owned-ref"}), gateway)
        result = gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "OPERATOR_STOP")
        self.assertEqual([entry[0] for entry in self.calls], ["dns"])
        self.assertEqual(self.authority.status("root")["pending_action_count"], 1)

    def test_lease_loss_during_secret_prevents_transport(self):
        def secret(_):
            self.calls.append(("secret", "redacted"))
            self.now = 160
            return "never-exported"
        gateway = self.make_gateway(secret_resolver=secret)
        req = self.grant(replace(request(), secret_refs={"Authorization": "owned-ref"}), gateway)
        result = gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "LEASE_EXPIRED")
        self.assertEqual([entry[0] for entry in self.calls], ["dns", "secret"])

    def test_redirects_consume_same_stage_budget_before_next_dns(self):
        self.limits(max_stages=2)
        gateway = self.make_gateway(transport=lambda _: self.calls.append(("transport", "redirect")) or
                                     TransportResponse(307, {"Location": "https://redirect.invalid/write"}, BODY))
        req = self.grant(gateway=gateway)
        result = gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "STAGE_BUDGET_EXHAUSTED")
        self.assertEqual([entry[0] for entry in self.calls], ["dns", "transport"])
        self.assertEqual(self.authority.status("root")["stage_count"], 2)

    def test_records_reservation_spends_the_same_action_budget(self):
        self.limits(max_actions=1)
        req = self.grant()
        record = dict(action(req), action_id="record:1", attempt_id="record-attempt:1",
                      target="records", arguments={"owned": "effect"})
        admitted = self.authority.reserve(record, channel="records", policy_digest=POLICY)
        self.assertEqual(admitted["status"], "ADMITTED")
        result = self.gateway.execute(action(req), req)
        self.assertEqual(result["reason"], "ACTION_BUDGET_EXHAUSTED")
        self.assertEqual(self.calls, [])

    def test_callback_failure_never_refunds_or_leaks_error_detail(self):
        self.limits(max_actions=1)
        def fail(_):
            self.calls.append(("dns", "attempt"))
            raise RuntimeError("sensitive diagnostic must stay host-side")
        gateway = self.make_gateway(resolver=fail)
        req = self.grant(gateway=gateway)
        result = gateway.execute(action(req), req)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertNotIn("sensitive", str(result))
        second = self.grant(request(2), gateway)
        self.assertEqual(gateway.execute(action(second), second)["reason"], "ACTION_BUDGET_EXHAUSTED")
        self.assertEqual(self.authority.status("root")["pending_stage_count"], 1)

    def test_hung_transport_does_not_hold_stop_or_capability_locks(self):
        entered, release = threading.Event(), threading.Event()
        result = []
        def transport(_):
            entered.set()
            self.assertTrue(release.wait(5))
            return TransportResponse(200, {}, BODY)
        gateway = self.make_gateway(transport=transport)
        req = self.grant(gateway=gateway)
        worker = threading.Thread(target=lambda: result.append(gateway.execute(action(req), req)))
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            started = time.monotonic()
            stopped = self.authority.stop("root")
            self.broker.revoke("cap:child", at_unix=110)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(stopped["pending_action_count"], 1)
            self.assertEqual(stopped["pending_stage_count"], 1)
            self.assertEqual(stopped["status"], "STOPPED")
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]["status"], "RETURNED")  # Admitted callback may finish after STOP.
        self.assertEqual(result[0]["external_effect"], "UNKNOWN")

    def test_capability_revoke_ack_cannot_precede_new_stage_reservation(self):
        entered, release, revoking, acknowledged = (threading.Event() for _ in range(4))
        original = self.authority.begin_stage
        result = []
        def gated(action_id, *, stage_id):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("stage test release missing")
            return original(action_id, stage_id=stage_id)
        self.authority.begin_stage = gated
        req = self.grant()
        worker = threading.Thread(target=lambda: result.append(self.gateway.execute(action(req), req)))
        def revoke():
            revoking.set()
            self.broker.revoke("cap:child", at_unix=110)
            acknowledged.set()
        revoker = threading.Thread(target=revoke)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            revoker.start()
            self.assertTrue(revoking.wait(3))
            self.assertFalse(acknowledged.wait(0.1))
        finally:
            release.set()
            worker.join(5)
            if revoker.ident is not None:
                revoker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertTrue(acknowledged.is_set())
        # Whichever thread wins scheduling, every callback was reserved before
        # the revoke ACK. The next proposal is unconditionally blocked.
        before = len(self.calls)
        self.assertEqual(self.gateway.execute(action(req), req)["reason"], "ACTION_ALREADY_RESERVED")
        self.assertEqual(len(self.calls), before)

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(), "fork isolation requires POSIX")
    def test_fork_cannot_copy_in_memory_capability_quota_into_same_root(self):
        req = self.grant()
        ctx = multiprocessing.get_context("fork")
        result = ctx.Queue()
        worker = ctx.Process(target=lambda: result.put(self.gateway.execute(action(req), req)))
        worker.start()
        worker.join(5)
        if worker.is_alive():
            worker.kill()
            worker.join()
        self.assertEqual(worker.exitcode, 0)
        self.assertEqual(result.get(timeout=2)["reason"], "BROKER_RESTART_REQUIRES_NEW_ROOT")
        self.assertEqual(self.authority.status("root")["action_count"], 0)
        self.assertEqual(self.gateway.execute(action(req), req)["status"], "RETURNED")

    def test_real_process_loss_after_effect_cannot_redispatch_on_restart(self):
        req = request()
        effect_path = Path(self.temp.name) / "owned-effect.db"
        worker = multiprocessing.get_context("spawn").Process(target=lost_response_child, args=(str(self.path), str(effect_path)))
        worker.start()
        worker.join(10)
        if worker.is_alive():
            worker.kill()
            worker.join()
        self.assertEqual(worker.exitcode, 17)
        with sqlite3.connect(effect_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)
        restarted = self.make_gateway(authority=SessionAuthority(self.path, clock=lambda: 110))
        result = restarted.execute(action(req), req)
        self.assertEqual(result["reason"], "BROKER_RESTART_REQUIRES_NEW_ROOT")
        self.assertEqual(self.calls, [])
        status = self.authority.status("root")
        self.assertEqual((status["pending_action_count"], status["pending_stage_count"]), (1, 1))

    def test_mutating_worker_dictionaries_during_dns_cannot_change_transport(self):
        req = replace(request(), headers={"X-Allowed": "original"})
        act = action(req)
        effects = []
        def resolver(_):
            req.headers["X-Allowed"] = "mutated"
            act["epoch"] = 999
            return ["93.184.216.34"]
        gateway = self.make_gateway(resolver=resolver,
                                    transport=lambda value: effects.append(dict(value.headers)) or TransportResponse(200, {}, BODY))
        self.grant(req, gateway)
        self.assertEqual(gateway.execute(act, req)["status"], "RETURNED")
        self.assertEqual(effects, [{"X-Allowed": "original"}])


if __name__ == "__main__":
    unittest.main()
