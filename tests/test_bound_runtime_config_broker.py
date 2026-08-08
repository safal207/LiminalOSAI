import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_config import (
    BoundRuntimeConfigBroker,
    RuntimeConfigPlan,
    STATE_SCHEMA,
    verify_receipt,
)
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

NOW = 2100002000
POLICY = "a" * 64
HOST = "b" * 64
S0 = canonical_sha256({"runtime": "state-0"})
S1 = canonical_sha256({"runtime": "state-1"})
S2 = canonical_sha256({"runtime": "state-2"})
CHANGE = canonical_sha256({"change": "profile-1"})


def state_doc(state_sha, *, forged=False):
    body = {
        "schema": STATE_SCHEMA,
        "host_binding_sha256": HOST,
        "state_sha256": state_sha,
    }
    evidence = canonical_sha256(body)
    if forged:
        evidence = "f" * 64
    return {**body, "evidence_sha256": evidence}


class FakeBackend:
    def __init__(self):
        self.state_sha = S0
        self.apply_count = 0
        self.target = S1
        self.fail_after_mutation = False
        self.forge_after = False

    def observe(self):
        return state_doc(self.state_sha, forged=self.forge_after and self.apply_count > 0)

    def apply(self, plan):
        self.apply_count += 1
        self.state_sha = self.target
        if self.fail_after_mutation:
            raise RuntimeError("host mutation failed")


def capability(capability_id, capability_type, scope, *, max_uses=4):
    return CapabilityContract.build(
        capability_id=capability_id,
        capability_type=capability_type,
        subject_id="agent:test",
        issuer_id="human:test",
        scope=scope,
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 1000,
        max_uses=max_uses,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    ).as_document()


def runtime_scope():
    return {"setting_keys": ["execution_profile", "proxy_mode"]}


def process_scope():
    return {
        "executables": ["/bin/true"],
        "working_directory": "/workspace",
        "argument_profile": "post-config-check",
    }


def make_stack():
    cap_broker = CapabilityBroker("broker:runtime-config-test")
    cap_broker.admit(capability("cap:runtime-config", "runtime.configure", runtime_scope()), at_unix=NOW)
    cap_broker.admit(capability("cap:old-process", "process.execute", process_scope()), at_unix=NOW)
    backend = FakeBackend()
    mediator = RuntimeMediator(broker=cap_broker)
    config = BoundRuntimeConfigBroker(mediator=mediator, backend=backend, host_binding_sha256=HOST)
    return cap_broker, mediator, backend, config


def plan(*, before=S0, after=S1, epoch=0, change=CHANGE):
    return RuntimeConfigPlan.build(
        operation_id="op:configure-1",
        setting_keys=runtime_scope()["setting_keys"],
        before_state_sha256=before,
        after_state_sha256=after,
        change_set_sha256=change,
        host_binding_sha256=HOST,
        epoch_before=epoch,
    )


def operation(p):
    return RuntimeOperation(
        operation_id=p.operation_id,
        subject_id="agent:test",
        policy_sha256=POLICY,
        kind="runtime.configure",
        scope=runtime_scope(),
        payload_sha256=p.payload_sha256,
        at_unix=NOW + 1,
    )


class BoundRuntimeConfigBrokerTests(unittest.TestCase):
    def test_success_advances_epoch_and_revokes_old_authority(self):
        cap_broker, mediator, backend, config = make_stack()
        p = plan()
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["outcome"], "SUCCEEDED")
        self.assertEqual(receipt["epoch_before"], 0)
        self.assertEqual(receipt["epoch_after"], 1)
        self.assertEqual(receipt["after_state_sha256"], S1)
        self.assertEqual(receipt["revoked_authority_count"], 2)
        self.assertEqual(config.epoch, 1)
        self.assertEqual(config.state_sha256, S1)
        self.assertFalse(config.tainted)
        verify_receipt(receipt)
        statuses = {item["capability_id"]: item["status"] for item in cap_broker.state_document()["capabilities"]}
        self.assertEqual(statuses["cap:runtime-config"], "revoked")
        self.assertEqual(statuses["cap:old-process"], "revoked")

        denied = mediator.mediate(
            RuntimeOperation(
                operation_id="op:old-process",
                subject_id="agent:test",
                policy_sha256=POLICY,
                kind="process.execute",
                scope=process_scope(),
                payload_sha256="c" * 64,
                at_unix=NOW + 2,
            ),
            lambda _: ExecutionObservation.success({"should_not": "run"}),
        )
        self.assertEqual(denied["admission_decision"], "BLOCK")
        self.assertIn("revoked", denied["reason_codes"])

    def test_stale_before_state_fails_without_consuming_capability_or_mutating(self):
        cap_broker, _, backend, config = make_stack()
        p = plan(before=S2)
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["outcome"], "NOT_EXECUTED")
        self.assertIn("stale_before_state", receipt["reason_codes"])
        self.assertEqual(backend.apply_count, 0)
        runtime_cap = next(x for x in cap_broker.state_document()["capabilities"] if x["capability_id"] == "cap:runtime-config")
        self.assertEqual(runtime_cap["use_count"], 0)
        self.assertEqual(runtime_cap["status"], "active")

    def test_completed_plan_replay_is_non_mutating(self):
        _, _, backend, config = make_stack()
        p = plan()
        first = config.execute(operation=operation(p), plan=p)
        self.assertEqual(first["decision"], "ALLOW")
        second = config.execute(operation=operation(p), plan=p)
        self.assertEqual(second["decision"], "BLOCK")
        self.assertIn("plan_replay", second["reason_codes"])
        self.assertEqual(backend.apply_count, 1)

    def test_stale_epoch_is_rejected_before_host_mutation(self):
        _, _, backend, config = make_stack()
        p = plan(epoch=1)
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertIn("stale_runtime_epoch", receipt["reason_codes"])
        self.assertEqual(backend.apply_count, 0)

    def test_after_state_mismatch_taints_runtime_and_revokes_authority(self):
        cap_broker, _, backend, config = make_stack()
        backend.target = S2
        p = plan(after=S1)
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["outcome"], "FAILED_CLOSED")
        self.assertIn("after_state_mismatch", receipt["reason_codes"])
        self.assertEqual(config.epoch, 1)
        self.assertTrue(config.tainted)
        self.assertEqual(config.state_sha256, S2)
        self.assertTrue(all(x["status"] == "revoked" for x in cap_broker.state_document()["capabilities"]))

    def test_partial_host_failure_is_tainted_and_invalidates_old_epoch(self):
        cap_broker, _, backend, config = make_stack()
        backend.fail_after_mutation = True
        receipt = config.execute(operation=operation(plan()), plan=plan())
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["outcome"], "FAILED_CLOSED")
        self.assertIn("host_mutation_unverified", receipt["reason_codes"])
        self.assertEqual(config.epoch, 1)
        self.assertTrue(config.tainted)
        self.assertTrue(all(x["status"] == "revoked" for x in cap_broker.state_document()["capabilities"]))

    def test_forged_after_evidence_fails_closed(self):
        cap_broker, _, backend, config = make_stack()
        backend.forge_after = True
        p = plan()
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["outcome"], "FAILED_CLOSED")
        self.assertTrue(config.tainted)
        self.assertEqual(config.epoch, 1)
        self.assertTrue(all(x["status"] == "revoked" for x in cap_broker.state_document()["capabilities"]))

    def test_containment_active_blocks_before_backend_apply(self):
        _, mediator, backend, config = make_stack()
        mediator.enter_containment(incident_receipt_sha256="d" * 64)
        p = plan()
        receipt = config.execute(operation=operation(p), plan=p)
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["outcome"], "NOT_EXECUTED")
        self.assertEqual(backend.apply_count, 0)
        self.assertIn("containment_active", receipt["reason_codes"])

    def test_receipt_tamper_is_rejected(self):
        _, _, _, config = make_stack()
        p = plan()
        receipt = config.execute(operation=operation(p), plan=p)
        forged = dict(receipt)
        forged["epoch_after"] = 99
        with self.assertRaises(Exception):
            verify_receipt(forged)


if __name__ == "__main__":
    unittest.main()
