from __future__ import annotations

import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_epoch_bound_capability import (
    AUTHORITY,
    EpochBindingError,
    EpochBoundCapabilityBroker,
    EpochBoundCapabilityContract,
    verify_contract,
    verify_receipt,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_config import (
    BoundRuntimeConfigBroker,
    RuntimeConfigPlan,
    STATE_SCHEMA as RUNTIME_STATE_SCHEMA,
)
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

POLICY = "a" * 64
STATE0 = "1" * 64
STATE1 = "2" * 64
HOST = "3" * 64
NOW = 2200000000


class FakeRuntimeProvider:
    def __init__(self, *, epoch=0, state=STATE0, tainted=False):
        self.epoch = epoch
        self.state = state
        self.tainted = tainted

    def state_document(self):
        return {"epoch": self.epoch, "state_sha256": self.state, "tainted": self.tainted}


def base_capability(**overrides):
    values = dict(
        capability_id="cap:process:1",
        capability_type="process.execute",
        subject_id="agent:test",
        issuer_id="issuer:test",
        scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        max_uses=4,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )
    values.update(overrides)
    return CapabilityContract.build(**values)


def bound(provider, **overrides):
    cap = base_capability(**overrides)
    state = getattr(provider, "state", None)
    if state is None:
        state = provider.state_sha256
    return EpochBoundCapabilityContract.build(
        base_capability=cap.as_document(), runtime_epoch=provider.epoch, runtime_state_sha256=state,
    )


def authorize_process(broker, *, at_unix=NOW + 1):
    return broker.authorize(
        subject_id="agent:test", capability_type="process.execute", policy_sha256=POLICY,
        requested_scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        action={"operation_id": "op:test", "payload_sha256": "4" * 64}, at_unix=at_unix,
    )


class EpochBoundCapabilityTests(unittest.TestCase):
    def test_authority_only_restricts_existing_capabilities(self):
        self.assertTrue(AUTHORITY["trusted_runtime_state_required"])
        self.assertTrue(AUTHORITY["stale_authority_revocation"])
        self.assertFalse(AUTHORITY["new_effect_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["process_execution"])
        self.assertFalse(AUTHORITY["network_access"])

    def test_contract_roundtrip_binds_base_epoch_and_state(self):
        provider = FakeRuntimeProvider()
        item = bound(provider)
        verified = verify_contract(item.as_document())
        self.assertEqual(verified["binding_sha256"], item.binding_sha256)
        self.assertEqual(verified["base_capability"]["contract_sha256"], base_capability().contract_sha256)
        self.assertEqual(verified["runtime_epoch"], 0)
        self.assertEqual(verified["runtime_state_sha256"], STATE0)

    def test_contract_tamper_is_rejected(self):
        doc = bound(FakeRuntimeProvider()).as_document()
        doc["runtime_epoch"] = 1
        with self.assertRaises(EpochBindingError):
            verify_contract(doc)

    def test_same_epoch_admission_and_authorization_succeeds(self):
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        admission = broker.admit(bound(provider).as_document(), at_unix=NOW)
        self.assertEqual(admission["decision"], "ALLOW")
        use = authorize_process(broker)
        self.assertEqual(use["decision"], "ALLOW")
        self.assertIn("epoch_binding_match", use["reason_codes"])
        self.assertEqual(verify_receipt(use), use)

    def test_stale_epoch_revokes_authority_before_use(self):
        provider = FakeRuntimeProvider()
        delegate = CapabilityBroker("broker:epoch-test")
        broker = EpochBoundCapabilityBroker(runtime_provider=provider, delegate=delegate)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        provider.epoch = 1
        provider.state = STATE1
        result = authorize_process(broker, at_unix=NOW + 2)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("stale_runtime_epoch", result["reason_codes"])
        self.assertIn("stale_authority_revoked", result["reason_codes"])
        self.assertEqual(delegate.state_document()["capabilities"][0]["status"], "revoked")

    def test_same_epoch_state_drift_revokes_authority(self):
        provider = FakeRuntimeProvider()
        delegate = CapabilityBroker("broker:state-drift")
        broker = EpochBoundCapabilityBroker(runtime_provider=provider, delegate=delegate)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        provider.state = STATE1
        result = authorize_process(broker, at_unix=NOW + 2)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("stale_runtime_state", result["reason_codes"])
        self.assertEqual(delegate.state_document()["capabilities"][0]["status"], "revoked")

    def test_tainted_runtime_revokes_and_blocks(self):
        provider = FakeRuntimeProvider()
        delegate = CapabilityBroker("broker:tainted")
        broker = EpochBoundCapabilityBroker(runtime_provider=provider, delegate=delegate)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        provider.tainted = True
        result = authorize_process(broker, at_unix=NOW + 2)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("runtime_state_tainted", result["reason_codes"])
        self.assertEqual(delegate.state_document()["capabilities"][0]["status"], "revoked")

    def test_unbound_active_capability_is_revoked_fail_closed(self):
        provider = FakeRuntimeProvider()
        delegate = CapabilityBroker("broker:unbound")
        delegate.admit(base_capability().as_document(), at_unix=NOW)
        broker = EpochBoundCapabilityBroker(runtime_provider=provider, delegate=delegate)
        result = authorize_process(broker, at_unix=NOW + 1)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("unbound_authority_revoked", result["reason_codes"])
        self.assertEqual(delegate.state_document()["capabilities"][0]["status"], "revoked")

    def test_duplicate_capability_id_with_different_binding_is_rejected(self):
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        provider.epoch = 1
        provider.state = STATE1
        with self.assertRaises(EpochBindingError):
            broker.admit(bound(provider).as_document(), at_unix=NOW + 1)

    def test_child_cannot_cross_parent_runtime_binding(self):
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        parent = bound(provider, capability_id="cap:parent")
        self.assertEqual(broker.admit(parent.as_document(), at_unix=NOW)["decision"], "ALLOW")
        provider.epoch = 1
        provider.state = STATE1
        child_base = base_capability(capability_id="cap:child", parent_capability_id="cap:parent")
        child = EpochBoundCapabilityContract.build(
            base_capability=child_base.as_document(), runtime_epoch=provider.epoch,
            runtime_state_sha256=provider.state,
        )
        result = broker.admit(child.as_document(), at_unix=NOW + 1)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("delegation_runtime_binding_mismatch", result["reason_codes"])

    def test_runtime_mediator_uses_same_broker_surface(self):
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        mediator = RuntimeMediator(broker=broker)
        operation = RuntimeOperation(
            operation_id="op:mediated", subject_id="agent:test", policy_sha256=POLICY,
            kind="process.execute",
            scope={
                "executables": ["/usr/local/bin/worker"],
                "working_directory": "/workspace", "argument_profile": "bounded:test",
            },
            payload_sha256="5" * 64, at_unix=NOW + 1,
        )
        result = mediator.mediate(operation, lambda _: ExecutionObservation.success({"bounded": True}))
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "SUCCEEDED")

    def test_state_document_exposes_only_binding_evidence(self):
        provider = FakeRuntimeProvider()
        broker = EpochBoundCapabilityBroker(runtime_provider=provider)
        broker.admit(bound(provider).as_document(), at_unix=NOW)
        state = broker.state_document()
        self.assertEqual(state["runtime_epoch"], 0)
        self.assertEqual(state["runtime_state_sha256"], STATE0)
        self.assertTrue(state["capabilities"][0]["epoch_bound"])
        self.assertNotIn("PATH=", repr(state))


class FakeRuntimeConfigBackend:
    def __init__(self):
        self.state = STATE0

    def observe(self):
        body = {"schema": RUNTIME_STATE_SCHEMA, "host_binding_sha256": HOST, "state_sha256": self.state}
        return {**body, "evidence_sha256": canonical_sha256(body)}

    def apply(self, plan):
        self.state = plan.after_state_sha256


class RuntimeConfigEpochBindingIntegrationTests(unittest.TestCase):
    def test_runtime_config_rollover_invalidates_old_bound_world(self):
        delegate = CapabilityBroker("broker:config-integration")
        mediator = RuntimeMediator(broker=delegate)
        backend = FakeRuntimeConfigBackend()
        config = BoundRuntimeConfigBroker(mediator=mediator, backend=backend, host_binding_sha256=HOST)
        epoch_broker = EpochBoundCapabilityBroker(
            runtime_provider=config, delegate=delegate, broker_id="broker:epoch-config-integration",
        )
        mediator.broker = epoch_broker

        process = bound(config, capability_id="cap:process:integration")
        self.assertEqual(epoch_broker.admit(process.as_document(), at_unix=NOW)["decision"], "ALLOW")
        config_base = base_capability(
            capability_id="cap:runtime-config", capability_type="runtime.configure",
            scope={"setting_keys": ["execution_profile"]}, max_uses=1,
        )
        config_bound = EpochBoundCapabilityContract.build(
            base_capability=config_base.as_document(), runtime_epoch=config.epoch,
            runtime_state_sha256=config.state_sha256,
        )
        self.assertEqual(epoch_broker.admit(config_bound.as_document(), at_unix=NOW)["decision"], "ALLOW")

        plan = RuntimeConfigPlan.build(
            operation_id="op:runtime-config", setting_keys=("execution_profile",),
            before_state_sha256=STATE0, after_state_sha256=STATE1,
            change_set_sha256="6" * 64, host_binding_sha256=HOST, epoch_before=0,
        )
        operation = RuntimeOperation(
            operation_id=plan.operation_id, subject_id="agent:test", policy_sha256=POLICY,
            kind="runtime.configure", scope={"setting_keys": ["execution_profile"]},
            payload_sha256=plan.payload_sha256, at_unix=NOW + 1,
        )
        receipt = config.execute(operation=operation, plan=plan)
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(config.epoch, 1)
        self.assertEqual(config.state_sha256, STATE1)

        result = authorize_process(epoch_broker, at_unix=NOW + 2)
        self.assertEqual(result["decision"], "BLOCK")
        statuses = {item["capability_id"]: item["status"] for item in delegate.state_document()["capabilities"]}
        self.assertEqual(statuses["cap:process:integration"], "revoked")


if __name__ == "__main__":
    unittest.main()
