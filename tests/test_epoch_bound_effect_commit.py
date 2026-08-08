from __future__ import annotations

import hashlib
import threading
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_effect_commit import (
    AUTHORITY,
    EffectCommitBroker,
    EffectCommitError,
    EpochBoundEffectRuntimeMediator,
    FencedBoundRuntimeConfigBroker,
    RuntimeCommitFence,
    build_session_document,
    verify_authorization_receipt,
    verify_commit_receipt,
)
from sdk.liminal_epoch_bound_capability import EpochBoundCapabilityBroker, EpochBoundCapabilityContract
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_config import RuntimeConfigPlan, STATE_SCHEMA as RUNTIME_STATE_SCHEMA
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

POLICY = "a" * 64
STATE0 = "1" * 64
STATE1 = "2" * 64
HOST = "3" * 64
SESSION0 = "4" * 64
SESSION1 = "5" * 64
NOW = 2200000000
ADAPTER_TOKEN = "trusted-effect-adapter"
ADAPTER_SHA = hashlib.sha256(ADAPTER_TOKEN.encode("utf-8")).hexdigest()


class MutableClock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class FakeRuntimeProvider:
    def __init__(self):
        self.epoch = 0
        self.state = STATE0
        self.tainted = False

    def state_document(self):
        return {"epoch": self.epoch, "state_sha256": self.state, "tainted": self.tainted}


class FakeSessionProvider:
    def __init__(self):
        self.session = SESSION0
        self.active = True

    def session_document(self, operation_id):
        return build_session_document(
            operation_id=operation_id,
            session_sha256=self.session,
            host_binding_sha256=HOST,
            active=self.active,
        )


def base_capability(*, capability_id="cap:effect:1", capability_type="process.execute", scope=None, max_uses=10):
    if scope is None:
        scope = {
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        }
    return CapabilityContract.build(
        capability_id=capability_id,
        capability_type=capability_type,
        subject_id="agent:test",
        issuer_id="issuer:test",
        scope=scope,
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        max_uses=max_uses,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=POLICY,
    )


def operation(operation_id="op:effect", *, at_unix=NOW + 1):
    return RuntimeOperation(
        operation_id=operation_id,
        subject_id="agent:test",
        policy_sha256=POLICY,
        kind="process.execute",
        scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        payload_sha256="6" * 64,
        at_unix=at_unix,
    )


def setup_stack(*, clock=None, fence=None):
    runtime = FakeRuntimeProvider()
    sessions = FakeSessionProvider()
    delegate = CapabilityBroker("broker:effect-delegate")
    epoch = EpochBoundCapabilityBroker(runtime_provider=runtime, delegate=delegate, broker_id="broker:effect-epoch")
    base = base_capability()
    bound = EpochBoundCapabilityContract.build(
        base_capability=base.as_document(),
        runtime_epoch=runtime.epoch,
        runtime_state_sha256=runtime.state,
    )
    assert epoch.admit(bound.as_document(), at_unix=NOW)["decision"] == "ALLOW"
    shared_fence = fence or RuntimeCommitFence()
    trusted_clock = clock or MutableClock()
    commit = EffectCommitBroker(
        runtime_provider=runtime,
        session_provider=sessions,
        capability_broker=epoch,
        host_binding_sha256=HOST,
        adapter_token_sha256=ADAPTER_SHA,
        commit_fence=shared_fence,
        lease_ttl_seconds=5,
        clock=trusted_clock,
    )
    return runtime, sessions, delegate, epoch, commit, shared_fence, trusted_clock


def authorize(epoch, op):
    return epoch.authorize(
        subject_id=op.subject_id,
        capability_type="process.execute",
        policy_sha256=op.policy_sha256,
        requested_scope=op.normalized_scope(),
        action={
            "operation_id": op.operation_id,
            "runtime_kind": op.kind,
            "scope_sha256": canonical_sha256(op.normalized_scope()),
            "payload_sha256": op.payload_sha256,
        },
        at_unix=op.at_unix,
    )


class EffectCommitLeaseTests(unittest.TestCase):
    def test_authority_only_commits_existing_authority(self):
        self.assertTrue(AUTHORITY["effect_commit"])
        self.assertTrue(AUTHORITY["one_time_lease"])
        self.assertTrue(AUTHORITY["shared_runtime_commit_fence"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_mutation"])
        self.assertFalse(AUTHORITY["network_authority"])
        self.assertFalse(AUTHORITY["kernel_enforcement"])

    def test_same_world_one_time_commit_succeeds_and_receipts_verify(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        decision = authorize(epoch, op)
        lease_id, authorization = commit.issue_for_trusted_adapter(operation=op, capability_decision=decision)
        self.assertEqual(verify_authorization_receipt(authorization), authorization)
        called = []
        observation = commit.consume_for_trusted_adapter(
            lease_id,
            adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"effect": "bounded"}),
        )
        self.assertEqual(observation.outcome, "SUCCEEDED")
        self.assertEqual(called, [True])
        receipt = commit.commit_receipts()[-1]
        self.assertEqual(verify_commit_receipt(receipt), receipt)
        self.assertEqual(receipt["runtime_epoch"], 0)
        self.assertEqual(receipt["runtime_state_sha256"], STATE0)
        self.assertEqual(receipt["execution_session_sha256"], SESSION0)

    def test_replay_is_blocked_without_second_effect(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        called = []
        commit.consume_for_trusted_adapter(
            lease_id, adapter_token=ADAPTER_TOKEN,
            executor=lambda _: called.append(True) or ExecutionObservation.success({"ok": True}),
        )
        with self.assertRaisesRegex(EffectCommitError, "lease_replayed"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(False) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [True])

    def test_stale_runtime_epoch_blocks_before_effect(self):
        runtime, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        runtime.epoch = 1
        runtime.state = STATE1
        called = []
        with self.assertRaisesRegex(EffectCommitError, "stale_runtime_epoch"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: called.append(True) or ExecutionObservation.success({"bad": True}),
            )
        self.assertEqual(called, [])

    def test_same_epoch_state_drift_blocks_before_effect(self):
        runtime, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        runtime.state = STATE1
        with self.assertRaisesRegex(EffectCommitError, "stale_runtime_state"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_execution_session_change_blocks_before_effect(self):
        _, sessions, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        sessions.session = SESSION1
        with self.assertRaisesRegex(EffectCommitError, "execution_session_changed"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_containment_after_issue_blocks_before_effect(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        commit.enter_containment(incident_receipt_sha256="7" * 64)
        with self.assertRaisesRegex(EffectCommitError, "containment_active"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_source_capability_revoked_after_issue_blocks_effect(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        decision = authorize(epoch, op)
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=decision)
        epoch.revoke(decision["capability_id"], at_unix=NOW + 2)
        with self.assertRaisesRegex(EffectCommitError, "source_capability_inactive_or_stale"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_expired_lease_and_bad_adapter_fail_closed(self):
        clock = MutableClock()
        _, _, _, epoch, commit, _, _ = setup_stack(clock=clock)
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        with self.assertRaisesRegex(EffectCommitError, "adapter_auth_failed"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token="wrong",
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )
        clock.now += 6
        with self.assertRaisesRegex(EffectCommitError, "lease_expired"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_failed_callback_burns_lease_and_records_digest_only_failure(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        with self.assertRaisesRegex(EffectCommitError, "effect_callback_failed"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: (_ for _ in ()).throw(RuntimeError("sensitive raw error")),
            )
        receipt = commit.commit_receipts()[-1]
        self.assertEqual(receipt["effect_outcome"], "FAILED")
        self.assertNotIn("sensitive raw error", repr(receipt))
        with self.assertRaisesRegex(EffectCommitError, "lease_replayed"):
            commit.consume_for_trusted_adapter(
                lease_id, adapter_token=ADAPTER_TOKEN,
                executor=lambda _: ExecutionObservation.success({"bad": True}),
            )

    def test_shared_fence_prevents_runtime_change_between_final_check_and_effect(self):
        runtime, _, _, epoch, commit, fence, _ = setup_stack()
        op = operation()
        lease_id, _ = commit.issue_for_trusted_adapter(operation=op, capability_decision=authorize(epoch, op))
        effect_entered = threading.Event()
        release_effect = threading.Event()
        mutation_done = threading.Event()
        errors = []

        def effect(_):
            effect_entered.set()
            if not release_effect.wait(2):
                raise RuntimeError("test release timeout")
            return ExecutionObservation.success({"world": runtime.epoch})

        def run_effect():
            try:
                commit.consume_for_trusted_adapter(lease_id, adapter_token=ADAPTER_TOKEN, executor=effect)
            except Exception as exc:  # pragma: no cover - diagnostic path
                errors.append(exc)

        def mutate_runtime():
            with fence.hold():
                runtime.epoch = 1
                runtime.state = STATE1
                mutation_done.set()

        effect_thread = threading.Thread(target=run_effect)
        mutation_thread = threading.Thread(target=mutate_runtime)
        effect_thread.start()
        self.assertTrue(effect_entered.wait(1))
        mutation_thread.start()
        self.assertFalse(mutation_done.wait(0.05))
        release_effect.set()
        effect_thread.join(2)
        mutation_thread.join(2)
        self.assertEqual(errors, [])
        self.assertTrue(mutation_done.is_set())
        self.assertEqual(runtime.epoch, 1)
        self.assertEqual(commit.commit_receipts()[-1]["runtime_epoch"], 0)


class RuntimeMediatorEffectCommitTests(unittest.TestCase):
    def test_opt_in_runtime_mediator_routes_effect_through_one_time_commit(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        mediator = EpochBoundEffectRuntimeMediator(broker=epoch, effect_commit_broker=commit)
        called = []
        result = mediator.mediate(
            operation("op:mediated-effect"),
            lambda _: called.append(True) or ExecutionObservation.success({"mediated": True}),
        )
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "SUCCEEDED")
        self.assertIn("effect_commit_lease_consumed", result["reason_codes"])
        self.assertEqual(called, [True])
        self.assertEqual(len(commit.commit_receipts()), 1)

    def test_containment_propagates_to_effect_commit_layer(self):
        _, _, _, epoch, commit, _, _ = setup_stack()
        mediator = EpochBoundEffectRuntimeMediator(broker=epoch, effect_commit_broker=commit)
        mediator.enter_containment(incident_receipt_sha256="8" * 64)
        called = []
        result = mediator.mediate(
            operation("op:contained-effect"),
            lambda _: called.append(True) or ExecutionObservation.success({"bad": True}),
        )
        self.assertEqual(result["admission_decision"], "BLOCK")
        self.assertEqual(called, [])
        self.assertTrue(commit.state_document()["contained"])


class FakeRuntimeConfigBackend:
    def __init__(self):
        self.state = STATE0

    def observe(self):
        body = {"schema": RUNTIME_STATE_SCHEMA, "host_binding_sha256": HOST, "state_sha256": self.state}
        return {**body, "evidence_sha256": canonical_sha256(body)}

    def apply(self, plan):
        self.state = plan.after_state_sha256


class FencedRuntimeConfigIntegrationTests(unittest.TestCase):
    def test_runtime_config_and_effect_commit_can_share_same_fence(self):
        fence = RuntimeCommitFence()
        delegate = CapabilityBroker("broker:fenced-config")
        base_mediator = RuntimeMediator(broker=delegate)
        backend = FakeRuntimeConfigBackend()
        config = FencedBoundRuntimeConfigBroker(
            commit_fence=fence,
            mediator=base_mediator,
            backend=backend,
            host_binding_sha256=HOST,
        )
        epoch = EpochBoundCapabilityBroker(runtime_provider=config, delegate=delegate, broker_id="broker:fenced-epoch")
        base_mediator.broker = epoch

        config_base = base_capability(
            capability_id="cap:runtime-config:fenced",
            capability_type="runtime.configure",
            scope={"setting_keys": ["execution_profile"]},
            max_uses=1,
        )
        config_bound = EpochBoundCapabilityContract.build(
            base_capability=config_base.as_document(),
            runtime_epoch=config.epoch,
            runtime_state_sha256=config.state_sha256,
        )
        self.assertEqual(epoch.admit(config_bound.as_document(), at_unix=NOW)["decision"], "ALLOW")

        plan = RuntimeConfigPlan.build(
            operation_id="op:fenced-config",
            setting_keys=("execution_profile",),
            before_state_sha256=STATE0,
            after_state_sha256=STATE1,
            change_set_sha256="9" * 64,
            host_binding_sha256=HOST,
            epoch_before=0,
        )
        op = RuntimeOperation(
            operation_id=plan.operation_id,
            subject_id="agent:test",
            policy_sha256=POLICY,
            kind="runtime.configure",
            scope={"setting_keys": ["execution_profile"]},
            payload_sha256=plan.payload_sha256,
            at_unix=NOW + 1,
        )
        receipt = config.execute(operation=op, plan=plan)
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(config.epoch, 1)
        self.assertEqual(config.state_sha256, STATE1)


if __name__ == "__main__":
    unittest.main()
