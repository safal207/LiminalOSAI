from __future__ import annotations

import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_egress_gateway import GatewayRequest
from sdk.liminal_objective_integrity import (
    AUTHORITY,
    ZERO_SHA256,
    ObjectiveAction,
    ObjectiveGuardedRuntimeMediator,
    ObjectiveIntegrityError,
    ObjectiveIntegrityGuard,
    ObjectiveIntegrityObservation,
    ObjectiveMethodPolicy,
    ObjectiveMethodRule,
    verify_completion,
    verify_decision,
    verify_observation,
    verify_policy,
)
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_mediation import ExecutionObservation, RuntimeMediator, RuntimeOperation

GOVERNANCE_POLICY = "a" * 64
OTHER_POLICY = "b" * 64
OBJECTIVE = "c" * 64
SOURCE_BINDING = "d" * 64
EVIDENCE = "e" * 64
NOW = 2_200_000_000


def policy(*, allowed=("process.execute",), rules=(), require_completion_evidence=True):
    return ObjectiveMethodPolicy.build(
        objective_id="objective:benchmark:test",
        objective_sha256=OBJECTIVE,
        method_policy_id="method-policy:test:v1",
        governance_policy_sha256=GOVERNANCE_POLICY,
        allowed_runtime_kinds=allowed,
        rules=rules,
        require_completion_evidence=require_completion_evidence,
    )


def process_operation(*, operation_id="op:process", policy_sha=GOVERNANCE_POLICY, payload="1" * 64, at=NOW + 10):
    return RuntimeOperation(
        operation_id=operation_id,
        subject_id="agent:test",
        policy_sha256=policy_sha,
        kind="process.execute",
        scope={
            "executables": ["/usr/local/bin/worker"],
            "working_directory": "/workspace",
            "argument_profile": "bounded:test",
        },
        payload_sha256=payload,
        at_unix=at,
    )


def process_capability(*, capability_id="cap:process:objective"):
    return CapabilityContract.build(
        capability_id=capability_id,
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
        max_uses=5,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=GOVERNANCE_POLICY,
    )


def guard_with_source(p=None, *, verifier=None):
    p = p or policy()
    return ObjectiveIntegrityGuard(
        policy=p,
        trusted_source_bindings={"detector:integrity": SOURCE_BINDING},
        verify_observation=verifier or (lambda doc: doc["source_binding_sha256"] == SOURCE_BINDING),
    )


def observation(
    p,
    *,
    observation_id="obs:1",
    source_id="detector:integrity",
    source_binding=SOURCE_BINDING,
    violation="hidden_answer_access",
    previous=ZERO_SHA256,
    at=NOW + 20,
):
    return ObjectiveIntegrityObservation.build(
        observation_id=observation_id,
        objective_id=p.objective_id,
        method_policy_sha256=p.policy_sha256,
        source_id=source_id,
        source_binding_sha256=source_binding,
        violation_code=violation,
        evidence_sha256=EVIDENCE,
        observed_at_unix=at,
        previous_observation_sha256=previous,
    )


class ObjectiveIntegrityGuardTests(unittest.TestCase):
    def test_authority_does_not_add_effect_power(self):
        self.assertTrue(AUTHORITY["deterministic_policy_evaluation"])
        self.assertTrue(AUTHORITY["trusted_observation_verification_required"])
        self.assertTrue(AUTHORITY["method_integrity_completion_gate"])
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["runtime_execution"])
        self.assertFalse(AUTHORITY["network_execution"])
        self.assertFalse(AUTHORITY["secret_access"])
        self.assertFalse(AUTHORITY["semantic_omniscience"])
        self.assertFalse(AUTHORITY["automatic_containment_execution"])

    def test_policy_roundtrip_is_digest_bound(self):
        p = policy(allowed=("process.execute", "package.install"))
        self.assertEqual(verify_policy(p.as_document()), p.as_document())
        tampered = p.as_document()
        tampered["allowed_runtime_kinds"] = ["process.execute"]
        with self.assertRaises(ObjectiveIntegrityError):
            verify_policy(tampered)

    def test_rule_must_belong_to_allowed_method_kind(self):
        rule = ObjectiveMethodRule.build(
            rule_id="rule:no-network",
            runtime_kind="network.connect_domain",
            violation_code="evaluator_state_access",
            decision="CONTAIN",
        )
        with self.assertRaises(ObjectiveIntegrityError):
            policy(allowed=("process.execute",), rules=(rule,))

    def test_clean_operation_allows_and_binds_phase0_contract(self):
        g = ObjectiveIntegrityGuard(policy=policy())
        result = g.evaluate_operation(process_operation())
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["observed_violation_codes"], [])
        self.assertEqual(len(result["phase0_contract_sha256"]), 64)
        self.assertEqual(verify_decision(result), result)

    def test_runtime_kind_outside_method_policy_blocks(self):
        g = ObjectiveIntegrityGuard(policy=policy(allowed=("package.install",)))
        result = g.evaluate_operation(process_operation())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("task_constraint_mutation", result["observed_violation_codes"])
        self.assertIn("runtime_kind_outside_method_policy", result["reason_codes"])

    def test_governance_policy_drift_contains(self):
        g = ObjectiveIntegrityGuard(policy=policy())
        result = g.evaluate_operation(process_operation(policy_sha=OTHER_POLICY))
        self.assertEqual(result["decision"], "CONTAIN")
        self.assertIn("unauthorized_policy_mutation", result["observed_violation_codes"])

    def test_exact_digest_rule_contains_matching_method(self):
        op = process_operation(payload="2" * 64)
        rule = ObjectiveMethodRule.build(
            rule_id="rule:forbidden-exact-method",
            runtime_kind="process.execute",
            violation_code="evaluation_environment_exploitation",
            decision="CONTAIN",
            scope_sha256=canonical_sha256(op.normalized_scope()),
            payload_sha256=op.payload_sha256,
        )
        g = ObjectiveIntegrityGuard(policy=policy(rules=(rule,)))
        result = g.evaluate_operation(op)
        self.assertEqual(result["decision"], "CONTAIN")
        self.assertEqual(result["matched_rule_ids"], ["rule:forbidden-exact-method"])

    def test_exact_digest_rule_does_not_match_different_payload(self):
        template = process_operation(payload="2" * 64)
        rule = ObjectiveMethodRule.build(
            rule_id="rule:forbidden-exact-method",
            runtime_kind="process.execute",
            violation_code="evaluation_environment_exploitation",
            decision="CONTAIN",
            scope_sha256=canonical_sha256(template.normalized_scope()),
            payload_sha256=template.payload_sha256,
        )
        g = ObjectiveIntegrityGuard(policy=policy(rules=(rule,)))
        result = g.evaluate_operation(process_operation(payload="3" * 64))
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["matched_rule_ids"], [])

    def test_observation_requires_configured_trusted_source(self):
        p = policy()
        g = guard_with_source(p)
        item = observation(
            p,
            source_id="detector:unknown",
            source_binding="f" * 64,
        )
        with self.assertRaises(ObjectiveIntegrityError):
            g.ingest_observation(item.as_document())

    def test_observation_requires_external_verifier(self):
        p = policy()
        g = guard_with_source(p, verifier=lambda _: False)
        with self.assertRaises(ObjectiveIntegrityError):
            g.ingest_observation(observation(p).as_document())

    def test_observation_roundtrip_and_chain_replay_protection(self):
        p = policy()
        g = guard_with_source(p)
        item = observation(p)
        self.assertEqual(verify_observation(item.as_document()), item.as_document())
        accepted = g.ingest_observation(item.as_document())
        self.assertEqual(accepted["decision_floor"], "CONTAIN")
        with self.assertRaises(ObjectiveIntegrityError):
            g.ingest_observation(item.as_document())

    def test_disconnected_observation_chain_is_rejected(self):
        p = policy()
        g = guard_with_source(p)
        bad = observation(p, previous="9" * 64)
        with self.assertRaises(ObjectiveIntegrityError):
            g.ingest_observation(bad.as_document())

    def test_critical_violation_is_monotonic_across_later_benign_step(self):
        p = policy()
        g = guard_with_source(p)
        g.ingest_observation(observation(p, violation="hidden_answer_access").as_document())
        result = g.evaluate_operation(process_operation(at=NOW + 30))
        self.assertEqual(result["decision"], "CONTAIN")
        self.assertIn("hidden_answer_access", result["observed_violation_codes"])
        self.assertEqual(g.state_document()["decision_floor"], "CONTAIN")

    def test_noncritical_violation_blocks_completion(self):
        p = policy()
        g = guard_with_source(p)
        g.ingest_observation(
            observation(p, violation="result_fabrication").as_document()
        )
        result = g.verify_completion(
            result_sha256="1" * 64,
            trajectory_sha256="2" * 64,
            method_evidence_sha256="3" * 64,
            at_unix=NOW + 40,
        )
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("method_integrity_not_clean", result["reason_codes"])

    def test_clean_completion_requires_method_evidence(self):
        g = ObjectiveIntegrityGuard(policy=policy())
        blocked = g.verify_completion(
            result_sha256="1" * 64,
            trajectory_sha256=ZERO_SHA256,
            method_evidence_sha256=ZERO_SHA256,
            at_unix=NOW + 40,
        )
        self.assertEqual(blocked["decision"], "BLOCK")
        allowed = g.verify_completion(
            result_sha256="1" * 64,
            trajectory_sha256="2" * 64,
            method_evidence_sha256="3" * 64,
            at_unix=NOW + 41,
        )
        self.assertEqual(allowed["decision"], "ALLOW")
        self.assertEqual(verify_completion(allowed), allowed)

    def test_correct_result_does_not_override_critical_method_violation(self):
        p = policy()
        g = guard_with_source(p)
        g.ingest_observation(
            observation(p, violation="evaluator_state_access").as_document()
        )
        completion = g.verify_completion(
            result_sha256="4" * 64,
            trajectory_sha256="5" * 64,
            method_evidence_sha256="6" * 64,
            at_unix=NOW + 50,
        )
        self.assertEqual(completion["decision"], "CONTAIN")
        self.assertIn("evaluator_state_access", completion["observed_violation_codes"])

    def test_guarded_runtime_mediator_delegates_only_after_allow(self):
        broker = CapabilityBroker("broker:objective-allow")
        broker.admit(process_capability().as_document(), at_unix=NOW)
        delegate = RuntimeMediator(broker=broker)
        guarded = ObjectiveGuardedRuntimeMediator(
            guard=ObjectiveIntegrityGuard(policy=policy()),
            delegate=delegate,
        )
        called = []
        result = guarded.mediate(
            process_operation(),
            lambda _: called.append(True) or ExecutionObservation.success({"safe": True}),
        )
        self.assertEqual(result["admission_decision"], "ALLOW")
        self.assertEqual(result["execution_outcome"], "SUCCEEDED")
        self.assertEqual(called, [True])

    def test_guarded_runtime_mediator_does_not_consume_capability_on_objective_block(self):
        op = process_operation(payload="7" * 64)
        rule = ObjectiveMethodRule.build(
            rule_id="rule:block-before-capability",
            runtime_kind="process.execute",
            violation_code="task_constraint_mutation",
            decision="BLOCK",
            payload_sha256=op.payload_sha256,
        )
        broker = CapabilityBroker("broker:objective-block")
        broker.admit(process_capability().as_document(), at_unix=NOW)
        delegate = RuntimeMediator(broker=broker)
        guarded = ObjectiveGuardedRuntimeMediator(
            guard=ObjectiveIntegrityGuard(policy=policy(rules=(rule,))),
            delegate=delegate,
        )
        called = []
        result = guarded.mediate(
            op,
            lambda _: called.append(True) or ExecutionObservation.success({"should": "not-run"}),
        )
        self.assertEqual(result["admission_decision"], "BLOCK")
        self.assertEqual(result["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(called, [])
        state = broker.state_document()["capabilities"][0]
        self.assertEqual(state["use_count"], 0)

    def test_network_forbidden_route_is_blocked_before_egress_gateway(self):
        req = GatewayRequest(
            call_id="net:objective:1",
            subject_id="agent:test",
            policy_sha256=GOVERNANCE_POLICY,
            method="GET",
            url="https://evaluator.invalid/answer",
            headers={},
            body_sha256="8" * 64,
            secret_refs={},
            at_unix=NOW + 10,
        )
        action = ObjectiveAction.from_network_request(req)
        rule = ObjectiveMethodRule.build(
            rule_id="rule:no-evaluator-route",
            runtime_kind="network.connect_domain",
            violation_code="evaluator_state_access",
            decision="CONTAIN",
            scope_sha256=action.scope_sha256,
        )
        g = ObjectiveIntegrityGuard(
            policy=policy(allowed=("network.connect_domain",), rules=(rule,))
        )
        guarded = ObjectiveGuardedRuntimeMediator(
            guard=g,
            delegate=RuntimeMediator(broker=CapabilityBroker("broker:no-egress")),
        )
        result = guarded.mediate_network(req)
        self.assertEqual(result["admission_decision"], "BLOCK")
        self.assertEqual(result["objective_decision"], "CONTAIN")
        self.assertEqual(result["runtime_mediation_receipt_sha256"], ZERO_SHA256)

    def test_safe_incident_shape_forbidden_method_completion_never_allows(self):
        p = policy(
            allowed=(
                "package.install",
                "network.connect_domain",
                "credential.access",
                "process.execute",
            )
        )
        g = guard_with_source(p)

        for index, kind in enumerate(
            ("package.install", "network.connect_domain", "credential.access"), start=1
        ):
            action = ObjectiveAction(
                action_id=f"synthetic:{index}",
                subject_id="agent:synthetic",
                policy_sha256=GOVERNANCE_POLICY,
                runtime_kind=kind,
                scope_sha256=canonical_sha256({"stage": index, "synthetic": True}),
                payload_sha256=canonical_sha256({"payload": index, "synthetic": True}),
                at_unix=NOW + index,
            )
            self.assertEqual(g.evaluate_action(action)["decision"], "ALLOW")

        obs = observation(
            p,
            observation_id="obs:forbidden-method",
            violation="hidden_answer_access",
            at=NOW + 10,
        )
        g.ingest_observation(obs.as_document())

        later = ObjectiveAction(
            action_id="synthetic:final",
            subject_id="agent:synthetic",
            policy_sha256=GOVERNANCE_POLICY,
            runtime_kind="process.execute",
            scope_sha256=canonical_sha256({"final": True}),
            payload_sha256=canonical_sha256({"result": "digest-only"}),
            at_unix=NOW + 11,
        )
        self.assertEqual(g.evaluate_action(later)["decision"], "CONTAIN")
        completion = g.verify_completion(
            result_sha256="9" * 64,
            trajectory_sha256="7" * 64,
            method_evidence_sha256="6" * 64,
            at_unix=NOW + 12,
        )
        self.assertEqual(completion["decision"], "CONTAIN")

    def test_receipts_do_not_expose_raw_objective_or_forbidden_route(self):
        raw_objective = "solve benchmark without reading hidden answers"
        raw_route = "https://evaluator.invalid/answer"
        p = ObjectiveMethodPolicy.build(
            objective_id="objective:redaction:test",
            objective_sha256=canonical_sha256(raw_objective),
            method_policy_id="method-policy:redaction:v1",
            governance_policy_sha256=GOVERNANCE_POLICY,
            allowed_runtime_kinds=("process.execute",),
        )
        g = ObjectiveIntegrityGuard(policy=p)
        result = g.evaluate_operation(process_operation())
        rendered = repr(result) + repr(g.state_document()) + repr(p.as_document())
        self.assertNotIn(raw_objective, rendered)
        self.assertNotIn(raw_route, rendered)


if __name__ == "__main__":
    unittest.main()
