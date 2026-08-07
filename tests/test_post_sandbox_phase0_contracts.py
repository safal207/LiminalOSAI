from __future__ import annotations

import copy
import unittest

from sdk.liminal_post_sandbox_contracts import (
    AUTHORITY,
    CAPABILITY_TYPES,
    CONTAINMENT_SCHEMA,
    OBJECTIVE_INTEGRITY_SCHEMA,
    CapabilityContract,
    CausalRuntimeEvent,
    ContractError,
    RuntimeEvidenceRequirement,
    canonical_sha256,
    default_evidence_requirements,
    validate_containment_transition,
    validate_objective_integrity,
    validate_scope,
)

ZERO = "0" * 64
A = "a" * 64
B = "b" * 64
C = "c" * 64


def capability(**overrides):
    values = dict(
        capability_id="cap:repo-write:1",
        capability_type="repository.write",
        subject_id="agent:worker",
        issuer_id="broker:test",
        scope={"repository": "safal207/LiminalOSAI", "refs": ["refs/heads/agent/test"], "paths": ["docs/"]},
        issued_at_unix=100,
        not_before_unix=100,
        expires_at_unix=200,
        max_uses=1,
        delegable=False,
        parent_capability_id=None,
        policy_sha256=A,
    )
    values.update(overrides)
    return CapabilityContract.build(**values)


def causal(**overrides):
    values = dict(
        event_id="event:1",
        event_type="use",
        subject_id="agent:worker",
        capability_id="cap:repo-write:1",
        recorder_event_id="tool:1",
        recorder_entry_sha256=A,
        effect="write",
        decision="ALLOW",
        observed_at_unix=150,
        previous_causal_event_sha256=ZERO,
        input_sha256=B,
        output_sha256=C,
        reason_codes=["capability_scope_match"],
    )
    values.update(overrides)
    return CausalRuntimeEvent.build(**values)


class CapabilityContractTests(unittest.TestCase):
    def test_all_initial_capability_types_have_default_evidence_contracts(self):
        requirements = default_evidence_requirements()
        self.assertEqual(len(requirements), len(CAPABILITY_TYPES))
        self.assertEqual({r.action_class.replace(":", ".") for r in requirements}, set(CAPABILITY_TYPES))

    def test_build_round_trip_is_deterministic(self):
        item = capability()
        self.assertEqual(CapabilityContract.from_document(item.as_document()), item)
        self.assertEqual(item.contract_sha256, canonical_sha256(item.body()))

    def test_authority_is_contract_only(self):
        self.assertFalse(AUTHORITY["capability_grant"])
        self.assertFalse(AUTHORITY["execution"])
        self.assertFalse(AUTHORITY["containment_execution"])

    def test_unknown_capability_type_rejected(self):
        with self.assertRaises(ContractError):
            capability(capability_type="root.shell")

    def test_empty_scope_rejected(self):
        with self.assertRaises(ContractError):
            capability(scope={})

    def test_scope_unknown_key_rejected(self):
        with self.assertRaises(ContractError):
            capability(scope={"repository": "safal207/LiminalOSAI", "token": "secret"})

    def test_repository_scope_requires_owner_name(self):
        with self.assertRaises(ContractError):
            capability(scope={"repository": "not-a-repo"})

    def test_invalid_validity_window_rejected(self):
        with self.assertRaises(ContractError):
            capability(not_before_unix=200, expires_at_unix=200)

    def test_zero_use_capability_rejected(self):
        with self.assertRaises(ContractError):
            capability(max_uses=0)

    def test_unbounded_use_count_rejected(self):
        with self.assertRaises(ContractError):
            capability(max_uses=1001)

    def test_delegation_requires_parent(self):
        with self.assertRaises(ContractError):
            capability(delegable=True)

    def test_tampered_contract_digest_rejected(self):
        doc = capability().as_document()
        doc["scope"]["paths"] = ["/"]
        with self.assertRaises(ContractError):
            CapabilityContract.from_document(doc)

    def test_network_scope_normalizes_domains(self):
        scope = validate_scope("network.connect_domain", {"domains": ["API.EXAMPLE.COM"], "protocols": ["https"], "ports": [443]})
        self.assertEqual(scope["domains"], ["api.example.com"])

    def test_invalid_network_domain_rejected(self):
        with self.assertRaises(ContractError):
            validate_scope("network.connect_domain", {"domains": ["localhost"], "protocols": ["https"], "ports": [443]})

    def test_invalid_port_rejected(self):
        with self.assertRaises(ContractError):
            validate_scope("network.connect_domain", {"domains": ["api.example.com"], "ports": [70000]})


class CausalEventTests(unittest.TestCase):
    def test_round_trip_and_hash(self):
        item = causal()
        self.assertEqual(CausalRuntimeEvent.from_document(item.as_document()), item)
        self.assertEqual(item.event_sha256, canonical_sha256(item.body()))

    def test_lifecycle_event_requires_capability(self):
        with self.assertRaises(ContractError):
            causal(capability_id=None)

    def test_recorder_reference_is_paired(self):
        with self.assertRaises(ContractError):
            causal(recorder_entry_sha256=None)

    def test_runtime_event_may_exist_without_recorder_reference(self):
        item = causal(event_type="runtime_action", capability_id=None, recorder_event_id=None, recorder_entry_sha256=None)
        self.assertIsNone(item.recorder_event_id)

    def test_unknown_decision_rejected(self):
        with self.assertRaises(ContractError):
            causal(decision="MAYBE")

    def test_empty_reason_codes_rejected(self):
        with self.assertRaises(ContractError):
            causal(reason_codes=[])

    def test_duplicate_reason_codes_rejected(self):
        with self.assertRaises(ContractError):
            causal(reason_codes=["scope_match", "scope_match"])

    def test_tampered_causal_hash_rejected(self):
        doc = causal().as_document()
        doc["decision"] = "BLOCK"
        with self.assertRaises(ContractError):
            CausalRuntimeEvent.from_document(doc)


class EvidenceRequirementTests(unittest.TestCase):
    def test_sensitive_evidence_is_fail_closed(self):
        for item in default_evidence_requirements():
            self.assertTrue(item.fail_closed_on_missing)
            self.assertTrue(item.require_capability)
            self.assertTrue(item.require_recorder_link)

    def test_fail_open_contract_rejected(self):
        item = RuntimeEvidenceRequirement.build(action_class="repository:write", required_roots=["policy_sha256"])
        doc = item.as_document()
        doc["fail_closed_on_missing"] = False
        body = {k: v for k, v in doc.items() if k != "requirement_sha256"}
        doc["requirement_sha256"] = canonical_sha256(body)
        with self.assertRaises(ContractError):
            RuntimeEvidenceRequirement.from_document(doc)

    def test_empty_required_roots_rejected(self):
        with self.assertRaises(ContractError):
            RuntimeEvidenceRequirement.build(action_class="repository:write", required_roots=[])


class ContainmentTests(unittest.TestCase):
    def transition(self, before, after, *, release=None):
        return {
            "schema": CONTAINMENT_SCHEMA,
            "incident_id": "incident:1",
            "from_state": before,
            "to_state": after,
            "reason_codes": ["trajectory_risk_threshold"],
            "evidence_sha256": A,
            "at_unix": 200,
            "human_release_id": release,
            "authority": AUTHORITY,
        }

    def test_canonical_sequence_is_valid(self):
        sequence = ["IDLE", "DETECT", "FREEZE", "REVOKE", "SEAL", "SNAPSHOT", "REVIEW"]
        for before, after in zip(sequence, sequence[1:]):
            self.assertEqual(validate_containment_transition(self.transition(before, after))["to_state"], after)
        self.assertEqual(validate_containment_transition(self.transition("REVIEW", "RELEASED", release="release:human:1"))["to_state"], "RELEASED")

    def test_skip_transition_rejected(self):
        with self.assertRaises(ContractError):
            validate_containment_transition(self.transition("DETECT", "REVOKE"))

    def test_rollback_transition_rejected(self):
        with self.assertRaises(ContractError):
            validate_containment_transition(self.transition("SEAL", "REVOKE"))

    def test_release_requires_human_id(self):
        with self.assertRaises(ContractError):
            validate_containment_transition(self.transition("REVIEW", "RELEASED"))

    def test_early_human_release_id_rejected(self):
        with self.assertRaises(ContractError):
            validate_containment_transition(self.transition("DETECT", "FREEZE", release="release:human:1"))


class ObjectiveIntegrityTests(unittest.TestCase):
    def contract(self, violations, decision):
        return {
            "schema": OBJECTIVE_INTEGRITY_SCHEMA,
            "objective_id": "objective:1",
            "method_policy_sha256": A,
            "observed_violation_codes": violations,
            "decision": decision,
            "evidence_sha256": B,
            "authority": AUTHORITY,
        }

    def test_clean_method_can_allow(self):
        self.assertEqual(validate_objective_integrity(self.contract([], "ALLOW"))["decision"], "ALLOW")

    def test_violation_cannot_allow(self):
        with self.assertRaises(ContractError):
            validate_objective_integrity(self.contract(["evidence_tampering"], "ALLOW"))

    def test_violation_can_contain(self):
        result = validate_objective_integrity(self.contract(["unauthorized_runtime_mutation"], "CONTAIN"))
        self.assertEqual(result["decision"], "CONTAIN")

    def test_unknown_violation_rejected(self):
        with self.assertRaises(ContractError):
            validate_objective_integrity(self.contract(["magic_escape"], "BLOCK"))

    def test_authority_tamper_rejected(self):
        doc = self.contract([], "ALLOW")
        doc["authority"] = copy.deepcopy(AUTHORITY)
        doc["authority"]["execution"] = True
        with self.assertRaises(ContractError):
            validate_objective_integrity(doc)


if __name__ == "__main__":
    unittest.main()
