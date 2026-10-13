"""Independent agent packet checks; actual Docker capture tamper tests follow.

Small signed packet fixtures exercise the offline validator only. They never
produce a runtime PASS or stand in for required real Docker execution.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("independent_agent_checker", ROOT / "scripts/verify_external_agent_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ExternalAgentPacketEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pin = {"supervisor_id": "supervisor:unit", "key_id": "key:unit", "public_key": self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        self.spec = {"schema": "liminal-owned-docker-agent-spec-v1", "command_id": "command:unit",
            "image_id": "sha256:" + "a" * 64, "host_workspace": "/tmp/command-unit", "fixture": "useful_completion",
            "argv": ["-I", "-u", "/workspace/external_agent_fixture.py", "useful_completion"], "timeout_seconds": 30,
            "isolation": deepcopy(verifier.ISOLATION), "working_directory": "/workspace",
            "environment_policy": "image-default-no-injected-env", "workspace_mount": {
                "source": "/tmp/command-unit", "target": "/workspace", "read_only": True},
            "entrypoint": "python3", "log_driver": "none", "fixture_sha256": verifier.FIXTURE_SHA256}
        self.spec["plan_sha256"] = verifier.sha({"operation_id": self.spec["command_id"], "image_id": self.spec["image_id"],
            "argv_sha256": verifier.sha(self.spec["argv"]), "host_workspace_sha256": verifier.sha(self.spec["host_workspace"]),
            "timeout_seconds": 30, "profile_sha256": verifier.sha(self.spec["isolation"])})
        self.action = {"action_id": "action:unit", "attempt_id": "attempt:unit", "root_id": "root:unit",
            "execution_id": "execution:unit", "epoch": 1, "target": "command", "arguments": {
                "stage": "CREATE", "spec": self.spec, "parent_reservation_id": None, "container_id": None}}
        self.grant = {"action_digest": verifier.sha(self.action), "policy_version": "c" * 64,
            "expires_at": 1000, "receiver_id": self.pin["supervisor_id"]}
        self.body = {"schema": "liminal.external-agent.receipt.v1", "supervisor_id": self.pin["supervisor_id"],
            "key_id": self.pin["key_id"], "reservation_id": "reservation:unit", **{k: self.action[k] for k in
                ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": verifier.sha(self.action), "authorization_digest": verifier.sha(self.grant), "stage": "CREATE",
            "command_id": self.spec["command_id"], "image_id": self.spec["image_id"], "container_id": "d" * 64,
            "plan_sha256": self.spec["plan_sha256"], "ownership_digest": "e" * 64,
            "create_confirmed": True, "callbacks_finished": True, "process_quiescent": True,
            "start_admitted": False, "start_outcome": "NOT_STARTED", "business_effects": "NOT_ESTABLISHED",
            "observation_digest": "f" * 64, "observed_at": 100, "status": "QUIESCENT"}

    def signed(self, body=None):
        value = deepcopy(self.body if body is None else body)
        return {**value, "signature": self.key.sign(verifier.RECEIPT_DOMAIN + verifier.canonical(value)).hex()}

    def test_signed_packet_validates_only_schema_binding_and_signature(self):
        receipt = self.signed()
        self.assertEqual(verifier._receipt(receipt, self.pin, self.action, self.grant, "reservation:unit"), receipt)
        self.assertNotIn("effect_count", receipt)

    def test_each_required_terminal_condition_is_mandatory(self):
        for field in ("create_confirmed", "callbacks_finished", "process_quiescent"):
            with self.subTest(field=field):
                changed = deepcopy(self.body)
                changed[field] = False
                with self.assertRaisesRegex(verifier.EvidenceError, "terminal conditions"):
                    verifier._receipt(self.signed(changed), self.pin)

    def test_terminal_flags_reject_integer_truth_values(self):
        for field in ("create_confirmed", "callbacks_finished", "process_quiescent", "start_admitted"):
            with self.subTest(field=field):
                changed = deepcopy(self.body)
                changed[field] = int(changed[field])
                with self.assertRaises(verifier.EvidenceError):
                    verifier._receipt(self.signed(changed), self.pin)

    def test_no_business_commit_or_effect_count_claim_is_terminal_proof(self):
        for field, value in (("status", "COMMITTED"), ("business_effects", "COMMITTED"), ("effect_count", 1)):
            changed = deepcopy(self.body)
            changed[field] = value
            with self.assertRaises(verifier.EvidenceError):
                verifier._receipt(self.signed(changed), self.pin)

    def test_signature_domain_and_pin_are_bound(self):
        receipt = self.signed()
        receipt["signature"] = "0" * 128
        with self.assertRaisesRegex(verifier.EvidenceError, "signature invalid"):
            verifier._receipt(receipt, self.pin)
        receipt = self.signed()
        receipt["signature"] = self.key.sign(b"wrong-domain" + verifier.canonical(self.body)).hex()
        with self.assertRaisesRegex(verifier.EvidenceError, "signature invalid"):
            verifier._receipt(receipt, self.pin)

    def test_exact_action_and_grant_digest_are_checked(self):
        for field in ("action_digest", "authorization_digest", "plan_sha256"):
            changed = deepcopy(self.body)
            changed[field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._receipt(self.signed(changed), self.pin, self.action, self.grant)
        different = deepcopy(self.grant)
        different["expires_at"] = 1000.0
        with self.assertRaisesRegex(verifier.EvidenceError, "authorization"):
            verifier._receipt(self.signed(), self.pin, self.action, different)

    def test_start_must_have_exact_parent_and_container_and_admitted_execution(self):
        start = deepcopy(self.action)
        start["arguments"].update(stage="START", parent_reservation_id="reservation:parent", container_id="d" * 64)
        self.assertEqual(verifier._action(start), start)
        start["arguments"]["parent_reservation_id"] = None
        with self.assertRaisesRegex(verifier.EvidenceError, "parent/container"):
            verifier._action(start)
        changed = deepcopy(self.body)
        changed["stage"] = "START"
        with self.assertRaisesRegex(verifier.EvidenceError, "admitted execution"):
            verifier._receipt(self.signed(changed), self.pin)

    def test_create_has_no_start_parent_or_container(self):
        for field, value in (("parent_reservation_id", "reservation:parent"), ("container_id", "d" * 64)):
            changed = deepcopy(self.action)
            changed["arguments"][field] = value
            with self.assertRaisesRegex(verifier.EvidenceError, "CREATE"):
                verifier._action(changed)

    def test_fixture_and_plan_cannot_change_after_binding(self):
        for field, value in (("argv", ["-c", "print('other')"]), ("image_id", "python:latest"),
            ("environment_policy", "injected"), ("plan_sha256", "0" * 64), ("timeout_seconds", True)):
            changed = deepcopy(self.spec)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._spec(changed)

    def test_workspace_and_isolation_cannot_broaden(self):
        changed = deepcopy(self.spec)
        changed["host_workspace"] = "/tmp/../etc"
        with self.assertRaisesRegex(verifier.EvidenceError, "workspace"):
            verifier._spec(changed)
        for field, value in (("uid", 0), ("network_mode", "host"), ("drop_all_capabilities", False), ("memory_mb", 512)):
            changed = deepcopy(self.spec)
            changed["isolation"][field] = value
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._spec(changed)

    def test_private_credentials_and_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(verifier.EvidenceError, "private credential"):
            verifier._bounded({"private_key": "unit-packet"})
        with self.assertRaisesRegex(verifier.EvidenceError, "non-finite"):
            verifier.canonical({"timestamp": float("nan")})

    def inventory_fixture(self):
        """Synthetic schema fixture; the full-report API requires real Docker."""
        record = {"registry_id": "1" * 32, "session_id": "liminal-control-" + "2" * 32,
            "ownership_token": "3" * 32, "root_id": self.action["root_id"], "action_id": self.action["action_id"],
            "image_id": self.spec["image_id"], "plan_sha256": self.spec["plan_sha256"],
            "backend_identity_sha256": verifier.sha({"backend": "docker", "image_id": self.spec["image_id"]}),
            "receiver_id": self.pin["supervisor_id"], "broker_context_sha256": verifier.sha({"profile": verifier.PROFILE, "spec": self.spec}),
            "registered_at": 1}
        callback = {"finished_at": 2, "returned": True, "returncode": 0, "error": None,
            "stdout_sha256": verifier.sha("unit") , "stdout_bytes": 0, "stdout_hex": "",
            "stderr_sha256": "4" * 64, "stderr_bytes": 0}
        import hashlib
        callback["stdout_sha256"] = hashlib.sha256(b"").hexdigest()
        callback["stderr_sha256"] = hashlib.sha256(b"").hexdigest()
        journal = [{"action_id": self.action["action_id"], "stage": "CREATE", "phase": "FINISHED", "result": callback}]
        image_env_digest = "5" * 64
        raw = {"Id": "d" * 64, "Image": self.spec["image_id"], "Config": {"Labels": {
            "liminal.control.registry": record["registry_id"], "liminal.control.owner": record["ownership_token"],
            "liminal.control.plan": record["plan_sha256"]}, "User": "65534:65534", "Entrypoint": ["python3"],
            "Cmd": self.spec["argv"], "WorkingDir": "/workspace", "EnvDigest": image_env_digest},
            "HostConfig": {"NetworkMode": "none", "LogConfig": {"Type": "none", "Config": {}}, "ReadonlyRootfs": True,
                "Privileged": False, "PidMode": "", "IpcMode": "private", "CapDrop": ["ALL"], "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"], "PidsLimit": 64, "Memory": 256 * 1024 * 1024,
                "NanoCpus": 1_000_000_000, "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}},
            "Mounts": [{"Source": self.spec["host_workspace"], "Destination": "/workspace", "RW": False}],
            "State": {"Running": False, "Paused": False, "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0}}
        observations = [{"kind": "positive_create", "observed_at": 3, "container_id": "d" * 64,
            "value": deepcopy(raw), "callbacks_digest": None}, {"kind": "stopped_inspect", "observed_at": 4,
            "container_id": "d" * 64, "value": deepcopy(raw), "callbacks_digest": verifier.sha(journal)},
            {"kind": "removed_absence", "observed_at": 5, "container_id": "d" * 64,
             "value": {"exists": False, "lookup_id": "d" * 64}, "callbacks_digest": verifier.sha(journal)}]
        body = deepcopy(self.body)
        body.update(ownership_digest=verifier.sha(record), observation_digest=verifier.sha({"observations": observations,
            "callbacks": journal}), observed_at=6)
        proof = self.signed(body)
        pair = {"unit_fixture": "already checked generic public proof seam"}
        stage = {"action": self.action, "authorization": self.grant, "action_digest": verifier.sha(self.action),
            "authorization_digest": verifier.sha(self.grant), "reservation_id": "reservation:unit", "begin_evidence": pair,
            "callback_phase": "FINISHED", "callback_result": callback, "receipt": proof, "settlement_status": "SETTLED", "status": "QUIESCENT"}
        command = {"command_id": self.spec["command_id"], "root_id": self.action["root_id"], "execution_id": self.action["execution_id"],
            "image_id": self.spec["image_id"], "plan_sha256": self.spec["plan_sha256"], "spec": self.spec, "registry_record": record,
            "container_id": "d" * 64, "create_confirmed": True, "cleanup_complete": True, "start_observed": False,
            "observations": observations, "stages": [stage], "callbacks_finished": True, "callback_journal": journal,
            "observation_digest": body["observation_digest"], "closing": True, "image_environment_digest": image_env_digest,
            "registry_completion": {"completed_at": 5.5, "evidence": {"verified": True, "zero_survivors": True,
                "container_id": "d" * 64, "callbacks_digest": verifier.sha(journal), "observations_digest": verifier.sha(observations)}}}
        authority_pin = {"authority_id": "authority:unit", "key_id": "key:authority", "public_key": "6" * 64}
        inventory = {"profile": verifier.PROFILE, "supervisor_pin": self.pin, "authority_pin": authority_pin,
            "commands": [command], "grants": [stage], "authority_evidence": [], "unfinished_registry": [], "execution_authorized": False}
        permits = {"reservation:unit": {"pair": pair, "action": self.action, "grant": self.grant}}
        return inventory, authority_pin, permits

    def inventory_rejects(self, mutate, message=None):
        inventory, pin, permits = self.inventory_fixture()
        mutate(inventory)
        with self.assertRaises(verifier.EvidenceError) as caught:
            verifier._inventory(inventory, pin, self.pin, permits, set())
        if message:
            self.assertIn(message, str(caught.exception))

    def test_synthetic_inventory_checks_schema_only_and_returns_no_runtime_verdict(self):
        inventory, pin, permits = self.inventory_fixture()
        result = verifier._inventory(inventory, pin, self.pin, permits, set())
        self.assertEqual(list(result), ["command:unit"])
        self.assertNotIn("status", result)

    def test_inventory_no_stopped_proof_from_absence_or_timeout(self):
        self.inventory_rejects(lambda i: i["commands"][0]["observations"].pop(1), "digest mismatch")
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][1]["value"]["State"].update(Pid=42))
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][1]["value"]["State"].update(Running=True))

    def test_inventory_immutable_identity_and_ownership_are_checked(self):
        self.inventory_rejects(lambda i: i["commands"][0]["registry_record"].update(ownership_token="9" * 32), "configuration")
        self.inventory_rejects(lambda i: i["commands"][0].update(container_id="9" * 64))
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][0]["value"].update(Image="sha256:" + "9" * 64))

    def test_inventory_finished_callback_cannot_be_invented(self):
        self.inventory_rejects(lambda i: i["grants"][0].update(callback_phase="INFLIGHT"), "unfinished callback")
        self.inventory_rejects(lambda i: i["commands"][0].update(callbacks_finished=False), "falsely finished")
        self.inventory_rejects(lambda i: i["grants"][0]["callback_result"].update(stdout_sha256="0" * 64), "stdout digest")

    def test_inventory_cannot_drop_unfinished_registry_or_terminal_signature(self):
        self.inventory_rejects(lambda i: i["commands"][0].update(cleanup_complete=False), "registry proof")
        self.inventory_rejects(lambda i: i["grants"][0]["receipt"].update(signature="0" * 128), "signature")

    def test_inventory_raw_config_requires_exact_mount_and_no_injected_environment(self):
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][0]["value"]["Config"].update(EnvDigest="0" * 64))
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][0]["value"]["Mounts"][0].update(RW=True))
        self.inventory_rejects(lambda i: i["commands"][0]["observations"][0]["value"]["HostConfig"].update(Privileged=True))

    def test_stage_result_cannot_attach_other_action_or_reservation_receipt(self):
        inventory, _, permits = self.inventory_fixture()
        receipt = inventory["grants"][0]["receipt"]
        result = {"status": "QUIESCENT", "reason": "COMMAND_QUIESCENCE_SETTLED", "action_id": self.action["action_id"],
            "reservation_id": "reservation:unit", "callback_phase": "FINISHED", "process_quiescent": True,
            "receipt": receipt, "settlement_status": "SETTLED", "business_effects": "NOT_ESTABLISHED", "execution_authorized": False}
        verifier._stage_result(result, self.action, {verifier.sha(receipt): receipt}, permits)
        for field, value in (("action_id", "different:action"), ("reservation_id", "different:reservation"),
            ("callback_phase", "INFLIGHT"), ("settlement_status", "UNKNOWN"), ("execution_authorized", True)):
            changed = deepcopy(result)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._stage_result(changed, self.action, {verifier.sha(receipt): receipt}, permits)

    def test_docker_start_timestamp_must_be_valid_nonzero_rfc3339(self):
        self.assertTrue(verifier._nonzero_timestamp("2026-10-13T00:43:57.123456789Z"))
        self.assertTrue(verifier._nonzero_timestamp("2026-10-13T00:43:57+03:00"))
        for value in ("garbage", "", "0001-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-13T25:00:00Z",
            "2026-10-13T00:00:00", "2026-10-13T00:00:00.1234567890Z", "2026-10-13T00:00:00+01:99"):
            with self.subTest(value=value):
                self.assertFalse(verifier._nonzero_timestamp(value))


class ExternalAgentNetworkPacketTests(unittest.TestCase):
    """Signed packets validate bounded contracts, never claim a Docker run."""

    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pin = {"endpoint_id": "endpoint:unit", "key_id": "endpoint:key", "public_key":
            self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        self.action = {"action_id": "effect:unit", "attempt_id": "attempt:effect", "root_id": "root:effect",
            "execution_id": "execution:effect", "epoch": 1, "target": "network", "arguments": {
                "method": "POST", "url": "http://127.0.0.1:31234/v1/record", "body": {"synthetic_marker": "unit-marker"}}}
        self.grant = {"action_digest": verifier.sha(self.action), "policy_version": "a" * 64,
            "expires_at": 1000, "receiver_id": self.pin["endpoint_id"]}
        self.body = {"schema": "liminal.external-network.receipt.v1", "endpoint_id": self.pin["endpoint_id"],
            "key_id": self.pin["key_id"], "reservation_id": "reservation:effect",
            **{k: self.action[k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": verifier.sha(self.action), "authorization_digest": verifier.sha(self.grant),
            "body_digest": verifier.sha(self.action["arguments"]["body"]), "committed_at": 100,
            "status": "COMMITTED", "effect_count": 1}

    def signed(self, body=None):
        body = deepcopy(self.body if body is None else body)
        return {**body, "signature": self.key.sign(verifier.NETWORK_RECEIPT_DOMAIN + verifier.canonical(body)).hex()}

    def test_independent_network_action_and_signed_endpoint_contract(self):
        self.assertEqual(verifier._network_action(self.action), self.action)
        self.assertEqual(verifier._network_grant(self.grant, self.action, self.pin), self.grant)
        receipt = self.signed()
        self.assertEqual(verifier._network_receipt(receipt, self.pin, self.action, self.grant, "reservation:effect"), receipt)

    def test_network_scope_cannot_add_arbitrary_destinations_headers_or_fields(self):
        for field, changed in (("url", "https://example.com/v1/record"), ("url", "http://127.0.0.1:31234/other"),
                ("url", "http://user@127.0.0.1:31234/v1/record"), ("method", "GET"), ("headers", {"X": "unit"})):
            action = deepcopy(self.action)
            action["arguments"][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises(verifier.EvidenceError):
                verifier._network_action(action)

    def test_network_receipt_cannot_be_negative_unknown_or_command_quiescence(self):
        for field, changed in (("effect_count", 0), ("effect_count", True), ("status", "UNKNOWN"),
                ("schema", "liminal.external-agent.receipt.v1"), ("status", "QUIESCENT")):
            body = deepcopy(self.body)
            body[field] = changed
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._network_receipt(self.signed(body), self.pin)

    def test_network_signature_domain_and_independent_endpoint_pin_are_required(self):
        receipt = self.signed()
        receipt["signature"] = self.key.sign(verifier.RECEIPT_DOMAIN + verifier.canonical(self.body)).hex()
        with self.assertRaisesRegex(verifier.EvidenceError, "signature invalid"):
            verifier._network_receipt(receipt, self.pin)
        pin = deepcopy(self.pin)
        pin["public_key"] = "0" * 64
        with self.assertRaisesRegex(verifier.EvidenceError, "signature invalid"):
            verifier._network_receipt(self.signed(), pin)

    def test_network_receipt_exact_grant_and_body_binding_preserve_canonical_types(self):
        for field in ("action_digest", "authorization_digest", "body_digest", "reservation_id"):
            body = deepcopy(self.body)
            body[field] = "0" * 64 if field != "reservation_id" else "reservation:other"
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._network_receipt(self.signed(body), self.pin, self.action, self.grant, "reservation:effect")
        grant = deepcopy(self.grant)
        grant["expires_at"] = 1000.0
        with self.assertRaisesRegex(verifier.EvidenceError, "authorization"):
            verifier._network_receipt(self.signed(), self.pin, self.action, grant)

    def test_unknown_effect_cannot_become_zero_commit_or_permission(self):
        result = {"status": "UNKNOWN", "reason": "UNIT_MISSING_RESPONSE", "action_id": self.action["action_id"],
            "reservation_id": None, "effect_count": None, "remote_outcome": None, "receipt": None,
            "dispatch_finished": False, "settlement_status": None, "execution_authorized": False}
        log = {"permits": {}, "terminal": {}, "receiver_pin": self.pin}
        verifier._network_result(result, self.action, {self.action["action_id"]: self.grant}, log, {})
        for field, changed in (("effect_count", 0), ("remote_outcome", "COMMITTED"), ("status", "COMMITTED"),
                ("settlement_status", "SETTLED"), ("execution_authorized", True), ("action_id", "effect:other")):
            altered = deepcopy(result)
            altered[field] = changed
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                verifier._network_result(altered, self.action, {self.action["action_id"]: self.grant}, log, {})

    def test_signed_root_census_counts_initial_denials_separately_from_issued_permits(self):
        authority_key = Ed25519PrivateKey.generate()
        authority_pin = {"authority_id": "authority:unit", "key_id": "authority:key", "public_key": authority_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        state = {"root_id": "root:effect", "receiver_id": self.pin["endpoint_id"], "policy_digest": "a" * 64,
            "epoch": 2, "state": "STOPPING", "max_actions": 2, "issued_count": 1, "lifetime_seconds": 1000,
            "created_at": 1, "expires_at": 1001, "stopped_at": 2, "stop_reason": "STOP", "pending_count": 1,
            "committed_count": 0, "denied_count": 1, "clock_fault": False, "admission_closed": True, "status": "STOP_PENDING"}
        request = {"schema": "liminal-external-authority-request-v1", "role": "admin", "operation": "status",
            "nonce": "b" * 64, "payload": {"root_id": "root:effect"}}
        body = {"schema": "liminal-external-authority-response-v1", "authority_id": authority_pin["authority_id"],
            "key_id": authority_pin["key_id"], "operation": "status", "request_digest": verifier.sha(request),
            "issued_at": 3, "result": state}
        response = {**body, "signature": authority_key.sign(b"liminal-external-authority-response-v1\x00" + verifier.canonical(body)).hex()}
        verifier.verify_public_response({"request": request, "response": response}, authority_pin)
        log = {"public": [(request, state, response)], "network": True, "receiver_pin": self.pin}
        self.assertEqual(verifier._signed_state(state, log, "root:effect")["issued_count"], 1)
        changed = deepcopy(state)
        changed["issued_count"] = 2
        log["public"] = [(request, changed, {**response, "result": changed})]
        with self.assertRaisesRegex(verifier.EvidenceError, "census"):
            verifier._signed_state(changed, log, "root:effect")


class ExternalAgentTracePacketTests(unittest.TestCase):
    """A bounded trace parser fixture has no runtime report or Docker verdict."""

    def setUp(self):
        network = ExternalAgentNetworkPacketTests()
        network.setUp()
        self.action, self.grant, self.endpoint_pin = network.action, network.grant, network.pin
        self.binding = {"run_id": "run:unit", "command": {"root_id": "root:command", "execution_id": "execution:command", "epoch": 1},
            "effect": {"root_id": self.action["root_id"], "execution_id": self.action["execution_id"], "epoch": 1},
            "effect_actions": [self.action], "endpoint_pin": self.endpoint_pin}
        authority_pin = {"authority_id": "authority:effect", "key_id": "authority:key", "public_key": "7" * 64}
        self.binding["effect"]["authority_pin"] = authority_pin
        self.configuration = {"run_binding": {"run_id": "run:unit", **{k: self.binding["effect"][k] for k in ("root_id", "execution_id", "epoch")}},
            "actions": [self.action], "admission_observer_required": True,
            "owned_command_binding": deepcopy(self.binding["command"]), "owned_run_binding_digest": verifier.sha(self.binding),
            "effect_gateway_configuration": {"schema": "liminal-network-gateway-store-v1", "profile": "owned-loopback-network-v1",
                "gateway_id": "gateway:unit", "authority_url": "http://127.0.0.1:31235", "authority_pin": authority_pin,
                "authority_role": "receiver", "endpoint_url": "http://127.0.0.1:31234", "endpoint_pin": self.endpoint_pin,
                "operator_key_digest": "1" * 64, "worker_key_digest": "2" * 64,
                "authority_request_key_digest": "3" * 64, "endpoint_request_key_digest": "4" * 64}}
        self.log = {"permits": {}, "terminal": {}, "receiver_pin": self.endpoint_pin}

    def fixture(self):
        result = {"status": "UNKNOWN", "reason": "OWNED_AGENT_OBSERVATION_UNAVAILABLE", "action_id": self.action["action_id"],
            "reservation_id": None, "effect_count": None, "remote_outcome": None, "receipt": None,
            "dispatch_finished": False, "settlement_status": None, "execution_authorized": False}
        events = [("untrusted_worker", "ready", {"protocol": 1, "mode": "useful_completion"}),
            ("trusted_host", "configuration", {"run_id": "run:unit", "actions": [self.action]}),
            ("untrusted_worker", "proposal", {"proposal_id": "proposal-1", "action": self.action}),
            ("trusted_host", "owned_agent_observation_error", {"proposal_id": "proposal-1", "action_id": self.action["action_id"], "error": "OSError"}),
            ("trusted_host", "fence", {"run_id": "run:unit", "closed": True, "reason": "OWNED_AGENT_OBSERVATION_UNAVAILABLE"}),
            ("trusted_host", "host_result", {"proposal_id": "proposal-1", "action_id": self.action["action_id"], "result": result}),
            ("untrusted_worker", "claim", {"outcome": "COMMITTED", "stop_state": "STOPPED", "authority": "NONE"}),
            ("untrusted_worker", "done", {"reason": "UNIT_PARSER_COMPLETE"}),
            ("trusted_host", "cli_exit", {"reaped": True, "returncode": 0, "workload_quiescence": "NOT_ESTABLISHED"})]
        trace, raw = [], bytearray()
        for sequence, (origin, kind, value) in enumerate(events, 1):
            event = {"sequence": sequence, "prev_hash": "0" * 64 if not trace else trace[-1]["event_hash"],
                "observed_at": sequence, "origin": origin, "kind": kind, "value": deepcopy(value)}
            event["event_hash"] = verifier.sha(event)
            trace.append(event)
            if origin == "untrusted_worker":
                frame = {"schema": "liminal.agent-stdio.v1", "kind": kind}
                frame.update({"claim": value} if kind == "claim" else value)
                raw.extend(verifier.canonical(frame) + b"\n")
        import hashlib
        return {"schema": "liminal.external-agent.bridge.v1", "run_binding": self.configuration["run_binding"],
            "configuration_digest": verifier.sha(self.configuration), "trace": trace, "trace_head": trace[-1]["event_hash"],
            "bridge_status": "FINISHED", "callback_finished": True, "cli_reaped": True, "cli_returncode": 0,
            "outstanding_effect_calls": 0, "effect_calls": [], "fenced": True, "stdout_bytes": len(raw), "stderr_bytes": 0,
            "stdout_observed_bytes": len(raw), "stderr_observed_bytes": 0,
            "stdout_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_trace_bytes": len(raw), "stdout_trace_sha256": hashlib.sha256(raw).hexdigest(),
            "messages": 4, "steps": 1, "model_calls": 0, "execution_authorized": False, "sender_quiescence": "NOT_ESTABLISHED",
            "observation_calls": [{"sequence": 1, "proposal_id": "proposal-1", "action_id": self.action["action_id"],
                "started_at": 3.1, "finished_at": 3.2, "deadline_exceeded": False, "still_running": False, "cancellation_confirmed": False}],
            "outstanding_observation_calls": 0}

    def parse(self, value):
        return verifier._bridge(value, self.binding, self.configuration, {self.action["action_id"]: self.grant}, self.log, {}, fixture="useful_completion")

    def test_observer_failure_after_fence_preserves_unknown_without_dispatch(self):
        result = self.parse(self.fixture())
        self.assertFalse(result["starts"])
        self.assertEqual(result["responses"]["proposal-1"]["value"]["result"]["status"], "UNKNOWN")
        self.assertNotIn("status", result)
        self.assertEqual(result["claims"][0]["stop_state"], "STOPPED")

    def test_untrusted_false_success_is_not_an_effect_receipt(self):
        value = self.fixture()
        value["trace"][6]["origin"] = "trusted_host"
        with self.assertRaises(verifier.EvidenceError):
            self.parse(value)

    def test_trace_hashes_and_parsed_output_prefix_are_required(self):
        for field, changed in (("trace_head", "0" * 64), ("stdout_trace_sha256", "0" * 64), ("steps", 0)):
            value = self.fixture()
            value[field] = changed
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                self.parse(value)

    def test_observer_callback_timeout_never_confirms_cancellation(self):
        value = self.fixture()
        value["observation_calls"][0]["cancellation_confirmed"] = True
        with self.assertRaises(verifier.EvidenceError):
            self.parse(value)
        value = self.fixture()
        value["observation_calls"][0].update(still_running=True, finished_at=None, deadline_exceeded=True)
        value.update(outstanding_observation_calls=1, callback_finished=False)
        self.assertFalse(self.parse(value)["starts"])
        value["callback_finished"] = True
        with self.assertRaises(verifier.EvidenceError):
            self.parse(value)


@unittest.skipUnless(os.environ.get("LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE") or os.environ.get("LIMINAL_EXTERNAL_AGENT_REQUIRE_DOCKER") == "1",
    "NOT_RUN: actual isolated-agent artifact requires explicit immutable real Docker image")
class ExternalAgentDockerCaptureEvidenceTests(unittest.TestCase):
    """Every mutation starts from one mandatory, independently valid real capture."""

    @classmethod
    def setUpClass(cls):
        image = os.environ.get("LIMINAL_EXTERNAL_AGENT_DOCKER_IMAGE")
        if not image:
            raise AssertionError("required actual Docker evidence has no explicit immutable image")
        from sdk.liminal_agent_control.external_agent_demo import run_demo
        cls.report = run_demo(image=image)
        cls.verification = verifier.verify_report(cls.report, repo_root=ROOT,
            expected_source_sha=os.environ.get("EXPECTED_SOURCE_SHA"))
        assert cls.verification["status"] == "PASS", cls.verification
        destination = os.environ.get("LIMINAL_EXTERNAL_AGENT_EVIDENCE")
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(cls.report, indent=2, sort_keys=True, allow_nan=False) + "\n")

    def verify(self, report=None, **kwargs):
        return verifier.verify_report(self.report if report is None else report, repo_root=ROOT, **kwargs)

    def rejects(self, mutate):
        report = deepcopy(self.report)
        mutate(report)
        with self.assertRaises((verifier.EvidenceError, KeyError, TypeError)):
            self.verify(report)

    def test_actual_capture_has_twelve_owned_agents_and_six_endpoint_effects(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cases_verified"], list(verifier.CASE_IDS))
        self.assertEqual((result["actual_agent_containers"], result["actual_create_calls"], result["actual_attached_start_calls"]), (12, 12, 12))
        self.assertEqual((result["actual_endpoint_requests"], result["actual_endpoint_effects"]), (6, 6))
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["live_llm"], "NOT_RUN")
        self.assertEqual(result["checkpoint_verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertEqual(result["live_observation_signatures"], "NOT_ESTABLISHED")

    def test_external_pins_and_anchors_cannot_be_silently_substituted(self):
        result = self.verify(expected_command_authority_pin=self.report["command_authority_public_pin"],
            expected_effect_authority_pin=self.report["effect_authority_public_pin"], expected_supervisor_pin=self.report["supervisor_public_pin"],
            expected_endpoint_pin=self.report["endpoint_public_pin"], trusted_command_anchor=self.report["command_checkpoint_anchor"],
            trusted_effect_anchor=self.report["effect_checkpoint_anchor"])
        self.assertEqual(result["checkpoint_verification_status"], "EXTERNAL_ANCHORED_VERIFIED")
        for argument, field in (("expected_command_authority_pin", "command_authority_public_pin"),
                ("expected_effect_authority_pin", "effect_authority_public_pin"), ("expected_supervisor_pin", "supervisor_public_pin"),
                ("expected_endpoint_pin", "endpoint_public_pin")):
            pin = deepcopy(self.report[field])
            pin["public_key"] = "0" * 64
            with self.subTest(argument=argument), self.assertRaises(verifier.EvidenceError):
                self.verify(**{argument: pin})

    def test_both_public_controller_signatures_and_fresh_challenges_are_required(self):
        for field in ("command_authority_evidence", "effect_authority_evidence"):
            self.rejects(lambda r, f=field: r[f][0]["response"].update(signature="0" * 128))
            self.rejects(lambda r, f=field: r[f][0]["request"].update(nonce="0" * 64))
            self.rejects(lambda r, f=field: r[f].append(deepcopy(r[f][0])))

    def test_endpoint_signature_and_actual_independent_sqlite_rows_are_required(self):
        self.rejects(lambda r: r["endpoint_evidence"][0]["response"].update(signature="0" * 128))
        self.rejects(lambda r: r["endpoint_final_inventory"].update(independent_sqlite_effect_count=0))
        self.rejects(lambda r: r["endpoint_final_inventory"]["effects"][0]["body"].update(synthetic_marker="different"))
        self.rejects(lambda r: r["endpoint_final_inventory"]["requests"][0].update(permit_digest="0" * 64))

    def test_signed_lifecycle_receipt_cannot_use_network_or_old_command_domain(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["grants"][0]["receipt"].update(signature="0" * 128))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["grants"][0]["receipt"].update(schema="liminal.external-command.receipt.v1"))

    def test_run_binding_links_both_roots_epochs_pins_and_actual_source(self):
        for field, value in (("spec_digest", "0" * 64), ("source_digest", "0" * 64), ("run_id", "run:other")):
            self.rejects(lambda r, f=field, v=value: r["outcomes"]["useful_completion"]["run_binding"].update({f: v}))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["run_binding"]["effect"].update(root_id="runtime:agent:useful_completion"))

    def test_host_allowlist_and_grant_cannot_be_mutated_by_agent(self):
        self.rejects(lambda r: r["outcomes"]["argument_mutation"]["effect_actions"][0]["arguments"]["body"].update(synthetic_marker="altered"))
        self.rejects(lambda r: r["outcomes"]["lineage_swap"]["effect_authorization"].update(receiver_id="other:endpoint"))

    def test_raw_or_parsed_stdio_cannot_hide_or_relabel_worker_proposals(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["bridge_inventory"].update(stdout_trace_sha256="0" * 64))
        self.rejects(lambda r: r["outcomes"]["duplicate_after_commit"]["bridge_inventory"].update(steps=1))
        self.rejects(lambda r: r["outcomes"]["forged_report"]["bridge_inventory"]["trace"][0].update(origin="trusted_host"))

    def test_callback_timeout_or_cli_reap_cannot_establish_lifecycle_quiescence(self):
        self.rejects(lambda r: r["outcomes"]["pending_effect_stop"]["pending_effect_snapshot"]["aggregate"].update(status="STOPPED"))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["attach_processes"][0].update(reaped=False))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["grants"][1].update(callback_phase="INFLIGHT"))

    def test_host_observer_calls_cannot_disappear_or_be_declared_cancelled(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["bridge_inventory"]["observation_calls"].clear())
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["bridge_inventory"]["observation_calls"][0].update(cancellation_confirmed=True))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["bridge_inventory"].update(outstanding_observation_calls=1))

    def test_owned_live_observer_cannot_fake_container_configuration_or_process(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["live_observations"][0].update(container_id="0" * 64))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["live_observations"][0]["inspect"]["HostConfig"].update(NetworkMode="host"))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["live_observations"][0]["process"].update(processes=[]))

    def test_external_stop_requires_both_closed_roots_and_actual_fence(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["coordinator_snapshots"][-1]["aggregate"]["effect_state"].update(pending_count=1))
        self.rejects(lambda r: r["outcomes"]["queued_after_stop"]["coordinator_snapshots"][-1]["inventory"]["state"].update(closed_at=None))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["coordinator_snapshots"][-1]["aggregate"].update(bridge_callbacks_finished=False))

    def test_known_pending_effect_after_owned_process_stop_remains_pending(self):
        self.rejects(lambda r: r["outcomes"]["pending_effect_stop"]["pending_effect_snapshot"]["aggregate"].update(lifecycle_receipts_verified=True))
        self.rejects(lambda r: r["outcomes"]["pending_effect_stop"]["endpoint_while_pending"].update(independent_sqlite_effect_count=1))

    def test_lost_response_unknown_cannot_be_retroactively_replaced_by_success(self):
        def alter(report):
            bridge = report["outcomes"]["lost_endpoint_response"]["bridge_inventory"]
            event = next(e for e in bridge["trace"] if e["kind"] == "host_result" and e["value"]["proposal_id"] == "proposal-1")
            event["value"]["result"].update(status="COMMITTED", effect_count=1)
        self.rejects(alter)

    def test_actual_docker_configuration_excludes_host_network_socket_and_canary_mount(self):
        self.rejects(lambda r: r["outcomes"]["direct_loopback"]["independent_docker_configuration"]["HostConfig"].update(NetworkMode="host"))
        self.rejects(lambda r: r["outcomes"]["synthetic_canary"]["independent_docker_configuration"]["Mounts"].append({"Source": "/tmp/liminal-synthetic-host-canary", "Destination": "/tmp/liminal-synthetic-host-canary", "RW": False}))

    def test_actual_descendants_and_failed_graceful_term_are_not_worker_claims(self):
        self.rejects(lambda r: r["outcomes"]["ignore_stop_descendant"]["independent_docker_tree"]["process_tree"].update(stdout="PID PPID\n1 0\n"))
        self.rejects(lambda r: r["outcomes"]["ignore_stop_descendant"]["independent_docker_after_term"]["state"].update(Running=False))

    def test_missing_process_observation_remains_unknown_with_closed_pending_admission(self):
        self.rejects(lambda r: r["outcomes"]["observation_outage"]["results"]["unavailable_stop"].update(status="STOPPED"))
        self.rejects(lambda r: r["outcomes"]["observation_outage"]["results"]["unavailable_stop"].update(process_quiescent=True, process_quiescence="CONFIRMED"))

    def test_actual_create_start_and_endpoint_counts_cannot_be_declared(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"].update(create_count_delta=2))
        self.rejects(lambda r: r["outcomes"]["duplicate_after_commit"].update(request_count_delta=2))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["docker_calls"][0].update(arguments_digest="0" * 64))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["results"]["create"].update(execution_authorized=True))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["results"]["start"].update(action_id="action:other"))

    def test_host_gateway_fixed_route_cannot_be_redirected_or_authorized_by_report(self):
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["bridge_configuration"]["effect_gateway_configuration"].update(endpoint_url="https://example.com"))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"].update(execution_authorized=True))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"].update(authority_url="https://unexpected.example"))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"].update(gateway_id="other:gateway"))

    def test_process_cleanup_and_final_container_census_cover_all_actual_children(self):
        self.rejects(lambda r: r["cleanup"][0].update(reaped=False))
        self.rejects(lambda r: r["owned_container_cleanup"].pop())
        self.rejects(lambda r: r["independent_docker_final_inventory"]["objects"].pop())

    def test_source_preregistration_and_both_checkpoint_chains_are_bound(self):
        self.rejects(lambda r: r["source_files_sha256"].pop("docs/AGENT_CONTROL_ISOLATED_AGENT.md"))
        self.rejects(lambda r: r["preregistration"].update(model_calls_budget=1))
        self.rejects(lambda r: r["command_authority_checkpoints"][0].update(signature="0" * 128))
        self.rejects(lambda r: r["effect_checkpoint_anchor"].update(sequence=0))

    def test_scope_cannot_claim_live_llm_training_or_kernel_escape_protection(self):
        for field, value in (("model_calls", 1), ("model_training", True), ("live_llm", "EXECUTED"), ("kernel_escape_resistance", "PROVEN")):
            self.rejects(lambda r, f=field, v=value: r["scope"].update({f: v}))


if __name__ == "__main__":
    unittest.main()
