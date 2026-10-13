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

    def test_offline_projection_requires_canonical_empty_isolation_even_after_rehash(self):
        # Explicit public schema fixture; no runtime helper or Docker capture.
        host = {key: [] for key in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules",
            "Dns", "DnsOptions", "DnsSearch", "ExtraHosts", "Links", "GroupAdd", "CapAdd")}
        host.update({key: "" for key in ("PidMode", "UTSMode", "UsernsMode", "Cgroup", "CgroupParent",
            "VolumeDriver", "ContainerIDFile")})
        host.update({"NetworkMode": "none", "CgroupnsMode": "private", "IpcMode": "private", "Runtime": "runc",
            "Isolation": "", "PublishAllPorts": False, "PortBindings": {}, "Privileged": False, "ReadonlyRootfs": True,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m"}, "LogConfig": {"Type": "none", "Config": {}},
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": False,
            "Annotations": {}, "StorageOpt": {}, "Sysctls": {}, "Init": False})
        command = {"container_id": "d" * 64, "spec": self.spec}
        projection = {"schema": "liminal-owned-agent-docker-channels-v1", "container_id": command["container_id"],
            "HostConfig": host, "Config": {"Volumes": {}, "ExposedPorts": {}, "Healthcheck": None, "MacAddress": ""},
            "NetworkSettings": {"Ports": {}, "Networks": {}}, "Mounts": [{"Type": "bind", "Destination": "/workspace",
                "RW": False, "Propagation": "rprivate", "source_digest": verifier.sha(self.spec["host_workspace"])}],
            "execution_authorized": False}
        projection["projection_digest"] = verifier.sha(projection)
        self.assertIsNone(verifier._closed_channel_projection(projection, command))
        changed = deepcopy(projection)
        changed["HostConfig"]["Isolation"] = "default"
        changed["projection_digest"] = verifier.sha({key: value for key, value in changed.items() if key != "projection_digest"})
        self.assertEqual(changed["projection_digest"], verifier.sha({key: value for key, value in changed.items() if key != "projection_digest"}))
        with self.assertRaisesRegex(verifier.EvidenceError, "closed-channel Docker isolation invalid"):
            verifier._closed_channel_projection(changed, command)

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
            "effect_actions": [self.action], "effect_action_digests": [verifier.sha(self.action)], "endpoint_pin": self.endpoint_pin}
        authority_pin = {"authority_id": "authority:effect", "key_id": "authority:key", "public_key": "7" * 64}
        self.binding["effect"]["authority_pin"] = authority_pin
        self.configuration = {"run_binding": {"run_id": "run:unit", **{k: self.binding["effect"][k] for k in ("root_id", "execution_id", "epoch")}},
            "actions": [self.action], "admission_observer_required": True,
            "owned_command_binding": deepcopy(self.binding["command"]), "owned_run_binding_digest": verifier.sha(self.binding),
            "effect_gateway_configuration": {"schema": "liminal-closed-channel-effect-gateway-store-v1", "profile": "owned-loopback-network-v1",
                "gateway_id": "gateway:unit", "authority_url": "http://127.0.0.1:31235", "authority_pin": authority_pin,
                "authority_role": "receiver", "endpoint_url": "http://127.0.0.1:31234", "endpoint_pin": self.endpoint_pin,
                "operator_key_digest": "1" * 64, "worker_key_digest": "2" * 64,
                "authority_request_key_digest": "3" * 64, "endpoint_request_key_digest": "4" * 64}}
        self.configuration["effect_gateway_configuration"]["dispatch_gate"] = {
            "schema": "liminal-agent-effect-dispatch-contract-v1", "stage": "BEFORE_ENDPOINT_POST",
            "run_binding_digest": verifier.sha(self.binding), "effect_action_digests": self.binding["effect_action_digests"],
            "gate_required": True, "failure_outcome": "UNKNOWN_PENDING", "execution_authorized": False}
        descriptor = self.configuration["effect_gateway_configuration"]["dispatch_gate"]
        descriptor["contract_digest"] = verifier.sha(descriptor)
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


class ExternalAgentDispatchBoundaryPacketTests(unittest.TestCase):
    """Independent signed seams check the guard's packet binding, not Docker."""

    def setUp(self):
        network = ExternalAgentNetworkPacketTests()
        network.setUp()
        self.action, self.grant, self.endpoint_pin = network.action, network.grant, network.pin
        self.binding = {"run_id": "run:unit", "effect_actions": [self.action],
            "effect_action_digests": [verifier.sha(self.action)]}
        descriptor = {"schema": "liminal-agent-effect-dispatch-contract-v1", "stage": "BEFORE_ENDPOINT_POST",
            "run_binding_digest": verifier.sha(self.binding), "effect_action_digests": self.binding["effect_action_digests"],
            "gate_required": True, "failure_outcome": "UNKNOWN_PENDING", "execution_authorized": False}
        descriptor["contract_digest"] = verifier.sha(descriptor)
        self.configuration = {"schema": "liminal-closed-channel-effect-gateway-store-v1",
            "profile": "owned-loopback-network-v1", "dispatch_gate": descriptor}
        authority_key = Ed25519PrivateKey.generate()
        authority_pin = {"authority_id": "authority:unit", "key_id": "authority:key", "public_key": authority_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        request = {"schema": "liminal-external-authority-request-v1", "role": "receiver", "operation": "begin",
            "nonce": "b" * 64, "payload": {"action": self.action, "authorization": self.grant}}
        result = {"status": "PERMITTED", "outcome": None, "receipt": None,
            "action_digest": verifier.sha(self.action), "receiver_id": self.endpoint_pin["endpoint_id"],
            "reservation_id": "reservation:effect", **{key: self.action[key] for key in
                ("action_id", "attempt_id", "root_id", "execution_id", "epoch")}}
        body = {"schema": "liminal-external-authority-response-v1", "authority_id": authority_pin["authority_id"],
            "key_id": authority_pin["key_id"], "operation": "begin", "request_digest": verifier.sha(request),
            "issued_at": 90, "result": result}
        pair = {"request": request, "response": {**body, "signature": authority_key.sign(
            b"liminal-external-authority-response-v1\x00" + verifier.canonical(body)).hex()}}
        # Establish both generic signed seams before checking unsigned host
        # diagnostics. The guard checker never authenticates an observer.
        verifier._network_permit(pair, authority_pin, self.endpoint_pin)
        receipt = network.signed()
        verifier._network_receipt(receipt, self.endpoint_pin, self.action, self.grant, "reservation:effect")
        self.log = {"permits": {"reservation:effect": {"pair": pair, "action": self.action, "grant": self.grant}}}
        self.gateway = {"authority_evidence": [pair]}
        self.before = {"requests": [], "receipts": []}
        self.after = {"requests": [{"action_id": self.action["action_id"], "permit_request": request,
            "permit": pair["response"], "permit_digest": verifier.sha(pair["response"])}], "receipts": [receipt]}
        self.boundary = {"schema": "liminal-agent-effect-dispatch-boundary-v1",
            "contract_digest": descriptor["contract_digest"], "execution_authorized": False,
            "events": [{"schema": "liminal-agent-effect-dispatch-observation-v1", "stage": "BEFORE_ENDPOINT_POST",
                "action_digest": verifier.sha(self.action), "reservation_id": "reservation:effect",
                "permit_request_digest": verifier.sha(request), "permit_response_digest": verifier.sha(pair["response"]),
                "observed_at": 95, "result": "READY", "reason": None, "execution_authorized": False}]}

    def verify(self, boundary=None, configuration=None, gateway=None, before=None, after=None):
        return verifier._effect_dispatch_boundary(self.boundary if boundary is None else boundary,
            binding=self.binding, configuration=self.configuration if configuration is None else configuration,
            gateway=self.gateway if gateway is None else gateway, log=self.log,
            before=self.before if before is None else before, after=self.after if after is None else after)

    def test_unsigned_ready_diagnostic_binds_signed_begin_and_recovered_receipt_without_commit_response(self):
        self.assertEqual(self.verify(), 1)
        self.assertNotIn("endpoint_evidence", self.gateway)

    def test_no_post_case_requires_empty_guard_census(self):
        boundary = deepcopy(self.boundary)
        boundary["events"] = []
        self.assertEqual(self.verify(boundary=boundary, gateway={"authority_evidence": []},
            after={"requests": [], "receipts": []}), 0)

    def test_missing_duplicate_extra_or_blocked_post_guard_is_rejected(self):
        changes = (lambda b: b["events"].clear(), lambda b: b["events"].append(deepcopy(b["events"][0])),
            lambda b: b["events"][0].update(reservation_id="reservation:other"),
            lambda b: b["events"][0].update(result="BLOCKED", reason="AGENT_LAUNCH_FENCED"),
            lambda b: b.update(execution_authorized=True), lambda b: b["events"][0].update(execution_authorized=True),
            lambda b: b["events"][0].update(stage="ENDPOINT_FINAL_COMMIT"))
        for change in changes:
            altered = deepcopy(self.boundary)
            change(altered)
            with self.subTest(change=change), self.assertRaises(verifier.EvidenceError):
                self.verify(boundary=altered)

    def test_retiming_guard_outside_signed_begin_to_receipt_window_is_rejected(self):
        for time in (89, 101, float("nan"), True):
            altered = deepcopy(self.boundary)
            altered["events"][0]["observed_at"] = time
            with self.subTest(time=time), self.assertRaises(verifier.EvidenceError):
                self.verify(boundary=altered)

    def test_exact_action_and_both_permit_digests_are_required(self):
        for field in ("action_digest", "permit_request_digest", "permit_response_digest"):
            altered = deepcopy(self.boundary)
            altered["events"][0][field] = "0" * 64
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                self.verify(boundary=altered)
        with self.assertRaises(verifier.EvidenceError):
            self.verify(gateway={"authority_evidence": []})

    def test_rehashed_descriptor_cannot_disable_guard_change_lineage_or_downgrade_store(self):
        for field, value in (("gate_required", False), ("failure_outcome", "CANCELLED"),
                ("run_binding_digest", "0" * 64), ("effect_action_digests", []), ("stage", "BEFORE_BEGIN")):
            configuration = deepcopy(self.configuration)
            configuration["dispatch_gate"][field] = value
            descriptor = configuration["dispatch_gate"]
            descriptor["contract_digest"] = verifier.sha({key: item for key, item in descriptor.items() if key != "contract_digest"})
            boundary = deepcopy(self.boundary)
            boundary["contract_digest"] = descriptor["contract_digest"]
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                self.verify(boundary=boundary, configuration=configuration)
        for field, value in (("schema", "liminal-network-gateway-store-v1"), ("profile", "arbitrary-network")):
            configuration = deepcopy(self.configuration)
            configuration[field] = value
            with self.subTest(field=field), self.assertRaises(verifier.EvidenceError):
                self.verify(configuration=configuration)

    def test_actual_post_census_and_begin_status_cannot_be_removed_or_swapped(self):
        with self.assertRaises(verifier.EvidenceError):
            self.verify(after={"requests": [], "receipts": self.after["receipts"]})
        after = deepcopy(self.after)
        after["requests"][0]["permit"]["result"]["status"] = "CONSUMED"
        after["requests"][0]["permit_digest"] = verifier.sha(after["requests"][0]["permit"])
        with self.assertRaises(verifier.EvidenceError):
            self.verify(after=after)


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

    @staticmethod
    def alter_dispatch_boundary(report, mutate):
        after = report["outcomes"]["useful_completion"]["supervisor_after"]
        mutate(after["gateway"]["dispatch_boundary"])
        report["outcomes"]["useful_completion"]["gateway_inventory"] = deepcopy(after["gateway"])
        report["supervisor_final_inventory"]["case_inventories"]["useful_completion"] = deepcopy(after)

    def test_actual_capture_has_one_post_begin_guard_per_actual_post_with_bounded_scope(self):
        result = self.verify()
        self.assertEqual(result["post_begin_dispatch_guards_verified"], 6)
        self.assertEqual(result["effect_dispatch_observation_signatures"], "NOT_ESTABLISHED")
        self.assertEqual(result["endpoint_final_commit_guard"], "NOT_ESTABLISHED")
        for name in verifier.CASE_IDS:
            case = self.report["outcomes"][name]
            gateway = case["gateway_inventory"]
            descriptor = case["bridge_configuration"]["effect_gateway_configuration"]["dispatch_gate"]
            self.assertEqual(gateway["dispatch_boundary"]["contract_digest"], descriptor["contract_digest"])
            self.assertEqual(len(gateway["dispatch_boundary"]["events"]), case["request_count_delta"])
            self.assertTrue(all(event["result"] == "READY" for event in gateway["dispatch_boundary"]["events"]))
        self.assertEqual(self.report["outcomes"]["pending_effect_stop"]["effect_count_delta"], 1)

    def test_missing_extra_or_blocked_dispatch_event_cannot_cover_an_actual_post(self):
        changes = (lambda b: b["events"].clear(), lambda b: b["events"].append(deepcopy(b["events"][0])),
            lambda b: b["events"][0].update(result="BLOCKED", reason="AGENT_LAUNCH_FENCED"),
            lambda b: b["events"][0].update(reservation_id="reservation:other"),
            lambda b: b["events"][0].update(stage="ENDPOINT_FINAL_COMMIT"),
            lambda b: b.update(contract_digest="0" * 64), lambda b: b["events"][0].update(execution_authorized=True))
        for change in changes:
            self.rejects(lambda r, mutation=change: self.alter_dispatch_boundary(r, mutation))
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"].pop("dispatch_boundary"))

    def test_dispatch_action_request_and_response_digests_are_bound_to_actual_permitted_begin(self):
        for field in ("action_digest", "permit_request_digest", "permit_response_digest"):
            self.rejects(lambda r, key=field: self.alter_dispatch_boundary(r,
                lambda b: b["events"][0].update({key: "0" * 64})))

    def test_retimed_dispatch_diagnostic_cannot_precede_begin_or_follow_committed_receipt(self):
        case = self.report["outcomes"]["useful_completion"]
        request = case["endpoint_after"]["requests"][len(case["endpoint_before"]["requests"])]
        reservation = request["permit"]["result"]["reservation_id"]
        receipt = next(r for r in case["endpoint_after"]["receipts"] if r["reservation_id"] == reservation)
        for time in (request["permit"]["issued_at"] - 1, receipt["committed_at"] + 1):
            self.rejects(lambda r, value=time: self.alter_dispatch_boundary(r,
                lambda b: b["events"][0].update(observed_at=value)))

    def test_rehashed_dispatch_descriptor_cannot_downgrade_profile_or_remove_guard(self):
        def alter(report, field, value):
            case = report["outcomes"]["useful_completion"]
            after = case["supervisor_after"]
            configuration = after["bridge_configuration"]
            route = configuration["effect_gateway_configuration"]
            if field in {"schema", "profile"}:
                route[field] = value
            else:
                descriptor = route["dispatch_gate"]
                descriptor[field] = value
                descriptor["contract_digest"] = verifier.sha({key: item for key, item in descriptor.items() if key != "contract_digest"})
                after["gateway"]["dispatch_boundary"]["contract_digest"] = descriptor["contract_digest"]
            after["bridge"]["configuration_digest"] = verifier.sha(configuration)
            case["bridge_configuration"] = deepcopy(configuration)
            case["bridge_inventory"] = deepcopy(after["bridge"])
            case["gateway_inventory"] = deepcopy(after["gateway"])
            report["supervisor_final_inventory"]["case_inventories"]["useful_completion"] = deepcopy(after)
        for field, value in (("schema", "liminal-network-gateway-store-v1"), ("profile", "arbitrary-network"),
                ("gate_required", False), ("run_binding_digest", "0" * 64), ("effect_action_digests", []),
                ("failure_outcome", "CANCELLED")):
            self.rejects(lambda r, key=field, changed=value: alter(r, key, changed))

    def test_post_begin_dispatch_gateway_sources_tests_and_guide_are_required(self):
        for name in ("sdk/liminal_agent_control/external_agent_effect_gateway.py",
                     "tests/test_agent_control_external_agent_effect_gateway.py", "docs/AGENT_CONTROL_EFFECT_DISPATCH_GATE.md"):
            self.rejects(lambda r, path=name: r["source_files_sha256"].pop(path))

    @staticmethod
    def alter_closed_boundary(report, mutate):
        """Rehash and synchronize unsigned captures so semantics are tested."""
        after = report["outcomes"]["useful_completion"]["supervisor_after"]
        boundary = after["launch_boundary"]
        mutate(boundary)
        contract = boundary.get("contract")
        if type(contract) is dict:
            contract["contract_digest"] = verifier.sha({key: value for key, value in contract.items() if key != "contract_digest"})
            boundary["contract_digest"] = contract["contract_digest"]
        for observation in boundary.get("channel_observations", []):
            projection = observation.get("projection")
            if type(projection) is dict:
                projection["projection_digest"] = verifier.sha({key: value for key, value in projection.items() if key != "projection_digest"})
        report["supervisor_final_inventory"]["case_inventories"]["useful_completion"] = deepcopy(after)

    def test_current_capture_requires_closed_contract_and_two_start_observations(self):
        result = self.verify()
        self.assertEqual(result["closed_channel_contracts_verified"], 12)
        self.assertGreaterEqual(result["closed_channel_observations_verified"], 24)
        self.assertEqual(result["channel_observation_signatures"], "NOT_ESTABLISHED")
        for name in verifier.CASE_IDS:
            boundary = self.report["outcomes"][name]["supervisor_after"]["launch_boundary"]
            self.assertEqual(len(boundary["contract"]["channels"]), 14)
            kinds = [item["boundary"] for item in boundary["channel_observations"]]
            self.assertEqual(kinds.count("BEFORE_BEGIN_START"), 1)
            self.assertEqual(kinds.count("BEFORE_DOCKER_START"), 1)
        self.rejects(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"].pop("launch_boundary"))

    def test_rehashed_closed_inventory_cannot_omit_add_or_unmediate_a_channel(self):
        changes = (lambda b: b["contract"]["channels"].pop("worker_network"),
            lambda b: b["contract"]["channels"].update(provider_api={"mode": "MEDIATED"}),
            lambda b: b["contract"]["channels"]["worker_stdio_proposals"].update(gate=None),
            lambda b: b["contract"]["channels"]["host_command_lifecycle"].update(watchdog=None))
        for change in changes:
            self.rejects(lambda r, mutation=change: self.alter_closed_boundary(r, mutation))

    def test_rehashed_closed_contract_binds_actual_service_urls_pins_and_source(self):
        changes = (lambda b: b["contract"].update(source_digest="0" * 64),
            lambda b: b["contract"].update(run_binding_digest="0" * 64),
            lambda b: b["contract"]["channels"]["host_endpoint_effect"].update(endpoint_url="http://127.0.0.1:12345"),
            lambda b: b["contract"]["channels"]["host_command_lifecycle"]["authority_pin"].update(key_id="changed-key"),
            lambda b: b["contract"]["channels"]["host_authority_control"].update(command_url="http://127.0.0.1:12345"))
        for change in changes:
            self.rejects(lambda r, mutation=change: self.alter_closed_boundary(r, mutation))
        self.rejects(lambda r: next(p for p in r["processes"] if p["role"] == "command_external_authority")["startup"].update(url="http://127.0.0.1:12345"))

    def test_rehashed_channel_projection_cannot_hide_devices_namespace_or_published_ports(self):
        for key, value in (("Devices", [{"PathOnHost": "/dev/kvm"}]), ("DeviceRequests", [{"Count": -1}]),
            ("VolumesFrom", ["other:rw"]), ("IpcMode", "host"), ("CgroupnsMode", "host"),
            ("PortBindings", {"80/tcp": []}), ("ExtraHosts", ["host.docker.internal:host-gateway"]),
            ("Runtime", "nvidia"), ("SecurityOpt", ["no-new-privileges:true", "seccomp:unconfined"])):
            def mutate(boundary, field=key, replacement=value):
                boundary["channel_observations"][0]["projection"]["HostConfig"][field] = replacement
            self.rejects(lambda r, mutation=mutate: self.alter_closed_boundary(r, mutation))
        self.rejects(lambda r: self.alter_closed_boundary(r,
            lambda b: b["channel_observations"][0]["projection"]["HostConfig"].pop("DeviceRequests")))

    def test_rehashed_channel_mount_and_container_identity_are_bound(self):
        changes = (lambda b: b["channel_observations"][0].update(container_id="0" * 64),
            lambda b: b["channel_observations"][0]["projection"].update(container_id="0" * 64),
            lambda b: b["channel_observations"][0]["projection"]["Mounts"][0].update(source_digest="0" * 64),
            lambda b: b["channel_observations"][0]["projection"]["Mounts"][0].update(RW=True),
            lambda b: b["channel_observations"][0]["projection"]["Mounts"][0].update(Propagation="rshared"),
            lambda b: b["channel_observations"][0]["projection"]["Mounts"].append({"Type": "bind", "Destination": "/run"}))
        for change in changes:
            self.rejects(lambda r, mutation=change: self.alter_closed_boundary(r, mutation))

    def test_channel_observation_count_boundaries_and_lifecycle_times_are_checked(self):
        changes = (lambda b: b["channel_observations"].pop(),
            lambda b: b["channel_observations"].append(deepcopy(b["channel_observations"][-1])),
            lambda b: b["channel_observations"][0].update(boundary="WORKER_CLAIM"),
            lambda b: b["channel_observations"][0].update(source="untrusted_worker"),
            lambda b: b["channel_observations"][0].update(observed_at=0),
            lambda b: b["channel_observations"][1].update(observed_at=1e12))
        for change in changes:
            self.rejects(lambda r, mutation=change: self.alter_closed_boundary(r, mutation))

    def test_namespace_contract_does_not_invent_user_namespace_isolation_or_change_create_flags(self):
        self.rejects(lambda r: self.alter_closed_boundary(r,
            lambda b: b["contract"]["channels"]["worker_host_namespaces"].update(user_namespace_isolation="ESTABLISHED")))
        self.rejects(lambda r: self.alter_closed_boundary(r,
            lambda b: b["contract"]["channels"]["worker_host_namespaces"]["create_flags"].clear()))

    def test_closed_channel_runtime_sources_and_guide_are_required(self):
        for name in ("sdk/liminal_agent_control/external_agent_launch.py", "sdk/liminal_agent_control/external_agent_channels.py",
                     "docs/AGENT_CONTROL_CLOSED_CHANNEL_LAUNCH.md"):
            self.rejects(lambda r, path=name: r["source_files_sha256"].pop(path))


if __name__ == "__main__":
    unittest.main()
