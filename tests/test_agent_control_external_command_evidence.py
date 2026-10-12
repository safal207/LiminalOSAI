"""Independent command packet checks; actual Docker capture tamper tests follow.

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
SPEC = importlib.util.spec_from_file_location("independent_command_checker", ROOT / "scripts/verify_external_command_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ExternalCommandPacketEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pin = {"supervisor_id": "supervisor:unit", "key_id": "key:unit", "public_key": self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        self.spec = {"schema": "liminal-owned-docker-command-spec-v1", "command_id": "command:unit",
            "image_id": "sha256:" + "a" * 64, "host_workspace": "/tmp/command-unit", "fixture": "positive",
            "argv": ["-I", "-u", "/workspace/external_command_fixture.py", "positive"], "timeout_seconds": 30,
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
        self.body = {"schema": "liminal.external-command.receipt.v1", "supervisor_id": self.pin["supervisor_id"],
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


@unittest.skipUnless(os.environ.get("LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE"),
    "real Docker command evidence requires an explicitly pinned immutable image")
class ExternalCommandDockerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sdk.liminal_agent_control.external_command_demo import run_demo
        cls.report = run_demo(image=os.environ["LIMINAL_EXTERNAL_COMMAND_DOCKER_IMAGE"])

    def verify(self, report=None, **kwargs):
        return verifier.verify_report(self.report if report is None else report, repo_root=ROOT, **kwargs)

    def reject(self, mutate):
        report = deepcopy(self.report)
        mutate(report)
        with self.assertRaises(verifier.EvidenceError):
            self.verify(report)

    def positive_command(self, report):
        return next(c for c in report["supervisor_final_inventory"]["commands"]
            if c["command_id"] == report["outcomes"]["command_positive"]["actions"]["create"]["arguments"]["spec"]["command_id"])

    def test_actual_docker_capture_passes_with_bounded_non_authorizing_scope(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cases_verified"], list(verifier.CASE_IDS))
        self.assertEqual(result["owned_workloads_verified"], 8)
        self.assertEqual(result["one_shot_stage_permits_verified"], 14)
        self.assertEqual(result["supervisor_receipts_verified"], 14)
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["business_effects"], "NOT_ESTABLISHED")
        self.assertEqual(result["checkpoint_verification_status"], "LOCAL_SIGNATURE_ONLY")

    def test_caller_supplied_pins_and_anchor_have_explicit_scope(self):
        result = self.verify(expected_authority_pin=self.report["authority_public_pin"],
            expected_supervisor_pin=self.report["supervisor_public_pin"], trusted_latest_anchor=self.report["checkpoint_anchor"])
        self.assertEqual(result["authority_pin_scope"], "caller_supplied")
        self.assertEqual(result["supervisor_pin_scope"], "caller_supplied")
        self.assertEqual(result["checkpoint_verification_status"], "EXTERNAL_ANCHORED_VERIFIED")
        pin = deepcopy(self.report["supervisor_public_pin"])
        pin["public_key"] = "0" * 64
        with self.assertRaises(verifier.EvidenceError):
            self.verify(expected_supervisor_pin=pin)

    def test_authority_signature_challenge_and_duplicate_rejected(self):
        self.reject(lambda r: r["authority_evidence"][0]["response"].update(signature="0" * 128))
        self.reject(lambda r: r["authority_evidence"][0]["request"].update(nonce="0" * 64))
        self.reject(lambda r: r["authority_evidence"].append(deepcopy(r["authority_evidence"][0])))

    def test_supervisor_signature_and_cross_profile_receipt_rejected(self):
        self.reject(lambda r: self.positive_command(r)["stages"][0]["receipt"].update(signature="0" * 128))
        self.reject(lambda r: self.positive_command(r)["stages"][0]["receipt"].update(schema="liminal.external-network.receipt.v1"))

    def test_create_confirmation_stopped_pid_and_postremove_absence_are_required(self):
        self.reject(lambda r: self.positive_command(r).update(create_confirmed=False))
        self.reject(lambda r: next(o for o in self.positive_command(r)["observations"] if o["kind"] == "stopped_inspect")["value"]["State"].update(Pid=1))
        self.reject(lambda r: self.positive_command(r)["observations"].pop())

    def test_finished_callback_cannot_be_replaced_by_deadline_or_daemon_return(self):
        self.reject(lambda r: self.positive_command(r).update(callbacks_finished=False))
        self.reject(lambda r: self.positive_command(r)["stages"][0].update(callback_phase="INFLIGHT"))
        self.reject(lambda r: r["outcomes"]["command_pending_launch_stop"]["results"]["held_cleanup"].update(process_quiescent=True))

    def test_nested_cleanup_stage_action_reservation_and_authority_are_exact(self):
        self.reject(lambda r: r["outcomes"]["command_positive"]["results"]["cleanup"]["stages"][0].update(action_id="different:stage"))
        self.reject(lambda r: r["outcomes"]["command_positive"]["results"]["cleanup"]["stages"][0].update(execution_authorized=True))
        self.reject(lambda r: r["outcomes"]["command_positive"]["results"]["cleanup"]["stages"][0].update(reservation_id="different:reservation"))

    def test_top_level_result_cannot_swap_create_and_start_receipts(self):
        def mutate(r):
            stages = r["outcomes"]["command_lost_launch_response"]["results"]["cleanup"]["stages"]
            r["outcomes"]["command_lost_launch_response"]["results"]["retry"]["receipt"] = deepcopy(stages[1]["receipt"])
        self.reject(mutate)

    def test_real_create_start_journal_and_counts_cannot_change(self):
        self.reject(lambda r: r["supervisor_final_inventory"]["docker_calls"][0].update(arguments_digest="0" * 64))
        self.reject(lambda r: r["outcomes"]["command_positive"].update(create_count_delta=True))
        self.reject(lambda r: r["outcomes"]["command_positive"]["supervisor_after"]["docker_calls"].pop())

    def test_actual_stdout_and_image_environment_are_bound(self):
        self.reject(lambda r: r["outcomes"]["command_positive"].update(positive_stdout="invented"))
        self.reject(lambda r: self.positive_command(r).update(image_environment_digest="0" * 64))

    def test_unknown_loss_and_observation_cannot_be_relabelled_success(self):
        self.reject(lambda r: r["outcomes"]["command_lost_launch_response"]["results"]["execute_create"].update(status="QUIESCENT"))
        self.reject(lambda r: r["outcomes"]["command_observation_unavailable"]["results"]["unavailable_cleanup"].update(status="QUIESCENT"))

    def test_stopped_or_empty_registry_cannot_replace_actual_registry_completion(self):
        self.reject(lambda r: self.positive_command(r).update(registry_completion=None))
        self.reject(lambda r: self.positive_command(r)["registry_completion"]["evidence"].update(observations_digest="0" * 64))

    def test_rollback_is_only_actual_stopped_dispatcher_cache(self):
        self.reject(lambda r: r["outcomes"]["command_restore_local_state"]["restore"].update(dispatcher_stopped_during_restore=False))
        self.reject(lambda r: r["outcomes"]["command_restore_local_state"]["restore"].update(supervisor_database_not_restored=False))
        self.reject(lambda r: r["outcomes"]["command_restore_local_state"]["restore"]["cache_after"]["rows"].append({"invented": True}))

    def test_independent_parent_observations_cover_all_created_ids(self):
        self.reject(lambda r: r["independent_docker_final_inventory"]["objects"].pop())
        self.reject(lambda r: r["independent_docker_final_inventory"]["objects"][0].update(available=False, exists=None))

    def test_descendant_lineage_and_unrelated_survivor_are_required(self):
        self.reject(lambda r: r["outcomes"]["command_descendant_cleanup"]["process_tree"]["processes"].pop())
        self.reject(lambda r: r["outcomes"]["command_descendant_cleanup"]["unrelated_sentinel_after"].update(running=False))

    def test_source_inventory_clean_expected_revision_and_preregistration_checked(self):
        self.reject(lambda r: r["source_files_sha256"].pop("scripts/verify_external_command_evidence.py"))
        self.reject(lambda r: r["source_files_sha256"].update({"../escape": "0" * 64}))
        self.reject(lambda r: r["preregistration"].update(max_actions_per_root=100))
        with self.assertRaises(verifier.EvidenceError):
            self.verify(expected_source_sha="0" * 40)

    def test_case_action_grant_and_query_metadata_bind_exact_recorded_stage(self):
        self.reject(lambda r: r["outcomes"]["command_positive"]["authorizations"]["create"].update(expires_at=1.0))
        self.reject(lambda r: r["outcomes"]["command_positive"]["authorizations"]["create"].update(policy_version="0" * 64))
        self.reject(lambda r: r["outcomes"]["command_positive"]["external_queries"].update(create=deepcopy(
            r["outcomes"]["command_positive"]["external_queries"]["start"])))

    def test_checkpoint_tip_signature_and_process_reap_checked(self):
        self.reject(lambda r: r["authority_checkpoints"].pop())
        self.reject(lambda r: r["authority_checkpoints"][0].update(signature="0" * 128))
        self.reject(lambda r: r["cleanup"][0].update(reaped=False))

    def test_scope_cannot_claim_model_training_business_effects_or_fake_docker(self):
        self.reject(lambda r: r["scope"].update(actual_docker=False))
        self.reject(lambda r: r["scope"].update(business_effects="COMMITTED"))
        self.reject(lambda r: r["scope"].update(live_training="PASS"))

