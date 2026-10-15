"""Docker argv and protocol unit tests; real isolation is exercised by CI demo."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.observer_auth import sign_attestation
from sdk.liminal_agent_control import observer_container as module
from tests.test_agent_control_observer_process import fixtures


class ObserverContainerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name).resolve() / "reality"
        self.source.mkdir()
        self.image = "sha256:" + "a" * 64
        self.request, self.evidence = fixtures()

    def observer(self, **overrides):
        arguments = {"image_id": self.image, "observer_id": "reality-observer", "role": "reality",
                     "key_id": "reality-key", "source_directory": self.source}
        arguments.update(overrides)
        with patch.object(module.shutil, "which", return_value=sys.executable):
            return module.DockerObserver(**arguments)

    def packet(self):
        payload = copy.deepcopy(self.evidence)
        payload.update(receiver_records=[], receiver_snapshot_verified_by_host=True,
            receiver_snapshot={"schema": "liminal.agent-control.snapshot.v1", "root_id": "root",
                "execution_id": "agent", "epoch": 1, "complete": True, "receipts": [],
                "accepted_action_ids": [], "receiver_id": "owned-receiver", "cutoff": 0,
                "signature": digest("unit snapshot signature"), "key_id": "receiver-hmac-v1",
                "enforcement_profile": "governed_v1", "observed_at": 100})
        return {"source_id": "owned-reality", "role": "reality", "request_digest": digest(self.request),
                "observed_at": 100, "payload": payload}

    def enrollment(self, private_key=b"x" * 32):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return {"observer_id": "reality-observer", "role": "reality", "key_id": "reality-key",
                "public_key": Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw().hex()}

    def fake_service(self, extra_code="", response=None):
        enrollment = self.enrollment()
        if response is None:
            envelope = sign_attestation(self.request, private_key=b"x" * 32, verdict="SUPPORT",
                evidence_digest=digest(self.packet()), observed_at=100, valid_until=110)
            response = {"envelope": envelope, "status": "PASS", "reason": None, "execution_authorized": False}
        code = ("import sys,json\nprint(" + repr(json.dumps(enrollment)) + ",flush=True)\n"
                "for line in sys.stdin:\n" + extra_code
                + " print(" + repr(json.dumps(response)) + ",flush=True)\n")
        process = subprocess.Popen([sys.executable, "-u", "-I", "-c", code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.addCleanup(lambda: module._kill_and_reap(process))
        return process

    def start_fake(self, observer, process):
        with patch.object(observer, "_command", return_value=(0, ("b" * 64).encode(), None)), \
                patch.object(observer, "_spawn", return_value=process):
            return observer.start()

    def test_fixed_create_command_has_minimal_hardened_mounts_and_no_key(self):
        observer = self.observer()
        command = observer.create_command()
        for flag in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--user=65532:65532", "--pids-limit=16",
                     "--memory=128m", "--memory-swap=128m", "--cpus=0.25"):
            self.assertIn(flag, command)
        mounts = [item for item in command if item.startswith("--mount=")]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(all(item.endswith(",readonly") for item in mounts))
        self.assertIn(",dst=/sdk,readonly", mounts[0])
        self.assertIn(",dst=/evidence,readonly", mounts[1])
        self.assertNotIn("docker.sock", repr(command))
        self.assertNotIn("authority.sqlite", repr(command))
        self.assertNotIn("private_key", repr(command))
        self.assertIn("--entrypoint=/usr/local/bin/python", command)
        self.assertIn("-I", command)
        self.assertEqual(command[command.index("--entrypoint=/usr/local/bin/python") + 1], self.image)
        tmpfs = next(item for item in command if item.startswith("--tmpfs="))
        for setting in ("noexec", "nosuid", "nodev", "size=16m", "uid=65532", "gid=65532", "mode=700"):
            self.assertIn(setting, tmpfs)

    def test_container_names_are_unique_and_host_generated(self):
        first, second = self.observer(), self.observer()
        self.assertNotEqual(first.container_name, second.container_name)
        self.assertRegex(first.container_name, r"^liminal-observer-[0-9a-f]{32}$")

    def test_mutable_image_tags_roles_and_unbounded_time_are_rejected(self):
        for image in ("python:latest", "sha256:" + "A" * 64, self.image + ";command"):
            with self.assertRaises(ControlError):
                self.observer(image_id=image)
        for timeout in (0, -1, 31, True, float("inf"), float("nan")):
            with self.assertRaises(ControlError):
                self.observer(timeout_seconds=timeout)
        with self.assertRaises(ControlError):
            self.observer(role="agent")
        with patch.object(module.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ControlError, "DOCKER_UNAVAILABLE"):
                module.DockerObserver(image_id=self.image, observer_id="o", role="reality", key_id="k", source_directory=self.source)

    def test_source_root_components_links_files_and_sdk_overlap_are_rejected(self):
        linked_root = self.source.parent / "link"
        linked_root.symlink_to(self.source, target_is_directory=True)
        for directory in (linked_root, self.source.parent / "link" / ".." / "reality", Path("relative")):
            with self.assertRaises((ControlError, FileNotFoundError)):
                self.observer(source_directory=directory)
        target = self.source.parent / "secret"
        target.write_text("fixture")
        link = self.source / "linked.json"
        link.symlink_to(target)
        with self.assertRaises(ControlError):
            self.observer()
        link.unlink()
        sdk = Path(module.__file__).resolve().parents[1]
        for directory in (sdk, sdk.parent):
            with self.assertRaises(ControlError):
                self.observer(source_directory=directory)

    def test_complete_ring_rejects_reused_ancestor_and_nested_sources(self):
        continuity = self.source.parent / "continuity"
        continuity.mkdir()
        self.assertEqual(module.validate_source_directories([self.source, continuity]), [self.source, continuity])
        self.assertEqual(module.validate_source_directories({"reality": self.source, "continuity": continuity}),
                         [self.source, continuity])
        for directories in ([self.source, self.source], [self.source.parent, self.source], [], "invalid"):
            with self.assertRaises(ControlError):
                module.validate_source_directories(directories)
        nested = self.source / "continuity"
        nested.mkdir()
        with self.assertRaises(ControlError):
            module.validate_source_directories([self.source, nested])

    def test_source_mount_rejects_unexpected_database_or_non_nonce_file(self):
        for name in ("authority.sqlite", "key.bin", "not-a-nonce.json"):
            unexpected = self.source / name
            unexpected.write_text("fixture")
            with self.assertRaises(ControlError):
                self.observer()
            unexpected.unlink()

    def test_start_accepts_only_exact_public_enrollment_and_cannot_restart(self):
        observer = self.observer()
        process = self.fake_service()
        enrollment = self.start_fake(observer, process)
        self.assertEqual(enrollment, self.enrollment())
        self.assertEqual(set(enrollment), {"observer_id", "role", "key_id", "public_key"})
        with self.assertRaisesRegex(ControlError, "RESTART_FORBIDDEN"):
            observer.start()
        with patch.object(observer, "_command", return_value=(0, b"", None)):
            cleanup = observer.stop()
        self.assertTrue(cleanup["removed"])

    def test_attestation_protocol_verifies_enrolled_key_and_whole_source_digest(self):
        observer = self.observer()
        process = self.fake_service()
        self.start_fake(observer, process)
        result = observer.attest(self.request)
        self.assertEqual(result["process"]["status"], "PASS")
        self.assertEqual(result["envelope"]["evidence_digest"], digest(self.packet()))
        self.assertFalse(result["execution_authorized"])
        self.assertNotIn((b"x" * 32).hex(), json.dumps(result))
        with patch.object(observer, "_command", return_value=(0, b"", None)):
            observer.stop()

    def test_request_for_other_role_key_or_identity_never_reaches_worker(self):
        observer = self.observer()
        for field, value in (("role", "continuity"), ("observer_id", "other-observer"),
                             ("key_id", "other-key"), ("nonce", "../private/key")):
            request = copy.deepcopy(self.request)
            request[field] = value
            with patch.object(observer, "_line") as exchange:
                result = observer.attest(request)
            self.assertIsNone(result["envelope"])
            self.assertEqual(result["process"]["status"], "HOLD")
            exchange.assert_not_called()

    def test_missing_source_returns_hold_without_key_export_or_authority(self):
        observer = self.observer()
        response = {"envelope": None, "status": "HOLD", "reason": "SOURCE_UNAVAILABLE", "execution_authorized": False}
        self.start_fake(observer, self.fake_service(response=response))
        result = observer.attest(self.request)
        self.assertIsNone(result["envelope"])
        self.assertEqual(result["process"]["reason"], "OBSERVER_CONTAINER_SOURCE_UNAVAILABLE")
        with patch.object(observer, "_command", return_value=(0, b"", None)):
            observer.stop()

    def test_replacement_key_is_rejected_and_service_is_removed(self):
        observer = self.observer()
        envelope = sign_attestation(self.request, private_key=b"y" * 32, verdict="SUPPORT",
            evidence_digest=digest(self.packet()), observed_at=100, valid_until=110)
        response = {"envelope": envelope, "status": "PASS", "reason": None, "execution_authorized": False}
        self.start_fake(observer, self.fake_service(response=response))
        with patch.object(observer, "_command", return_value=(0, b"", None)) as command:
            result = observer.attest(self.request)
        self.assertIsNone(result["envelope"])
        self.assertEqual(result["process"]["reason"], "OBSERVER_AUTH_SIGNATURE_INVALID")
        self.assertTrue(result["process"]["cleanup_verified"])
        self.assertIn([observer.docker_binary, "rm", "--force", observer.container_name], [call.args[0] for call in command.call_args_list])

    def test_timeout_removes_container_by_name_and_verifies_absence(self):
        observer = self.observer(timeout_seconds=0.03)
        process = self.fake_service(extra_code=" import time;time.sleep(20)\n")
        # Enrollment uses a normal deadline; the smaller deadline applies only to
        # the response fixture, not interpreter startup scheduling.
        observer.timeout_seconds = 2
        self.start_fake(observer, process)
        observer.timeout_seconds = 0.03
        with patch.object(observer, "_command", return_value=(0, b"", None)) as commands:
            result = observer.attest(self.request)
        self.assertEqual(result["process"]["reason"], "OBSERVER_CONTAINER_TIMEOUT")
        self.assertTrue(result["process"]["cleanup_verified"])
        self.assertIsNotNone(process.returncode)
        self.assertEqual(commands.call_count, 2)
        self.assertEqual(commands.call_args_list[0].args[0][1:3], ["rm", "--force"])

    def test_cleanup_connection_failure_is_visible_not_claimed_removed(self):
        observer = self.observer()
        with patch.object(observer, "_command", return_value=(None, b"", "OBSERVER_CONTAINER_CLI_ERROR")):
            cleanup = observer.stop()
        self.assertFalse(cleanup["removed"])
        self.assertFalse(cleanup["execution_authorized"])

    def test_create_failure_still_removes_random_name_without_container_id(self):
        observer = self.observer()
        responses = [(1, b"", "OBSERVER_CONTAINER_CLI_ERROR"), (0, b"", None), (0, b"", None)]
        with patch.object(observer, "_command", side_effect=responses) as command:
            with self.assertRaisesRegex(ControlError, "CREATE_FAILED"):
                observer.start()
        self.assertIsNone(observer.container_id)
        self.assertTrue(observer.last_cleanup["removed"])
        self.assertEqual(command.call_args_list[1].args[0], [observer.docker_binary, "rm", "--force", observer.container_name])

    def test_protocol_overflow_or_extra_lines_are_hold_and_cleanup(self):
        for raw, reason in ((b"x" * (module.MAX_REPORT_BYTES + 1), "OUTPUT_LIMIT"),
                            (b"{}\n{}\n", "REPORT_INVALID")):
            observer = self.observer()
            process = self.fake_service()
            self.start_fake(observer, process)
            code = "import sys,time;sys.stdout.buffer.write(" + repr(raw) + ");sys.stdout.flush();time.sleep(20)"
            module._kill_and_reap(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
            replacement = subprocess.Popen([sys.executable, "-u", "-I", "-c", code], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            observer._process = replacement
            with patch.object(observer, "_command", return_value=(0, b"", None)):
                result = observer.attest(self.request)
            self.assertIsNone(result["envelope"])
            self.assertIn(reason, result["process"]["reason"])
            self.assertTrue(result["process"]["cleanup_verified"])

    def test_private_key_is_created_locally_once_with_private_modes(self):
        path = self.source.parent / "private" / "key.bin"
        with patch.object(module, "PRIVATE_KEY_PATH", str(path)):
            private, public = module._new_private_key()
            self.assertEqual(len(private), 32)
            self.assertRegex(public, r"^[0-9a-f]{64}$")
            self.assertEqual(path.read_bytes(), private)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            with self.assertRaises(FileExistsError):
                module._new_private_key()

    def test_worker_reads_only_regular_nonce_file_and_commits_complete_packet(self):
        packet = self.packet()
        target = self.source / (self.request["nonce"] + ".json")
        target.write_bytes(canonical_bytes(packet))
        with patch.object(module, "SOURCE_DIRECTORY", str(self.source)):
            self.assertEqual(module._source_packet(self.request), packet)
            target.unlink()
            target.symlink_to(self.source.parent / "private-key")
            with self.assertRaises(OSError):
                module._source_packet(self.request)
            target.unlink()
            os.mkfifo(target)
            with self.assertRaises(ControlError):
                module._source_packet(self.request)
            target.unlink()
            target.write_bytes(b"x" * (module.MAX_SOURCE_BYTES + 1))
            with self.assertRaises(ControlError):
                module._source_packet(self.request)

    def test_worker_service_uses_one_generated_key_and_rejects_cross_role_request(self):
        other = copy.deepcopy(self.request)
        other["role"] = "continuity"
        raw = canonical_bytes(self.request) + b"\n" + canonical_bytes(other) + b"\n"
        output = io.BytesIO()
        with patch.object(module, "_new_private_key", return_value=(b"x" * 32, self.enrollment()["public_key"])) as generate, \
                patch.object(module, "_source_packet", return_value=self.packet()) as source, \
                patch.object(module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw))), \
                patch.object(module.sys, "stdout", SimpleNamespace(buffer=output)):
            code = module._container_worker("reality-observer", "reality", "reality-key")
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(code, 0)
        generate.assert_called_once()
        source.assert_called_once()
        self.assertEqual(records[0], self.enrollment())
        self.assertEqual(records[1]["envelope"]["evidence_digest"], digest(self.packet()))
        self.assertEqual(records[2]["status"], "HOLD")
        self.assertIsNone(records[2]["envelope"])
        self.assertNotIn((b"x" * 32).hex(), output.getvalue().decode())

    def test_legacy_state_and_edge_without_actual_receiver_export_is_unknown(self):
        packet = self.packet()
        packet["payload"] = copy.deepcopy(self.evidence)
        verdict, packet_digest, _ = module.evaluate_source_packet(self.request, packet)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(packet_digest, digest(packet))
        self.assertEqual(module.evaluate_source_packet(self.request, self.packet())[0], "SUPPORT")

    def test_incomplete_or_unverified_receiver_snapshot_never_supports(self):
        for mutate in (lambda payload: payload.pop("receiver_snapshot"),
                       lambda payload: payload.update(receiver_snapshot_verified_by_host=False),
                       lambda payload: payload["receiver_snapshot"].update(complete=False),
                       lambda payload: payload["receiver_snapshot"].update(accepted_action_ids=["pending"]),
                       lambda payload: payload["receiver_snapshot"].update(receipts="not-a-list")):
            packet = self.packet()
            mutate(packet["payload"])
            self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "UNKNOWN")

    def test_receiver_snapshot_requires_signed_export_metadata(self):
        for field in ("signature", "key_id", "enforcement_profile", "observed_at"):
            packet = self.packet()
            packet["payload"]["receiver_snapshot"].pop(field)
            self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "UNKNOWN")
        for field, value in (("signature", "invalid"), ("key_id", "other-key"),
                             ("enforcement_profile", "baseline_unfenced"), ("observed_at", -1)):
            packet = self.packet()
            packet["payload"]["receiver_snapshot"][field] = value
            self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "UNKNOWN")

    def committed_record(self):
        action = {"action_id": "previous", "attempt_id": "try-previous", "root_id": "root",
                  "execution_id": "agent", "epoch": 1, "target": "records", "arguments": {"value": "observed"}}
        receipt = {"schema": "liminal.agent-control.receipt.v1", "status": "COMMITTED",
                   "action_id": action["action_id"], "attempt_id": action["attempt_id"], "root_id": "root",
                   "execution_id": "agent", "epoch": 1, "action_digest": digest(action),
                   "effect_count": 1, "receiver_id": "owned-receiver"}
        return {"action": action, "arguments": action["arguments"], "receipt": receipt}

    def test_receiver_receipts_match_real_records_without_revision_count_assumption(self):
        packet = self.packet()
        record = self.committed_record()
        packet["payload"]["receiver_records"] = [record]
        packet["payload"]["receiver_snapshot"].update(receipts=[record["receipt"]], cutoff=1)
        # Graph revision remains zero: the export check does not equate a graph
        # transition counter with records observed through one effect channel.
        self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "SUPPORT")
        for change in (lambda value: value["receiver_snapshot"].update(receipts=[]),
                       lambda value: value["receiver_snapshot"].update(receiver_id="other-receiver"),
                       lambda value: value["receiver_records"][0]["receipt"].update(effect_count=0),
                       lambda value: value["receiver_records"][0]["receipt"].update(status="ACCEPTED"),
                       lambda value: value["receiver_records"][0]["receipt"].update(action_digest=digest("changed")),
                       lambda value: value["receiver_records"].append(copy.deepcopy(value["receiver_records"][0]))):
            changed = copy.deepcopy(packet)
            change(changed["payload"])
            self.assertEqual(module.evaluate_source_packet(self.request, changed)[0], "VETO")

    def test_foreign_receiver_snapshot_binding_is_veto(self):
        for field, value in (("root_id", "foreign"), ("execution_id", "other-agent"), ("epoch", 2)):
            packet = self.packet()
            packet["payload"]["receiver_snapshot"][field] = value
            self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "VETO")

    def test_receiver_record_arguments_preserve_json_types(self):
        packet = self.packet()
        record = self.committed_record()
        record["action"]["arguments"] = {"value": 1}
        record["receipt"]["action_digest"] = digest(record["action"])
        packet["payload"]["receiver_snapshot"].update(receipts=[record["receipt"]], cutoff=1)
        packet["payload"]["receiver_records"] = [record]
        for arguments in ({"value": True}, {"value": 1.0}):
            record["arguments"] = arguments
            self.assertEqual(module.evaluate_source_packet(self.request, packet)[0], "VETO")

    def test_other_roles_require_their_specific_collector_export(self):
        for role, kind in (("continuity", "append-only exported audit copy"),
                           ("projection", "installed immutable policy export")):
            request, evidence = fixtures(role)
            packet = {"source_id": role + "-collector", "role": role, "request_digest": digest(request),
                      "observed_at": 100, "payload": evidence}
            self.assertEqual(module.evaluate_source_packet(request, packet)[0], "UNKNOWN")
            evidence["collector_kind"] = kind
            self.assertEqual(module.evaluate_source_packet(request, packet)[0], "SUPPORT")


if __name__ == "__main__":
    unittest.main()
