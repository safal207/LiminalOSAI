"""Real fixed Python issuer processes expose signed owned receiver reads only."""
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import time
import unittest

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.brakes_store import SessionAuthority
from sdk.liminal_agent_control.observer_auth import CHALLENGE_SCHEMA
from sdk.liminal_agent_control.receiver import Receiver
from sdk.liminal_agent_control.receiver_source import verify_source_statement
from sdk.liminal_agent_control.receiver_source_service import ReceiverSourceProcess, MAX_REQUEST_BYTES
from tests import test_agent_control_observer_auth as auth_tests


@unittest.skipIf(auth_tests.Ed25519PrivateKey is None, "receiver source processes require cryptography")
class ReceiverSourceServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.db_path = self.directory / "owned.sqlite"
        self.broker_key, self.receipt_key = b"b" * 32, b"r" * 32
        self.key_files = []
        for name, key in (("broker.key", self.broker_key), ("receipt.key", self.receipt_key)):
            path = self.directory / name
            path.write_bytes(key)
            path.chmod(0o600)
            self.key_files.append(path)
        self.authority = SessionAuthority(self.db_path)
        self.authority.create_session("root", controller_id="owned-host", policy_digest=digest("owned-policy"),
            objective_digest=digest("owned-objective"), max_actions=10, max_executions=5, max_depth=2,
            max_stages=20, lifetime_seconds=120, lease_seconds=120)
        self.authority.bind_execution("root", "worker")
        self.receiver = Receiver(self.db_path, self.broker_key, self.receipt_key,
            admission_controller=self.authority)
        self.db_path.chmod(0o600)
        self.nonce_count = 0

    def process(self, **overrides):
        options = {"db_path": self.db_path, "broker_key_file": self.key_files[0],
                   "receipt_key_file": self.key_files[1], "issuer_id": "owned-issuer",
                   "source_id": "owned-receiver-source", "key_id": "owned-key",
                   "expected_receiver_id": self.receiver.receiver_id, "timeout_seconds": 3}
        options.update(overrides)
        process = ReceiverSourceProcess(**options)
        self.addCleanup(process.stop)
        return process

    def request(self):
        """A bounded owned challenge fixture; no stored observer proof is claimed."""
        self.nonce_count += 1
        now = time.time()
        result = {"schema": CHALLENGE_SCHEMA, "nonce": digest("nonce-" + str(self.nonce_count)),
                  "issued_at": now, "valid_until": now + 20, "action_id": "next-action",
                  "root_id": "root", "execution_id": "worker", "epoch": 1,
                  "observer_id": "reality-observer", "role": "reality", "key_id": "observer-key",
                  "center_id": "owned-center", "policy_digest": digest("owned-policy"),
                  "objective_digest": digest("owned-objective")}
        result.update({field: digest("owned-" + field) for field in ("action_digest", "projection_digest",
            "predecessor_hash", "ring_profile_digest", "auth_profile_digest", "orientation_profile_digest")})
        return result

    def record(self):
        action = {"action_id": "owned-record", "attempt_id": "owned-attempt", "root_id": "root",
                  "execution_id": "worker", "epoch": 1, "target": "records",
                  "arguments": {"message": "public owned test record"}}
        authorization = {"action_digest": digest(action), "policy_version": digest("owned-policy"),
                         "expires_at": time.time() + 30, "receiver_id": self.receiver.receiver_id}
        result = self.receiver.commit(action, authorization=authorization)
        self.assertEqual(result["status"], "COMMITTED")
        return action, result

    def raw(self, process, value):
        return json.loads(process._line(canonical_bytes(value) + b"\n"))

    def logical_database_snapshot(self):
        """Read the full schema and every table in one readonly transaction."""
        with closing(sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            return tuple(db.iterdump())

    @contextmanager
    def cwd(self, directory):
        previous = Path.cwd()
        os.chdir(directory)
        try:
            yield
        finally:
            os.chdir(previous)

    def test_actual_child_signs_empty_receiver_export_with_public_enrollment(self):
        process = self.process()
        pin = process.start()
        self.assertNotEqual(process.pid, os.getpid())
        self.assertEqual(set(pin), {"issuer_id", "source_id", "key_id", "receiver_id", "public_key"})
        request = self.request()
        statement = process.issue(request)
        self.assertEqual(verify_source_statement(request, statement, pin, now=time.time()), statement)
        self.assertEqual(statement["export"]["receiver_records"], [])
        self.assertTrue(statement["export"]["receiver_snapshot"]["complete"])
        self.assertEqual(statement["request_digest"], digest(request))
        wire = canonical_bytes(statement)
        self.assertNotIn(self.broker_key, wire)
        self.assertNotIn(self.receipt_key, wire)
        self.assertNotIn(b"private_key", wire)
        self.assertFalse(process.stop()["execution_authorized"])
        self.assertIsNotNone(process.process.poll())

    def test_actual_committed_record_is_read_and_no_new_effect_is_created(self):
        action, receipt = self.record()
        before = self.logical_database_snapshot()
        process = self.process()
        process.start()
        statement = process.issue(self.request())
        self.assertEqual(statement["export"]["receiver_records"],
            [{"action": action, "arguments": action["arguments"], "receipt": receipt}])
        self.assertEqual(statement["export"]["receiver_snapshot"]["receipts"], [receipt])
        self.assertEqual(len(self.receiver.records()), 1)
        # SQLite may checkpoint WAL pages while opening/closing a reader. The
        # invariant is unchanged schema and all rows, including authority data.
        self.assertEqual(self.logical_database_snapshot(), before)

    def test_logical_snapshot_survives_a_real_wal_checkpoint(self):
        # Keep a connection open so an actual owned commit remains in the WAL.
        # A checkpoint then deterministically changes main-file bytes while
        # preserving the complete logical snapshot used by the source test.
        with closing(sqlite3.connect(self.db_path, isolation_level=None)) as db:
            db.execute("PRAGMA wal_autocheckpoint=0")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.record()
            process = self.process()
            process.start()
            process.issue(self.request())
            before = self.logical_database_snapshot()
            main_file_before = self.db_path.read_bytes()
            self.assertIsNone(process.process.poll())
            self.assertEqual(db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(), (0, 0, 0))
            self.assertNotEqual(self.db_path.read_bytes(), main_file_before)
            self.assertEqual(self.logical_database_snapshot(), before)
            self.assertEqual(len(self.receiver.records()), 1)

    def test_enrollment_copies_cannot_replace_the_process_pin(self):
        process = self.process()
        returned = process.start()
        original = process.enrollment
        returned["public_key"] = "f" * 64
        public = process.enrollment
        public["public_key"] = "0" * 64
        self.assertEqual(process.enrollment, original)
        request = self.request()
        statement = process.issue(request)
        self.assertEqual(verify_source_statement(request, statement, original), statement)

    def test_wrong_expected_receiver_identity_rejects_and_reaps_startup(self):
        process = self.process(expected_receiver_id="different-owned-receiver")
        with self.assertRaisesRegex(ControlError, "ENROLLMENT_MISMATCH"):
            process.start()
        self.assertIsNotNone(process.pid)
        self.assertIsNotNone(process.process.poll())
        self.assertTrue(process.stop()["reaped"])
        with self.assertRaisesRegex(ControlError, "RESTART_FORBIDDEN"):
            process.start()

    def test_new_child_key_requires_new_enrollment_and_old_pin_rejects(self):
        first = self.process()
        first_pin = first.start()
        first.stop()
        second = self.process()
        second_pin = second.start()
        self.assertNotEqual(first_pin["public_key"], second_pin["public_key"])
        request = self.request()
        statement = second.issue(request)
        with self.assertRaisesRegex(ControlError, "SIGNATURE_INVALID"):
            verify_source_statement(request, statement, first_pin)
        self.assertEqual(verify_source_statement(request, statement, second_pin), statement)

    def test_no_start_and_stopped_process_cannot_issue_or_restart(self):
        process = self.process()
        with self.assertRaisesRegex(ControlError, "PROCESS_UNAVAILABLE"):
            process.issue(self.request())
        process.start()
        self.assertTrue(process.stop()["reaped"])
        with self.assertRaisesRegex(ControlError, "PROCESS_UNAVAILABLE"):
            process.issue(self.request())
        with self.assertRaisesRegex(ControlError, "RESTART_FORBIDDEN"):
            process.start()

    def test_deleted_source_database_refuses_and_is_never_recreated(self):
        process = self.process()
        process.start()
        self.db_path.unlink()
        with self.assertRaisesRegex(ControlError, "PROCESS_REFUSED"):
            process.issue(self.request())
        self.assertFalse(self.db_path.exists())
        self.assertTrue(process.stop()["reaped"])
        self.assertIsNotNone(process.process.poll())

    def test_world_readable_key_and_database_files_are_rejected(self):
        for file in (*self.key_files, self.db_path):
            file.chmod(0o644)
            try:
                with self.subTest(file=file.name), self.assertRaisesRegex(ControlError, "PRIVATE_FILE_UNSAFE"):
                    self.process()
            finally:
                file.chmod(0o600)

    def test_symlink_aliases_for_key_and_database_files_are_rejected(self):
        for field, target in (("broker_key_file", self.key_files[0]),
                              ("receipt_key_file", self.key_files[1]), ("db_path", self.db_path)):
            alias = self.directory / (field + ".alias")
            alias.symlink_to(target)
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "PRIVATE_FILE_UNSAFE"):
                self.process(**{field: alias})

    def test_invalid_key_lengths_fail_startup_without_export_or_live_child(self):
        for length in (0, 31, 33):
            self.key_files[0].write_bytes(b"x" * length)
            process = self.process()
            with self.subTest(length=length), self.assertRaisesRegex(ControlError, "PROCESS_UNAVAILABLE"):
                process.start()
            self.assertTrue(process.stop()["reaped"])
            self.assertIsNone(process.enrollment)
        self.key_files[0].write_bytes(self.broker_key)

    def test_wrong_receipt_authentication_key_cannot_export_a_committed_record(self):
        self.record()
        self.key_files[1].write_bytes(b"x" * 32)
        process = self.process()
        process.start()
        with self.assertRaisesRegex(ControlError, "PROCESS_REFUSED"):
            process.issue(self.request())
        self.assertTrue(process.stop()["reaped"])
        self.assertEqual(len(self.receiver.records()), 1)

    def test_hostile_working_directory_package_cannot_replace_fixed_worker(self):
        hostile = self.directory / "hostile"
        package = hostile / "liminal_agent_control"
        package.mkdir(parents=True)
        marker = self.directory / "hostile-package-executed"
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "receiver_source_service.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n",
            encoding="utf-8")
        process = self.process()
        with self.cwd(hostile):
            process.start()
            statement = process.issue(self.request())
        self.assertFalse(marker.exists())
        self.assertEqual(statement["receiver_id"], self.receiver.receiver_id)

    def test_protocol_has_no_caller_export_or_sign_arbitrary_operation(self):
        process = self.process()
        pin = process.start()
        request = self.request()
        for extra in ({"export": {"receiver_records": [], "receiver_snapshot": {}}},
                      {"operation": "sign", "payload": {"invented": True}},
                      {"source_id": "attacker-source", "public_key": "f" * 64}):
            response = self.raw(process, {**request, **extra})
            self.assertEqual(response, {"status": "HOLD", "statement": None,
                "reason": "SOURCE_UNAVAILABLE", "execution_authorized": False})
        statement = process.issue(self.request())
        self.assertEqual(statement["source_id"], pin["source_id"])
        self.assertNotIn("private_key", canonical_bytes(statement).decode())

    def test_malformed_json_is_refused_without_secret_error_contents(self):
        process = self.process()
        process.start()
        response = json.loads(process._line(b"{not-json}\n"))
        self.assertEqual(response, {"status": "HOLD", "statement": None,
            "reason": "SOURCE_UNAVAILABLE", "execution_authorized": False})
        self.assertIsNone(process.process.poll())
        self.assertEqual(process.issue(self.request())["receiver_id"], self.receiver.receiver_id)

    def test_oversized_raw_frame_terminates_child_and_can_be_reaped(self):
        process = self.process()
        process.start()
        with self.assertRaisesRegex(ControlError, "PROCESS_UNAVAILABLE"):
            process._line(b"x" * (MAX_REQUEST_BYTES + 1) + b"\n")
        self.assertTrue(process.stop()["reaped"])
        self.assertIsNotNone(process.process.poll())

    @unittest.skipUnless(os.name == "posix", "owned child suspension requires POSIX")
    def test_suspended_source_times_out_and_is_killed_and_reaped(self):
        process = self.process(timeout_seconds=1)
        process.start()
        os.kill(process.pid, signal.SIGSTOP)
        started = time.monotonic()
        with self.assertRaisesRegex(ControlError, "PROCESS_TIMEOUT"):
            process.issue(self.request())
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(process.process.poll())
        self.assertTrue(process.stop()["reaped"])


if __name__ == "__main__":
    unittest.main()
