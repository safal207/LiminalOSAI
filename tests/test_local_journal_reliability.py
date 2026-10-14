"""Fault and process boundaries of the five local journal writer contracts."""

from __future__ import annotations

import importlib
import json
import multiprocessing
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sdk.liminal_github_policy import ApprovalLedger, PolicySnapshot, TransactionPolicy
from sdk.liminal_github_transaction import TransactionPlan
from sdk.liminal_portable_receipt import ProjectionLedger, ReceiptError
from sdk.liminal_session_recorder import RecorderError, SessionRecorder

MODULES = (
    ("sdk.liminal_github_policy._ledger", "_atomic_write_json", "_exclusive_lock"),
    ("sdk.liminal_session_recorder", "_atomic_write_json", "_journal_lock"),
    ("sdk.liminal_github_transaction._journal", "_atomic_write_json", "_exclusive_lock"),
    ("sdk.liminal_host_adapter._core", "atomic_write_json", "exclusive_lock"),
    ("sdk.liminal_portable_receipt._ledger", "_atomic_write", "_exclusive_lock"),
)


def _projection_arguments(tag: str) -> dict:
    return {"source_receipt_sha256": tag * 64, "projection_profile": "test", "projection": {"tag": tag}}


def _hold_lock(module_name, helper_name, path, ready, release):
    module = importlib.import_module(module_name)
    with getattr(module, helper_name)(Path(path)):
        ready.set()
        if not release.wait(10):
            raise RuntimeError("test lock release timed out")


def _projection_writer(root, ready, release, queue):
    module = importlib.import_module("sdk.liminal_portable_receipt._ledger")
    original = module._atomic_write

    def held_write(path, value):
        ready.set()
        if not release.wait(10):
            raise RuntimeError("test projection release timed out")
        original(path, value)

    try:
        ledger = ProjectionLedger(root)
        with mock.patch.object(module, "_atomic_write", side_effect=held_write):
            queue.put(ledger.append(**_projection_arguments("a"))["sequence"])
    except Exception as exc:
        queue.put(type(exc).__name__ + ":" + str(exc))


def _crash_recorder(path, after_replace):
    module = importlib.import_module("sdk.liminal_session_recorder")
    if after_replace:
        module._fsync_directory = lambda _: os._exit(71)
    else:
        module.os.replace = lambda *_: os._exit(72)
    SessionRecorder(path).record_user_message(event_id="crashed", text="bounded event")


def _approval_fixture():
    plan = TransactionPlan.build(
        transaction_id="journal-test", runtime_config_path="runtime.json",
        runtime_config_sha256="1" * 64, repository_full_name="safal207/LiminalOSAI",
        steps=[{
            "step_id": "branch", "call_id": "call-branch", "action": "create_branch",
            "arguments": {"repository_full_name": "safal207/LiminalOSAI", "branch_name": "test/journal", "base_ref": "main"},
            "exports": {}, "expect": {}, "gate_step_ids": [],
        }],
    )
    policy = TransactionPolicy.build(policy_id="journal-test", allowed_repositories=["safal207/LiminalOSAI"])
    return PolicySnapshot.evaluate(policy, plan)


class LocalJournalDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, module, helper_name, path, tag):
        value = json.dumps({"value": tag}) + "\n" if helper_name == "_atomic_write" else {"value": tag}
        return getattr(module, helper_name)(path, value)

    def test_replacement_failure_preserves_previous_bytes_and_cleans_temporary_file(self):
        for index, (name, helper, _) in enumerate(MODULES):
            with self.subTest(module=name):
                module = importlib.import_module(name)
                path = self.root / str(index) / "journal.json"
                self.write(module, helper, path, "accepted")
                previous = path.read_bytes()
                with mock.patch.object(module.os, "replace", side_effect=OSError("injected replace failure")):
                    with self.assertRaisesRegex(OSError, "replace failure"):
                        self.write(module, helper, path, "new")
                self.assertEqual(path.read_bytes(), previous)
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_file_sync_failure_preserves_previous_bytes(self):
        for index, (name, helper, _) in enumerate(MODULES):
            with self.subTest(module=name):
                module = importlib.import_module(name)
                path = self.root / str(index) / "journal.json"
                self.write(module, helper, path, "accepted")
                previous = path.read_bytes()
                with mock.patch.object(module.os, "fsync", side_effect=OSError("injected file sync failure")):
                    with self.assertRaisesRegex(OSError, "file sync failure"):
                        self.write(module, helper, path, "new")
                self.assertEqual(path.read_bytes(), previous)
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_directory_open_failure_after_replace_never_acknowledges_success(self):
        original_open = os.open
        for index, (name, helper, _) in enumerate(MODULES):
            with self.subTest(module=name):
                module = importlib.import_module(name)
                path = self.root / str(index) / "journal.json"
                self.write(module, helper, path, "accepted")

                def fail_directory(name, *args, **kwargs):
                    if Path(name) == path.parent:
                        raise OSError("injected directory open failure")
                    return original_open(name, *args, **kwargs)

                with mock.patch.object(module.os, "open", side_effect=fail_directory):
                    with self.assertRaisesRegex(OSError, "directory open failure"):
                        self.write(module, helper, path, "new")
                self.assertEqual(json.loads(path.read_text()), {"value": "new"})
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_directory_sync_failure_after_replace_never_acknowledges_success(self):
        original_fsync = os.fsync
        for index, (name, helper, _) in enumerate(MODULES):
            with self.subTest(module=name):
                module = importlib.import_module(name)
                path = self.root / str(index) / "journal.json"
                self.write(module, helper, path, "accepted")

                def fail_directory(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode):
                        raise OSError("injected directory sync failure")
                    return original_fsync(fd)

                with mock.patch.object(module.os, "fsync", side_effect=fail_directory):
                    with self.assertRaisesRegex(OSError, "directory sync failure"):
                        self.write(module, helper, path, "new")
                self.assertEqual(json.loads(path.read_text()), {"value": "new"})
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_lock_setup_errors_close_descriptor_and_remove_only_owned_lock(self):
        for name, _, helper in MODULES:
            for operation in ("write", "fsync"):
                with self.subTest(module=name, operation=operation):
                    module = importlib.import_module(name)
                    path = self.root / "journal.json"
                    original_close = os.close
                    descriptors = []

                    def close(fd):
                        descriptors.append(fd)
                        return original_close(fd)

                    with mock.patch.object(module.os, operation, side_effect=OSError("lock setup failed")):
                        with mock.patch.object(module.os, "close", side_effect=close):
                            with self.assertRaisesRegex(OSError, "lock setup failed"):
                                with getattr(module, helper)(path):
                                    self.fail("body ran after failed lock setup")
                    self.assertEqual(len(descriptors), 1)
                    with self.assertRaises(OSError):
                        os.fstat(descriptors[0])
                    lock = path.with_name(path.name + ".lock")
                    self.assertFalse(lock.exists())
                    lock.write_text("external")
                    with self.assertRaisesRegex(ValueError, "lock already exists"):
                        with getattr(module, helper)(path):
                            self.fail("external lock was accepted")
                    self.assertEqual(lock.read_text(), "external")
                    lock.unlink()

    def test_process_shared_contention_rejects_second_writer_for_every_journal(self):
        context = multiprocessing.get_context("spawn")
        for name, _, helper in MODULES:
            with self.subTest(module=name):
                path = self.root / "journal.json"
                ready, release = context.Event(), context.Event()
                child = context.Process(target=_hold_lock, args=(name, helper, str(path), ready, release))
                child.start()
                try:
                    self.assertTrue(ready.wait(5), "child did not acquire lock")
                    module = importlib.import_module(name)
                    with self.assertRaisesRegex(ValueError, "lock already exists"):
                        with getattr(module, helper)(path):
                            self.fail("second writer entered")
                    self.assertTrue(path.with_name(path.name + ".lock").exists())
                finally:
                    release.set()
                    child.join(5)
                    if child.is_alive():
                        child.terminate()
                        child.join(5)
                self.assertEqual(child.exitcode, 0)
                self.assertFalse(path.with_name(path.name + ".lock").exists())

    def test_process_death_before_or_after_replace_preserves_a_complete_journal_and_lock(self):
        context = multiprocessing.get_context("spawn")
        for after_replace in (False, True):
            with self.subTest(after_replace=after_replace):
                path = self.root / str(after_replace) / "session.json"
                recorder = SessionRecorder.create(path, session_id="crash", high_stakes=False, requires_current_information=False)
                recorder.record_user_message(event_id="accepted", text="retained event")
                previous = path.read_bytes()
                child = context.Process(target=_crash_recorder, args=(str(path), after_replace))
                child.start()
                child.join(5)
                if child.is_alive():
                    child.terminate()
                    child.join(5)
                self.assertEqual(child.exitcode, 71 if after_replace else 72)
                self.assertEqual(recorder.verify()["event_count"], 2 if after_replace else 1)
                self.assertEqual(recorder.read()["entries"][0]["event"]["id"], "accepted")
                if not after_replace:
                    self.assertEqual(path.read_bytes(), previous)
                lock = path.with_name(path.name + ".lock")
                self.assertTrue(lock.exists())
                with self.assertRaisesRegex(RecorderError, "lock already exists"):
                    recorder.record_user_message(event_id="retry", text="must not run")

    def test_accepted_denial_survives_failed_append_and_remains_a_veto(self):
        module = importlib.import_module("sdk.liminal_github_policy._ledger")
        snapshot = _approval_fixture()
        ledger = ApprovalLedger.create(self.root / "approval.json", snapshot)
        requirement = snapshot.requirements[0]
        role = next(iter(requirement.required_role_counts))
        ledger.append(snapshot, approval_id="deny", principal_id="denier", role=role, decision="deny", requirement_id=requirement.requirement_id)
        previous = ledger.path.read_bytes()
        with mock.patch.object(module.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                ledger.append(snapshot, approval_id="approval", principal_id="approver", role=role, decision="approve", requirement_id=requirement.requirement_id)
        self.assertEqual(ledger.path.read_bytes(), previous)
        self.assertEqual(ledger.summary(snapshot)["status"], "denied")
        self.assertEqual(ledger.summary(snapshot)["denial_approval_ids"], ["deny"])


    def test_denial_visible_after_failed_directory_sync_must_be_reconciled_not_replayed(self):
        module = importlib.import_module("sdk.liminal_github_policy._ledger")
        snapshot = _approval_fixture()
        ledger = ApprovalLedger.create(self.root / "approval.json", snapshot)
        requirement = snapshot.requirements[0]
        role = next(iter(requirement.required_role_counts))
        arguments = dict(approval_id="deny", principal_id="denier", role=role, decision="deny", requirement_id=requirement.requirement_id)
        with mock.patch.object(module, "_fsync_directory", side_effect=OSError("directory sync failed")):
            with self.assertRaisesRegex(OSError, "directory sync failed"):
                ledger.append(snapshot, **arguments)
        # Visible complete state is evidence of a write, not a durability acknowledgment.
        self.assertEqual(ledger.summary(snapshot)["status"], "denied")
        self.assertEqual(ledger.summary(snapshot)["denial_approval_ids"], ["deny"])
        previous = ledger.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate approval_id"):
            ledger.append(snapshot, **arguments)
        self.assertEqual(ledger.path.read_bytes(), previous)


class ProjectionJournalReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = ProjectionLedger(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_process_contention_cannot_duplicate_sequence_or_receipt_ancestry(self):
        context = multiprocessing.get_context("spawn")
        ready, release, queue = context.Event(), context.Event(), context.Queue()
        child = context.Process(target=_projection_writer, args=(str(self.root), ready, release, queue))
        child.start()
        try:
            self.assertTrue(ready.wait(5))
            with self.assertRaisesRegex(ReceiptError, "lock already exists"):
                self.ledger.append(**_projection_arguments("b"))
        finally:
            release.set()
            child.join(5)
            if child.is_alive():
                child.terminate()
                child.join(5)
        self.assertEqual(child.exitcode, 0)
        self.assertEqual(queue.get(timeout=2), 1)
        self.assertEqual(self.ledger.append(**_projection_arguments("b"))["sequence"], 2)
        state = ProjectionLedger(self.root).verify()
        self.assertEqual(state["entry_count"], 2)
        self.assertEqual(state["receipt_refs"], ["a" * 64, "b" * 64])

    def test_append_replaces_atomically_and_preserves_historical_wire_bytes(self):
        self.ledger.append(**_projection_arguments("a"))
        previous = self.ledger.journal_path.read_bytes().replace(b"\n", b"\r\n") + b"\r\n"
        self.ledger.journal_path.write_bytes(previous)
        self.ledger.append(**_projection_arguments("b"))
        self.assertTrue(self.ledger.journal_path.read_bytes().startswith(previous))
        self.assertEqual(self.ledger.verify()["entry_count"], 2)

    def test_failed_replace_preserves_accepted_entries(self):
        module = importlib.import_module("sdk.liminal_portable_receipt._ledger")
        self.ledger.append(**_projection_arguments("a"))
        previous = self.ledger.journal_path.read_bytes()
        with mock.patch.object(module.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.ledger.append(**_projection_arguments("b"))
        self.assertEqual(self.ledger.journal_path.read_bytes(), previous)
        self.assertEqual(ProjectionLedger(self.root).verify()["entry_count"], 1)

    def test_older_checkpoint_is_verified_as_a_prefix_without_claiming_current_equality(self):
        self.ledger.append(**_projection_arguments("a"))
        checkpoint = self.ledger.write_snapshot()
        self.ledger.append(**_projection_arguments("b"))
        reopened = ProjectionLedger(self.root)
        verified = reopened.verify_snapshot()
        self.assertEqual(verified["snapshot_sha256"], checkpoint["snapshot_sha256"])
        self.assertTrue(verified["checkpoint_replay_equal"])
        self.assertFalse(verified["replay_equal"])
        self.assertEqual(verified["entry_count"], 1)
        self.assertEqual(verified["current_entry_count"], 2)
        self.assertEqual(verified["current_head_sha256"], reopened.verify()["head_sha256"])

    def test_snapshot_and_append_share_the_same_writer_lock(self):
        module = importlib.import_module("sdk.liminal_portable_receipt._ledger")
        with module._exclusive_lock(self.ledger.journal_path):
            with self.assertRaisesRegex(ReceiptError, "lock already exists"):
                self.ledger.write_snapshot()
        self.assertFalse(self.ledger.snapshot_path.exists())

    def test_self_consistent_but_divergent_snapshot_is_rejected(self):
        module = importlib.import_module("sdk.liminal_portable_receipt._ledger")
        self.ledger.append(**_projection_arguments("a"))
        snapshot = self.ledger.write_snapshot()
        snapshot["receipt_refs"] = ["b" * 64]
        body = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
        snapshot["snapshot_sha256"] = module.canonical_sha256(body)
        self.ledger.snapshot_path.write_text(json.dumps(snapshot))
        with self.assertRaisesRegex(ReceiptError, "replay prefix"):
            ProjectionLedger(self.root)
        previous = self.ledger.journal_path.read_bytes()
        with self.assertRaisesRegex(ReceiptError, "replay prefix"):
            self.ledger.append(**_projection_arguments("b"))
        with self.assertRaisesRegex(ReceiptError, "replay prefix"):
            self.ledger.write_snapshot()
        self.assertEqual(self.ledger.journal_path.read_bytes(), previous)
        self.assertEqual(json.loads(self.ledger.snapshot_path.read_text()), snapshot)

    def test_snapshot_count_beyond_tip_boolean_or_negative_is_rejected(self):
        module = importlib.import_module("sdk.liminal_portable_receipt._ledger")
        self.ledger.append(**_projection_arguments("a"))
        original = self.ledger.write_snapshot()
        for count in (2, -1, True, 1.0):
            with self.subTest(count=count):
                snapshot = {**original, "entry_count": count}
                snapshot["snapshot_sha256"] = module.canonical_sha256({key: value for key, value in snapshot.items() if key != "snapshot_sha256"})
                self.ledger.snapshot_path.write_text(json.dumps(snapshot))
                with self.assertRaisesRegex(ReceiptError, "valid journal prefix"):
                    self.ledger.verify_snapshot()

    def test_older_checkpoint_cannot_hide_a_corrupt_journal_suffix(self):
        self.ledger.append(**_projection_arguments("a"))
        self.ledger.write_snapshot()
        self.ledger.append(**_projection_arguments("b"))
        with self.ledger.journal_path.open("ab") as handle:
            handle.write(b'{"partial":')
        previous = self.ledger.journal_path.read_bytes()
        with self.assertRaisesRegex(ReceiptError, "invalid JSON"):
            self.ledger.verify_snapshot()
        with self.assertRaisesRegex(ReceiptError, "invalid JSON"):
            self.ledger.append(**_projection_arguments("c"))
        self.assertEqual(self.ledger.journal_path.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
