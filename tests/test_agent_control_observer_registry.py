"""Observer lifecycle races and durable bindings; no Docker/OS containment claim."""
import copy
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from sdk.liminal_agent_control.observer_registry import (
    ObserverRegistryError, ObserverRingRegistry, ownership_labels)


class ObserverRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.authority = self.path / "authority.db"
        self.authority.touch()
        self.registry = ObserverRingRegistry(self.path / "observer-ring.db")
        self.observers = [{"observer_id": "observer:" + role, "role": role,
                           "key_id": "key:" + role,
                           "container_name": "liminal-observer-" + character * 32}
                          for role, character in zip(("reality", "continuity", "projection"), "abc")]

    def tearDown(self):
        self.directory.cleanup()

    def register(self, *, registry=None, root_id="root:observer-registry", **changes):
        parameters = dict(root_id=root_id, authority_db=self.authority,
                          image_id="sha256:" + "d" * 64,
                          observers=copy.deepcopy(self.observers), lifetime_seconds=60)
        parameters.update(changes)
        return (registry or self.registry).register_ring(**parameters)

    def enroll(self, record, index=0):
        child = self.observers[index]
        container_id = str(index + 1) * 64
        enrollment = {key: child[key] for key in ("observer_id", "role", "key_id")}
        enrollment["public_key"] = str(index + 4) * 64
        self.registry.mark_create_pending(record, child["observer_id"])
        self.registry.confirm_created(record, child["observer_id"], container_id)
        self.registry.confirm_enrolled(record, child["observer_id"], enrollment)
        return container_id, enrollment

    def test_atomic_durable_ring_registration_and_fixed_deadline(self):
        with self.registry.controller_lease(), patch("sdk.liminal_agent_control.observer_registry.time.time", return_value=1000):
            record = self.register(lifetime_seconds=7)
        reopened = ObserverRingRegistry(self.registry.path, create=False)
        self.assertEqual(reopened.registry_id, self.registry.registry_id)
        self.assertEqual(reopened.unfinished(), [record])
        snapshot = reopened.snapshot(record)
        self.assertEqual(snapshot["deadline_at"], 1007)
        self.assertEqual(snapshot["status"], "REGISTERED")
        self.assertEqual([child["phase"] for child in snapshot["children"]], ["REGISTERED"] * 3)
        self.assertTrue(all(child["container_id"] is None and child["enrollment"] is None
                            for child in snapshot["children"]))

    def test_controller_lease_required_and_exclusive_but_probe_does_not_steal_it(self):
        competitor = ObserverRingRegistry(self.registry.path, create=False)
        self.assertFalse(competitor.controller_present())
        with self.assertRaisesRegex(ObserverRegistryError, "LEASE_REQUIRED"):
            self.register()
        with self.registry.controller_lease():
            self.assertTrue(self.registry.controller_present())
            self.assertTrue(competitor.controller_present())
            with self.assertRaisesRegex(ObserverRegistryError, "BUSY"):
                with competitor.controller_lease():
                    self.fail("two controllers acquired the same lease")
            record = self.register()
            self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
        self.assertFalse(competitor.controller_present())
        with self.assertRaisesRegex(ObserverRegistryError, "LEASE_REQUIRED"):
            self.registry.confirm_created(record, self.observers[0]["observer_id"], "1" * 64)

    def test_controller_lock_noninheritable_and_pid_bound(self):
        with self.registry.controller_lease():
            self.assertFalse(os.get_inheritable(self.registry._lease_fd))
            with patch("sdk.liminal_agent_control.observer_registry.os.getpid", return_value=os.getpid() + 1):
                with self.assertRaisesRegex(ObserverRegistryError, "LEASE_REQUIRED"):
                    self.register()

    def test_controller_probe_failure_is_not_absence(self):
        self.registry.lock_path.symlink_to(self.authority)
        with self.assertRaisesRegex(ObserverRegistryError, "LOCK_UNAVAILABLE"):
            self.registry.controller_present()
        with self.assertRaisesRegex(ObserverRegistryError, "LOCK_UNAVAILABLE"):
            with self.registry.controller_lease():
                self.fail("followed a symlink lock")

    @unittest.skipUnless(os.name == "posix", "flock/SIGKILL fixture requires POSIX")
    def test_controller_sigkill_releases_lease_and_preserves_all_children(self):
        program = """
import json, sys, time
from sdk.liminal_agent_control.observer_registry import ObserverRingRegistry
registry = ObserverRingRegistry(sys.argv[1], create=False)
with registry.controller_lease():
    record = registry.register_ring(**json.loads(sys.argv[2]))
    registry.mark_create_pending(record, record['observers'][0]['observer_id'])
    print('durable', flush=True)
    time.sleep(30)
"""
        parameters = dict(root_id="root:crashed", authority_db=str(self.authority),
                          image_id="sha256:" + "d" * 64, observers=self.observers, lifetime_seconds=60)
        child = subprocess.Popen([sys.executable, "-c", program, str(self.registry.path), json.dumps(parameters)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(3), "child did not persist its ring")
                self.assertEqual(child.stdout.readline().strip(), "durable")
            self.assertTrue(self.registry.controller_present())
            child.kill()
            child.wait(timeout=3)
            self.assertFalse(self.registry.controller_present())
            record = self.registry.unfinished()[0]
            self.assertEqual([row["phase"] for row in self.registry.snapshot(record)["children"]],
                             ["CREATE_PENDING", "REGISTERED", "REGISTERED"])
            with self.registry.controller_lease(), self.assertRaisesRegex(ObserverRegistryError, "RECOVERY_REQUIRED"):
                self.register(root_id="root:second")
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()

    def test_complete_ring_retains_root_identity_after_close(self):
        with self.registry.controller_lease():
            record = self.register()
        self.registry.begin_closing(record, "controller-exited")
        for child in self.observers:
            self.registry.complete_child(record, child["observer_id"], None, True)
        self.registry.complete_ring(record)
        self.registry.complete_ring(record)  # Exact replay is harmless, no reopening.
        self.assertEqual(self.registry.unfinished(), [])
        self.assertEqual(self.registry.snapshot(record)["status"], "CLOSED")
        with self.registry.controller_lease(), self.assertRaisesRegex(ObserverRegistryError, "ROOT_REPLACEMENT"):
            self.register()
        with self.registry.controller_lease():
            self.assertEqual(self.register(root_id="root:fresh")["root_id"], "root:fresh")

    def test_ring_closing_blocks_every_controller_transition_while_lease_is_live(self):
        watcher = ObserverRingRegistry(self.registry.path, create=False)
        with self.registry.controller_lease():
            record = self.register()
            self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
            self.registry.confirm_created(record, self.observers[0]["observer_id"], "1" * 64)
            watcher.begin_closing(record, "WATCHDOG_EXPIRED")
            self.assertTrue(watcher.controller_present())
            for action in (
                lambda: self.registry.mark_create_pending(record, self.observers[1]["observer_id"]),
                lambda: self.registry.confirm_created(record, self.observers[0]["observer_id"], "1" * 64),
                lambda: self.registry.confirm_enrolled(record, self.observers[0]["observer_id"],
                    {"observer_id": self.observers[0]["observer_id"], "role": "reality",
                     "key_id": "key:reality", "public_key": "4" * 64}),
            ):
                with self.assertRaisesRegex(ObserverRegistryError, "RING_CLOSING"):
                    action()
        watcher.begin_closing(record, "SECOND_REASON")
        self.assertEqual(watcher.snapshot(record)["closing_reason"], "WATCHDOG_EXPIRED")

    def test_create_pending_absence_cannot_release_any_unfinished_ring(self):
        with self.registry.controller_lease():
            record = self.register()
            self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
        self.registry.begin_closing(record, "CONTROLLER_LOST")
        with self.assertRaisesRegex(ObserverRegistryError, "CREATE_OUTCOME_UNCONFIRMED"):
            self.registry.complete_child(record, self.observers[0]["observer_id"], None, True)
        for child in self.observers[1:]:
            self.registry.complete_child(record, child["observer_id"], None, True)
        with self.assertRaisesRegex(ObserverRegistryError, "RECOVERY_INCOMPLETE"):
            self.registry.complete_ring(record)
        self.assertEqual(self.registry.snapshot(record)["children"][0]["phase"], "CREATE_PENDING")
        self.assertEqual(self.registry.unfinished(), [record])

    def test_removal_requires_closing_verified_absence_and_exact_id(self):
        with self.registry.controller_lease():
            record = self.register()
            container_id, _ = self.enroll(record)
        with self.assertRaisesRegex(ObserverRegistryError, "NOT_CLOSING"):
            self.registry.complete_child(record, self.observers[0]["observer_id"], container_id, True)
        self.registry.begin_closing(record, "NORMAL_CLOSE")
        for claimed in (False, None, 1, "true"):
            with self.assertRaisesRegex(ObserverRegistryError, "REMOVAL_UNVERIFIED"):
                self.registry.complete_child(record, self.observers[0]["observer_id"], container_id, claimed)
        for wrong in (None, "2" * 64, self.observers[0]["container_name"]):
            with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
                self.registry.complete_child(record, self.observers[0]["observer_id"], wrong, True)
        self.registry.complete_child(record, self.observers[0]["observer_id"], container_id, True)
        original = self.registry.snapshot(record)["children"][0]
        self.registry.complete_child(record, self.observers[0]["observer_id"], container_id, True)
        self.assertEqual(self.registry.snapshot(record)["children"][0], original)
        with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
            self.registry.complete_child(record, self.observers[0]["observer_id"], "2" * 64, True)

    def test_pinned_container_and_enrollment_retries_preserve_key_and_phase(self):
        with self.registry.controller_lease():
            record = self.register()
            container_id, enrollment = self.enroll(record)
            original = self.registry.snapshot(record)["children"][0]
            self.registry.confirm_created(record, self.observers[0]["observer_id"], container_id)
            self.registry.confirm_enrolled(record, self.observers[0]["observer_id"], enrollment)
            self.assertEqual(self.registry.snapshot(record)["children"][0], original)
            with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
                self.registry.confirm_created(record, self.observers[0]["observer_id"], "2" * 64)
            with self.assertRaisesRegex(ObserverRegistryError, "REPLACEMENT_FORBIDDEN"):
                self.registry.confirm_enrolled(record, self.observers[0]["observer_id"],
                                               {**enrollment, "public_key": "7" * 64})
            self.assertEqual(self.registry.snapshot(record)["children"][0], original)

    def test_cannot_confirm_unsubmitted_create_or_unconfirmed_enrollment(self):
        with self.registry.controller_lease():
            record = self.register()
            with self.assertRaisesRegex(ObserverRegistryError, "CREATE_NOT_SUBMITTED"):
                self.registry.confirm_created(record, self.observers[0]["observer_id"], "1" * 64)
            self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
            with self.assertRaisesRegex(ObserverRegistryError, "ALREADY_SUBMITTED"):
                self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
            with self.assertRaisesRegex(ObserverRegistryError, "CREATE_UNCONFIRMED"):
                self.registry.confirm_enrolled(record, self.observers[0]["observer_id"],
                    {"observer_id": self.observers[0]["observer_id"], "role": "reality",
                     "key_id": "key:reality", "public_key": "4" * 64})

    def test_enrollment_identity_and_distinct_public_keys_are_required(self):
        with self.registry.controller_lease():
            record = self.register()
            _, first = self.enroll(record)
            second = self.observers[1]
            self.registry.mark_create_pending(record, second["observer_id"])
            self.registry.confirm_created(record, second["observer_id"], "2" * 64)
            valid = {key: second[key] for key in ("observer_id", "role", "key_id")}
            valid["public_key"] = "5" * 64
            for field, value in (("observer_id", "observer:other"), ("role", "reality"), ("key_id", "key:other")):
                with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
                    self.registry.confirm_enrolled(record, second["observer_id"], {**valid, field: value})
            with self.assertRaisesRegex(ObserverRegistryError, "DUPLICATE_KEY"):
                self.registry.confirm_enrolled(record, second["observer_id"], {**valid, "public_key": first["public_key"]})
            self.registry.confirm_enrolled(record, second["observer_id"], valid)

    def test_forged_record_cannot_mutate_read_or_complete_ring(self):
        with self.registry.controller_lease():
            record = self.register()
            for field, value in (("ownership_token", "f" * 32), ("root_id", "root:other"),
                                 ("authority_db", str(self.path / "other.db")),
                                 ("image_id", "sha256:" + "e" * 64)):
                forged = {**record, field: value}
                for action in (
                    lambda: self.registry.snapshot(forged),
                    lambda: self.registry.mark_create_pending(forged, self.observers[0]["observer_id"]),
                    lambda: self.registry.begin_closing(forged, "forged"),
                    lambda: self.registry.complete_ring(forged),
                ):
                    with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
                        action()
        self.assertEqual(self.registry.snapshot(record)["status"], "REGISTERED")

    def test_duplicate_or_missing_principals_and_unbounded_lifetimes_are_rejected(self):
        with self.registry.controller_lease():
            invalid = [self.observers[:2]]
            for field in ("observer_id", "role", "key_id", "container_name"):
                changed = copy.deepcopy(self.observers)
                changed[1][field] = changed[0][field]
                invalid.append(changed)
            for observers in invalid:
                with self.assertRaisesRegex(ObserverRegistryError, "REGISTRATION_INVALID"):
                    self.register(observers=observers)
            for lifetime in (True, 0, -1, float("nan"), float("inf"), 86401, "60"):
                with self.assertRaisesRegex(ObserverRegistryError, "REGISTRATION_INVALID"):
                    self.register(lifetime_seconds=lifetime)
        self.assertEqual(self.registry.unfinished(), [])

    def test_authority_path_must_exist_and_be_canonical_and_separate(self):
        linked = self.path / "authority-link.db"
        linked.symlink_to(self.authority)
        with self.registry.controller_lease():
            for path in (linked, self.path / "missing.db", self.registry.path, self.path, Path("relative.db")):
                with self.assertRaisesRegex(ObserverRegistryError, "REGISTRATION_INVALID"):
                    self.register(authority_db=path)

    def test_deadline_or_clock_rollback_blocks_late_create(self):
        with self.registry.controller_lease():
            with patch("sdk.liminal_agent_control.observer_registry.time.time", return_value=100):
                record = self.register(lifetime_seconds=2)
            for now, reason in ((102, "RING_EXPIRED"), (99, "CLOCK_UNSAFE"), (float("nan"), "CLOCK_UNSAFE")):
                with patch("sdk.liminal_agent_control.observer_registry.time.time", return_value=now):
                    with self.assertRaisesRegex(ObserverRegistryError, reason):
                        self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
        self.assertEqual(self.registry.snapshot(record)["children"][0]["phase"], "REGISTERED")

    def test_closing_and_create_race_never_erases_pending_uncertainty(self):
        watcher = ObserverRingRegistry(self.registry.path, create=False)
        barrier = threading.Barrier(2)
        outcomes = []
        with self.registry.controller_lease():
            record = self.register()
            def creator():
                barrier.wait(timeout=2)
                try:
                    self.registry.mark_create_pending(record, self.observers[0]["observer_id"])
                    outcomes.append("pending")
                except ObserverRegistryError as exc:
                    outcomes.append(str(exc))
            def closer():
                barrier.wait(timeout=2)
                watcher.begin_closing(record, "WATCHDOG_EXPIRED")
            threads = [threading.Thread(target=target) for target in (creator, closer)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive(), "bounded registry operation did not finish")
        self.assertEqual(watcher.snapshot(record)["status"], "CLOSING")
        self.assertIn(outcomes[0], ("pending", "OBSERVER_RING_CLOSING"))
        phase = watcher.snapshot(record)["children"][0]["phase"]
        if outcomes == ["pending"]:
            self.assertEqual(phase, "CREATE_PENDING")
            with self.assertRaisesRegex(ObserverRegistryError, "CREATE_OUTCOME_UNCONFIRMED"):
                watcher.complete_child(record, self.observers[0]["observer_id"], None, True)
        else:
            self.assertEqual(phase, "REGISTERED")
            watcher.complete_child(record, self.observers[0]["observer_id"], None, True)

    def test_existing_only_open_and_removed_storage_do_not_recreate_evidence(self):
        missing = self.path / "never-created.db"
        with self.assertRaisesRegex(ObserverRegistryError, "REGISTRY_NOT_FOUND"):
            ObserverRingRegistry(missing, create=False)
        self.assertFalse(missing.exists())
        self.registry.path.unlink()
        with self.assertRaisesRegex(ObserverRegistryError, "STORAGE_UNAVAILABLE"):
            self.registry.unfinished()
        self.assertFalse(self.registry.path.exists())

    def test_labels_are_separate_bound_principals(self):
        with self.registry.controller_lease():
            record = self.register()
        labels = [ownership_labels(record, child["observer_id"]) for child in self.observers]
        self.assertTrue(all(item["liminal.observer.registry"] == record["registry_id"]
                            and item["liminal.observer.ring"] == record["ring_id"]
                            and item["liminal.observer.owner"] == record["ownership_token"] for item in labels))
        self.assertEqual({item["liminal.observer.role"] for item in labels}, {"reality", "continuity", "projection"})
        self.assertEqual(len({item["liminal.observer.observer"] for item in labels}), 3)
        with self.assertRaisesRegex(ObserverRegistryError, "BINDING_MISMATCH"):
            ownership_labels(record, "observer:other")


if __name__ == "__main__":
    unittest.main()
