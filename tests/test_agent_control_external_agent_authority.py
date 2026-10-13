"""Separate agent-profile identity, exact grants and lifecycle accounting."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_agent_authority import ExternalAgentAuthorityStore
from sdk.liminal_agent_control.external_agent_protocol import (
    AGENT_FIXTURES, AGENT_FIXTURE_SHA256, AGENT_PROFILE, AGENT_RECEIPT_DOMAIN,
    AGENT_RECEIPT_SCHEMA, agent_action, agent_plan, agent_spec, validate_agent_action,
    validate_agent_authorization, validate_agent_spec, verify_agent_receipt,
)
from sdk.liminal_agent_control.external_authority import ExternalAuthorityStore
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient
from sdk.liminal_agent_control.external_command_authority import ExternalCommandAuthorityStore
from sdk.liminal_agent_control.external_command_protocol import (
    COMMAND_RECEIPT_DOMAIN, COMMAND_RECEIPT_SCHEMA, command_action, command_spec,
    validate_command_action, validate_command_spec, verify_command_receipt,
)
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.observer_auth import _crypto
from sdk.liminal_agent_control.external_stop_demo import _Child


class ExternalAgentAuthorityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "agent-authority.sqlite"
        self.now = 100.0
        private, _ = _crypto()
        self.signer = private.from_private_bytes(b"s" * 32)
        self.pin = {"supervisor_id": "supervisor", "key_id": "supervisor-key",
                    "public_key": self.signer.public_key().public_bytes_raw().hex()}
        self.spec = agent_spec("agent", "sha256:" + "f" * 64, "/tmp/owned-agent")
        self.store = ExternalAgentAuthorityStore(self.path, supervisor_pin=self.pin, **self.options(create=True))
        self.store.create_root("root", "supervisor", "b" * 64, 10, 100)
        self.store.bind_execution("root", "worker")

    def options(self, **changes):
        value = {"authority_id": "authority", "key_id": "authority-key", "private_key": b"a" * 32,
                 "receipt_key": b"r" * 32, "clock": lambda: self.now, "create": False}
        value.update(changes)
        return value

    def reopen(self):
        return ExternalAgentAuthorityStore(self.path, supervisor_pin=self.pin, **self.options())

    def action(self, name="create", **changes):
        value = {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
                 "execution_id": "worker", "epoch": 1, "stage": "CREATE", "spec": self.spec}
        value.update(changes)
        return agent_action(**value)

    def grant(self, action):
        return {"action_digest": digest(action), "policy_version": "b" * 64,
                "expires_at": 180, "receiver_id": "supervisor"}

    def admit(self, action):
        grant = self.grant(action)
        permit = self.store.begin(action, grant)
        self.assertEqual(permit["status"], "PERMITTED")
        return grant, permit

    def lifecycle(self):
        create = self.action()
        cg, cp = self.admit(create)
        start = self.action("start", stage="START", parent_reservation_id=cp["reservation_id"], container_id="c" * 64)
        sg, sp = self.admit(start)
        return create, cg, cp, start, sg, sp

    def receipt(self, action, grant, permit, *, started=False, schema=AGENT_RECEIPT_SCHEMA,
                domain=AGENT_RECEIPT_DOMAIN, **changes):
        spec = action["arguments"]["spec"]
        value = {"schema": schema, "supervisor_id": "supervisor", "key_id": "supervisor-key",
            "reservation_id": permit["reservation_id"], **{field: action[field] for field in
            ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": digest(action), "authorization_digest": digest(grant),
            "stage": action["arguments"]["stage"], "command_id": spec["command_id"],
            "image_id": spec["image_id"], "container_id": "c" * 64, "plan_sha256": spec["plan_sha256"],
            "ownership_digest": "d" * 64, "create_confirmed": True, "callbacks_finished": True,
            "process_quiescent": True, "start_admitted": started,
            "start_outcome": "STARTED" if started else "NOT_STARTED", "business_effects": "NOT_ESTABLISHED",
            "observation_digest": "e" * 64, "observed_at": 100.0, "status": "QUIESCENT"}
        value.update(changes)
        return {**value, "signature": self.signer.sign(domain + canonical_bytes(value)).hex()}

    def test_spec_binds_all_twelve_fixture_modes_to_one_pinned_source(self):
        self.assertEqual(len(AGENT_FIXTURES), 12)
        for fixture in AGENT_FIXTURES:
            with self.subTest(fixture=fixture):
                spec = agent_spec("agent", self.spec["image_id"], self.spec["host_workspace"], fixture)
                self.assertEqual(validate_agent_spec(spec), spec)
                plan = agent_plan(spec)
                self.assertEqual(plan.argv, ("-I", "-u", "/workspace/external_agent_fixture.py", fixture))
                self.assertEqual(plan.plan_sha256, spec["plan_sha256"])
                self.assertEqual(spec["fixture_sha256"], AGENT_FIXTURE_SHA256)

    def test_fixture_bytes_match_frozen_protocol_pin(self):
        path = Path(__file__).parents[1] / "experiments/agent_control/external_agent_fixture.py"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), AGENT_FIXTURE_SHA256)

    def test_command_v1_and_agent_v1_actions_are_mutually_rejected(self):
        command = command_action(action_id="create", attempt_id="attempt:create", root_id="root",
            execution_id="worker", epoch=1, stage="CREATE",
            spec=command_spec("agent", self.spec["image_id"], self.spec["host_workspace"]))
        with self.assertRaises(ControlError):
            validate_agent_action(command)
        with self.assertRaises(ControlError):
            validate_command_action(self.action())
        with self.assertRaises(ControlError):
            validate_command_spec(self.spec)
        with self.assertRaises(ControlError):
            self.store.begin(command, self.grant(command))
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_unlisted_mode_and_arbitrary_shell_are_rejected(self):
        for fixture in ("positive", "descendant", "shell", "", 1, True, ["useful_completion"]):
            with self.subTest(fixture=fixture), self.assertRaises(ControlError):
                agent_spec("agent", self.spec["image_id"], self.spec["host_workspace"], fixture)
        changed = copy.deepcopy(self.spec)
        changed["argv"] = ["-c", "print('not granted')"]
        with self.assertRaises(ControlError):
            validate_agent_spec(changed)

    def test_source_image_mount_and_isolation_cannot_be_swapped(self):
        replacements = {"fixture_sha256": "0" * 64, "schema": "liminal-owned-docker-command-spec-v1",
            "image_id": "python:latest", "host_workspace": "/tmp/../owned-agent", "entrypoint": "sh",
            "environment_policy": "injected-secrets", "log_driver": "json-file", "working_directory": "/tmp"}
        for field, replacement in replacements.items():
            with self.subTest(field=field), self.assertRaises(ControlError):
                validate_agent_spec({**self.spec, field: replacement})
        for path, replacement in (("network_mode", "host"), ("read_only_root", False), ("pids_limit", 65)):
            changed = copy.deepcopy(self.spec)
            changed["isolation"][path] = replacement
            with self.subTest(path=path), self.assertRaises(ControlError):
                validate_agent_spec(changed)
        changed = copy.deepcopy(self.spec)
        changed["workspace_mount"]["read_only"] = False
        with self.assertRaises(ControlError):
            validate_agent_spec(changed)

    def test_epoch_and_derived_numeric_values_require_exact_types(self):
        for epoch in (True, 1.0, 0, -1):
            with self.subTest(epoch=epoch), self.assertRaises(ControlError):
                validate_agent_action({**self.action(), "epoch": epoch})
        with self.assertRaises(ControlError):
            validate_agent_spec({**self.spec, "timeout_seconds": 30.0})
        action = self.action()
        for field, value in (("expires_at", True), ("expires_at", float("nan")),
                             ("action_digest", "0" * 64), ("receiver_id", "other")):
            with self.subTest(field=field, value=value), self.assertRaises(ControlError):
                validate_agent_authorization(action, {**self.grant(action), field: value}, "supervisor")

    def test_validated_action_is_frozen_before_caller_mutation(self):
        proposed = self.action()
        frozen = validate_agent_action(proposed)
        proposed["arguments"]["spec"]["argv"].append("unapproved")
        self.assertEqual(frozen["arguments"]["spec"]["argv"], self.spec["argv"])

    def test_two_stage_stop_waits_for_same_positive_final_lifecycle(self):
        create, cg, cp, start, sg, sp = self.lifecycle()
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.store.finish(sp["reservation_id"], self.receipt(start, sg, sp, started=True))
        self.assertEqual(self.store.status("root")["status"], "STOPPING")
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        self.assertEqual(self.store.status("root")["status"], "STOPPED")
        self.assertEqual(self.store.status("root")["committed_count"], 2)

    def test_stop_before_create_admits_no_docker_stage(self):
        self.store.stop("root")
        action = self.action()
        self.assertEqual(self.store.begin(action, self.grant(action))["status"], "DENIED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_stop_between_stages_does_not_create_start_permission(self):
        create = self.action()
        cg, cp = self.admit(create)
        self.store.stop("root")
        start = self.action("start", stage="START", parent_reservation_id=cp["reservation_id"], container_id="c" * 64)
        self.assertEqual(self.store.begin(start, self.grant(start))["status"], "DENIED")
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        self.assertEqual(self.store.status("root")["status"], "STOPPED")

    def test_restart_preserves_consumption_and_stop(self):
        create = self.action()
        cg, cp = self.admit(create)
        reopened = self.reopen()
        self.assertEqual(reopened.begin(create, cg)["status"], "UNKNOWN")
        reopened.stop("root")
        reopened.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        self.assertEqual(self.reopen().begin(create, cg)["status"], "CONSUMED")
        self.assertEqual(self.reopen().status("root")["status"], "STOPPED")

    def test_float_reencoding_does_not_restore_consumed_grant(self):
        action = self.action()
        grant, _ = self.admit(action)
        result = self.store.begin(action, {**grant, "expires_at": 180.0})
        self.assertEqual(result["reason"], "EXTERNAL_AUTHORITY_REUSE_MISMATCH")
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_new_action_ids_cannot_duplicate_create_or_start(self):
        _, _, cp, _, _, _ = self.lifecycle()
        create = self.action("create-duplicate")
        self.assertEqual(self.store.begin(create, self.grant(create))["reason"], "EXTERNAL_COMMAND_CREATE_ALREADY_ADMITTED")
        start = self.action("start-duplicate", stage="START", parent_reservation_id=cp["reservation_id"], container_id="c" * 64)
        self.assertEqual(self.store.begin(start, self.grant(start))["reason"], "EXTERNAL_COMMAND_START_ALREADY_ADMITTED")
        self.assertEqual(self.store.status("root")["issued_count"], 2)

    def test_missing_cross_root_and_wrong_execution_parent_are_denied(self):
        _, cp = self.admit(self.action())
        self.store.bind_execution("root", "other")
        self.store.create_root("other-root", "supervisor", "b" * 64, 4, 100)
        self.store.bind_execution("other-root", "other-worker")
        for name, changes in (("missing", {"parent_reservation_id": "reservation:missing"}),
            ("other-execution", {"execution_id": "other"}),
            ("other-root", {"root_id": "other-root", "execution_id": "other-worker"})):
            arguments = {"stage": "START", "parent_reservation_id": cp["reservation_id"], "container_id": "c" * 64, **changes}
            action = self.action(name, **arguments)
            result = self.store.begin(action, self.grant(action))
            self.assertIn(result["reason"], {"EXTERNAL_COMMAND_PARENT_NOT_PENDING", "EXTERNAL_COMMAND_PARENT_BINDING_MISMATCH"})

    def test_competing_start_admissions_are_atomic(self):
        _, cp = self.admit(self.action())
        barrier = threading.Barrier(2)
        def begin(name):
            store = self.reopen()
            action = self.action(name, stage="START", parent_reservation_id=cp["reservation_id"], container_id="c" * 64)
            barrier.wait()
            return store.begin(action, self.grant(action))
        with ThreadPoolExecutor(max_workers=2) as pool:
            left, right = pool.submit(begin, "left"), pool.submit(begin, "right")
            values = [left.result(), right.result()]
        self.assertEqual(sorted(value["status"] for value in values), ["DENIED", "PERMITTED"])

    def test_create_cannot_claim_no_start_after_start_admission(self):
        create, cg, cp, _, _, _ = self.lifecycle()
        with self.assertRaisesRegex(ControlError, "START_ACCOUNTING_MISMATCH"):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        self.assertEqual(self.store.status("root")["pending_count"], 2)

    def test_lifecycle_receipts_require_same_owned_object_and_census(self):
        create, cg, cp, start, sg, sp = self.lifecycle()
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        for field, value in (("container_id", "0" * 64), ("ownership_digest", "0" * 64),
                             ("observation_digest", "0" * 64), ("observed_at", 101.0)):
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.store.finish(sp["reservation_id"], self.receipt(start, sg, sp, started=True, **{field: value}))

    def test_claimed_process_zero_or_callback_timeout_cannot_settle(self):
        create = self.action()
        grant, permit = self.admit(create)
        for field, value in (("callbacks_finished", False), ("process_quiescent", False),
            ("create_confirmed", False), ("start_outcome", "UNKNOWN"), ("effect_count", 0),
            ("business_effects", "NONE"), ("process_quiescent", 1)):
            receipt = self.receipt(create, grant, permit, **{field: value})
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], receipt)
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")

    def test_other_profiles_and_receipt_domains_cannot_settle_agent(self):
        create = self.action()
        grant, permit = self.admit(create)
        valid = self.receipt(create, grant, permit)
        self.assertTrue(verify_agent_receipt(valid, self.pin))
        self.assertFalse(verify_command_receipt(valid, self.pin))
        for schema, domain in ((COMMAND_RECEIPT_SCHEMA, COMMAND_RECEIPT_DOMAIN),
                               (AGENT_RECEIPT_SCHEMA, COMMAND_RECEIPT_DOMAIN),
                               (COMMAND_RECEIPT_SCHEMA, AGENT_RECEIPT_DOMAIN)):
            receipt = self.receipt(create, grant, permit, schema=schema, domain=domain)
            with self.subTest(schema=schema, domain=domain), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], receipt)
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_exact_action_grant_reservation_and_pin_bindings_are_mandatory(self):
        create = self.action()
        grant, permit = self.admit(create)
        for field, value in (("action_digest", "0" * 64), ("authorization_digest", "0" * 64),
            ("reservation_id", "wrong"), ("action_id", "wrong"), ("execution_id", "other"),
            ("epoch", 2), ("plan_sha256", "0" * 64), ("supervisor_id", "other")):
            with self.subTest(field=field), self.assertRaises(ControlError):
                self.store.finish(permit["reservation_id"], self.receipt(create, grant, permit, **{field: value}))

    def test_agent_database_cannot_reopen_as_command_records_or_network(self):
        for store_class in (ExternalCommandAuthorityStore, ExternalAuthorityStore):
            kwargs = {"supervisor_pin": self.pin} if store_class is ExternalCommandAuthorityStore else {}
            with self.subTest(store_class=store_class), self.assertRaises(ControlError):
                store_class(self.path, **kwargs, **self.options())
        endpoint = {"endpoint_id": self.pin["supervisor_id"], "key_id": self.pin["key_id"], "public_key": self.pin["public_key"]}
        with self.assertRaises(ControlError):
            ExternalNetworkAuthorityStore(self.path, endpoint_pin=endpoint, **self.options())
        command_path = self.path.with_name("command.sqlite")
        ExternalCommandAuthorityStore(command_path, supervisor_pin=self.pin, **self.options(create=True))
        with self.assertRaises(ControlError):
            ExternalAgentAuthorityStore(command_path, supervisor_pin=self.pin, **self.options())
        records_path = self.path.with_name("records.sqlite")
        ExternalAuthorityStore(records_path, **self.options(create=True))
        with self.assertRaises(ControlError):
            ExternalAgentAuthorityStore(records_path, supervisor_pin=self.pin, **self.options())
        network_path = self.path.with_name("network.sqlite")
        ExternalNetworkAuthorityStore(network_path, endpoint_pin=endpoint, **self.options(create=True))
        with self.assertRaises(ControlError):
            ExternalAgentAuthorityStore(network_path, supervisor_pin=self.pin, **self.options())

    def test_live_pin_or_reopen_pin_drift_is_not_authority(self):
        wrong = {**self.pin, "key_id": "other-key"}
        with self.assertRaises(ControlError):
            ExternalAgentAuthorityStore(self.path, supervisor_pin=wrong, **self.options())
        self.store._supervisor_pin = wrong
        with self.assertRaises(ControlError):
            self.store.status("root")

    def test_supervisor_and_authority_signers_cannot_be_same(self):
        private, _ = _crypto()
        same = {**self.pin, "public_key": private.from_private_bytes(b"a" * 32).public_key().public_bytes_raw().hex()}
        with self.assertRaisesRegex(ControlError, "KEY_MUST_DIFFER"):
            ExternalAgentAuthorityStore(self.path.with_name("same.sqlite"), supervisor_pin=same, **self.options(create=True))

    def service_arguments(self, *, with_pin=True):
        directory = self.path.parent
        arguments = ["--profile", AGENT_PROFILE, "--db", str(directory / "child-authority.sqlite"),
            "--authority-id", "authority", "--key-id", "authority-key", "--initialize"]
        for option, name, key in (("signing-key-file", "signer", b"a" * 32),
            ("receipt-key-file", "receipt", b"r" * 32), ("operator-key-file", "admin", b"o" * 32),
            ("receiver-key-file", "receiver", b"q" * 32)):
            path = directory / (name + ".key")
            path.write_bytes(key)
            path.chmod(0o600)
            arguments += ["--" + option, str(path)]
        if with_pin:
            pin_file = directory / "supervisor-pin.json"
            pin_file.write_bytes(canonical_bytes(self.pin))
            arguments += ["--supervisor-pin-file", str(pin_file)]
        return arguments

    def test_authority_cli_persists_agent_profile_and_accepts_only_agent_ir(self):
        child = _Child("sdk.liminal_agent_control.external_authority_service", self.service_arguments())
        self.addCleanup(child.stop)
        startup = child.start()
        admin = HTTPExternalAuthorityClient(startup["url"], b"o" * 32, startup["pin"], role="admin")
        receiver = HTTPExternalAuthorityClient(startup["url"], b"q" * 32, startup["pin"])
        admin.create_root("root", "supervisor", "b" * 64, 2, 100)
        admin.bind_execution("root", "worker")
        action = self.action()
        grant = {**self.grant(action), "expires_at": time.time() + 30}
        self.assertEqual(receiver.begin(action, grant)["status"], "PERMITTED")
        command = command_action(action_id="other", attempt_id="attempt:other", root_id="root",
            execution_id="worker", epoch=1, stage="CREATE",
            spec=command_spec("other", self.spec["image_id"], self.spec["host_workspace"]))
        with self.assertRaises(ControlError):
            receiver.begin(command, {**self.grant(command), "expires_at": time.time() + 30})
        self.assertEqual(admin.status("root")["issued_count"], 1)
        with sqlite3.connect(self.path.parent / "child-authority.sqlite") as database:
            meta = dict(database.execute("SELECT key,value FROM external_meta"))
        self.assertEqual(meta["profile"], AGENT_PROFILE)
        self.assertTrue(child.stop()["reaped"])

    def test_authority_cli_agent_profile_requires_independent_supervisor_pin(self):
        result = subprocess.run([sys.executable, "-m", "sdk.liminal_agent_control.external_authority_service",
            *self.service_arguments(with_pin=False)], cwd=Path(__file__).parents[1],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.path.parent / "child-authority.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
