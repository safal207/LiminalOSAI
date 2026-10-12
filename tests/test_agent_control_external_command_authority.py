"""External CREATE/START one-shot accounting and signed-quiescence regressions."""
from __future__ import annotations

import copy
import hashlib
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sdk.liminal_agent_control.authority import ControlError, canonical_bytes, digest
from sdk.liminal_agent_control.external_authority import ExternalAuthorityStore
from sdk.liminal_agent_control.external_authority_service import HTTPExternalAuthorityClient, make_server
from sdk.liminal_agent_control.external_checkpoint import verify_checkpoint_chain
from sdk.liminal_agent_control.external_command_authority import ExternalCommandAuthorityStore
from sdk.liminal_agent_control.external_command_protocol import (
    COMMAND_FIXTURE_SHA256, COMMAND_RECEIPT_DOMAIN, COMMAND_RECEIPT_SCHEMA,
    command_action, command_plan, command_spec, validate_command_action,
    validate_command_authorization, validate_command_spec, validate_supervisor_pin,
    verify_command_receipt,
)
from sdk.liminal_agent_control.external_network_authority import ExternalNetworkAuthorityStore
from sdk.liminal_agent_control.observer_auth import _crypto


AUTHORITY_KEY = b"a" * 32
SUPERVISOR_KEY = b"s" * 32
RECEIPT_KEY = b"r" * 32
OPERATOR_KEY = b"o" * 32
REQUEST_KEY = b"q" * 32
POLICY = "b" * 64
CONTAINER = "c" * 64


def pin(key=SUPERVISOR_KEY):
    private, _ = _crypto()
    return {"supervisor_id": "supervisor", "key_id": "supervisor-key",
            "public_key": private.from_private_bytes(key).public_key().public_bytes_raw().hex()}


class ExternalCommandAuthorityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "authority.sqlite"
        self.now = 100.0
        self.pin = pin()
        self.spec = command_spec("command", "sha256:" + "f" * 64, "/tmp/owned")
        self.store = self.reopen(create=True)
        self.store.create_root("root", "supervisor", POLICY, 10, 100)
        self.store.bind_execution("root", "worker")

    def options(self, **changes):
        result = {"authority_id": "authority", "key_id": "authority-key", "private_key": AUTHORITY_KEY,
                  "receipt_key": RECEIPT_KEY, "clock": lambda: self.now, "create": False}
        result.update(changes)
        return result

    def reopen(self, **changes):
        supervisor_pin = changes.pop("supervisor_pin", self.pin)
        return ExternalCommandAuthorityStore(self.path, supervisor_pin=supervisor_pin, **self.options(**changes))

    def action(self, name="create", *, stage="CREATE", parent=None, container=None, **changes):
        values = {"action_id": name, "attempt_id": "attempt:" + name, "root_id": "root",
                  "execution_id": "worker", "epoch": 1, "stage": stage, "spec": self.spec,
                  "parent_reservation_id": parent, "container_id": container}
        values.update(changes)
        return command_action(**values)

    def grant(self, action, **changes):
        result = {"action_digest": digest(action), "receiver_id": "supervisor", "policy_version": POLICY,
                  "expires_at": 180}
        result.update(changes)
        return result

    def admit(self, action):
        authorization = self.grant(action)
        permit = self.store.begin(action, authorization)
        self.assertEqual(permit["status"], "PERMITTED")
        return authorization, permit

    def lifecycle(self):
        create = self.action()
        create_grant, create_permit = self.admit(create)
        start = self.action("start", stage="START", parent=create_permit["reservation_id"], container=CONTAINER)
        start_grant, start_permit = self.admit(start)
        return create, create_grant, create_permit, start, start_grant, start_permit

    def receipt(self, action, authorization, permit, *, started=False, key=SUPERVISOR_KEY, **changes):
        spec = action["arguments"]["spec"]
        body = {"schema": COMMAND_RECEIPT_SCHEMA, "supervisor_id": "supervisor", "key_id": "supervisor-key",
            "reservation_id": permit["reservation_id"], **{k: action[k] for k in
            ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": digest(action), "authorization_digest": digest(authorization),
            "stage": action["arguments"]["stage"], "command_id": spec["command_id"], "image_id": spec["image_id"],
            "container_id": CONTAINER, "plan_sha256": spec["plan_sha256"], "ownership_digest": "d" * 64,
            "create_confirmed": True, "callbacks_finished": True, "process_quiescent": True,
            "start_admitted": started, "start_outcome": "STARTED" if started else "NOT_STARTED",
            "business_effects": "NOT_ESTABLISHED", "observation_digest": "e" * 64,
            "observed_at": 100.0, "status": "QUIESCENT"}
        body.update(changes)
        private, _ = _crypto()
        return {**body, "signature": private.from_private_bytes(key).sign(COMMAND_RECEIPT_DOMAIN + canonical_bytes(body)).hex()}

    def test_two_stages_remain_pending_until_lifecycle_quiescence(self):
        create, cg, cp, start, sg, sp = self.lifecycle()
        self.assertEqual(self.store.status("root")["pending_count"], 2)
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        result = self.store.finish(sp["reservation_id"], self.receipt(start, sg, sp, started=True))
        self.assertEqual((result["status"], result["outcome"]), ("SETTLED", "COMMITTED"))
        self.assertEqual(result["receipt"]["status"], "QUIESCENT")
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        self.assertEqual(self.store.status("root")["committed_count"], 2)

    def test_terminal_stages_can_settle_in_reverse_order(self):
        create, cg, cp, start, sg, sp = self.lifecycle()
        self.store.stop("root")
        self.store.finish(sp["reservation_id"], self.receipt(start, sg, sp, started=True))
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")

    def test_stop_before_create_prevents_both_stages(self):
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")
        create = self.action()
        self.assertEqual(self.store.begin(create, self.grant(create))["status"], "DENIED")
        self.assertEqual(self.store.status("root")["issued_count"], 0)

    def test_stop_between_create_and_start_blocks_start_but_can_settle_owned_create(self):
        create = self.action()
        cg, cp = self.admit(create)
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")
        start = self.action("start", stage="START", parent=cp["reservation_id"], container=CONTAINER)
        self.assertEqual(self.store.begin(start, self.grant(start))["status"], "DENIED")
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        self.assertEqual(self.store.stop("root")["status"], "STOPPED")

    def test_pending_duplicate_and_restart_never_reissue_permit(self):
        create = self.action()
        cg, cp = self.admit(create)
        result = self.reopen().begin(create, cg)
        self.assertEqual((result["status"], result["reservation_id"]), ("UNKNOWN", cp["reservation_id"]))
        self.now = 10000
        self.assertEqual(self.store.query(create["action_id"])["status"], "UNKNOWN")
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")

    def test_action_and_attempt_consumption_are_exact_and_cumulative(self):
        create = self.action()
        cg, _ = self.admit(create)
        changed = self.action("different", attempt_id=create["attempt_id"])
        self.assertEqual(self.store.begin(changed, self.grant(changed))["reason"], "EXTERNAL_AUTHORITY_REUSE_MISMATCH")
        self.assertEqual(self.store.begin(create, {**cg, "expires_at": 180.0})["reason"], "EXTERNAL_AUTHORITY_REUSE_MISMATCH")
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_command_cannot_admit_another_create_using_a_new_action_id(self):
        self.admit(self.action())
        extra = self.action("extra-create")
        result = self.store.begin(extra, self.grant(extra))
        self.assertEqual(result["reason"], "EXTERNAL_COMMAND_CREATE_ALREADY_ADMITTED")
        self.assertEqual(self.store.status("root")["issued_count"], 1)

    def test_start_without_parent_or_with_terminal_parent_is_denied(self):
        missing = self.action("missing", stage="START", parent="reservation:unknown", container=CONTAINER)
        self.assertEqual(self.store.begin(missing, self.grant(missing))["reason"], "EXTERNAL_COMMAND_PARENT_NOT_PENDING")
        create = self.action()
        cg, cp = self.admit(create)
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        start = self.action("start", stage="START", parent=cp["reservation_id"], container=CONTAINER)
        self.assertEqual(self.store.begin(start, self.grant(start))["reason"], "EXTERNAL_COMMAND_PARENT_NOT_PENDING")

    def test_start_requires_matching_execution_and_exact_spec(self):
        create = self.action()
        _, cp = self.admit(create)
        self.store.bind_execution("root", "other")
        for name, changes in (("worker-swap", {"execution_id": "other"}),
                              ("spec-swap", {"spec": command_spec("other-command", self.spec["image_id"], "/tmp/owned")})):
            start = self.action(name, stage="START", parent=cp["reservation_id"], container=CONTAINER, **changes)
            self.assertEqual(self.store.begin(start, self.grant(start))["reason"], "EXTERNAL_COMMAND_PARENT_BINDING_MISMATCH")

    def test_start_cannot_bind_parent_in_another_root(self):
        create = self.action()
        _, cp = self.admit(create)
        self.store.create_root("other-root", "supervisor", POLICY, 2, 100)
        self.store.bind_execution("other-root", "other-worker")
        start = self.action("start", stage="START", parent=cp["reservation_id"], container=CONTAINER,
                            root_id="other-root", execution_id="other-worker")
        self.assertEqual(self.store.begin(start, self.grant(start))["reason"], "EXTERNAL_COMMAND_PARENT_BINDING_MISMATCH")

    def test_start_is_admitted_at_most_once_even_with_distinct_action_ids(self):
        _, _, cp, _, _, _ = self.lifecycle()
        replay = self.action("other-start", stage="START", parent=cp["reservation_id"], container=CONTAINER)
        self.assertEqual(self.store.begin(replay, self.grant(replay))["reason"], "EXTERNAL_COMMAND_START_ALREADY_ADMITTED")
        self.assertEqual(self.store.status("root")["issued_count"], 2)

    def test_start_parent_checks_and_consumption_are_atomic_under_race(self):
        _, cp = self.admit(self.action())
        barrier = threading.Barrier(2)
        def begin(name):
            local = self.reopen()
            action = self.action(name, stage="START", parent=cp["reservation_id"], container=CONTAINER)
            barrier.wait()
            return local.begin(action, self.grant(action))
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(begin, "start-a")
            b = pool.submit(begin, "start-b")
            results = [a.result(), b.result()]
        self.assertEqual(sorted(r["status"] for r in results), ["DENIED", "PERMITTED"])
        self.assertEqual(self.store.status("root")["issued_count"], 2)

    def test_start_consumes_separate_budget(self):
        self.store.create_root("small", "supervisor", POLICY, 1, 100)
        self.store.bind_execution("small", "small-worker")
        create = self.action("small-create", root_id="small", execution_id="small-worker")
        _, cp = self.admit(create)
        start = self.action("small-start", stage="START", parent=cp["reservation_id"], container=CONTAINER,
                            root_id="small", execution_id="small-worker")
        self.assertEqual(self.store.begin(start, self.grant(start))["reason"], "EXTERNAL_AUTHORITY_BUDGET_EXHAUSTED")
        self.assertEqual(self.store.status("small")["pending_count"], 1)

    def test_no_start_terminal_is_rejected_after_start_admission(self):
        create, cg, cp, _, _, _ = self.lifecycle()
        with self.assertRaisesRegex(ControlError, "START_ACCOUNTING_MISMATCH"):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        self.assertEqual(self.store.status("root")["pending_count"], 2)

    def test_started_terminal_requires_actual_external_start_admission(self):
        create = self.action()
        cg, cp = self.admit(create)
        with self.assertRaisesRegex(ControlError, "START_ACCOUNTING_MISMATCH"):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_create_terminal_must_bind_actual_started_container(self):
        create, cg, cp, _, _, _ = self.lifecycle()
        with self.assertRaisesRegex(ControlError, "LIFECYCLE_BINDING_MISMATCH"):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True, container_id="0" * 64))

    def test_start_and_create_terminal_must_describe_same_final_census(self):
        create, cg, cp, start, sg, sp = self.lifecycle()
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, started=True))
        for field, value in (("ownership_digest", "0" * 64), ("observation_digest", "0" * 64), ("observed_at", 101.0)):
            with self.subTest(field=field), self.assertRaisesRegex(ControlError, "LIFECYCLE_BINDING_MISMATCH"):
                self.store.finish(sp["reservation_id"], self.receipt(start, sg, sp, started=True, **{field: value}))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_stale_no_start_terminal_cannot_race_into_unaccounted_start(self):
        create = self.action()
        cg, cp = self.admit(create)
        start = self.action("start", stage="START", parent=cp["reservation_id"], container=CONTAINER)
        barrier = threading.Barrier(2)
        def begin():
            local = self.reopen()
            barrier.wait()
            return local.begin(start, self.grant(start))
        def finish():
            local = self.reopen()
            barrier.wait()
            try:
                return local.finish(cp["reservation_id"], self.receipt(create, cg, cp))
            except ControlError:
                return {"status": "REJECTED"}
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(begin), pool.submit(finish)
            admitted, settled = a.result(), b.result()
        self.assertIn((admitted["status"], settled["status"]), (("PERMITTED", "REJECTED"), ("DENIED", "SETTLED")))

    def test_terminal_signature_and_exact_action_grant_binding_are_required(self):
        create = self.action()
        cg, cp = self.admit(create)
        for changes in ({"action_digest": "0" * 64}, {"authorization_digest": "0" * 64},
                        {"reservation_id": "wrong"}, {"action_id": "wrong"}, {"epoch": 2},
                        {"plan_sha256": "0" * 64}, {"image_id": "sha256:" + "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, **changes))
        with self.assertRaises(ControlError):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, key=b"x" * 32))
        self.assertEqual(self.store.status("root")["pending_count"], 1)

    def test_uncertain_create_start_or_callback_cannot_settle(self):
        create = self.action()
        cg, cp = self.admit(create)
        for changes in ({"create_confirmed": False}, {"callbacks_finished": False}, {"process_quiescent": False},
                        {"start_outcome": "UNKNOWN"}, {"status": "DENIED"}, {"effect_count": 0}):
            with self.subTest(changes=changes), self.assertRaises(ControlError):
                self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, **changes))
        self.assertEqual(self.store.stop("root")["status"], "STOP_PENDING")

    def test_terminal_is_immutable_and_consumption_survives_reopen(self):
        create = self.action()
        cg, cp = self.admit(create)
        terminal = self.receipt(create, cg, cp)
        first = self.store.finish(cp["reservation_id"], terminal)
        self.assertEqual(self.reopen().finish(cp["reservation_id"], terminal), first)
        with self.assertRaises(ControlError):
            self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp, observed_at=101.0))
        self.assertEqual(self.reopen().begin(create, cg)["status"], "CONSUMED")

    def test_profile_reopen_cannot_substitute_records_or_network(self):
        with self.assertRaises(ControlError):
            ExternalAuthorityStore(self.path, **self.options())
        endpoint_pin = {"endpoint_id": "supervisor", "key_id": self.pin["key_id"], "public_key": self.pin["public_key"]}
        with self.assertRaises(ControlError):
            ExternalNetworkAuthorityStore(self.path, endpoint_pin=endpoint_pin, **self.options())
        records_path = self.path.with_name("records.sqlite")
        ExternalAuthorityStore(records_path, **self.options(create=True))
        with self.assertRaises(ControlError):
            ExternalCommandAuthorityStore(records_path, supervisor_pin=self.pin, **self.options())

    def test_live_pin_mutation_or_reopen_pin_drift_is_rejected(self):
        with self.assertRaises(ControlError):
            self.reopen(supervisor_pin=pin(b"x" * 32))
        self.store._supervisor_pin = pin(b"x" * 32)
        with self.assertRaises(ControlError):
            self.store.status("root")

    def test_supervisor_and_authority_signers_must_differ(self):
        with self.assertRaisesRegex(ControlError, "KEY_MUST_DIFFER"):
            ExternalCommandAuthorityStore(self.path.with_name("same.sqlite"), supervisor_pin=pin(AUTHORITY_KEY),
                                          **self.options(create=True))
        with self.assertRaisesRegex(ControlError, "IDENTITY_MISMATCH"):
            self.store.create_root("bad-root", "other-supervisor", POLICY, 2, 100)

    def test_original_authority_restart_keeps_stop_and_consumption(self):
        create = self.action()
        cg, cp = self.admit(create)
        self.store.stop("root")
        self.store.finish(cp["reservation_id"], self.receipt(create, cg, cp))
        reopened = self.reopen()
        self.assertEqual(reopened.stop("root")["status"], "STOPPED")
        self.assertEqual(reopened.begin(create, cg)["status"], "CONSUMED")
        authority_pin = reopened.pin()
        chain = verify_checkpoint_chain(reopened.checkpoints(), **authority_pin, signer_id=authority_pin["authority_id"])
        self.assertEqual(chain["verification_status"], "LOCAL_SIGNATURE_ONLY")
        self.assertFalse(chain["execution_authorized"])

    def test_http_service_exposes_same_bound_profile_without_operator_role_for_worker(self):
        server = make_server(self.store, OPERATOR_KEY, REQUEST_KEY, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:" + str(server.server_address[1])
            worker = HTTPExternalAuthorityClient(url, REQUEST_KEY, self.store.pin())
            admin = HTTPExternalAuthorityClient(url, OPERATOR_KEY, self.store.pin(), role="admin")
            create = self.action()
            cg = self.grant(create)
            permit = worker.begin(create, cg)
            self.assertEqual(permit["status"], "PERMITTED")
            with self.assertRaises(ControlError):
                worker.stop("root")
            self.assertEqual(admin.stop("root")["status"], "STOP_PENDING")
            worker.finish(permit["reservation_id"], self.receipt(create, cg, permit))
            self.assertEqual(admin.stop("root")["status"], "STOPPED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


class ExternalCommandProtocolTests(unittest.TestCase):
    def setUp(self):
        private, _ = _crypto()
        self.signer = private.from_private_bytes(b"s" * 32)
        self.pin = {"supervisor_id": "supervisor", "key_id": "supervisor-key",
                    "public_key": self.signer.public_key().public_bytes_raw().hex()}
        self.spec = command_spec("command", "sha256:" + "f" * 64, "/tmp/owned")
        self.action = command_action(action_id="create", attempt_id="create-attempt", root_id="root",
            execution_id="worker", epoch=1, stage="CREATE", spec=self.spec)
        self.grant = {"action_digest": digest(self.action), "policy_version": "b" * 64,
                      "expires_at": 180, "receiver_id": "supervisor"}

    def terminal(self, **changes):
        body = {"schema": COMMAND_RECEIPT_SCHEMA, "supervisor_id": "supervisor", "key_id": "supervisor-key",
            "reservation_id": "reservation:1", **{k: self.action[k] for k in
            ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
            "action_digest": digest(self.action), "authorization_digest": digest(self.grant),
            "stage": "CREATE", "command_id": self.spec["command_id"], "image_id": self.spec["image_id"],
            "container_id": "c" * 64, "plan_sha256": self.spec["plan_sha256"], "ownership_digest": "d" * 64,
            "create_confirmed": True, "callbacks_finished": True, "process_quiescent": True,
            "start_admitted": False, "start_outcome": "NOT_STARTED", "business_effects": "NOT_ESTABLISHED",
            "observation_digest": "e" * 64, "observed_at": 100.0, "status": "QUIESCENT"}
        body.update(changes)
        return {**body, "signature": self.signer.sign(COMMAND_RECEIPT_DOMAIN + canonical_bytes(body)).hex()}

    def test_spec_and_plan_share_exact_immutable_identity(self):
        self.assertEqual(command_plan(self.spec).plan_sha256, self.spec["plan_sha256"])
        self.assertEqual(command_plan(self.spec).argv, tuple(self.spec["argv"]))
        self.assertEqual(validate_command_spec(self.spec), self.spec)

    def test_fixture_source_bytes_match_pinned_constant(self):
        fixture = Path(__file__).parents[1] / "experiments/agent_control/external_command_fixture.py"
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), COMMAND_FIXTURE_SHA256)

    def test_spec_cannot_change_argv(self):
        changed = copy.deepcopy(self.spec)
        changed["argv"] = ["-c", "print('unapproved')"]
        with self.assertRaises(ControlError):
            validate_command_spec(changed)

    def test_spec_cannot_change_isolation_or_mount(self):
        for key, value in (("network_mode", "host"), ("read_only_root", False), ("pids_limit", 65)):
            changed = copy.deepcopy(self.spec)
            changed["isolation"][key] = value
            with self.subTest(key=key), self.assertRaises(ControlError):
                validate_command_spec(changed)
        changed = copy.deepcopy(self.spec)
        changed["workspace_mount"]["read_only"] = False
        with self.assertRaises(ControlError):
            validate_command_spec(changed)

    def test_spec_cannot_substitute_fixture_hash(self):
        changed = {**self.spec, "fixture_sha256": "0" * 64}
        with self.assertRaises(ControlError):
            validate_command_spec(changed)

    def test_spec_rejects_unapproved_entrypoint_environment_workdir_and_log(self):
        for field, value in (("entrypoint", "sh"), ("environment_policy", "caller-env"),
                             ("working_directory", "/tmp"), ("log_driver", "json-file")):
            with self.subTest(field=field), self.assertRaises(ControlError):
                validate_command_spec({**self.spec, field: value})

    def test_spec_numeric_types_are_canonical(self):
        with self.assertRaises(ControlError):
            validate_command_spec({**self.spec, "timeout_seconds": 30.0})
        changed = copy.deepcopy(self.spec)
        changed["workspace_mount"]["read_only"] = 1
        with self.assertRaises(ControlError):
            validate_command_spec(changed)

    def test_only_positive_and_descendant_are_exposed(self):
        self.assertEqual(command_spec("command", self.spec["image_id"], "/tmp/owned", "descendant")["fixture"], "descendant")
        for mode in ("sentinel", "custom", "", 1):
            with self.subTest(mode=mode), self.assertRaises(ControlError):
                command_spec("command", self.spec["image_id"], "/tmp/owned", mode)

    def test_image_and_workspace_require_fixed_normalized_forms(self):
        for image, workspace in (("python:latest", "/tmp/owned"), ("sha256:" + "F" * 64, "/tmp/owned"),
                                 (self.spec["image_id"], "relative"), (self.spec["image_id"], "/tmp/../owned"),
                                 (self.spec["image_id"], "/tmp,owned")):
            with self.subTest(image=image, workspace=workspace), self.assertRaises(ControlError):
                command_spec("command", image, workspace)

    def test_action_exact_shape_and_positive_integer_epoch(self):
        for value in ({**self.action, "extra": True}, {**self.action, "target": "records"},
                      {**self.action, "epoch": True}, {**self.action, "epoch": 1.0}):
            with self.subTest(value=value), self.assertRaises(ControlError):
                validate_command_action(value)

    def test_create_cannot_carry_parent_or_container(self):
        for field, value in (("parent_reservation_id", "reservation:1"), ("container_id", "c" * 64)):
            changed = copy.deepcopy(self.action)
            changed["arguments"][field] = value
            with self.subTest(field=field), self.assertRaises(ControlError):
                validate_command_action(changed)

    def test_start_requires_exact_parent_and_immutable_container(self):
        start = command_action(action_id="start", attempt_id="start-attempt", root_id="root",
            execution_id="worker", epoch=1, stage="START", spec=self.spec,
            parent_reservation_id="reservation:1", container_id="c" * 64)
        self.assertEqual(validate_command_action(start), start)
        for field, value in (("parent_reservation_id", None), ("container_id", "name"), ("container_id", "C" * 64)):
            changed = copy.deepcopy(start)
            changed["arguments"][field] = value
            with self.subTest(field=field), self.assertRaises(ControlError):
                validate_command_action(changed)

    def test_action_and_spec_are_copied_before_mutation(self):
        copied = validate_command_action(self.action)
        self.action["arguments"]["spec"]["argv"].append("extra")
        self.assertNotEqual(copied["arguments"]["spec"]["argv"], self.action["arguments"]["spec"]["argv"])

    def test_grant_requires_exact_action_and_supervisor(self):
        self.assertEqual(validate_command_authorization(self.action, self.grant, "supervisor"), self.grant)
        for changed in ({**self.grant, "action_digest": "0" * 64}, {**self.grant, "receiver_id": "other"},
                        {**self.grant, "expires_at": True}, {**self.grant, "extra": 1}):
            with self.subTest(changed=changed), self.assertRaises(ControlError):
                validate_command_authorization(self.action, changed, "supervisor")

    def test_pin_exact_identity_and_lowercase_key(self):
        self.assertEqual(validate_supervisor_pin(self.pin), self.pin)
        for changed in ({**self.pin, "extra": 1}, {**self.pin, "public_key": "X" * 64},
                        {**self.pin, "supervisor_id": ""}):
            with self.subTest(changed=changed), self.assertRaises(ControlError):
                validate_supervisor_pin(changed)

    def test_signed_quiescence_is_not_business_effect_success(self):
        receipt = self.terminal()
        self.assertTrue(verify_command_receipt(receipt, self.pin))
        self.assertEqual(receipt["business_effects"], "NOT_ESTABLISHED")
        self.assertNotIn("effect_count", receipt)
        self.assertFalse(verify_command_receipt(self.terminal(effect_count=1), self.pin))

    def test_all_three_positive_lifecycle_witnesses_are_mandatory(self):
        for field in ("create_confirmed", "callbacks_finished", "process_quiescent"):
            for value in (False, None, 1):
                with self.subTest(field=field, value=value):
                    self.assertFalse(verify_command_receipt(self.terminal(**{field: value}), self.pin))

    def test_admitted_start_requires_positive_started_outcome(self):
        self.assertTrue(verify_command_receipt(self.terminal(start_admitted=True, start_outcome="STARTED"), self.pin))
        for outcome in ("UNKNOWN", "NOT_STARTED", "COMMITTED"):
            with self.subTest(outcome=outcome):
                self.assertFalse(verify_command_receipt(self.terminal(start_admitted=True, start_outcome=outcome), self.pin))
        self.assertFalse(verify_command_receipt(self.terminal(stage="START"), self.pin))

    def test_unadmitted_start_cannot_claim_launch(self):
        self.assertFalse(verify_command_receipt(self.terminal(start_admitted=False, start_outcome="STARTED"), self.pin))
        self.assertFalse(verify_command_receipt(self.terminal(start_admitted=0), self.pin))

    def test_other_status_or_business_effect_claim_is_rejected(self):
        for changed in ({"status": "DENIED"}, {"status": "COMMITTED"}, {"business_effects": "NONE"},
                        {"observed_at": True}, {"epoch": True}, {"container_id": "name"}):
            with self.subTest(changed=changed):
                self.assertFalse(verify_command_receipt(self.terminal(**changed), self.pin))

    def test_wrong_key_domain_or_changed_signed_receipt_is_rejected(self):
        receipt = self.terminal()
        receipt["observation_digest"] = "0" * 64
        self.assertFalse(verify_command_receipt(receipt, self.pin))
        receipt = self.terminal()
        body = {k: v for k, v in receipt.items() if k != "signature"}
        receipt["signature"] = self.signer.sign(b"liminal-external-network-receipt-v1\x00" + canonical_bytes(body)).hex()
        self.assertFalse(verify_command_receipt(receipt, self.pin))
        self.assertFalse(verify_command_receipt(self.terminal(), {**self.pin, "public_key": "0" * 64}))


if __name__ == "__main__":
    unittest.main()
