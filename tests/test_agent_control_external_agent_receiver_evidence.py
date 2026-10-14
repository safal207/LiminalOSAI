"""Independent signed packet/SQL mutations; real captured matrix runs in CI.

These local signed fixtures exercise checker predicates and never stand in for
Docker execution. Capture tests always exist and explicitly report NOT_RUN
without a real report. CI loads packet tests first, then requires all nine
capture checks after the runtime report is produced.
"""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_receiver_offline_test", ROOT / "scripts/verify_external_agent_receiver_evidence.py")
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ReceiverPacketEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.authority_key = Ed25519PrivateKey.generate()
        self.pin = {"endpoint_id": "endpoint:unit", "key_id": "receiver:unit", "public_key": self.key.public_key().public_bytes_raw().hex()}
        self.authority_pin = {"authority_id": "authority:unit", "key_id": "authority-key:unit", "public_key": self.authority_key.public_key().public_bytes_raw().hex()}
        self.url = "http://127.0.0.1:43210"
        self.actions, self.grants, self.permits, self.receipts = {}, {}, {}, []
        for index in (1, 2):
            action = {"action_id": f"action:{index}", "attempt_id": f"attempt:{index}", "root_id": "root:unit", "execution_id": "worker:unit",
                "epoch": 1, "target": "network", "arguments": {"method": "POST", "url": self.url + "/v1/record", "body": {"synthetic_marker": f"marker:{index}"}}}
            grant = {"action_digest": verifier.sha(action), "policy_version": "b" * 64, "expires_at": 100, "receiver_id": self.pin["endpoint_id"]}
            request = {"schema": "liminal-external-authority-request-v1", "role": "receiver", "operation": "begin", "nonce": str(index) * 64,
                "payload": {"action": action, "authorization": grant}}
            result = {"status": "PERMITTED", "outcome": None, "receipt": None, "action_digest": verifier.sha(action),
                "receiver_id": self.pin["endpoint_id"], "reservation_id": f"reservation:{index}", **{k: action[k] for k in
                    ("action_id", "attempt_id", "root_id", "execution_id", "epoch")}}
            response = self.sign({"schema": "liminal-external-authority-response-v1", "authority_id": self.authority_pin["authority_id"],
                "key_id": self.authority_pin["key_id"], "operation": "begin", "request_digest": verifier.sha(request), "issued_at": 10 + index, "result": result},
                b"liminal-external-authority-response-v1\0", self.authority_key)
            pair = {"request": request, "response": response}
            self.actions[index], self.grants[index] = action, grant
            self.permits[result["reservation_id"]] = {"pair": pair, "action": action, "grant": grant, "reservation_id": result["reservation_id"]}
        self.fence = self.sign({"schema": "liminal.external-agent-receiver.fence.v1", "endpoint_id": self.pin["endpoint_id"], "key_id": self.pin["key_id"],
            "root_id": "root:unit", "epoch": 1, "fence_sequence": 2, "fenced_at": 30, "status": "FENCED"}, b"liminal-external-agent-receiver-fence-v1\0")
        for index in (1, 2):
            action, grant = self.actions[index], self.grants[index]
            receipt = {"schema": "liminal.external-agent-receiver.receipt.v1", "endpoint_id": self.pin["endpoint_id"], "key_id": self.pin["key_id"],
                "reservation_id": f"reservation:{index}", **{k: action[k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch")},
                "action_digest": verifier.sha(action), "authorization_digest": verifier.sha(grant), "body_digest": verifier.sha(action["arguments"]["body"]),
                "terminal_at": 20 if index == 1 else 40, "terminal_sequence": 1 if index == 1 else 3,
                "status": "COMMITTED" if index == 1 else "NO_EFFECT", "effect_count": 1 if index == 1 else 0,
                "fence_digest": None if index == 1 else verifier.sha(self.fence), "reason": "EFFECT_COMMITTED" if index == 1 else "RECEIVER_FENCED"}
            self.receipts.append(self.sign(receipt, b"liminal-external-agent-receiver-receipt-v1\0"))
        self.cache = []
        self.add_request("create_root", {"root_id": "root:unit", "epoch": 1}, {"status": "ROOT_CREATED", "root_id": "root:unit", "epoch": 1})
        enrollment = {"root_id": "root:unit", "execution_id": "worker:unit", "epoch": 1, "parent_execution_id": None}
        self.add_request("bind_execution", enrollment, {"status": "BOUND", **enrollment})
        for index in (1, 2):
            pair = self.permits[f"reservation:{index}"]["pair"]
            self.add_request("commit", {"action": self.actions[index], "authorization": self.grants[index],
                "permit_request": pair["request"], "permit": pair["response"]}, self.receipts[index - 1])
        self.add_request("stop", {"root_id": "root:unit", "epoch": 1}, self.fence)
        counters = {op + "_request_count": sum(row["request"]["operation"] == op for row in self.cache)
            for op in ("commit", "query", "create_root", "bind_execution", "stop")}
        effect = {**{k: self.receipts[0][k] for k in ("action_id", "attempt_id", "root_id", "execution_id", "epoch", "reservation_id", "body_digest", "terminal_sequence")},
            "sequence": 1, "committed_at": 20, "body": self.actions[1]["arguments"]["body"]}
        self.inventory = {"endpoint_id": self.pin["endpoint_id"], "pin": self.pin, "url": self.url, "profile": verifier.RECEIVER_PROFILE,
            **counters, "transition_sequence": 3, "roots": [{"root_id": "root:unit", "epoch": 1, "fenced": 1}], "executions": [enrollment],
            "fences": [self.fence], "terminals": self.receipts, "receipts": self.receipts, "effects": [effect],
            "requests": [{"action_id": self.actions[i]["action_id"], "permit_request": self.permits[f"reservation:{i}"]["pair"]["request"],
                "permit": self.permits[f"reservation:{i}"]["pair"]["response"], "permit_digest": verifier.sha(self.permits[f"reservation:{i}"]["pair"]["response"])} for i in (1, 2)],
            "authenticated_requests": self.cache, "independent_sqlite_effect_count": 1, "independent_sqlite_terminal_count": 2,
            "independent_sqlite_fence_count": 1, "independent_sqlite_action_ids": ["action:1"], "independent_sqlite_request_counts": counters,
            "observation": "actual readonly receiver SQLite inventory"}

    def sign(self, body, domain, key=None):
        body = {k: deepcopy(v) for k, v in body.items() if k != "signature"}
        return {**body, "signature": (self.key if key is None else key).sign(domain + verifier.canonical(body)).hex()}

    def add_request(self, operation, payload, result):
        request = {"schema": "liminal-external-agent-receiver-request-v1", "role": "gateway" if operation in {"commit", "query"} else "operator",
            "operation": operation, "nonce": f"{len(self.cache) + 1:064x}", "payload": deepcopy(payload)}
        self.cache.append({"request": request, "request_digest": verifier.sha(request), "result": deepcopy(result)})

    def check_inventory(self, value=None):
        verifier._endpoint_inventory(self.inventory if value is None else value, self.pin, self.authority_pin, self.permits)

    def matrix_enrollment_fixture(self):
        """Fourteen signed enrollments; thirteen have no terminal to bind them."""
        inventory = deepcopy(self.inventory)
        cases = {verifier.CASE_IDS[0]: {"run_binding": {"effect": {
            "root_id": "root:unit", "execution_id": "worker:unit", "epoch": 1}}}}
        for index, name in enumerate(verifier.CASE_IDS[1:], 1):
            root = {"root_id": "root:" + name, "epoch": 1, "fenced": 1}
            execution = {"root_id": root["root_id"], "execution_id": "worker:" + name,
                "epoch": 1, "parent_execution_id": None}
            fence = self.sign({**self.fence, "root_id": root["root_id"], "fence_sequence": 3 + index,
                "fenced_at": 40 + index}, b"liminal-external-agent-receiver-fence-v1\0")
            cases[name] = {"run_binding": {"effect": {k: execution[k] for k in ("root_id", "execution_id", "epoch")}}}
            inventory["roots"].append(root)
            inventory["executions"].append(execution)
            inventory["fences"].append(fence)
            for operation, payload, result in (
                    ("create_root", {"root_id": root["root_id"], "epoch": 1}, {"status": "ROOT_CREATED", "root_id": root["root_id"], "epoch": 1}),
                    ("bind_execution", execution, {"status": "BOUND", **execution}),
                    ("stop", {"root_id": root["root_id"], "epoch": 1}, fence)):
                request = {"schema": "liminal-external-agent-receiver-request-v1", "role": "operator", "operation": operation,
                    "nonce": f"{len(inventory['authenticated_requests']) + 1:064x}", "payload": deepcopy(payload)}
                inventory["authenticated_requests"].append({"request": request, "request_digest": verifier.sha(request), "result": deepcopy(result)})
        inventory["transition_sequence"] = 3 + len(verifier.CASE_IDS) - 1
        inventory["independent_sqlite_fence_count"] = len(inventory["fences"])
        for name in inventory["independent_sqlite_request_counts"]:
            inventory[name] = inventory["independent_sqlite_request_counts"][name] = sum(
                row["request"]["operation"] + "_request_count" == name for row in inventory["authenticated_requests"])
        return inventory, cases

    def resign_enrollment_capture(self, inventory):
        """Produce valid control packets after a consistent wrong enrollment."""
        roots = {r["root_id"]: r for r in inventory["roots"]}
        executions = {r["execution_id"]: r for r in inventory["executions"]}
        inventory["fences"] = [self.sign({**f, "epoch": roots[f["root_id"]]["epoch"]},
            b"liminal-external-agent-receiver-fence-v1\0") for f in inventory["fences"]]
        fences = {f["root_id"]: f for f in inventory["fences"]}
        report = {"endpoint_evidence": [], "endpoint_operator_evidence": [], "outcomes": {}}
        for item in inventory["authenticated_requests"]:
            request = item["request"]
            operation, payload = request["operation"], request["payload"]
            if operation == "bind_execution":
                request["payload"] = deepcopy(executions[payload["execution_id"]])
                item["result"] = {"status": "BOUND", **request["payload"]}
            elif operation in {"create_root", "stop"}:
                request["payload"] = {"root_id": payload["root_id"], "epoch": roots[payload["root_id"]]["epoch"]}
                item["result"] = ({"status": "ROOT_CREATED", **request["payload"]}
                    if operation == "create_root" else fences[payload["root_id"]])
            item["request_digest"] = verifier.sha(request)
            result = item["result"]
            if operation == "commit":
                result = {"status": "OBSERVED", "action_id": result["action_id"], "reservation_id": result["reservation_id"],
                    "effect_count": result["effect_count"], "receipt": result}
            response = self.sign({"schema": "liminal-external-agent-receiver-response-v1", "endpoint_id": self.pin["endpoint_id"],
                "key_id": self.pin["key_id"], "operation": operation, "request_digest": item["request_digest"], "result": result},
                b"liminal-external-agent-receiver-response-v1\0")
            pair = {"request": deepcopy(request), "response": response}
            report["endpoint_evidence" if request["role"] == "gateway" else "endpoint_operator_evidence"].append(pair)
        encodings = {verifier.canonical(p) for p in report["endpoint_evidence"] + report["endpoint_operator_evidence"]}
        verifier._receiver_capture_pairs(report, inventory, {"endpoint": self.pin, "effect": self.authority_pin}, encodings)

    def test_signed_both_orders_match_actual_sql_rows(self):
        self.check_inventory()
        for receipt in self.receipts:
            self.assertEqual(verifier._network_receipt(receipt, self.pin), receipt)

    def test_unsigned_recensus_cannot_erase_committed_effect(self):
        changed = deepcopy(self.inventory)
        changed["effects"] = []; changed["independent_sqlite_effect_count"] = 0; changed["independent_sqlite_action_ids"] = []
        with self.assertRaisesRegex(verifier.EvidenceError, "row census"):
            self.check_inventory(changed)

    def test_no_effect_cannot_have_actual_effect_even_with_recensus(self):
        changed = deepcopy(self.inventory)
        effect = deepcopy(changed["effects"][0]); receipt = changed["receipts"][1]
        effect.update({k: receipt[k] for k in ("action_id", "attempt_id", "reservation_id", "body_digest", "terminal_sequence")})
        effect.update(sequence=2, committed_at=40, body=self.actions[2]["arguments"]["body"])
        changed["effects"].append(effect); changed["independent_sqlite_effect_count"] = 2; changed["independent_sqlite_action_ids"].append("action:2")
        with self.assertRaises(verifier.EvidenceError): self.check_inventory(changed)

    def test_missing_fence_and_rebound_execution_rejected(self):
        for mutate in (lambda v: v["fences"].clear(), lambda v: v["executions"][0].update(root_id="other"),
                       lambda v: v["roots"][0].update(fenced=0), lambda v: v["executions"][0].update(parent_execution_id="worker:unit")):
            changed = deepcopy(self.inventory); mutate(changed)
            with self.assertRaises(verifier.EvidenceError): self.check_inventory(changed)

    def test_resigned_terminal_cannot_cross_fence_sequence(self):
        changed = deepcopy(self.inventory)
        changed["receipts"][1] = self.sign({**changed["receipts"][1], "terminal_sequence": 1}, b"liminal-external-agent-receiver-receipt-v1\0")
        changed["terminals"] = changed["receipts"]
        with self.assertRaises(verifier.EvidenceError): self.check_inventory(changed)

    def test_no_effect_requires_exact_fence_digest(self):
        changed = deepcopy(self.inventory)
        changed["receipts"][1] = self.sign({**changed["receipts"][1], "fence_digest": "0" * 64}, b"liminal-external-agent-receiver-receipt-v1\0")
        changed["terminals"] = changed["receipts"]
        with self.assertRaisesRegex(verifier.EvidenceError, "preceding durable"): self.check_inventory(changed)

    def test_signature_domain_boolean_counts_and_status_bound(self):
        for mutate in (lambda r: r.update(effect_count=False), lambda r: r.update(terminal_sequence=True), lambda r: r.update(status="DENIED"),
                       lambda r: r.update(reason="NOT_OBSERVED"), lambda r: r.update(fence_digest=None)):
            changed = deepcopy(self.receipts[1]); mutate(changed)
            with self.assertRaises(verifier.EvidenceError): verifier._network_receipt(self.sign(changed, b"liminal-external-agent-receiver-receipt-v1\0"), self.pin)
        with self.assertRaises(verifier.EvidenceError):
            verifier._network_receipt(self.sign(self.receipts[0], b"liminal-external-network-receipt-v1\0"), self.pin)

    def test_cached_observed_query_must_match_current_terminal(self):
        changed = deepcopy(self.inventory)
        request = {"schema": "liminal-external-agent-receiver-request-v1", "role": "gateway", "operation": "query", "nonce": "e" * 64,
            "payload": {"action_id": "action:2", "reservation_id": "reservation:2"}}
        result = {"status": "OBSERVED", "action_id": "action:2", "reservation_id": "reservation:2", "effect_count": 0, "receipt": self.receipts[0]}
        changed["authenticated_requests"].append({"request": request, "request_digest": verifier.sha(request), "result": result})
        changed["query_request_count"] = 1; changed["independent_sqlite_request_counts"]["query_request_count"] = 1
        with self.assertRaises(verifier.EvidenceError): self.check_inventory(changed)

    def test_request_digest_rehash_does_not_allow_operator_commit(self):
        changed = deepcopy(self.inventory)
        row = changed["authenticated_requests"][2]; row["request"]["role"] = "operator"; row["request_digest"] = verifier.sha(row["request"])
        with self.assertRaisesRegex(verifier.EvidenceError, "role/operation"): self.check_inventory(changed)

    def test_enrollment_omission_cannot_be_hidden_by_recounting(self):
        changed = deepcopy(self.inventory)
        changed["authenticated_requests"] = [row for row in changed["authenticated_requests"]
            if row["request"]["operation"] not in {"create_root", "bind_execution"}]
        for name in ("create_root_request_count", "bind_execution_request_count"):
            changed[name] = changed["independent_sqlite_request_counts"][name] = 0
        with self.assertRaisesRegex(verifier.EvidenceError, "enrollment control census"):
            self.check_inventory(changed)

    def test_sql_boolean_integer_aliases_are_rejected(self):
        for mutate in (lambda v: v["executions"][0].update(epoch=True),
                lambda v: v.update(independent_sqlite_effect_count=True),
                lambda v: v["authenticated_requests"][1]["result"].update(epoch=True)):
            changed = deepcopy(self.inventory); mutate(changed)
            with self.assertRaises(verifier.EvidenceError): self.check_inventory(changed)

    def test_zero_terminal_matrix_enrollment_requires_exact_approved_lineage(self):
        inventory, cases = self.matrix_enrollment_fixture()
        self.check_inventory(inventory)
        self.resign_enrollment_capture(inventory)
        verifier._receiver_matrix_enrollment(inventory, cases)
        for mutation in ("wrong_id", "swapped_roots", "epoch", "parent", "duplicate_root_missing_mapping"):
            with self.subTest(mutation=mutation):
                changed = deepcopy(inventory)
                first, second = changed["executions"][1:3]
                if mutation == "wrong_id":
                    old_id = first["execution_id"]
                    first["execution_id"] += ":wrong"
                    for row in changed["authenticated_requests"]:
                        if row["request"]["operation"] == "bind_execution" and row["request"]["payload"]["execution_id"] == old_id:
                            row["request"]["payload"]["execution_id"] = first["execution_id"]
                elif mutation == "swapped_roots":
                    first["root_id"], second["root_id"] = second["root_id"], first["root_id"]
                elif mutation == "epoch":
                    first["epoch"] = 2
                    next(r for r in changed["roots"] if r["root_id"] == first["root_id"])["epoch"] = 2
                else:
                    second["root_id"] = first["root_id"]
                    if mutation == "parent":
                        second["parent_execution_id"] = first["execution_id"]
                self.resign_enrollment_capture(changed)
                # All signatures, control-cache mappings, ancestry and counts are
                # valid, including the old fourteen-root/count-only predicate.
                self.check_inventory(changed)
                self.assertEqual({r["root_id"] for r in changed["roots"]},
                    {c["run_binding"]["effect"]["root_id"] for c in cases.values()})
                self.assertEqual((len(changed["roots"]), len(changed["executions"])), (14, 14))
                self.assertTrue(all(r["fenced"] == 1 for r in changed["roots"]))
                with self.assertRaisesRegex(verifier.EvidenceError, "matrix"):
                    verifier._receiver_matrix_enrollment(changed, cases)

    def test_matrix_enrollment_preserves_exact_types_and_complete_identity_census(self):
        inventory, cases = self.matrix_enrollment_fixture()
        for mutation in ("boolean_execution_epoch", "float_root_epoch", "boolean_fence", "duplicate_execution", "duplicate_binding", "boolean_binding_epoch"):
            with self.subTest(mutation=mutation):
                changed, bindings = deepcopy(inventory), deepcopy(cases)
                if mutation == "boolean_execution_epoch":
                    changed["executions"][1]["epoch"] = True
                elif mutation == "float_root_epoch":
                    changed["roots"][1]["epoch"] = 1.0
                elif mutation == "boolean_fence":
                    changed["roots"][1]["fenced"] = True
                elif mutation == "duplicate_execution":
                    changed["executions"][-1] = deepcopy(changed["executions"][1])
                elif mutation == "duplicate_binding":
                    bindings[verifier.CASE_IDS[-1]]["run_binding"]["effect"] = deepcopy(bindings[verifier.CASE_IDS[1]]["run_binding"]["effect"])
                else:
                    bindings[verifier.CASE_IDS[1]]["run_binding"]["effect"]["epoch"] = True
                with self.assertRaisesRegex(verifier.EvidenceError, "matrix"):
                    verifier._receiver_matrix_enrollment(changed, bindings)

    def test_root_census_handles_delayed_status_signing_and_exact_terminal_denials(self):
        state = {key: None for key in verifier.STATE_FIELDS}
        state.update(root_id="root:unit", receiver_id=self.pin["endpoint_id"], policy_digest="b" * 64,
            epoch=1, state="ACTIVE", max_actions=2, issued_count=1, pending_count=1, committed_count=0,
            denied_count=0, clock_fault=False, admission_closed=False, status="STATE")
        public = [({"operation": "status", "payload": {"root_id": "root:unit"}}, state, {"issued_at": 45}),
            ({"operation": "finish"}, {"status": "SETTLED", "outcome": "DENIED", "receipt": self.receipts[1]}, {"issued_at": 42})]
        terminal = {r["reservation_id"]: r for r in self.receipts}
        log = {"public": public, "network": True, "receiver_pin": self.pin, "terminal": terminal, "permits": self.permits}
        # A status read can precede FINISH while its signed response leaves later.
        self.assertEqual(verifier._signed_state(state, log, "root:unit"), state)
        final = {**state, "state": "STOPPED", "admission_closed": True, "issued_count": 2, "pending_count": 0,
            "committed_count": 1, "denied_count": 2}  # Extra BEGIN denial is never an issued terminal.
        public.append(({"operation": "status", "payload": {"root_id": "root:unit"}}, final, {"issued_at": 50}))
        self.assertEqual(verifier._signed_state(final, log, "root:unit"), final)
        changed = {**final, "issued_count": 3, "denied_count": 3}
        public.append(({"operation": "status", "payload": {"root_id": "root:unit"}}, changed, {"issued_at": 50}))
        with self.assertRaises(verifier.EvidenceError): verifier._signed_state(changed, log, "root:unit")

    def test_unknown_is_not_zero_effect_terminal(self):
        request = {"schema": "liminal-external-agent-receiver-request-v1", "role": "gateway", "operation": "query", "nonce": "e" * 64,
            "payload": {"action_id": "action:2", "reservation_id": "reservation:2"}}
        for count in (0, False, 1):
            with self.assertRaisesRegex(verifier.EvidenceError, "UNKNOWN"):
                verifier._receiver_result(request, {"status": "UNKNOWN", **request["payload"], "effect_count": count, "receipt": None}, self.pin, self.authority_pin)

    def test_delayed_consumed_permit_is_not_claimed_as_final_expiry_guard(self):
        receipt = self.sign({**self.receipts[1], "terminal_at": 101}, b"liminal-external-agent-receiver-receipt-v1\0")
        self.assertEqual(verifier._network_receipt(receipt, self.pin, self.actions[2], self.grants[2], "reservation:2"), receipt)

    def test_checker_source_does_not_import_runtime_helpers(self):
        import ast
        paths = [ROOT / "scripts/verify_external_agent_receiver_evidence.py", ROOT / "scripts/verify_external_agent_evidence.py"]
        for path in paths:
            imports = [n for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, (ast.Import, ast.ImportFrom))]
            self.assertTrue(all("liminal_agent_control" not in ast.unparse(n) for n in imports))


_CAPTURE = os.environ.get("LIMINAL_EXTERNAL_AGENT_RECEIVER_EVIDENCE")
class ReceiverCaptureMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _CAPTURE or not Path(_CAPTURE).is_file():
            if os.environ.get("LIMINAL_EXTERNAL_AGENT_RECEIVER_REQUIRE_DOCKER") == "1":
                raise RuntimeError("required actual G03 capture missing; receiver evidence NOT_RUN")
            raise unittest.SkipTest("NOT_RUN: actual G03 receiver capture required")
        cls.report = json.loads(Path(_CAPTURE).read_bytes())
        cls.expected_sha = os.environ.get("EXPECTED_SOURCE_SHA")

    def verify(self, report):
        return verifier.verify_report(report, expected_source_sha=self.expected_sha)

    def test_actual_capture_passes_complete_independent_reconstruction(self):
        result = self.verify(self.report)
        self.assertEqual((result["actual_agent_containers"], result["actual_endpoint_requests"], result["actual_endpoint_effects"],
                          result["signed_no_effect_receipts"], result["signed_receiver_fences"], result["post_begin_dispatch_guards_verified"]), (14, 8, 6, 2, 14, 8))

    def mutation(self, callback):
        changed = deepcopy(self.report); callback(changed)
        with self.assertRaises(verifier.EvidenceError): self.verify(changed)

    def test_actual_fence_effect_and_terminal_census_mutations_fail(self):
        for field in ("fences", "effects", "receipts", "requests", "authenticated_requests"):
            with self.subTest(field=field): self.mutation(lambda r: r["endpoint_final_inventory"][field].pop())
        # Exercise the complete enrollment predicate on actual matrix bindings
        # without relying on invalid signatures to reject changed SQL lineage.
        inventory, cases = self.report["endpoint_final_inventory"], self.report["outcomes"]
        verifier._receiver_matrix_enrollment(inventory, cases)
        zero_terminal = next(r for r in inventory["executions"]
            if not any(t["execution_id"] == r["execution_id"] for t in inventory["terminals"]))
        for field, value in (("execution_id", zero_terminal["execution_id"] + ":wrong"),
                ("root_id", next(r["root_id"] for r in inventory["roots"] if r["root_id"] != zero_terminal["root_id"])),
                ("epoch", zero_terminal["epoch"] + 1), ("epoch", True), ("parent_execution_id", zero_terminal["execution_id"])):
            with self.subTest(enrollment_field=field, value=value):
                changed = deepcopy(inventory)
                next(r for r in changed["executions"] if r["execution_id"] == zero_terminal["execution_id"])[field] = value
                with self.assertRaisesRegex(verifier.EvidenceError, "matrix"):
                    verifier._receiver_matrix_enrollment(changed, cases)

    def test_actual_no_effect_loss_or_false_zero_claim_fails(self):
        self.mutation(lambda r: r["endpoint_final_inventory"]["independent_sqlite_effect_count"] == 0 or r["endpoint_final_inventory"].update(independent_sqlite_effect_count=0))
        self.mutation(lambda r: r["outcomes"]["pending_effect_stop"]["results"]["final_stop"].update(receiver_fence=None))

    def test_actual_dispatch_omission_and_retime_fail(self):
        self.mutation(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"]["dispatch_boundary"]["events"].clear())
        self.mutation(lambda r: r["outcomes"]["useful_completion"]["gateway_inventory"]["dispatch_boundary"]["events"][0].update(observed_at=0))

    def test_actual_dispatch_tamper_in_every_duplicated_projection_fails(self):
        def mutate_all(value):
            if isinstance(value, dict):
                if value.get("schema") == "liminal-agent-effect-dispatch-observation-v1":
                    value["permit_response_digest"] = "0" * 64
                for item in value.values(): mutate_all(item)
            elif isinstance(value, list):
                for item in value: mutate_all(item)
        self.mutation(mutate_all)

    def test_actual_held_commit_snapshot_requires_durable_closure(self):
        self.mutation(lambda r: r["outcomes"]["receiver_commit_wins"]["pending_effect_snapshot"]["inventory"].update(events=[]))

    def test_actual_route_downgrade_and_channel_omission_fail(self):
        self.mutation(lambda r: r["outcomes"]["useful_completion"]["bridge_configuration"]["effect_gateway_configuration"].update(schema="liminal-closed-channel-effect-gateway-store-v1"))
        self.mutation(lambda r: r["outcomes"]["useful_completion"]["supervisor_after"]["launch_boundary"]["contract"]["channels"].pop("host_receiver_fence_control"))

    def test_actual_ack_packet_substitution_and_control_omission_fail(self):
        def substitute(report):
            case = report["outcomes"]["useful_completion"]
            event = next(e for e in case["coordinator_snapshots"][-1]["inventory"]["events"] if e["kind"] == "RECEIVER_STOP")
            event["pair"] = report["endpoint_evidence"][0]
        self.mutation(substitute)
        self.mutation(lambda r: r["endpoint_operator_evidence"].clear())

    def test_actual_source_and_model_scope_mutations_fail(self):
        self.mutation(lambda r: r["source_files_sha256"].pop("sdk/liminal_agent_control/external_agent_receiver.py"))
        self.mutation(lambda r: r["scope"].update(live_llm="PASS"))

if __name__ == "__main__": unittest.main()
