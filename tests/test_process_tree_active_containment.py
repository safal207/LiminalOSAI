import hashlib
import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_containment import ContainmentBlocked, ContainmentCoordinator
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_process_lineage import (
    ACTION_SCHEMA,
    OBSERVATION_SCHEMA,
    ProcessLineageContainmentSupervisor,
    ProcessLineageError,
    verify_receipt as verify_lineage_receipt,
)
from sdk.liminal_process_tree import ProcessTreeSupervisor, ZERO_SHA256, verify_receipt as verify_tree_receipt

SESSION = "exec:session:1"
ROOT = "proc:root"
BINDING = "a" * 64
NOW = 2100001000


def node(pid, parent, state="running", identity=None):
    return {
        "process_id": pid,
        "parent_process_id": parent,
        "identity_sha256": identity or canonical_sha256({"trusted_host_process": pid}),
        "state": state,
    }


class FakeLineageBackend:
    def __init__(self, nodes, *, survivor=None, wrong_session=False, forge_action=False):
        self.nodes = [dict(n) for n in nodes]
        self.survivor = survivor
        self.wrong_session = wrong_session
        self.forge_action = forge_action

    def _snapshot_doc(self):
        ordered = sorted((dict(n) for n in self.nodes), key=lambda n: n["process_id"])
        tree_sha = canonical_sha256(ordered)
        body = {
            "schema": OBSERVATION_SCHEMA,
            "session_id": "exec:other" if self.wrong_session else SESSION,
            "root_process_id": ROOT,
            "backend_binding_sha256": BINDING,
            "nodes": ordered,
            "tree_sha256": tree_sha,
        }
        return {**body, "evidence_sha256": canonical_sha256(body)}

    def snapshot(self, session_id):
        self.assert_session(session_id)
        return self._snapshot_doc()

    def _action(self, action, affected):
        result_tree = self._snapshot_doc()["tree_sha256"]
        body = {
            "schema": ACTION_SCHEMA,
            "session_id": SESSION,
            "root_process_id": ROOT,
            "backend_binding_sha256": BINDING,
            "action": action,
            "affected_count": affected,
            "result_tree_sha256": result_tree,
        }
        evidence = canonical_sha256(body)
        if self.forge_action:
            evidence = "f" * 64
        return {**body, "evidence_sha256": evidence}

    def freeze(self, session_id):
        self.assert_session(session_id)
        affected = 0
        for item in self.nodes:
            if item["state"] != "terminated":
                affected += 1
                item["state"] = "frozen"
        return self._action("freeze", affected)

    def terminate(self, session_id):
        self.assert_session(session_id)
        affected = 0
        for item in self.nodes:
            if item["state"] != "terminated" and item["process_id"] != self.survivor:
                affected += 1
                item["state"] = "terminated"
        return self._action("terminate", affected)

    @staticmethod
    def assert_session(session_id):
        if session_id != SESSION:
            raise AssertionError("unexpected execution session")


def lineage_supervisor(backend):
    return ProcessLineageContainmentSupervisor(
        session_id=SESSION,
        root_process_id=ROOT,
        backend_binding_sha256=BINDING,
        backend=backend,
    )


def phase3_receipt():
    return {"decision": "CONTAIN", "receipt_sha256": "b" * 64}


def cap():
    return CapabilityContract.build(
        capability_id="cap:process-test",
        capability_type="network.connect_domain",
        subject_id="agent:test",
        issuer_id="issuer:test",
        scope={"domains": ["example.com"], "protocols": ["https"], "ports": [443]},
        issued_at_unix=NOW,
        not_before_unix=NOW,
        expires_at_unix=NOW + 600,
        max_uses=2,
        delegable=False,
        parent_capability_id=None,
        policy_sha256="c" * 64,
    ).as_document()


class ProcessLineageContainmentTests(unittest.TestCase):
    def test_deep_tree_freezes_and_quiesces_to_zero_survivors(self):
        backend = FakeLineageBackend([
            node(ROOT, None),
            node("proc:child", ROOT),
            node("proc:grandchild", "proc:child"),
        ])
        s = lineage_supervisor(backend)
        frozen = s.freeze()
        self.assertEqual(frozen["observed_count"], 3)
        receipt = s.quiesce()
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["terminated_count"], 3)
        self.assertEqual(receipt["surviving_count"], 0)
        self.assertEqual(verify_lineage_receipt(receipt), receipt)

    def test_unknown_parent_fails_closed(self):
        s = lineage_supervisor(FakeLineageBackend([node(ROOT, None), node("proc:orphan", "proc:missing")]))
        with self.assertRaises(ProcessLineageError):
            s.freeze()

    def test_cycle_fails_closed(self):
        s = lineage_supervisor(FakeLineageBackend([node(ROOT, None), node("proc:loop", "proc:loop")]))
        with self.assertRaises(ProcessLineageError):
            s.freeze()

    def test_cross_session_backend_observation_fails_closed(self):
        s = lineage_supervisor(FakeLineageBackend([node(ROOT, None)], wrong_session=True))
        with self.assertRaises(ProcessLineageError):
            s.freeze()

    def test_forged_backend_action_evidence_fails_closed(self):
        s = lineage_supervisor(FakeLineageBackend([node(ROOT, None)], forge_action=True))
        with self.assertRaises(ProcessLineageError):
            s.freeze()

    def test_partial_termination_produces_block_receipt(self):
        backend = FakeLineageBackend([node(ROOT, None), node("proc:child", ROOT)], survivor="proc:child")
        s = lineage_supervisor(backend)
        s.freeze()
        receipt = s.quiesce()
        self.assertEqual(receipt["decision"], "BLOCK")
        self.assertEqual(receipt["surviving_count"], 1)
        self.assertEqual(receipt["terminated_count"], 1)
        verify_lineage_receipt(receipt)

    def test_identity_change_after_freeze_fails_closed(self):
        backend = FakeLineageBackend([node(ROOT, None), node("proc:child", ROOT)])
        s = lineage_supervisor(backend)
        s.freeze()
        backend.nodes[1]["identity_sha256"] = "d" * 64
        with self.assertRaises(ProcessLineageError):
            s.quiesce()

    def test_phase4_quiesces_only_after_capability_revoke(self):
        backend = FakeLineageBackend([node(ROOT, None), node("proc:child", ROOT)])
        s = lineage_supervisor(backend)
        broker = CapabilityBroker("broker:process-test")
        broker.admit(cap(), at_unix=NOW)
        order = []

        def freeze_runtime():
            order.append("freeze")
            s.freeze()

        def close_egress():
            order.append("egress")

        def quiesce_runtime():
            statuses = [item["status"] for item in broker.state_document()["capabilities"]]
            self.assertEqual(statuses, ["revoked"])
            order.append("quiesce")
            return s.quiesce()

        c = ContainmentCoordinator(
            broker=broker,
            freeze_runtime=freeze_runtime,
            close_egress=close_egress,
            quiesce_runtime=quiesce_runtime,
            seal_trace=lambda: (order.append("seal") or hashlib.sha256(b"trace").hexdigest()),
            snapshot_forensics=lambda: {
                "trace_head_sha256": "e" * 64,
                "broker_head_sha256": broker.head_sha256,
                "event_count": 1,
                "capability_count": 1,
                "reason_codes": ["process_lineage_test"],
            },
        )
        incident = c.contain(phase3_receipt(), incident_id="incident:process-lineage", at_unix=NOW + 1)
        self.assertEqual(incident["final_state"], "REVIEW")
        self.assertFalse(incident["partial_failures"])
        self.assertEqual(incident["runtime_quiescence_sha256"], s.receipt()["receipt_sha256"])
        self.assertLess(order.index("freeze"), order.index("quiesce"))
        self.assertLess(order.index("quiesce"), order.index("seal"))

    def test_survivor_becomes_partial_failure_and_blocks_release(self):
        backend = FakeLineageBackend([node(ROOT, None), node("proc:child", ROOT)], survivor="proc:child")
        s = lineage_supervisor(backend)
        broker = CapabilityBroker("broker:process-test")
        c = ContainmentCoordinator(
            broker=broker,
            freeze_runtime=lambda: s.freeze(),
            close_egress=lambda: None,
            quiesce_runtime=lambda: s.quiesce(),
            seal_trace=lambda: "1" * 64,
            snapshot_forensics=lambda: {"trace_head_sha256": "2" * 64, "broker_head_sha256": broker.head_sha256},
        )
        incident = c.contain(phase3_receipt(), incident_id="incident:survivor", at_unix=NOW + 1)
        self.assertIn("runtime_quiescence_incomplete", incident["partial_failures"])
        with self.assertRaises(ContainmentBlocked):
            c.release(human_release_id="human:1", approved=True, at_unix=NOW + 2)


class FakeSessionHost:
    def __init__(self):
        self.state = {
            SESSION: {
                "exists": True,
                "running": True,
                "descendant_count": 2,
                "tree_sha256": canonical_sha256(["opaque-root", "opaque-child", "opaque-grandchild"]),
            }
        }
        self.order = []

    def inspect(self, session_id):
        return dict(self.state[session_id])

    def freeze(self, session_id):
        self.order.append("freeze_host")
        self.state[session_id]["running"] = False

    def terminate(self, session_id):
        self.order.append("terminate_host")
        self.state[session_id] = {
            "exists": False,
            "running": False,
            "descendant_count": 0,
            "tree_sha256": ZERO_SHA256,
        }


class ProcessSessionSupervisorTests(unittest.TestCase):
    def _registry(self, host):
        registry = ProcessTreeSupervisor(
            inspect_session=host.inspect,
            freeze_session=host.freeze,
            terminate_session=host.terminate,
        )
        registry.register_session(
            session_id=SESSION,
            operation_id="operation:1",
            plan_sha256="3" * 64,
            backend_identity_sha256="4" * 64,
        )
        return registry

    def test_phase4_session_path_is_freeze_revoke_terminate_seal(self):
        host = FakeSessionHost()
        registry = self._registry(host)
        broker = CapabilityBroker("broker:session-process-test")
        broker.admit(cap(), at_unix=NOW)
        order = []

        def freeze_runtime():
            order.append("freeze")
            receipt = registry.freeze_all()
            self.assertFalse(receipt["failure_codes"])

        def quiesce_runtime():
            self.assertEqual([x["status"] for x in broker.state_document()["capabilities"]], ["revoked"])
            order.append("terminate")
            return registry.quiesce_all(incident_id="incident:session-tree")

        c = ContainmentCoordinator(
            broker=broker,
            freeze_runtime=freeze_runtime,
            close_egress=lambda: order.append("egress"),
            quiesce_runtime=quiesce_runtime,
            seal_trace=lambda: (order.append("seal") or "5" * 64),
            snapshot_forensics=lambda: {"trace_head_sha256": "6" * 64, "broker_head_sha256": broker.head_sha256},
        )
        incident = c.contain(phase3_receipt(), incident_id="incident:session-tree", at_unix=NOW + 1)
        self.assertFalse(incident["partial_failures"])
        self.assertLess(order.index("freeze"), order.index("terminate"))
        self.assertLess(order.index("terminate"), order.index("seal"))
        receipt = registry.receipts()[-1]
        self.assertTrue(receipt["zero_survivors"])
        self.assertEqual(receipt["survivor_count"], 0)
        verify_tree_receipt(receipt)

    def test_post_revoke_quiesce_refuses_to_hide_missing_freeze(self):
        host = FakeSessionHost()
        registry = self._registry(host)
        receipt = registry.quiesce_all(incident_id="incident:missing-freeze")
        self.assertFalse(receipt["zero_survivors"])
        self.assertEqual(receipt["survivor_count"], 1)
        self.assertTrue(any(code.startswith("not_frozen:") for code in receipt["failure_codes"]))
        self.assertNotIn("terminate_host", host.order)


if __name__ == "__main__":
    unittest.main()
