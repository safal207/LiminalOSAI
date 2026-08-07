import unittest

from sdk.liminal_capability_broker import CapabilityBroker
from sdk.liminal_causal_escalation import analyze_trajectory, replay
from sdk.liminal_egress_gateway import EgressGateway, GatewayRequest, TransportResponse
from sdk.liminal_post_sandbox_contracts import CapabilityContract, canonical_sha256
from sdk.liminal_runtime_mediation import (
    AUTHORITY, ExecutionObservation, MediationError, RuntimeMediator, RuntimeOperation, verify_receipt,
)

P = "a" * 64
PAYLOAD = "b" * 64


def contract(cid, kind, subject, scope, *, uses=4, expires=500):
    return CapabilityContract.build(
        capability_id=cid, capability_type=kind, subject_id=subject,
        issuer_id="human:owner", scope=scope,
        issued_at_unix=10, not_before_unix=10, expires_at_unix=expires,
        max_uses=uses, delegable=False, parent_capability_id=None,
        policy_sha256=P,
    ).as_document()


def op(kind, scope, *, oid="op:1", subject="agent:a", before=0, after=0, at=20):
    return RuntimeOperation(
        operation_id=oid, subject_id=subject, policy_sha256=P, kind=kind,
        scope=scope, payload_sha256=PAYLOAD, at_unix=at,
        privilege_level_before=before, privilege_level_after=after,
    )


class RuntimeMediationTests(unittest.TestCase):
    def setUp(self):
        self.broker = CapabilityBroker("broker:runtime-tests")
        self.m = RuntimeMediator(broker=self.broker)

    def admit(self, cid, kind, scope, **kwargs):
        return self.broker.admit(contract(cid, kind, "agent:a", scope, **kwargs), at_unix=20)

    def test_default_deny_never_calls_executor(self):
        called = []
        r = self.m.mediate(op("process.execute", {"executables":["python3"],"working_directory":"/workspace","argument_profile":"tests"}), lambda x: called.append(x))
        self.assertEqual(r["admission_decision"], "BLOCK")
        self.assertEqual(r["execution_outcome"], "NOT_EXECUTED")
        self.assertEqual(called, [])

    def test_valid_process_capability_calls_host_once(self):
        scope={"executables":["python3"],"working_directory":"/workspace","argument_profile":"tests"}
        self.admit("cap:proc","process.execute",scope)
        called=[]
        r=self.m.mediate(op("process.execute",scope), lambda x: (called.append(x.operation_id) or ExecutionObservation.success({"exit_code":0})))
        self.assertEqual(called,["op:1"])
        self.assertEqual(r["admission_decision"],"ALLOW")
        self.assertEqual(r["execution_outcome"],"SUCCEEDED")
        verify_receipt(r)

    def test_scope_mismatch_never_calls_executor(self):
        self.admit("cap:proc","process.execute",{"executables":["python3"],"working_directory":"/workspace","argument_profile":"tests"})
        called=[]
        r=self.m.mediate(op("process.execute",{"executables":["bash"],"working_directory":"/workspace","argument_profile":"tests"}),lambda x: called.append(x))
        self.assertEqual(r["admission_decision"],"BLOCK"); self.assertEqual(called,[])

    def test_revoked_capability_never_calls_executor(self):
        scope={"packages":["safe-lib"],"registries":["registry.example.com"]}
        self.admit("cap:pkg","package.install",scope)
        self.broker.revoke("cap:pkg",at_unix=21)
        called=[]
        r=self.m.mediate(op("package.install",scope,at=22),lambda x: called.append(x))
        self.assertEqual(r["admission_decision"],"BLOCK"); self.assertEqual(called,[])

    def test_containment_blocks_even_valid_capability(self):
        scope={"setting_keys":["feature.safe_mode"]}
        self.admit("cap:cfg","runtime.configure",scope)
        self.m.enter_containment(incident_receipt_sha256="c"*64)
        called=[]
        r=self.m.mediate(op("runtime.configure",scope),lambda x: called.append(x))
        self.assertEqual(r["reason_codes"],["containment_active"])
        self.assertEqual(called,[])

    def test_external_verified_release_reopens_reference_gate(self):
        scope={"setting_keys":["feature.safe_mode"]}
        self.admit("cap:cfg","runtime.configure",scope)
        self.m.enter_containment(incident_receipt_sha256="c"*64)
        self.m.exit_containment(human_release_receipt_sha256="d"*64)
        r=self.m.mediate(op("runtime.configure",scope),lambda x: ExecutionObservation.success({"changed":True}))
        self.assertEqual(r["execution_outcome"],"SUCCEEDED")

    def test_executor_failure_is_digest_only(self):
        scope={"credential_ids":["cred:db"],"purpose":"runtime_test"}
        self.admit("cap:cred","credential.access",scope)
        secret="TOP-SECRET-DO-NOT-RECORD"
        def fail(_): raise RuntimeError(secret)
        r=self.m.mediate(op("credential.access",scope),fail)
        self.assertEqual(r["admission_decision"],"ALLOW")
        self.assertEqual(r["execution_outcome"],"FAILED")
        self.assertNotIn(secret,str(r))
        self.assertEqual(r["result_sha256"],canonical_sha256({"error_type":"RuntimeError"}))

    def test_file_write_projects_to_write_event_without_raw_content(self):
        scope={"paths":["/tmp/liminal-output.txt"]}
        self.admit("cap:file","filesystem.write_outside_workspace",scope)
        r=self.m.mediate(op("filesystem.write_outside_workspace",scope),lambda x: ExecutionObservation.success({"bytes":12}))
        self.assertEqual(r["runtime_kind"],"filesystem.write_outside_workspace")
        self.assertEqual(self.m.trajectory_events()[-1].kind,"repository.write")

    def test_bad_executor_return_is_failed_not_unverified_success(self):
        scope={"executables":["python3"],"working_directory":"/workspace","argument_profile":"tests"}
        self.admit("cap:proc","process.execute",scope)
        r=self.m.mediate(op("process.execute",scope),lambda x: {"exit_code":0})
        self.assertEqual(r["execution_outcome"],"FAILED")

    def test_receipt_tamper_fails(self):
        scope={"setting_keys":["feature.safe_mode"]}; self.admit("cap:cfg","runtime.configure",scope)
        r=self.m.mediate(op("runtime.configure",scope),lambda x: ExecutionObservation.success({"changed":True}))
        bad=dict(r); bad["payload_sha256"]="f"*64
        with self.assertRaises(MediationError): verify_receipt(bad)

    def test_trajectory_replays_deterministically(self):
        pkg={"packages":["safe-lib"],"registries":["registry.example.com"]}
        net={"domains":["api.example.com"],"protocols":["https"],"ports":[443]}
        cred={"credential_ids":["cred:db"],"purpose":"runtime_test"}
        child={"executables":["worker"],"max_children":1}
        for cid,kind,scope in (("pkg","package.install",pkg),("cred","credential.access",cred),("child","process.spawn_child",child)):
            self.admit("cap:"+cid,kind,scope)
        resolver=lambda host:["93.184.216.34"]
        transport=lambda req: TransportResponse(200,{},"e"*64)
        eg=EgressGateway(broker=self.broker,resolver=resolver,transport=transport)
        self.m.egress_gateway=eg
        self.broker.admit(contract("cap:net","network.connect_domain","agent:a",net),at_unix=20)
        self.m.mediate(op("package.install",pkg,oid="op:pkg",at=30),lambda x: ExecutionObservation.success({"ok":1}))
        self.m.mediate_network(GatewayRequest("op:net","agent:a",P,"GET","https://api.example.com/x",{},"e"*64,{},31))
        self.m.mediate(op("credential.access",cred,oid="op:cred",before=0,after=1,at=32),lambda x: ExecutionObservation.success({"ref":"used"}))
        self.m.mediate(op("process.spawn_child",child,oid="op:child",before=1,after=2,at=33),lambda x: ExecutionObservation.success({"pid_digest":"x"}))
        events=self.m.trajectory_events()
        d1=analyze_trajectory(events)
        d2=replay([e.__dict__ for e in events])
        self.assertEqual(d1["receipt_sha256"],d2["receipt_sha256"])
        self.assertEqual(d1["decision"],"CONTAIN")

    def test_network_requires_egress_gateway(self):
        req=GatewayRequest("net:1","agent:a",P,"GET","https://api.example.com",{},"e"*64,{},20)
        with self.assertRaises(MediationError): self.m.mediate_network(req)

    def test_network_success_uses_existing_gateway(self):
        net={"domains":["api.example.com"],"protocols":["https"],"ports":[443]}
        self.broker.admit(contract("cap:net","network.connect_domain","agent:a",net),at_unix=20)
        seen=[]
        eg=EgressGateway(
            broker=self.broker,
            resolver=lambda host:["93.184.216.34"],
            transport=lambda req:(seen.append(req.url) or TransportResponse(204,{},"e"*64)),
        )
        self.m.egress_gateway=eg
        r=self.m.mediate_network(GatewayRequest("net:1","agent:a",P,"GET","https://api.example.com/x",{},"e"*64,{},21))
        self.assertEqual(r["admission_decision"],"ALLOW")
        self.assertEqual(r["execution_outcome"],"SUCCEEDED")
        self.assertEqual(seen,["https://api.example.com/x"])

    def test_network_containment_stops_transport(self):
        seen=[]
        eg=EgressGateway(broker=self.broker,resolver=lambda host:["93.184.216.34"],transport=lambda req:(seen.append(req.url) or TransportResponse(200,{},"e"*64)))
        self.m.egress_gateway=eg; self.m.enter_containment(incident_receipt_sha256="c"*64)
        r=self.m.mediate_network(GatewayRequest("net:1","agent:a",P,"GET","https://api.example.com/x",{},"e"*64,{},21))
        self.assertEqual(r["admission_decision"],"BLOCK"); self.assertEqual(seen,[])

    def test_authority_boundary_does_not_claim_os_enforcement(self):
        self.assertTrue(AUTHORITY["host_callback_dispatch"])
        self.assertFalse(AUTHORITY["direct_subprocess_execution"])
        self.assertFalse(AUTHORITY["direct_socket_creation"])
        self.assertFalse(AUTHORITY["direct_filesystem_mutation"])
        self.assertFalse(AUTHORITY["os_kernel_enforcement"])
        self.assertFalse(AUTHORITY["seccomp_ebpf_apparmor_enforcement"])


if __name__ == "__main__":
    unittest.main()
