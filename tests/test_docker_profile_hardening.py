"""Command construction regressions; real Docker behavior is a separate capture."""
import unittest
from types import SimpleNamespace

from adapters.docker.liminal_docker_executor import build_docker_argv
from sdk.liminal_isolated_execution import IsolatedExecutionPlan


class DockerProfileHardeningTests(unittest.TestCase):
    def plan(self, argv):
        return IsolatedExecutionPlan.build(
            operation_id="hardening", image_id="sha256:" + "b" * 64,
            argv=argv, host_workspace="/host/workspace")

    def test_generic_command_clears_inherited_entrypoint_and_daemon_logs(self):
        plan = self.plan(("/bin/true", "literal argument"))
        argv = build_docker_argv(plan)
        self.assertEqual(argv.count("--entrypoint"), 1)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "")
        self.assertEqual(argv[argv.index("--log-driver") + 1], "none")
        self.assertEqual(argv[-3:], [plan.image_id, "/bin/true", "literal argument"])

    def test_trusted_fixed_worker_entrypoint_retains_interpreter_arguments(self):
        plan = self.plan(("-I", "-u", "/workspace/fixed.py"))
        argv = build_docker_argv(plan, entrypoint="python3")
        self.assertEqual(argv.count("--entrypoint"), 1)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "python3")
        self.assertEqual(argv[-4:], [plan.image_id, "-I", "-u", "/workspace/fixed.py"])

    def test_g03_create_argv_matches_its_independent_admitted_stage_contract(self):
        from sdk.liminal_agent_control.external_agent_launch import ClosedChannelAgentSupervisor
        from tests.test_agent_control_external_agent_evidence import verifier

        plan = self.plan(("-I", "-u", "/workspace/fixed.py"))
        spec = {"host_workspace": plan.host_workspace, "image_id": plan.image_id, "argv": list(plan.argv)}
        record = {"session_id": "liminal-control-" + "a" * 32, "registry_id": "registry:unit",
                  "ownership_token": "b" * 64, "plan_sha256": plan.plan_sha256}
        command = {"spec": spec, "registry_record": record}
        subject = object.__new__(ClosedChannelAgentSupervisor)
        subject.controller = SimpleNamespace(docker_binary="docker")
        subject.launch_gate = SimpleNamespace(assert_ready=lambda: None)
        subject._plan = lambda spec: plan
        self.assertEqual(subject._create_argv(command), verifier._create_argv(command))


if __name__ == "__main__":
    unittest.main()
