"""Command construction regressions; real Docker behavior is a separate capture."""
import unittest

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


if __name__ == "__main__":
    unittest.main()
