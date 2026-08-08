import unittest

from sdk.liminal_isolated_execution import IsolationError, IsolatedExecutionPlan


IMAGE = "sha256:" + "a" * 64


class IsolatedWorkspacePathTests(unittest.TestCase):
    def test_normalized_absolute_workspace_is_allowed(self):
        plan = IsolatedExecutionPlan.build(
            operation_id="op:workspace-good",
            image_id=IMAGE,
            argv=("/bin/true",),
            host_workspace="/srv/liminal/workspace",
        )
        self.assertEqual(plan.host_workspace, "/srv/liminal/workspace")

    def test_parent_segment_is_rejected_before_docker_mount(self):
        with self.assertRaises(IsolationError):
            IsolatedExecutionPlan.build(
                operation_id="op:workspace-parent",
                image_id=IMAGE,
                argv=("/bin/true",),
                host_workspace="/srv/liminal/../secret",
            )

    def test_dot_and_redundant_segments_are_rejected(self):
        for path in ("/srv/./workspace", "/srv//workspace", "//srv/workspace"):
            with self.subTest(path=path):
                with self.assertRaises(IsolationError):
                    IsolatedExecutionPlan.build(
                        operation_id="op:workspace-nonnormal",
                        image_id=IMAGE,
                        argv=("/bin/true",),
                        host_workspace=path,
                    )


if __name__ == "__main__":
    unittest.main()
