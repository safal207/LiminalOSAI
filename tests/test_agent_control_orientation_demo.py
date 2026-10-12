"""Check observable trajectory facts and safe, self-contained graph export."""
import json
import re
import unittest

from sdk.liminal_agent_control.orientation_demo import run_demo
from sdk.liminal_agent_control.orientation_guidance import guidance
from sdk.liminal_agent_control.orientation_view import render


class OrientationDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_demo()

    def test_receiver_effects_pending_observations_and_separate_positions(self):
        self.assertTrue(self.report["passed"], self.report["checks"])
        frames = self.report["frames"]
        self.assertEqual(len(frames), 9)
        by_id = lambda frame: {s["execution_id"]: s for s in frame["graph"]["executions"]}
        self.assertEqual(by_id(frames[1])["alpha"]["node_id"], "record")
        self.assertEqual(by_id(frames[1])["beta"]["revision"], 0)
        self.assertEqual(by_id(frames[3])["beta"]["pending_action_id"], "beta:send")
        self.assertEqual(by_id(frames[3])["beta"]["node_id"], "center")
        self.assertEqual(by_id(frames[6])["beta"]["node_id"], "network")
        self.assertEqual(frames[-1]["authority"]["status"], "STOPPED")
        self.assertEqual(frames[-1]["authority"]["action_count"], 4)
        self.assertEqual(len(frames[-1]["graph"]["occurrences"]), 4)
        self.assertTrue(all(s["steps"] == 2 for s in frames[-1]["graph"]["executions"]))

    def test_graph_export_keeps_exact_report_without_external_dependencies(self):
        page = render(self.report)
        data = re.search(r'<script id="report" type="application/json">(.*?)</script>', page, re.S)
        self.assertIsNotNone(data)
        self.assertEqual(json.loads(data.group(1)), self.report)
        self.assertNotRegex(page, r'<(?:script|link)[^>]+(?:src|href)=')
        self.assertIn('aria-label="Момент истории"', page)

    def test_guidance_is_actor_scoped_and_cannot_override_missing_evidence_or_authority(self):
        frame = self.report["frames"][1]
        own = guidance(frame["graph"], frame["authority"], "alpha")
        self.assertEqual(own["disposition"], "RETURN_CANDIDATE")
        self.assertEqual([e["edge_id"] for e in own["candidates"]], ["review_record"])
        self.assertFalse(own["execution_authorized"])
        for authority in ({**frame["authority"], "epoch": 5},
                          {**frame["authority"], "root_id": "other"},
                          {**frame["authority"], "remaining_actions": 0},
                          {**frame["authority"], "last_now": frame["authority"]["last_now"] + 100}):
            self.assertEqual(guidance(frame["graph"], authority, "alpha")["disposition"], "HOLD")
        self.assertEqual(guidance(frame["graph"], frame["authority"], "unregistered")["candidates"], [])

    def test_untrusted_claim_cannot_break_out_of_embedded_report(self):
        altered = {**self.report, "worker_claims": ["</script><script>alert('claim')</script>"]}
        page = render(altered)
        self.assertNotIn("</script><script>alert", page)
        self.assertEqual(page.count('<script'), 2)


if __name__ == "__main__":
    unittest.main()
