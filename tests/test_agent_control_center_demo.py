"""Verify owned effects and evidence separation in the public demonstration."""
import copy
import json
import unittest

from sdk.liminal_agent_control.center_demo import run_demo
from sdk.liminal_agent_control.center_view import render


class CenterDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_demo()

    def test_report_preserves_real_effects_and_denials(self):
        report = self.report
        self.assertTrue(report['passed'])
        self.assertTrue(all(report['checks'].values()))
        self.assertEqual([f['record_count'] for f in report['frames']], [0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2])
        self.assertEqual(report['outcomes']['veto_case']['record_count'], 0)
        self.assertEqual(report['scope']['model_calls'], 0)
        self.assertFalse(report['scope']['external_network'])

    def test_schedule_change_preserves_history_and_requires_new_evidence(self):
        before, changed, returned = [self.report['frames'][i] for i in (3, 6, 8)]
        self.assertEqual(before['continuity']['events'], changed['continuity']['events'])
        self.assertEqual(changed['continuity']['states'][0]['node_id'], 'work')
        self.assertEqual(changed['continuity']['states'][0]['active_center_id'], 'B')
        self.assertEqual(returned['continuity']['states'][0]['node_id'], 'center-b')
        self.assertEqual(returned['continuity']['states'][0]['last_progress_at'], 105)

    def test_exported_labels_cannot_close_json_script(self):
        report = copy.deepcopy(self.report)
        payload = '</script><script>globalThis.injected=true</script>'
        report['frames'][0]['label'] = payload
        html = render(report)
        self.assertNotIn(payload, html)
        data = html.split('<script id="report" type="application/json">', 1)[1].split('</script>', 1)[0]
        self.assertEqual(json.loads(data)['frames'][0]['label'], payload)


if __name__ == '__main__':
    unittest.main()
