import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from garuda_v3.server import App

ARTIFACTS = Path(__file__).resolve().parents[1] / 'artifacts/residual_run'

class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = App(ARTIFACTS, self.tmp.name, 'v'*40, 'o'*40,
                       policy_key='k'*40, allowed_cidrs=['198.51.100.0/24'],
                       enforce=True, lab_automation=True)
        self.graph = json.loads((ARTIFACTS / 'alert_replay.json').read_text())
    def tearDown(self):
        self.app.policy.close()
        self.tmp.cleanup()
    def test_unarmed_alert_requires_review_and_does_not_block(self):
        result = self.app.forecast(self.graph)
        self.assertTrue(result['alert'])
        self.assertEqual(result['defence_signal']['route'], 'krishna')
        self.assertFalse(result['automatic_containment'])
        self.assertEqual(self.app.policy.active(), [])
        self.assertEqual(self.app.response.status()['memory'], [])
    def test_reviewed_snapshot_routes_to_arjuna_and_is_not_generic_learning(self):
        event = self.app.forecast(self.graph)['defence_signal']
        self.app.response.approve(event['id'], 'Lab replay review', 'Operator inspected recorded test evidence')
        result = self.app.forecast(self.graph)
        self.assertEqual(result['defence_signal']['route'], 'arjuna')
        changed = json.loads(json.dumps(self.graph))
        changed['times'] = [t+100 for t in changed['times']]
        self.assertEqual(self.app.forecast(changed)['defence_signal']['route'], 'krishna')
        self.assertTrue(self.app.policy.verify())
    def test_scoped_arm_expiry_and_disarm(self):
        for target in ('127.0.0.1', '8.8.8.8', '192.168.1.2'):
            with self.assertRaises(ValueError): self.app.response.arm(target)
        with self.assertRaises(ValueError): self.app.response.arm('198.51.100.2', ttl=True)
        self.app.response.arm('198.51.100.2')
        with patch('garuda_v3.response.time.time', return_value=10**12):
            self.assertIsNone(self.app.response.status()['armed'])
        self.assertFalse(self.app.forecast(self.graph)['automatic_containment'])
        self.app.response.arm('198.51.100.2')
        self.app.response.disarm()
        self.assertFalse(self.app.forecast(self.graph)['automatic_containment'])
    def test_armed_forecast_publishes_signed_policy_and_kill_revokes(self):
        self.app.response.arm('198.51.100.2')
        result = self.app.forecast(self.graph)
        self.assertTrue(result['automatic_containment'])
        signal = result['defence_signal']
        self.assertEqual(signal['target'], '198.51.100.2')
        self.assertEqual(signal['enforcement_confirmation'], 'pending_proxy_observation')
        self.app.response.disarm()
        self.app.policy.kill_switch()
        self.assertEqual(self.app.policy.active(), [])
        self.assertFalse(self.app.forecast(self.graph)['automatic_containment'])
