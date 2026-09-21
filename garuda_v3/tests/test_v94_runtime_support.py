import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from garuda_v3.integrated_server import IntegratedApp
from garuda_v3.support_gate import decision, fit


ARTIFACTS = Path(__file__).resolve().parents[1] / 'artifacts/residual_run'


class V94RuntimeSupportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = IntegratedApp(
            ARTIFACTS,
            self.tmp.name,
            'v' * 40,
            'o' * 40,
            policy_key='k' * 40,
            allowed_cidrs=['198.51.100.0/24'],
            enforce=True,
            lab_automation=True,
            bundle_metadata={'bundle_id': 'test-pinned-runtime'},
        )
        self.graph = json.loads((ARTIFACTS / 'alert_replay.json').read_text())

    def tearDown(self):
        self.app.policy.close()
        self.tmp.cleanup()

    def test_missing_pinned_support_gate_is_shadow_unresolved(self):
        self.assertIsNone(self.app.service.support_gate)
        result = self.app.forecast(self.graph)
        support = result['runtime_support']
        self.assertEqual(support['status'], 'UNVERIFIED_RUNTIME_SUPPORT')
        self.assertFalse(support['supported'])
        self.assertFalse(support['autonomous_action_permitted'])
        self.assertTrue(support['enforcement_active'])
        self.assertEqual(result['operating_mode'], 'SHADOW_UNRESOLVED')
        self.assertIsNone(result['predicted_attack_stage'])
        self.assertEqual(result['stage_trajectory'], [])
        self.assertFalse(result['automatic_containment'])
        self.assertEqual(result['defence_signal']['sudarshana'], 'standby_support_unresolved')

    def test_reviewed_arjuna_match_cannot_bypass_support_gate(self):
        first = self.app.forecast(self.graph)['defence_signal']
        self.app.response.approve(first['id'], 'Reviewed lab replay', 'Operator inspected recorded V94 regression evidence')
        self.app.response.arm('198.51.100.2')
        second = self.app.forecast(self.graph)
        self.assertEqual(second['defence_signal']['route'], 'arjuna')
        self.assertEqual(second['defence_signal']['runtime_support_status'], 'UNVERIFIED_RUNTIME_SUPPORT')
        self.assertFalse(second['defence_signal']['autonomous_action_permitted'])
        self.assertFalse(second['automatic_containment'])
        self.assertEqual(self.app.policy.active(), [])

    def test_validation_fitted_gate_decision_is_fail_closed(self):
        x = np.full((12, 3, 4, 21), .2, dtype='float32')
        mask = np.ones((12, 3, 4), dtype='float32')
        gate = fit(x, mask, x, mask)
        inside = decision(gate, x[:1], mask[:1])
        shifted = decision(gate, x[:1] + .5, mask[:1])
        self.assertEqual(inside['status'], 'SUPPORTED')
        self.assertTrue(inside['autonomous_action_permitted'])
        self.assertEqual(shifted['status'], 'OUTSIDE_VALIDATED_SUPPORT')
        self.assertFalse(shifted['autonomous_action_permitted'])
        self.assertTrue(shifted['advisory_only'])

    def test_status_discloses_support_policy(self):
        status = self.app.integrated_status()['runtime_support_gate']
        self.assertFalse(status['present'])
        self.assertEqual(status['missing_gate_mode'], 'SHADOW_UNRESOLVED')
        self.assertFalse(status['abstention_is_detection'])


if __name__ == '__main__':
    unittest.main()
