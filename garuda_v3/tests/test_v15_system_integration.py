import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.integrated_server import IntegratedApp
from garuda_v3.v15_bridge import V15EvidenceBridge

ARTIFACTS = Path(__file__).resolve().parents[1] / 'artifacts/residual_run'
UI_APP = Path(__file__).resolve().parents[1] / 'ui/app.js'


class V15SystemIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.bridge = V15EvidenceBridge()
        self.tmp = tempfile.TemporaryDirectory()
        self.app = IntegratedApp(
            ARTIFACTS, self.tmp.name, 'v'*40, 'o'*40,
            policy_key='k'*40, allowed_cidrs=['198.51.100.0/24'],
            enforce=True, lab_automation=True,
        )
        self.graph = json.loads((ARTIFACTS / 'alert_replay.json').read_text())

    def tearDown(self):
        self.app.policy.close()
        self.tmp.cleanup()

    def test_fresh_lstm_metrics_are_loaded_from_persisted_evidence(self):
        s = self.bridge.public_status()['lstm']
        self.assertEqual(s['observed_fpr'], 0.0)
        self.assertAlmostEqual(s['recall'], 0.8608946608946608)
        self.assertAlmostEqual(s['pr_auc'], 0.9914998221988123)

    def test_same_untouched_test_support_is_preserved(self):
        self.assertEqual(self.bridge.public_status()['test_support'], {'n':2521, 'benign':1366, 'attack':1155})

    def test_zero_clean_history_onsets_blocks_precompromise_claim(self):
        s = self.bridge.public_status()
        self.assertEqual(s['clean_history_future_positive_n'], 0)
        self.assertFalse(s['pre_compromise_warning_verified'])
        self.assertFalse(s['autonomous_unknown_containment_approved'])

    def test_network_only_and_runtime_compatibility_gates_are_explicit(self):
        s = self.bridge.public_status()
        self.assertFalse(s['network_only_feature_audit_passed'])
        self.assertFalse(s['runtime_graph_schema_compatible'])
        self.assertFalse(s['deployable_risk_checkpoint_available'])

    def test_gnn_branch_is_retained_but_not_claimed_better_than_lstm(self):
        s = self.bridge.public_status()
        self.assertLess(s['lstm']['brier'], s['gnn_lstm']['brier'])
        self.assertGreater(s['lstm']['recall'], s['gnn_lstm']['recall'])

    def test_integrated_status_exposes_v15_and_fail_closed_response_state(self):
        status = self.app.integrated_status()
        self.assertIn('v15', status)
        self.assertFalse(status['v15']['autonomous_unknown_containment_approved'])
        self.assertFalse(status['response']['unknown_forecast_autonomous_containment_approved'])

    def test_dashboard_surfaces_v15_evidence_and_limits(self):
        source = UI_APP.read_text()
        self.assertIn('garuda_v15', source)
        self.assertIn('clean-history future-positive', source)
        self.assertIn('network-only audit', source)
        self.assertIn('shadow-only', source)

    def test_real_forecast_is_decorated_with_v15_and_system_roles(self):
        out = self.app.forecast(self.graph)
        self.assertIn('garuda_v15', out)
        self.assertIn('krishna_system', out)
        self.assertEqual(out['defence_signal']['route'], 'krishna')
        self.assertFalse(out['defence_signal']['unknown_forecast_autonomous_containment_approved'])

    def test_armed_unknown_forecast_stays_shadow_with_current_v15_evidence(self):
        self.app.response.arm('198.51.100.2')
        out = self.app.forecast(self.graph)
        self.assertTrue(out['alert'])
        self.assertFalse(out['automatic_containment'])
        self.assertEqual(out['defence_signal']['sudarshana'], 'standby_unapproved_forecast')
        self.assertEqual(self.app.policy.active(), [])

    def test_reviewed_arjuna_memory_can_use_existing_scoped_lab_enforcement(self):
        first = self.app.forecast(self.graph)['defence_signal']
        self.app.response.approve(first['id'], 'Reviewed lab replay', 'Operator inspected recorded evidence and approved exact snapshot')
        self.app.response.arm('198.51.100.2')
        out = self.app.forecast(self.graph)
        self.assertEqual(out['defence_signal']['route'], 'arjuna')
        self.assertTrue(out['automatic_containment'])
        self.assertEqual(out['defence_signal']['target'], '198.51.100.2')


if __name__ == '__main__':
    unittest.main()
