import unittest
import numpy as np

from garuda_v3.latest_state_runtime import LatestStateForecastService
from garuda_v3.ps_complete import FEATURES


class V127DualLiveRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = LatestStateForecastService()

    def test_v123_runtime_is_pinned_state_only(self):
        status = self.service.public_status()
        self.assertTrue(status['enabled'])
        self.assertEqual(status['role'], 'state_forecasting_only')
        self.assertEqual(status['feature_count'], 34)
        self.assertTrue(status['packet_features_trained'])
        self.assertFalse(status['risk_head_trained'])
        self.assertFalse(status['stage_head_trained'])
        self.assertEqual(status['fresh_external_evidence'], 'V123 PASS')
        self.assertGreater(status['v123_improvement_vs_persistence'], 0.0)

    def test_supported_history_produces_four_state_steps_without_risk_claim(self):
        h, n, f = 8, 32, len(FEATURES)
        x = np.zeros((h, n, f), dtype=np.float32)
        adj = np.zeros((h, n, n), dtype=np.float32)
        mask = np.zeros((h, n), dtype=np.float32)
        mask[:, 0] = 1.0
        for name in ('packet_features_present', 'iat_present', 'tcp_window_present', 'payload_present', 'scan_sequence_present'):
            x[:, 0, FEATURES.index(name)] = 1.0
        times = np.arange(h, dtype=np.int64) * 10

        out = self.service.forecast_history(x, adj, mask, times)
        self.assertEqual(out['status'], 'SUPPORTED_STATE_FORECAST')
        self.assertEqual(len(out['trajectory']), 4)
        self.assertIsNone(out['risk_probability'])
        self.assertIsNone(out['mitre_stage'])
        self.assertFalse(out['automatic_containment'])
        self.assertEqual(out['fresh_external_evidence']['status'], 'PASS')
        self.assertEqual(out['fresh_external_evidence']['sequences'], 2209)


if __name__ == '__main__':
    unittest.main()
