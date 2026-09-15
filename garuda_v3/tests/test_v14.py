import tempfile
import unittest
from pathlib import Path

import numpy as np

from garuda_v3.v14_readiness import evaluate
from garuda_v3.v14_risk_support import training_only_hard_negative_weights
from garuda_v3.verified_campaigns import (
    add_benign_interval,
    add_event,
    clean_history_eligible,
    freeze_campaign_split,
    future_binary_target,
    new_manifest,
    validate_manifest,
)


class V14VerifiedCampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.capture = Path(self.tmp.name) / 'capture.pcap'
        self.capture.write_bytes(b'controlled-capture-fixture')
        self.base = new_manifest(
            campaign_id='lab-1', role='attack', domain='isolated-lab',
            capture_path=self.capture, graph_path='graphs/lab-1.npz',
            start_epoch=1000, end_epoch=3000, timezone='UTC',
            evidence_source='controller + target receipt logs',
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_compromise_requires_successful_evidenced_event(self):
        with self.assertRaises(ValueError):
            add_event(self.base, event_id='bad', epoch=2000, stage='Initial Access', outcome='failure', evidence='controller receipt', establishes_compromise=True)

    def test_missing_annotation_never_becomes_benign(self):
        self.assertIsNone(future_binary_target(self.base, 1500, 4))

    def test_explicit_benign_coverage_and_clean_history(self):
        m = add_benign_interval(self.base, 1000, 2200, 'predeclared idle baseline')
        self.assertEqual(future_binary_target(m, 1500, 4), 0)
        self.assertTrue(clean_history_eligible(m, 2000, 8))

    def test_successful_event_makes_future_target_positive(self):
        m = add_event(self.base, event_id='ia', epoch=1700, stage='Initial Access', outcome='success', evidence='controller + target success receipt')
        self.assertEqual(future_binary_target(m, 1500, 4), 1)

    def test_campaign_split_is_disjoint_exhaustive_and_immutable(self):
        path = Path(self.tmp.name) / 'split.json'
        assignment = {'train':['a'], 'calibration':['b'], 'policy':['c'], 'final_test':['d']}
        freeze_campaign_split(path, assignment, ['a','b','c','d'])
        with self.assertRaises(FileExistsError):
            freeze_campaign_split(path, assignment, ['a','b','c','d'])
        with self.assertRaises(ValueError):
            freeze_campaign_split(Path(self.tmp.name)/'bad.json', {'train':['a'], 'calibration':['a'], 'policy':['c'], 'final_test':['d']}, ['a','c','d'])

    def test_training_only_group_oof_hard_negative_support(self):
        rng = np.random.default_rng(4)
        X = rng.normal(size=(40, 3)); y = np.array([0,1]*20); groups = np.repeat(np.arange(8), 5)
        result = training_only_hard_negative_weights(X, y, groups, folds=4)
        self.assertEqual(result['scope'], 'training_groups_only')
        self.assertEqual(len(result['weights']), 40)
        self.assertTrue(np.isfinite(result['oof_probability']).all())

    def test_readiness_fails_closed_without_independent_campaign_support(self):
        r = evaluate([])
        self.assertFalse(r['ready'])
        self.assertIn('No verified campaign manifests', r['reason'])


if __name__ == '__main__':
    unittest.main()
