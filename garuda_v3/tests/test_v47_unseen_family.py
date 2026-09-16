import unittest
import numpy as np

try:
    import pandas as pd
    from garuda_v3.v47_unseen_family import (
        detect_label_hierarchy,
        choose_network_numeric_features,
        fpr_threshold,
        family_split,
    )
    V47_RESEARCH_DEPS = True
except ModuleNotFoundError:
    pd = None
    V47_RESEARCH_DEPS = False


@unittest.skipUnless(V47_RESEARCH_DEPS, 'V47 research deps are intentionally separate from the production-facing runtime')
class V47UnseenFamilyTests(unittest.TestCase):
    def test_detects_binary_and_coarse_family_without_using_labels_as_features(self):
        df = pd.DataFrame({
            'class1': ['Reconnaissance', 'Reconnaissance', 'Normal', 'Lateral Movement'],
            'class2': ['Generic_scanning', 'fuzzing', 'Normal', 'TCP Relay'],
            'class3': ['Attack', 'Attack', 'Normal', 'Attack'],
            'Duration': [1, 2, 3, 4],
            'Scr_bytes': [10, 20, 30, 40],
        })
        y, family, binary_col, family_col, _ = detect_label_hierarchy(df)
        self.assertEqual(binary_col, 'class3')
        self.assertEqual(family_col, 'class1')
        self.assertEqual(y.tolist(), [1.0, 1.0, 0.0, 1.0])
        self.assertEqual(family.iloc[0], 'Reconnaissance')

    def test_network_feature_allowlist_rejects_host_and_alert_fields(self):
        n = 20
        df = pd.DataFrame({
            'Duration': np.arange(n) + 1,
            'Scr_bytes': np.arange(n) + 2,
            'Des_bytes': np.arange(n) + 3,
            'Scr_pkts': np.arange(n) + 4,
            'Des_pkts': np.arange(n) + 5,
            'total_bytes': np.arange(n) + 6,
            'byte_rate': np.arange(n) + 7,
            'is_SYN_only': np.arange(n) % 2,
            'OSSEC_alert_level': np.arange(n),
            'Avg_kbmemused': np.arange(n),
            'Process_activity': np.arange(n),
            'class1': ['Normal'] * n,
        })
        selected, _ = choose_network_numeric_features(df)
        self.assertGreaterEqual(len(selected), 8)
        self.assertNotIn('OSSEC_alert_level', selected)
        self.assertNotIn('Avg_kbmemused', selected)
        self.assertNotIn('Process_activity', selected)
        self.assertNotIn('class1', selected)

    def test_family_split_excludes_heldout_family_from_all_development_masks(self):
        n = 8
        sequences = {
            'history_families': np.asarray([
                frozenset(), frozenset({'Novel'}), frozenset(), frozenset(),
                frozenset(), frozenset(), frozenset(), frozenset(),
            ], dtype=object),
            'step_families': np.asarray([
                (frozenset(),) * 4,
                (frozenset(),) * 4,
                (frozenset({'Novel'}), frozenset(), frozenset(), frozenset()),
                (frozenset(),) * 4,
                (frozenset(),) * 4,
                (frozenset({'Novel'}), frozenset(), frozenset(), frozenset()),
                (frozenset(),) * 4,
                (frozenset(),) * 4,
            ], dtype=object),
            'clean': np.ones(n, dtype=bool),
            'y': np.asarray([0, 0, 1, 0, 0, 1, 0, 0], dtype=np.int8),
        }
        time_masks = {
            'train': np.asarray([1,1,1,0,0,0,0,0], dtype=bool),
            'calibration': np.asarray([0,0,0,1,0,0,0,0], dtype=bool),
            'policy': np.asarray([0,0,0,0,1,0,0,0], dtype=bool),
            'test': np.asarray([0,0,0,0,0,1,1,1], dtype=bool),
        }
        split = family_split(sequences, time_masks, 'Novel')
        self.assertFalse(split['train'][1])
        self.assertFalse(split['train'][2])
        self.assertTrue(split['train'][0])
        self.assertTrue(split['test_positive'][5])
        self.assertTrue(split['test_negative'][6])

    def test_policy_threshold_respects_empirical_one_percent_budget(self):
        scores = np.arange(100, dtype=float)
        th = fpr_threshold(scores, 0.01)
        self.assertLessEqual(int((scores >= th).sum()), 1)


if __name__ == '__main__':
    unittest.main()
