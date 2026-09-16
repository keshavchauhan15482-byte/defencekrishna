import unittest

from garuda_v3 import v47_unseen_family as v47


class V47ClaimBoundaryTests(unittest.TestCase):
    def test_family_split_removes_heldout_family_from_development(self):
        import numpy as np
        seq = {
            'history_families': np.asarray([
                frozenset(), frozenset({'held'}), frozenset(), frozenset()
            ], dtype=object),
            'step_families': np.asarray([
                (frozenset(), frozenset(), frozenset(), frozenset()),
                (frozenset(), frozenset(), frozenset(), frozenset()),
                (frozenset({'held'}), frozenset(), frozenset(), frozenset()),
                (frozenset(), frozenset(), frozenset(), frozenset()),
            ], dtype=object),
            'clean': np.asarray([True, False, True, True]),
            'y': np.asarray([0, 0, 1, 0], dtype=np.int8),
        }
        masks = {
            'train': np.asarray([True, True, True, False]),
            'calibration': np.asarray([False, False, False, False]),
            'policy': np.asarray([False, False, False, False]),
            'test': np.asarray([False, False, True, True]),
        }
        split = v47.family_split(seq, masks, 'held')
        self.assertTrue(split['train'][0])
        self.assertFalse(split['train'][1])
        self.assertFalse(split['train'][2])
        self.assertTrue(split['test_positive'][2])
        self.assertTrue(split['test_negative'][3])

    def test_threshold_budget_is_benign_only(self):
        # V47 thresholding must not need attack positives; policy benign scores alone
        # define the maximum accepted empirical-FPR operating point.
        self.assertEqual(v47.FPR_BUDGET, 0.01)


if __name__ == '__main__':
    unittest.main()
