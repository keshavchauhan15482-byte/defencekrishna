from __future__ import annotations

import unittest
import numpy as np

from garuda_v3.v111_freeze_warning_policy import (
    POLICY_BUDGET,
    WarningPolicyError,
    transition_score,
    upper_tail_threshold,
)


class V111WarningPolicyTests(unittest.TestCase):
    def test_transition_score_uses_prediction_vs_persistence_only(self):
        pred = np.array([[[1., 2.], [3., 4.]], [[2., 2.], [2., 2.]]])
        base = np.array([[[0., 2.], [1., 4.]], [[2., 1.], [2., 3.]]])
        score = transition_score(pred, base)
        np.testing.assert_allclose(score, [0.75, 0.5])

    def test_higher_empirical_quantile_is_deterministic(self):
        x = np.arange(1, 1001, dtype=float)
        threshold = upper_tail_threshold(x, POLICY_BUDGET)
        self.assertEqual(threshold, 995.0)
        self.assertEqual(int(np.sum(x > threshold)), 5)

    def test_small_reference_is_rejected(self):
        with self.assertRaises(WarningPolicyError):
            upper_tail_threshold(np.arange(99, dtype=float), POLICY_BUDGET)

    def test_shape_mismatch_rejected(self):
        with self.assertRaises(WarningPolicyError):
            transition_score(np.zeros((2,4,34)), np.zeros((2,4,21)))


if __name__ == '__main__':
    unittest.main()
