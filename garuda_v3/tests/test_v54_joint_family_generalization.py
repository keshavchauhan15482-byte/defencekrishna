import unittest
import numpy as np

try:
    from garuda_v3.v54_joint_family_generalization import (
        _joint_development_split,
        _joint_reserve_split,
        _selection_objective,
        _simplex_weight_sets,
    )
    V54_DEPS = True
except ModuleNotFoundError:
    V54_DEPS = False


@unittest.skipUnless(V54_DEPS, 'V54 research deps are intentionally separate from production runtime')
class V54JointFamilyTests(unittest.TestCase):
    @staticmethod
    def _sequences():
        n = 50
        histories = []
        steps = []
        for i in range(n):
            hist = set()
            future = [set(), set(), set(), set()]
            if i == 20:
                future[0].add('reserve-a')
            if i == 25:
                future[1].add('reserve-b')
            if i == 35:
                future[0].add('dev-a')
            if i == 40:
                future[0].add('dev-b')
            histories.append(frozenset(hist))
            steps.append(tuple(frozenset(x) for x in future))
        return {
            'X': np.zeros((n, 8, 2), dtype=np.float32),
            'future': np.zeros((n, 4, 2), dtype=np.float32),
            'cutoff': np.arange(n, dtype=np.int64) * 60,
            'clean': np.ones(n, dtype=bool),
            'y': np.zeros(n, dtype=np.int8),
            'history_families': np.asarray(histories, dtype=object),
            'step_families': np.asarray(steps, dtype=object),
        }

    @staticmethod
    def _masks(n=50):
        return {
            'train': np.arange(n) < 15,
            'calibration': (np.arange(n) >= 15) & (np.arange(n) < 25),
            'policy': (np.arange(n) >= 25) & (np.arange(n) < 35),
            'test': np.arange(n) >= 35,
        }

    def test_simplex_weights_are_complete_and_normalized(self):
        rows = _simplex_weight_sets()
        self.assertGreaterEqual(len(rows), 70)
        for row in rows:
            self.assertAlmostEqual(sum(row['weights'].values()), 1.0, places=8)
            self.assertTrue(all(v >= 0.0 for v in row['weights'].values()))

    def test_joint_reserve_split_excludes_both_reserve_families(self):
        seq = self._sequences()
        masks = self._masks()
        split = _joint_reserve_split(seq, masks, ('reserve-a', 'reserve-b'))
        self.assertTrue(split['blocked'][20])
        self.assertTrue(split['blocked'][25])
        self.assertFalse(split['train'][20])
        self.assertFalse(split['calibration'][20])
        self.assertFalse(split['policy'][25])

    def test_development_pair_split_also_respects_permanent_reserve_mask(self):
        seq = self._sequences()
        masks = self._masks()
        from garuda_v3.v48_strict_runner import reserve_exposure_mask
        reserve = reserve_exposure_mask(seq, ('reserve-a', 'reserve-b'))
        split = _joint_development_split(seq, masks, ('dev-a', 'dev-b'), reserve)
        self.assertTrue(split['blocked'][20])
        self.assertTrue(split['blocked'][25])
        self.assertTrue(split['blocked'][35])
        self.assertTrue(split['blocked'][40])
        self.assertFalse(np.any(split['train'] & reserve))
        self.assertFalse(np.any(split['calibration'] & reserve))
        self.assertFalse(np.any(split['policy'] & reserve))
        self.assertFalse(np.any(split['selection_negative'] & reserve))

    def test_selection_objective_rewards_more_full_gate_folds(self):
        stronger = [
            {'state_gate_passed': True, 'fpr': 0.005, 'recall': 0.85},
            {'state_gate_passed': True, 'fpr': 0.006, 'recall': 0.82},
        ]
        weaker = [
            {'state_gate_passed': True, 'fpr': 0.003, 'recall': 0.95},
            {'state_gate_passed': True, 'fpr': 0.003, 'recall': 0.60},
        ]
        self.assertGreater(_selection_objective(stronger), _selection_objective(weaker))

    def test_selection_objective_breaks_ties_on_worst_safe_recall(self):
        a = [
            {'state_gate_passed': True, 'fpr': 0.005, 'recall': 0.82},
            {'state_gate_passed': True, 'fpr': 0.005, 'recall': 0.84},
        ]
        b = [
            {'state_gate_passed': True, 'fpr': 0.005, 'recall': 0.80},
            {'state_gate_passed': True, 'fpr': 0.005, 'recall': 0.90},
        ]
        self.assertGreater(_selection_objective(a), _selection_objective(b))


if __name__ == '__main__':
    unittest.main()
