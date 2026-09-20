import tempfile
import unittest
from pathlib import Path
import numpy as np
from garuda_v3.v47_unseen_family import train_world_model, HISTORY, HORIZON, fpr_threshold
from garuda_v3.v48_unseen_fusion import raw_components, fused_score, COMPONENTS
import importlib.util


class RuntimeTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("torch"), "V48 parity requires optional torch research dependency")
    def test_export_reload_parity_and_contract(self):
        from garuda_v3.v48_runtime import export_fold, V48Runtime
        rng = np.random.default_rng(73)
        n = 180
        X = rng.normal(size=(n, HISTORY, 3)).astype('float32')
        future = rng.normal(size=(n, HORIZON, 3)).astype('float32')
        y = np.zeros(n, dtype=int); y[:40] = 1
        split = {k: np.zeros(n, dtype=bool) for k in ('train', 'calibration', 'policy')}
        split['train'][:80] = True; split['calibration'][80:120] = True; split['policy'][120:150] = True
        world = train_world_model(X, future, split['train'], split['calibration'], 42, epochs=2)
        sequences = {'X': X, 'y': y, 'clean': y == 0}
        components = raw_components(world, sequences, split, 42)
        config = {'weights': {k: 1 / len(COMPONENTS) for k in COMPONENTS}}
        expected = fused_score(components['evidence'], config['weights'])
        threshold = fpr_threshold(expected[components['policy_benign']], .01)
        fold = {'world': world, 'components': components, 'seed': 42, 'family': 'synthetic'}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fold'
            export_fold(path, fold, config, threshold, ['a', 'b', 'c'])
            runtime = V48Runtime(path)
            result = runtime.predict(X, ['a', 'b', 'c'])
            np.testing.assert_allclose(result['state_scaled'], world['pred'], atol=1e-6)
            np.testing.assert_allclose(result['score'], expected, atol=1e-12)
            np.testing.assert_array_equal(result['alert'], (expected >= threshold) & world['state_gate_passed'])
            for key in COMPONENTS:
                np.testing.assert_allclose(result['components'][key], components['evidence'][key], atol=1e-12)
            with self.assertRaises(ValueError): runtime.predict(X, ['b', 'a', 'c'])
            with self.assertRaises(ValueError): runtime.predict(X, ['a', 'b', 'c'], 10)
            with self.assertRaises(ValueError): runtime.predict(X[:, :2], ['a', 'b', 'c'])
            with (path / 'arrays.npz').open('ab') as f: f.write(b'changed')
            with self.assertRaises(ValueError): V48Runtime(path)

    def test_missing_seeds_cannot_pass(self):
        from unittest.mock import patch
        from garuda_v3.v48_unseen_fusion import evaluate_reserve_family
        with patch('garuda_v3.v48_unseen_fusion.prepare_fold', return_value=None):
            result = evaluate_reserve_family({}, {}, 'missing', [42, 43, 44], 1, {})
        self.assertFalse(result['summary']['state_gate_passed_all_seeds'])
        self.assertFalse(result['summary']['unseen_gate_passed_all_seeds'])
        self.assertEqual(result['summary']['evaluated_seeds'], 0)
