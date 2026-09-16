import unittest
import numpy as np

try:
    from garuda_v3.v48_unseen_fusion import (
        COMPONENTS,
        EXPOSED_DEVELOPMENT_FAMILIES,
        candidate_weight_sets,
        tail_evidence,
        fused_score,
        _canonical_hash,
    )
    V48_DEPS = True
except ModuleNotFoundError:
    V48_DEPS = False


@unittest.skipUnless(V48_DEPS, 'V48 research deps are intentionally separate from production runtime')
class V48FusionTests(unittest.TestCase):
    def test_tail_evidence_is_monotonic_for_larger_suspicion(self):
        cal = np.arange(1, 101, dtype=float)
        score = tail_evidence(cal, np.asarray([10.0, 50.0, 99.0, 120.0]))
        self.assertTrue(np.all(np.diff(score) >= 0))
        self.assertGreater(score[-1], score[0])

    def test_candidate_weights_are_nonnegative_and_normalized(self):
        candidates = candidate_weight_sets()
        self.assertGreaterEqual(len(candidates), 10)
        for row in candidates:
            self.assertEqual(set(row['weights']), set(COMPONENTS))
            self.assertAlmostEqual(sum(row['weights'].values()), 1.0, places=7)
            self.assertTrue(all(v >= 0 for v in row['weights'].values()))

    def test_fusion_uses_only_named_components(self):
        evidence = {k: np.asarray([1.0, 2.0]) for k in COMPONENTS}
        weights = {k: 0.0 for k in COMPONENTS}
        weights['known_attack_transfer'] = 0.75
        weights['predicted_delta_novelty'] = 0.25
        out = fused_score(evidence, weights)
        np.testing.assert_allclose(out, np.asarray([1.0, 2.0]))

    def test_exposed_v47_families_are_explicitly_frozen_as_development(self):
        self.assertIn('Weaponization', EXPOSED_DEVELOPMENT_FAMILIES)
        self.assertIn('Exfiltration', EXPOSED_DEVELOPMENT_FAMILIES)
        self.assertIn('Lateral Movement', EXPOSED_DEVELOPMENT_FAMILIES)
        self.assertGreaterEqual(len(EXPOSED_DEVELOPMENT_FAMILIES), 5)

    def test_config_hash_is_order_stable(self):
        a = {'weights': {'b': 2, 'a': 1}, 'budget': 0.005}
        b = {'budget': 0.005, 'weights': {'a': 1, 'b': 2}}
        self.assertEqual(_canonical_hash(a), _canonical_hash(b))


if __name__ == '__main__':
    unittest.main()
