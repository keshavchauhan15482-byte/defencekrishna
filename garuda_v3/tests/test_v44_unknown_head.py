import unittest
import numpy as np

from garuda_v3.experiments.v44.unknown_head import (
    RobustReference, benign_threshold, combine_scores, tail_score,
)


class V44UnknownHeadTests(unittest.TestCase):
    def test_robust_reference_scores_shifted_samples_higher(self):
        rng = np.random.default_rng(7)
        benign = rng.normal(0, 0.2, size=(200, 6))
        ref = RobustReference.fit(benign)
        normal = ref.score(rng.normal(0, 0.2, size=(40, 6)))
        shifted = ref.score(rng.normal(2.0, 0.2, size=(40, 6)))
        self.assertGreater(float(np.median(shifted)), float(np.median(normal)) * 3)

    def test_tail_score_is_empirical_and_bounded(self):
        ref = np.linspace(0.0, 1.0, 100)
        score = tail_score(ref, np.asarray([-1.0, 0.5, 2.0]))
        self.assertEqual(float(score[0]), 0.0)
        self.assertTrue(0.49 <= float(score[1]) <= 0.51)
        self.assertEqual(float(score[2]), 1.0)

    def test_benign_threshold_respects_empirical_budget(self):
        benign = np.linspace(0.0, 0.99, 200)
        policy = benign_threshold(benign, 0.01)
        self.assertEqual(policy["status"], "benign_validation_selected")
        self.assertLessEqual(policy["validation_fpr"], 0.01)
        self.assertIsNotNone(policy["threshold"])

    def test_threshold_fails_closed_with_too_few_benign_examples(self):
        policy = benign_threshold(np.linspace(0, 1, 99), 0.01)
        self.assertIsNone(policy["threshold"])
        self.assertEqual(policy["status"], "insufficient_benign_validation_support")

    def test_fixed_combination_does_not_fit_attack_labels(self):
        train = {
            "history_novelty": np.linspace(0, 1, 100),
            "forecast_novelty": np.linspace(0, 1, 100),
            "topology_novelty": np.linspace(0, 1, 100),
            "model_disagreement": np.linspace(0, 1, 100),
        }
        values = {k: np.asarray([0.0, 2.0]) for k in train}
        score, parts = combine_scores(train, values)
        self.assertEqual(score.shape, (2,))
        self.assertLess(float(score[0]), float(score[1]))
        self.assertEqual(set(parts), set(train))


if __name__ == "__main__":
    unittest.main()
