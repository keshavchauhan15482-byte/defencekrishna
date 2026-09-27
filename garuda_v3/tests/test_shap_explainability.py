import unittest

import numpy as np

from garuda_v3.data import FEATURES
from garuda_v3.shap_explainability import channel_coalition_predictor


class _Risk:
    def __init__(self, data):
        self.data = data


class _FakeModel:
    def forward(self, x, adj, mask, horizon=4):
        pooled = (x * mask[:, :, :, None]).sum(axis=(1, 2, 3))
        risk = np.repeat((pooled / 100.0)[:, None], horizon, axis=1)
        return None, None, _Risk(risk)


class ShapExplainabilityContractTests(unittest.TestCase):
    def fixture(self):
        f = len(FEATURES)
        x = np.ones((1, 2, 3, f), dtype=np.float32)
        mask = np.ones((1, 2, 3), dtype=np.float32)
        adj = np.zeros((1, 2, 3, 3), dtype=np.float32)
        return x, adj, mask

    def test_zero_and_full_coalitions_are_deterministic(self):
        x, adj, mask = self.fixture()
        fn = channel_coalition_predictor(_FakeModel(), x, adj, mask, horizon=4)
        zero = fn(np.zeros((1, len(FEATURES)), dtype=np.float32))[0]
        full = fn(np.ones((1, len(FEATURES)), dtype=np.float32))[0]
        self.assertEqual(zero, 0.0)
        self.assertGreater(full, zero)

    def test_future_labels_are_not_an_input(self):
        x, adj, mask = self.fixture()
        fn = channel_coalition_predictor(_FakeModel(), x, adj, mask, horizon=4, target_horizon=2)
        values = fn(np.vstack([np.zeros(len(FEATURES)), np.ones(len(FEATURES))]))
        self.assertEqual(values.shape, (2,))

    def test_wrong_feature_contract_is_rejected(self):
        x, adj, mask = self.fixture()
        with self.assertRaises(ValueError):
            channel_coalition_predictor(_FakeModel(), x[..., :-1], adj, mask, horizon=4)


if __name__ == "__main__":
    unittest.main()
