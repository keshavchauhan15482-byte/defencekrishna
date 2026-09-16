import unittest

import numpy as np

from garuda_v3.data import FEATURES
from garuda_v3.model import GraphWorldModel
from garuda_v3.train_v45_core import fit_risk_head, fit_state


def arrays(seed=1, examples=8, history=3, horizon=2, nodes=4):
    rng = np.random.default_rng(seed)
    x = rng.uniform(0.05, 0.4, (examples, history, nodes, len(FEATURES))).astype(np.float32)
    adj = np.zeros((examples, history, nodes, nodes), dtype=np.float32)
    mask = np.ones((examples, history, nodes), dtype=np.float32)
    pooled = x.mean(axis=2)[:, -1]
    target = np.stack([np.clip(pooled + 0.01 * (h + 1), 0, 1) for h in range(horizon)], axis=1)
    labels = np.asarray([[0, 0], [0, 1], [1, 1], [0, 0], [1, 0], [0, 1], [1, 1], [0, 0]], dtype=np.float32)
    ongoing = np.zeros(examples, dtype=np.float32)
    return x, adj, mask, target.astype(np.float32), labels, ongoing


class V45TrainingCoreTests(unittest.TestCase):
    def test_epoch_zero_residual_model_is_persistence_baseline(self):
        train = arrays(1)
        valid = arrays(2)
        model = GraphWorldModel(architecture="lstm", seed=42, decoder="residual")
        result = fit_state(model, train, valid, epochs=1, patience=1, seed=42)
        epoch0 = result["curve"][0]
        self.assertAlmostEqual(
            epoch0["validation_state_mse"],
            epoch0["persistence_mse"],
            places=6,
        )

    def test_risk_phase_does_not_modify_world_model_parameters(self):
        train = arrays(3)
        valid = arrays(4)
        model = GraphWorldModel(architecture="lstm", seed=7, decoder="residual")
        frozen = {
            name: tensor.data.copy()
            for name, tensor in model.params.items()
            if name not in {"risk", "risk_b"}
        }
        risk_before = model.params["risk"].data.copy()
        fit_risk_head(model, train, valid, epochs=2, patience=2, seed=7)
        for name, value in frozen.items():
            np.testing.assert_array_equal(model.params[name].data, value)
        self.assertFalse(np.array_equal(model.params["risk"].data, risk_before))


if __name__ == "__main__":
    unittest.main()
