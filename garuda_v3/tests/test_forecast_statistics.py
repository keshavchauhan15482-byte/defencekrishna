import unittest

import numpy as np

from garuda_v3.forecast_statistics import campaign_bootstrap, fit_support_envelope, support_report


class ForecastStatisticsTests(unittest.TestCase):
    def test_support_envelope_is_fit_without_test_data(self):
        train = np.zeros((6, 2, 2, 3), dtype=np.float32)
        train[..., 0] = 0.2
        train[..., 1] = 0.4
        train[..., 2] = 0.6
        valid = train.copy()
        mask = np.ones((6, 2, 2), dtype=np.float32)
        envelope = fit_support_envelope(train, mask, valid, mask)
        test = train[:2].copy()
        test[1, ..., 0] = 1.0
        report = support_report(test, mask[:2], envelope)
        self.assertTrue(report["supported"][0])
        self.assertFalse(report["supported"][1])
        self.assertEqual(report["summary"]["supported_examples"], 1)

    def test_campaign_bootstrap_uses_campaign_units(self):
        datasets = []
        indices = []
        labels = []
        probabilities = []
        for source, campaign in enumerate(("a", "b", "c")):
            datasets.append({"metadata": {"campaign_id": campaign}})
            for j in range(4):
                indices.append((source, j))
                labels.append([0, 1] if j % 2 else [0, 0])
                probabilities.append([0.1, 0.9] if j % 2 else [0.1, 0.2])
        result = campaign_bootstrap(
            datasets,
            indices,
            np.asarray(labels),
            np.asarray(probabilities),
            0.5,
            seed=7,
            samples=100,
        )
        self.assertEqual(result["status"], "descriptive_campaign_bootstrap")
        self.assertEqual(result["campaigns"], 3)
        self.assertEqual(result["bootstrap_unit"], "campaign")


if __name__ == "__main__":
    unittest.main()
