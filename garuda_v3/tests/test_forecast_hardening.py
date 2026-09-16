import tempfile
import unittest
from pathlib import Path

import numpy as np

from garuda_v3.data import FEATURES, SCHEMA
from garuda_v3.forecast_hardening import (
    abstention_status,
    family_release_gate,
    lead_time_summary,
    multi_horizon_targets,
    persistence_gate,
    reserve_final_holdout,
    validate_campaign_split_manifest,
    validate_network_dataset_contract,
)


def dataset(campaign, digest, labels=(0, 0, 1, -1)):
    return {
        "x": np.zeros((len(labels), 32, len(FEATURES)), dtype=np.float32),
        "adj": np.zeros((len(labels), 32, 32), dtype=np.float32),
        "mask": np.ones((len(labels), 32), dtype=np.float32),
        "y": np.asarray(labels, dtype=np.int8),
        "times": np.arange(len(labels), dtype=np.int64) * 10,
        "metadata": {
            "schema": SCHEMA,
            "features": FEATURES,
            "mode": "host",
            "window_seconds": 10,
            "max_nodes": 32,
            "source_sha256": digest,
            "campaign_id": campaign,
        },
    }


class ForecastHardeningTests(unittest.TestCase):
    def test_network_contract_requires_common_10_second_schema(self):
        a = dataset("train-a", "a" * 64)
        b = dataset("test-a", "b" * 64)
        result = validate_network_dataset_contract([a, b], expected_window_seconds=10)
        self.assertEqual(result["window_seconds"], 10)
        b["metadata"]["window_seconds"] = 60
        with self.assertRaises(ValueError):
            validate_network_dataset_contract([a, b], expected_window_seconds=10)

    def test_unknown_is_not_silently_benign_at_any_horizon(self):
        labels = np.asarray([
            [0, -1, 0, 0],
            [0, 1, -1, 0],
            [0, 0, 0, 0],
        ])
        target = multi_horizon_targets(labels, (1, 2, 4))
        self.assertEqual(target.tolist(), [[0, -1, -1], [0, 1, 1], [0, 0, 0]])

    def test_campaign_split_is_disjoint_and_exhaustive(self):
        data = [dataset("train-a", "a" * 64), dataset("val-a", "b" * 64), dataset("test-a", "c" * 64)]
        split = validate_campaign_split_manifest(
            {"train": ["train-a"], "validation": ["val-a"], "test": ["test-a"]}, data
        )
        self.assertTrue(split["test_is_final_holdout"])
        with self.assertRaises(ValueError):
            validate_campaign_split_manifest(
                {"train": ["train-a"], "validation": ["val-a"], "test": ["val-a", "test-a"]}, data
            )

    def test_final_holdout_reservation_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "reservation.json"
            first = reserve_final_holdout(p, campaign_ids=["final-a"], source_hashes=["a" * 64])
            second = reserve_final_holdout(p, campaign_ids=["final-a"], source_hashes=["a" * 64])
            self.assertEqual(first, second)
            with self.assertRaises(FileExistsError):
                reserve_final_holdout(p, campaign_ids=["final-b"], source_hashes=["b" * 64])

    def test_persistence_is_a_hard_validation_gate(self):
        self.assertTrue(persistence_gate(0.8, 1.0)["passed"])
        rejected = persistence_gate(1.0, 1.0)
        self.assertFalse(rejected["passed"])
        self.assertIn("persistence", rejected["status"])

    def test_family_gate_requires_support_and_target_metrics(self):
        reports = {
            "dos": {
                "positives": 25,
                "negatives": 100,
                "fpr": 0.01,
                "recall": 0.84,
                "policy_enabled": True,
            },
            "botnet": {
                "positives": 3,
                "negatives": 100,
                "fpr": 0.0,
                "recall": 1.0,
                "policy_enabled": True,
            },
        }
        result = family_release_gate(reports, min_positives=20, min_negatives=20)
        self.assertFalse(result["passed"])
        self.assertTrue(result["per_family"]["dos"]["passed"])
        self.assertEqual(result["per_family"]["botnet"]["reason"], "insufficient_support")

    def test_verified_lead_time_counts_missing_warning_as_miss(self):
        summary = lead_time_summary([100.0, 200.0, 300.0], [90.0, None, 310.0], bootstrap_samples=0)
        self.assertEqual(summary["warned_before_compromise"], 1)
        self.assertAlmostEqual(summary["pre_compromise_warning_rate"], 1 / 3)
        self.assertEqual(summary["median_lead_seconds"], 10.0)

    def test_abstention_is_fail_closed(self):
        status = abstention_status(
            contract_valid=True,
            policy_enabled=True,
            persistence_passed=False,
            supported_family=True,
        )
        self.assertTrue(status["abstain"])
        self.assertEqual(status["status"], "insufficient_evidence")


if __name__ == "__main__":
    unittest.main()
