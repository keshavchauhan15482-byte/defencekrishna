import unittest
import numpy as np
import pandas as pd

from garuda_v3.data import FEATURES, MAX_NODES, SCHEMA
from garuda_v3.experiments.v44.network_feature_gate import choose_numeric_features
from garuda_v3.experiments.v44.runtime_contract import (
    HISTORY, HORIZON, WINDOW_SECONDS, assert_runtime_dataset,
    unix_seconds, validate_metadata,
)


class V44RuntimeContractTests(unittest.TestCase):
    def metadata(self):
        return {
            "schema": SCHEMA,
            "features": list(FEATURES),
            "window_seconds": WINDOW_SECONDS,
            "max_nodes": MAX_NODES,
            "synthetic": False,
            "packet_features": True,
        }

    def dataset(self):
        n = 3
        return {
            "x": np.zeros((n, MAX_NODES, len(FEATURES)), dtype=np.float32),
            "adj": np.zeros((n, MAX_NODES, MAX_NODES), dtype=np.float32),
            "mask": np.zeros((n, MAX_NODES), dtype=np.float32),
            "times": np.arange(n, dtype=np.int64) * WINDOW_SECONDS,
            "metadata": self.metadata(),
        }

    def test_exact_live_contract(self):
        self.assertEqual(WINDOW_SECONDS, 10)
        self.assertEqual(HISTORY, 8)
        self.assertEqual(HORIZON, 4)
        self.assertEqual(len(FEATURES), 21)
        assert_runtime_dataset(self.dataset())

    def test_rejects_old_60_second_64_node_contract(self):
        meta = self.metadata()
        meta.update(window_seconds=60, max_nodes=64)
        errors = validate_metadata(meta)
        self.assertTrue(any(x.startswith("window_seconds") for x in errors))
        self.assertTrue(any(x.startswith("max_nodes") for x in errors))

    def test_rejects_non_network_feature_injection(self):
        meta = self.metadata()
        meta["features"] = list(FEATURES[:-1]) + ["Process_activity"]
        errors = validate_metadata(meta)
        self.assertIn("feature_order_mismatch", errors)
        self.assertTrue(any(x.startswith("forbidden_feature_names") for x in errors))

    def test_rejects_synthetic_or_missing_packet_evidence(self):
        meta = self.metadata()
        meta["synthetic"] = True
        self.assertIn("synthetic_or_unspecified", validate_metadata(meta))
        meta = self.metadata()
        meta["packet_features"] = False
        self.assertIn("packet_features_not_observed", validate_metadata(meta))

    def test_unix_seconds_does_not_assume_datetime_storage_unit(self):
        values = pd.Series(pd.to_datetime(
            ["2026-09-16T00:00:00Z", "2026-09-16T00:01:00Z"], utc=True
        ))
        sec = unix_seconds(values)
        self.assertEqual(int(sec[1] - sec[0]), 60)
        self.assertEqual(sec.dtype, np.dtype("int64"))

    def test_tabular_gate_rejects_process_system_fields(self):
        frame = pd.DataFrame({
            "Flow_Duration": np.arange(20, dtype=float),
            "Packet_Count": np.arange(20, dtype=float) + 1,
            "TCP_Window": np.arange(20, dtype=float) + 2,
            "Bytes_Total": np.arange(20, dtype=float) + 3,
            "Process_activity": np.arange(20, dtype=float) + 4,
            "CPU_usage": np.arange(20, dtype=float) + 5,
            "Attack_label": [0, 1] * 10,
        })
        selected = choose_numeric_features(frame)
        self.assertIn("Flow_Duration", selected)
        self.assertIn("Packet_Count", selected)
        self.assertNotIn("Process_activity", selected)
        self.assertNotIn("CPU_usage", selected)
        self.assertNotIn("Attack_label", selected)

    def test_tabular_gate_fails_closed_below_four_network_features(self):
        frame = pd.DataFrame({
            "Flow_Duration": np.arange(20, dtype=float),
            "Packet_Count": np.arange(20, dtype=float),
            "Process_activity": np.arange(20, dtype=float),
            "CPU_usage": np.arange(20, dtype=float),
        })
        with self.assertRaises(RuntimeError):
            choose_numeric_features(frame)


if __name__ == "__main__":
    unittest.main()
