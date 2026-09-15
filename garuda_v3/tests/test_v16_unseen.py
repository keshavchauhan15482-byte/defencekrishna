import importlib.util
from pathlib import Path
import unittest

import numpy as np
import pandas as pd


SCRIPT = Path(__file__).parents[1] / "experiments" / "v16" / "v16_xiiotid_unseen_forecast.py"
spec = importlib.util.spec_from_file_location("v16_unseen", SCRIPT)
v16 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v16)


class V16ProtocolTests(unittest.TestCase):
    def test_class3_is_fine_grained_holdout_label(self):
        df = pd.DataFrame({
            "class1": ["Normal", "Attack", "Attack", "Attack"],
            "class2": ["Normal", "Reconnaissance", "Reconnaissance", "Exploitation"],
            "class3": ["Normal", "Generic Scanning", "Fuzzing", "Reverse Shell"],
        })
        y, binary, _ = v16.detect_binary_label(df)
        self.assertEqual(binary, "class1")
        self.assertEqual(v16.detect_family_col(df, binary), "class3")
        self.assertEqual(y.tolist(), [0.0, 1.0, 1.0, 1.0])

    def test_strict_network_filter_blocks_host_process_features(self):
        n = 100
        df = pd.DataFrame({
            "Scr_port": np.arange(n) + 1000,
            "Des_port": np.arange(n) + 2000,
            "Duration": np.linspace(1, 10, n),
            "Scr_bytes": np.arange(n) + 1,
            "Des_bytes": np.arange(n) + 2,
            "Scr_pkts": np.arange(n) + 3,
            "Des_pkts": np.arange(n) + 4,
            "packet_rate": np.linspace(0.1, 5, n),
            "Login_attempt": np.arange(n) % 2,
            "Process_activity": np.arange(n),
            "File_activity": np.arange(n),
            "Avg_system_time": np.arange(n),
            "class3": ["Normal"] * n,
        })
        cols, _ = v16.strict_network_features(df, {"class3"})
        self.assertIn("Scr_port", cols)
        self.assertIn("packet_rate", cols)
        self.assertNotIn("Login_attempt", cols)
        self.assertNotIn("Process_activity", cols)
        self.assertNotIn("File_activity", cols)
        self.assertNotIn("Avg_system_time", cols)

    def test_epoch_seconds_is_resolution_independent(self):
        s = pd.Series(pd.date_range("2026-01-01", periods=5, freq="min", tz="UTC"))
        t = v16.epoch_seconds(s)
        np.testing.assert_array_equal(np.diff(t), np.array([60, 60, 60, 60]))

    def test_policy_threshold_respects_one_percent_fpr(self):
        benign = np.linspace(0.0, 0.49, 1000)
        attack = np.linspace(0.30, 1.0, 200)
        y = np.concatenate([np.zeros(len(benign), dtype=int), np.ones(len(attack), dtype=int)])
        p = np.concatenate([benign, attack])
        th = v16.choose_fpr_threshold(y, p, max_fpr=0.01)
        m = v16.metrics(y, p, th)
        self.assertLessEqual(m["fpr"], 0.0100000001)

    def test_family_helpers_keep_holdout_explicit(self):
        hist = np.array([(), ("fuzzing",), ("reverse shell",)], dtype=object)
        fut = np.empty(3, dtype=object)
        fut[0] = (("fuzzing",), (), (), ())
        fut[1] = ((), (), (), ())
        fut[2] = ((), ("fuzzing",), (), ())
        np.testing.assert_array_equal(v16.future_has_family(fut, "fuzzing"), [True, False, True])
        np.testing.assert_array_equal(v16.history_has_family(hist, "fuzzing"), [False, True, False])
        np.testing.assert_array_equal(v16.family_lead_offsets(fut, "fuzzing"), [1, 0, 2])


if __name__ == "__main__":
    unittest.main()
