import unittest

import numpy as np

from garuda_v3.v92_corrected_attack_step_leadtime import (
    bootstrap_median_ci,
    group_event_onsets,
    onset_audit,
    prediction_issue_times,
)


class V92CorrectedLeadTimeTests(unittest.TestCase):
    def test_prediction_uses_history_window_end(self):
        np.testing.assert_allclose(prediction_issue_times([100, 110]), [110, 120])

    def test_history_start_would_inflate_lead_by_one_window(self):
        onset = [{"epoch": 150.0, "tactics": ["x"], "techniques": ["y"], "raw_rows": 1}]
        legacy, legacy_leads = onset_audit(onset, [100.0])
        corrected, corrected_leads = onset_audit(onset, prediction_issue_times([100.0]))
        self.assertTrue(legacy[0]["warning_hit"])
        self.assertTrue(corrected[0]["warning_hit"])
        self.assertEqual(legacy_leads[0] - corrected_leads[0], 10.0)

    def test_exact_timestamp_rows_are_one_onset_group(self):
        rows = [
            {"epoch": 200.0, "tactic": "cleanup", "technique": "a"},
            {"epoch": 200.0, "tactic": "cleanup", "technique": "b"},
            {"epoch": 230.0, "tactic": "discovery", "technique": "c"},
        ]
        grouped = group_event_onsets(rows)
        self.assertEqual(len(grouped), 2)
        self.assertEqual(grouped[0]["raw_rows"], 2)
        self.assertEqual(grouped[0]["techniques"], ["a", "b"])

    def test_late_or_at_onset_warning_is_not_early(self):
        onset = [{"epoch": 300.0, "tactics": ["x"], "techniques": ["y"], "raw_rows": 1}]
        audited, leads = onset_audit(onset, [300.0, 301.0])
        self.assertFalse(audited[0]["warning_hit"])
        self.assertEqual(leads, [])

    def test_overlapping_alert_windows_count_one_hit_per_onset(self):
        onset = [{"epoch": 400.0, "tactics": ["x"], "techniques": ["y"], "raw_rows": 1}]
        audited, leads = onset_audit(onset, [350.0, 360.0, 370.0])
        self.assertTrue(audited[0]["warning_hit"])
        self.assertEqual(audited[0]["qualifying_alert_windows"], 3)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0], 50.0)

    def test_bootstrap_is_withheld_for_small_support(self):
        out = bootstrap_median_ci(range(10))
        self.assertTrue(out["withheld"])
        self.assertEqual(out["support"], 10)

    def test_bootstrap_is_deterministic_when_supported(self):
        leads = np.arange(20, dtype=float) + 1
        a = bootstrap_median_ci(leads, iterations=300, seed=123)
        b = bootstrap_median_ci(leads, iterations=300, seed=123)
        self.assertFalse(a["withheld"])
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
