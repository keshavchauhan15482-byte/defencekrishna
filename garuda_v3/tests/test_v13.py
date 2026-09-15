import unittest

from garuda_v3.v13_policy import approved_threshold, risk_output_permission


class V13PolicyTests(unittest.TestCase):
    def test_failed_calibration_withholds_threshold(self):
        self.assertIsNone(approved_threshold(selected_threshold=.7, calibration_fitted=False, development_support_ready=True, confidence_gate_passed=True))

    def test_missing_support_withholds_threshold(self):
        self.assertIsNone(approved_threshold(selected_threshold=.7, calibration_fitted=True, development_support_ready=False, confidence_gate_passed=True))

    def test_failed_confidence_gate_withholds_threshold(self):
        self.assertIsNone(approved_threshold(selected_threshold=.7, calibration_fitted=True, development_support_ready=True, confidence_gate_passed=False))

    def test_invalid_threshold_withheld(self):
        self.assertIsNone(approved_threshold(selected_threshold=1.5, calibration_fitted=True, development_support_ready=True, confidence_gate_passed=True))

    def test_supported_threshold_preserved(self):
        kwargs=dict(selected_threshold=.73, calibration_fitted=True, development_support_ready=True, confidence_gate_passed=True)
        self.assertEqual(approved_threshold(**kwargs), .73)
        self.assertTrue(risk_output_permission(**kwargs))


if __name__ == '__main__':
    unittest.main()
