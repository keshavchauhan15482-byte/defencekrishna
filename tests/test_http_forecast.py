import unittest
from deployment.render.http_forecast import forecast

class HttpForecastTests(unittest.TestCase):
    def test_insufficient_history(self):
        self.assertIsNone(forecast(3600,3500,[],[]))
        self.assertIsNone(forecast(3600,None,[],[]))
    def test_real_recorded_count_projection_and_no_new_denials(self):
        now=3600
        pages=[(t,1) for t in range(60,3600,60)]
        baseline=forecast(now,0,pages,[])
        self.assertEqual(baseline["score"],3)
        self.assertEqual(baseline["trajectory"][0]["expected_page_requests"],1)
        result=forecast(now,0,pages,[(3540,1,3599)])
        self.assertGreater(result["score"],baseline["score"])
        self.assertEqual(result["trajectory"][-1]["conditional_index"],3)
        self.assertFalse(result["is_attack_probability"])
        self.assertFalse(result["automatic_containment"])
        self.assertEqual(result["condition"],"no_new_fixture_denials")
        self.assertEqual(result["audit_samples"],result["history_minutes"]-8)
    def test_no_recorded_activity_is_zero_not_fake_motion(self):
        result=forecast(3600,0,[],[])
        self.assertEqual(result["score"],0)
        self.assertEqual(result["expected_requests_per_minute"],0)
        self.assertEqual(result["method"],"persistence")
