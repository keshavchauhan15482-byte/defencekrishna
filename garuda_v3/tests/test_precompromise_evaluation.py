import unittest

from garuda_v3.precompromise_evaluation import (
    STATUS_MISS,
    STATUS_NO_COMPROMISE,
    STATUS_VERIFIED,
    evaluate_manifest,
)


def campaign(*, compromise=True):
    events = [
        {
            "event_id": "initial-access",
            "epoch": 1200.0,
            "stage": "Initial Access",
            "outcome": "success",
            "establishes_compromise": False,
            "source_host": "attacker",
            "target_host": "victim",
            "evidence": "authorized-lab attack log",
        }
    ]
    if compromise:
        events.append(
            {
                "event_id": "objective-marker",
                "epoch": 1500.0,
                "stage": "Execution",
                "outcome": "success",
                "establishes_compromise": True,
                "source_host": "attacker",
                "target_host": "victim",
                "evidence": "authorized-lab objective success marker",
            }
        )
    return {
        "schema": "krishna-verified-campaign-v1",
        "campaign_id": "lab-1",
        "role": "final_test",
        "domain": "authorized isolated lab",
        "capture_sha256": "a" * 64,
        "graph_path": "capture.npz",
        "start_epoch": 0.0,
        "end_epoch": 2000.0,
        "timezone": "UTC",
        "evidence_source": "authorized lab runbook and capture",
        "benign_intervals": [
            {"start_epoch": 0.0, "end_epoch": 1100.0, "evidence": "lab baseline interval"}
        ],
        "events": events,
    }


class PrecompromiseEvaluationTests(unittest.TestCase):
    def test_attack_step_is_not_substituted_for_compromise(self):
        result = evaluate_manifest(campaign(compromise=False), [1000.0])
        self.assertEqual(result["status"], STATUS_NO_COMPROMISE)
        self.assertIsNone(result["lead_seconds"])
        self.assertFalse(result["claimable_as_verified_precompromise"])

    def test_positive_lead_uses_verified_compromise_only(self):
        result = evaluate_manifest(campaign(), [1000.0, 1300.0, 1600.0])
        self.assertEqual(result["status"], STATUS_VERIFIED)
        self.assertEqual(result["verified_compromise_epoch"], 1500.0)
        self.assertEqual(result["first_warning_before_compromise_epoch"], 1000.0)
        self.assertEqual(result["lead_seconds"], 500.0)
        self.assertTrue(result["claimable_as_verified_precompromise"])

    def test_post_compromise_warning_is_a_miss(self):
        result = evaluate_manifest(campaign(), [1500.0, 1600.0])
        self.assertEqual(result["status"], STATUS_MISS)
        self.assertIsNone(result["lead_seconds"])
        self.assertFalse(result["claimable_as_verified_precompromise"])


if __name__ == "__main__":
    unittest.main()
