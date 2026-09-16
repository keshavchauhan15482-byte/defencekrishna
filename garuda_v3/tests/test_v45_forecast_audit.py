import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.v45_forecast_audit import audit


def model_report():
    family = {
        "dos": {
            "positives": 25,
            "negatives": 100,
            "fpr": 0.0,
            "recall": 0.84,
            "policy_enabled": True,
        }
    }
    return {
        "validation_state_mse": 0.8,
        "validation_persistence_mse": 1.0,
        "per_family_alert_metrics": family,
        "calibration": {"status": "fitted"},
        "validation_alert_selection": {"status": "validation_selected", "threshold": 0.9},
        "clean_history_warning_policy": {
            "test": {"samples": 40, "positives": 20, "f1": 0.8}
        },
    }


class V45AuditTests(unittest.TestCase):
    def test_reused_holdout_never_passes_release_gate(self):
        report = {
            "evaluation_scope": "development_reused_holdout",
            "models": {"lstm": model_report(), "gnn_lstm": model_report()},
        }
        result = audit(report)
        self.assertFalse(result["any_model_passed"])
        self.assertIn(
            "evaluation_is_not_new_predeclared_holdout",
            result["models"]["lstm"]["reasons"],
        )

    def test_missing_verified_timeline_keeps_model_research_only(self):
        report = {
            "evaluation_scope": "new_predeclared_holdout",
            "models": {"lstm": model_report(), "gnn_lstm": model_report()},
        }
        result = audit(report)
        self.assertFalse(result["models"]["lstm"]["passed"])
        self.assertIn(
            "verified_incident_timeline_not_supplied",
            result["models"]["lstm"]["reasons"],
        )

    def test_verified_positive_lead_time_can_complete_evidence_gate(self):
        report = {
            "evaluation_scope": "new_predeclared_holdout",
            "models": {"lstm": model_report(), "gnn_lstm": model_report()},
        }
        incidents = {
            "incidents": [
                {
                    "outcome": "success",
                    "establishes_compromise": True,
                    "evidence": "controller + target receipt",
                    "compromise_epoch": 1000 + i * 100,
                    "first_warning_epoch": 970 + i * 100,
                }
                for i in range(5)
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incidents.json"
            path.write_text(json.dumps(incidents))
            result = audit(report, incident_file=str(path), min_verified_incidents=5)
        self.assertTrue(result["models"]["lstm"]["passed"])
        self.assertFalse(result["models"]["lstm"]["automatic_containment_approved"])

    def test_persistence_failure_forces_abstention(self):
        weak = model_report()
        weak["validation_state_mse"] = 1.1
        report = {
            "evaluation_scope": "new_predeclared_holdout",
            "models": {"lstm": weak, "gnn_lstm": weak},
        }
        result = audit(report)
        self.assertTrue(result["models"]["lstm"]["runtime_decision"]["abstain"])
        self.assertIn(
            "state_forecast_not_better_than_persistence",
            result["models"]["lstm"]["runtime_decision"]["reasons"],
        )


if __name__ == "__main__":
    unittest.main()
