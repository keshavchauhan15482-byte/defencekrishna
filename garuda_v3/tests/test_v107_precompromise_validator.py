from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.v107_verify_precompromise import EvidenceError, verify


MODEL_SHA = "a" * 64


class PrecompromiseValidatorTests(unittest.TestCase):
    def write_case(self, root: Path, warning: dict, compromise: dict, provenance: dict):
        paths = []
        for name, value in (("warning.json", warning), ("compromise.json", compromise), ("provenance.json", provenance)):
            path = root / name
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            paths.append(path)
        return paths

    def valid_objects(self):
        warning = {
            "event_type": "model_warning",
            "campaign_id": "campaign-001",
            "timestamp": "2026-09-27T10:00:00+00:00",
            "emitted_by_model": True,
            "warning_id": "warning-001",
            "model_sha256": MODEL_SHA,
        }
        compromise = {
            "event_type": "successful_compromise",
            "campaign_id": "campaign-001",
            "timestamp": "2026-09-27T10:02:00+00:00",
            "establishes_successful_compromise": True,
            "objective_success_marker": "controlled target proof token observed",
            "source_reference": "lab-evidence/campaign-001/result.json",
            "event_semantics": "objective_success_marker",
        }
        provenance = {
            "identity_proof_complete": True,
            "evidence_campaign_ids": ["campaign-001"],
            "train_campaign_ids": ["train-a"],
            "validation_campaign_ids": ["val-a"],
            "calibration_campaign_ids": ["cal-a"],
            "development_reused_campaign_ids": ["dev-a"],
        }
        return warning, compromise, provenance

    def test_valid_pair_passes_with_positive_lead(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            warning, compromise, provenance = self.valid_objects()
            paths = self.write_case(root, warning, compromise, provenance)
            out = verify(*paths)
            self.assertEqual(out["status"], "PASS")
            self.assertEqual(out["lead_time_seconds"], 120.0)
            self.assertEqual(len(out["warning_event"]["raw_json_sha256"]), 64)
            self.assertEqual(len(out["compromise_event"]["raw_json_sha256"]), 64)

    def test_attack_onset_cannot_be_promoted_to_compromise(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            warning, compromise, provenance = self.valid_objects()
            compromise["event_semantics"] = "attack_onset"
            paths = self.write_case(root, warning, compromise, provenance)
            with self.assertRaises(EvidenceError):
                verify(*paths)

    def test_reused_campaign_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            warning, compromise, provenance = self.valid_objects()
            provenance["development_reused_campaign_ids"].append("campaign-001")
            paths = self.write_case(root, warning, compromise, provenance)
            with self.assertRaises(EvidenceError):
                verify(*paths)

    def test_nonpositive_lead_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            warning, compromise, provenance = self.valid_objects()
            compromise["timestamp"] = warning["timestamp"]
            paths = self.write_case(root, warning, compromise, provenance)
            with self.assertRaises(EvidenceError):
                verify(*paths)


if __name__ == "__main__":
    unittest.main()
