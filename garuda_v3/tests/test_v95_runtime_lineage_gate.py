import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.v95_runtime_lineage_gate import (
    EXPECTED_SPLIT_COUNTS,
    STATUS_PASS,
    STATUS_UNRESOLVED,
    evaluate,
    git_blob_sha1,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class V95RuntimeLineageGateTests(unittest.TestCase):
    def _fixture(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        artifact = root / "garuda_v3/artifacts/residual_run"
        artifact.mkdir(parents=True)
        gate = artifact / "support_gate.json"
        gate.write_text(json.dumps({"center": [0.0], "scale": [1.0], "threshold": 2.0}) + "\n")
        metrics = {
            "evaluation_scope": "development_reused_holdout",
            "selection": "validation loss checkpoint; validation F1 thresholds; test not used for checkpoint selection",
            "split_counts": [
                {"examples": EXPECTED_SPLIT_COUNTS["train"]},
                {"examples": EXPECTED_SPLIT_COUNTS["validation"]},
                {"examples": EXPECTED_SPLIT_COUNTS["test"]},
            ],
        }
        (artifact / "metrics.json").write_text(json.dumps(metrics) + "\n")
        runtime = {
            "schema_version": 1,
            "status": "validated-runtime-input",
            "artifact_directory": "garuda_v3/artifacts/residual_run",
            "files": {"support_gate.json": git_blob_sha1(gate)},
        }
        runtime_path = root / "garuda_v3/active_runtime_bundle.json"
        runtime_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_path.write_text(json.dumps(runtime) + "\n")
        certification = {
            "schema_version": 1,
            "runtime_bundle_manifest": "garuda_v3/active_runtime_bundle.json",
            "metrics": "garuda_v3/artifacts/residual_run/metrics.json",
            "split_identities": {
                "train": [f"train:{i}" for i in range(456)],
                "validation": [f"validation:{i}" for i in range(158)],
                "test": [f"test:{i}" for i in range(160)],
            },
            "fit_provenance": {
                "support_statistics_fit_splits": ["train"],
                "support_threshold_selection_splits": ["validation"],
                "support_gate_artifact": "garuda_v3/artifacts/residual_run/support_gate.json",
            },
        }
        return td, root, certification

    def test_complete_explicit_provenance_passes(self):
        td, root, certification = self._fixture()
        try:
            report = evaluate(root, certification)
            self.assertEqual(report["status"], STATUS_PASS, report["reasons"])
            self.assertTrue(report["certified_for_autonomous_forecast_response"])
        finally:
            td.cleanup()

    def test_wrong_split_count_fails_closed(self):
        td, root, certification = self._fixture()
        try:
            metrics_path = root / "garuda_v3/artifacts/residual_run/metrics.json"
            metrics = json.loads(metrics_path.read_text())
            metrics["split_counts"][2]["examples"] = 159
            metrics_path.write_text(json.dumps(metrics) + "\n")
            report = evaluate(root, certification)
            self.assertEqual(report["status"], STATUS_UNRESOLVED)
            self.assertTrue(any("split counts" in x.lower() for x in report["reasons"]))
        finally:
            td.cleanup()

    def test_split_identity_overlap_fails_closed(self):
        td, root, certification = self._fixture()
        try:
            certification["split_identities"]["test"][0] = certification["split_identities"]["train"][0]
            report = evaluate(root, certification)
            self.assertEqual(report["status"], STATUS_UNRESOLVED)
            self.assertTrue(any("overlap" in x.lower() for x in report["reasons"]))
        finally:
            td.cleanup()

    def test_test_or_replay_in_fit_provenance_fails_closed(self):
        td, root, certification = self._fixture()
        try:
            certification["fit_provenance"]["support_statistics_fit_splits"] = ["train", "test"]
            certification["fit_provenance"]["support_threshold_selection_splits"] = ["validation", "replay"]
            report = evaluate(root, certification)
            self.assertEqual(report["status"], STATUS_UNRESOLVED)
            leakage = " ".join(report["reasons"]).lower()
            self.assertIn("forbidden test/replay leakage", leakage)
        finally:
            td.cleanup()

    def test_missing_pinned_support_gate_fails_closed(self):
        td, root, certification = self._fixture()
        try:
            runtime_path = root / "garuda_v3/active_runtime_bundle.json"
            runtime = json.loads(runtime_path.read_text())
            runtime["files"].pop("support_gate.json")
            runtime_path.write_text(json.dumps(runtime) + "\n")
            report = evaluate(root, certification)
            self.assertEqual(report["status"], STATUS_UNRESOLVED)
            self.assertTrue(any("does not integrity-pin support_gate.json" in x for x in report["reasons"]))
        finally:
            td.cleanup()

    def test_current_repository_evidence_remains_shadow_unresolved(self):
        path = REPO_ROOT / "garuda_v3/artifacts/certification/v95/runtime_lineage_manifest.json"
        certification = json.loads(path.read_text())
        report = evaluate(REPO_ROOT, certification)
        self.assertEqual(report["status"], STATUS_UNRESOLVED)
        self.assertFalse(report["certified_for_autonomous_forecast_response"])
        reasons = " ".join(report["reasons"]).lower()
        self.assertIn("split identities", reasons)
        self.assertIn("support_gate.json", reasons)


if __name__ == "__main__":
    unittest.main()
