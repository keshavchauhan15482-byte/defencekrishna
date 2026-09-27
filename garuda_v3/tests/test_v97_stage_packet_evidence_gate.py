import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from garuda_v3.v97_stage_packet_evidence_gate import sha256_file, verify_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]
STAGES = (
    "reconnaissance",
    "initial_access",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
)


class V97StagePacketEvidenceGateTests(unittest.TestCase):
    def _fixture(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        evidence = root / "evidence"
        evidence.mkdir(parents=True)

        stage_artifact = evidence / "stage_report.json"
        stage_artifact.write_text(json.dumps({"kind": "supervised-stage-evidence"}) + "\n")
        packet_artifact = evidence / "packet_report.json"
        packet_artifact.write_text(json.dumps({"kind": "packet-extraction-evidence"}) + "\n")

        metrics = {
            stage: {
                "precision": 0.80,
                "recall": 0.75,
                "f1": 0.774,
                "fpr": 0.01,
                "support": 40,
            }
            for stage in STAGES
        }
        manifest = {
            "schema_version": "v97.test",
            "candidate_id": "unit-test",
            "required_stages": list(STAGES),
            "stage_evidence": {
                "label_source": "native_timeline_backed",
                "unknown_label_policy": "masked",
                "provenance": {
                    "training_sources": ["development_train"],
                    "validation_sources": ["development_validation"],
                    "calibration_sources": ["validation_only"],
                    "evaluation_sources": ["sealed_test"],
                },
                "metrics": metrics,
                "artifact": {
                    "path": "evidence/stage_report.json",
                    "sha256": sha256_file(stage_artifact),
                },
            },
            "packet_evidence": {
                "origin": "pcapng",
                "source_capture_sha256": hashlib.sha256(b"capture-bytes").hexdigest(),
                "world_model_consumes_packet_features": True,
                "supported_features": {
                    "ttl_variance": True,
                    "tcp_window": True,
                    "fragmentation": True,
                    "payload_distribution": True,
                    "port_scan_patterns": True,
                    "retransmission": True,
                },
                "artifact": {
                    "path": "evidence/packet_report.json",
                    "sha256": sha256_file(packet_artifact),
                },
            },
        }
        return td, root, manifest

    def test_complete_supervised_packet_provenance_passes(self):
        td, root, manifest = self._fixture()
        try:
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "PASS", report["reasons"])
            self.assertEqual(report["reasons"], [])
            self.assertFalse(report["checks"]["performance_threshold_applied"])
        finally:
            td.cleanup()

    def test_heuristic_or_proxy_labels_fail_closed(self):
        for label_source in ("heuristic", "proxy", "weak_proxy", "prediction_derived"):
            td, root, manifest = self._fixture()
            try:
                manifest["stage_evidence"]["label_source"] = label_source
                report = verify_manifest(root, manifest)
                self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
                self.assertTrue(any("label_source" in x for x in report["reasons"]))
            finally:
                td.cleanup()

    def test_unknown_label_mask_is_mandatory(self):
        td, root, manifest = self._fixture()
        try:
            manifest["stage_evidence"]["unknown_label_policy"] = "unknown_as_benign"
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
            self.assertTrue(any("unknown labels" in x for x in report["reasons"]))
        finally:
            td.cleanup()

    def test_test_or_replay_leakage_in_fit_provenance_fails(self):
        td, root, manifest = self._fixture()
        try:
            manifest["stage_evidence"]["training_sources" if False else "provenance"]["training_sources"] = [
                "development_train", "sealed_test"
            ]
            manifest["stage_evidence"]["provenance"]["calibration_sources"] = ["alert_replay"]
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
            text = " ".join(report["reasons"]).lower()
            self.assertIn("forbidden test/replay", text)
        finally:
            td.cleanup()

    def test_missing_stage_metric_or_support_fails(self):
        td, root, manifest = self._fixture()
        try:
            del manifest["stage_evidence"]["metrics"]["exfiltration"]
            manifest["stage_evidence"]["metrics"]["reconnaissance"]["support"] = 0
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
            text = " ".join(report["reasons"])
            self.assertIn("missing metrics for exfiltration", text)
            self.assertIn("reconnaissance.support", text)
        finally:
            td.cleanup()

    def test_packet_feature_names_without_source_proof_fail(self):
        td, root, manifest = self._fixture()
        try:
            manifest["packet_evidence"]["source_capture_sha256"] = None
            manifest["packet_evidence"]["artifact"] = None
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
            text = " ".join(report["reasons"]).lower()
            self.assertIn("source_capture_sha256", text)
            self.assertIn("missing artifact specification", text)
        finally:
            td.cleanup()

    def test_tampered_evidence_hash_fails(self):
        td, root, manifest = self._fixture()
        try:
            (root / "evidence/stage_report.json").write_text("tampered\n")
            report = verify_manifest(root, manifest)
            self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
            self.assertTrue(any("sha256 mismatch" in x for x in report["reasons"]))
        finally:
            td.cleanup()

    def test_current_repository_manifest_remains_honestly_unresolved(self):
        path = REPO_ROOT / "garuda_v3/artifacts/certification/v97/stage_packet_manifest.json"
        manifest = json.loads(path.read_text())
        report = verify_manifest(REPO_ROOT, manifest)
        self.assertEqual(report["status"], "SHADOW_UNRESOLVED")
        self.assertGreater(report["reason_count"], 0)
        text = " ".join(report["reasons"]).lower()
        self.assertIn("label_source", text)
        self.assertIn("source_capture_sha256", text)


if __name__ == "__main__":
    unittest.main()
