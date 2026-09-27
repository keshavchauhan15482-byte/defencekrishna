import hashlib
import json
from pathlib import Path

from garuda_v3.v98_verified_precompromise_gate import (
    STATUS_PASS,
    STATUS_UNRESOLVED,
    verify_manifest,
)


def _write_json(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path, *, warning_ts="2026-09-01T10:00:00Z", compromise_ts="2026-09-01T10:00:30Z"):
    campaign = "controlled-campaign-001"
    warning_path = tmp_path / "events" / "warning.json"
    compromise_path = tmp_path / "events" / "compromise.json"

    warning_sha = _write_json(
        warning_path,
        {
            "campaign_id": campaign,
            "event_type": "model_warning",
            "timestamp": warning_ts,
            "emitted_by_model": True,
        },
    )
    compromise_sha = _write_json(
        compromise_path,
        {
            "campaign_id": campaign,
            "event_type": "successful_compromise",
            "timestamp": compromise_ts,
            "establishes_successful_compromise": True,
        },
    )

    manifest = {
        "schema_version": "v98.1",
        "declared_status": "PASS",
        "campaign_id": campaign,
        "warning_event": {
            "artifact": {"path": "events/warning.json", "sha256": warning_sha},
            "timestamp_field": "timestamp",
            "kind_field": "event_type",
            "campaign_field": "campaign_id",
            "required_kind": "model_warning",
        },
        "compromise_event": {
            "artifact": {"path": "events/compromise.json", "sha256": compromise_sha},
            "timestamp_field": "timestamp",
            "kind_field": "event_type",
            "campaign_field": "campaign_id",
            "required_kind": "successful_compromise",
        },
        "provenance": {
            "identity_proof_complete": True,
            "evidence_campaign_ids": [campaign],
            "train_campaign_ids": ["train-a"],
            "validation_campaign_ids": ["validation-a"],
            "calibration_campaign_ids": ["calibration-a"],
            "development_reused_campaign_ids": ["development-a"],
        },
    }
    return manifest


def test_complete_integrity_pinned_fixture_passes(tmp_path):
    manifest = _fixture(tmp_path)
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_PASS
    assert report["lead_time_seconds"] == 30.0
    assert report["v93_attack_step_lead_time_is_successful_compromise_evidence"] is False


def test_missing_successful_compromise_artifact_fails_closed(tmp_path):
    manifest = _fixture(tmp_path)
    manifest["compromise_event"]["artifact"]["path"] = "events/missing.json"
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert any("does not exist" in reason for reason in report["reasons"])


def test_attack_onset_is_rejected_as_compromise_evidence(tmp_path):
    manifest = _fixture(tmp_path)
    path = tmp_path / "events" / "compromise.json"
    manifest["compromise_event"]["artifact"]["sha256"] = _write_json(
        path,
        {
            "campaign_id": manifest["campaign_id"],
            "event_type": "attack_onset",
            "timestamp": "2026-09-01T10:00:30Z",
            "establishes_successful_compromise": True,
        },
    )
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert any("attack activity/onset" in reason for reason in report["reasons"])


def test_missing_model_warning_artifact_fails_closed(tmp_path):
    manifest = _fixture(tmp_path)
    manifest["warning_event"] = None
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert any("warning_event: event specification is missing" in reason for reason in report["reasons"])


def test_warning_at_or_after_compromise_fails_closed(tmp_path):
    manifest = _fixture(
        tmp_path,
        warning_ts="2026-09-01T10:00:30Z",
        compromise_ts="2026-09-01T10:00:30Z",
    )
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert report["lead_time_seconds"] == 0.0
    assert any("does not precede" in reason for reason in report["reasons"])


def test_tampered_artifact_sha_fails_closed(tmp_path):
    manifest = _fixture(tmp_path)
    warning_path = tmp_path / "events" / "warning.json"
    warning_path.write_text("{}", encoding="utf-8")
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert any("SHA-256 mismatch" in reason for reason in report["reasons"])


def test_campaign_overlap_with_any_fitted_or_reused_set_fails_closed(tmp_path):
    for key in (
        "train_campaign_ids",
        "validation_campaign_ids",
        "calibration_campaign_ids",
        "development_reused_campaign_ids",
    ):
        case_root = tmp_path / key
        manifest = _fixture(case_root)
        manifest["provenance"][key].append(manifest["campaign_id"])
        report = verify_manifest(manifest, case_root)
        assert report["status"] == STATUS_UNRESOLVED
        assert any(f"provenance.{key}" in reason for reason in report["reasons"])


def test_incomplete_identity_proof_fails_closed(tmp_path):
    manifest = _fixture(tmp_path)
    manifest["provenance"]["identity_proof_complete"] = False
    report = verify_manifest(manifest, tmp_path)
    assert report["status"] == STATUS_UNRESOLVED
    assert any("identity proof" in reason for reason in report["reasons"])


def test_repository_manifest_is_honestly_unresolved():
    repo_root = Path(__file__).resolve().parents[2]
    manifest_path = (
        repo_root
        / "garuda_v3"
        / "artifacts"
        / "certification"
        / "v98"
        / "verified_precompromise_manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = verify_manifest(manifest, repo_root)
    assert manifest["declared_status"] == STATUS_UNRESOLVED
    assert report["status"] == STATUS_UNRESOLVED
    assert report["lead_time_seconds"] is None
