from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from garuda_v3.v100_external_recovery_audit import AuditError, build_audit


ROOT = Path(__file__).resolve().parents[2]


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def evidence():
    return (
        load("garuda_v3/artifacts/certification/v99/hikari_one_shot_result.json"),
        load("garuda_v3/artifacts/residual_run/metrics.json"),
        load("garuda_v3/artifacts/residual_run/support_gate.json"),
        load("garuda_v3/artifacts/certification/v97/stage_packet_manifest.json"),
        load("garuda_v3/artifacts/certification/v98/verified_precompromise_manifest.json"),
    )


def test_current_v99_failure_is_diagnosed_without_rewriting_it():
    report = build_audit(*evidence())

    assert report["status"] == "RECOVERY_REQUIRED"
    assert report["source_result"]["status"] == "FAIL"
    assert report["source_result"]["consumed_external_holdout"] is True
    assert report["source_result"]["rerun_permitted_for_claim_improvement"] is False
    assert report["state_forecasting"]["gate_passed"] is False

    diagnosis = report["support_diagnosis"]
    assert diagnosis["training_sources_packet_features"] == [False, False]
    assert diagnosis["external_packet_features_present_mean"] == 1.0
    assert diagnosis["train_support_center"] == 0.0
    assert diagnosis["train_support_scale"] == pytest.approx(0.02)
    assert diagnosis["packet_presence_standardized_deviation"] == pytest.approx(50.0)
    assert diagnosis["support_threshold"] < diagnosis["packet_presence_standardized_deviation"]
    assert diagnosis["recorded_supported_sequences"] == 0
    assert diagnosis["recorded_total_sequences"] == 1070
    assert diagnosis["packet_availability_shift_alone_exceeds_support_threshold"] is True
    assert diagnosis["packet_availability_shift_matches_recorded_median_score"] is True

    assert report["other_open_evidence_gates"] == {
        "v97_stage_packet_evidence": "SHADOW_UNRESOLVED",
        "v98_verified_precompromise": "SHADOW_UNRESOLVED",
    }


def test_hikari_capture_is_explicitly_quarantined_from_future_fitting():
    v99, metrics, gate, v97, v98 = evidence()
    report = build_audit(v99, metrics, gate, v97, v98)

    quarantine = report["holdout_quarantine"]
    assert quarantine["dataset"] == "HIKARI-2021"
    assert quarantine["capture_sha256"] == v99["dataset"]["sha256"]
    prohibited = " ".join(quarantine["prohibited_for_future_claim_fitting"])
    for expected in ("training", "normalization", "support", "adapter", "hyperparameter"):
        assert expected in prohibited


def test_audit_fails_closed_if_v99_result_is_relabelled_pass():
    v99, metrics, gate, v97, v98 = evidence()
    changed = copy.deepcopy(v99)
    changed["status"] = "PASS"
    changed["state_forecasting"]["beats_persistence"] = True

    with pytest.raises(AuditError, match="must remain FAIL"):
        build_audit(changed, metrics, gate, v97, v98)


def test_audit_fails_closed_if_training_packet_provenance_is_rewritten():
    v99, metrics, gate, v97, v98 = evidence()
    changed = copy.deepcopy(metrics)
    changed["sources"][0]["packet_features"] = True

    with pytest.raises(AuditError, match="was not packet-feature trained"):
        build_audit(v99, changed, gate, v97, v98)


def test_audit_fails_closed_if_open_certification_gates_are_claimed_resolved():
    v99, metrics, gate, v97, v98 = evidence()
    changed_v98 = copy.deepcopy(v98)
    changed_v98["declared_status"] = "PASS"

    with pytest.raises(AuditError, match="V98 status changed"):
        build_audit(v99, metrics, gate, v97, changed_v98)
