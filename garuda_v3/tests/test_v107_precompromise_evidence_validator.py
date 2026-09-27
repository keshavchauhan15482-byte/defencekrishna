import json
from pathlib import Path

import pytest

from garuda_v3.v107_precompromise_evidence_validator import (
    PrecompromiseEvidenceError, validate,
)


def write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    return path


def valid_inputs(tmp_path):
    warning = write(tmp_path/'warning.json', {
        'event_id': 'warn-1', 'campaign_id': 'lab-campaign-7',
        'timestamp': '2026-09-27T10:00:00+05:30', 'emitted_by_model': True,
        'model_identity': {'sha256': 'a'*64},
    })
    compromise = write(tmp_path/'compromise.json', {
        'event_id': 'success-1', 'campaign_id': 'lab-campaign-7',
        'timestamp': '2026-09-27T10:02:30+05:30',
        'event_kind': 'objective_success',
        'establishes_successful_compromise': True,
        'objective_basis': 'isolated-lab success oracle recorded completion of the declared compromise objective',
    })
    provenance = write(tmp_path/'provenance.json', {
        'identity_proof_complete': True,
        'evidence_campaign_ids': ['lab-campaign-7'],
        'train_campaign_ids': ['train-a'],
        'validation_campaign_ids': ['val-a'],
        'calibration_campaign_ids': [],
        'development_reused_campaign_ids': ['dev-a'],
    })
    return warning, compromise, provenance


def test_valid_real_shape_contract_passes_logic(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    out = validate(warning, compromise, provenance)
    assert out['declared_status'] == 'PASS'
    assert out['lead_time_seconds'] == 150.0
    assert out['integrity_checks']['positive_lead_time'] is True
    # Unit fixture validates logic only; it is not checked into certification evidence.


def test_attack_onset_cannot_masquerade_as_successful_compromise(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    value = json.loads(compromise.read_text())
    value['event_kind'] = 'attack_onset'
    write(compromise, value)
    with pytest.raises(PrecompromiseEvidenceError):
        validate(warning, compromise, provenance)


def test_synthetic_evidence_is_rejected(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    value = json.loads(compromise.read_text())
    value['synthetic'] = True
    write(compromise, value)
    with pytest.raises(PrecompromiseEvidenceError):
        validate(warning, compromise, provenance)


def test_campaign_overlap_is_rejected(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    value = json.loads(provenance.read_text())
    value['train_campaign_ids'].append('lab-campaign-7')
    write(provenance, value)
    with pytest.raises(PrecompromiseEvidenceError):
        validate(warning, compromise, provenance)


def test_nonpositive_lead_time_is_rejected(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    value = json.loads(compromise.read_text())
    value['timestamp'] = '2026-09-27T09:59:59+05:30'
    write(compromise, value)
    with pytest.raises(PrecompromiseEvidenceError):
        validate(warning, compromise, provenance)


def test_timezone_naive_timestamp_is_rejected(tmp_path):
    warning, compromise, provenance = valid_inputs(tmp_path)
    value = json.loads(warning.read_text())
    value['timestamp'] = '2026-09-27T10:00:00'
    write(warning, value)
    with pytest.raises(PrecompromiseEvidenceError):
        validate(warning, compromise, provenance)
