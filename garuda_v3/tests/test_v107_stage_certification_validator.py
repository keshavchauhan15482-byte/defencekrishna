import json
from pathlib import Path

import pytest

from garuda_v3.v107_stage_certification_validator import (
    REQUIRED_STAGES, StageCertificationError, validate,
)


def write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    return path


def valid_evidence(tmp_path):
    return write(tmp_path/'stage.json', {
        'required_stages': list(REQUIRED_STAGES),
        'label_evidence': {
            'network_stage_validated': True,
            'heuristic_only': False,
            'uses_proxy_labels': False,
            'source_kind': 'independently_validated_network_stage',
            'artifact_sha256': 'a'*64,
        },
        'model_evidence': {
            'model_sha256': 'b'*64,
            'stage_supervised': True,
            'stage_count': 5,
        },
        'evaluation_split': {
            'held_out': True,
            'used_for_training': False,
            'used_for_threshold_or_calibration': False,
            'identity_sha256': 'c'*64,
        },
        'per_stage_metrics': {
            stage: {'support': 10+i, 'precision': .8, 'recall': .75, 'f1': .77, 'fpr': .02}
            for i, stage in enumerate(REQUIRED_STAGES)
        },
    })


def test_complete_native_shape_passes_validator_logic(tmp_path):
    evidence = valid_evidence(tmp_path)
    out = validate(evidence)
    assert out['declared_status'] == 'PASS'
    assert set(out['per_stage_metrics']) == set(REQUIRED_STAGES)
    # Fixture proves validator logic only; it is not certification evidence.


def test_proxy_labels_rejected(tmp_path):
    evidence = valid_evidence(tmp_path)
    data = json.loads(evidence.read_text())
    data['label_evidence']['uses_proxy_labels'] = True
    write(evidence, data)
    with pytest.raises(StageCertificationError):
        validate(evidence)


def test_unvalidated_labels_rejected(tmp_path):
    evidence = valid_evidence(tmp_path)
    data = json.loads(evidence.read_text())
    data['label_evidence']['network_stage_validated'] = False
    write(evidence, data)
    with pytest.raises(StageCertificationError):
        validate(evidence)


def test_missing_stage_rejected(tmp_path):
    evidence = valid_evidence(tmp_path)
    data = json.loads(evidence.read_text())
    del data['per_stage_metrics']['exfiltration']
    write(evidence, data)
    with pytest.raises(StageCertificationError):
        validate(evidence)


def test_zero_support_rejected(tmp_path):
    evidence = valid_evidence(tmp_path)
    data = json.loads(evidence.read_text())
    data['per_stage_metrics']['command_and_control']['support'] = 0
    write(evidence, data)
    with pytest.raises(StageCertificationError):
        validate(evidence)


def test_reused_evaluation_split_rejected(tmp_path):
    evidence = valid_evidence(tmp_path)
    data = json.loads(evidence.read_text())
    data['evaluation_split']['used_for_training'] = True
    write(evidence, data)
    with pytest.raises(StageCertificationError):
        validate(evidence)
