"""Fail-closed validator for the SIH five-stage supervised MITRE evidence gate.

A PASS is an evidence-integrity statement only: all five required network stages must
have native or independently network-validated supervision and held-out metrics.
Proxy labels, heuristic-only mappings, incomplete stage support, reused evaluation,
or unpinned model/label artifacts are rejected. Performance values are reported, not
silently converted into an arbitrary quality threshold here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

REQUIRED_STAGES = (
    'reconnaissance',
    'initial_access',
    'lateral_movement',
    'command_and_control',
    'exfiltration',
)
METRICS = ('precision', 'recall', 'f1', 'fpr')


class StageCertificationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise StageCertificationError(f'{field} must be a 64-character SHA-256 hex digest')
    try:
        int(value, 16)
    except ValueError as exc:
        raise StageCertificationError(f'{field} must be hexadecimal SHA-256') from exc
    return value.lower()


def _metric(value: object, field: str) -> float:
    try:
        x = float(value)
    except (TypeError, ValueError) as exc:
        raise StageCertificationError(f'{field} must be numeric') from exc
    if not math.isfinite(x) or x < 0.0 or x > 1.0:
        raise StageCertificationError(f'{field} must be finite in [0,1]')
    return x


def validate(evidence_path: Path) -> dict:
    evidence = json.loads(evidence_path.read_text())
    stages = tuple(evidence.get('required_stages') or ())
    if stages != REQUIRED_STAGES:
        raise StageCertificationError(f'required_stages must exactly equal {REQUIRED_STAGES}')

    labels = evidence.get('label_evidence')
    if not isinstance(labels, dict):
        raise StageCertificationError('label_evidence object is required')
    if labels.get('network_stage_validated') is not True:
        raise StageCertificationError('network stage labels are not independently/native validated')
    if labels.get('heuristic_only') is True:
        raise StageCertificationError('heuristic-only labels cannot certify supervised stages')
    if labels.get('uses_proxy_labels') is True:
        raise StageCertificationError('proxy stage labels cannot certify supervised stages')
    if labels.get('source_kind') not in {'publisher_native_network_stage', 'independently_validated_network_stage'}:
        raise StageCertificationError('label source_kind is not certifiable')
    _sha(labels.get('artifact_sha256'), 'label_evidence.artifact_sha256')

    model = evidence.get('model_evidence')
    if not isinstance(model, dict):
        raise StageCertificationError('model_evidence object is required')
    _sha(model.get('model_sha256'), 'model_evidence.model_sha256')
    if model.get('stage_supervised') is not True:
        raise StageCertificationError('evaluated model must set stage_supervised=true')
    if int(model.get('stage_count', -1)) != 5:
        raise StageCertificationError('evaluated model must expose exactly five supervised stages')

    split = evidence.get('evaluation_split')
    if not isinstance(split, dict):
        raise StageCertificationError('evaluation_split object is required')
    if split.get('held_out') is not True or split.get('used_for_training') is not False:
        raise StageCertificationError('stage metrics must come from a held-out non-training split')
    if split.get('used_for_threshold_or_calibration') is not False:
        raise StageCertificationError('stage evaluation split cannot fit threshold/calibration')
    _sha(split.get('identity_sha256'), 'evaluation_split.identity_sha256')

    metrics = evidence.get('per_stage_metrics')
    if not isinstance(metrics, dict) or set(metrics) != set(REQUIRED_STAGES):
        raise StageCertificationError('per_stage_metrics must contain exactly all five required stages')

    normalized = {}
    for stage in REQUIRED_STAGES:
        row = metrics[stage]
        if not isinstance(row, dict):
            raise StageCertificationError(f'{stage} metric row must be an object')
        try:
            support = int(row.get('support', 0))
        except (TypeError, ValueError) as exc:
            raise StageCertificationError(f'{stage}.support must be an integer') from exc
        if support <= 0:
            raise StageCertificationError(f'{stage}.support must be > 0')
        normalized[stage] = {'support': support}
        for name in METRICS:
            normalized[stage][name] = _metric(row.get(name), f'{stage}.{name}')

    return {
        'schema_version': 'v97.2',
        'declared_status': 'PASS',
        'required_stages': list(REQUIRED_STAGES),
        'label_evidence': {
            'network_stage_validated': True,
            'heuristic_only': False,
            'uses_proxy_labels': False,
            'source_kind': labels['source_kind'],
            'artifact_sha256': labels['artifact_sha256'].lower(),
        },
        'model_evidence': {
            'model_sha256': model['model_sha256'].lower(),
            'stage_supervised': True,
            'stage_count': 5,
        },
        'evaluation_split': {
            'held_out': True,
            'used_for_training': False,
            'used_for_threshold_or_calibration': False,
            'identity_sha256': split['identity_sha256'].lower(),
        },
        'per_stage_metrics': normalized,
        'raw_evidence_sha256': sha256(evidence_path),
        'claim_boundary': 'Five-stage supervision evidence is complete for the exact hash-pinned label/model/evaluation artifacts only; this does not certify external world-model generalisation or successful-compromise lead time.',
    }


def unresolved(reason: str, evidence_path: Path | None = None) -> dict:
    return {
        'schema_version': 'v97.2',
        'declared_status': 'SHADOW_UNRESOLVED',
        'required_stages': list(REQUIRED_STAGES),
        'failure_reason': reason,
        'raw_evidence_sha256': sha256(evidence_path) if evidence_path and evidence_path.exists() else None,
        'claim_boundary': 'No complete supervised five-stage MITRE certification claim is made.',
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    try:
        result = validate(args.evidence)
        code = 0
    except Exception as exc:
        result = unresolved(str(exc), args.evidence)
        code = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
