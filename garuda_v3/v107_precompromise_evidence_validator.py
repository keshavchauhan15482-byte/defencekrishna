"""Fail-closed validator for V98 warning-before-successful-compromise evidence.

The validator never invents a compromise timestamp and never upgrades attack onset,
stage onset, exfiltration onset, or a synthetic fixture into successful-compromise
evidence. A PASS requires two raw, hash-pinned event artifacts for the same explicitly
identified campaign plus disjointness provenance:
  1) a real model-emitted warning event; and
  2) an objective event that explicitly establishes successful compromise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path


class PrecompromiseEvidenceError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def parse_aware_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise PrecompromiseEvidenceError(f'{field} must be a non-empty ISO-8601 timestamp')
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PrecompromiseEvidenceError(f'{field} is not valid ISO-8601') from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise PrecompromiseEvidenceError(f'{field} must be timezone-aware')
    return dt


def require_campaign(event: dict, name: str) -> str:
    campaign = event.get('campaign_id')
    if not isinstance(campaign, str) or not campaign.strip():
        raise PrecompromiseEvidenceError(f'{name}.campaign_id is required')
    return campaign.strip()


def validate(warning_path: Path, compromise_path: Path, provenance_path: Path) -> dict:
    warning = json.loads(warning_path.read_text())
    compromise = json.loads(compromise_path.read_text())
    provenance = json.loads(provenance_path.read_text())

    warning_campaign = require_campaign(warning, 'warning')
    compromise_campaign = require_campaign(compromise, 'compromise')
    if warning_campaign != compromise_campaign:
        raise PrecompromiseEvidenceError('warning and compromise campaign_id differ')
    campaign = warning_campaign

    if warning.get('emitted_by_model') is not True:
        raise PrecompromiseEvidenceError('warning must set emitted_by_model=true')
    if warning.get('synthetic') is True or warning.get('fixture') is True:
        raise PrecompromiseEvidenceError('synthetic/fixture warning cannot certify V98')
    model_identity = warning.get('model_identity')
    if not isinstance(model_identity, dict) or not model_identity.get('sha256'):
        raise PrecompromiseEvidenceError('warning.model_identity.sha256 is required')
    if not isinstance(warning.get('event_id'), str) or not warning['event_id'].strip():
        raise PrecompromiseEvidenceError('warning.event_id is required')

    if compromise.get('establishes_successful_compromise') is not True:
        raise PrecompromiseEvidenceError('compromise must explicitly establish successful compromise')
    if compromise.get('synthetic') is True or compromise.get('fixture') is True:
        raise PrecompromiseEvidenceError('synthetic/fixture compromise cannot certify V98')
    if compromise.get('event_kind') in {'attack_onset', 'stage_onset', 'exfiltration_onset'}:
        raise PrecompromiseEvidenceError('an onset event is not objective successful-compromise evidence')
    if not isinstance(compromise.get('event_id'), str) or not compromise['event_id'].strip():
        raise PrecompromiseEvidenceError('compromise.event_id is required')
    objective_basis = compromise.get('objective_basis')
    if not isinstance(objective_basis, str) or not objective_basis.strip():
        raise PrecompromiseEvidenceError('compromise.objective_basis is required')

    warning_time = parse_aware_timestamp(warning.get('timestamp'), 'warning.timestamp')
    compromise_time = parse_aware_timestamp(compromise.get('timestamp'), 'compromise.timestamp')
    lead_seconds = (compromise_time - warning_time).total_seconds()
    if lead_seconds <= 0:
        raise PrecompromiseEvidenceError('warning must precede successful compromise')

    evidence_ids = set(provenance.get('evidence_campaign_ids') or [])
    if evidence_ids != {campaign}:
        raise PrecompromiseEvidenceError('provenance.evidence_campaign_ids must contain exactly the evidence campaign')
    reused_groups = {
        'train_campaign_ids': set(provenance.get('train_campaign_ids') or []),
        'validation_campaign_ids': set(provenance.get('validation_campaign_ids') or []),
        'calibration_campaign_ids': set(provenance.get('calibration_campaign_ids') or []),
        'development_reused_campaign_ids': set(provenance.get('development_reused_campaign_ids') or []),
    }
    overlap = {name: sorted(values & {campaign}) for name, values in reused_groups.items() if values & {campaign}}
    if overlap:
        raise PrecompromiseEvidenceError(f'evidence campaign overlaps prior fitting/reuse identities: {overlap}')
    if provenance.get('identity_proof_complete') is not True:
        raise PrecompromiseEvidenceError('provenance.identity_proof_complete must be true')

    return {
        'schema_version': 'v98.2',
        'declared_status': 'PASS',
        'campaign_id': campaign,
        'warning_event': {
            'event_id': warning['event_id'],
            'timestamp': warning['timestamp'],
            'emitted_by_model': True,
            'model_identity': model_identity,
            'raw_json_sha256': sha256(warning_path),
        },
        'compromise_event': {
            'event_id': compromise['event_id'],
            'timestamp': compromise['timestamp'],
            'establishes_successful_compromise': True,
            'objective_basis': objective_basis,
            'raw_json_sha256': sha256(compromise_path),
        },
        'lead_time_seconds': float(lead_seconds),
        'provenance': {
            'identity_proof_complete': True,
            'evidence_campaign_ids': [campaign],
            **{name: sorted(values) for name, values in reused_groups.items()},
            'raw_json_sha256': sha256(provenance_path),
        },
        'integrity_checks': {
            'same_campaign': True,
            'warning_emitted_by_model': True,
            'objective_successful_compromise': True,
            'timezone_aware_timestamps': True,
            'positive_lead_time': True,
            'campaign_disjoint_from_train_validation_calibration_and_development_reuse': True,
            'synthetic_or_fixture_evidence_rejected': True,
        },
        'claim_boundary': 'Certified only for the exact evidence campaign and raw event artifacts identified by this manifest.',
    }


def unresolved_manifest(reason: str, warning_path: Path | None = None, compromise_path: Path | None = None,
                        provenance_path: Path | None = None) -> dict:
    return {
        'schema_version': 'v98.2',
        'declared_status': 'SHADOW_UNRESOLVED',
        'campaign_id': None,
        'warning_event': None,
        'compromise_event': None,
        'lead_time_seconds': None,
        'failure_reason': reason,
        'input_hashes': {
            'warning_json_sha256': sha256(warning_path) if warning_path and warning_path.exists() else None,
            'compromise_json_sha256': sha256(compromise_path) if compromise_path and compromise_path.exists() else None,
            'provenance_json_sha256': sha256(provenance_path) if provenance_path and provenance_path.exists() else None,
        },
        'claim_boundary': 'No successful-compromise lead-time claim is certified.',
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--warning', required=True, type=Path)
    p.add_argument('--compromise', required=True, type=Path)
    p.add_argument('--provenance', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    try:
        result = validate(args.warning, args.compromise, args.provenance)
        code = 0
    except Exception as exc:
        result = unresolved_manifest(str(exc), args.warning, args.compromise, args.provenance)
        code = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
