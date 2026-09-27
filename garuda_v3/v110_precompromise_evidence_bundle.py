"""Build a hash-pinned warning-before-successful-compromise evidence bundle.

V110 never invents timestamps or upgrades attack onset into compromise. It selects a
same-campaign pair only from caller-supplied raw model-warning and objective-success
events, copies the selected raw JSON objects into an immutable bundle, then delegates
the final claim check to the strict V107 verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .v107_verify_precompromise import (
    EvidenceError,
    parse_time,
    validate_warning,
    validate_compromise,
    validate_provenance,
    verify,
)


class BundleError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lineno, raw in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            raise BundleError(f'{path}:{lineno}: invalid JSON: {exc}') from exc
        if not isinstance(row, dict):
            raise BundleError(f'{path}:{lineno}: JSON object required')
        rows.append(row)
    if not rows:
        raise BundleError(f'{path}: no JSON events')
    return rows


def canonical_write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')


def candidate_pairs(warnings: list[dict[str, Any]], compromises: list[dict[str, Any]], provenance: dict[str, Any], expected_model_sha256: str | None = None) -> list[dict[str, Any]]:
    valid_warnings = []
    for row in warnings:
        try:
            campaign, when, model_hash = validate_warning(row)
        except EvidenceError:
            continue
        if expected_model_sha256 and model_hash != expected_model_sha256:
            continue
        try:
            validate_provenance(provenance, campaign)
        except EvidenceError:
            continue
        valid_warnings.append((campaign, when, model_hash, row))

    valid_compromises = []
    for row in compromises:
        try:
            campaign, when, marker = validate_compromise(row)
            validate_provenance(provenance, campaign)
        except EvidenceError:
            continue
        valid_compromises.append((campaign, when, marker, row))

    pairs = []
    campaigns = sorted({x[0] for x in valid_warnings} & {x[0] for x in valid_compromises})
    for campaign in campaigns:
        cands_c = sorted((x for x in valid_compromises if x[0] == campaign), key=lambda x: x[1])
        if not cands_c:
            continue
        # First objective successful-compromise event defines the campaign boundary.
        compromise = cands_c[0]
        prior = sorted((x for x in valid_warnings if x[0] == campaign and x[1] < compromise[1]), key=lambda x: x[1])
        if not prior:
            continue
        # First model warning is the predeclared lead-time statistic.
        warning = prior[0]
        lead = (compromise[1] - warning[1]).total_seconds()
        if lead <= 0:
            continue
        pairs.append({
            'campaign_id': campaign,
            'warning_time': warning[1].isoformat(),
            'compromise_time': compromise[1].isoformat(),
            'lead_time_seconds': float(lead),
            'warning': warning[3],
            'compromise': compromise[3],
        })
    return sorted(pairs, key=lambda x: (x['campaign_id'], x['warning_time'], x['compromise_time']))


def build_bundle(warning_log: Path, compromise_log: Path, provenance_path: Path, output_dir: Path, expected_model_sha256: str | None = None, campaign_id: str | None = None) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise BundleError('output directory is not empty; evidence bundles are immutable')
    warnings = load_jsonl(warning_log)
    compromises = load_jsonl(compromise_log)
    provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
    if not isinstance(provenance, dict):
        raise BundleError('provenance top-level object required')

    pairs = candidate_pairs(warnings, compromises, provenance, expected_model_sha256)
    if campaign_id:
        pairs = [p for p in pairs if p['campaign_id'] == campaign_id]
    if not pairs:
        raise BundleError('no certifiable same-campaign warning-before-successful-compromise pair found')
    if campaign_id is None and len(pairs) != 1:
        raise BundleError('multiple certifiable campaigns found; pass --campaign-id to avoid post-hoc campaign selection')
    selected = pairs[0]

    output_dir.mkdir(parents=True, exist_ok=True)
    warning_path = output_dir / 'warning_event.json'
    compromise_path = output_dir / 'compromise_event.json'
    provenance_copy = output_dir / 'provenance.json'
    canonical_write(warning_path, selected['warning'])
    canonical_write(compromise_path, selected['compromise'])
    canonical_write(provenance_copy, provenance)

    verified = verify(warning_path, compromise_path, provenance_copy)
    if verified.get('status') != 'PASS':
        raise BundleError('strict V107 verifier did not pass selected evidence')

    report = {
        'schema_version': 'v110.1',
        'status': 'PASS',
        'campaign_id': selected['campaign_id'],
        'selection_policy': {
            'campaign_selection': 'explicit --campaign-id required when more than one certifiable campaign exists',
            'warning_statistic': 'first valid model warning before first objective successful-compromise event',
            'compromise_statistic': 'first objective successful-compromise event',
            'attack_onset_accepted_as_compromise': False,
            'synthetic_events_allowed_for_release_evidence': False,
        },
        'source_logs': {
            'warning_log_sha256': sha256_file(warning_log),
            'compromise_log_sha256': sha256_file(compromise_log),
            'provenance_source_sha256': sha256_file(provenance_path),
        },
        'selected_raw_artifacts': {
            'warning_event_sha256': sha256_file(warning_path),
            'compromise_event_sha256': sha256_file(compromise_path),
            'provenance_sha256': sha256_file(provenance_copy),
        },
        'verification': verified,
        'claim_boundary': 'PASS applies only to the exact campaign and raw event artifacts in this bundle.',
    }
    canonical_write(output_dir / 'verification.json', report)
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--warning-log', required=True, type=Path)
    p.add_argument('--compromise-log', required=True, type=Path)
    p.add_argument('--provenance', required=True, type=Path)
    p.add_argument('--output-dir', required=True, type=Path)
    p.add_argument('--expected-model-sha256')
    p.add_argument('--campaign-id')
    args = p.parse_args()
    result = build_bundle(args.warning_log, args.compromise_log, args.provenance, args.output_dir, args.expected_model_sha256, args.campaign_id)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
