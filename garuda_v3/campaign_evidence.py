"""Reproduce clean-history warnings and objective lead time for every campaign.

Consumes reviewed observations and independent objective events. Replays are
retrospective evaluations, never described as live warnings. Missed incidents and
unknown histories remain in the report; attack onset is not compromise.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import numpy as np

from .bundle_manifest import resolve_active_bundle
from .inference import ForecastService
from .data import SCHEMA
from .v107_verify_precompromise import validate_compromise, validate_provenance
from .v110_precompromise_evidence_bundle import build_bundle


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def evaluate(manifest_path, output, artifacts=None):
    manifest_path, output = Path(manifest_path), Path(output)
    if output.exists():
        raise ValueError('Evidence output must be new')
    manifest = json.loads(manifest_path.read_text())
    provenance = manifest['provenance']
    campaigns = manifest['campaigns']
    ids = [c['campaign_id'] for c in campaigns]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError('Unique nonempty campaigns required')
    service = ForecastService(artifacts or resolve_active_bundle(Path(__file__).resolve().parents[1]))
    # Validate all inputs before creating any evidence artifact.
    loaded = []
    for campaign in campaigns:
        cid = campaign['campaign_id']; validate_provenance(provenance, cid)
        path = manifest_path.parent / campaign['graph_path']
        events_path = manifest_path.parent / campaign['objective_events_path']
        if sha(path) != campaign['graph_sha256'] or sha(events_path) != campaign['objective_events_sha256']:
            raise ValueError('Evidence source hash mismatch')
        events = json.loads(events_path.read_text())
        if not isinstance(events, list) or not events:
            raise ValueError('Independent objective events required')
        for e in events:
            ecid, _, _ = validate_compromise(e)
            if ecid != cid: raise ValueError('Objective event campaign mismatch')
        with np.load(path, allow_pickle=False) as z:
            d = {k: z[k].copy() for k in ('x','adj','mask','times','y')}
            meta = json.loads(str(z['metadata']))
        if meta.get('risk_labels_reviewed') is not True or meta.get('campaign_id') != cid:
            raise ValueError('Reviewed benign history labels and campaign identity required')
        if not np.isin(d['y'], [-1,0,1]).all():
            raise ValueError('Unknown observed labels must remain -1')
        if len(d['times']) != len(d['x']) or len(d['y']) != len(d['x']):
            raise ValueError('Window arrays differ in length')
        if np.any(np.diff(d['times']) <= 0): raise ValueError('Ordered unique timestamps required')
        loaded.append((campaign,d,meta,events))
    output.mkdir(parents=True)
    reports = []
    for campaign, d, meta, events in loaded:
        cid = campaign['campaign_id']
        # Directory names cannot be supplied by external campaign strings.
        folder = output / hashlib.sha256(cid.encode()).hexdigest()[:16]; folder.mkdir()
        warnings = []; evaluated = unknown = unsupported = 0
        h, step = service.meta['history'], service.meta['window_seconds']
        first_success = min(validate_compromise(e)[1].timestamp() for e in events)
        for end in range(h, len(d['times'])+1):
            start = end-h; cutoff = float(d['times'][end-1])+step
            if cutoff >= first_success: break
            if not np.all(np.diff(d['times'][start:end]) == step): continue
            labels = d['y'][start:end]
            if np.any(labels < 0): unknown += 1; continue
            if np.any(labels != 0): continue
            payload = {'schema': SCHEMA, 'mode': meta['mode'], 'window_seconds': step,
                'times': d['times'][start:end].tolist(), 'data_source': 'reviewed_campaign_replay',
                **{k:d[k][start:end].tolist() for k in ('x','adj','mask')}}
            try: forecast = service.predict(payload)
            except ValueError: unsupported += 1; continue
            evaluated += 1
            if forecast.get('alert'):
                warnings.append({'event_type': 'model_warning', 'emitted_by_model': True,
                    'campaign_id': cid, 'timestamp': datetime.fromtimestamp(cutoff,timezone.utc).isoformat(),
                    'model_sha256': service.model_hash, 'warning_id': f'{cid}:{end}',
                    'evaluation_mode': 'retrospective_observed-history_replay',
                    'live_warning_claim': False, 'graph_sha256': campaign['graph_sha256']})
        wp, cp, pp = folder/'warnings.jsonl', folder/'objectives.jsonl', folder/'provenance.json'
        wp.write_text(''.join(json.dumps(w)+'\n' for w in warnings))
        cp.write_text(''.join(json.dumps(e)+'\n' for e in events))
        pp.write_text(json.dumps(provenance,indent=2))
        row = {'campaign_id': cid, 'clean_histories_evaluated': evaluated,
            'unknown_histories_excluded': unknown, 'unsupported_histories': unsupported,
            'objective_incidents': 1, 'hit': bool(warnings), 'lead_time_seconds': None}
        if warnings:
            bundle = build_bundle(wp, cp, pp, folder/'bundle', service.model_hash, cid)
            row['lead_time_seconds'] = bundle['verification']['lead_time_seconds']
        reports.append(row)
    leads = [r['lead_time_seconds'] for r in reports if r['hit']]
    result = {'evaluation_mode': 'retrospective_replay', 'live_warning_claim': False,
        'model_sha256': service.model_hash, 'manifest_sha256': sha(manifest_path),
        'campaigns': reports, 'event_recall': sum(r['hit'] for r in reports)/len(reports),
        'median_hit_lead_time_seconds': float(np.median(leads)) if leads else None,
        'all_campaigns_reported': True, 'automatic_containment': False,
        'claim_boundary': 'Objective timestamp lead time in retrospective clean-history replay; not a live pilot or production certification.'}
    (output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    print(json.dumps(evaluate(args.manifest,args.output),indent=2))


if __name__ == '__main__': main()
