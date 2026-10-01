"""Train future risk/stage heads on the frozen V123 spatial/temporal backbone.

Input is hash-pinned, campaign-separated *sequence* NPZs with reviewed future
labels. No old 21-feature graph or record classifier can satisfy this contract.
Unknown targets are masked. Candidates never replace the certified state bundle.
"""
import argparse
import json
from pathlib import Path

import numpy as np

from .autograd import Adam
from .latest_state_runtime import LatestStateForecastService, EXPECTED, _sha256
from .model import GraphWorldModel
from .ps_complete import FEATURES
from .v101_packet_graph_recovery import HISTORY, HORIZON, MAX_NODES
from .v115_relative_state_world_model import RAW_SCHEMA

STAGES = ['Reconnaissance', 'Initial Access', 'Lateral Movement', 'Command and Control', 'Exfiltration']
HEAD_KEYS = {'risk', 'risk_b', 'stage', 'stage_b'}


def prepare_sequences(window_graph, output):
    from .ps_complete import load_dataset
    data = load_dataset(window_graph)
    if data['x'].shape[1:] != (MAX_NODES, len(FEATURES)) or data['metadata']['mode'] != 'service':
        raise ValueError('Frozen backbone requires 32-node service graphs')
    if 'stage_y' not in data or data['stage_y'].shape != (len(data['times']), 5):
        raise ValueError('Reviewed five-tactic timeline is required')
    if Path(output).exists(): raise ValueError('Sequence output must be new')
    stages = np.full(len(data['times']), -1, np.int64)
    for i, row in enumerate(data['stage_y']):
        # Overlapping or partially unknown tactics cannot become one exact stage.
        if np.isin(row, [0,1]).all() and int((row == 1).sum()) == 1 and data['y'][i] == 1:
            stages[i] = int(row.argmax())
    out = {k: [] for k in ('x','adj','mask','times','risk_y','stage_y')}
    for start in range(len(data['times']) - HISTORY - HORIZON + 1):
        end = start + HISTORY
        if not np.all(np.diff(data['times'][start:end+HORIZON]) == 10): continue
        for k in ('x','adj','mask','times'): out[k].append(data[k][start:end])
        out['risk_y'].append(data['y'][end:end+HORIZON])
        out['stage_y'].append(stages[end:end+HORIZON])
    if not out['x']: raise ValueError('No complete 80s history + 40s future sequences')
    np.savez_compressed(output, **{k:np.asarray(v) for k,v in out.items()}, metadata=json.dumps({'raw_schema': RAW_SCHEMA, 'features': FEATURES, 'campaign_id': data['metadata'].get('campaign_id')}))
    return {'sequences': len(out['x']), 'input_sha256': _sha256(window_graph),
        'sequence_sha256': _sha256(output), 'unknown_targets_preserved': True}


def load_split(entries, base):
    arrays = {k: [] for k in ('x', 'adj', 'mask', 'times', 'risk_y', 'stage_y')}
    families = []
    for entry in entries:
        path = (base / entry['path']).resolve()
        if _sha256(path) != entry['sha256'] or entry.get('labels_reviewed') is not True:
            raise ValueError('Hash-pinned reviewed labels required')
        if not entry.get('annotation_sha256') or not entry.get('raw_source_sha256'):
            raise ValueError('Raw source and annotation provenance required')
        if _sha256(base / entry['annotation_path']) != entry['annotation_sha256']:
            raise ValueError('Reviewed annotation hash mismatch')
        if _sha256(base / entry['raw_source_path']) != entry['raw_source_sha256']:
            raise ValueError('Raw telemetry hash mismatch')
        z = np.load(path, allow_pickle=False)
        metadata = json.loads(str(z['metadata']))
        if metadata.get('raw_schema') != RAW_SCHEMA or metadata.get('features') != FEATURES or metadata.get('campaign_id') != entry['campaign_id']:
            raise ValueError('Sequence schema, feature ordering or campaign mismatch')
        n = len(z['x'])
        shapes = {'x': (n, HISTORY, MAX_NODES, len(FEATURES)),
            'adj': (n, HISTORY, MAX_NODES, MAX_NODES), 'mask': (n, HISTORY, MAX_NODES),
            'times': (n, HISTORY), 'risk_y': (n, HORIZON), 'stage_y': (n, HORIZON)}
        for key, shape in shapes.items():
            a = np.asarray(z[key])
            if a.shape != shape or not np.isfinite(a).all():
                raise ValueError(f'{key}: 34-feature/80s/4-horizon contract required')
            arrays[key].append(a.astype(np.int64) if key in ('risk_y', 'stage_y', 'times') else a)
        if np.any(np.asarray(z['times']) % 10 != 0):
            raise ValueError('UTC 10-second bucket timestamps required')
        if any(np.any((z[k] < 0) | (z[k] > 1)) for k in ('x','adj','mask')):
            raise ValueError('Raw packet/flow graph features must remain in [0,1]')
        if not np.all(np.diff(z['times'], axis=1) == 10):
            raise ValueError('Non-contiguous history')
        if not np.isin(z['risk_y'], [-1, 0, 1]).all() or not np.isin(z['stage_y'], [-1, 0, 1, 2, 3, 4]).all():
            raise ValueError('Unknown labels must be -1; exact five-stage indices required')
        if np.any((z['stage_y'] >= 0) & (z['risk_y'] != 1)):
            raise ValueError('A verified attack stage requires a positive risk target')
        families.extend([entry['family']] * n)
    if not families:
        raise ValueError('Empty split')
    return {k: np.concatenate(v) for k, v in arrays.items()}, np.asarray(families)


def validate_manifest(manifest):
    identities = []
    for split in ('train', 'validation', 'test'):
        entries = manifest[split]
        if not entries:
            raise ValueError('Three nonempty campaign splits required')
        campaigns = {e['campaign_id'] for e in entries}
        sources = {e['raw_source_sha256'] for e in entries}
        identities.append((campaigns, sources))
    for i in range(3):
        for j in range(i):
            if identities[i][0] & identities[j][0] or identities[i][1] & identities[j][1]:
                raise ValueError('Campaign/source leakage across splits')
    consumed = set(manifest.get('backbone_development_source_sha256', []))
    if not consumed:
        raise ValueError('Backbone development sources must be declared')
    if consumed & identities[2][1]:
        raise ValueError('Final sources were consumed by backbone development')


def attach_heads(backbone, seed):
    cfg = {**backbone.config, 'stage_count': 5, 'seed': seed}
    model = GraphWorldModel(**cfg)
    for key, parameter in model.params.items():
        if key not in HEAD_KEYS:
            parameter.data = backbone.params[key].data.copy()
        parameter.requires_grad = key in HEAD_KEYS
    return model


class ShadowReadout:
    """Explicit research opt-in for trained future heads, never an enforcement gate."""
    def __init__(self, folder, backbone, seed=42):
        folder = Path(folder)
        self.report = json.loads((folder/'report.json').read_text())
        if self.report['base_model_sha256'] != EXPECTED['model']:
            raise ValueError('Head experiment backbone mismatch')
        checkpoint = folder / f'heads_seed{seed}.npz'
        self.model, meta = GraphWorldModel.load(checkpoint)
        if meta.get('base_model_sha256') != EXPECTED['model'] or meta.get('features') != FEATURES:
            raise ValueError('Head checkpoint feature/base identity mismatch')
        if meta.get('risk_head_trained') is not True or meta.get('stage_head_trained') is not True or meta.get('shadow_only') is not True:
            raise ValueError('Explicit trained shadow heads required')
        for k, value in backbone.params.items():
            if k not in HEAD_KEYS and not np.array_equal(value.data, self.model.params[k].data):
                raise ValueError('Head checkpoint changed certified state backbone')
        rows = [r for r in self.report['seeds'] if r['seed'] == seed]
        if len(rows) != 1: raise ValueError('Unique seed report required')
        self.row = rows[0]; self.model_sha256 = _sha256(checkpoint)
        if self.model_sha256 != self.row['checkpoint_sha256']:
            raise ValueError('Experiment report/checkpoint hash mismatch')
        for p in self.model.parameters(): p.requires_grad = False

    def forecast(self, x, adj, mask):
        _, _, r, s = self.model.forward(x, adj, mask, HORIZON, return_stages=True)
        trajectory = []
        for h in range(HORIZON):
            index = int(s.data[0,h].argmax()); name = STAGES[index]
            evidence = self.row['per_stage'][name]
            stage_supported = evidence['support'] >= 30 and evidence['recall'] >= .8
            trajectory.append({'horizon_seconds':(h+1)*10,
                'future_attack_score':float(r.data[0,h]),
                'validation_threshold':self.row['thresholds_validation_only'][h],
                'stage':name if stage_supported else 'insufficient evidence'})
        return {'status':'EXPERIMENTAL_SHADOW_ONLY', 'trajectory':trajectory,
            'model_sha256':self.model_sha256, 'same_frozen_state_backbone':True,
            'calibrated_probability':False, 'automatic_containment':False,
            'any_horizon_alert':bool(r.data[0].max()>=self.row.get('any_horizon_threshold_validation_only',1.000001)),
            'any_horizon_gate_verified':self.row.get('any_horizon_metrics',{}).get('gate_passed',False),
            'independent_gates_passed':self.report['all_seed_gates_passed'] and self.row.get('any_horizon_metrics',{}).get('gate_passed',False)}


def objective(model, data, ids):
    _, _, risk, stage = model.forward(data['x'][ids], data['adj'][ids], data['mask'][ids], HORIZON, return_stages=True)
    y = data['risk_y'][ids]
    known = (y >= 0).astype(np.float32)
    risk = .000001 + .999998 * risk
    target = np.maximum(y, 0)
    bce = -((target * risk.log() + (1-target) * (1-risk).log()) * known).sum() / max(1, known.sum())
    sy = data['stage_y'][ids]
    stage_known = (sy >= 0)[..., None].astype(np.float32)
    target_stage = np.eye(5, dtype=np.float32)[np.maximum(sy, 0)]
    stage = .000001 + .999998 * stage
    stage_loss = -((target_stage * stage.log() + (1-target_stage) * (1-stage).log()) * stage_known).sum() / max(1, stage_known.sum()*5)
    return bce + stage_loss


def predict(model, data):
    risks, stages = [], []
    for start in range(0, len(data['x']), 64):
        sl = slice(start, start+64)
        _, _, r, s = model.forward(data['x'][sl], data['adj'][sl], data['mask'][sl], HORIZON, return_stages=True)
        risks.append(r.data); stages.append(s.data)
    return np.concatenate(risks), np.concatenate(stages)


def binary_metrics(y, scores, threshold):
    valid = y >= 0; y, scores = y[valid], scores[valid]
    positive, negative = y == 1, y == 0
    pred = scores >= threshold
    tp, fp = int(np.sum(pred & positive)), int(np.sum(pred & negative))
    p, n = int(positive.sum()), int(negative.sum())
    precision, recall = tp/max(1, tp+fp), tp/max(1, p)
    return {'positive_support': p, 'negative_support': n, 'recall': recall,
        'fpr': fp/max(1, n), 'precision': precision,
        'f1': 2*precision*recall/max(1e-12, precision+recall),
        'gate_passed': p >= 30 and n >= 300 and recall >= .8 and fp/max(1, n) <= .01}


def select_thresholds(y, scores):
    thresholds = []
    for h in range(HORIZON):
        candidates = np.unique(np.r_[scores[:, h], 1.000001])
        feasible = [(binary_metrics(y[:, h], scores[:, h], float(t)), float(t)) for t in candidates]
        feasible = [(m, t) for m, t in feasible if m['fpr'] <= .01]
        thresholds.append(max(feasible, key=lambda v: (v[0]['recall'], v[1]))[1])
    return thresholds


def future_any_target(y):
    """Unknown future windows cannot silently become a negative 40s outcome."""
    y=np.asarray(y)
    if y.ndim!=2 or not np.isin(y,[-1,0,1]).all():raise ValueError('Reviewed multi-horizon labels required')
    return np.where((y==1).any(1),1,np.where((y<0).any(1),-1,0))


def select_any_horizon_threshold(y,scores):
    target=future_any_target(y);score=np.asarray(scores).max(1)
    candidates=np.unique(np.r_[score,1.000001])
    feasible=[(binary_metrics(target,score,float(t)),float(t)) for t in candidates]
    feasible=[(m,t) for m,t in feasible if m['fpr']<=.01]
    return max(feasible,key=lambda v:(v[0]['recall'],v[1]))[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path)
    ap.add_argument('--prepare-window-graph', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--epochs', type=int, default=15)
    ap.add_argument('--seeds', nargs='+', type=int, default=[42, 43, 44])
    args = ap.parse_args()
    if args.prepare_window_graph:
        if args.manifest: ap.error('Choose preparation or training')
        print(json.dumps(prepare_sequences(args.prepare_window_graph, args.output), indent=2))
        return
    if not args.manifest: ap.error('--manifest required for training')
    if args.output.exists() or len(set(args.seeds)) < 3 or args.epochs < 1:
        ap.error('New output, >=3 distinct seeds and positive epochs required')
    manifest = json.loads(args.manifest.read_text()); validate_manifest(manifest)
    runtime = LatestStateForecastService()
    # The actual pinned backbone's known development identities are mandatory.
    source_summary = json.loads((Path(__file__).parent / 'artifacts/certification/v116/summary.json').read_text())
    known_sources = {source_summary['development_sources'][p]['sha256'] for p in ('phase1', 'phase2')}
    if not known_sources.issubset(set(manifest['backbone_development_source_sha256'])):
        raise ValueError('Manifest omits pinned backbone development sources')
    sets = {}; family = {}
    for split in ('train', 'validation', 'test'):
        sets[split], family[split] = load_split(manifest[split], args.manifest.parent)
        sets[split]['x'], _ = runtime._relative_history(sets[split]['x'], sets[split]['mask'])
    for split in ('train', 'validation'):
        for h in range(HORIZON):
            labels = sets[split]['risk_y'][:, h]
            if min(int((labels == 0).sum()), int((labels == 1).sum())) < 5:
                raise ValueError('Every development horizon needs >=5 benign and attack targets')
        if any(int((sets[split]['stage_y'] == i).sum()) < 5 for i in range(5)):
            raise ValueError('Every stage needs reviewed train/validation support')
    args.output.mkdir(parents=True)
    reports = []
    for seed in args.seeds:
        model = attach_heads(runtime.model, seed)
        opt = Adam([model.params[k] for k in HEAD_KEYS], lr=.003)
        rng = np.random.default_rng(seed); best = float('inf'); selected = None
        for epoch in range(args.epochs):
            order = rng.permutation(len(sets['train']['x']))
            for start in range(0, len(order), 64):
                objective(model, sets['train'], order[start:start+64]).backward(); opt.step()
            v = float(objective(model, sets['validation'], np.arange(len(sets['validation']['x']))).data)
            if v < best:
                best = v; selected = {k: model.params[k].data.copy() for k in HEAD_KEYS}
        for k, value in selected.items(): model.params[k].data = value
        for k, value in runtime.model.params.items():
            if k not in HEAD_KEYS and not np.array_equal(model.params[k].data, value.data):
                raise RuntimeError('Frozen state backbone changed')
        vr, _ = predict(model, sets['validation'])
        thresholds = select_thresholds(sets['validation']['risk_y'], vr)
        # Control the actual any-horizon alert, rather than OR-ing four separate
        # 1% rules and accidentally multiplying the operational false-alert rate.
        joint_threshold=select_any_horizon_threshold(sets['validation']['risk_y'],vr)
        tr, ts = predict(model, sets['test'])
        risk_report = {str(h+1): {str(f): binary_metrics(sets['test']['risk_y'][family['test']==f, h], tr[family['test']==f, h], thresholds[h]) for f in np.unique(family['test'])} for h in range(HORIZON)}
        sy = sets['test']['stage_y']; sp = ts.argmax(axis=-1)
        stage_report = {}
        for i, name in enumerate(STAGES):
            tp = int(((sp == i) & (sy == i)).sum())
            actual, predicted = int((sy == i).sum()), int(((sp == i) & (sy >= 0)).sum())
            precision, recall = tp/max(1, predicted), tp/max(1, actual)
            stage_report[name] = {'support': actual, 'precision': precision, 'recall': recall, 'f1': 2*precision*recall/max(1e-12,precision+recall)}
        joint_metrics=binary_metrics(future_any_target(sets['test']['risk_y']),tr.max(1),joint_threshold)
        passed = joint_metrics['gate_passed'] and all(m['gate_passed'] for row in risk_report.values() for m in row.values()) and all(m['support']>=30 and m['recall']>=.8 for m in stage_report.values())
        model.save(args.output / f'heads_seed{seed}.npz', {'schema': RAW_SCHEMA, 'base_model_sha256': EXPECTED['model'], 'features': FEATURES, 'risk_head_trained': True, 'stage_head_trained': True, 'shadow_only': True})
        reports.append({'seed': seed, 'checkpoint_sha256': _sha256(args.output / f'heads_seed{seed}.npz'), 'thresholds_validation_only': thresholds,
            'any_horizon_threshold_validation_only':joint_threshold,
            'any_horizon_metrics':binary_metrics(future_any_target(sets['test']['risk_y']),tr.max(1),joint_threshold),
            'per_family_per_horizon': risk_report, 'per_stage': stage_report, 'gate_passed': passed})
    report = {'base_model_sha256': EXPECTED['model'], 'manifest_sha256': _sha256(args.manifest),
        'state_backbone_unchanged': True, 'seeds': reports,
        'all_seed_gates_passed': all(r['gate_passed'] for r in reports),
        'automatic_promotion': False, 'automatic_containment': False,
        'claim_boundary': 'Frozen-backbone future-label head experiment; independent lead-time evidence remains separate.'}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
