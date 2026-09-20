"""Offline minute-state CSV inference for explicitly installed joint-reserve models.

No labels are read. Returns tail-evidence scores in shadow mode, not probabilities.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import numpy as np
import pandas as pd
from .v47_unseen_family import HISTORY, parse_time, pick_col
from .v48_runtime import V48Runtime


def analyze_v48(raw):
    root = os.environ.get('GARUDA_V48_RUNTIME_DIR')
    if not root:
        raise ValueError('V48 joint runtime not installed. Set GARUDA_V48_RUNTIME_DIR to validated joint-reserve runtime folder.')
    manifests = sorted(Path(root).glob('*/manifest.json'))
    by_seed = {}
    for path in manifests:
        meta = json.loads(path.read_text())
        seed = meta['seed']
        if seed in by_seed and by_seed[seed][0]['arrays_sha256'] != meta['arrays_sha256']:
            raise ValueError('Family-specific models cannot be routed using unknown ground truth; install joint-reserve models')
        by_seed[seed] = (meta, path.parent)
    if set(by_seed) != {42, 43, 44}:
        raise ValueError('V48 shadow runtime requires seeds 42, 43 and 44; missing seeds are not silently skipped')
    models = [V48Runtime(by_seed[seed][1]) for seed in sorted(by_seed)]
    names = models[0].meta['feature_names']
    if any(m.meta['feature_names'] != names for m in models):
        raise ValueError('V48 ensemble feature contract mismatch')
    df = pd.read_csv(io.BytesIO(raw), low_memory=False)
    dt, *_ = parse_time(df)
    src = pick_col(df.columns, ['Scr_IP','Src_IP','Source_IP','source_ip'])
    if not src or dt.isna().any() or df[src].isna().any():
        raise ValueError('V48 CSV requires source IP and valid absolute timestamps for every record')
    features = list(dict.fromkeys(n.rsplit('__', 1)[0] for n in names if n != 'flow_count'))
    missing = sorted(set(features) - set(df.columns))
    if missing:
        raise ValueError('V48 network feature columns missing: ' + ', '.join(missing))
    base = pd.DataFrame({'src': df[src].astype(str), 'minute': dt.dt.floor('min')})
    for col in features:
        base[col] = pd.to_numeric(df[col].replace(['-', '?', 'None', 'none', 'null', ''], np.nan), errors='coerce')
    grouped = base.groupby(['src','minute'], sort=True)
    state = grouped[features].agg(['mean','std','max'])
    state.columns = ['__'.join(parts) for parts in state.columns]
    state['flow_count'] = grouped.size().astype(float)
    state = state.reset_index()
    histories = []
    for host, rows in state.groupby('src', sort=True):
        times = rows['minute'].astype('int64').to_numpy() // 10**9
        values = rows[names].to_numpy(dtype=np.float32)
        for end in range(HISTORY, len(rows)+1):
            if np.all(np.diff(times[end-HISTORY:end]) == 60):
                histories.append((int(times[end-1]+60), host, values[end-HISTORY:end]))
    histories.sort(key=lambda x: (x[0], x[1]))
    histories = histories[-32:]
    outputs = []
    if histories:
        X = np.stack([h[2] for h in histories])
        results = [m.predict(X, names) for m in models]
        for i, (cutoff, host, _) in enumerate(histories):
            outputs.append({'cutoff_epoch_seconds': cutoff, 'host': host,
                'horizon_seconds': [60,120,180,240],
                'seeds': [{'seed': m.meta['seed'], 'score': float(r['score'][i]),
                           'threshold': m.meta['threshold'], 'alert': bool(r['alert'][i]),
                           'component_evidence': {k: float(v[i]) for k,v in r['components'].items()},
                           'transfer_features': [{'feature': names[j], 'logit_contribution': float(r['transfer_feature_contributions'][i,j])} for j in np.argsort(-np.abs(r['transfer_feature_contributions'][i]))[:5]],
                           'transition_features': [{'feature': names[j], 'scaled_energy': float(r['transition_feature_energy'][i,j])} for j in np.argsort(-r['transition_feature_energy'][i])[:5]],
                           'explanation_scope': 'Exact logistic-head contributions and transition-energy decomposition; not causal or fused-probability attribution',
                           'state_scaled': r['state_scaled'][i].tolist()}
                          for m,r in zip(models,results)],
                'stage': 'insufficient evidence', 'automatic_containment': False})
    return {'status': 'shadow_forecast_available' if outputs else 'insufficient_evidence',
            'lane': 'v48_joint_shadow', 'score_kind': 'benign_tail_evidence_not_probability',
            'input_sha256': hashlib.sha256(raw).hexdigest(), 'windows': len(state),
            'scope': 'Last 32 contiguous 8-minute host histories; fixed three-seed shadow output',
            'model_hashes': [m.meta['arrays_sha256'] for m in models],
            'feature_names': names, 'forecasts': outputs, 'automatic_containment': False}
