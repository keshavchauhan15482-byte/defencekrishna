"""V48 fresh ToN-IoT unseen-family temporal transfer benchmark.

V47 showed that a benign future-trajectory anomaly score alone is too conservative
for unseen-family attack warning, while a discriminative model transfers to some
held-out families but overshoots the false-positive budget. V48 freezes a hybrid
before looking at ToN-IoT outcomes:

  temporal LSTM known-family risk (75%) + world-forecast novelty percentile (25%).

The held-out attack family is absent from train/calibration/policy data. Labels are
used only to construct the family-disjoint split and evaluate frozen predictions.
The policy threshold is chosen from benign policy traffic only at a 0.5% empirical
FPR reserve; the release gate remains <=1% FPR and >=80% recall.

This is a controlled unseen-family benchmark, not proof of an undisclosed zero-day
or verified compromise lead time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

HISTORY = 8
HORIZON = 4
SEEDS = (42, 43, 44)
EMBARGO_MINUTES = HISTORY + HORIZON
POLICY_FPR_RESERVE = 0.005
RELEASE_FPR = 0.01
RELEASE_RECALL = 0.80
FUSION_RISK_WEIGHT = 0.75
FUSION_WORLD_WEIGHT = 0.25

# Common network-only fields intentionally available in ToN-IoT and the V47
# X-IIoTID development track. IPs are grouping keys only, never model features.
FEATURE_ALIASES = {
    'src_port': ('src_port', 'scr_port', 'source_port'),
    'dst_port': ('dst_port', 'des_port', 'destination_port'),
    'duration': ('duration',),
    'src_bytes': ('src_bytes', 'scr_bytes'),
    'dst_bytes': ('dst_bytes', 'des_bytes'),
    'missed_bytes': ('missed_bytes',),
    'src_pkts': ('src_pkts', 'scr_pkts'),
    'src_ip_bytes': ('src_ip_bytes', 'scr_ip_bytes'),
    'dst_pkts': ('dst_pkts', 'des_pkts'),
    'dst_ip_bytes': ('dst_ip_bytes', 'des_ip_bytes'),
}


def norm(value):
    return ''.join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def pick_col(columns, names):
    mapping = {norm(c): c for c in columns}
    for name in names:
        if norm(name) in mapping:
            return mapping[norm(name)]
    return None


def resolve_schema(df):
    ts = pick_col(df.columns, ['ts', 'timestamp', 'time'])
    src_ip = pick_col(df.columns, ['src_ip', 'source_ip', 'scr_ip'])
    label = pick_col(df.columns, ['label', 'attack_flag', 'class'])
    family = pick_col(df.columns, ['type', 'attack_name', 'attack_type'])
    if not all([ts, src_ip, label, family]):
        raise ValueError(f'Required ToN-IoT columns missing: ts={ts} src_ip={src_ip} label={label} family={family}')
    selected = {}
    for canonical, aliases in FEATURE_ALIASES.items():
        col = pick_col(df.columns, aliases)
        if col is not None:
            numeric = pd.to_numeric(df[col], errors='coerce')
            if float(numeric.notna().mean()) >= 0.70 and int(numeric.nunique(dropna=True)) > 1:
                selected[canonical] = col
    if len(selected) < 8:
        raise ValueError(f'Only {len(selected)} strict network numeric features available: {selected}')
    return {'timestamp': ts, 'src_ip': src_ip, 'label': label, 'family': family, 'features': selected}


def parse_timestamp(series):
    numeric = pd.to_numeric(series, errors='coerce')
    if float(numeric.notna().mean()) >= 0.95:
        med = float(numeric.dropna().median())
        unit = 'ms' if med > 1e11 else 's'
        dt = pd.to_datetime(numeric, unit=unit, errors='coerce', utc=True)
        if float(dt.notna().mean()) >= 0.95:
            return dt, unit
    dt = pd.to_datetime(series.astype(str), errors='coerce', utc=True)
    if float(dt.notna().mean()) < 0.95:
        raise ValueError('Timestamp parsing below 95%')
    return dt, 'text'


def normalize_labels(df, schema):
    raw = df[schema['label']]
    numeric = pd.to_numeric(raw, errors='coerce')
    if float(numeric.notna().mean()) >= 0.99 and set(numeric.dropna().unique()).issubset({0, 1, 0.0, 1.0}):
        y = numeric.astype('float64')
    else:
        text = raw.astype(str).str.strip().str.lower()
        y = pd.Series(np.nan, index=df.index, dtype='float64')
        y.loc[text.isin(['normal', 'benign', '0'])] = 0.0
        y.loc[text.isin(['attack', 'malicious', '1'])] = 1.0
    family = df[schema['family']].astype(str).str.strip()
    return y, family


def _family_tuple(values, labels):
    out = set()
    for value, attack in zip(values, labels):
        if int(attack) != 1:
            continue
        text = str(value).strip()
        if text.lower() not in {'normal', 'benign', 'attack', 'nan', 'none', ''}:
            out.add(text)
    return tuple(sorted(out))


def build_minute_state(df, dt, y, family, schema):
    base = pd.DataFrame({'dt': dt, 'label': y, 'family': family, 'src': df[schema['src_ip']].astype(str)})
    for canonical, col in schema['features'].items():
        base[canonical] = pd.to_numeric(df[col], errors='coerce')
    base = base.dropna(subset=['dt', 'label']).copy()
    base['label'] = base['label'].astype(int)
    base['minute'] = base['dt'].dt.floor('min')
    feature_names = list(schema['features'])
    grouped = base.groupby(['src', 'minute'], sort=True)
    state = grouped[feature_names].agg(['mean', 'std', 'max'])
    state.columns = ['__'.join(parts) for parts in state.columns]
    state['flow_count'] = grouped.size().astype(float)
    state['attack_now'] = grouped['label'].max().astype(int)
    fam = grouped.apply(lambda g: _family_tuple(g['family'].tolist(), g['label'].tolist()), include_groups=False)
    fam.name = 'families'
    state = state.join(fam).reset_index().sort_values(['src', 'minute']).reset_index(drop=True)
    state_features = [c for c in state.columns if c not in {'src', 'minute', 'attack_now', 'families'}]
    return state, state_features


def make_sequences(state, state_features):
    X, future, y, cutoff, clean, hist_families, step_families = [], [], [], [], [], [], []
    for _, group in state.groupby('src', sort=False):
        g = group.sort_values('minute').reset_index(drop=True)
        t = g['minute'].astype('int64').to_numpy() // 10**9
        attack = g['attack_now'].to_numpy(dtype=int)
        z = g[state_features].to_numpy(dtype=np.float32)
        families = g['families'].tolist()
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            stop = i + HORIZON + 1
            span = t[lo:stop]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            X.append(z[lo:i + 1])
            future.append(z[i + 1:stop])
            y.append(int(attack[i + 1:stop].max()))
            cutoff.append(int(t[i]))
            clean.append(bool(attack[lo:i + 1].max() == 0))
            hs = set()
            for item in families[lo:i + 1]:
                hs.update(item)
            hist_families.append(frozenset(hs))
            step_families.append(tuple(frozenset(item) for item in families[i + 1:stop]))
    if not X:
        raise ValueError('No contiguous ToN-IoT histories with complete future horizon')
    return {
        'X': np.stack(X), 'future': np.stack(future), 'y': np.asarray(y, dtype=np.int8),
        'cutoff': np.asarray(cutoff, dtype=np.int64), 'clean': np.asarray(clean, dtype=bool),
        'history_families': np.asarray(hist_families, dtype=object),
        'step_families': np.asarray(step_families, dtype=object),
    }


def temporal_masks(cutoff):
    times = np.unique(cutoff)
    if len(times) < 80:
        raise ValueError(f'Only {len(times)} unique cutoff minutes; temporal benchmark refused')
    b1 = times[int(0.60 * (len(times) - 1))]
    b2 = times[int(0.75 * (len(times) - 1))]
    b3 = times[int(0.85 * (len(times) - 1))]
    emb = EMBARGO_MINUTES * 60
    return {
        'train': cutoff <= b1,
        'calibration': (cutoff > b1 + emb) & (cutoff <= b2),
        'policy': (cutoff > b2 + emb) & (cutoff <= b3),
        'test': cutoff > b3 + emb,
    }, {'train_end': int(b1), 'calibration_end': int(b2), 'policy_end': int(b3), 'embargo_seconds': int(emb)}


def family_presence(sequences, family):
    hist = np.asarray([family in items for items in sequences['history_families']], dtype=bool)
    steps = np.zeros((len(hist), HORIZON), dtype=bool)
    for i, row in enumerate(sequences['step_families']):
        for h, items in enumerate(row):
            steps[i, h] = family in items
    return hist, steps


def family_split(sequences, masks, family):
    hist, steps = family_presence(sequences, family)
    future_any = steps.any(axis=1)
    family_exposed = hist | future_any
    dev_free = ~family_exposed
    train = masks['train'] & dev_free
    calibration = masks['calibration'] & dev_free
    policy = masks['policy'] & dev_free
    positive = masks['test'] & ~hist & future_any
    negative = masks['test'] & sequences['clean'] & (sequences['y'] == 0)
    clean_positive = positive & sequences['clean']
    return {
        'train': train, 'calibration': calibration, 'policy': policy,
        'test_positive': positive, 'test_negative': negative,
        'test_eval': positive | negative, 'clean_positive': clean_positive,
        'future_steps': steps,
    }


def fit_state_scaler(X, future, train_idx):
    joint = np.concatenate([X[train_idx].reshape(-1, X.shape[-1]), future[train_idx].reshape(-1, future.shape[-1])], axis=0).astype(np.float64)
    joint[~np.isfinite(joint)] = np.nan
    med = np.nanmedian(joint, axis=0)
    med[~np.isfinite(med)] = 0.0
    def impute(a):
        z = np.asarray(a, dtype=np.float32).copy()
        bad = ~np.isfinite(z)
        if bad.any():
            z[bad] = med[np.where(bad)[-1]]
        return z
    train_joint = np.concatenate([impute(X[train_idx]).reshape(-1, X.shape[-1]), impute(future[train_idx]).reshape(-1, future.shape[-1])], axis=0)
    scaler = StandardScaler().fit(train_joint)
    def transform(a):
        z = impute(a)
        return scaler.transform(z.reshape(-1, z.shape[-1])).reshape(z.shape).astype(np.float32)
    return transform(X), transform(future), med


def train_world_model(X, future, train_mask, validation_mask, seed, epochs=12):
    import torch
    import torch.nn as nn
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))
    tr = np.where(train_mask)[0]; va = np.where(validation_mask)[0]
    if len(tr) < 100 or len(va) < 40:
        raise ValueError(f'World-model support insufficient train={len(tr)} validation={len(va)}')
    Xs, Fs, _ = fit_state_scaler(X, future, tr)

    class World(nn.Module):
        def __init__(self, features):
            super().__init__()
            self.rnn = nn.LSTM(features, 32, batch_first=True)
            self.head = nn.Sequential(nn.Linear(32, 64), nn.ReLU(), nn.Linear(64, HORIZON * features))
        def forward(self, x):
            _, (h, _) = self.rnn(x)
            return self.head(h[-1]).reshape(len(x), HORIZON, x.shape[-1])

    model = World(X.shape[-1]); opt = torch.optim.Adam(model.parameters(), lr=0.003); mse = nn.MSELoss()
    xtr = torch.tensor(Xs[tr]); ftr = torch.tensor(Fs[tr]); xva = torch.tensor(Xs[va]); fva = torch.tensor(Fs[va])
    rng = np.random.default_rng(seed); best = None; best_state = None; stale = 0
    for _ in range(epochs):
        model.train(); order = rng.permutation(len(tr))
        for start in range(0, len(order), 256):
            ids = order[start:start + 256]
            loss = mse(model(xtr[ids]), ftr[ids]); opt.zero_grad(); loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            val = float(mse(model(xva), fva).item())
        if best is None or val < best - 1e-7:
            best = val; best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}; stale = 0
        else:
            stale += 1
            if stale >= 5:
                break
    model.load_state_dict(best_state); model.eval()
    with torch.no_grad():
        pred = model(torch.tensor(Xs)).cpu().numpy()
    persistence = np.repeat(Xs[:, -1:, :], HORIZON, axis=1)
    val_mse = float(np.mean((pred[va] - Fs[va]) ** 2)); val_persist = float(np.mean((persistence[va] - Fs[va]) ** 2))
    return {'pred': pred, 'future': Fs, 'persistence': persistence, 'validation_mse': val_mse, 'validation_persistence_mse': val_persist, 'state_gate_passed': bool(val_mse < val_persist)}


def prepare_risk_inputs(X, train_idx):
    z = X.astype(np.float64, copy=True); z[~np.isfinite(z)] = np.nan
    flat = z[train_idx].reshape(-1, X.shape[-1])
    med = np.nanmedian(flat, axis=0); med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(z)
    if bad.any():
        z[bad] = med[np.where(bad)[-1]]
    scaler = StandardScaler().fit(z[train_idx].reshape(-1, X.shape[-1]))
    return scaler.transform(z.reshape(-1, X.shape[-1])).reshape(z.shape).astype(np.float32)


def sigmoid(x):
    x = np.asarray(x, dtype=float)
    return 1.0 / (1.0 + np.exp(-np.clip(x, -40, 40)))


def train_risk_lstm(X, y, train_mask, calibration_mask, seed, epochs=12):
    import torch
    import torch.nn as nn
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))
    tr = np.where(train_mask)[0]; ca = np.where(calibration_mask)[0]
    if len(tr) < 100 or len(ca) < 40 or len(np.unique(y[tr])) < 2 or len(np.unique(y[ca])) < 2:
        return {'status': 'insufficient_support'}
    Z = prepare_risk_inputs(X, tr)

    class Risk(nn.Module):
        def __init__(self, features):
            super().__init__(); self.rnn = nn.LSTM(features, 32, batch_first=True); self.head = nn.Linear(32, 1)
        def forward(self, x):
            _, (h, _) = self.rnn(x); return self.head(h[-1]).squeeze(-1)

    model = Risk(X.shape[-1]); pos = max(1, int((y[tr] == 1).sum())); neg = max(1, int((y[tr] == 0).sum()))
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(neg / pos))); opt = torch.optim.Adam(model.parameters(), lr=0.003)
    xtr = torch.tensor(Z[tr]); ytr = torch.tensor(y[tr].astype(np.float32)); xca = torch.tensor(Z[ca]); yca = torch.tensor(y[ca].astype(np.float32))
    rng = np.random.default_rng(seed); best = None; best_state = None; stale = 0
    for _ in range(epochs):
        model.train(); order = rng.permutation(len(tr))
        for start in range(0, len(order), 256):
            ids = order[start:start + 256]
            loss = loss_fn(model(xtr[ids]), ytr[ids]); opt.zero_grad(); loss.backward(); opt.step()
        model.eval()
        with torch.no_grad():
            val = float(loss_fn(model(xca), yca).item())
        if best is None or val < best - 1e-6:
            best = val; best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}; stale = 0
        else:
            stale += 1
            if stale >= 4:
                break
    model.load_state_dict(best_state); model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(Z)).cpu().numpy()
    # Platt calibration uses family-free calibration labels only.
    platt = LogisticRegression(C=1e6, solver='lbfgs', max_iter=300)
    platt.fit(logits[ca].reshape(-1, 1), y[ca])
    score = platt.predict_proba(logits.reshape(-1, 1))[:, 1]
    return {'status': 'ok', 'score': score, 'validation_bce': best}


def logistic_baseline(X, y, train_mask, calibration_mask, seed):
    tr = np.where(train_mask)[0]; ca = np.where(calibration_mask)[0]
    if len(tr) < 100 or len(ca) < 40 or len(np.unique(y[tr])) < 2 or len(np.unique(y[ca])) < 2:
        return {'status': 'insufficient_support'}
    flat = X.reshape(len(X), -1).astype(np.float64); flat[~np.isfinite(flat)] = np.nan
    med = np.nanmedian(flat[tr], axis=0); med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(flat)
    if bad.any(): flat[bad] = med[np.where(bad)[1]]
    scaler = StandardScaler().fit(flat[tr]); z = scaler.transform(flat)
    model = LogisticRegression(max_iter=1000, class_weight='balanced', solver='liblinear', random_state=seed)
    model.fit(z[tr], y[tr]); raw = model.decision_function(z)
    platt = LogisticRegression(C=1e6, solver='lbfgs', max_iter=300); platt.fit(raw[ca].reshape(-1, 1), y[ca])
    return {'status': 'ok', 'score': platt.predict_proba(raw.reshape(-1, 1))[:, 1]}


def robust_reference(pred):
    flat = pred.reshape(len(pred), -1)
    center = np.median(flat, axis=0)
    mad = np.median(np.abs(flat - center), axis=0) * 1.4826
    std = np.std(flat, axis=0)
    scale = np.maximum(mad, np.maximum(std * 0.1, 1e-3))
    return center, scale


def anomaly_score(pred, center, scale):
    flat = pred.reshape(len(pred), -1)
    return np.mean(((flat - center) / scale) ** 2, axis=1)


def benign_percentile(scores, benign_reference):
    ref = np.sort(np.asarray(benign_reference, dtype=float))
    return np.searchsorted(ref, np.asarray(scores, dtype=float), side='right') / max(1, len(ref))


def fpr_threshold(benign_scores, budget=POLICY_FPR_RESERVE):
    scores = np.sort(np.asarray(benign_scores, dtype=float))[::-1]
    if not len(scores): return None
    allowed = int(math.floor(budget * len(scores)))
    if allowed <= 0: return float(np.nextafter(scores[0], np.inf))
    if allowed >= len(scores): return float(scores[-1])
    return float(np.nextafter(scores[allowed], np.inf))


def metrics(y, score, threshold):
    if threshold is None or not len(y): return {'samples': int(len(y)), 'status': 'insufficient_support'}
    pred = np.asarray(score) >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {'samples': int(len(y)), 'positives': int((y == 1).sum()), 'negatives': int((y == 0).sum()), 'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp), 'fpr': float(fp / (fp + tn)) if fp + tn else None, 'recall': float(tp / (tp + fn)) if tp + fn else None, 'precision': float(tp / (tp + fp)) if tp + fp else None, 'f1': float(f1_score(y, pred, zero_division=0))}


def evaluate_score(score, split, policy_benign, label_name='score'):
    threshold = fpr_threshold(score[policy_benign])
    ids = np.where(split['test_eval'])[0]
    y = split['test_positive'][ids].astype(int)
    return {'name': label_name, 'threshold': threshold, 'test': metrics(y, score[ids], threshold)}


def run_family(sequences, masks, family, seeds, epochs, min_pos, min_neg):
    split = family_split(sequences, masks, family)
    support = {k: int(v.sum()) for k, v in split.items() if isinstance(v, np.ndarray) and v.dtype == bool and v.ndim == 1}
    if support['test_positive'] < min_pos or support['test_negative'] < min_neg or support['train'] < 100 or support['calibration'] < 40 or support['policy'] < 40:
        return {'status': 'insufficient_support', 'support': support, 'seeds': {}}
    rows = {}
    for seed in seeds:
        world = train_world_model(sequences['X'], sequences['future'], split['train'], split['calibration'], seed, epochs)
        risk = train_risk_lstm(sequences['X'], sequences['y'], split['train'], split['calibration'], seed, epochs)
        logistic = logistic_baseline(sequences['X'], sequences['y'], split['train'], split['calibration'], seed)
        cal_benign = split['calibration'] & sequences['clean'] & (sequences['y'] == 0)
        policy_benign = split['policy'] & sequences['clean'] & (sequences['y'] == 0)
        if int(cal_benign.sum()) < 40 or int(policy_benign.sum()) < 100 or risk['status'] != 'ok' or logistic['status'] != 'ok':
            rows[str(seed)] = {'status': 'insufficient_calibration', 'state': {k: world[k] for k in ('validation_mse', 'validation_persistence_mse', 'state_gate_passed')}}
            continue
        center, scale = robust_reference(world['pred'][cal_benign])
        world_raw = anomaly_score(world['pred'], center, scale)
        world_pct = benign_percentile(world_raw, world_raw[cal_benign])
        risk_pct = benign_percentile(risk['score'], risk['score'][cal_benign])
        logistic_pct = benign_percentile(logistic['score'], logistic['score'][cal_benign])
        fusion = FUSION_RISK_WEIGHT * risk_pct + FUSION_WORLD_WEIGHT * world_pct

        test_mask = split['test_eval']
        state_test_mse = float(np.mean((world['pred'][test_mask] - world['future'][test_mask]) ** 2))
        state_persist_mse = float(np.mean((world['persistence'][test_mask] - world['future'][test_mask]) ** 2))
        evaluations = {
            'temporal_risk_lstm': evaluate_score(risk_pct, split, policy_benign, 'temporal_risk_lstm'),
            'world_novelty': evaluate_score(world_pct, split, policy_benign, 'world_novelty'),
            'frozen_hybrid': evaluate_score(fusion, split, policy_benign, 'frozen_hybrid'),
            'logistic_baseline': evaluate_score(logistic_pct, split, policy_benign, 'logistic_baseline'),
        }
        clean_ids = np.where(split['clean_positive'] | split['test_negative'])[0]
        clean_y = split['clean_positive'][clean_ids].astype(int)
        fusion_threshold = evaluations['frozen_hybrid']['threshold']
        clean_metrics = metrics(clean_y, fusion[clean_ids], fusion_threshold)
        first_horizon = np.full(len(sequences['X']), -1, dtype=int)
        for i, steps in enumerate(split['future_steps']):
            hits = np.where(steps)[0]
            if len(hits): first_horizon[i] = int(hits[0] + 1)
        horizon = []
        for h in range(1, HORIZON + 1):
            pos = split['test_positive'] & (first_horizon == h)
            ids = np.where(pos | split['test_negative'])[0]
            horizon.append({'first_seen_minutes': h, 'positive_support': int(pos.sum()), 'test': metrics(pos[ids].astype(int), fusion[ids], fusion_threshold)})
        rows[str(seed)] = {
            'status': 'evaluated',
            'state': {'validation_mse': world['validation_mse'], 'validation_persistence_mse': world['validation_persistence_mse'], 'state_gate_passed': world['state_gate_passed'], 'test_mse': state_test_mse, 'test_persistence_mse': state_persist_mse},
            'evaluations': evaluations,
            'clean_history_hybrid': clean_metrics,
            'horizon_hybrid': horizon,
        }
    return {'status': 'evaluated', 'support': support, 'seeds': rows}


def compact(result):
    if result.get('status') != 'evaluated': return {'status': result.get('status'), 'support': result.get('support')}
    rows = [r for r in result['seeds'].values() if r.get('status') == 'evaluated']
    out = {'evaluated_seeds': len(rows)}
    for model in ('temporal_risk_lstm', 'world_novelty', 'frozen_hybrid', 'logistic_baseline'):
        for metric in ('recall', 'fpr'):
            vals = [r['evaluations'][model]['test'].get(metric) for r in rows]
            vals = [float(v) for v in vals if v is not None]
            out[f'{model}_{metric}_mean'] = float(np.mean(vals)) if vals else None
            out[f'{model}_{metric}_sd'] = float(np.std(vals, ddof=1)) if len(vals) > 1 else None
    out['state_gate_passed_all_seeds'] = bool(rows and all(r['state']['state_gate_passed'] for r in rows))
    out['hybrid_release_gate_passed_all_seeds'] = bool(rows and all(
        r['state']['state_gate_passed'] and
        r['evaluations']['frozen_hybrid']['test'].get('fpr') is not None and r['evaluations']['frozen_hybrid']['test']['fpr'] <= RELEASE_FPR and
        r['evaluations']['frozen_hybrid']['test'].get('recall') is not None and r['evaluations']['frozen_hybrid']['test']['recall'] >= RELEASE_RECALL
        for r in rows
    ))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--epochs', type=int, default=12)
    p.add_argument('--max-families', type=int, default=5)
    p.add_argument('--min-test-positives', type=int, default=20)
    p.add_argument('--min-test-negatives', type=int, default=100)
    p.add_argument('--seeds', nargs='+', type=int, default=list(SEEDS))
    args = p.parse_args()
    if len(set(args.seeds)) < 3: p.error('At least three distinct seeds required')
    out = Path(args.output)
    if out.exists(): p.error('Output exists; V48 evidence is immutable')
    out.mkdir(parents=True)
    path = Path(args.csv); df = pd.read_csv(path, low_memory=False)
    schema = resolve_schema(df); dt, time_method = parse_timestamp(df[schema['timestamp']]); y, family = normalize_labels(df, schema)
    state, state_features = build_minute_state(df, dt, y, family, schema); sequences = make_sequences(state, state_features); masks, boundaries = temporal_masks(sequences['cutoff'])
    families = sorted({item for row in sequences['step_families'] for items in row for item in items})
    support_rows = []
    for fam in families:
        split = family_split(sequences, masks, fam)
        support_rows.append({'family': fam, 'test_positive': int(split['test_positive'].sum()), 'test_negative': int(split['test_negative'].sum()), 'clean_positive': int(split['clean_positive'].sum()), 'train': int(split['train'].sum()), 'calibration': int(split['calibration'].sum()), 'policy': int(split['policy'].sum())})
    eligible = [r for r in support_rows if r['test_positive'] >= args.min_test_positives and r['test_negative'] >= args.min_test_negatives and r['train'] >= 100 and r['calibration'] >= 40 and r['policy'] >= 40]
    eligible.sort(key=lambda r: (-r['test_positive'], r['family']))
    selected = [r['family'] for r in eligible[:args.max_families]]
    report = {
        'protocol': 'V48 fresh ToN-IoT family-disjoint temporal transfer',
        'claim_boundary': 'Fresh public-dataset unseen-family benchmark. Not proof of a real undisclosed zero-day or verified compromise lead time.',
        'source': {'filename': path.name, 'bytes': int(path.stat().st_size), 'sha256': sha256(path), 'rows': int(len(df)), 'columns': int(len(df.columns))},
        'schema': schema, 'timestamp_method': time_method, 'history_minutes': HISTORY, 'horizon_minutes': HORIZON,
        'policy_fpr_reserve': POLICY_FPR_RESERVE, 'release_fpr': RELEASE_FPR, 'release_recall': RELEASE_RECALL,
        'frozen_fusion': {'temporal_risk_weight': FUSION_RISK_WEIGHT, 'world_novelty_weight': FUSION_WORLD_WEIGHT, 'rationale': 'Frozen before ToN-IoT result using V47 development finding: discriminative transfer had higher unseen-family recall while world novelty reduced false alerts.'},
        'seeds': list(args.seeds), 'time_boundaries': boundaries, 'state_rows': int(len(state)), 'sequence_rows': int(len(sequences['X'])),
        'family_support': support_rows, 'family_selection': {'method': 'largest supported final-tail families by positive count only, never by model performance', 'selected': selected},
        'families': {}, 'automatic_containment_approved': False,
    }
    for fam in selected:
        print(f'V48 ToN-IoT heldout={fam}', flush=True)
        result = run_family(sequences, masks, fam, tuple(args.seeds), args.epochs, args.min_test_positives, args.min_test_negatives)
        result['summary'] = compact(result); report['families'][fam] = result
        (out / f'{norm(fam)}.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    report['all_selected_hybrid_release_gates_passed'] = bool(selected and all(v['summary'].get('hybrid_release_gate_passed_all_seeds') for v in report['families'].values()))
    report['any_clean_history_positive_support'] = bool(any(r['clean_positive'] > 0 for r in support_rows if r['family'] in selected))
    (out / 'summary.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'selected': selected, 'summaries': {k: v['summary'] for k, v in report['families'].items()}, 'any_clean_history_positive_support': report['any_clean_history_positive_support']}, indent=2), flush=True)


if __name__ == '__main__':
    main()
