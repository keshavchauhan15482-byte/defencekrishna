import os, json, math, random, hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score, brier_score_loss

SEEDS = [42, 43, 44]
HISTORY = 8
HORIZON = 4
MIN_RECALL = 0.80
MAX_TRAIN = 80000
OUT = Path('artifacts/v15')
OUT.mkdir(parents=True, exist_ok=True)


def norm(s):
    return ''.join(ch.lower() for ch in str(s) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def pick_col(cols, names):
    m = {norm(c): c for c in cols}
    for n in names:
        if norm(n) in m:
            return m[norm(n)]
    return None


def parse_time(df):
    date_col = pick_col(df.columns, ['Date'])
    ts_col = pick_col(df.columns, ['Timestamp', 'Ts', 'Time'])
    if ts_col is None:
        raise RuntimeError('No timestamp column; temporal experiment refused')
    attempts = []
    if date_col and date_col != ts_col:
        s = df[date_col].astype(str).str.strip() + ' ' + df[ts_col].astype(str).str.strip()
        attempts.append(('date+timestamp', s))
    attempts.append(('timestamp', df[ts_col]))
    for name, s in attempts:
        dt = pd.to_datetime(s.astype(str), errors='coerce', utc=True)
        frac = float(dt.notna().mean())
        if frac >= 0.80:
            return dt, date_col, ts_col, name, frac
        num = pd.to_numeric(s, errors='coerce')
        if float(num.notna().mean()) >= 0.80:
            med = float(num.dropna().median())
            unit = 'ms' if med > 1e11 else 's'
            dt = pd.to_datetime(num, unit=unit, errors='coerce', utc=True)
            frac = float(dt.notna().mean())
            if frac >= 0.80:
                return dt, date_col, ts_col, name + ':' + unit, frac
    raise RuntimeError('Timestamp parsing below 80%; temporal experiment refused')


def detect_label(df):
    candidates = [c for c in df.columns if any(k in norm(c) for k in ['class', 'label'])]
    reports = []
    for c in candidates:
        vals = df[c].dropna().astype(str).str.strip()
        vc = vals.value_counts().head(30)
        low = {str(v).lower() for v in vc.index}
        reports.append({'column': c, 'unique_top30': len(low), 'top_values': list(map(str, vc.index[:10]))})
        if any(v in low for v in ['normal', 'benign']) and len(low) <= 5:
            y = ~vals.str.lower().isin(['normal', 'benign'])
            out = pd.Series(np.nan, index=df.index, dtype='float64')
            out.loc[vals.index] = y.astype(float)
            return out, c, reports
    for c in candidates:
        x = pd.to_numeric(df[c], errors='coerce')
        u = set(x.dropna().unique().tolist())
        if u and u.issubset({0, 1, 0.0, 1.0}):
            return x.astype(float), c, reports
    raise RuntimeError(f'No trustworthy binary label found. Candidates={reports}')


STRICT_NETWORK_ONLY = True
NETWORK_WORDS = ('flow','packet','byte','length','protocol','tcp','udp','icmp','port','flag',
                 'syn','ack','rst','fin','psh','urg','ttl','window','payload','iat','interarrival',
                 'duration','rate','fwd','bwd','forward','backward','header','segment','subflow',
                 'connection','count','size','active','bulk','downup','initwin','idle')
NON_NETWORK_WORDS = ('process','pid','thread','cpu','memory','disk','system','kernel','user',
                     'command','temperature','voltage','current','power','sensor','os','device',
                     'service','uptime','loadavg','filesystem','handle')


def choose_numeric_features(df, excluded):
    """Select only observable network/packet telemetry; fail closed on system fields."""
    leak_words = ['label', 'class', 'attack', 'alert', 'rule', 'ossec', 'anomaly', 'uid',
                  'date', 'timestamp', 'time', 'srcip', 'scri', 'desip', 'dstip', 'sourceip', 'destinationip']
    sample = df.head(min(len(df), 60000))
    scored = []
    for c in df.columns:
        nc = norm(c)
        if c in excluded or any(w in nc for w in leak_words):
            continue
        if STRICT_NETWORK_ONLY and (any(w in nc for w in NON_NETWORK_WORDS) or not any(w in nc for w in NETWORK_WORDS)):
            continue
        sx = sample[c].replace(['-', '?', 'None', 'none', 'null', ''], np.nan)
        x = pd.to_numeric(sx, errors='coerce')
        coverage = float(x.notna().mean())
        if coverage < 0.85 or x.nunique(dropna=True) <= 1:
            continue
        var = float(np.nanvar(x.to_numpy(dtype=float)))
        scored.append((coverage, math.log1p(var) if np.isfinite(var) and var >= 0 else -1, c))
    scored.sort(reverse=True)
    selected = [c for _, _, c in scored[:24]]
    if STRICT_NETWORK_ONLY and len(selected) < 4:
        raise RuntimeError('Strict network-only feature audit found fewer than four usable flow/packet columns; refusing non-network fallback')
    return selected

def build_minute_state(df, dt, y, label_col, date_col, ts_col):
    src_col = pick_col(df.columns, ['Scr_IP', 'Src_IP', 'Source_IP', 'source_ip'])
    dst_col = pick_col(df.columns, ['Des_IP', 'Dst_IP', 'Destination_IP', 'dst_ip'])
    excluded = {x for x in [label_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if any(k in norm(c) for k in ['class', 'label']))
    feature_cols = choose_numeric_features(df, excluded)
    if len(feature_cols) < 4:
        raise RuntimeError(f'Only {len(feature_cols)} non-leaking numeric features; fit refused')

    base = pd.DataFrame({'dt': dt, 'y': y})
    base['src'] = df[src_col].astype(str) if src_col else 'GLOBAL'
    if dst_col:
        base['dst'] = df[dst_col].astype(str)
    for c in feature_cols:
        base[c] = pd.to_numeric(df[c].replace(['-', '?', 'None', 'none', 'null', ''], np.nan), errors='coerce')
    base = base.dropna(subset=['dt', 'y']).copy()
    base['minute'] = base['dt'].dt.floor('min')
    base['y'] = base['y'].astype(int)

    # Do NOT globally impute telemetry here: aggregation ignores NaN, and later imputation is fit on train only.
    g = base.groupby(['src', 'minute'], sort=True)
    state = g[feature_cols].agg(['mean', 'std', 'max'])
    state.columns = ['__'.join(x) for x in state.columns]
    state['flow_count'] = g.size().astype(float)
    state['attack_now'] = g['y'].max().astype(int)
    if dst_col:
        state['unique_dst'] = g['dst'].nunique().astype(float)
    state = state.reset_index().sort_values(['src', 'minute'])
    fcols = [c for c in state.columns if c not in ['src', 'minute', 'attack_now']]
    return state, fcols, feature_cols, src_col, dst_col


def make_sequences(state, fcols):
    X, Y, cutoff, clean = [], [], [], []
    for src, g in state.groupby('src', sort=False):
        g = g.sort_values('minute').reset_index(drop=True)
        t = g['minute'].astype('int64').to_numpy() // 10**9
        a = g['attack_now'].to_numpy(dtype=int)
        z = g[fcols].to_numpy(dtype=np.float32)
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            span = t[lo:i + HORIZON + 1]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            X.append(z[lo:i + 1])
            Y.append(int(a[i + 1:i + HORIZON + 1].max()))
            cutoff.append(int(t[i]))
            clean.append(bool(a[lo:i + 1].max() == 0))
    if not X:
        raise RuntimeError('No contiguous histories with complete future horizon')
    return np.stack(X), np.asarray(Y, int), np.asarray(cutoff, np.int64), np.asarray(clean, bool)


def time_split(cutoff, y):
    # Boundaries are actual cutoff timestamps. Each later partition gets a 12-minute embargo.
    unique_t = np.unique(cutoff)
    if len(unique_t) < 40:
        raise RuntimeError(f'Only {len(unique_t)} unique cutoff minutes; insufficient temporal split')
    b1 = unique_t[int(0.60 * (len(unique_t)-1))]
    b2 = unique_t[int(0.75 * (len(unique_t)-1))]
    b3 = unique_t[int(0.85 * (len(unique_t)-1))]
    emb = (HISTORY + HORIZON) * 60
    out = {
        'train': np.where(cutoff <= b1)[0],
        'calibration': np.where((cutoff > b1 + emb) & (cutoff <= b2))[0],
        'policy': np.where((cutoff > b2 + emb) & (cutoff <= b3))[0],
        'test': np.where(cutoff > b3 + emb)[0],
    }
    for name, idx in out.items():
        c = np.bincount(y[idx], minlength=2) if len(idx) else np.array([0,0])
        if c.min() < 10:
            raise RuntimeError(f'{name} class support insufficient: benign={c[0]}, attack={c[1]}')
    return out, {'b1': int(b1), 'b2': int(b2), 'b3': int(b3), 'embargo_seconds': int(emb)}


def sample_train(idx, y, seed):
    if len(idx) <= MAX_TRAIN:
        return idx
    rng = np.random.default_rng(seed)
    pos, neg = idx[y[idx] == 1], idx[y[idx] == 0]
    half = MAX_TRAIN // 2
    npick, nnick = min(len(pos), half), min(len(neg), half)
    selected = [rng.choice(pos, npick, replace=False), rng.choice(neg, nnick, replace=False)]
    used = np.concatenate(selected)
    remaining_n = MAX_TRAIN - len(used)
    if remaining_n > 0:
        rest = np.setdiff1d(idx, used, assume_unique=False)
        if len(rest): selected.append(rng.choice(rest, min(remaining_n, len(rest)), replace=False))
    out = np.concatenate(selected)
    rng.shuffle(out)
    return out


def fit_train_imputer(X, train_idx):
    flat = X[train_idx].reshape(-1, X.shape[-1]).astype(np.float64)
    flat[~np.isfinite(flat)] = np.nan
    med = np.nanmedian(flat, axis=0)
    med[~np.isfinite(med)] = 0.0
    return med.astype(np.float32)


def impute(X, med):
    z = X.astype(np.float32, copy=True)
    bad = ~np.isfinite(z)
    if bad.any():
        cols = np.where(bad)[2]
        z[bad] = med[cols]
    return z


def platt_fit(raw, y):
    m = LogisticRegression(C=1e6, solver='lbfgs', max_iter=300)
    m.fit(np.asarray(raw).reshape(-1,1), y)
    return m


def platt_apply(m, raw):
    return m.predict_proba(np.asarray(raw).reshape(-1,1))[:,1]


def choose_threshold(y, p):
    best = None
    grid = np.unique(np.concatenate([np.linspace(.005, .995, 199), p]))
    for th in grid:
        pred = p >= th
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel()
        rec = tp/(tp+fn) if tp+fn else 0.0
        fpr = fp/(fp+tn) if fp+tn else 1.0
        prec = tp/(tp+fp) if tp+fp else 0.0
        if rec >= MIN_RECALL:
            cand = (fpr, -rec, -prec, float(th))
            if best is None or cand < best: best = cand
    return None if best is None else best[3]


def calc_metrics(y, p, th, clean=None):
    pred = p >= th
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel()
    d = {
        'n': int(len(y)), 'benign': int((y==0).sum()), 'attack': int((y==1).sum()),
        'threshold': float(th), 'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
        'fpr': float(fp/(fp+tn)) if fp+tn else None,
        'recall': float(tp/(tp+fn)) if tp+fn else None,
        'precision': float(tp/(tp+fp)) if tp+fp else None,
        'f1': float(f1_score(y, pred, zero_division=0)),
        'pr_auc': float(average_precision_score(y,p)),
        'brier': float(brier_score_loss(y,p)),
    }
    if clean is not None:
        mask = clean & (y == 1)
        d['clean_history_future_positive_n'] = int(mask.sum())
        d['clean_history_future_positive_recall'] = float(pred[mask].mean()) if mask.any() else None
    return d


def prepare_scaled(X, split, seed):
    tr = sample_train(split['train'], np.zeros(len(X), dtype=int), seed)  # overridden by callers when sampling labels
    raise AssertionError('not used')


def logistic_run(X, y, clean, split, seed):
    tr = sample_train(split['train'], y, seed)
    med = fit_train_imputer(X, tr)
    Z = impute(X, med)
    flat = Z.reshape(len(Z), -1)
    scaler = StandardScaler().fit(flat[tr])
    xtr = scaler.transform(flat[tr])
    base = LogisticRegression(max_iter=500, class_weight='balanced', solver='liblinear', random_state=seed)
    base.fit(xtr, y[tr])
    p0 = base.predict_proba(xtr)[:,1]
    hard = (y[tr] == 0) & (p0 >= .50)
    weights = np.ones(len(tr), dtype=float); weights[hard] = 3.0
    model = LogisticRegression(max_iter=500, class_weight='balanced', solver='liblinear', random_state=seed)
    model.fit(xtr, y[tr], sample_weight=weights)
    ca, po, te = split['calibration'], split['policy'], split['test']
    cal = platt_fit(model.decision_function(scaler.transform(flat[ca])), y[ca])
    ppol = platt_apply(cal, model.decision_function(scaler.transform(flat[po])))
    th = choose_threshold(y[po], ppol)
    actionable = th is not None
    if th is None: th = .5
    ptest = platt_apply(cal, model.decision_function(scaler.transform(flat[te])))
    return calc_metrics(y[te], ptest, th, clean[te]), actionable, int(hard.sum()), int((~np.isfinite(X[tr])).sum())


def lstm_run(X, y, clean, split, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))
    tr = sample_train(split['train'], y, seed)
    med = fit_train_imputer(X, tr)
    Z = impute(X, med)
    scaler = StandardScaler().fit(Z[tr].reshape(-1, Z.shape[-1]))
    def scaled(idx):
        a = scaler.transform(Z[idx].reshape(-1, Z.shape[-1]))
        return a.reshape(len(idx), Z.shape[1], Z.shape[2]).astype(np.float32)
    xtr, ytr = scaled(tr), y[tr].astype(np.float32)
    class Net(nn.Module):
        def __init__(self, f):
            super().__init__(); self.rnn = nn.LSTM(f, 32, batch_first=True); self.head = nn.Sequential(nn.Linear(32,16), nn.ReLU(), nn.Linear(16,1))
        def forward(self, x):
            o,_ = self.rnn(x); return self.head(o[:,-1]).squeeze(1)
    net = Net(Z.shape[-1])
    pos, neg = max(1,int((ytr==1).sum())), max(1,int((ytr==0).sum()))
    lossfn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg/pos], dtype=torch.float32))
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    dl = DataLoader(TensorDataset(torch.from_numpy(xtr), torch.from_numpy(ytr)), batch_size=256, shuffle=True)
    for _ in range(12):
        net.train()
        for xb,yb in dl:
            opt.zero_grad(set_to_none=True); loss = lossfn(net(xb), yb); loss.backward(); opt.step()
    def logits(idx):
        net.eval(); z = scaled(idx); out=[]
        with torch.no_grad():
            for i in range(0,len(z),1024): out.append(net(torch.from_numpy(z[i:i+1024])).cpu().numpy())
        return np.concatenate(out)
    ca, po, te = split['calibration'], split['policy'], split['test']
    cal = platt_fit(logits(ca), y[ca])
    ppol = platt_apply(cal, logits(po))
    th = choose_threshold(y[po], ppol)
    actionable = th is not None
    if th is None: th = .5
    ptest = platt_apply(cal, logits(te))
    return calc_metrics(y[te], ptest, th, clean[te]), actionable, int((~np.isfinite(X[tr])).sum())


def main():
    import kagglehub
    handle = 'munaalhawawreh/xiiotid-iiot-intrusion-dataset'
    root = Path(kagglehub.dataset_download(handle))
    csvs = list(root.rglob('*.csv'))
    if not csvs: raise RuntimeError('No CSV found in downloaded X-IIoTID package')
    csv_path = max(csvs, key=lambda p: p.stat().st_size)
    prov = {
        'dataset': 'X-IIoTID',
        'official_repo': 'https://github.com/Alhawawreh/X-IIoTID',
        'author_download_pointer': 'https://cloudstor.aarnet.edu.au/plus/s/uCa6M7IDI1S8VrE',
        'transport_mirror': 'https://www.kaggle.com/datasets/munaalhawawreh/xiiotid-iiot-intrusion-dataset',
        'filename': csv_path.name, 'bytes': int(csv_path.stat().st_size), 'sha256': sha256(csv_path)
    }
    print('DATASET', json.dumps(prov, indent=2), flush=True)
    df = pd.read_csv(csv_path, low_memory=False)
    prov.update({'rows': int(len(df)), 'columns': int(len(df.columns))})
    dt, date_col, ts_col, time_method, parsed_fraction = parse_time(df)
    y, label_col, label_reports = detect_label(df)
    state, fcols, raw_features, src_col, dst_col = build_minute_state(df, dt, y, label_col, date_col, ts_col)
    X, target, cutoff, clean = make_sequences(state, fcols)
    split, boundaries = time_split(cutoff, target)
    report = {
        'schema': 'krishna-v15-xiiotid-temporal-pilot-v2',
        'claim_scope': 'Fresh chronological X-IIoTID future-malicious-traffic pilot. This is not verified compromise forecasting, campaign-independent validation, MITRE stage validation, or production approval.',
        'provenance': prov,
        'detected': {'date_col': date_col, 'timestamp_col': ts_col, 'time_parse_method': time_method, 'time_parse_fraction': parsed_fraction, 'label_col': label_col, 'source_ip_col': src_col, 'destination_ip_col': dst_col, 'raw_numeric_features': raw_features, 'state_feature_count': len(fcols), 'label_candidates': label_reports},
        'sequence': {'history_minutes': HISTORY, 'future_horizon_minutes': HORIZON, 'n': int(len(X)), 'benign_targets': int((target==0).sum()), 'attack_targets': int((target==1).sum()), 'clean_history_n': int(clean.sum()), 'derived_nonfinite_cells_before_train_imputation': int((~np.isfinite(X)).sum())},
        'split_boundaries': boundaries,
        'splits': {k: {'n': int(len(v)), 'benign': int((target[v]==0).sum()), 'attack': int((target[v]==1).sum()), 'first_cutoff_epoch': int(cutoff[v].min()), 'last_cutoff_epoch': int(cutoff[v].max())} for k,v in split.items()},
        'seeds': {}
    }
    for seed in SEEDS:
        print('SEED', seed, 'LOGISTIC', flush=True)
        lm, la, hard, lbad = logistic_run(X,target,clean,split,seed)
        print('SEED', seed, 'LSTM', flush=True)
        tm, ta, tbad = lstm_run(X,target,clean,split,seed)
        report['seeds'][str(seed)] = {'history_logistic': lm, 'history_logistic_actionable': la, 'training_hard_negatives_upweighted': hard, 'logistic_train_nonfinite_imputed': lbad, 'lstm': tm, 'lstm_actionable': ta, 'lstm_train_nonfinite_imputed': tbad}
        print(json.dumps(report['seeds'][str(seed)], indent=2), flush=True)
    def mean(model,key):
        vals=[report['seeds'][str(s)][model][key] for s in SEEDS if report['seeds'][str(s)][model][key] is not None]
        return float(np.mean(vals)) if vals else None
    report['three_seed_mean']={m:{k:mean(m,k) for k in ['fpr','recall','precision','f1','pr_auc','brier','clean_history_future_positive_recall']} for m in ['history_logistic','lstm']}
    report['release_gate']={
        'engineering_target':'mean FPR <= 0.06 and mean recall >= 0.80, with a valid policy threshold in every seed',
        'history_logistic_pass': bool(report['three_seed_mean']['history_logistic']['fpr'] <= .06 and report['three_seed_mean']['history_logistic']['recall'] >= .80 and all(report['seeds'][str(s)]['history_logistic_actionable'] for s in SEEDS)),
        'lstm_pass': bool(report['three_seed_mean']['lstm']['fpr'] <= .06 and report['three_seed_mean']['lstm']['recall'] >= .80 and all(report['seeds'][str(s)]['lstm_actionable'] for s in SEEDS)),
        'evidence_limit':'Even a pass here is only a temporal X-IIoTID malicious-traffic result; it does not prove pre-compromise success.'
    }
    (OUT/'results.json').write_text(json.dumps(report,indent=2))
    lines=['# Krishna Defence V15 — X-IIoTID temporal pilot v2','',report['claim_scope'],'','## Three-seed mean','','| Model | FPR | Recall | Precision | F1 | PR-AUC | Brier | Clean-history future-positive recall |','|---|---:|---:|---:|---:|---:|---:|---:|']
    for m in ['history_logistic','lstm']:
        x=report['three_seed_mean'][m]
        def fmt(v): return 'n/a' if v is None else f'{v:.4f}'
        lines.append(f"| {m} | {fmt(x['fpr'])} | {fmt(x['recall'])} | {fmt(x['precision'])} | {fmt(x['f1'])} | {fmt(x['pr_auc'])} | {fmt(x['brier'])} | {fmt(x['clean_history_future_positive_recall'])} |")
    lines += ['','## Release gate','', '```json', json.dumps(report['release_gate'],indent=2), '```','','## Provenance','', '```json', json.dumps(prov,indent=2), '```']
    (OUT/'REPORT.md').write_text('\n'.join(lines))
    print('FINAL_MEAN',json.dumps(report['three_seed_mean'],indent=2),flush=True)
    print('GATE',json.dumps(report['release_gate'],indent=2),flush=True)

if __name__ == '__main__': main()
