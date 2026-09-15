from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score
from sklearn.preprocessing import StandardScaler

SEEDS = [42, 43, 44]
HISTORY = 8
HORIZON = 4
MAX_TRAIN = 60000
MAX_FAMILIES = 5
MAX_POLICY_FPR = 0.01
OUT = Path("artifacts/v16")
OUT.mkdir(parents=True, exist_ok=True)

BENIGN_ALIASES = {"normal", "benign", "0", "none", "background"}
NETWORK_ALLOW = (
    "port", "protocol", "service", "duration", "byte", "bytes", "pkt", "pkts",
    "packet", "connstate", "connectionstate", "syn", "ack", "fin", "rst",
    "payload", "checksum", "rate", "ratio", "missedbytes"
)
NETWORK_BLOCK = (
    "label", "class", "attack", "alert", "rule", "ossec", "zeek", "uid",
    "date", "timestamp", "time", "srcip", "scri", "desip", "dstip",
    "sourceip", "destinationip", "process", "file", "cpu", "memory", "mem",
    "disk", "login", "privilege", "activity", "resource", "iowait", "idle",
    "usertime", "systemtime", "nicetime", "tps", "rtps", "wtps", "load"
)


def norm(s):
    return "".join(ch.lower() for ch in str(s) if ch.isalnum())


def norm_label(v):
    s = str(v).strip().lower()
    return "normal" if s in BENIGN_ALIASES else s


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def pick_col(cols, names):
    m = {norm(c): c for c in cols}
    for n in names:
        if norm(n) in m:
            return m[norm(n)]
    return None


def numericize(s):
    x = s.replace({
        "-": np.nan, "?": np.nan, "None": np.nan, "none": np.nan, "null": np.nan, "": np.nan,
        True: 1, False: 0, "True": 1, "False": 0, "true": 1, "false": 0,
    })
    return pd.to_numeric(x, errors="coerce")


def parse_time(df):
    date_col = pick_col(df.columns, ["Date"])
    ts_col = pick_col(df.columns, ["Timestamp", "Ts", "Time"])
    if ts_col is None:
        raise RuntimeError("No timestamp column; temporal experiment refused")
    attempts = []
    if date_col and date_col != ts_col:
        attempts.append(("date+timestamp", df[date_col].astype(str).str.strip() + " " + df[ts_col].astype(str).str.strip()))
    attempts.append(("timestamp", df[ts_col]))
    for name, s in attempts:
        dt = pd.to_datetime(s.astype(str), errors="coerce", utc=True)
        frac = float(dt.notna().mean())
        if frac >= 0.80:
            return dt, date_col, ts_col, name, frac
        num = pd.to_numeric(s, errors="coerce")
        if float(num.notna().mean()) >= 0.80:
            med = float(num.dropna().median())
            unit = "ms" if med > 1e11 else "s"
            dt = pd.to_datetime(num, unit=unit, errors="coerce", utc=True)
            frac = float(dt.notna().mean())
            if frac >= 0.80:
                return dt, date_col, ts_col, name + ":" + unit, frac
    raise RuntimeError("Timestamp parsing below 80%; temporal experiment refused")


def detect_binary_label(df):
    preferred = [c for c in df.columns if norm(c) == "class1"]
    candidates = preferred + [c for c in df.columns if c not in preferred and any(k in norm(c) for k in ["class", "label"])]
    reports = []
    for c in candidates:
        vals = df[c].dropna().astype(str).str.strip()
        low = {v.lower() for v in vals.value_counts().head(30).index.astype(str)}
        reports.append({"column": c, "top_values": sorted(list(low))[:12]})
        if any(v in low for v in ("normal", "benign")) and len(low) <= 5:
            out = pd.Series(np.nan, index=df.index, dtype="float64")
            out.loc[vals.index] = (~vals.str.lower().isin(["normal", "benign"])).astype(float)
            return out, c, reports
    raise RuntimeError(f"No trustworthy binary label found. Candidates={reports}")


def detect_family_col(df, binary_col):
    c3 = pick_col(df.columns, ["class3"])
    if c3 and c3 != binary_col:
        return c3
    scored = []
    for c in df.columns:
        if c == binary_col:
            continue
        nc = norm(c)
        if not any(k in nc for k in ["class", "label", "attack", "type", "category"]):
            continue
        vals = df[c].dropna().astype(str).map(norm_label)
        u = vals.nunique()
        if 3 <= u <= 80 and (vals == "normal").any():
            scored.append((u, c))
    if not scored:
        raise RuntimeError("No multi-class attack-family column found")
    scored.sort(reverse=True)
    return scored[0][1]


def strict_network_features(df, excluded):
    sample = df.head(min(len(df), 80000))
    out, audit = [], []
    for c in df.columns:
        nc = norm(c)
        if c in excluded:
            continue
        allowed = any(k in nc for k in NETWORK_ALLOW)
        blocked = any(k in nc for k in NETWORK_BLOCK)
        if not allowed or blocked:
            continue
        x = numericize(sample[c])
        coverage = float(x.notna().mean())
        nunique = int(x.nunique(dropna=True))
        if coverage < 0.70 or nunique <= 1:
            continue
        var = float(np.nanvar(x.to_numpy(dtype=float)))
        if not np.isfinite(var):
            continue
        out.append(c)
        audit.append({"column": c, "coverage": coverage, "unique": nunique})
    if len(out) < 8:
        raise RuntimeError(f"Strict network-only audit left only {len(out)} usable numeric features: {out}")
    return out, audit


def epoch_seconds(series):
    origin = pd.Timestamp("1970-01-01", tz="UTC")
    return ((series - origin).dt.total_seconds().round().astype("int64")).to_numpy()


def build_minute_state(df, dt, y, family_col, binary_col, date_col, ts_col):
    src_col = pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    dst_col = pick_col(df.columns, ["Des_IP", "Dst_IP", "Destination_IP", "dst_ip"])
    dport_col = pick_col(df.columns, ["Des_port", "Dst_port", "Destination_port", "dst_port"])
    excluded = {x for x in [family_col, binary_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if norm(c) in {"class1", "class2", "class3"})
    feature_cols, feature_audit = strict_network_features(df, excluded)

    base = pd.DataFrame({
        "dt": dt,
        "y": y,
        "family": df[family_col].astype(str).map(norm_label),
        "src": df[src_col].astype(str) if src_col else "GLOBAL",
    })
    if dst_col:
        base["dst"] = df[dst_col].astype(str)
    if dport_col:
        base["dport_raw"] = df[dport_col].astype(str)
    for c in feature_cols:
        base[c] = numericize(df[c])
    base = base.dropna(subset=["dt", "y"]).copy()
    base["minute"] = base["dt"].dt.floor("min")
    base["y"] = base["y"].astype(int)

    g = base.groupby(["src", "minute"], sort=True)
    state = g[feature_cols].agg(["mean", "std", "max"])
    state.columns = ["__".join(x) for x in state.columns]
    state["flow_count"] = g.size().astype(float)
    state["attack_now"] = g["y"].max().astype(int)
    state["family_now"] = g["family"].agg(
        lambda s: tuple(sorted({norm_label(v) for v in s if norm_label(v) != "normal"}))
    )
    if dst_col:
        state["_dst_set"] = g["dst"].agg(lambda s: tuple(sorted(set(s.astype(str)))))
        state["unique_dst"] = g["dst"].nunique().astype(float)
    if dport_col:
        state["unique_dst_port"] = g["dport_raw"].nunique().astype(float)

    state = state.reset_index().sort_values(["src", "minute"]).reset_index(drop=True)
    if "_dst_set" in state.columns:
        new_ratio = np.zeros(len(state), dtype=float)
        churn = np.zeros(len(state), dtype=float)
        for _, idx in state.groupby("src", sort=False).groups.items():
            idx = list(idx)
            recent = []
            for row_idx in idx:
                cur = set(state.at[row_idx, "_dst_set"])
                prev_union = set().union(*recent) if recent else set()
                new = cur - prev_union
                new_ratio[row_idx] = len(new) / max(1, len(cur))
                union = cur | prev_union
                churn[row_idx] = 1.0 - (len(cur & prev_union) / len(union)) if union else 0.0
                recent.append(cur)
                if len(recent) > HISTORY:
                    recent.pop(0)
        state["new_dst_ratio"] = new_ratio
        state["dst_churn"] = churn
        state = state.drop(columns=["_dst_set"])

    fcols = [c for c in state.columns if c not in ["src", "minute", "attack_now", "family_now"]]
    return state, fcols, feature_cols, feature_audit, src_col, dst_col, dport_col


def make_sequences(state, fcols):
    X, target, cutoff, clean, srcs = [], [], [], [], []
    hist_fams, future_steps = [], []
    for src, g in state.groupby("src", sort=False):
        g = g.sort_values("minute").reset_index(drop=True)
        t = epoch_seconds(g["minute"])
        a = g["attack_now"].to_numpy(dtype=int)
        z = g[fcols].to_numpy(dtype=np.float32)
        fams = list(g["family_now"])
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            span = t[lo:i + HORIZON + 1]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            hsets = [set(x) for x in fams[lo:i + 1]]
            fsets = [set(x) for x in fams[i + 1:i + HORIZON + 1]]
            X.append(z[lo:i + 1])
            target.append(int(a[i + 1:i + HORIZON + 1].max()))
            cutoff.append(int(t[i]))
            clean.append(bool(a[lo:i + 1].max() == 0))
            srcs.append(str(src))
            hist_fams.append(tuple(sorted(set().union(*hsets) if hsets else set())))
            future_steps.append(tuple(tuple(sorted(s)) for s in fsets))
    if not X:
        raise RuntimeError("No contiguous histories with complete future horizon")
    return (
        np.stack(X), np.asarray(target, dtype=int), np.asarray(cutoff, dtype=np.int64),
        np.asarray(clean, dtype=bool), np.asarray(srcs, dtype=object),
        np.asarray(hist_fams, dtype=object), np.asarray(future_steps, dtype=object),
    )


def global_split(cutoff):
    u = np.unique(cutoff)
    if len(u) < 40:
        raise RuntimeError("Insufficient unique temporal cutoffs")
    b1 = u[int(0.60 * (len(u) - 1))]
    b2 = u[int(0.75 * (len(u) - 1))]
    b3 = u[int(0.85 * (len(u) - 1))]
    emb = (HISTORY + HORIZON) * 60
    return {
        "train": np.where(cutoff <= b1)[0],
        "calibration": np.where((cutoff > b1 + emb) & (cutoff <= b2))[0],
        "policy": np.where((cutoff > b2 + emb) & (cutoff <= b3))[0],
        "test": np.where(cutoff > b3 + emb)[0],
    }, {"b1": int(b1), "b2": int(b2), "b3": int(b3), "embargo_seconds": emb}


def future_has_family(future_steps, family):
    return np.asarray([any(family in set(step) for step in seq) for seq in future_steps], dtype=bool)


def history_has_family(hist_fams, family):
    return np.asarray([family in set(v) for v in hist_fams], dtype=bool)


def family_lead_offsets(future_steps, family):
    out = np.zeros(len(future_steps), dtype=int)
    for i, seq in enumerate(future_steps):
        for j, step in enumerate(seq, start=1):
            if family in set(step):
                out[i] = j
                break
    return out


def sample_train(idx, y, seed):
    if len(idx) <= MAX_TRAIN:
        return idx
    rng = np.random.default_rng(seed)
    pos, neg = idx[y[idx] == 1], idx[y[idx] == 0]
    half = MAX_TRAIN // 2
    a = rng.choice(pos, min(len(pos), half), replace=False) if len(pos) else np.array([], dtype=int)
    b = rng.choice(neg, min(len(neg), half), replace=False) if len(neg) else np.array([], dtype=int)
    used = np.concatenate([a, b])
    remain = MAX_TRAIN - len(used)
    if remain > 0:
        rest = np.setdiff1d(idx, used, assume_unique=False)
        if len(rest):
            used = np.concatenate([used, rng.choice(rest, min(remain, len(rest)), replace=False)])
    rng.shuffle(used)
    return used


def fit_imputer(X, idx):
    flat = X[idx].reshape(-1, X.shape[-1]).astype(np.float64)
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
    if len(np.unique(y)) < 2:
        raise RuntimeError("Calibration split lacks both classes")
    m = LogisticRegression(C=1e6, solver="lbfgs", max_iter=300)
    m.fit(np.asarray(raw).reshape(-1, 1), y)
    return m


def platt_apply(m, raw):
    return m.predict_proba(np.asarray(raw).reshape(-1, 1))[:, 1]


def novelty_percentile(scores, benign_reference):
    ref = np.sort(np.asarray(benign_reference, dtype=float))
    if len(ref) < 20:
        raise RuntimeError("Too few benign calibration embeddings for novelty CDF")
    return np.searchsorted(ref, scores, side="right") / len(ref)


def choose_fpr_threshold(y, p, max_fpr=MAX_POLICY_FPR):
    y = np.asarray(y, dtype=int)
    p = np.asarray(p, dtype=float)
    benign, attack = p[y == 0], p[y == 1]
    if len(benign) < 50 or len(attack) < 10:
        raise RuntimeError(f"Policy support insufficient: benign={len(benign)} attack={len(attack)}")
    grid = np.unique(np.concatenate([[float(np.quantile(benign, 1.0 - max_fpr, method="higher"))], p]))
    best = None
    for th in grid:
        pred = p >= th
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if fp + tn else 1.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        prec = tp / (tp + fp) if tp + fp else 0.0
        if fpr <= max_fpr + 1e-12:
            cand = (-rec, fpr, -prec, float(th))
            if best is None or cand < best:
                best = cand
    return best[3] if best is not None else float(np.quantile(benign, 1.0 - max_fpr, method="higher"))


def metrics(y, p, th, clean_positive=None):
    pred = np.asarray(p) >= th
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)), "benign": int((y == 0).sum()), "attack": int((y == 1).sum()),
        "threshold": float(th), "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else None,
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else None,
    }
    if clean_positive is not None:
        cp = np.asarray(clean_positive, dtype=bool)
        out["clean_history_future_positive_n"] = int(cp.sum())
        out["clean_history_future_positive_recall"] = float(pred[cp].mean()) if cp.any() else None
    return out


def run_family(X, target, clean, split, hist_fams, future_steps, family, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))

    future_hold = future_has_family(future_steps, family)
    history_hold = history_has_family(hist_fams, family)
    exposed = future_hold | history_hold
    local = {k: idx[~exposed[idx]] for k, idx in split.items() if k != "test"}
    for k in ("train", "calibration", "policy"):
        c = np.bincount(target[local[k]], minlength=2)
        if c.min() < 20:
            raise RuntimeError(f"{family}: {k} known-family support insufficient benign={c[0]} attack={c[1]}")

    tr = sample_train(local["train"], target, seed)
    med = fit_imputer(X, tr)
    Z = impute(X, med)
    scaler = StandardScaler().fit(Z[tr].reshape(-1, Z.shape[-1]))

    def scaled(idx):
        a = scaler.transform(Z[idx].reshape(-1, Z.shape[-1]))
        return a.reshape(len(idx), Z.shape[1], Z.shape[2]).astype(np.float32)

    class Net(nn.Module):
        def __init__(self, f):
            super().__init__()
            self.rnn = nn.LSTM(f, 32, batch_first=True)
            self.head = nn.Sequential(nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 1))
        def forward(self, x, return_embed=False):
            o, _ = self.rnn(x)
            emb = o[:, -1]
            logit = self.head(emb).squeeze(1)
            return (logit, emb) if return_embed else logit

    net = Net(Z.shape[-1])
    ytr = target[tr].astype(np.float32)
    pos, neg = max(1, int((ytr == 1).sum())), max(1, int((ytr == 0).sum()))
    lossfn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg / pos], dtype=torch.float32))
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    dl = DataLoader(TensorDataset(torch.from_numpy(scaled(tr)), torch.from_numpy(ytr)), batch_size=256, shuffle=True)
    for _ in range(8):
        net.train()
        for xb, yb in dl:
            opt.zero_grad(set_to_none=True)
            loss = lossfn(net(xb), yb)
            loss.backward(); opt.step()

    def infer(idx):
        net.eval(); z = scaled(idx); logits, embeds = [], []
        with torch.no_grad():
            for i in range(0, len(z), 1024):
                lg, em = net(torch.from_numpy(z[i:i+1024]), return_embed=True)
                logits.append(lg.cpu().numpy()); embeds.append(em.cpu().numpy())
        return np.concatenate(logits), np.concatenate(embeds)

    ca, po = local["calibration"], local["policy"]
    _, etr = infer(tr); lca, eca = infer(ca); lpo, epo = infer(po)
    platt = platt_fit(lca, target[ca])
    ppo = platt_apply(platt, lpo)

    benign_train = etr[target[tr] == 0]
    if len(benign_train) > 20000:
        rng = np.random.default_rng(seed)
        benign_train = benign_train[rng.choice(len(benign_train), 20000, replace=False)]
    iso = IsolationForest(n_estimators=160, max_samples=min(4096, len(benign_train)), contamination="auto", random_state=seed, n_jobs=-1)
    iso.fit(benign_train)
    benign_ref = (-iso.decision_function(eca))[target[ca] == 0]
    nov_po = novelty_percentile(-iso.decision_function(epo), benign_ref)
    dual_po = 1.0 - (1.0 - ppo) * (1.0 - np.square(nov_po))
    th_sup = choose_fpr_threshold(target[po], ppo)
    th_dual = choose_fpr_threshold(target[po], dual_po)

    te = split["test"]
    pos_mask = future_hold[te]
    neg_mask = (target[te] == 0) & clean[te]
    eval_idx = te[pos_mask | neg_mask]
    if int(pos_mask.sum()) < 10 or int(neg_mask.sum()) < 100:
        raise RuntimeError(f"{family}: chronological unseen support insufficient positives={int(pos_mask.sum())} clean_benign={int(neg_mask.sum())}")

    lte, ete = infer(eval_idx)
    psup = platt_apply(platt, lte)
    nov = novelty_percentile(-iso.decision_function(ete), benign_ref)
    pdual = 1.0 - (1.0 - psup) * (1.0 - np.square(nov))
    y_eval = future_hold[eval_idx].astype(int)
    clean_pos = y_eval.astype(bool) & clean[eval_idx]
    sup_m = metrics(y_eval, psup, th_sup, clean_pos)
    dual_m = metrics(y_eval, pdual, th_dual, clean_pos)

    offsets = family_lead_offsets(future_steps[eval_idx], family)
    pred = pdual >= th_dual
    lead = {}
    for minute in range(1, HORIZON + 1):
        m = clean_pos & (offsets == minute)
        lead[str(minute)] = {"n": int(m.sum()), "detected": int(pred[m].sum()) if m.any() else 0, "recall": float(pred[m].mean()) if m.any() else None}

    return {
        "family": family, "seed": seed,
        "train_support": {"n": int(len(tr)), "benign": int((target[tr] == 0).sum()), "known_attack": int((target[tr] == 1).sum())},
        "policy_support": {"n": int(len(po)), "benign": int((target[po] == 0).sum()), "known_attack": int((target[po] == 1).sum())},
        "test_support": {"unseen_future_positive": int(pos_mask.sum()), "clean_benign_negative": int(neg_mask.sum()), "clean_history_unseen_positive": int(clean_pos.sum())},
        "supervised_only": sup_m, "dual_head": dual_m, "lead_time_minutes": lead,
        "heldout_exposure_in_train_cal_policy": 0, "policy_max_fpr": MAX_POLICY_FPR,
    }


def main():
    import kagglehub
    handle = "munaalhawawreh/xiiotid-iiot-intrusion-dataset"
    root = Path(kagglehub.dataset_download(handle))
    csvs = list(root.rglob("*.csv"))
    if not csvs:
        raise RuntimeError("No CSV found in downloaded X-IIoTID package")
    csv_path = max(csvs, key=lambda p: p.stat().st_size)
    prov = {
        "dataset": "X-IIoTID", "official_repo": "https://github.com/Alhawawreh/X-IIoTID",
        "transport_mirror": "https://www.kaggle.com/datasets/munaalhawawreh/xiiotid-iiot-intrusion-dataset",
        "filename": csv_path.name, "bytes": int(csv_path.stat().st_size), "sha256": sha256(csv_path),
    }
    print("DATASET", json.dumps(prov, indent=2), flush=True)
    df = pd.read_csv(csv_path, low_memory=False)
    prov.update({"rows": int(len(df)), "columns": int(len(df.columns))})
    dt, date_col, ts_col, time_method, parsed_fraction = parse_time(df)
    y, binary_col, label_reports = detect_binary_label(df)
    family_col = detect_family_col(df, binary_col)
    state, fcols, raw_features, feature_audit, src_col, dst_col, dport_col = build_minute_state(df, dt, y, family_col, binary_col, date_col, ts_col)
    X, target, cutoff, clean, srcs, hist_fams, future_steps = make_sequences(state, fcols)
    split, boundaries = global_split(cutoff)

    te = split["test"]
    families = sorted({fam for seq in future_steps[te] for step in seq for fam in step if fam != "normal"})
    support = []
    for fam in families:
        f = future_has_family(future_steps[te], fam)
        support.append((int(f.sum()), int((f & clean[te]).sum()), fam))
    support.sort(reverse=True)
    selected = [fam for n, clean_n, fam in support if n >= 10][:MAX_FAMILIES]
    if len(selected) < 3:
        raise RuntimeError(f"Fewer than 3 held-out families have >=10 chronological test positives: {support[:20]}")

    report = {
        "schema": "krishna-v16-xiiotid-unseen-forecast-v1",
        "claim_scope": "Leave-one-attack-family-out future-risk experiment. Each held-out class3 attack family is absent from training/calibration/policy sequences. Garuda forecasts next-4-minute unseen-family risk from the prior 8 minutes of strict network-only telemetry. This is zero-day-like generalization evidence, not proof against arbitrary real-world zero-days or verified compromise.",
        "provenance": prov,
        "detected": {
            "binary_label_col": binary_col, "family_col": family_col, "timestamp_col": ts_col,
            "time_parse_method": time_method, "time_parse_fraction": parsed_fraction,
            "source_ip_col": src_col, "destination_ip_col": dst_col, "destination_port_col": dport_col,
            "strict_network_raw_features": raw_features, "network_feature_audit": feature_audit,
            "state_feature_count": len(fcols), "label_candidates": label_reports,
        },
        "protocol": {
            "history_minutes": HISTORY, "future_horizon_minutes": HORIZON,
            "family_holdout": "class3 fine-grained attack type", "heldout_family_seen_in_train_cal_policy": False,
            "network_only_feature_audit_passed": True, "policy_threshold_source": "non-heldout policy partition only",
            "policy_max_fpr": MAX_POLICY_FPR, "chronological_boundaries": boundaries,
            "selected_family_support_before_modeling": support[:20],
        },
        "sequence": {"n": int(len(X)), "benign_future": int((target == 0).sum()), "attack_future": int((target == 1).sum()), "clean_history": int(clean.sum())},
        "heldout_families": selected, "results": {},
    }

    for fam in selected:
        report["results"][fam] = {}
        for seed in SEEDS:
            print(f"RUN family={fam} seed={seed}", flush=True)
            r = run_family(X, target, clean, split, hist_fams, future_steps, fam, seed)
            report["results"][fam][str(seed)] = r
            print(json.dumps(r, indent=2), flush=True)

    def macro(model, key):
        vals = []
        for fam in selected:
            vals.append(float(np.mean([report["results"][fam][str(s)][model][key] for s in SEEDS])))
        return float(np.mean(vals))

    clean_ns, clean_hits = [], []
    for fam in selected:
        for s in SEEDS:
            m = report["results"][fam][str(s)]["dual_head"]
            n = int(m["clean_history_future_positive_n"]); rec = m["clean_history_future_positive_recall"]
            clean_ns.append(n); clean_hits.append(0 if rec is None else n * rec)

    report["macro_mean"] = {
        "supervised_only": {k: macro("supervised_only", k) for k in ["fpr", "recall", "precision", "f1"]},
        "dual_head": {k: macro("dual_head", k) for k in ["fpr", "recall", "precision", "f1"]},
        "dual_head_clean_history_positive_total_across_family_seed_runs": int(sum(clean_ns)),
        "dual_head_clean_history_positive_weighted_recall": float(sum(clean_hits) / sum(clean_ns)) if sum(clean_ns) else None,
    }
    dual = report["macro_mean"]["dual_head"]
    report["release_gate"] = {
        "engineering_target": "At least 3 truly held-out attack families; macro observed FPR <= 0.02, macro unseen-family recall >= 0.80, and nonzero clean-history unseen future-positive support. Thresholds are selected without held-out examples.",
        "family_count": len(selected), "macro_fpr_pass": bool(dual["fpr"] <= 0.02),
        "macro_unseen_recall_pass": bool(dual["recall"] >= 0.80), "clean_history_support_pass": bool(sum(clean_ns) > 0),
        "pass": bool(len(selected) >= 3 and dual["fpr"] <= 0.02 and dual["recall"] >= 0.80 and sum(clean_ns) > 0),
        "evidence_limit": "A pass is evidence of zero-day-like family generalization on X-IIoTID network-only telemetry, not a guarantee for arbitrary unseen attacks or a production containment approval.",
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2))
    lines = ["# Krishna Defence V16 — unseen-family future forecasting", "", report["claim_scope"], "", "## Macro mean", "", "| Model | FPR | Recall | Precision | F1 |", "|---|---:|---:|---:|---:|"]
    for model in ("supervised_only", "dual_head"):
        m = report["macro_mean"][model]
        lines.append(f"| {model} | {m['fpr']:.4f} | {m['recall']:.4f} | {m['precision']:.4f} | {m['f1']:.4f} |")
    lines += ["", f"Held-out families: {', '.join(selected)}", "", f"Clean-history unseen positives across family/seed runs: {sum(clean_ns)}", f"Weighted clean-history recall: {report['macro_mean']['dual_head_clean_history_positive_weighted_recall']}", "", "## Release gate", "", "```json", json.dumps(report["release_gate"], indent=2), "```", "", "## Strict network-only features", "", ", ".join(raw_features)]
    (OUT / "REPORT.md").write_text("\n".join(lines))
    print("FINAL", json.dumps(report["macro_mean"], indent=2), flush=True)
    print("GATE", json.dumps(report["release_gate"], indent=2), flush=True)


if __name__ == "__main__":
    main()
