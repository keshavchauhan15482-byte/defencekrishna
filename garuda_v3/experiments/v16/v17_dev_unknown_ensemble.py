from __future__ import annotations

import json
import os
import random
from pathlib import Path

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

import v16_xiiotid_unseen_forecast as base
import v16_xiiotid_unseen_forecast_v2 as blocked

DEV_FAMILIES = [
    "bruteforce",
    "false_data_injection",
    "modbus_register_reading",
    "mqtt_cloud_broker_subscription",
    "tcp relay",
]
OUT = Path("artifacts/v17_dev")
OUT.mkdir(parents=True, exist_ok=True)
PER_HEAD_FPR = 0.005


def smooth_percentile(scores, reference):
    ref = np.sort(np.asarray(reference, dtype=float))
    s = np.asarray(scores, dtype=float)
    if len(ref) < 20:
        raise RuntimeError("Too few benign calibration scores")
    rank = np.searchsorted(ref, s, side="right")
    return (rank + 0.5) / (len(ref) + 1.0)


def summary_features(z):
    z = np.asarray(z, dtype=np.float32)
    last = z[:, -1, :]
    first = z[:, 0, :]
    mean = z.mean(axis=1)
    std = z.std(axis=1)
    delta = last - first
    abs_step = np.abs(np.diff(z, axis=1)).mean(axis=1)
    return np.concatenate([last, mean, std, delta, abs_step], axis=1).astype(np.float32)


def binary_metrics(y, pred, score=None, clean_positive=None):
    y = np.asarray(y, dtype=int)
    pred = np.asarray(pred, dtype=bool)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)), "benign": int((y == 0).sum()), "attack": int((y == 1).sum()),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else None,
        "f1": float(f1_score(y, pred, zero_division=0)),
    }
    if score is not None and len(np.unique(y)) > 1:
        out["pr_auc"] = float(average_precision_score(y, score))
    if clean_positive is not None:
        cp = np.asarray(clean_positive, dtype=bool)
        out["clean_history_future_positive_n"] = int(cp.sum())
        out["clean_history_future_positive_recall"] = float(pred[cp].mean()) if cp.any() else None
    return out


def benign_quantile_threshold(scores, benign_mask, fpr):
    b = np.asarray(scores, dtype=float)[np.asarray(benign_mask, dtype=bool)]
    if len(b) < 100:
        raise RuntimeError(f"Too few benign policy examples: {len(b)}")
    return float(np.quantile(b, 1.0 - fpr, method="higher"))


def fit_family(X, target, clean, split, blocks, eligible, hist_fams, future_steps, family, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))

    future_hold = base.future_has_family(future_steps, family)
    history_hold = base.history_has_family(hist_fams, family)
    exposed = future_hold | history_hold
    heldout_blocks = set(int(x) for x in np.unique(blocks[eligible & exposed]))

    def safe(name):
        idx = split[name]
        keep = np.asarray([(int(blocks[i]) not in heldout_blocks) and (not exposed[i]) for i in idx], dtype=bool)
        return idx[keep]

    local = {k: safe(k) for k in ("train", "calibration", "policy")}
    for k, idx in local.items():
        c = np.bincount(target[idx], minlength=2)
        if c.min() < 20:
            raise RuntimeError(f"{family}: {k} support insufficient {c.tolist()}")

    tr = base.sample_train(local["train"], target, seed)
    med = base.fit_imputer(X, tr)
    Z = base.impute(X, med)
    seq_scaler = StandardScaler().fit(Z[tr].reshape(-1, Z.shape[-1]))

    def scaled_seq(idx):
        a = seq_scaler.transform(Z[idx].reshape(-1, Z.shape[-1]))
        return a.reshape(len(idx), Z.shape[1], Z.shape[2]).astype(np.float32)

    class Net(nn.Module):
        def __init__(self, f):
            super().__init__()
            self.rnn = nn.LSTM(f, 32, batch_first=True)
            self.head = nn.Sequential(nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 1))
        def forward(self, x):
            o, _ = self.rnn(x)
            return self.head(o[:, -1]).squeeze(1)

    net = Net(Z.shape[-1])
    ytr = target[tr].astype(np.float32)
    pos, neg = max(1, int((ytr == 1).sum())), max(1, int((ytr == 0).sum()))
    lossfn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg / pos], dtype=torch.float32))
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    dl = DataLoader(TensorDataset(torch.from_numpy(scaled_seq(tr)), torch.from_numpy(ytr)), batch_size=256, shuffle=True)
    for _ in range(8):
        net.train()
        for xb, yb in dl:
            opt.zero_grad(set_to_none=True); loss = lossfn(net(xb), yb); loss.backward(); opt.step()

    def logits(idx):
        net.eval(); z = scaled_seq(idx); out = []
        with torch.no_grad():
            for i in range(0, len(z), 1024):
                out.append(net(torch.from_numpy(z[i:i+1024])).cpu().numpy())
        return np.concatenate(out)

    ca, po = local["calibration"], local["policy"]
    platt = base.platt_fit(logits(ca), target[ca])
    ppo = base.platt_apply(platt, logits(po))
    th_sup = base.choose_fpr_threshold(target[po], ppo, max_fpr=PER_HEAD_FPR)

    # Benign world-model / novelty branch. It never sees attack-family labels.
    btr = tr[target[tr] == 0]
    bca = ca[target[ca] == 0]
    Spo = summary_features(scaled_seq(po))
    Str = summary_features(scaled_seq(btr))
    Sca = summary_features(scaled_seq(bca))

    sum_scaler = StandardScaler().fit(Str)
    Str_s = sum_scaler.transform(Str)
    Sca_s = sum_scaler.transform(Sca)
    Spo_s = sum_scaler.transform(Spo)

    if len(Str_s) > 20000:
        rng = np.random.default_rng(seed)
        fit_rows = Str_s[rng.choice(len(Str_s), 20000, replace=False)]
    else:
        fit_rows = Str_s

    iso = IsolationForest(n_estimators=220, max_samples=min(4096, len(fit_rows)), contamination="auto", random_state=seed, n_jobs=-1)
    iso.fit(fit_rows)

    ncomp = max(2, min(24, fit_rows.shape[1] - 1, len(fit_rows) - 1))
    pca = PCA(n_components=ncomp, svd_solver="randomized", random_state=seed)
    pca.fit(fit_rows)

    med_s = np.median(fit_rows, axis=0)
    mad_s = np.median(np.abs(fit_rows - med_s), axis=0)
    mad_s = np.where(mad_s < 1e-3, 1e-3, mad_s)

    def components(S):
        s = sum_scaler.transform(S) if S is not Spo and S is not Sca and S is not Str else None
        if s is None:
            raise AssertionError("internal use only")

    def novelty_from_scaled(Ss, cal=False):
        iso_raw = -iso.decision_function(Ss)
        rec = pca.inverse_transform(pca.transform(Ss))
        pca_raw = np.mean((Ss - rec) ** 2, axis=1)
        rz = np.abs((Ss - med_s) / mad_s)
        robust_raw = np.mean(np.partition(rz, -min(8, rz.shape[1]), axis=1)[:, -min(8, rz.shape[1]):], axis=1)
        return iso_raw, pca_raw, robust_raw

    ref_iso, ref_pca, ref_rob = novelty_from_scaled(Sca_s)
    po_iso, po_pca, po_rob = novelty_from_scaled(Spo_s)
    po_nov = np.maximum.reduce([
        smooth_percentile(po_iso, ref_iso),
        smooth_percentile(po_pca, ref_pca),
        smooth_percentile(po_rob, ref_rob),
    ])
    th_nov = benign_quantile_threshold(po_nov, target[po] == 0, PER_HEAD_FPR)

    policy_union = (ppo >= th_sup) | (po_nov >= th_nov)
    policy_m = binary_metrics(target[po], policy_union)

    all_idx = np.where(eligible)[0]
    pos_idx = all_idx[future_hold[all_idx]]
    neg_base = split["test"]
    neg_keep = np.asarray([(int(blocks[i]) not in heldout_blocks) and clean[i] and target[i] == 0 for i in neg_base], dtype=bool)
    neg_idx = neg_base[neg_keep]
    if len(pos_idx) < 10 or len(neg_idx) < 100:
        raise RuntimeError(f"{family}: test support insufficient pos={len(pos_idx)} neg={len(neg_idx)}")

    ev = np.concatenate([pos_idx, neg_idx])
    yev = np.concatenate([np.ones(len(pos_idx), dtype=int), np.zeros(len(neg_idx), dtype=int)])
    pev = base.platt_apply(platt, logits(ev))
    Sev = summary_features(scaled_seq(ev))
    Sev_s = sum_scaler.transform(Sev)
    ev_iso, ev_pca, ev_rob = novelty_from_scaled(Sev_s)
    nev = np.maximum.reduce([
        smooth_percentile(ev_iso, ref_iso),
        smooth_percentile(ev_pca, ref_pca),
        smooth_percentile(ev_rob, ref_rob),
    ])

    pred_sup = pev >= th_sup
    pred_nov = nev >= th_nov
    pred_union = pred_sup | pred_nov
    union_score = np.maximum(pev, nev)
    clean_pos = np.concatenate([clean[pos_idx], np.zeros(len(neg_idx), dtype=bool)])

    offsets = base.family_lead_offsets(future_steps[pos_idx], family)
    ppos = pred_union[:len(pos_idx)]
    lead = {}
    for m in range(1, base.HORIZON + 1):
        mask = clean[pos_idx] & (offsets == m)
        lead[str(m)] = {"n": int(mask.sum()), "detected": int(ppos[mask].sum()) if mask.any() else 0, "recall": float(ppos[mask].mean()) if mask.any() else None}

    return {
        "family": family, "seed": seed, "heldout_hour_blocks": len(heldout_blocks), "heldout_exposure_in_train_cal_policy": 0,
        "thresholds": {"supervised": float(th_sup), "novelty": float(th_nov), "per_head_policy_fpr_budget": PER_HEAD_FPR},
        "policy_union": policy_m,
        "test_support": {"unseen_future_positive": int(len(pos_idx)), "clean_history_unseen_positive": int(clean[pos_idx].sum()), "clean_benign_negative": int(len(neg_idx))},
        "supervised": binary_metrics(yev, pred_sup, pev, clean_pos),
        "novelty_only": binary_metrics(yev, pred_nov, nev, clean_pos),
        "union": binary_metrics(yev, pred_union, union_score, clean_pos),
        "lead_time_minutes": lead,
    }


def main():
    import kagglehub
    root = Path(kagglehub.dataset_download("munaalhawawreh/xiiotid-iiot-intrusion-dataset"))
    csvs = list(root.rglob("*.csv"))
    csv_path = max(csvs, key=lambda p: p.stat().st_size)
    if base.sha256(csv_path) != "7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0":
        raise RuntimeError("X-IIoTID source hash changed")

    import pandas as pd
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, _, _ = base.parse_time(df)
    y, binary_col, _ = base.detect_binary_label(df)
    family_col = base.detect_family_col(df, binary_col)
    state, fcols, raw_features, feature_audit, *_ = base.build_minute_state(df, dt, y, family_col, binary_col, date_col, ts_col)
    X, target, cutoff, clean, _, hist_fams, future_steps = base.make_sequences(state, fcols)
    split, blocks, eligible, split_meta = blocked.blocked_split(cutoff)

    report = {
        "schema": "krishna-v17-dev-unknown-ensemble-v1",
        "purpose": "Development only. These five families were already consumed by V16 diagnostic and may be used for architecture selection. Final validation families remain frozen and untouched.",
        "development_families": DEV_FAMILIES,
        "final_validation_families_not_scored": ["exfiltration", "dictionary", "insider_malcious", "c&c", "reverse_shell"],
        "network_only_features": raw_features,
        "split": split_meta,
        "results": {},
    }
    completed = []
    for fam in DEV_FAMILIES:
        report["results"][fam] = {}
        try:
            for seed in base.SEEDS:
                print(f"V17 DEV family={fam} seed={seed}", flush=True)
                r = fit_family(X, target, clean, split, blocks, eligible, hist_fams, future_steps, fam, seed)
                report["results"][fam][str(seed)] = r
                print(json.dumps(r, indent=2), flush=True)
            completed.append(fam)
        except RuntimeError as exc:
            report["results"][fam]["skipped"] = str(exc)
            print(f"SKIP {fam}: {exc}", flush=True)

    if len(completed) < 3:
        (OUT / "results.json").write_text(json.dumps(report, indent=2))
        raise RuntimeError(f"Only {len(completed)} dev families completed")

    def macro(head, key):
        return float(np.mean([
            np.mean([report["results"][fam][str(seed)][head][key] for seed in base.SEEDS])
            for fam in completed
        ]))

    report["macro_mean"] = {
        h: {k: macro(h, k) for k in ["fpr", "recall", "precision", "f1"]}
        for h in ["supervised", "novelty_only", "union"]
    }
    report["development_target"] = {
        "target_fpr": 0.02,
        "target_unseen_recall": 0.80,
        "union_fpr_pass": report["macro_mean"]["union"]["fpr"] <= 0.02,
        "union_recall_pass": report["macro_mean"]["union"]["recall"] >= 0.80,
        "ready_to_unlock_frozen_final_validation": bool(report["macro_mean"]["union"]["fpr"] <= 0.02 and report["macro_mean"]["union"]["recall"] >= 0.80),
    }
    (OUT / "results.json").write_text(json.dumps(report, indent=2))
    (OUT / "REPORT.md").write_text("# V17 development unknown ensemble\n\n```json\n" + json.dumps({"macro_mean": report["macro_mean"], "development_target": report["development_target"]}, indent=2) + "\n```\n")
    print("V17_FINAL", json.dumps(report["macro_mean"], indent=2), flush=True)
    print("V17_TARGET", json.dumps(report["development_target"], indent=2), flush=True)


if __name__ == "__main__":
    main()
