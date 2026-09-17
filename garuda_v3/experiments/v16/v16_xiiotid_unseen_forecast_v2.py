from __future__ import annotations

import json
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import v16_xiiotid_unseen_forecast as base

BLOCK_SECONDS = 3600
OUT = Path("artifacts/v16_blocked")
OUT.mkdir(parents=True, exist_ok=True)


def blocked_split(cutoff):
    cutoff = np.asarray(cutoff, dtype=np.int64)
    blocks = cutoff // BLOCK_SECONDS
    pos = cutoff % BLOCK_SECONDS
    eligible = (pos >= (base.HISTORY - 1) * 60) & (pos <= BLOCK_SECONDS - base.HORIZON * 60 - 1)
    ub = np.sort(np.unique(blocks[eligible]))
    if len(ub) < 20:
        raise RuntimeError(f"Only {len(ub)} eligible hour blocks")
    rank = {int(b): i for i, b in enumerate(ub)}
    mod = np.asarray([rank.get(int(b), -1) % 10 for b in blocks], dtype=int)
    return {
        "train": np.where(eligible & np.isin(mod, [0, 1, 2, 3, 4, 5]))[0],
        "calibration": np.where(eligible & np.isin(mod, [6]))[0],
        "policy": np.where(eligible & np.isin(mod, [7]))[0],
        "test": np.where(eligible & np.isin(mod, [8, 9]))[0],
    }, blocks, eligible, {
        "block_seconds": BLOCK_SECONDS,
        "sequence_contained_in_block": True,
        "partition": "block-rank modulo 10: train=0..5, calibration=6, policy=7, benign-test=8..9",
    }


def fit_family(X, target, clean, split, blocks, eligible, hist_fams, future_steps, family, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))

    future_hold = base.future_has_family(future_steps, family)
    history_hold = base.history_has_family(hist_fams, family)
    exposed = future_hold | history_hold
    heldout_blocks = set(int(x) for x in np.unique(blocks[eligible & exposed]))

    def safe_partition(name):
        idx = split[name]
        keep = np.asarray([(int(blocks[i]) not in heldout_blocks) and (not exposed[i]) for i in idx], dtype=bool)
        return idx[keep]

    local = {k: safe_partition(k) for k in ("train", "calibration", "policy")}
    for k in local:
        c = np.bincount(target[local[k]], minlength=2)
        if c.min() < 20:
            raise RuntimeError(f"{family}: {k} support after heldout-block removal benign={c[0]} attack={c[1]}")

    tr = base.sample_train(local["train"], target, seed)
    med = base.fit_imputer(X, tr)
    Z = base.impute(X, med)
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
            loss.backward()
            opt.step()

    def infer(idx):
        net.eval()
        z = scaled(idx)
        logits, embeds = [], []
        with torch.no_grad():
            for i in range(0, len(z), 1024):
                lg, em = net(torch.from_numpy(z[i:i+1024]), return_embed=True)
                logits.append(lg.cpu().numpy())
                embeds.append(em.cpu().numpy())
        return np.concatenate(logits), np.concatenate(embeds)

    ca, po = local["calibration"], local["policy"]
    _, etr = infer(tr)
    lca, eca = infer(ca)
    lpo, epo = infer(po)

    platt = base.platt_fit(lca, target[ca])
    ppo = base.platt_apply(platt, lpo)

    benign_train = etr[target[tr] == 0]
    if len(benign_train) > 20000:
        rng = np.random.default_rng(seed)
        benign_train = benign_train[rng.choice(len(benign_train), 20000, replace=False)]
    iso = IsolationForest(n_estimators=160, max_samples=min(4096, len(benign_train)), contamination="auto", random_state=seed, n_jobs=-1)
    iso.fit(benign_train)

    benign_ref = (-iso.decision_function(eca))[target[ca] == 0]
    nov_po = base.novelty_percentile(-iso.decision_function(epo), benign_ref)
    dual_po = 1.0 - (1.0 - ppo) * (1.0 - np.square(nov_po))
    th_sup = base.choose_fpr_threshold(target[po], ppo)
    th_dual = base.choose_fpr_threshold(target[po], dual_po)

    all_idx = np.where(eligible)[0]
    pos_idx = all_idx[future_hold[all_idx]]
    neg_base = split["test"]
    neg_keep = np.asarray([(int(blocks[i]) not in heldout_blocks) and clean[i] and target[i] == 0 for i in neg_base], dtype=bool)
    neg_idx = neg_base[neg_keep]
    if len(pos_idx) < 10 or len(neg_idx) < 100:
        raise RuntimeError(f"{family}: unseen/benign test support insufficient positives={len(pos_idx)} clean_benign={len(neg_idx)}")

    eval_idx = np.concatenate([pos_idx, neg_idx])
    y_eval = np.concatenate([np.ones(len(pos_idx), dtype=int), np.zeros(len(neg_idx), dtype=int)])
    lte, ete = infer(eval_idx)
    psup = base.platt_apply(platt, lte)
    nov = base.novelty_percentile(-iso.decision_function(ete), benign_ref)
    pdual = 1.0 - (1.0 - psup) * (1.0 - np.square(nov))

    clean_pos = np.concatenate([clean[pos_idx], np.zeros(len(neg_idx), dtype=bool)])
    sup_m = base.metrics(y_eval, psup, th_sup, clean_pos)
    dual_m = base.metrics(y_eval, pdual, th_dual, clean_pos)

    offsets_pos = base.family_lead_offsets(future_steps[pos_idx], family)
    pred_pos = pdual[:len(pos_idx)] >= th_dual
    lead = {}
    for minute in range(1, base.HORIZON + 1):
        m = clean[pos_idx] & (offsets_pos == minute)
        lead[str(minute)] = {"n": int(m.sum()), "detected": int(pred_pos[m].sum()) if m.any() else 0, "recall": float(pred_pos[m].mean()) if m.any() else None}

    return {
        "family": family,
        "seed": seed,
        "heldout_hour_blocks": len(heldout_blocks),
        "heldout_exposure_in_train_cal_policy": 0,
        "train_support": {"n": int(len(tr)), "benign": int((target[tr] == 0).sum()), "known_attack": int((target[tr] == 1).sum())},
        "policy_support": {"n": int(len(po)), "benign": int((target[po] == 0).sum()), "known_attack": int((target[po] == 1).sum())},
        "test_support": {"unseen_future_positive": int(len(pos_idx)), "clean_history_unseen_positive": int(clean[pos_idx].sum()), "clean_benign_negative": int(len(neg_idx))},
        "supervised_only": sup_m,
        "dual_head": dual_m,
        "lead_time_minutes": lead,
        "policy_max_fpr": base.MAX_POLICY_FPR,
    }


def main():
    import kagglehub

    root = Path(kagglehub.dataset_download("munaalhawawreh/xiiotid-iiot-intrusion-dataset"))
    csvs = list(root.rglob("*.csv"))
    if not csvs:
        raise RuntimeError("No X-IIoTID CSV found")
    csv_path = max(csvs, key=lambda p: p.stat().st_size)
    prov = {"dataset": "X-IIoTID", "filename": csv_path.name, "bytes": int(csv_path.stat().st_size), "sha256": base.sha256(csv_path), "official_repo": "https://github.com/Alhawawreh/X-IIoTID"}
    print("DATASET", json.dumps(prov, indent=2), flush=True)

    df = pd.read_csv(csv_path, low_memory=False)
    prov.update({"rows": int(len(df)), "columns": int(len(df.columns))})
    dt, date_col, ts_col, time_method, parsed_fraction = base.parse_time(df)
    y, binary_col, label_reports = base.detect_binary_label(df)
    family_col = base.detect_family_col(df, binary_col)
    state, fcols, raw_features, feature_audit, src_col, dst_col, dport_col = base.build_minute_state(df, dt, y, family_col, binary_col, date_col, ts_col)
    X, target, cutoff, clean, srcs, hist_fams, future_steps = base.make_sequences(state, fcols)
    split, blocks, eligible, split_meta = blocked_split(cutoff)

    families = sorted({fam for i in np.where(eligible)[0] for step in future_steps[i] for fam in step if fam != "normal"})
    support = []
    for fam in families:
        f = base.future_has_family(future_steps, fam) & eligible
        exposed = (f | base.history_has_family(hist_fams, fam)) & eligible
        support.append({"family": fam, "future_positive": int(f.sum()), "clean_history_future_positive": int((f & clean).sum()), "heldout_blocks": len(np.unique(blocks[exposed]))})

    candidates = [x for x in support if x["future_positive"] >= 10 and x["heldout_blocks"] >= 1]
    candidates.sort(key=lambda x: (x["clean_history_future_positive"], x["future_positive"]), reverse=True)
    selected = [x["family"] for x in candidates[:base.MAX_FAMILIES]]
    if len(selected) < 3:
        raise RuntimeError(f"Fewer than 3 feasible class3 families: {support}")

    report = {
        "schema": "krishna-v16-xiiotid-unseen-forecast-blocked-v2",
        "claim_scope": "Zero-day-like leave-one-class3-family-out future forecasting. For each held-out attack type, every hour block containing that family in history or future is removed from training/calibration/policy. 8-minute history and 4-minute future are contained inside one hour block. Only strict network-traffic features are used. This does not prove arbitrary real-world zero-day or compromise forecasting.",
        "provenance": prov,
        "detected": {"binary_label_col": binary_col, "family_col": family_col, "time_parse_method": time_method, "time_parse_fraction": parsed_fraction, "strict_network_raw_features": raw_features, "network_feature_audit": feature_audit, "state_feature_count": len(fcols), "source_ip_col": src_col, "destination_ip_col": dst_col, "destination_port_col": dport_col, "label_candidates": label_reports},
        "protocol": {"history_minutes": base.HISTORY, "future_horizon_minutes": base.HORIZON, "split": split_meta, "family_holdout": "class3 fine-grained attack type", "heldout_family_blocks_seen_in_train_cal_policy": False, "network_only_feature_audit_passed": True, "policy_threshold_source": "non-heldout policy blocks only", "policy_max_fpr": base.MAX_POLICY_FPR},
        "family_support_before_modeling": support,
        "heldout_families": selected,
        "results": {},
    }

    completed = []
    for fam in selected:
        report["results"][fam] = {}
        try:
            for seed in base.SEEDS:
                print(f"RUN family={fam} seed={seed}", flush=True)
                r = fit_family(X, target, clean, split, blocks, eligible, hist_fams, future_steps, fam, seed)
                report["results"][fam][str(seed)] = r
                print(json.dumps(r, indent=2), flush=True)
            completed.append(fam)
        except RuntimeError as exc:
            report["results"][fam]["skipped"] = str(exc)
            print(f"SKIP family={fam}: {exc}", flush=True)

    if len(completed) < 3:
        (OUT / "results.json").write_text(json.dumps(report, indent=2))
        raise RuntimeError(f"Only {len(completed)} families completed: {completed}")

    report["heldout_families_completed"] = completed

    def macro(model, key):
        vals = []
        for fam in completed:
            vals.append(float(np.mean([report["results"][fam][str(s)][model][key] for s in base.SEEDS])))
        return float(np.mean(vals))

    clean_n = 0
    clean_hit = 0.0
    for fam in completed:
        for s in base.SEEDS:
            m = report["results"][fam][str(s)]["dual_head"]
            n = int(m["clean_history_future_positive_n"])
            rec = m["clean_history_future_positive_recall"]
            clean_n += n
            if rec is not None:
                clean_hit += n * rec

    report["macro_mean"] = {
        "supervised_only": {k: macro("supervised_only", k) for k in ["fpr", "recall", "precision", "f1"]},
        "dual_head": {k: macro("dual_head", k) for k in ["fpr", "recall", "precision", "f1"]},
        "clean_history_unseen_positive_total_across_family_seed_runs": int(clean_n),
        "dual_head_clean_history_weighted_recall": float(clean_hit / clean_n) if clean_n else None,
    }
    dm = report["macro_mean"]["dual_head"]
    report["release_gate"] = {
        "engineering_target": ">=3 held-out class3 families, macro FPR <=2%, macro unseen recall >=80%, and nonzero clean-history unseen future-positive support.",
        "family_count": len(completed),
        "macro_fpr_pass": bool(dm["fpr"] <= 0.02),
        "macro_unseen_recall_pass": bool(dm["recall"] >= 0.80),
        "clean_history_support_pass": bool(clean_n > 0),
        "pass": bool(len(completed) >= 3 and dm["fpr"] <= 0.02 and dm["recall"] >= 0.80 and clean_n > 0),
        "evidence_limit": "A pass demonstrates family- and hour-block-disjoint X-IIoTID generalization using network-only telemetry. It is not a guarantee for arbitrary zero-days and does not authorize production blocking.",
    }

    (OUT / "results.json").write_text(json.dumps(report, indent=2))
    lines = ["# Krishna Defence V16 — blocked unseen-family forecasting", "", report["claim_scope"], "", "## Macro mean", "", "| Model | FPR | Recall | Precision | F1 |", "|---|---:|---:|---:|---:|"]
    for model in ("supervised_only", "dual_head"):
        m = report["macro_mean"][model]
        lines.append(f"| {model} | {m['fpr']:.4f} | {m['recall']:.4f} | {m['precision']:.4f} | {m['f1']:.4f} |")
    lines += ["", f"Completed held-out families: {', '.join(completed)}", f"Clean-history unseen positives across family/seed runs: {clean_n}", f"Weighted clean-history unseen recall: {report['macro_mean']['dual_head_clean_history_weighted_recall']}", "", "## Gate", "```json", json.dumps(report["release_gate"], indent=2), "```"]
    (OUT / "REPORT.md").write_text("\n".join(lines))
    print("FINAL", json.dumps(report["macro_mean"], indent=2), flush=True)
    print("GATE", json.dumps(report["release_gate"], indent=2), flush=True)


if __name__ == "__main__":
    main()
