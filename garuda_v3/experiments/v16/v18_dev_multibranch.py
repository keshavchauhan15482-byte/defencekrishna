from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

import v16_xiiotid_unseen_forecast as base
import v16_xiiotid_unseen_forecast_v2 as blocked

DEV_FAMILIES = ["bruteforce", "false_data_injection", "modbus_register_reading", "mqtt_cloud_broker_subscription", "tcp relay"]
FINAL_FAMILIES = ["exfiltration", "dictionary", "insider_malcious", "c&c", "reverse_shell"]
OUT = Path("artifacts/v18_dev")
OUT.mkdir(parents=True, exist_ok=True)
N_BUCKETS = 12
MAX_POLICY_FPR = 0.02


def stable_bucket(value, buckets=N_BUCKETS):
    raw = str(value).strip().lower().encode("utf-8", errors="ignore")
    return int.from_bytes(hashlib.blake2b(raw, digest_size=4).digest(), "big") % buckets


def enhanced_state(df, dt, y, family_col, binary_col, date_col, ts_col):
    src_col = base.pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    dst_col = base.pick_col(df.columns, ["Des_IP", "Dst_IP", "Destination_IP", "dst_ip"])
    dport_col = base.pick_col(df.columns, ["Des_port", "Dst_port", "Destination_port", "dst_port"])
    proto_col = base.pick_col(df.columns, ["Protocol", "Proto"])
    service_col = base.pick_col(df.columns, ["Service", "Serv"])

    excluded = {x for x in [family_col, binary_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if base.norm(c) in {"class1", "class2", "class3"})
    numeric_cols, audit = base.strict_network_features(df, excluded)

    frame = pd.DataFrame({
        "dt": dt,
        "y": y,
        "family": df[family_col].astype(str).map(base.norm_label),
        "src": df[src_col].astype(str) if src_col else "GLOBAL",
    })
    if dst_col:
        frame["dst"] = df[dst_col].astype(str)
    if dport_col:
        frame["dport_raw"] = df[dport_col].astype(str)
    for c in numeric_cols:
        frame[c] = base.numericize(df[c])

    categorical = []
    for prefix, col in (("proto", proto_col), ("service", service_col)):
        if not col:
            continue
        vals = df[col].fillna("__missing__").astype(str)
        buckets = vals.map(stable_bucket).to_numpy(dtype=int)
        for b in range(N_BUCKETS):
            name = f"{prefix}_bucket_{b}"
            frame[name] = (buckets == b).astype(np.float32)
            categorical.append(name)
        frame[f"{prefix}_present"] = (vals.str.len() > 0).astype(np.float32)
        categorical.append(f"{prefix}_present")

    frame = frame.dropna(subset=["dt", "y"]).copy()
    frame["minute"] = frame["dt"].dt.floor("min")
    frame["y"] = frame["y"].astype(int)
    g = frame.groupby(["src", "minute"], sort=True)

    state = g[numeric_cols].agg(["mean", "std", "max"])
    state.columns = ["__".join(x) for x in state.columns]
    if categorical:
        cat_state = g[categorical].mean()
        state = state.join(cat_state, how="left")
    state["flow_count"] = g.size().astype(float)
    state["attack_now"] = g["y"].max().astype(int)
    state["family_now"] = g["family"].agg(lambda s: tuple(sorted({base.norm_label(v) for v in s if base.norm_label(v) != "normal"})))
    if dst_col:
        state["_dst_set"] = g["dst"].agg(lambda s: tuple(sorted(set(s.astype(str)))))
        state["unique_dst"] = g["dst"].nunique().astype(float)
    if dport_col:
        state["unique_dst_port"] = g["dport_raw"].nunique().astype(float)

    state = state.reset_index().sort_values(["src", "minute"]).reset_index(drop=True)
    if "_dst_set" in state:
        new_ratio = np.zeros(len(state), dtype=float)
        churn = np.zeros(len(state), dtype=float)
        for _, idx in state.groupby("src", sort=False).groups.items():
            recent = []
            for row_idx in list(idx):
                cur = set(state.at[row_idx, "_dst_set"])
                prev = set().union(*recent) if recent else set()
                new_ratio[row_idx] = len(cur - prev) / max(1, len(cur))
                union = cur | prev
                churn[row_idx] = 1.0 - (len(cur & prev) / len(union)) if union else 0.0
                recent.append(cur)
                if len(recent) > base.HISTORY:
                    recent.pop(0)
        state["new_dst_ratio"] = new_ratio
        state["dst_churn"] = churn
        state = state.drop(columns=["_dst_set"])

    fcols = [c for c in state.columns if c not in ["src", "minute", "attack_now", "family_now"]]
    return state, fcols, numeric_cols, categorical, {"protocol_col": proto_col, "service_col": service_col, "source_ip_col": src_col, "destination_ip_col": dst_col}


def smooth_percentile(scores, reference):
    ref = np.sort(np.asarray(reference, dtype=float))
    rank = np.searchsorted(ref, np.asarray(scores, dtype=float), side="right")
    return (rank + 0.5) / (len(ref) + 1.0)


def summaries(z):
    z = np.asarray(z, dtype=np.float32)
    return np.concatenate([
        z[:, -1], z.mean(1), z.std(1), z.max(1), z[:, -1] - z[:, 0], np.abs(np.diff(z, axis=1)).mean(1)
    ], axis=1).astype(np.float32)


def calibrate_probability(raw_p, y):
    p = np.clip(np.asarray(raw_p, dtype=float), 1e-6, 1 - 1e-6)
    logit = np.log(p / (1 - p))
    m = LogisticRegression(C=1e6, solver="lbfgs", max_iter=300)
    m.fit(logit.reshape(-1, 1), y)
    return m


def apply_probability_calibrator(m, raw_p):
    p = np.clip(np.asarray(raw_p, dtype=float), 1e-6, 1 - 1e-6)
    return m.predict_proba(np.log(p / (1 - p)).reshape(-1, 1))[:, 1]


def binary_metrics(y, score, th, clean_positive=None):
    y = np.asarray(y, dtype=int); score = np.asarray(score, dtype=float); pred = score >= th
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)), "benign": int((y == 0).sum()), "attack": int((y == 1).sum()), "threshold": float(th),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if fp + tn else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "precision": float(tp / (tp + fp)) if tp + fp else None,
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, score)) if len(np.unique(y)) > 1 else None,
    }
    if clean_positive is not None:
        cp = np.asarray(clean_positive, dtype=bool)
        out["clean_history_future_positive_n"] = int(cp.sum())
        out["clean_history_future_positive_recall"] = float(pred[cp].mean()) if cp.any() else None
    return out


def run_family(X, target, clean, split, blocks, eligible, hist_fams, future_steps, family, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed); torch.set_num_threads(max(1, min(2, os.cpu_count() or 1)))
    future_hold = base.future_has_family(future_steps, family)
    exposed = future_hold | base.history_has_family(hist_fams, family)
    held_blocks = set(int(x) for x in np.unique(blocks[eligible & exposed]))

    def safe(name):
        idx = split[name]
        keep = np.asarray([(int(blocks[i]) not in held_blocks) and (not exposed[i]) for i in idx], dtype=bool)
        return idx[keep]

    local = {k: safe(k) for k in ("train", "calibration", "policy")}
    for k, idx in local.items():
        c = np.bincount(target[idx], minlength=2)
        if c.min() < 20: raise RuntimeError(f"{family}: {k} support {c.tolist()}")

    tr = base.sample_train(local["train"], target, seed)
    ca, po = local["calibration"], local["policy"]
    med = base.fit_imputer(X, tr); Z = base.impute(X, med)
    seq_scaler = StandardScaler().fit(Z[tr].reshape(-1, Z.shape[-1]))
    def seq(idx):
        a = seq_scaler.transform(Z[idx].reshape(-1, Z.shape[-1]))
        return a.reshape(len(idx), Z.shape[1], Z.shape[2]).astype(np.float32)

    # Temporal LSTM branch.
    class Net(nn.Module):
        def __init__(self, f):
            super().__init__(); self.rnn = nn.LSTM(f, 48, batch_first=True); self.head = nn.Sequential(nn.Linear(48, 24), nn.ReLU(), nn.Dropout(.10), nn.Linear(24, 1))
        def forward(self, x):
            o, _ = self.rnn(x); return self.head(o[:, -1]).squeeze(1)
    net = Net(Z.shape[-1]); ytr = target[tr].astype(np.float32)
    pos, neg = max(1, int((ytr == 1).sum())), max(1, int((ytr == 0).sum()))
    lossfn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg / pos], dtype=torch.float32)); opt = torch.optim.AdamW(net.parameters(), lr=8e-4, weight_decay=1e-4)
    dl = DataLoader(TensorDataset(torch.from_numpy(seq(tr)), torch.from_numpy(ytr)), batch_size=256, shuffle=True)
    for _ in range(12):
        net.train()
        for xb, yb in dl:
            opt.zero_grad(set_to_none=True); loss = lossfn(net(xb), yb); loss.backward(); torch.nn.utils.clip_grad_norm_(net.parameters(), 2.0); opt.step()
    def lstm_raw(idx):
        net.eval(); zz = seq(idx); out=[]
        with torch.no_grad():
            for i in range(0, len(zz), 1024): out.append(net(torch.from_numpy(zz[i:i+1024])).cpu().numpy())
        return np.concatenate(out)
    lstm_cal = base.platt_fit(lstm_raw(ca), target[ca])
    def lstm_p(idx): return base.platt_apply(lstm_cal, lstm_raw(idx))

    # Nonlinear summary branch learns generic malicious temporal/network patterns.
    Str = summaries(seq(tr)); Sca = summaries(seq(ca)); Spo = summaries(seq(po))
    tree_scaler = StandardScaler().fit(Str); Str_s=tree_scaler.transform(Str); Sca_s=tree_scaler.transform(Sca); Spo_s=tree_scaler.transform(Spo)
    tree = HistGradientBoostingClassifier(max_iter=220, learning_rate=.055, max_leaf_nodes=31, min_samples_leaf=20, l2_regularization=1.0, class_weight="balanced", random_state=seed)
    tree.fit(Str_s, target[tr])
    tree_cal = calibrate_probability(tree.predict_proba(Sca_s)[:, 1], target[ca])
    def tree_p_from_summary(S): return apply_probability_calibrator(tree_cal, tree.predict_proba(tree_scaler.transform(S))[:, 1])
    tpo = tree_p_from_summary(Spo)

    # Benign-only world-model novelty branch.
    btr_mask = target[tr] == 0; bca_mask = target[ca] == 0
    B = Str_s[btr_mask]
    if len(B) > 20000:
        rng=np.random.default_rng(seed); B=B[rng.choice(len(B),20000,replace=False)]
    iso=IsolationForest(n_estimators=220,max_samples=min(4096,len(B)),contamination="auto",random_state=seed,n_jobs=-1); iso.fit(B)
    ncomp=max(2,min(24,B.shape[1]-1,len(B)-1)); pca=PCA(n_components=ncomp,svd_solver="randomized",random_state=seed); pca.fit(B)
    med_b=np.median(B,axis=0); mad_b=np.median(np.abs(B-med_b),axis=0); mad_b=np.where(mad_b<1e-3,1e-3,mad_b)
    def novelty_raw(Ss):
        ir=-iso.decision_function(Ss); rec=pca.inverse_transform(pca.transform(Ss)); pr=np.mean((Ss-rec)**2,axis=1)
        rz=np.abs((Ss-med_b)/mad_b); k=min(8,rz.shape[1]); rr=np.mean(np.partition(rz,-k,axis=1)[:,-k:],axis=1)
        return ir,pr,rr
    ri,rp,rr=novelty_raw(Sca_s[bca_mask]); pi,pp,pr=novelty_raw(Spo_s)
    nov_po=np.maximum.reduce([smooth_percentile(pi,ri),smooth_percentile(pp,rp),smooth_percentile(pr,rr)])

    lpo=lstm_p(po)
    # Use complementary branches: high score if any learned malicious branch or benign novelty branch fires.
    sup_po=1.0-(1.0-lpo)*(1.0-tpo)
    final_po=np.maximum(sup_po, nov_po)
    th=base.choose_fpr_threshold(target[po], final_po, max_fpr=MAX_POLICY_FPR)

    all_idx=np.where(eligible)[0]; pos_idx=all_idx[future_hold[all_idx]]
    neg_base=split["test"]; neg_keep=np.asarray([(int(blocks[i]) not in held_blocks) and clean[i] and target[i]==0 for i in neg_base],dtype=bool); neg_idx=neg_base[neg_keep]
    if len(pos_idx)<10 or len(neg_idx)<100: raise RuntimeError(f"{family}: test support pos={len(pos_idx)} neg={len(neg_idx)}")
    ev=np.concatenate([pos_idx,neg_idx]); yev=np.concatenate([np.ones(len(pos_idx),int),np.zeros(len(neg_idx),int)])
    Sev=summaries(seq(ev)); Sev_s=tree_scaler.transform(Sev)
    lp=lstm_p(ev); tp=tree_p_from_summary(Sev); sup=1.0-(1.0-lp)*(1.0-tp)
    ei,ep,er=novelty_raw(Sev_s); nov=np.maximum.reduce([smooth_percentile(ei,ri),smooth_percentile(ep,rp),smooth_percentile(er,rr)])
    final=np.maximum(sup,nov); clean_pos=np.concatenate([clean[pos_idx],np.zeros(len(neg_idx),bool)])

    # Individual diagnostics use their own policy FPR-limited thresholds; final branch alone is candidate architecture.
    th_l=base.choose_fpr_threshold(target[po],lpo,max_fpr=MAX_POLICY_FPR)
    th_t=base.choose_fpr_threshold(target[po],tpo,max_fpr=MAX_POLICY_FPR)
    th_s=base.choose_fpr_threshold(target[po],sup_po,max_fpr=MAX_POLICY_FPR)
    th_n=float(np.quantile(nov_po[target[po]==0],1.0-MAX_POLICY_FPR,method="higher"))

    return {
        "family":family,"seed":seed,"heldout_hour_blocks":len(held_blocks),"heldout_exposure_in_train_cal_policy":0,
        "test_support":{"unseen_future_positive":int(len(pos_idx)),"clean_history_unseen_positive":int(clean[pos_idx].sum()),"clean_benign_negative":int(len(neg_idx))},
        "lstm":binary_metrics(yev,lp,th_l,clean_pos),"tree":binary_metrics(yev,tp,th_t,clean_pos),"supervised_ensemble":binary_metrics(yev,sup,th_s,clean_pos),"novelty":binary_metrics(yev,nov,th_n,clean_pos),"final":binary_metrics(yev,final,th,clean_pos),
    }


def main():
    import kagglehub
    root=Path(kagglehub.dataset_download("munaalhawawreh/xiiotid-iiot-intrusion-dataset")); csv_path=max(root.rglob("*.csv"),key=lambda p:p.stat().st_size)
    if base.sha256(csv_path)!="7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0": raise RuntimeError("source hash changed")
    df=pd.read_csv(csv_path,low_memory=False); dt,date_col,ts_col,_,_=base.parse_time(df); y,binary_col,_=base.detect_binary_label(df); family_col=base.detect_family_col(df,binary_col)
    state,fcols,numeric,categorical,columns=enhanced_state(df,dt,y,family_col,binary_col,date_col,ts_col)
    X,target,cutoff,clean,_,hist_fams,future_steps=base.make_sequences(state,fcols); split,blocks,eligible,split_meta=blocked.blocked_split(cutoff)
    report={"schema":"krishna-v18-dev-multibranch-v1","purpose":"Development only; frozen final families are never scored here.","development_families":DEV_FAMILIES,"final_validation_families_not_scored":FINAL_FAMILIES,"network_numeric_features":numeric,"network_categorical_features":categorical,"columns":columns,"state_feature_count":len(fcols),"split":split_meta,"results":{}}
    completed=[]
    for fam in DEV_FAMILIES:
        report["results"][fam]={}
        try:
            for seed in base.SEEDS:
                print(f"V18 DEV family={fam} seed={seed}",flush=True); r=run_family(X,target,clean,split,blocks,eligible,hist_fams,future_steps,fam,seed); report["results"][fam][str(seed)]=r; print(json.dumps(r,indent=2),flush=True)
            completed.append(fam)
        except RuntimeError as exc:
            report["results"][fam]["skipped"]=str(exc); print(f"SKIP {fam}: {exc}",flush=True)
    if len(completed)<3: (OUT/"results.json").write_text(json.dumps(report,indent=2)); raise RuntimeError("too few completed dev families")
    def macro(head,key): return float(np.mean([np.mean([report["results"][f][str(s)][head][key] for s in base.SEEDS]) for f in completed]))
    report["macro_mean"]={h:{k:macro(h,k) for k in ["fpr","recall","precision","f1"]} for h in ["lstm","tree","supervised_ensemble","novelty","final"]}
    m=report["macro_mean"]["final"]; report["development_target"]={"target_fpr":0.02,"target_unseen_recall":0.80,"fpr_pass":m["fpr"]<=0.02,"recall_pass":m["recall"]>=0.80,"ready_to_unlock_frozen_final_validation":bool(m["fpr"]<=0.02 and m["recall"]>=0.80)}
    (OUT/"results.json").write_text(json.dumps(report,indent=2)); (OUT/"REPORT.md").write_text("# V18 development multi-branch\n\n```json\n"+json.dumps({"macro_mean":report["macro_mean"],"development_target":report["development_target"]},indent=2)+"\n```\n")
    print("V18_FINAL",json.dumps(report["macro_mean"],indent=2),flush=True); print("V18_TARGET",json.dumps(report["development_target"],indent=2),flush=True)


if __name__=="__main__": main()
