from __future__ import annotations

"""V39: invariant temporal LSTM cross-device clean-onset development test."""

import copy
import json
import math
import random
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, log_loss, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler

HERE = Path(__file__).resolve().parent
V35_DIR = HERE.parent / "v35"
if str(V35_DIR) not in sys.path:
    sys.path.insert(0, str(V35_DIR))
import v35_unsw_cross_device_forecast as v35

OUT = HERE / "artifacts" / "unsw_temporal_lstm"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
FOLDS = [
    {"name":"fold0", "test":["00166cab6b88","0017882b9a25"], "calibration":["44650d56ccd3"], "policy":["50c7bf005639"], "train":["70ee50183443","74c63b29d71d","d073d5018308","ec1a5979f489"]},
    {"name":"fold1", "test":["44650d56ccd3","50c7bf005639"], "calibration":["70ee50183443"], "policy":["74c63b29d71d"], "train":["00166cab6b88","0017882b9a25","d073d5018308","ec1a5979f489"]},
    {"name":"fold2", "test":["70ee50183443","74c63b29d71d"], "calibration":["d073d5018308"], "policy":["ec1a5979f489"], "train":["00166cab6b88","0017882b9a25","44650d56ccd3","50c7bf005639"]},
    {"name":"fold3", "test":["d073d5018308","ec1a5979f489"], "calibration":["00166cab6b88"], "policy":["0017882b9a25"], "train":["44650d56ccd3","50c7bf005639","70ee50183443","74c63b29d71d"]},
]
DEVICES = sorted(set(d for f in FOLDS for role in ("train","calibration","policy","test") for d in f[role]))
POLICY_BUDGETS = [0.005, 0.01, 0.02, 0.05]
COUNT_N = len(v35.COUNT_NAMES)
FRACTION_N = len(v35.FRACTION_NAMES)


def seed_all(seed: int):
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(1)
    try:
        torch.use_deterministic_algorithms(True)
    except Exception:
        pass


def temporal_sequence(H: np.ndarray) -> np.ndarray:
    """8x33 canonical history -> 7x12 invariant fraction-difference sequence."""
    F = H[:, COUNT_N:].astype(np.float64)
    med = np.median(F, axis=0)
    q25 = np.quantile(F, 0.25, axis=0); q75 = np.quantile(F, 0.75, axis=0)
    scale = np.maximum(q75 - q25, 0.10)
    Z = np.clip((F - med) / scale, -12.0, 12.0)
    return np.diff(Z, axis=0).astype(np.float32)


def build_device_sequences(device: str, flow: dict, events: list[dict]):
    rows = flow["rows"]; timestamps = flow["timestamps"]
    minutes = sorted(rows); minute_set = set(minutes)
    attack_minute = {m: v35.minute_overlaps_event(m, events) for m in minutes}
    out = []
    for m in minutes:
        hist = list(range(m - v35.HISTORY_MINUTES + 1, m + 1))
        future = list(range(m + 1, m + 5))
        if not all(x in minute_set for x in hist + future):
            continue
        if any(attack_minute[x] for x in hist):
            continue
        cutoff = float(timestamps[m])
        future_events = [e for e in events if cutoff < e["start"] <= cutoff + v35.FUTURE_SECONDS]
        if future_events:
            y = 1; event_ids = [e["id"] for e in future_events]
        else:
            if any(attack_minute[x] for x in future):
                continue
            y = 0; event_ids = []
        H = np.stack([rows[x] for x in hist])
        out.append({
            "seq": temporal_sequence(H), "y": int(y), "device": device,
            "cutoff_ts": cutoff, "event_ids": event_ids,
        })
    return out


def concatenate(data, devices, meta=False):
    X = np.concatenate([data[d]["X"] for d in devices], axis=0)
    y = np.concatenate([data[d]["y"] for d in devices], axis=0)
    if not meta:
        return X, y
    m = []
    for d in devices:
        m.extend(data[d]["meta"])
    return X, y, m


def domain_invariance(data: dict) -> dict:
    rows = []
    for fi, fold in enumerate(FOLDS):
        held = fold["test"]
        other = [d for d in DEVICES if d not in held]
        A = np.concatenate([data[d]["X"][data[d]["y"] == 0] for d in other], axis=0).reshape(-1, 84)
        B = np.concatenate([data[d]["X"][data[d]["y"] == 0] for d in held], axis=0).reshape(-1, 84)
        rng = np.random.default_rng(3901 + fi)
        n = min(20_000, len(A), len(B))
        ia = rng.choice(len(A), n, replace=False); ib = rng.choice(len(B), n, replace=False)
        X = np.concatenate([A[ia], B[ib]], axis=0)
        y = np.concatenate([np.zeros(n, int), np.ones(n, int)])
        xa, xb, ya, yb = train_test_split(X, y, test_size=.30, random_state=3901+fi, stratify=y)
        sc = StandardScaler().fit(xa)
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=3901+fi).fit(sc.transform(xa), ya)
        p = clf.predict_proba(sc.transform(xb))[:, 1]
        rows.append({
            "fold": fold["name"], "heldout": held,
            "roc_auc": float(roc_auc_score(yb, p)),
            "accuracy": float(accuracy_score(yb, p >= .5)),
        })
    return {
        "folds": rows,
        "mean_domain_roc_auc": float(np.mean([r["roc_auc"] for r in rows])),
        "max_domain_roc_auc": float(np.max([r["roc_auc"] for r in rows])),
        "pass": bool(np.mean([r["roc_auc"] for r in rows]) <= .70),
    }


def fit_channel_scaler(X: np.ndarray):
    flat = X.reshape(-1, X.shape[-1])
    sc = StandardScaler().fit(flat)
    return sc


def apply_channel_scaler(sc, X):
    shp = X.shape
    return sc.transform(X.reshape(-1, shp[-1])).reshape(shp).astype(np.float32)


class TinyLSTM(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(input_size=FRACTION_N, hidden_size=32, num_layers=1, batch_first=True)
        self.head = nn.Linear(32, 1)
    def forward(self, x):
        y, _ = self.lstm(x)
        return self.head(y[:, -1]).squeeze(-1)


def torch_prob(model, X, batch=4096):
    model.eval(); out = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            t = torch.from_numpy(X[i:i+batch])
            out.append(torch.sigmoid(model(t)).cpu().numpy())
    return np.concatenate(out) if out else np.asarray([], float)


def train_lstm(Xtr, ytr, Xca, yca, seed):
    seed_all(seed)
    model = TinyLSTM()
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    counts = np.bincount(ytr, minlength=2).astype(float)
    weights = np.where(ytr == 1, 0.5 / max(1.0, counts[1]), 0.5 / max(1.0, counts[0]))
    draws = min(30_000, len(ytr))
    sampler = WeightedRandomSampler(torch.tensor(weights, dtype=torch.double), num_samples=draws, replacement=True)
    ds = TensorDataset(torch.from_numpy(Xtr), torch.from_numpy(ytr.astype(np.float32)))
    loader = DataLoader(ds, batch_size=512, sampler=sampler, num_workers=0)
    loss_fn = nn.BCEWithLogitsLoss()
    best_state = None; best_loss = math.inf; history = []
    for epoch in range(1, 9):
        model.train(); losses = []
        for xb, yb in loader:
            opt.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0); opt.step()
            losses.append(float(loss.detach()))
        pca = np.clip(torch_prob(model, Xca), 1e-6, 1-1e-6)
        ca_loss = float(log_loss(yca, pca, labels=[0,1]))
        history.append({"epoch": epoch, "train_loss": float(np.mean(losses)), "calibration_log_loss": ca_loss})
        if ca_loss < best_loss:
            best_loss = ca_loss; best_state = copy.deepcopy(model.state_dict())
    if best_state is None:
        raise RuntimeError("no LSTM checkpoint")
    model.load_state_dict(best_state)
    return model, history, best_loss


def robust_policy(scores_ca, yca, scores_po, ypo):
    rows = []
    bca = np.asarray(scores_ca)[np.asarray(yca) == 0]
    bpo = np.asarray(scores_po)[np.asarray(ypo) == 0]
    for budget in POLICY_BUDGETS:
        qca = float(np.quantile(bca, 1-budget, method="higher"))
        qpo = float(np.quantile(bpo, 1-budget, method="higher"))
        th = max(qca, qpo)
        m = v35.binary_metrics(ypo, scores_po, th)
        rows.append({"budget": budget, "threshold": th, "calibration_benign_quantile": qca, "policy_benign_quantile": qpo, "policy_metrics": m})
    valid = [r for r in rows if r["policy_metrics"]["fpr"] <= .0505]
    if not valid:
        raise RuntimeError("no robust threshold candidate")
    chosen = sorted(valid, key=lambda r: (-r["policy_metrics"]["recall"], r["policy_metrics"]["fpr"], r["budget"]))[0]
    return {"candidates": rows, "chosen": chosen}


def event_metrics(test_devices, meta, scores, threshold, events):
    cand = defaultdict(list)
    for i, s in enumerate(meta):
        for eid in s["event_ids"]: cand[eid].append(i)
    rows = []; leads = []
    for d in test_devices:
        for e in events[d]:
            idx = cand.get(e["id"], [])
            if not idx:
                rows.append({"event_id":e["id"],"device":d,"label":e["label"],"evaluable":False,"detected":False,"candidate_windows":0,"max_lead_seconds":None}); continue
            hit = [i for i in idx if scores[i] >= threshold]
            ll = [float(e["start"] - meta[i]["cutoff_ts"]) for i in hit]
            ml = max(ll) if ll else None
            if ml is not None: leads.append(ml)
            rows.append({"event_id":e["id"],"device":d,"label":e["label"],"evaluable":True,"detected":bool(hit),"candidate_windows":len(idx),"max_lead_seconds":ml})
    ev = [r for r in rows if r["evaluable"]]; det = [r for r in ev if r["detected"]]
    return {"total_annotated_events":len(rows),"evaluable_event_n":len(ev),"unsupported_event_n":len(rows)-len(ev),"event_recall":float(len(det)/max(1,len(ev))),"detected_event_n":len(det),"detected_event_median_max_lead_seconds":float(np.median(leads)) if leads else 0.0,"events":rows}


def score_model(kind, Xtr, ytr, Xca, yca, Xpo, ypo, Xte, yte, meta_te, fold, events, seed):
    if kind == "lstm":
        csc = fit_channel_scaler(Xtr)
        a,b,c,d = [apply_channel_scaler(csc, X) for X in (Xtr,Xca,Xpo,Xte)]
        model, train_hist, best = train_lstm(a,ytr,b,yca,seed)
        rca = torch_prob(model,b); rpo = torch_prob(model,c); rte = torch_prob(model,d)
        extra = {"training_history":train_hist,"best_calibration_log_loss":best}
    else:
        sc = StandardScaler().fit(Xtr.reshape(len(Xtr),-1))
        a,b,c,d = [sc.transform(X.reshape(len(X),-1)) for X in (Xtr,Xca,Xpo,Xte)]
        model = HistGradientBoostingClassifier(max_iter=350,learning_rate=.04,max_leaf_nodes=31,min_samples_leaf=12,l2_regularization=2.0,class_weight="balanced",random_state=seed).fit(a,ytr)
        rca=model.predict_proba(b)[:,1]; rpo=model.predict_proba(c)[:,1]; rte=model.predict_proba(d)[:,1]; extra={}
    cal = v35.calibrator(rca,yca)
    pca=v35.apply_cal(cal,rca); ppo=v35.apply_cal(cal,rpo); pte=v35.apply_cal(cal,rte)
    plan=robust_policy(pca,yca,ppo,ypo); th=plan["chosen"]["threshold"]
    return {"kind":kind,"threshold_plan":plan,"test":v35.binary_metrics(yte,pte,th),"event_test":event_metrics(fold["test"],meta_te,pte,th,events),**extra}


def run_fold(data, events, fold, seed):
    Xtr,ytr=concatenate(data,fold["train"]); Xca,yca=concatenate(data,fold["calibration"]); Xpo,ypo=concatenate(data,fold["policy"]); Xte,yte,meta=concatenate(data,fold["test"],meta=True)
    for name,y,minpos in (("train",ytr,20),("calibration",yca,5),("policy",ypo,5),("test",yte,10)):
        cc=np.bincount(y,minlength=2)
        if len(y)<50 or cc[0]<30 or cc[1]<minpos: raise RuntimeError(f"{fold['name']} {name} support={cc.tolist()} n={len(y)}")
    return {"fold":fold["name"],"seed":seed,"devices":fold,"support":{"train":len(ytr),"train_positive":int((ytr==1).sum()),"calibration":len(yca),"calibration_positive":int((yca==1).sum()),"policy":len(ypo),"policy_positive":int((ypo==1).sum()),"test":len(yte),"test_positive":int((yte==1).sum())},"lstm":score_model("lstm",Xtr,ytr,Xca,yca,Xpo,ypo,Xte,yte,meta,fold,events,seed),"hgb_flat_baseline":score_model("hgb",Xtr,ytr,Xca,yca,Xpo,ypo,Xte,yte,meta,fold,events,seed)}


def aggregate(runs, key):
    return {"fpr":float(np.mean([r[key]["test"]["fpr"] for r in runs])),"sequence_recall":float(np.mean([r[key]["test"]["recall"] for r in runs])),"precision":float(np.mean([r[key]["test"]["precision"] for r in runs])),"f1":float(np.mean([r[key]["test"]["f1"] for r in runs])),"pr_auc":float(np.mean([r[key]["test"]["pr_auc"] for r in runs])),"event_recall":float(np.mean([r[key]["event_test"]["event_recall"] for r in runs])),"lead_seconds":float(np.mean([r[key]["event_test"]["detected_event_median_max_lead_seconds"] for r in runs]))}


def main():
    with tempfile.TemporaryDirectory(prefix="krishna-v39-") as tmp:
        td=Path(tmp); fp=td/"flowdata.zip"; ap=td/"annotations.zip"
        fm=v35.download(v35.FLOW_URL,fp); am=v35.download(v35.ANN_URL,ap)
        if fm["sha256"]!=v35.EXPECTED_FLOW_SHA or am["sha256"]!=v35.EXPECTED_ANN_SHA: raise RuntimeError("source hash mismatch")
        with zipfile.ZipFile(fp) as zf: flows,_=v35.load_flows(zf)
        with zipfile.ZipFile(ap) as za: events=v35.load_events(za)
    if set(DEVICES)&set(v35.TEST_DEVICES): raise RuntimeError("inspected V35 test device leaked into V39")
    data={}; support={}
    for d in DEVICES:
        ds=build_device_sequences(d,flows[d],events[d]); X=np.stack([s["seq"] for s in ds]); y=np.asarray([s["y"] for s in ds],int); meta=[{"device":d,"cutoff_ts":s["cutoff_ts"],"event_ids":s["event_ids"]} for s in ds]
        data[d]={"X":X,"y":y,"meta":meta}; support[d]={"samples":len(y),"positive":int((y==1).sum()),"benign":int((y==0).sum()),"events":len(events[d])}
        print(f"V39 {d} n={len(y)} pos={support[d]['positive']} seq={X.shape[1:]}",flush=True)
    inv=domain_invariance(data); print(json.dumps({"invariance":inv},indent=2),flush=True)
    report={"schema":"krishna-v39-unsw-invariant-temporal-lstm-dev-v1","source_provenance":{"flow":fm,"annotations":am},"representation":{"shape":[7,12]},"support":support,"invariance_gate":inv,"runs":[]}
    if not inv["pass"]:
        (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8"); raise RuntimeError("V39 exact temporal representation failed benign invariance gate")
    runs=[]
    for fold in FOLDS:
        for seed in SEEDS:
            print(f"V39 {fold['name']} seed={seed}",flush=True); r=run_fold(data,events,fold,seed); runs.append(r)
            print(json.dumps({"fold":r["fold"],"seed":seed,"lstm_test":r["lstm"]["test"],"lstm_event":{k:v for k,v in r["lstm"]["event_test"].items() if k!="events"},"hgb_test":r["hgb_flat_baseline"]["test"]},indent=2),flush=True)
    pm=aggregate(runs,"lstm"); bm=aggregate(runs,"hgb_flat_baseline")
    per_fold={}
    for f in FOLDS:
        rr=[r for r in runs if r["fold"]==f["name"]]
        per_fold[f["name"]]={"fpr":float(np.mean([r["lstm"]["test"]["fpr"] for r in rr])),"sequence_recall":float(np.mean([r["lstm"]["test"]["recall"] for r in rr])),"event_recall":float(np.mean([r["lstm"]["event_test"]["event_recall"] for r in rr])),"evaluable_event_n":int(min(r["lstm"]["event_test"]["evaluable_event_n"] for r in rr)),"lead_seconds":float(np.mean([r["lstm"]["event_test"]["detected_event_median_max_lead_seconds"] for r in rr]))}
    gate={"mean_test_fpr_pass":pm["fpr"]<=.05,"mean_sequence_recall_pass":pm["sequence_recall"]>=.70,"mean_event_recall_pass":pm["event_recall"]>=.80,"minimum_fold_event_support_pass":all(x["evaluable_event_n"]>=5 for x in per_fold.values()),"lead_time_pass":pm["lead_seconds"]>=60}; gate["pass"]=bool(all(gate.values()))
    report.update({"runs":runs,"lstm_mean":pm,"hgb_flat_baseline_mean":bm,"per_fold_lstm_mean":per_fold,"development_gate":gate,"claim_boundary":"development only; external/new final validation required"})
    (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    (OUT/"REPORT.md").write_text("# V39 invariant temporal LSTM\n\n```json\n"+json.dumps({"invariance":inv,"lstm_mean":pm,"hgb_flat_baseline_mean":bm,"per_fold_lstm_mean":per_fold,"development_gate":gate},indent=2)+"\n```\n",encoding="utf-8")
    print(json.dumps({"lstm_mean":pm,"hgb_flat_baseline_mean":bm,"per_fold_lstm_mean":per_fold,"development_gate":gate},indent=2),flush=True)
    if not gate["pass"]: raise RuntimeError("V39 temporal LSTM development gate not met")


if __name__=="__main__": main()
