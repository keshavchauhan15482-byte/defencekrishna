from __future__ import annotations

import hashlib, json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score
from sklearn.preprocessing import StandardScaler

import v16_xiiotid_unseen_forecast as base

DEV_FAMILIES = ["bruteforce", "false_data_injection", "modbus_register_reading", "mqtt_cloud_broker_subscription", "tcp relay"]
FINAL_FAMILIES = ["exfiltration", "dictionary", "insider_malcious", "c&c", "reverse_shell"]
WINDOW_SECONDS = 10
HISTORY_WINDOWS = 48
FUTURE_WINDOWS = 24
BLOCK_SECONDS = 3600
HASH_BUCKETS = 10
POLICY_FPR_BUDGETS = [0.005, 0.01, 0.02, 0.03, 0.05]
OUT = Path("artifacts/v19_dev")
OUT.mkdir(parents=True, exist_ok=True)


def bucket(v):
    return int.from_bytes(hashlib.blake2b(str(v).strip().lower().encode("utf-8", errors="ignore"), digest_size=4).digest(), "big") % HASH_BUCKETS


def build_state(df, dt, y, family_col, binary_col, date_col, ts_col):
    src_col = base.pick_col(df.columns, ["Scr_IP", "Src_IP", "Source_IP", "source_ip"])
    dst_col = base.pick_col(df.columns, ["Des_IP", "Dst_IP", "Destination_IP", "dst_ip"])
    dport_col = base.pick_col(df.columns, ["Des_port", "Dst_port", "Destination_port", "dst_port"])
    proto_col = base.pick_col(df.columns, ["Protocol", "Proto"])
    service_col = base.pick_col(df.columns, ["Service", "Serv"])
    excluded = {x for x in [family_col, binary_col, date_col, ts_col, src_col, dst_col] if x}
    excluded.update(c for c in df.columns if base.norm(c) in {"class1", "class2", "class3"})
    numeric, audit = base.strict_network_features(df, excluded)

    f = pd.DataFrame({"dt": dt, "y": y, "family": df[family_col].astype(str).map(base.norm_label), "src": df[src_col].astype(str) if src_col else "GLOBAL"})
    if dst_col: f["dst"] = df[dst_col].astype(str)
    if dport_col: f["dport"] = df[dport_col].astype(str)
    for c in numeric: f[c] = base.numericize(df[c])
    cats = []
    for prefix, col in (("proto", proto_col), ("service", service_col)):
        if col:
            b = df[col].fillna("__missing__").astype(str).map(bucket).to_numpy()
            for k in range(HASH_BUCKETS):
                name = f"{prefix}_b{k}"; f[name] = (b == k).astype(np.float32); cats.append(name)
    f = f.dropna(subset=["dt", "y"]).copy()
    f["bin"] = f["dt"].dt.floor(f"{WINDOW_SECONDS}s")
    f["y"] = f["y"].astype(int)
    g = f.groupby(["src", "bin"], sort=True)
    s = g[numeric].agg(["mean", "std", "max"])
    s.columns = ["__".join(x) for x in s.columns]
    if cats: s = s.join(g[cats].mean())
    s["flow_count"] = g.size().astype(float)
    s["attack_now"] = g["y"].max().astype(int)
    s["family_now"] = g["family"].agg(lambda x: tuple(sorted({base.norm_label(v) for v in x if base.norm_label(v) != "normal"})))
    if dst_col:
        s["unique_dst"] = g["dst"].nunique().astype(float)
    if dport_col:
        s["unique_dst_port"] = g["dport"].nunique().astype(float)
    s = s.reset_index().sort_values(["src", "bin"]).reset_index(drop=True)
    fcols = [c for c in s.columns if c not in ["src", "bin", "attack_now", "family_now"]]
    return s, fcols, numeric, cats, {"source_ip": src_col, "destination_ip": dst_col, "protocol": proto_col, "service": service_col}


def epoch_seconds(series):
    origin = pd.Timestamp("1970-01-01", tz="UTC")
    return ((series - origin).dt.total_seconds().round().astype("int64")).to_numpy()


def make_summary_sequences(state, fcols):
    S, target, cutoff, clean, hist_fams, future_steps = [], [], [], [], [], []
    for _, g in state.groupby("src", sort=False):
        g = g.sort_values("bin").reset_index(drop=True)
        t = epoch_seconds(g["bin"]); a = g["attack_now"].to_numpy(int); z = g[fcols].to_numpy(np.float32); fam = list(g["family_now"])
        for i in range(HISTORY_WINDOWS - 1, len(g) - FUTURE_WINDOWS):
            lo = i - HISTORY_WINDOWS + 1
            span = t[lo:i + FUTURE_WINDOWS + 1]
            if len(span) != HISTORY_WINDOWS + FUTURE_WINDOWS or not np.all(np.diff(span) == WINDOW_SECONDS): continue
            h = z[lo:i+1]
            last6 = h[-6:].mean(0); prev6 = h[-12:-6].mean(0) if len(h) >= 12 else h[:6].mean(0)
            summary = np.concatenate([h[-1], h.mean(0), h.std(0), h.max(0), h[-1]-h[0], np.abs(np.diff(h,axis=0)).mean(0), last6-prev6]).astype(np.float32)
            hsets = [set(x) for x in fam[lo:i+1]]; fsets = [set(x) for x in fam[i+1:i+FUTURE_WINDOWS+1]]
            S.append(summary); target.append(int(a[i+1:i+FUTURE_WINDOWS+1].max())); cutoff.append(int(t[i])); clean.append(bool(a[lo:i+1].max()==0)); hist_fams.append(tuple(sorted(set().union(*hsets) if hsets else set()))); future_steps.append(tuple(tuple(sorted(x)) for x in fsets))
    if not S: raise RuntimeError("No contiguous 10-second histories")
    return np.stack(S), np.asarray(target,int), np.asarray(cutoff,np.int64), np.asarray(clean,bool), np.asarray(hist_fams,object), np.asarray(future_steps,object)


def family_mask(future_steps, family):
    return np.asarray([any(family in set(step) for step in seq) for seq in future_steps], bool)


def history_mask(hist_fams, family): return np.asarray([family in set(x) for x in hist_fams], bool)


def split_blocks(cutoff):
    blocks = cutoff // BLOCK_SECONDS; pos = cutoff % BLOCK_SECONDS
    eligible = (pos >= (HISTORY_WINDOWS-1)*WINDOW_SECONDS) & (pos <= BLOCK_SECONDS - FUTURE_WINDOWS*WINDOW_SECONDS - 1)
    ub = np.sort(np.unique(blocks[eligible])); rank = {int(b):i for i,b in enumerate(ub)}; mod=np.asarray([rank.get(int(b),-1)%10 for b in blocks])
    return {"train":np.where(eligible & np.isin(mod,[0,1,2,3,4,5]))[0],"calibration":np.where(eligible & (mod==6))[0],"policy":np.where(eligible & (mod==7))[0],"test":np.where(eligible & np.isin(mod,[8,9]))[0]}, blocks, eligible


def calibrator(raw_p, y):
    p=np.clip(raw_p,1e-6,1-1e-6); x=np.log(p/(1-p)).reshape(-1,1); m=LogisticRegression(C=1e6,max_iter=300); m.fit(x,y); return m

def apply_cal(m,p): p=np.clip(p,1e-6,1-1e-6); return m.predict_proba(np.log(p/(1-p)).reshape(-1,1))[:,1]


def threshold_from_policy(y,p,budget):
    benign=p[y==0]
    return float(np.quantile(benign,1-budget,method="higher"))


def metrics(y,p,th,clean_pos=None):
    pred=p>=th; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel(); d={"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp),"fpr":float(fp/(fp+tn)) if fp+tn else None,"recall":float(tp/(tp+fn)) if tp+fn else None,"precision":float(tp/(tp+fp)) if tp+fp else 0.0,"f1":float(f1_score(y,pred,zero_division=0)),"pr_auc":float(average_precision_score(y,p)) if len(np.unique(y))>1 else None,"threshold":float(th)}
    if clean_pos is not None: d.update(clean_history_future_positive_n=int(clean_pos.sum()),clean_history_future_positive_recall=float(pred[clean_pos].mean()) if clean_pos.any() else None)
    return d


def run_family(S,target,clean,split,blocks,eligible,hist_fams,future_steps,family,seed):
    future=family_mask(future_steps,family); exposed=future|history_mask(hist_fams,family); held=set(int(x) for x in np.unique(blocks[eligible&exposed]))
    def safe(name):
        idx=split[name]; keep=np.asarray([(int(blocks[i]) not in held) and not exposed[i] for i in idx]); return idx[keep]
    tr,ca,po=safe("train"),safe("calibration"),safe("policy")
    for name,idx in (("train",tr),("calibration",ca),("policy",po)):
        c=np.bincount(target[idx],minlength=2)
        if c.min()<20: raise RuntimeError(f"{family}: {name} support {c.tolist()}")
    rng=np.random.default_rng(seed)
    if len(tr)>80000: tr=rng.choice(tr,80000,replace=False)
    med=np.nanmedian(S[tr].astype(np.float64),axis=0); med[~np.isfinite(med)]=0
    Z=S.astype(np.float32,copy=True); bad=~np.isfinite(Z); Z[bad]=med[np.where(bad)[1]].astype(np.float32)
    scaler=StandardScaler().fit(Z[tr]); ztr=scaler.transform(Z[tr]); zca=scaler.transform(Z[ca]); zpo=scaler.transform(Z[po])
    model=HistGradientBoostingClassifier(max_iter=300,learning_rate=.05,max_leaf_nodes=31,min_samples_leaf=20,l2_regularization=1.5,class_weight="balanced",random_state=seed)
    model.fit(ztr,target[tr]); cal=calibrator(model.predict_proba(zca)[:,1],target[ca]); ppo=apply_cal(cal,model.predict_proba(zpo)[:,1])
    allidx=np.where(eligible)[0]; posidx=allidx[future[allidx]]; negbase=split["test"]; negidx=negbase[np.asarray([(int(blocks[i]) not in held) and clean[i] and target[i]==0 for i in negbase])]
    if len(posidx)<10 or len(negidx)<100: raise RuntimeError(f"{family}: test support pos={len(posidx)} neg={len(negidx)}")
    ev=np.concatenate([posidx,negidx]); yev=np.concatenate([np.ones(len(posidx),int),np.zeros(len(negidx),int)]); pev=apply_cal(cal,model.predict_proba(scaler.transform(Z[ev]))[:,1]); cp=np.concatenate([clean[posidx],np.zeros(len(negidx),bool)])
    curves={}
    for b in POLICY_FPR_BUDGETS:
        th=threshold_from_policy(target[po],ppo,b); curves[str(b)]=metrics(yev,pev,th,cp)
    return {"family":family,"seed":seed,"heldout_blocks":len(held),"heldout_exposure_in_train_cal_policy":0,"test_support":{"unseen_positive":int(len(posidx)),"clean_history_unseen_positive":int(clean[posidx].sum()),"clean_benign_negative":int(len(negidx))},"budget_curve":curves}


def main():
    import kagglehub
    root=Path(kagglehub.dataset_download("munaalhawawreh/xiiotid-iiot-intrusion-dataset")); csv_path=max(root.rglob("*.csv"),key=lambda p:p.stat().st_size)
    if base.sha256(csv_path)!="7b9290057ee42e784da3c0d84b781815502c9205c74175c96374e71a5ffd98a0": raise RuntimeError("source hash changed")
    df=pd.read_csv(csv_path,low_memory=False); dt,date_col,ts_col,_,_=base.parse_time(df); y,binary_col,_=base.detect_binary_label(df); family_col=base.detect_family_col(df,binary_col)
    state,fcols,numeric,cats,cols=build_state(df,dt,y,family_col,binary_col,date_col,ts_col); S,target,cutoff,clean,hist,fut=make_summary_sequences(state,fcols); split,blocks,eligible=split_blocks(cutoff)
    report={"schema":"krishna-v19-dev-highres-tree-v1","purpose":"Development only; final frozen families not scored.","window_seconds":WINDOW_SECONDS,"history_minutes":8,"future_minutes":4,"development_families":DEV_FAMILIES,"final_validation_families_not_scored":FINAL_FAMILIES,"network_numeric":numeric,"network_categorical":cats,"columns":cols,"state_feature_count":len(fcols),"summary_feature_count":int(S.shape[1]),"results":{}}
    completed=[]
    for fam in DEV_FAMILIES:
        report["results"][fam]={}
        try:
            for seed in base.SEEDS:
                print(f"V19 family={fam} seed={seed}",flush=True); r=run_family(S,target,clean,split,blocks,eligible,hist,fut,fam,seed); report["results"][fam][str(seed)]=r; print(json.dumps(r,indent=2),flush=True)
            completed.append(fam)
        except RuntimeError as e: report["results"][fam]["skipped"]=str(e); print("SKIP",fam,e,flush=True)
    if len(completed)<3: raise RuntimeError(f"only {len(completed)} families completed")
    budgets={}
    for b in POLICY_FPR_BUDGETS:
        key=str(b); fam_metrics=[]
        for fam in completed:
            fam_metrics.append({k:float(np.mean([report["results"][fam][str(s)]["budget_curve"][key][k] for s in base.SEEDS])) for k in ["fpr","recall","precision","f1"]})
        budgets[key]={"macro":{k:float(np.mean([m[k] for m in fam_metrics])) for k in fam_metrics[0]},"per_family":{fam:fam_metrics[i] for i,fam in enumerate(completed)}}
    feasible=[(b,v) for b,v in budgets.items() if v["macro"]["fpr"]<=0.02]
    chosen=max(feasible,key=lambda x:x[1]["macro"]["recall"]) if feasible else min(budgets.items(),key=lambda x:x[1]["macro"]["fpr"])
    report["budget_results"]=budgets; report["chosen_policy_budget"]=chosen[0]; report["macro_mean"]=chosen[1]["macro"]
    report["development_target"]={"target_macro_fpr":0.02,"target_macro_unseen_recall":0.80,"macro_fpr_pass":chosen[1]["macro"]["fpr"]<=0.02,"macro_recall_pass":chosen[1]["macro"]["recall"]>=0.80,"all_family_recall_ge_0_80":all(m["recall"]>=0.80 for m in chosen[1]["per_family"].values()),"ready_to_unlock_frozen_final_validation":bool(chosen[1]["macro"]["fpr"]<=0.02 and chosen[1]["macro"]["recall"]>=0.80 and all(m["recall"]>=0.80 for m in chosen[1]["per_family"].values()))}
    (OUT/"results.json").write_text(json.dumps(report,indent=2)); (OUT/"REPORT.md").write_text("# V19 high-resolution development\n\n```json\n"+json.dumps({"chosen_policy_budget":report["chosen_policy_budget"],"macro_mean":report["macro_mean"],"per_family":budgets[chosen[0]]["per_family"],"development_target":report["development_target"]},indent=2)+"\n```\n")
    print("V19_FINAL",json.dumps({"chosen":chosen[0],"macro":report["macro_mean"],"per_family":budgets[chosen[0]]["per_family"],"target":report["development_target"]},indent=2),flush=True)

if __name__=="__main__": main()
