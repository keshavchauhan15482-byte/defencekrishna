from __future__ import annotations

"""V24 development: adaptive, strict-network unseen-behaviour forecasting.

This is a development successor to the frozen V23 baseline.  It keeps the same
30-second / 8-minute-history / 4-minute-future task and the same held-out
behaviours, but removes environment-scale drift by building each history in its
own causal robust coordinate system.  A benign-only IsolationForest novelty
head is fused with the supervised future-risk head.  Fusion weight and alert
threshold are selected only on the policy split; held-out evaluation is never
used for selection.
"""

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

import v23_iot23_unseen_forecast as v23

v23.MAX_ROWS_PER_SCENARIO = 100_000
OUT = Path("artifacts/iot23_adaptive_v24")
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = list(v23.DEV_FAMILIES)
WEIGHTS = [0.0, 0.25, 0.5, 0.75, 1.0]
POLICY_BUDGETS = [0.005, 0.01, 0.02]
EPS = 1e-3


def adaptive_sequences(states):
    S=[]; target=[]; clean=[]; scenario=[]; cutoff=[]; block=[]; eligible=[]; hist_fams=[]; future_fams=[]
    for sc, rows in states.items():
        t=np.asarray([x[0] for x in rows],np.int64)
        z=np.stack([x[1] for x in rows]).astype(np.float32)
        a=np.asarray([x[2] for x in rows],int)
        fam=[set(x[3]) for x in rows]
        start=int(t[0])
        for i in range(v23.HISTORY_WINDOWS-1, len(rows)-v23.FUTURE_WINDOWS):
            lo=i-v23.HISTORY_WINDOWS+1
            h=z[lo:i+1].astype(np.float64)
            med=np.median(h,axis=0)
            q25=np.quantile(h,0.25,axis=0); q75=np.quantile(h,0.75,axis=0)
            scale=np.maximum(q75-q25,EPS)
            r=np.clip((h-med)/scale,-12.0,12.0)
            last2=r[-2:].mean(0)
            prev2=r[-4:-2].mean(0)
            last4=r[-4:].mean(0)
            prev4=r[-8:-4].mean(0)
            # All features are causal transformations of the preceding history.
            # No raw IP identity, UID, labels or future rows enter this vector.
            summary=np.concatenate([
                r[-1],
                last2,
                last4,
                r.std(0),
                np.abs(np.diff(r,axis=0)).mean(0),
                r[-1]-r[0],
                last2-prev2,
                last4-prev4,
            ]).astype(np.float32)
            hf=tuple(sorted(set().union(*fam[lo:i+1]) if fam[lo:i+1] else set()))
            ff=tuple(tuple(sorted(x)) for x in fam[i+1:i+v23.FUTURE_WINDOWS+1])
            local=int(t[i]-start); bi=local//v23.BLOCK_SECONDS; pos=local%v23.BLOCK_SECONDS
            S.append(summary)
            target.append(int(a[i+1:i+v23.FUTURE_WINDOWS+1].max()))
            clean.append(bool(a[lo:i+1].max()==0))
            scenario.append(sc); cutoff.append(int(t[i])); block.append(f"{sc}:{bi}")
            eligible.append(bool(pos >= (v23.HISTORY_WINDOWS-1)*v23.WINDOW_SECONDS and pos <= v23.BLOCK_SECONDS-v23.FUTURE_WINDOWS*v23.WINDOW_SECONDS-v23.WINDOW_SECONDS))
            hist_fams.append(hf); future_fams.append(ff)
    if not S:
        raise RuntimeError("No adaptive histories")
    return np.stack(S),np.asarray(target,int),np.asarray(clean,bool),np.asarray(scenario,object),np.asarray(cutoff,np.int64),np.asarray(block,object),np.asarray(eligible,bool),np.asarray(hist_fams,object),np.asarray(future_fams,object)


def empirical_percentile(reference, values):
    ref=np.sort(np.asarray(reference,float))
    if len(ref)<20:
        raise RuntimeError(f"novelty reference too small: {len(ref)}")
    return np.searchsorted(ref,np.asarray(values,float),side="right")/float(len(ref))


def calibrator(raw_p,y):
    if len(np.unique(y))<2:
        return None
    p=np.clip(raw_p,1e-6,1-1e-6)
    x=np.log(p/(1-p)).reshape(-1,1)
    return LogisticRegression(C=1e4,max_iter=400).fit(x,y)


def apply_cal(m,p):
    if m is None:
        return np.asarray(p,float)
    q=np.clip(p,1e-6,1-1e-6)
    return m.predict_proba(np.log(q/(1-q)).reshape(-1,1))[:,1]


def threshold_from_benign(scores,budget):
    b=np.asarray(scores,float)
    if len(b)<50:
        raise RuntimeError(f"policy benign support too small: {len(b)}")
    return float(np.quantile(b,1-budget,method="higher"))


def choose_policy(y_policy,p_sup_policy,p_nov_policy):
    best=None
    for w in WEIGHTS:
        fused=(1.0-w)*p_sup_policy+w*p_nov_policy
        benign=fused[y_policy==0]
        for budget in POLICY_BUDGETS:
            th=threshold_from_benign(benign,budget)
            pred=fused>=th
            fpr=float(pred[y_policy==0].mean()) if np.any(y_policy==0) else 1.0
            recall=float(pred[y_policy==1].mean()) if np.any(y_policy==1) else 0.0
            cand={"weight":float(w),"budget":float(budget),"threshold":th,"policy_fpr":fpr,"policy_recall":recall}
            # Policy-only selection: maximize known-development recall while
            # respecting the frozen <=2% FPR budget, then prefer lower FPR and
            # less novelty weight for stability.
            key=(recall,-fpr,-w,-budget)
            if fpr<=0.0205 and (best is None or key>best[0]):
                best=(key,cand)
    if best is None:
        raise RuntimeError("No policy fusion satisfies <=2.05% policy FPR")
    return best[1]


def run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed):
    future=v23.fam_future(future_fams,fam); hist=v23.fam_hist(hist_fams,fam); exposed=future|hist
    held_blocks=set(str(x) for x in block[exposed])
    def idx(name):
        m=v23.split_mask(block,eligible,name) & ~exposed & np.asarray([str(b) not in held_blocks for b in block])
        return np.where(m)[0]
    tr,ca,po,te=idx("train"),idx("calibration"),idx("policy"),idx("test")
    for name,x in (("train",tr),("calibration",ca),("policy",po)):
        c=np.bincount(target[x],minlength=2)
        if len(x)<100 or c.min()<5:
            raise RuntimeError(f"{fam} {name} support={c.tolist()} n={len(x)}")
    rng=np.random.default_rng(seed)
    if len(tr)>100000:
        tr=rng.choice(tr,100000,replace=False)
    med=np.nanmedian(S[tr].astype(np.float64),axis=0); med[~np.isfinite(med)]=0.0
    Z=S.astype(np.float32,copy=True); bad=~np.isfinite(Z)
    if bad.any():
        Z[bad]=med[np.where(bad)[1]].astype(np.float32)
    scaler=StandardScaler().fit(Z[tr])
    ztr=scaler.transform(Z[tr]); zca=scaler.transform(Z[ca]); zpo=scaler.transform(Z[po])
    sup=HistGradientBoostingClassifier(max_iter=300,learning_rate=.05,max_leaf_nodes=31,min_samples_leaf=20,l2_regularization=1.5,class_weight="balanced",random_state=seed)
    sup.fit(ztr,target[tr])
    cal=calibrator(sup.predict_proba(zca)[:,1],target[ca])
    ps_ca=apply_cal(cal,sup.predict_proba(zca)[:,1])
    ps_po=apply_cal(cal,sup.predict_proba(zpo)[:,1])

    benign_train=tr[clean[tr] & (target[tr]==0)]
    if len(benign_train)>50000:
        benign_train=rng.choice(benign_train,50000,replace=False)
    zben=scaler.transform(Z[benign_train])
    iso=IsolationForest(n_estimators=250,max_samples=min(8192,len(zben)),contamination="auto",random_state=seed,n_jobs=1)
    iso.fit(zben)
    nov_ca=-iso.decision_function(zca)
    nov_ref=nov_ca[(target[ca]==0) & clean[ca]]
    pn_po=empirical_percentile(nov_ref,-iso.decision_function(zpo))
    policy=choose_policy(target[po],ps_po,pn_po)

    def scores(indices):
        if not len(indices): return np.asarray([],float)
        zz=scaler.transform(Z[indices])
        ps=apply_cal(cal,sup.predict_proba(zz)[:,1])
        pn=empirical_percentile(nov_ref,-iso.decision_function(zz))
        return (1.0-policy["weight"])*ps+policy["weight"]*pn

    neg=te[clean[te] & (target[te]==0)]
    pos=np.where(clean & future)[0]
    events=v23.build_events(states,fam)
    if len(neg)<100 or len(pos)<1 or len(events)<1:
        raise RuntimeError(f"{fam} eval neg={len(neg)} pos={len(pos)} events={len(events)}")
    pneg=scores(neg); ppos=scores(pos); th=policy["threshold"]
    event_rows=[]
    for e in events:
        cand=np.where((scenario==e["scenario"]) & clean & future & (cutoff<e["onset"]) & ((e["onset"]-cutoff)>=v23.WINDOW_SECONDS) & ((e["onset"]-cutoff)<=v23.FUTURE_WINDOWS*v23.WINDOW_SECONDS))[0]
        ss=scores(cand); hit=ss>=th
        leads=(e["onset"]-cutoff[cand]).astype(int) if len(cand) else np.asarray([],int)
        detleads=leads[hit] if len(leads) else np.asarray([],int)
        event_rows.append({"scenario":e["scenario"],"onset":e["onset"],"candidate_windows":int(len(cand)),"detected":bool(hit.any()) if len(hit) else False,"max_lead_seconds":int(detleads.max()) if len(detleads) else None,"horizon_detected":{"60":bool(np.any(hit & (leads<=60))) if len(leads) else False,"120":bool(np.any(hit & (leads<=120))) if len(leads) else False,"240":bool(np.any(hit & (leads<=240))) if len(leads) else False}})
    return {
        "family":fam,"seed":seed,"heldout_blocks":len(held_blocks),"heldout_exposure_in_train_cal_policy":0,
        "policy_selection":policy,
        "test":{"reserved_benign_n":int(len(neg)),"heldout_clean_positive_windows":int(len(pos)),"fpr":float(np.mean(pneg>=th)),"sequence_recall":float(np.mean(ppos>=th)),"event_n":len(event_rows),"event_recall":float(np.mean([e["detected"] for e in event_rows])),"events":event_rows},
    }


def main():
    states=v23.load_states()
    print(f"V24 loaded scenarios={len(states)} state_feature_count={v23.feature_count()}",flush=True)
    S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams=adaptive_sequences(states)
    report={"schema":"krishna-v24-iot23-adaptive-unseen-forecast-dev-v1","purpose":"Development only after V23 baseline failure; held-out evaluation never used to select fusion weight or threshold.","strict_network_only":True,"raw_ip_identity_model_feature":False,"window_seconds":v23.WINDOW_SECONDS,"history_minutes":8,"future_minutes":4,"adaptive_summary_feature_count":int(S.shape[1]),"seeds":SEEDS,"development_families":DEV_FAMILIES,"fusion_weights_pre_enumerated":WEIGHTS,"policy_fpr_budgets":POLICY_BUDGETS,"results":{}}
    completed=[]
    for fam in DEV_FAMILIES:
        report["results"][fam]={}
        try:
            for seed in SEEDS:
                print(f"V24 family={fam} seed={seed}",flush=True)
                r=run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed)
                report["results"][fam][str(seed)]=r
                print(json.dumps(r,indent=2),flush=True)
            completed.append(fam)
        except RuntimeError as e:
            report["results"][fam]["skipped"]=str(e); print(f"SKIP {fam}: {e}",flush=True)
    if len(completed)<3:
        raise RuntimeError(f"Only {len(completed)} V24 families completed")
    per={}
    for fam in completed:
        vals=[report["results"][fam][str(s)]["test"] for s in SEEDS]
        per[fam]={
            "fpr":float(np.mean([x["fpr"] for x in vals])),
            "sequence_recall":float(np.mean([x["sequence_recall"] for x in vals])),
            "event_recall":float(np.mean([x["event_recall"] for x in vals])),
            "max_lead_seconds_mean":float(np.mean([max([e["max_lead_seconds"] or 0 for e in x["events"]],default=0) for x in vals])),
        }
    macro={k:float(np.mean([per[f][k] for f in completed])) for k in ["fpr","sequence_recall","event_recall","max_lead_seconds_mean"]}
    gate={"macro_fpr_pass":macro["fpr"]<=0.02,"macro_event_recall_pass":macro["event_recall"]>=0.80,"all_family_event_recall_ge_0_80":all(per[f]["event_recall"]>=0.80 for f in completed),"positive_lead_time_pass":all(per[f]["max_lead_seconds_mean"]>=30 for f in completed)}
    gate["pass"]=bool(all(gate.values()))
    report["macro_mean"]=macro; report["per_family_mean"]=per; report["development_gate"]=gate
    (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    (OUT/"REPORT.md").write_text("# V24 adaptive unseen clean-onset forecast development\n\n```json\n"+json.dumps({"macro_mean":macro,"per_family_mean":per,"development_gate":gate},indent=2)+"\n```\n",encoding="utf-8")
    print(json.dumps({"macro_mean":macro,"per_family_mean":per,"development_gate":gate},indent=2),flush=True)
    if not gate["pass"]:
        raise RuntimeError("V24 adaptive unseen forecasting development gate not met")


if __name__=="__main__":
    main()
