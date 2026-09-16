from __future__ import annotations

"""V29 development: topology/periodicity precursor forecasting for unseen behaviour.

Only attack-free 8-minute histories enter train/calibration/policy/evaluation.
Raw network identities are never model features. They are used transiently inside
one scenario to compute causal aggregate topology churn, fan-out, overlap and
persistence features, then discarded.
"""

import json
import math
import sys
import urllib.request
from collections import Counter, defaultdict, deque
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
V23_DIR = HERE.parent / "v23"
if str(V23_DIR) not in sys.path:
    sys.path.insert(0, str(V23_DIR))
import v23_iot23_unseen_forecast as v23

v23.MAX_ROWS_PER_SCENARIO = 100_000
OUT = HERE / "artifacts" / "iot23_topology_precursor"
OUT.mkdir(parents=True, exist_ok=True)
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
WEIGHTS = [0.0, 0.15, 0.30, 0.45]
POLICY_BUDGETS = [0.005, 0.01, 0.015, 0.02]
EPS = 1e-3
LAGS = (1, 2, 4, 8)


def entropy(counter: Counter, n: int) -> float:
    if n <= 0 or len(counter) <= 1:
        return 0.0
    p = np.asarray(list(counter.values()), dtype=float) / float(n)
    h = -float(np.sum(p * np.log(np.maximum(p, 1e-12))))
    return h / max(math.log(len(counter)), 1e-12)


def overlap_fraction(cur: set, old: set) -> float:
    return float(len(cur & old) / max(1, len(cur)))


def new_fraction(cur: set, old: set) -> float:
    return float(len(cur - old) / max(1, len(cur)))


def fresh_agg():
    return {
        "count": 0,
        "src": set(), "dst": set(), "dport": set(), "edge": set(),
        "src_count": Counter(), "dst_count": Counter(), "dport_count": Counter(),
        "pair_count": Counter(), "src_dst": defaultdict(set), "src_port": defaultdict(set),
        "proto": Counter(), "service": Counter(), "state": Counter(), "port_bucket": Counter(),
        "num_sum": defaultdict(float), "num_sq": defaultdict(float), "num_max": defaultdict(float),
        "attack": 0, "families": set(),
    }


def zero_meta():
    return {"src": set(), "dst": set(), "dport": set(), "edge": set()}


def base_feature_count() -> int:
    # 16 structural + 8 numeric fields x3 + protocol/service/state fractions + 16 port buckets.
    return 16 + len(v23.NUM_FIELDS) * 3 + len(v23.PROTO_KEYS) + len(v23.SERVICE_KEYS) + len(v23.STATE_KEYS) + v23.PORT_BUCKETS


def topology_feature_count() -> int:
    # current overlap at 4 exact lags for edges/dst/ports + novelty against 8-bin unions.
    return len(LAGS) * 3 + 6


def stream_scenario(sc: str):
    url = f"{v23.BASE_URL}{sc}bro/conn.log.labeled"
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V29/1.0"})
    bins = {}
    total = 0
    with urllib.request.urlopen(req, timeout=120) as r:
        for raw in r:
            line = raw.decode("utf-8", errors="ignore").rstrip("\n")
            if not line or line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 21:
                continue
            try:
                ts = float(p[0])
            except Exception:
                continue
            b = int(ts // v23.WINDOW_SECONDS) * v23.WINDOW_SECONDS
            a = bins.setdefault(b, fresh_agg())
            src, dst, dport = p[2], p[4], p[5]
            a["count"] += 1
            a["src"].add(src); a["dst"].add(dst); a["dport"].add(dport); a["edge"].add((src, dst))
            a["src_count"][src] += 1; a["dst_count"][dst] += 1; a["dport_count"][dport] += 1
            a["pair_count"][(dst, dport)] += 1; a["src_dst"][src].add(dst); a["src_port"][src].add(dport)
            a["proto"][v23.cat_key(p[6], v23.PROTO_KEYS)] += 1
            a["service"][v23.cat_key(p[7], v23.SERVICE_KEYS)] += 1
            a["state"][v23.cat_key(p[11], v23.STATE_KEYS)] += 1
            a["port_bucket"][v23.stable_bucket(str(dport), v23.PORT_BUCKETS)] += 1
            for name, idx in v23.NUM_FIELDS:
                x = v23.fnum(p[idx]); a["num_sum"][name] += x; a["num_sq"][name] += x*x; a["num_max"][name] = max(a["num_max"][name], x)
            malicious, detail = v23.parse_label(p[-1])
            if malicious:
                a["attack"] = 1; a["families"].add(detail)
            total += 1
            if total >= v23.MAX_ROWS_PER_SCENARIO:
                break
    if not bins:
        return None

    lo, hi = min(bins), max(bins)
    metas = []
    rows = []
    for b in range(lo, hi + v23.WINDOW_SECONDS, v23.WINDOW_SECONDS):
        a = bins.get(b)
        if a is None:
            current_meta = zero_meta()
            base = np.zeros(base_feature_count(), np.float32)
            attack, fams = 0, tuple()
        else:
            n = max(1, a["count"])
            fanout = [len(x) for x in a["src_dst"].values()] or [0]
            portfan = [len(x) for x in a["src_port"].values()] or [0]
            fail = sum(a["state"].get(k, 0) for k in ("s0", "rej", "rsto", "rstr")) / n
            sf = a["state"].get("sf", 0) / n
            base_list = [
                math.log1p(a["count"]), math.log1p(len(a["src"])), math.log1p(len(a["dst"])),
                math.log1p(len(a["dport"])), math.log1p(len(a["edge"])),
                max(a["src_count"].values(), default=0) / n,
                max(a["dst_count"].values(), default=0) / n,
                max(a["dport_count"].values(), default=0) / n,
                max(a["pair_count"].values(), default=0) / n,
                entropy(a["src_count"], n), entropy(a["dst_count"], n), entropy(a["dport_count"], n),
                float(max(fanout)), float(np.mean(fanout)), float(max(portfan)), float(fail + 0.25*sf),
            ]
            for name, _ in v23.NUM_FIELDS:
                mean = a["num_sum"][name] / n
                var = max(0.0, a["num_sq"][name] / n - mean*mean)
                base_list.extend([math.log1p(max(0.0, mean)), math.log1p(math.sqrt(var)), math.log1p(max(0.0, a["num_max"][name]))])
            for key in v23.PROTO_KEYS: base_list.append(a["proto"][key] / n)
            for key in v23.SERVICE_KEYS: base_list.append(a["service"][key] / n)
            for key in v23.STATE_KEYS: base_list.append(a["state"][key] / n)
            for k in range(v23.PORT_BUCKETS): base_list.append(a["port_bucket"][k] / n)
            base = np.asarray(base_list, np.float32)
            current_meta = {"src": set(a["src"]), "dst": set(a["dst"]), "dport": set(a["dport"]), "edge": set(a["edge"])}
            attack, fams = int(a["attack"]), tuple(sorted(a["families"]))

        topo = []
        for lag in LAGS:
            old = metas[-lag] if len(metas) >= lag else zero_meta()
            topo.extend([
                overlap_fraction(current_meta["edge"], old["edge"]),
                overlap_fraction(current_meta["dst"], old["dst"]),
                overlap_fraction(current_meta["dport"], old["dport"]),
            ])
        prev8 = metas[-8:] if metas else []
        edge_u = set().union(*(x["edge"] for x in prev8)) if prev8 else set()
        dst_u = set().union(*(x["dst"] for x in prev8)) if prev8 else set()
        port_u = set().union(*(x["dport"] for x in prev8)) if prev8 else set()
        topo.extend([
            new_fraction(current_meta["edge"], edge_u), new_fraction(current_meta["dst"], dst_u), new_fraction(current_meta["dport"], port_u),
            overlap_fraction(current_meta["edge"], edge_u), overlap_fraction(current_meta["dst"], dst_u), overlap_fraction(current_meta["dport"], port_u),
        ])
        feat = np.concatenate([base, np.asarray(topo, np.float32)])
        rows.append((b, feat, attack, fams))
        metas.append(current_meta)

    print(f"V29 SCENARIO {sc.rstrip('/')} raw_rows={total} bins={len(rows)} span_min={(hi-lo)/60:.1f}", flush=True)
    return rows


def load_states():
    states = {}
    for i, sc in enumerate(v23.scenarios(), 1):
        name = sc.rstrip("/")
        print(f"V29 LOAD {i}: {name}", flush=True)
        try:
            rows = stream_scenario(sc)
            if rows:
                states[name] = rows
        except Exception as exc:
            print(f"V29 WARN {name}: {exc!r}", flush=True)
    if len(states) < 8:
        raise RuntimeError(f"Only {len(states)} IoT-23 scenarios loaded")
    return states


def lag_product(r: np.ndarray, lag: int) -> np.ndarray:
    if len(r) <= lag:
        return np.zeros(r.shape[1], np.float64)
    return np.mean(r[lag:] * r[:-lag], axis=0)


def make_sequences(states):
    S=[]; target=[]; clean=[]; scenario=[]; cutoff=[]; block=[]; eligible=[]; hist_fams=[]; future_fams=[]
    for sc, rows in states.items():
        t=np.asarray([x[0] for x in rows],np.int64); z=np.stack([x[1] for x in rows]).astype(np.float32)
        a=np.asarray([x[2] for x in rows],int); fam=[set(x[3]) for x in rows]; start=int(t[0])
        for i in range(v23.HISTORY_WINDOWS-1, len(rows)-v23.FUTURE_WINDOWS):
            lo=i-v23.HISTORY_WINDOWS+1; h=z[lo:i+1].astype(np.float64)
            med=np.median(h,axis=0); q25=np.quantile(h,.25,axis=0); q75=np.quantile(h,.75,axis=0)
            scale=np.maximum(q75-q25,EPS); r=np.clip((h-med)/scale,-12.0,12.0)
            last2=r[-2:].mean(0); prev2=r[-4:-2].mean(0); last4=r[-4:].mean(0); prev4=r[-8:-4].mean(0)
            periodic=np.concatenate([lag_product(r,k) for k in LAGS])
            summary=np.concatenate([
                r[-1], last2, last4, r.std(0), np.abs(np.diff(r,axis=0)).mean(0),
                r[-1]-r[0], last2-prev2, last4-prev4, periodic,
            ]).astype(np.float32)
            hf=tuple(sorted(set().union(*fam[lo:i+1]) if fam[lo:i+1] else set()))
            ff=tuple(tuple(sorted(x)) for x in fam[i+1:i+v23.FUTURE_WINDOWS+1])
            local=int(t[i]-start); bi=local//v23.BLOCK_SECONDS; pos=local%v23.BLOCK_SECONDS
            S.append(summary); target.append(int(a[i+1:i+v23.FUTURE_WINDOWS+1].max())); clean.append(bool(a[lo:i+1].max()==0))
            scenario.append(sc); cutoff.append(int(t[i])); block.append(f"{sc}:{bi}")
            eligible.append(bool(pos >= (v23.HISTORY_WINDOWS-1)*v23.WINDOW_SECONDS and pos <= v23.BLOCK_SECONDS-v23.FUTURE_WINDOWS*v23.WINDOW_SECONDS-v23.WINDOW_SECONDS))
            hist_fams.append(hf); future_fams.append(ff)
    return np.stack(S),np.asarray(target,int),np.asarray(clean,bool),np.asarray(scenario,object),np.asarray(cutoff,np.int64),np.asarray(block,object),np.asarray(eligible,bool),np.asarray(hist_fams,object),np.asarray(future_fams,object)


def calibrator(raw_p, y):
    if len(np.unique(y)) < 2:
        return None
    p=np.clip(raw_p,1e-6,1-1e-6); x=np.log(p/(1-p)).reshape(-1,1)
    return LogisticRegression(C=1e4,max_iter=400).fit(x,y)


def apply_cal(m, p):
    if m is None:
        return np.asarray(p,float)
    q=np.clip(p,1e-6,1-1e-6); x=np.log(q/(1-q)).reshape(-1,1)
    return m.predict_proba(x)[:,1]


def empirical_percentile(reference, values):
    ref=np.sort(np.asarray(reference,float))
    return np.searchsorted(ref,np.asarray(values,float),side="right")/float(max(1,len(ref)))


def choose_policy(y, ps, pn):
    best=None
    for w in WEIGHTS:
        score=(1.0-w)*ps+w*pn
        for budget in POLICY_BUDGETS:
            benign=score[y==0]
            if len(benign)<100:
                continue
            th=float(np.quantile(benign,1-budget,method="higher"))
            pred=score>=th; fpr=float(pred[y==0].mean()); rec=float(pred[y==1].mean()) if np.any(y==1) else 0.0
            if fpr<=0.0205:
                key=(rec,-fpr,-w,-budget)
                cand={"weight":float(w),"budget":float(budget),"threshold":th,"policy_fpr":fpr,"policy_recall":rec}
                if best is None or key>best[0]: best=(key,cand)
    if best is None:
        raise RuntimeError("No V29 policy configuration satisfies <=2.05% FPR")
    return best[1]


def run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed):
    future=v23.fam_future(future_fams,fam); hist=v23.fam_hist(hist_fams,fam); exposed=future|hist
    held_blocks=set(str(x) for x in block[exposed])
    notheld=np.asarray([str(b) not in held_blocks for b in block])
    def idx(name):
        return np.where(v23.split_mask(block,eligible,name) & clean & ~exposed & notheld)[0]
    tr,ca,po,te=idx("train"),idx("calibration"),idx("policy"),idx("test")
    for name,x,minpos in (("train",tr,10),("calibration",ca,2),("policy",po,2)):
        c=np.bincount(target[x],minlength=2)
        if len(x)<100 or c[1]<minpos or c[0]<100:
            raise RuntimeError(f"{fam} {name} support={c.tolist()} n={len(x)}")
    rng=np.random.default_rng(seed)
    if len(tr)>80000: tr=rng.choice(tr,80000,replace=False)
    med=np.nanmedian(S[tr].astype(np.float64),axis=0); med[~np.isfinite(med)]=0.0
    Z=S.astype(np.float32,copy=True); bad=~np.isfinite(Z)
    if bad.any(): Z[bad]=med[np.where(bad)[1]].astype(np.float32)
    scaler=StandardScaler().fit(Z[tr]); ztr=scaler.transform(Z[tr]); zca=scaler.transform(Z[ca]); zpo=scaler.transform(Z[po])
    sup=HistGradientBoostingClassifier(max_iter=350,learning_rate=.04,max_leaf_nodes=31,min_samples_leaf=15,l2_regularization=2.0,class_weight="balanced",random_state=seed)
    sup.fit(ztr,target[tr]); cal=calibrator(sup.predict_proba(zca)[:,1],target[ca])
    ps_po=apply_cal(cal,sup.predict_proba(zpo)[:,1])
    benign_tr=tr[target[tr]==0]
    if len(benign_tr)>50000: benign_tr=rng.choice(benign_tr,50000,replace=False)
    iso=IsolationForest(n_estimators=300,max_samples=min(8192,len(benign_tr)),contamination="auto",random_state=seed,n_jobs=1)
    iso.fit(scaler.transform(Z[benign_tr]))
    nov_ref=-iso.decision_function(zca[target[ca]==0])
    pn_po=empirical_percentile(nov_ref,-iso.decision_function(zpo))
    policy=choose_policy(target[po],ps_po,pn_po); th=policy["threshold"]
    def scores(ind):
        if not len(ind): return np.asarray([],float)
        zz=scaler.transform(Z[ind]); ps=apply_cal(cal,sup.predict_proba(zz)[:,1]); pn=empirical_percentile(nov_ref,-iso.decision_function(zz))
        return (1.0-policy["weight"])*ps+policy["weight"]*pn
    neg=te[(target[te]==0)]
    pos=np.where(eligible & clean & future)[0]
    events=v23.build_events(states,fam)
    if len(neg)<100 or len(pos)<1 or len(events)<1:
        raise RuntimeError(f"{fam} eval neg={len(neg)} pos={len(pos)} events={len(events)}")
    pneg=scores(neg); ppos=scores(pos)
    event_rows=[]
    for e in events:
        cand=np.where(eligible & clean & future & (scenario==e["scenario"]) & (cutoff<e["onset"]) & ((e["onset"]-cutoff)>=30) & ((e["onset"]-cutoff)<=240))[0]
        ss=scores(cand); hit=ss>=th; leads=(e["onset"]-cutoff[cand]).astype(int) if len(cand) else np.asarray([],int); det=leads[hit] if len(hit) else np.asarray([],int)
        event_rows.append({"scenario":e["scenario"],"onset":e["onset"],"candidate_windows":int(len(cand)),"detected":bool(hit.any()) if len(hit) else False,"max_lead_seconds":int(det.max()) if len(det) else None})
    return {
        "family":fam,"seed":seed,"clean_history_training_only":True,"heldout_blocks":len(held_blocks),"heldout_family_exposure_in_train_cal_policy":0,
        "split_support":{"train":len(tr),"calibration":len(ca),"policy":len(po),"test":len(te)},"policy_selection":policy,
        "test":{"reserved_clean_benign_n":int(len(neg)),"heldout_clean_future_positive_windows":int(len(pos)),"fpr":float(np.mean(pneg>=th)),"sequence_recall":float(np.mean(ppos>=th)),"event_n":len(event_rows),"event_recall":float(np.mean([e["detected"] for e in event_rows])),"events":event_rows},
    }


def main():
    states=load_states()
    print(f"V29 loaded scenarios={len(states)} state_features={base_feature_count()+topology_feature_count()}",flush=True)
    S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams=make_sequences(states)
    print(f"V29 histories={len(S)} clean={int(clean.sum())} clean_future_positive={int((clean & (target==1)).sum())}",flush=True)
    report={"schema":"krishna-v29-iot23-topology-precursor-dev-v1","strict_network_only":True,"raw_identity_model_feature":False,"development_families":DEV_FAMILIES,"seeds":SEEDS,"summary_feature_count":int(S.shape[1]),"results":{}}
    completed=[]
    for fam in DEV_FAMILIES:
        report["results"][fam]={}
        try:
            for seed in SEEDS:
                print(f"V29 family={fam} seed={seed}",flush=True)
                r=run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed)
                report["results"][fam][str(seed)]=r; print(json.dumps(r,indent=2),flush=True)
            completed.append(fam)
        except RuntimeError as exc:
            report["results"][fam]["skipped"]=str(exc); print(f"V29 SKIP {fam}: {exc}",flush=True)
    if len(completed)<3:
        (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
        raise RuntimeError(f"Only {len(completed)} V29 families completed")
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
    gate={
        "macro_fpr_pass":macro["fpr"]<=0.02,
        "macro_event_recall_pass":macro["event_recall"]>=0.80,
        "all_family_event_recall_ge_0_70":all(per[f]["event_recall"]>=0.70 for f in completed),
        "positive_lead_time_pass":all(per[f]["max_lead_seconds_mean"]>=30 for f in completed),
    }
    gate["pass"]=bool(all(gate.values()))
    report["macro_mean"]=macro; report["per_family_mean"]=per; report["development_gate"]=gate
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    (OUT/"REPORT.md").write_text("# V29 topology/periodicity unseen precursor development\n\n```json\n"+json.dumps({"macro_mean":macro,"per_family_mean":per,"development_gate":gate},indent=2)+"\n```\n",encoding="utf-8")
    print(json.dumps({"macro_mean":macro,"per_family_mean":per,"development_gate":gate},indent=2),flush=True)
    if not gate["pass"]:
        raise RuntimeError("V29 topology precursor development gate not met")


if __name__ == "__main__":
    main()
