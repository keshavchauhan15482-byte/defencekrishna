from __future__ import annotations

import hashlib
import json
import math
import re
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

BASE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
OUT = Path("artifacts/iot23_unseen_forecast")
OUT.mkdir(parents=True, exist_ok=True)

WINDOW_SECONDS = 30
HISTORY_WINDOWS = 16
FUTURE_WINDOWS = 8
BLOCK_SECONDS = 3600
MAX_ROWS_PER_SCENARIO = 300_000
SEEDS = [42, 43, 44]
DEV_FAMILIES = ["c&c-heartbeat", "c&c", "partofahorizontalportscan"]
POLICY_FPR_BUDGETS = [0.005, 0.01, 0.02, 0.03, 0.05]
PORT_BUCKETS = 16

NUM_FIELDS = [
    ("duration", 8),
    ("orig_bytes", 9),
    ("resp_bytes", 10),
    ("missed_bytes", 14),
    ("orig_pkts", 16),
    ("orig_ip_bytes", 17),
    ("resp_pkts", 18),
    ("resp_ip_bytes", 19),
]
PROTO_KEYS = ["tcp", "udp", "icmp", "other"]
SERVICE_KEYS = ["dns", "http", "ssl", "ssh", "dhcp", "irc", "other"]
STATE_KEYS = ["sf", "s0", "rej", "rsto", "rstr", "sh", "oth", "other"]


def norm(x: str) -> str:
    return str(x).strip().lower().replace(" ", "_")


def stable_bucket(text: str, n: int) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=4).digest(), "big") % n


def scenarios():
    req = urllib.request.Request(BASE_URL, headers={"User-Agent": "KrishnaDefence-V23/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        html = r.read().decode("utf-8", errors="ignore")
    return sorted(set(re.findall(r'href="(CTU-IoT[^"]+/)"', html)))


def parse_label(field: str):
    parts = field.strip().split()
    if len(parts) < 3:
        return False, "unknown"
    malicious = parts[1].strip().lower() == "malicious"
    detail = parts[2].strip().lower() if malicious else "benign"
    return malicious, detail


def fnum(v: str) -> float:
    try:
        x = float(v)
        return x if math.isfinite(x) else 0.0
    except Exception:
        return 0.0


def cat_key(value: str, allowed):
    x = str(value).strip().lower()
    return x if x in allowed[:-1] else "other"


def new_agg():
    return {
        "count": 0,
        "src": set(), "dst": set(), "dport": set(), "edge": set(),
        "dst_count": Counter(), "dport_count": Counter(), "pair_count": Counter(),
        "proto": Counter(), "service": Counter(), "state": Counter(), "port_bucket": Counter(),
        "num_sum": defaultdict(float), "num_sq": defaultdict(float), "num_max": defaultdict(float),
        "attack": 0, "families": set(),
    }


def stream_scenario(sc: str):
    url = f"{BASE_URL}{sc}bro/conn.log.labeled"
    req = urllib.request.Request(url, headers={"User-Agent": "KrishnaDefence-V23/1.0"})
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
            b = int(ts // WINDOW_SECONDS) * WINDOW_SECONDS
            a = bins.setdefault(b, new_agg())
            a["count"] += 1
            src, dst, dport = p[2], p[4], p[5]
            a["src"].add(src); a["dst"].add(dst); a["dport"].add(dport); a["edge"].add((src, dst))
            a["dst_count"][dst] += 1; a["dport_count"][dport] += 1; a["pair_count"][(dst, dport)] += 1
            a["proto"][cat_key(p[6], PROTO_KEYS)] += 1
            a["service"][cat_key(p[7], SERVICE_KEYS)] += 1
            a["state"][cat_key(p[11], STATE_KEYS)] += 1
            a["port_bucket"][stable_bucket(str(dport), PORT_BUCKETS)] += 1
            for name, idx in NUM_FIELDS:
                x = fnum(p[idx]); a["num_sum"][name] += x; a["num_sq"][name] += x*x; a["num_max"][name] = max(a["num_max"][name], x)
            malicious, detail = parse_label(p[-1])
            if malicious:
                a["attack"] = 1; a["families"].add(detail)
            total += 1
            if total >= MAX_ROWS_PER_SCENARIO:
                break
    if not bins:
        return None
    lo, hi = min(bins), max(bins)
    rows = []
    for b in range(lo, hi + WINDOW_SECONDS, WINDOW_SECONDS):
        a = bins.get(b)
        if a is None:
            rows.append((b, np.zeros(feature_count(), np.float32), 0, tuple()))
            continue
        n = max(1, a["count"])
        feat = [
            math.log1p(a["count"]), math.log1p(len(a["src"])), math.log1p(len(a["dst"])),
            math.log1p(len(a["dport"])), math.log1p(len(a["edge"])),
            max(a["dst_count"].values(), default=0) / n,
            max(a["dport_count"].values(), default=0) / n,
            max(a["pair_count"].values(), default=0) / n,
        ]
        for name, _ in NUM_FIELDS:
            mean = a["num_sum"][name] / n
            var = max(0.0, a["num_sq"][name] / n - mean*mean)
            feat.extend([math.log1p(max(0.0, mean)), math.log1p(math.sqrt(var)), math.log1p(max(0.0, a["num_max"][name]))])
        for key in PROTO_KEYS: feat.append(a["proto"][key] / n)
        for key in SERVICE_KEYS: feat.append(a["service"][key] / n)
        for key in STATE_KEYS: feat.append(a["state"][key] / n)
        for k in range(PORT_BUCKETS): feat.append(a["port_bucket"][k] / n)
        rows.append((b, np.asarray(feat, np.float32), int(a["attack"]), tuple(sorted(a["families"]))))
    print(f"SCENARIO {sc.rstrip('/')} raw_rows={total} bins={len(rows)} span_min={(hi-lo)/60:.1f}", flush=True)
    return rows


def feature_count():
    return 8 + len(NUM_FIELDS)*3 + len(PROTO_KEYS) + len(SERVICE_KEYS) + len(STATE_KEYS) + PORT_BUCKETS


def load_states():
    states = {}
    for i, sc in enumerate(scenarios(), 1):
        name = sc.rstrip("/")
        print(f"LOAD {i}: {name}", flush=True)
        try:
            rows = stream_scenario(sc)
            if rows:
                states[name] = rows
        except Exception as e:
            print(f"WARN {name}: {e!r}", flush=True)
    if len(states) < 8:
        raise RuntimeError(f"Only {len(states)} IoT-23 scenarios loaded")
    return states


def make_sequences(states):
    S=[]; target=[]; clean=[]; scenario=[]; cutoff=[]; block=[]; eligible=[]; hist_fams=[]; future_fams=[]
    for sc, rows in states.items():
        t=np.asarray([x[0] for x in rows],np.int64); z=np.stack([x[1] for x in rows]); a=np.asarray([x[2] for x in rows],int); fam=[set(x[3]) for x in rows]
        start=int(t[0])
        for i in range(HISTORY_WINDOWS-1, len(rows)-FUTURE_WINDOWS):
            lo=i-HISTORY_WINDOWS+1
            h=z[lo:i+1]
            last4=h[-4:].mean(0); prev4=h[-8:-4].mean(0)
            last2=h[-2:].mean(0); prev2=h[-4:-2].mean(0)
            summary=np.concatenate([h[-1],h.mean(0),h.std(0),h.max(0),h[-1]-h[0],np.abs(np.diff(h,axis=0)).mean(0),last4-prev4,last2-prev2]).astype(np.float32)
            hf=tuple(sorted(set().union(*fam[lo:i+1]) if fam[lo:i+1] else set()))
            ff=tuple(tuple(sorted(x)) for x in fam[i+1:i+FUTURE_WINDOWS+1])
            local=int(t[i]-start); bi=local//BLOCK_SECONDS; pos=local%BLOCK_SECONDS
            S.append(summary); target.append(int(a[i+1:i+FUTURE_WINDOWS+1].max())); clean.append(bool(a[lo:i+1].max()==0)); scenario.append(sc); cutoff.append(int(t[i])); block.append(f"{sc}:{bi}")
            eligible.append(bool(pos >= (HISTORY_WINDOWS-1)*WINDOW_SECONDS and pos <= BLOCK_SECONDS-FUTURE_WINDOWS*WINDOW_SECONDS-WINDOW_SECONDS))
            hist_fams.append(hf); future_fams.append(ff)
    return np.stack(S),np.asarray(target,int),np.asarray(clean,bool),np.asarray(scenario,object),np.asarray(cutoff,np.int64),np.asarray(block,object),np.asarray(eligible,bool),np.asarray(hist_fams,object),np.asarray(future_fams,object)


def fam_future(future_fams,fam):
    return np.asarray([any(fam in set(step) for step in seq) for seq in future_fams],bool)


def fam_hist(hist_fams,fam):
    return np.asarray([fam in set(x) for x in hist_fams],bool)


def split_mask(block, eligible, which):
    buckets=np.asarray([stable_bucket(str(b),10) for b in block])
    wanted={"train":{0,1,2,3,4,5},"calibration":{6},"policy":{7},"test":{8,9}}[which]
    return eligible & np.isin(buckets,list(wanted))


def calibrate(p,y):
    if len(np.unique(y))<2: return None
    q=np.clip(p,1e-6,1-1e-6); x=np.log(q/(1-q)).reshape(-1,1)
    m=LogisticRegression(C=1e5,max_iter=300).fit(x,y); return m


def apply_cal(m,p):
    if m is None: return p
    q=np.clip(p,1e-6,1-1e-6); x=np.log(q/(1-q)).reshape(-1,1)
    return m.predict_proba(x)[:,1]


def threshold(yp,pp,budget):
    b=pp[yp==0]
    if len(b)<50: raise RuntimeError(f"policy benign support too small: {len(b)}")
    return float(np.quantile(b,1-budget,method="higher"))


def build_events(states,fam):
    events=[]
    for sc,rows in states.items():
        attacks=np.asarray([x[2] for x in rows],int); famsets=[set(x[3]) for x in rows]; times=np.asarray([x[0] for x in rows],np.int64)
        for i in range(1,len(rows)):
            if fam in famsets[i] and fam not in famsets[i-1]:
                lo=i-HISTORY_WINDOWS
                if lo<0: continue
                if attacks[lo:i].max()!=0: continue
                events.append({"scenario":sc,"onset":int(times[i]),"family":fam})
    return events


def run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed):
    future=fam_future(future_fams,fam); hist=fam_hist(hist_fams,fam); exposed=future|hist
    held_blocks=set(str(x) for x in block[exposed])
    def idx(name):
        m=split_mask(block,eligible,name) & ~exposed & np.asarray([str(b) not in held_blocks for b in block])
        return np.where(m)[0]
    tr,ca,po,te=idx("train"),idx("calibration"),idx("policy"),idx("test")
    for name,x in [("train",tr),("calibration",ca),("policy",po)]:
        c=np.bincount(target[x],minlength=2)
        if len(x)<100 or c.min()<5: raise RuntimeError(f"{fam} {name} support={c.tolist()} n={len(x)}")
    rng=np.random.default_rng(seed)
    if len(tr)>100000: tr=rng.choice(tr,100000,replace=False)
    med=np.nanmedian(S[tr].astype(np.float64),axis=0); med[~np.isfinite(med)]=0
    Z=S.astype(np.float32,copy=True); bad=~np.isfinite(Z)
    if bad.any(): Z[bad]=med[np.where(bad)[1]].astype(np.float32)
    scaler=StandardScaler().fit(Z[tr]); ztr=scaler.transform(Z[tr]); zca=scaler.transform(Z[ca]); zpo=scaler.transform(Z[po])
    model=HistGradientBoostingClassifier(max_iter=300,learning_rate=.05,max_leaf_nodes=31,min_samples_leaf=20,l2_regularization=1.5,class_weight="balanced",random_state=seed)
    model.fit(ztr,target[tr]); cal=calibrate(model.predict_proba(zca)[:,1],target[ca]); ppo=apply_cal(cal,model.predict_proba(zpo)[:,1])
    neg=te[clean[te] & (target[te]==0)]
    pos=np.where(clean & future)[0]
    events=build_events(states,fam)
    if len(neg)<100 or len(pos)<1 or len(events)<1: raise RuntimeError(f"{fam} eval neg={len(neg)} pos={len(pos)} events={len(events)}")
    def score(indices): return apply_cal(cal,model.predict_proba(scaler.transform(Z[indices]))[:,1]) if len(indices) else np.asarray([])
    pneg=score(neg); ppos=score(pos)
    curves={}
    for budget in POLICY_FPR_BUDGETS:
        th=threshold(target[po],ppo,budget)
        seq_recall=float(np.mean(ppos>=th))
        fpr=float(np.mean(pneg>=th))
        ev=[]
        for e in events:
            cand=np.where((scenario==e["scenario"]) & clean & future & (cutoff<e["onset"]) & ((e["onset"]-cutoff)>=WINDOW_SECONDS) & ((e["onset"]-cutoff)<=FUTURE_WINDOWS*WINDOW_SECONDS))[0]
            ps=score(cand); detected=ps>=th
            leads=(e["onset"]-cutoff[cand]).astype(int) if len(cand) else np.asarray([],int)
            detleads=leads[detected] if len(leads) else np.asarray([],int)
            ev.append({"scenario":e["scenario"],"onset":e["onset"],"candidate_windows":int(len(cand)),"detected":bool(detected.any()) if len(detected) else False,"max_lead_seconds":int(detleads.max()) if len(detleads) else None,"horizon_detected":{"60":bool(np.any(detected & (leads<=60))) if len(leads) else False,"120":bool(np.any(detected & (leads<=120))) if len(leads) else False,"240":bool(np.any(detected & (leads<=240))) if len(leads) else False}})
        curves[str(budget)]={"threshold":th,"reserved_benign_n":int(len(neg)),"heldout_clean_positive_windows":int(len(pos)),"fpr":fpr,"sequence_recall":seq_recall,"event_n":len(ev),"event_recall":float(np.mean([x["detected"] for x in ev])),"events":ev}
    return {"family":fam,"seed":seed,"heldout_blocks":len(held_blocks),"heldout_exposure_in_train_cal_policy":0,"train_n":int(len(tr)),"calibration_n":int(len(ca)),"policy_n":int(len(po)),"budget_curve":curves}


def main():
    states=load_states()
    print(f"Loaded scenarios={len(states)} feature_count={feature_count()}",flush=True)
    S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams=make_sequences(states)
    report={"schema":"krishna-v23-iot23-unseen-forecast-dev-v1","source":BASE_URL,"strict_network_only":True,"raw_ip_identity_model_feature":False,"window_seconds":WINDOW_SECONDS,"history_minutes":8,"future_minutes":4,"seeds":SEEDS,"development_families":DEV_FAMILIES,"scenario_count":len(states),"sequence_count":int(len(S)),"state_feature_count":feature_count(),"summary_feature_count":int(S.shape[1]),"results":{}}
    completed=[]
    for fam in DEV_FAMILIES:
        report["results"][fam]={}
        try:
            for seed in SEEDS:
                print(f"RUN family={fam} seed={seed}",flush=True)
                r=run_family(states,S,target,clean,scenario,cutoff,block,eligible,hist_fams,future_fams,fam,seed)
                report["results"][fam][str(seed)]=r
                print(json.dumps({"family":fam,"seed":seed,"curve":r["budget_curve"]},indent=2),flush=True)
            completed.append(fam)
        except RuntimeError as e:
            report["results"][fam]["skipped"]=str(e); print(f"SKIP {fam}: {e}",flush=True)
    if len(completed)<3: raise RuntimeError(f"Only {len(completed)} clean-onset families completed")
    budgets={}
    for b in POLICY_FPR_BUDGETS:
        k=str(b); per={}
        for fam in completed:
            vals=[report["results"][fam][str(s)]["budget_curve"][k] for s in SEEDS]
            per[fam]={"fpr":float(np.mean([x["fpr"] for x in vals])),"sequence_recall":float(np.mean([x["sequence_recall"] for x in vals])),"event_recall":float(np.mean([x["event_recall"] for x in vals])),"max_lead_seconds_mean":float(np.mean([max([e["max_lead_seconds"] or 0 for e in x["events"]],default=0) for x in vals]))}
        macro={q:float(np.mean([per[f][q] for f in completed])) for q in ["fpr","sequence_recall","event_recall","max_lead_seconds_mean"]}
        budgets[k]={"macro":macro,"per_family":per}
    feasible=[(k,v) for k,v in budgets.items() if v["macro"]["fpr"]<=0.02]
    chosen=max(feasible,key=lambda kv:(kv[1]["macro"]["event_recall"],kv[1]["macro"]["sequence_recall"])) if feasible else min(budgets.items(),key=lambda kv:kv[1]["macro"]["fpr"])
    report["budget_results"]=budgets; report["chosen_policy_budget"]=chosen[0]; report["macro_mean"]=chosen[1]["macro"]
    all_event=all(chosen[1]["per_family"][f]["event_recall"]>=0.8 for f in completed)
    report["development_gate"]={"macro_fpr_pass":chosen[1]["macro"]["fpr"]<=0.02,"macro_event_recall_pass":chosen[1]["macro"]["event_recall"]>=0.80,"all_family_event_recall_ge_0_80":all_event,"positive_lead_time_pass":all(chosen[1]["per_family"][f]["max_lead_seconds_mean"]>=30 for f in completed),"pass":bool(chosen[1]["macro"]["fpr"]<=0.02 and chosen[1]["macro"]["event_recall"]>=0.80 and all_event and all(chosen[1]["per_family"][f]["max_lead_seconds_mean"]>=30 for f in completed))}
    (OUT/"results.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    (OUT/"REPORT.md").write_text("# V23 IoT-23 unseen clean-onset forecast development\n\n```json\n"+json.dumps({"chosen_policy_budget":report["chosen_policy_budget"],"macro_mean":report["macro_mean"],"development_gate":report["development_gate"],"per_family":chosen[1]["per_family"]},indent=2)+"\n```\n",encoding="utf-8")
    print(json.dumps({"chosen_policy_budget":report["chosen_policy_budget"],"macro_mean":report["macro_mean"],"development_gate":report["development_gate"],"per_family":chosen[1]["per_family"]},indent=2),flush=True)
    if not report["development_gate"]["pass"]: raise RuntimeError("V23 clean-onset unseen forecasting development gate not met")


if __name__=="__main__":
    main()
