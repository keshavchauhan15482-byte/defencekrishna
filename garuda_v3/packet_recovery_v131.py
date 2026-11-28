"""34-feature, state-first Garuda research recovery on real bundled packet captures.

All four campaigns are previously consumed development data. Schedule-assisted
labels are weak and never independent attack/compromise evidence. No deployment.
The candidate must beat persistence and separately pass calibration/support/risk
diagnostics; no threshold fitting or model selection uses test labels.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from .ps_complete import convert_pcap, attach_ids2018_weak_schedule, save_dataset, FEATURES
from .data import campaign_examples
from .train import batch
from .train_v46 import run as train
from .support_gate import fit, score
from .calibration import future_target, interval

ROOT=Path(__file__).resolve().parents[1]
CAMPAIGNS={
 "Thursday-22-02-2018":"train",
 "Friday-23-02-2018":"validation",
 "Thursday-01-03-2018":"test",
 "Friday-02-03-2018":"test",
}
SEEDS=(42,43,44)

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def label_counts(y):
    y=np.asarray(y)
    if y.ndim!=2 or not np.isin(y,[-1,0,1]).all():
        raise ValueError("Invalid future labels")
    target=future_target(y)
    return {str(v):int((target==v).sum()) for v in (-1,0,1)}

def risk_diagnostic(y,prob,supported,threshold):
    target=future_target(y)
    if prob.shape!=y.shape or supported.shape!=(len(y),) or not np.isfinite(prob).all() or np.any((prob<0)|(prob>1)):
        raise ValueError("Invalid prediction evidence")
    pos=target==1; neg=target==0
    alert=np.zeros(len(y),dtype=bool) if threshold is None else (prob.max(1)>=threshold)&supported
    p=int(pos.sum()); n=int((neg&supported).sum())
    tp=int((alert&pos).sum()); fp=int((alert&neg).sum())
    return {"accepted_negative_fpr":fp/n if n else None,
            "all_positive_recall":tp/p if p else None,
            "accepted_negatives":n,"all_positives":p,"fp":fp,"tp":tp,
            "fpr_descriptive_95pct":interval(fp,n),"recall_descriptive_95pct":interval(tp,p)}

def execute(output):
    out=Path(output)
    if out.exists() and any(out.iterdir()):
        raise ValueError("Use an empty output directory")
    out.mkdir(parents=True,exist_ok=True)
    manifest={role:[c for c,r in CAMPAIGNS.items() if r==role] for role in ("train","validation","test")}
    split=out/"split.json"; split.write_text(json.dumps(manifest,indent=2))
    graphs=[]; datasets=[]; provenance=[]
    for campaign,role in CAMPAIGNS.items():
        raw=ROOT/"datasets/ids2018/raw"/(campaign+".pcap")
        source=json.loads(Path(str(raw)+".source.json").read_text())
        if sha(raw)!=source["sha256"] or not source["original_member_crc_verified"]:
            raise ValueError("Capture provenance mismatch: "+campaign)
        data=convert_pcap(raw,campaign=campaign,mode="service",max_nodes=32,max_packets=2_000_000)
        data=attach_ids2018_weak_schedule(data,raw,campaign,max_packets=2_000_000)
        graph=out/(campaign+".npz"); save_dataset(data,graph)
        graphs.append(str(graph)); datasets.append(data)
        provenance.append({"campaign":campaign,"role":role,"capture_sha256":source["sha256"],
                           "graph_sha256":sha(graph),"windows":len(data["times"]),
                           "label_counts":{str(v):int((data["y"]==v).sum()) for v in (-1,0,1)}})
    # Non-overlapping 80s history + 40s future examples within each campaign.
    splits,_=campaign_examples(datasets,manifest,8,4,12,allow_unknown=True)
    arrays=[batch(datasets,s,8,4) for s in splits]
    counts={r:label_counts(a[4]) for r,a in zip(("train","validation","test"),arrays)}
    # A minimally populated training AND validation class is required before
    # fitting risk. Test class counts cannot influence training decisions.
    risk_ready=all(counts[r][str(v)]>=20 for r in ("train","validation") for v in (0,1))
    gate=fit(arrays[0][0],arrays[0][2],arrays[1][0],arrays[1][2])
    test_support=score(gate,arrays[2][0],arrays[2][2])<=gate["threshold"]
    coverage=float(test_support.mean())
    clean_positive=0
    for source,start in splits[2]:
        labels=datasets[source]["y"][start:start+12]
        clean_positive+=int((labels[:8]==0).all() and (labels[8:]==1).any())
    report={"scope":"development_reused_holdout","feature_count":len(FEATURES),
            "window_seconds":10,"history_seconds":80,"horizons_seconds":[10,20,30,40],
            "sources":provenance,"nonoverlapping_label_counts":counts,
            "risk_training_ready":risk_ready,"test_support_coverage":coverage,
            "weak_clean_history_future_positive_examples":clean_positive,
            "production_approved":False,"fresh_external_holdout":False,
            "verified_compromise_lead_time_seconds":None,"seeds":[]}
    def save():
        (out/"recovery_report.json").write_text(json.dumps(report,indent=2,allow_nan=False)+"\n")
    save()
    (out/"development_support_gate.json").write_text(json.dumps(gate,indent=2,allow_nan=False))
    for seed in SEEDS:
        dest=out/("seed-"+str(seed))
        args=argparse.Namespace(graphs=graphs,split_manifest=str(split),output=str(dest),
          history=8,horizon=4,stride=12,seed=seed,state_epochs=12,risk_epochs=12,
          stage_epochs=1,patience=4,fpr_budget=.01,stage_supervision=False,
          state_only=not risk_ready,evaluation_scope="development_reused_holdout")
        result=train(args)
        row={"seed":seed,"models":{}}
        for architecture in ("lstm","gnn_lstm"):
            m=result["models"][architecture]
            diag=None
            if m["risk_head_trained"]:
                with np.load(dest/(architecture+"_test_predictions.npz"),allow_pickle=False) as pred:
                    if not np.array_equal(pred["labels"],arrays[2][4]) or not np.array_equal(pred["example_indices"],np.asarray(splits[2])):
                        raise ValueError("Frozen test prediction alignment mismatch")
                    diag=risk_diagnostic(pred["labels"],pred["probabilities"],test_support,m["validation_alert_selection"]["threshold"])
            row["models"][architecture]={"state_gate_passed":m["state_gate_passed"],
                "test_state_mse":m["state_mse"],"test_persistence_mse":m["state_persistence_mse"],
                "risk_head_trained":m["risk_head_trained"],"risk_diagnostic":diag}
        report["seeds"].append(row);save()
    print(json.dumps(report,indent=2,allow_nan=False))
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",required=True)
    execute(p.parse_args().output)
