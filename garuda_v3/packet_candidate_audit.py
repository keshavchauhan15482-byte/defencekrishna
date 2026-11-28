"""Reproducible development-only packet risk audit. Never installs a runtime.
Fit support using training/validation histories only, then evaluate a frozen
risk policy on the already-consumed campaign holdout. Abstentions remain misses
for positive recall; they are not true negatives or attack blocks.
"""
import argparse, hashlib, json
from pathlib import Path
import numpy as np
from .data import load_dataset, campaign_examples
from .train import batch
from .support_gate import fit, score
from .calibration import future_target, interval

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def audit(folder, output):
    folder=Path(folder); output=Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Audit output must be empty; preserve previous evidence")
    report=json.loads((folder/"metrics.json").read_text())
    config=report["config"]
    manifest=json.loads(Path(config["split_manifest"]).read_text())
    datasets=[load_dataset(p) for p in config["graphs"]]
    h,k,stride=config["history"],config["horizon"],config["stride"]
    splits,_=campaign_examples(datasets,manifest,h,k,stride)
    train,valid,test=[batch(datasets,s,h,k) for s in splits]
    gate=fit(train[0],train[2],valid[0],valid[2])
    support=score(gate,test[0],test[2])<=gate["threshold"]
    hashes=report["checkpoint_sha256"]
    for name in ("gnn_lstm.npz","gnn_lstm_test_predictions.npz","gnn_lstm_validation_predictions.npz"):
        if digest(folder/name)!=hashes[name]:raise ValueError("Artifact hash mismatch")
    threshold=report["models"]["gnn_lstm"]["alert_policy"]["threshold"]
    with np.load(folder/"gnn_lstm_test_predictions.npz",allow_pickle=False) as saved:
        if not np.array_equal(saved["example_indices"],np.asarray(splits[2])) or not np.array_equal(saved["labels"],test[4]):
            raise ValueError("Test examples do not match recorded labels and split")
        probs=saved["probabilities"]
    if probs.shape!=test[4].shape or not np.isfinite(probs).all() or np.any((probs<0)|(probs>1)):
        raise ValueError("Invalid predictions")
    y=future_target(test[4]); known=y>=0
    positive=known&(y==1); negative=known&(y==0)
    alert=(probs.max(1)>=threshold)&support
    p,n=int(positive.sum()),int(negative.sum())
    tp,fp=int((alert&positive).sum()),int((alert&negative).sum())
    sn=int((negative&support).sum())
    recall=tp/p if p else None
    accepted_fpr=fp/sn if sn else None
    fpr_ci=interval(fp,sn); recall_ci=interval(tp,p)
    coverage=float(support.mean())
    clean=(test[5]==0)&positive
    gates={"support_coverage_at_least_80pct":coverage>=.8,
           "accepted_negative_fpr_at_most_1pct":accepted_fpr is not None and accepted_fpr<=.01,
           "all_positive_recall_at_least_80pct":recall is not None and recall>=.8,
           "fpr_upper_95pct_at_most_1pct":fpr_ci[1] is not None and fpr_ci[1]<=.01,
           "recall_lower_95pct_at_least_80pct":recall_ci[0] is not None and recall_ci[0]>=.8,
           "clean_history_future_positive_evidence":bool(clean.any()),
           "fresh_independent_external_holdout":False}
    result={"scope":"development_reused_holdout","checkpoint_sha256":hashes["gnn_lstm.npz"],
            "support_fit":"training summaries and validation cutoff only",
            "counts":{"train":len(splits[0]),"validation":len(splits[1]),"test":len(splits[2]),
                      "supported_test":int(support.sum()),"accepted_negatives":sn,"positives":p,"negatives":n,
                      "true_positive_alerts":tp,"false_positive_alerts":fp,
                      "clean_history_future_positives":int(clean.sum())},
            "coverage":coverage,"accepted_negative_fpr":accepted_fpr,"all_positive_recall":recall,
            "fpr_descriptive_95pct":fpr_ci,"recall_descriptive_95pct":recall_ci,
            "gates":gates,"production_approved":False,
            "limitations":["weak labels","correlated overlapping samples","already consumed holdout","no live packet source","no verified compromise lead time"]}
    output.mkdir(parents=True,exist_ok=True)
    (output/"candidate_support_gate.json").write_text(json.dumps(gate,indent=2,allow_nan=False))
    (output/"audit.json").write_text(json.dumps(result,indent=2,allow_nan=False))
    print(json.dumps(result,indent=2,allow_nan=False))
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    audit(args.checkpoint,args.output)
