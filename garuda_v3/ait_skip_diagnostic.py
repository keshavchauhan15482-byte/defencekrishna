"""Post-exposure diagnostic of a history skip, NOT fresh final evaluation.

Only training fits trees. Validation chooses history-only versus augmented state
inputs and threshold. The previously exposed evaluation remains diagnostic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier
from .calibration import future_target, select_policy
from .data import load_dataset, campaign_examples
from .model import GraphWorldModel
from .train import batch, pooled, metrics
from .train_v45_core import infer


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cache',required=True);p.add_argument('--backbones',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();out=Path(a.output)
    if out.exists():raise ValueError('Output must be new')
    cache=Path(a.cache);base=Path(a.backbones)
    protocol=Path(__file__).resolve().parents[1]/'docs/release/ait_development_protocol.json'
    cfg=json.loads(protocol.read_text())
    ds=[load_dataset(cache/(c+'-graph.npz')) for c in ('fox','harrison','russellmitchell')]
    splits,_=campaign_examples(ds,cfg,8,4,cfg['stride'],allow_unknown=True)
    arrays=[batch(ds,s,8,4) for s in splits];targets=[future_target(x[4]) for x in arrays]
    histories=[pooled(x[0],x[2]).reshape(len(x[0]),-1) for x in arrays]
    rows=[];out.mkdir(parents=True)
    for seed in cfg['seeds']:
        for arch in ('lstm','gnn_lstm'):
            checkpoint=base/f'seed{seed}'/(arch+'.npz')
            before=hashlib.sha256(checkpoint.read_bytes()).hexdigest()
            model,_=GraphWorldModel.load(checkpoint)
            means=[infer(model,x,4)[0] for x in arrays]
            inputs={'history_only':histories,
                'history_plus_rollout':[np.concatenate([h,m.reshape(len(m),-1),
                  (m-pooled(x[0],x[2])[:,-1,None,:]).reshape(len(m),-1)],axis=1) for h,m,x in zip(histories,means,arrays)]}
            candidates=[]
            for name,x in inputs.items():
                keep=targets[0]>=0
                learner=ExtraTreesClassifier(n_estimators=200,min_samples_leaf=5,max_features=.7,random_state=seed,n_jobs=2)
                learner.fit(x[0][keep],targets[0][keep])
                val=learner.predict_proba(x[1])[:,1];known=targets[1]>=0
                policy=select_policy(targets[1][known],val[known],.01)
                t=policy.get('threshold');t=t if t is not None else 1.000001
                vm=metrics(targets[1],val,t)
                candidates.append((vm['recall'],-vm['fpr'],-vm['brier'],name,learner,policy))
            selected=max(candidates,key=lambda z:z[:3]);_,_,_,kind,learner,policy=selected
            # Policy and input kind are frozen before reading evaluation scores.
            probability=learner.predict_proba(inputs[kind][2])[:,1]
            threshold=policy.get('threshold');threshold=threshold if threshold is not None else 1.000001
            row=dict(seed=seed,architecture=arch,selected_readout=kind,
                selection='validation recall then FPR then Brier; train-only tree fitting',
                validation_policy=policy,test=metrics(targets[2],probability,threshold),
                backbone_sha256=before,backbone_unchanged=before==hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
                rollout_risk_value_established=False)
            rows.append(row);print(json.dumps(row),flush=True)
            np.savez_compressed(out/f'{arch}_seed{seed}_predictions.npz',probability=probability,labels=targets[2])
    report=dict(scope='Post-exposure development risk-head diagnostic; no fresh final claim',
        candidates_predeclared_in_code=True,rows=rows,automatic_promotion=False,automatic_containment=False,
        caveat='Same campaigns and correlated targets; source/domain and five-stage generalisation remain unproven')
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False))


if __name__=='__main__':main()
