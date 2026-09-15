"""Frozen-forecast risk readout experiment with separate calibration/policy blocks.
Targets are future malicious-flow presence from existing weak schedule labels,
not compromise probability. This is a reused-holdout diagnostic.
"""
import hashlib
import argparse
import json
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from .data import load_dataset
from .train import batch,pooled,infer,metrics
from .model import GraphWorldModel
from .calibration import fit,apply,select_policy,future_target,interval

OUT=Path('datasets/v12')
CONFIG=dict(history=8,horizon=4,stride=2,seeds=[42,43,44],horizons=[1,2,4],
    train_fraction=.70,calibration_end_fraction=.85,embargo_windows=12,
    variants=['history_only','history_plus_lstm','history_plus_gnn_lstm'],
    readout=dict(type='logistic_regression',C=1.,max_iter=2000,class_weight='balanced'),
    fpr_budget=.01,calibration='monotone Platt; separate development block',
    policy_selection='separate final development block; no test optimization',
    test_scope='Reused DoS15 and infiltration March1 capture diagnostics',
    target='Any malicious-flow-labelled window in next 1/2/4 minutes',
    verified_compromise_target=False,supervised_stage_target=False,automatic_containment_approved=False)


def partition(datasets,development_count):
    splits=[[],[],[],[]];details=[];width=CONFIG['history']+CONFIG['horizon']
    hashes=[d['metadata']['source_sha256'] for d in datasets]
    if len(set(hashes))!=len(hashes):raise ValueError('Duplicate source hash')
    for s,d in enumerate(datasets):
        n=len(d['times']);a=int(n*.70);b=int(n*.85)
        if (d['metadata']['mode'],d['metadata']['max_nodes'],d['metadata']['window_seconds'])!=('host',64,60):raise ValueError('Incompatible graph schema')
        details.append(dict(campaign=d['metadata']['campaign_id'],windows=n,train_stop=a,calibration_start=a+12,calibration_stop=b,policy_start=b+12,test_only=s>=development_count))
        for i in range(0,n-width+1,CONFIG['stride']):
            if np.any(np.diff(d['times'][i:i+width])!=60):continue
            group=3 if s>=development_count else 0 if i+width<=a else 1 if i>=a+12 and i+width<=b else 2 if i>=b+12 else None
            if group is not None:splits[group].append((s,i))
    if any(not split for split in splits):raise ValueError('Empty data partition')
    return splits,details


def describe(y,p,threshold):
    known=y>=0;y=y[known];p=p[known]
    if not len(y):return dict(samples=0,status='unknown_targets_only')
    r=metrics(y,p,threshold if threshold is not None else 1.000001)
    tn,fp=r['confusion_matrix'][0];fn,tp=r['confusion_matrix'][1]
    r.update(policy_enabled=threshold is not None,fpr_95pct=interval(fp,fp+tn),recall_95pct=interval(tp,tp+fn))
    return r


def readiness(labels):
    counts=[dict(benign=int((y==0).sum()),malicious=int((y==1).sum()),unknown=int((y<0).sum())) for y in labels]
    reasons=[]
    if min(counts[0]['benign'],counts[0]['malicious'])<1:reasons.append('Training lacks both known classes')
    if min(counts[1]['benign'],counts[1]['malicious'])<20:reasons.append('Calibration has fewer than 20 cases in one class')
    if min(counts[2]['benign'],counts[2]['malicious'])<1:reasons.append('Policy selection lacks both known classes')
    return dict(counts=counts,ready_for_supervised_policy_evaluation=not reasons,reasons=reasons,
        limitation='Count gate alone does not establish independent incidents or deployment readiness')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic-only',action='store_true',help='Explicitly allow non-actionable fits despite insufficient calibration/policy classes')
    args=parser.parse_args()
    OUT.mkdir(exist_ok=True);cfg=OUT/'config.json'
    if cfg.exists() and json.loads(cfg.read_text())!=CONFIG:raise ValueError('Frozen configuration changed')
    cfg.write_text(json.dumps(CONFIG,indent=2))
    paths=[f'datasets/ids2018/labelled/{n}.npz' for n in ('Thursday-22-02-2018','Friday-23-02-2018','Friday-02-03-2018')]
    paths+=['datasets/ids2018/fresh_holdout/labelled_graph.npz','datasets/ids2018/labelled/Thursday-01-03-2018.npz']
    datasets=[load_dataset(p) for p in paths];splits,details=partition(datasets,3)
    arrays=[batch(datasets,s,8,4) for s in splits]
    audit={str(h):readiness([future_target(a[4][:,:h]) for a in arrays]) for h in CONFIG['horizons']}
    (OUT/'readiness.json').write_text(json.dumps(audit,indent=2))
    if not args.diagnostic_only and any(not a['ready_for_supervised_policy_evaluation'] for a in audit.values()):
        raise ValueError('Insufficient calibration/policy labels; inspect readiness.json. Only --diagnostic-only permits exploratory non-actionable fitting')
    observed=[pooled(a[0],a[2]).reshape(len(a[0]),-1) for a in arrays]
    (OUT/'splits.json').write_text(json.dumps(dict(sources=[dict(path=p,sha256=d['metadata']['source_sha256'],campaign=d['metadata']['campaign_id']) for p,d in zip(paths,datasets)],boundaries=details,examples=[len(s) for s in splits]),indent=2))
    rows=[]
    for variant in CONFIG['variants']:
        for seed in CONFIG['seeds']:
            features=observed;state_hash=None
            if variant!='history_only':
                architecture=variant.removeprefix('history_plus_')
                folder=Path(f'garuda_v3/artifacts/v10/combined_{architecture}_state_only_{seed}')
                checkpoint=folder/f'{architecture}.npz';model,meta=GraphWorldModel.load(checkpoint)
                state_hash=hashlib.sha256(checkpoint.read_bytes()).hexdigest()
                report=json.loads((folder/'metrics.json').read_text())
                if report['checkpoint_sha256'].get(checkpoint.name)!=state_hash:raise ValueError('State checkpoint hash mismatch')
                if set(meta['training_campaigns']) & {d['metadata']['campaign_id'] for d in datasets[3:]}:raise ValueError('Test campaign was used by frozen forecaster')
                for p in model.parameters():p.requires_grad=False
                means=[infer(model,a,4)[0] for a in arrays]
                features=[np.concatenate([obs,mu.reshape(len(mu),-1)],axis=1) for obs,mu in zip(observed,means)]
            for horizon in CONFIG['horizons']:
                name=f'{variant}_seed{seed}_h{horizon}';folder=Path('garuda_v3/artifacts/v12')/name
                if folder.exists():raise ValueError('Existing run preserved: '+str(folder))
                folder.mkdir(parents=True)
                labels=[future_target(a[4][:,:horizon]) for a in arrays];keep=labels[0]>=0
                if len(np.unique(labels[0][keep]))<2:raise ValueError('Insufficient training classes')
                scaler=StandardScaler().fit(features[0][keep])
                xs=[scaler.transform(x) for x in features]
                lr=LogisticRegression(C=1.,max_iter=2000,class_weight='balanced',random_state=seed).fit(xs[0][keep],labels[0][keep])
                raw=[lr.predict_proba(x)[:,1] for x in xs]
                cal_keep=labels[1]>=0;cal=fit(labels[1][cal_keep],raw[1][cal_keep])
                probs=[apply(p,cal) for p in raw];policy_keep=labels[2]>=0
                selection=select_policy(labels[2][policy_keep],probs[2][policy_keep],.01)
                # Selection may be reported diagnostically, but uncalibrated heads are not actionable.
                actionable=cal['status']=='fitted' and selection.get('confidence_gate_passed',False)
                threshold=selection['threshold']
                result=dict(name=name,variant=variant,seed=seed,horizon_minutes=horizon,
                    source_state_checkpoint_sha256=state_hash,
                    class_counts=[{'unknown':int((y<0).sum()),'benign':int((y==0).sum()),'malicious':int((y==1).sum())} for y in labels],
                    calibration=cal,validation_policy=selection,actionable=bool(actionable),
                    automatic_containment_approved=False,test={},
                    warning_lead_time=None,stage_accuracy=None,evidence_scope=CONFIG['test_scope'])
                for source,d in enumerate(datasets[3:],3):
                    mask=np.array([s==source for s,i in splits[3]])
                    clean=mask & (arrays[3][5]==0)
                    result['test'][d['metadata']['campaign_id']]=dict(
                        validation_selected_policy=describe(labels[3][mask],probs[3][mask],threshold),
                        fixed_half_threshold_diagnostic=describe(labels[3][mask],probs[3][mask],.5),
                        clean_history=describe(labels[3][clean],probs[3][clean],threshold),
                        unknown_targets=int((labels[3][mask]<0).sum()),
                        clean_history_future_positive_cases=int((labels[3][clean]==1).sum()))
                weights=folder/'risk_readout.npz'
                np.savez_compressed(weights,weights=lr.coef_,bias=lr.intercept_,center=scaler.mean_,scale=scaler.scale_,
                    metadata=json.dumps(dict(variant=variant,horizon=horizon,state_checkpoint_sha256=state_hash,
                        calibration=cal,threshold=threshold,automatic_containment_approved=False,actionable=bool(actionable),
                        target=CONFIG['target'],scope=CONFIG['test_scope'])))
                np.savez_compressed(folder/'test_predictions.npz',probability=probs[3],raw_probability=raw[3],labels=labels[3],example_indices=np.asarray(splits[3]),clean_history=arrays[3][5]==0)
                result['checkpoint_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.glob('*.npz')}
                (folder/'metrics.json').write_text(json.dumps(result,indent=2,allow_nan=False));rows.append(result)
                print(name,'calibration',cal['status'],'policy',selection['status'],'actionable',actionable,flush=True)
    summary=[]
    for variant in CONFIG['variants']:
        for horizon in CONFIG['horizons']:
            rr=[r for r in rows if r['variant']==variant and r['horizon_minutes']==horizon]
            for family in rr[0]['test']:
                record=dict(variant=variant,horizon_minutes=horizon,campaign=family,actionable_seeds=sum(r['actionable'] for r in rr))
                for kind in ('validation_selected_policy','fixed_half_threshold_diagnostic'):
                    results=[r['test'][family][kind] for r in rr];record[kind]={}
                    for field in ('fpr','recall','precision','f1','brier'):
                        vals=[r[field] for r in results if r.get(field) is not None]
                        record[kind][field]=dict(mean=float(np.mean(vals)),seed_sd=float(np.std(vals,ddof=1))) if vals else None
                    record[kind]['samples']=results[0].get('samples',0)
                    record[kind]['confusion_matrices']=[r.get('confusion_matrix') for r in results]
                summary.append(record)
    (OUT/'summary.json').write_text(json.dumps(dict(config=CONFIG,rows=summary,fitted_readouts=len(rows)),indent=2,allow_nan=False))


if __name__=='__main__':main()
