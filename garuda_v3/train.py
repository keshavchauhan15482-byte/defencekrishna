"""Time-ordered training/validation/test with future-only supervision and ablations."""
import argparse
import hashlib
import json
import time
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix, average_precision_score, brier_score_loss
from .data import load_dataset, build_examples, campaign_examples, development_examples, SCHEMA, FEATURES
from .model import GraphWorldModel, loss
from .autograd import Adam
from .annotations import STAGES, MITRE
from .state_evaluation import state_evidence
from .event_evaluation import evaluate as evaluate_events
from .calibration import fit as fit_calibration, apply as apply_calibration, select_policy, family_report, future_target


def batch(datasets, indices, history, horizon):
    xs=[];adjs=[];masks=[];ys=[];targets=[];ongoing=[]
    for source,start in indices:
        d=datasets[source];stop=start+history
        xs.append(d['x'][start:stop]);adjs.append(d['adj'][start:stop]);masks.append(d['mask'][start:stop])
        future=d['x'][stop:stop+horizon]; fm=d['mask'][stop:stop+horizon]
        targets.append((future*fm[:,:,None]).sum(axis=1)/np.maximum(fm.sum(axis=1,keepdims=True),1))
        ys.append(d['y'][stop:stop+horizon]);ongoing.append(bool(d['y'][start:stop].any()))
    return tuple(np.asarray(a,dtype=np.float32) for a in (xs,adjs,masks,targets,ys,ongoing))


def pooled(x,mask): return (x*mask[:,:,:,None]).sum(axis=2)/np.maximum(mask.sum(axis=2,keepdims=True),1)


def metrics(y,p,threshold):
    y=np.asarray(y,dtype=int);p=np.asarray(p)
    known=y>=0;y=y[known];p=p[known]
    if not len(y):return {'samples':0,'status':'insufficient_samples'}
    pred=p>=threshold;tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return dict(samples=len(y),positives=int(y.sum()),f1=float(f1_score(y,pred,zero_division=0)),
        precision=float(precision_score(y,pred,zero_division=0)),recall=float(recall_score(y,pred,zero_division=0)),
        fpr=float(fp/(fp+tn)) if fp+tn else None,pr_auc=float(average_precision_score(y,p)) if 0<y.sum()<len(y) else None,
        brier=float(brier_score_loss(y,p)),confusion_matrix=[[int(tn),int(fp)],[int(fn),int(tp)]])


def threshold(y,p):
    known=np.asarray(y)>=0;y=np.asarray(y)[known];p=np.asarray(p)[known]
    if len(np.unique(y))<2:return 1.000001
    return float(max(np.linspace(.05,.95,37),key=lambda t:(metrics(y,p,t)['f1'],-metrics(y,p,t)['fpr'] if metrics(y,p,t)['fpr'] is not None else 0,t)))


def infer(model,arrays,horizon,batch_size=64):
    x,a,m,*_=arrays;means=[];sigmas=[];risks=[]
    for i in range(0,len(x),batch_size):
        mu,sd,r=model.forward(x[i:i+batch_size],a[i:i+batch_size],m[i:i+batch_size],horizon)
        means.append(mu.data);sigmas.append(sd.data);risks.append(r.data)
    return np.concatenate(means),np.concatenate(sigmas),np.concatenate(risks)


def block_interval(y,p,t,seed=42):
    """Contiguous-example block bootstrap; not a substitute for held-out campaigns."""
    known=np.asarray(y)>=0;y=np.asarray(y)[known];p=np.asarray(p)[known]
    if len(y)<40:return None
    rng=np.random.default_rng(seed);values=[];block=20
    for _ in range(200):
        starts=rng.integers(0,max(1,len(y)-block+1),size=int(np.ceil(len(y)/block)))
        ids=np.concatenate([np.arange(s,min(s+block,len(y))) for s in starts])[:len(y)]
        values.append(f1_score(y[ids],p[ids]>=t,zero_division=0))
    return {'f1_95pct_interval':np.quantile(values,[.025,.975]).tolist(),'method':'contiguous-example block bootstrap','block_examples':block}


def stage_batch(datasets,indices,history,horizon):
    return np.asarray([datasets[s]['stage_y'][i+history:i+history+horizon] for s,i in indices],dtype=np.float32)


def stage_infer(model,arrays,horizon):
    x,a,m,*_=arrays
    return np.concatenate([model.forward(x[i:i+64],a[i:i+64],m[i:i+64],horizon,return_stages=True)[3].data for i in range(0,len(x),64)])


def alert_threshold(y,p,fpr_budget=.05):
    """Select any-horizon alert policy on validation only, with an explicit FPR budget."""
    y=np.asarray(y,dtype=int);p=np.asarray(p)
    if len(np.unique(y))<2:return 1.0,'insufficient_validation_classes'
    candidates=np.unique(np.r_[0.,p,np.nextafter(p,1.),1.])
    acceptable=[(t,metrics(y,p,t)) for t in candidates]
    acceptable=[(t,m) for t,m in acceptable if m['fpr']<=fpr_budget]
    if not acceptable:return 1.0,'no_feasible_threshold'
    t,_=max(acceptable,key=lambda pair:(pair[1]['recall'],-pair[1]['fpr'],pair[0]))
    return float(t),'validation_only_fpr_budget'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graphs',nargs='+',required=True);parser.add_argument('--output',default='garuda_v3/artifacts/run')
    parser.add_argument('--epochs',type=int,default=20);parser.add_argument('--history',type=int,default=8)
    parser.add_argument('--horizon',type=int,default=4);parser.add_argument('--stride',type=int,default=8);parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--decoder',choices=['absolute','residual'],default='absolute')
    parser.add_argument('--allow-unknown-labels',action='store_true',help='Retain contiguous observed states; mask unknown risk supervision')
    parser.add_argument('--calibrate',action='store_true',help='Fit monotone risk calibration on validation only')
    parser.add_argument('--balance-risk',action='store_true',help='Per-horizon class weights from training only')
    parser.add_argument('--fpr-budget',type=float,default=.01)
    parser.add_argument('--stage-supervision',action='store_true')
    parser.add_argument('--split-manifest',help='JSON train/validation/test campaign IDs')
    parser.add_argument('--evaluation-scope',choices=['development_reused_holdout','new_predeclared_holdout'],default='development_reused_holdout')
    args=parser.parse_args()
    if not 0<args.fpr_budget<1:parser.error('FPR budget must be between zero and one')
    if not 1<=args.epochs<=300:parser.error('epochs must be 1..300')
    datasets=[load_dataset(p) for p in args.graphs]
    if args.allow_unknown_labels and not args.split_manifest:parser.error('Masked supervision requires explicit campaign split')
    if args.evaluation_scope=='new_predeclared_holdout' and not args.split_manifest:parser.error('New holdout requires a predeclared campaign manifest')
    if args.split_manifest:
        manifest=json.loads(Path(args.split_manifest).read_text())
        splits,boundaries=(development_examples if manifest.get('development') else campaign_examples)(datasets,manifest,args.history,args.horizon,args.stride,allow_unknown=args.allow_unknown_labels)
    else:splits,boundaries=build_examples(datasets,args.history,args.horizon,args.stride)
    if args.stage_supervision and any('stage_y' not in d or d['stage_y'].shape!=(len(d['y']),len(STAGES)) or not np.isin(d['stage_y'],[-1,0,1]).all() for d in datasets):
        parser.error('Valid explicit stage_y annotations required for every capture')
    stage_arrays=[stage_batch(datasets,split,args.history,args.horizon) for split in splits] if args.stage_supervision else [None]*3
    if args.stage_supervision and not (stage_arrays[0]==1).any():parser.error('Training requires positive stage annotations')
    arrays=[batch(datasets,s,args.history,args.horizon) for s in splits]
    out=Path(args.output)
    if out.exists() and any(out.iterdir()):parser.error('Output must be empty; existing checkpoints are preserved')
    out.mkdir(parents=True,exist_ok=True)
    report=dict(schema=SCHEMA,config=vars(args),split_boundaries=boundaries,
        sources=[{k:v for k,v in d['metadata'].items() if k!='node_names'} for d in datasets],
        split_counts=[{'examples':len(a[0]),'future_positive_windows':int((a[4]==1).sum()),'clean_histories':int((1-a[5]).sum()),'clean_history_future_positive_examples':int((a[4][a[5]==0]==1).any(axis=1).sum())} for a in arrays],
        target='malicious flow present in each FUTURE completed-flow window; not compromise probability',
        selection='validation loss checkpoint; validation F1 thresholds; test not used for checkpoint selection',
        evaluation_scope=args.evaluation_scope,
        models={},limitations=['overlapping examples are correlated','no external deployment validation']+(['service graphs do not describe host lateral movement'] if datasets[0]['metadata']['mode']=='service' else [])+(['no incident/compromise labels'] if not any(d['metadata'].get('incidents') for d in datasets) else [])+(['no supervised stage head'] if not args.stage_supervision else []))
    train,valid,test=arrays
    positive_weight=np.clip((train[4]==0).sum(0)/np.maximum((train[4]==1).sum(0),1),.1,10) if args.balance_risk else 1.
    report['training_positive_weight']=np.asarray(positive_weight).tolist()
    report['feature_scaling']='Fixed documented physical/log transforms, no dataset-fitted scaling.'
    val_y=valid[4][:,-1].astype(int);test_y=test[4][:,-1].astype(int)
    if len(np.unique(train[4][:,-1][train[4][:,-1]>=0]))<2:raise ValueError('Training target has one class')
    flat=[pooled(a[0],a[2]).reshape(len(a[0]),-1) for a in arrays]
    lr=LogisticRegression(max_iter=2000,random_state=args.seed).fit(flat[0][train[4][:,-1]>=0],train[4][:,-1][train[4][:,-1]>=0])
    vp=lr.predict_proba(flat[1])[:,1];tp=lr.predict_proba(flat[2])[:,1];th=threshold(val_y,vp)
    report['models']['logistic_regression']=dict(threshold=th,test=metrics(test_y,tp,th),clean_history_test=metrics(test_y[test[5]==0],tp[test[5]==0],th))
    np.savez_compressed(out/'logistic_regression.npz',weights=lr.coef_,bias=lr.intercept_,threshold=th)
    # Label persistence is diagnostic: requires observed attack labels, NOT deployable detection.
    label_persistence=np.array([datasets[s]['y'][i+args.history-1] for s,i in splits[2]])
    report['oracle_label_persistence_diagnostic']=metrics(test_y[label_persistence>=0],label_persistence[label_persistence>=0],.5)
    base=pooled(test[0],test[2])[:,-1:, :]
    report['state_persistence_mse']=float(np.mean((base-test[3])**2))
    rng=np.random.default_rng(args.seed)
    for architecture in ('lstm','gnn_lstm'):
        model=GraphWorldModel(architecture=architecture,seed=args.seed,decoder=args.decoder,stage_count=len(STAGES) if args.stage_supervision else 0);optimizer=Adam(model.parameters(),lr=.003)
        best=float('inf');best_weights=None;history_log=[];started=time.monotonic()
        for epoch in range(args.epochs):
            order=rng.permutation(len(train[0])); losses=[]
            for offset in range(0,len(order),32):
                ids=order[offset:offset+32]
                objective=loss(model,*[a[ids] for a in train[:5]],stage_labels=stage_arrays[0][ids] if args.stage_supervision else None,positive_weight=positive_weight)
                objective.backward();optimizer.step();losses.append(float(objective.data))
            validation=float(loss(model,*valid[:5],stage_labels=stage_arrays[1],positive_weight=positive_weight).data)
            history_log.append(dict(epoch=epoch+1,train_loss=float(np.mean(losses)),validation_loss=validation))
            if validation<best:
                best=validation;best_weights={k:v.data.copy() for k,v in model.params.items()};best_epoch=epoch+1
            print(f'{architecture} epoch {epoch+1}/{args.epochs} train={np.mean(losses):.4f} val={validation:.4f}',flush=True)
        for k,v in best_weights.items():model.params[k].data=v
        vmu,_,vr=infer(model,valid,args.horizon);mu,sd,tr=infer(model,test,args.horizon)
        cal=fit_calibration(valid[4][valid[4]>=0],vr[valid[4]>=0]) if args.calibrate else {'status':'disabled'}
        raw_tr=tr.copy();vr=apply_calibration(vr,cal);tr=apply_calibration(tr,cal)
        th=threshold(val_y,vr[:,-1]);clean=test[5]==0
        val_target=future_target(valid[4]);vk=val_target>=0
        policy=select_policy(val_target[vk],vr.max(axis=1)[vk],args.fpr_budget)
        alert_th=policy['threshold'] if policy['threshold'] is not None else 1.000001
        alert_status=policy['status']
        clean_val=valid[5]==0
        early_known=clean_val&vk
        early_policy=select_policy(val_target[early_known],vr[early_known].max(axis=1),args.fpr_budget)
        early_th=early_policy['threshold'] if early_policy['threshold'] is not None else 1.000001
        early_status=early_policy['status']
        stage_results=[];stage_thresholds=[];stage_validated=[]
        if args.stage_supervision:
            vs=stage_infer(model,valid,args.horizon);ts=stage_infer(model,test,args.horizon)
            for j,name in enumerate(STAGES):
                known=stage_arrays[1][:,:,j]>=0;train_known=stage_arrays[0][:,:,j]>=0
                vy=stage_arrays[1][:,:,j][known];vp=vs[:,:,j][known]
                supported=len(np.unique(vy))==2 and len(np.unique(stage_arrays[0][:,:,j][train_known]))==2
                st=threshold(vy,vp) if supported else 1.0
                tk=stage_arrays[2][:,:,j]>=0
                stage_thresholds.append(st);stage_validated.append(bool(supported))
                stage_results.append(dict(stage=name,mitre=MITRE[j],threshold=st,validation_supported=bool(supported),
                    test=metrics(stage_arrays[2][:,:,j][tk],ts[:,:,j][tk],st)))
        # Event onset timing uses observed malicious-flow labels, never calls it compromise lead time.
        earliest={}
        for j,(source,start) in enumerate(splits[2]):
            if not clean[j] or not (tr[j]>=th).any():continue
            future=np.flatnonzero(test[4][j]==1)
            if not len(future):continue
            onset_idx=start+args.history+int(future[0]);onset=int(datasets[source]['times'][onset_idx])+datasets[source]['metadata']['window_seconds']
            cutoff=int(datasets[source]['times'][start+args.history-1])+datasets[source]['metadata']['window_seconds']
            key=(source,onset);earliest[key]=min(earliest.get(key,cutoff),cutoff)
        lead=[onset-cutoff for (_,onset),cutoff in earliest.items()]
        result=dict(calibration=cal,validation_alert_selection=policy,per_family_alert_metrics=family_report(datasets,splits[2],test[4],tr,policy['threshold']),threshold=th,best_epoch=best_epoch,training_seconds=round(time.monotonic()-started,2),
            test=metrics(test_y,tr[:,-1],th),clean_history_test=metrics(test_y[clean],tr[clean,-1],th),
            horizon_metrics=[metrics(test[4][:,h],tr[:,h],th) for h in range(args.horizon)],
            state_evidence=state_evidence(mu,test[3],base,args.seed),
            state_mse=float(np.mean((mu-test[3])**2)),gaussian_95pct_coverage=float(np.mean(abs(mu-test[3])<=1.96*sd)),
            bootstrap=block_interval(test_y,tr[:,-1],th),training_curve=history_log,
            onset_alerts={'unique_future_malicious_window_onsets_alerted':len(lead),'lead_seconds':lead,'interpretation':'flow-labelled onset, not compromise; only clean observation histories'},
            measured_compromise_lead_time_seconds=None,
            validation_state_mse=float(np.mean((vmu-valid[3])**2)),
            validation_persistence_mse=float(np.mean((pooled(valid[0],valid[2])[:,-1:]-valid[3])**2)),
            alert_policy=dict(threshold=alert_th,status=alert_status,validation_fpr_budget=args.fpr_budget,
                test=metrics(future_target(test[4]),tr.max(axis=1),alert_th)),
            clean_history_warning_policy=dict(threshold=early_th,status=early_status,validation_fpr_budget=args.fpr_budget,
                validation_positive_examples=int((future_target(valid[4][clean_val])==1).sum()),
                test=metrics(future_target(test[4][clean]),tr[clean].max(axis=1),early_th)),
            incident_evaluation=evaluate_events(datasets,splits[2],tr,args.history,args.horizon,alert_th),
            supervised_stages=stage_results)
        if architecture=='gnn_lstm':
            zeros=list(test);zeros[1]=np.zeros_like(test[1]);_,_,abl=infer(model,zeros,args.horizon)
            result['edge_removal_ablation']=metrics(test_y,apply_calibration(abl,cal)[:,-1],th)
            start=time.monotonic()
            for _ in range(10):model.forward(test[0][:1],test[1][:1],test[2][:1],args.horizon)
            result['single_example_mean_latency_ms']=100*(time.monotonic()-start)
        meta=dict(schema=SCHEMA,features=FEATURES,architecture=architecture,history=args.history,horizon=args.horizon,
            mode=datasets[0]['metadata']['mode'],max_nodes=datasets[0]['metadata']['max_nodes'],window_seconds=datasets[0]['metadata']['window_seconds'],
            source_hashes=[d['metadata']['source_sha256'] for d in datasets],threshold=th,seed=args.seed,
            unknown_supervision_masked=args.allow_unknown_labels,risk_calibration=cal,trained=True,validation_scope=('campaign holdout' if args.split_manifest else 'internal temporal holdout only')+'; '+args.evaluation_scope,automatic_containment_approved=False,
            packet_features_trained=bool(train[0][:,:,:,FEATURES.index('packet_features_present')].max()>0),target=report['target'],
            decoder=args.decoder,alert_threshold=alert_th,alert_policy_status=alert_status,
            evaluation_scope=args.evaluation_scope,stage_names=STAGES if args.stage_supervision else [],
            stage_thresholds=stage_thresholds,stage_validation_supported=stage_validated,
            stage_supervised=args.stage_supervision,
            training_campaigns=sorted({datasets[s]['metadata'].get('campaign_id','unannotated') for s,_ in splits[0]}))
        model.save(out/f'{architecture}.npz',meta)
        if args.stage_supervision:
            np.savez_compressed(out/f'{architecture}_stage_predictions.npz',probabilities=ts,labels=stage_arrays[2],thresholds=stage_thresholds)
        report['models'][architecture]=result
        np.savez_compressed(out/f'{architecture}_test_predictions.npz',probabilities=tr,raw_probabilities=raw_tr,labels=test[4],state_prediction=mu,state_target=test[3],sigma=sd,example_indices=np.asarray(splits[2]),history_clean=clean)
        np.savez_compressed(out/f'{architecture}_validation_predictions.npz',probabilities=vr,labels=valid[4],example_indices=np.asarray(splits[1]))
        print(architecture,json.dumps({k:v for k,v in result.items() if k!='training_curve'}),flush=True)
    report['checkpoint_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.npz')}
    (out/'metrics.json').write_text(json.dumps(report,indent=2,allow_nan=False))
    # Small actual held-out graph replay, no labels sent as model inputs.
    s,i=splits[2][0];d=datasets[s];stop=i+args.history
    payload=dict(schema=SCHEMA,mode=d['metadata']['mode'],window_seconds=d['metadata']['window_seconds'],
        x=d['x'][i:stop].tolist(),adj=d['adj'][i:stop].tolist(),mask=d['mask'][i:stop].tolist(),
        times=d['times'][i:stop].tolist(),node_names=d['metadata']['node_names'][stop-1],data_source='held_out_capture_replay')
    (out/'replay.json').write_text(json.dumps(payload))

if __name__=='__main__': main()
