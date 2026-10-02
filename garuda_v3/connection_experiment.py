"""Frozen connection-start forecast experiment, not a compromise certification.

Development-only fitting; all seeds and unsuccessful gates are retained. Test
records are not parsed until model, calibration and joint alert policies exist.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

import numpy as np

from . import causal_stage_forecast as training
from .connection_start import FEATURES, STAGES, SERVICE_NODES, HISTORY, HORIZON, STEP, prepare_source
from .coupled_heads import future_any_target
from .model import CONNECTION_START_SCHEMA, GraphWorldModel


def validate_protocol(p):
    if p.get('schema')!='garuda-connection-start-protocol-1' or p.get('feature_order')!=FEATURES:
        raise ValueError('Explicit first-packet feature protocol required')
    if p.get('seeds')!=[42,43,44] or (p['window_seconds'],p['history'],p['horizon'])!=(STEP,HISTORY,HORIZON):
        raise ValueError('Fixed three-seed time contract required')
    if p.get('test_metrics_inspected_before_freeze') is not False:raise ValueError('Unexposed model evaluation required')
    sources=p['sources'];ids=[s['id'] for s in sources]
    if len(ids)!=len(set(ids)):raise ValueError('Unique source identities required')
    dev={s['release'] for s in sources if s['split'] in ('train','validation')}
    final={s['release'] for s in sources if s['split']=='test'}
    if not final or final&dev:raise ValueError('Final release cannot supply development data')
    seen={}
    for s in sources+p.get('benign_sources',[]):
        split='test' if s['release'] in final else 'development'
        if s['sha256'] in seen and seen[s['sha256']]!=split:raise ValueError('Source alias across fitting/final data')
        seen[s['sha256']]=split


def load_group(sources,split,maximum=None,mmap_dir=None):
    arrays=[];audit=[]
    count=sum(s.get('split')==split for s in sources)
    cap=maximum//max(1,count) if maximum else None
    for s in sources:
        if s.get('split')!=split:continue
        benign=next((b for b in sources if b.get('role')=='time_matched_benign' and b['release']==s['release']),None)
        try:data,row=prepare_source(s,benign,cap,
            Path(mmap_dir)/s['id'] if mmap_dir is not None else None)
        except ValueError as e:
            if str(e)!='No valid first-packet event windows':raise
            data,row=None,{'id':s['id'],'sha256':s['sha256'],'sequences':0,'quality_excluded':str(e)}
        audit.append(row)
        print(json.dumps({'prepared':s['id'],'split':split,'sequences':row['sequences'],
                          'future_risk_counts':row.get('future_risk_counts')}),flush=True)
        if data is not None:arrays.append(data)
    if not arrays:return None,audit
    if mmap_dir is None:return {k:np.concatenate([d[k] for d in arrays]) for k in arrays[0]},audit
    folder=Path(mmap_dir)/'combined';folder.mkdir()
    result={};n=sum(len(d['x']) for d in arrays)
    for k in arrays[0]:
        first=arrays[0][k]
        dtype=np.result_type(*[d[k].dtype for d in arrays])
        out=np.lib.format.open_memmap(folder/(k+'.npy'),mode='w+',dtype=dtype,shape=(n,*first.shape[1:]))
        offset=0
        for d in arrays:
            for start in range(0,len(d[k]),256):
                out[offset+start:offset+start+len(d[k][start:start+256])]=d[k][start:start+256]
            offset+=len(d[k])
        out.flush();result[k]=out
    return result,audit


def calibrated_scores(model,data,row):
    _,_,raw,_=training.predict(model,data)
    return np.stack([training.calibrate(raw[:,h],row['risk_calibration'][h]) for h in range(HORIZON)],1)


def freeze_joint_policy(row,val,output):
    model,_=GraphWorldModel.load(Path(output)/row['checkpoint'])
    scores=calibrated_scores(model,val,row)
    threshold,status=training.threshold(future_any_target(val['y']),scores.max(1))
    row={**row,'any_horizon_threshold':threshold,'any_horizon_threshold_status':status,
        'feature_order':FEATURES,'model_schema':CONNECTION_START_SCHEMA,
        'future_target':'native-labelled connection starts, not successful compromise',
        'any_horizon_validation':training.binary_metrics(future_any_target(val['y']),scores.max(1),threshold)}
    training.write_json(Path(output)/f"{row['architecture']}_seed{row['seed']}_frozen.json",row)
    return row


def event_warnings(test,scores,threshold):
    """Unique first future malicious starts from fully benign observed histories.

    This is an advance-connection warning, NOT successful-compromise lead time.
    Every eligible event remains in the report including misses and abstentions.
    """
    clean=(test['history_y']==0).all(1)
    candidates=np.flatnonzero(clean&(test['y']==1).any(1))
    events={}
    for i in candidates:
        positive=test['y'][i]==1
        t=float(np.min(test['future_attack_times'][i,positive]))
        key=(str(test['source'][i]),t)
        e=events.setdefault(key,{'source':key[0],'labelled_connection_start_utc_epoch':t,
            'eligible_histories':0,'first_warning_origin_utc_epoch':None,'hit':False,
            'warning_lead_seconds':None,'successful_compromise_time':None})
        e['eligible_histories']+=1
        cutoff=int(test['cutoff'][i])
        if cutoff<t and scores[i].max()>=threshold:
            if e['first_warning_origin_utc_epoch'] is None or cutoff<e['first_warning_origin_utc_epoch']:
                e.update(first_warning_origin_utc_epoch=cutoff,hit=True,warning_lead_seconds=t-cutoff,
                    horizon_scores=scores[i].tolist(),defender_decision='shadow investigation only')
    rows=list(events.values());leads=[e['warning_lead_seconds'] for e in rows if e['hit']]
    return {'target':'first future native-labelled malicious connection from clean observed history',
        'eligible_events':len(rows),'hits':sum(e['hit'] for e in rows),'misses':sum(not e['hit'] for e in rows),
        'event_recall':sum(e['hit'] for e in rows)/len(rows) if rows else None,
        'median_hit_lead_seconds':float(np.median(leads)) if leads else None,
        'lead_p05_p95_seconds':np.quantile(leads,[.05,.95]).tolist() if leads else None,
        'precompromise_claim':False,'retrospective_reconstruction':True,'events':rows}


def score_candidate(row,test,output):
    result=training.evaluate_candidate(row,test,output)
    model,_=GraphWorldModel.load(Path(output)/row['checkpoint'])
    scores=calibrated_scores(model,test,row);target=future_any_target(test['y'])
    result['any_horizon_test']=training.binary_metrics(target,scores.max(1),row['any_horizon_threshold'])
    clean=(test['history_y']==0).all(1)
    result['clean_history_any_horizon']=training.binary_metrics(target[clean],scores[clean].max(1),row['any_horizon_threshold'])
    result['advance_connection_warnings']=event_warnings(test,scores,row['any_horizon_threshold'])
    result['risk_gate_passed']=result['risk_gate_passed'] and result['any_horizon_test']['gate_passed']
    result['state_gate_passed']=row['state_validation_selected'] and result['test_state']['gate_passed']
    result['automatic_promotion']=False
    return result


def run(protocol_path,cache,output):
    p=json.loads(Path(protocol_path).read_text());validate_protocol(p)
    output=Path(output)
    if output.exists():raise ValueError('Immutable experiment output must be new')
    sources=training.acquire(p,Path(cache));output.mkdir(parents=True)
    training.write_json(output/'acquisition.json',sources)
    train,ta=load_group(sources,'train',p['max_train_sequences']);val,va=load_group(sources,'validation',p['max_validation_sequences'])
    if train is None or val is None:raise ValueError('Nonempty development train/validation required')
    if set(train['day'])&set(val['day']):raise ValueError('Development observation days overlap')
    training.write_json(output/'development_audit.json',{'train':ta,'validation':va})
    records=[]
    for arch in ('lstm','gnn_lstm'):
        for seed in p['seeds']:
            row=training.train_candidate(arch,seed,train,val,p,output,
                feature_names=FEATURES,model_schema=CONNECTION_START_SCHEMA)
            records.append(freeze_joint_policy(row,val,output))
    baseline=training.fit_logistic(train,val,output)
    training.write_json(output/'freeze.json',{'protocol_sha256':training.sha(protocol_path),
        'frozen_at_utc_epoch':time.time(),'test_records_parsed':False,'models':records,'baseline':baseline})
    test,ea=load_group(sources,'test',mmap_dir=output/'test_sequences')
    if test is None:
        report={'schema':'garuda-connection-start-result-1','status':'INSUFFICIENT_FINAL_OBSERVATIONS',
            'models_frozen':records,'sources':{'train':ta,'validation':va,'test':ea},
            'test_metrics':None,'automatic_promotion':False,'precompromise_certified':False}
        training.write_json(output/'report.json',report);return report
    if set(test['day'])&(set(train['day'])|set(val['day'])):raise ValueError('Final observation-day leakage')
    results=[score_candidate(r,test,output) for r in records]
    summary={}
    for arch in ('lstm','gnn_lstm'):
        rows=[r for r in results if r['architecture']==arch]
        def stat(key):
            v=[r['any_horizon_test'][key] for r in rows if r['any_horizon_test'][key] is not None]
            return {'mean':float(np.mean(v)) if v else None,'seed_sd':float(np.std(v,ddof=1)) if len(v)>1 else None}
        summary[arch]={'state_improvement_mean':float(np.mean([r['test_state']['relative_improvement'] for r in rows])),
            'state_improvement_seed_sd':float(np.std([r['test_state']['relative_improvement'] for r in rows],ddof=1)),
            'state_gates_passed':sum(r['state_gate_passed'] for r in rows),
            'risk_gates_passed':sum(r['risk_gate_passed'] for r in rows),
            'five_stage_gates_passed':sum(r['five_stage_gate_passed'] for r in rows),
            'any_horizon':{k:stat(k) for k in ('recall','precision','fpr','f1')}}
    report={'schema':'garuda-connection-start-result-1','status':'COMPLETE_RESEARCH_EVALUATION',
        'protocol_sha256':training.sha(protocol_path),'freeze_sha256':training.sha(output/'freeze.json'),
        'feature_order':FEATURES,'graph_nodes':SERVICE_NODES,'model_schema':CONNECTION_START_SCHEMA,
        'sources':{'train':ta,'validation':va,'test':ea},'models':results,'summary':summary,
        'equal_history_logistic_baseline':training.score_logistic(baseline,test,output),
        'all_state_and_risk_gates_passed':all(r['state_gate_passed'] and r['risk_gate_passed'] for r in results),
        'future_target':'next 10/20/30/40s native-labelled connection starts',
        'live_sensor_availability_certified':False,'packet_features_used':False,
        'precompromise_certified':False,'automatic_promotion':False,'automatic_containment':False,
        'claim_boundary':'Retrospective first-packet event reconstruction; no completed-flow feature leakage. Publisher conn.log export latency is unknown. Native flow tactics are labels of connection starts, not verified host-compromise times. Same-publisher release holdout, not independent enterprise or zero-day proof.'}
    training.write_json(output/'report.json',report)
    print(json.dumps({'summary':summary,'report':str(output/'report.json')}),flush=True)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol',type=Path,required=True);parser.add_argument('--cache',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.protocol,args.cache,args.output)


if __name__=='__main__':main()
