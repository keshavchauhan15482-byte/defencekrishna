"""Validation-selected history skip heads on frozen state backbones.

The original compressed-head diagnostic stays immutable. A fresh release is
reserved before this runner fits/calibrates and opens its final records.
"""
import argparse
import json
from pathlib import Path
import shutil
import time

import numpy as np

from . import causal_stage_forecast as training
from .connection_experiment import validate_protocol, load_group, event_warnings
from .connection_start import FEATURES, STAGES, SERVICE_NODES, HORIZON, STEP
from .coupled_heads import future_any_target
from .model import CONNECTION_START_SCHEMA, GraphWorldModel
from .skip_heads import SkipReadout, fit


def frozen_model(row,bundle):
    p=Path(bundle)/row['checkpoint']
    if training.sha(p)!=row['checkpoint_sha256']:raise ValueError('Original state backbone changed')
    model,_=GraphWorldModel.load(p)
    for v in model.parameters():v.requires_grad=False
    return model


def evaluate(row,test,output):
    model=frozen_model(row,output)
    mean,_,_,stage=training.predict(model,test)
    head=SkipReadout(Path(output)/row['skip_checkpoint'],row['skip_checkpoint_sha256'])
    scores=head.probabilities(test,mean)
    risk={};native={};stages={}
    for h in range(HORIZON):
        name=str((h+1)*STEP);threshold=row['risk_thresholds'][h]
        risk[name]={**training.binary_metrics(test['y'][:,h],scores[:,h],threshold),
                    'brier':training.brier(test['y'][:,h],scores[:,h])}
        native[name]={}
        for i,s in enumerate(STAGES):
            k=(test['stage'][:,h,i]==1)|(test['y'][:,h]==0)
            native[name][s]=training.binary_metrics(test['y'][k,h],scores[k,h],threshold)
    for i,s in enumerate(STAGES):
        stages[s]={**training.binary_metrics(test['stage'][...,i],stage[...,i],row['stage_thresholds'][i]),
            'supported_in_development':bool(row['stage_supported_in_development'][i])}
    joint=training.binary_metrics(future_any_target(test['y']),scores.max(1),row['any_horizon_threshold'])
    clean=(test['history_y']==0).all(1)
    state=training.state_metrics(test,mean)
    return {**row,'test_state':state,'test_risk_per_horizon':risk,'test_risk_per_native_tactic':native,
        'test_stage_multilabel':stages,'any_horizon_test':joint,
        'clean_history_any_horizon':training.binary_metrics(future_any_target(test['y'][clean]),scores[clean].max(1),row['any_horizon_threshold']),
        'advance_connection_warnings':event_warnings(test,scores,row['any_horizon_threshold']),
        'state_gate_passed':row['state_validation_selected'] and state['gate_passed'],
        'risk_gate_passed':joint['gate_passed'] and all(r['gate_passed'] for r in risk.values()),
        'five_stage_gate_passed':all(r['supported_in_development'] and r['positive_support']>=30 and
            r['recall']>=.8 for r in stages.values()),'automatic_promotion':False}


def run(protocol,cache,backbones,output):
    p=json.loads(Path(protocol).read_text());validate_protocol(p)
    if p.get('risk_variant')!='history_skip_validation_selected_rollouts':raise ValueError('Explicit skip protocol required')
    backbones=Path(backbones);original=backbones/'freeze.json'
    if training.sha(original)!=p['original_backbone_freeze_sha256']:raise ValueError('State freeze provenance mismatch')
    output=Path(output)
    if output.exists():raise ValueError('Immutable experiment directory must be new')
    sources=training.acquire(p,Path(cache));output.mkdir(parents=True)
    training.write_json(output/'acquisition.json',sources)
    train,ta=load_group(sources,'train',p['max_train_sequences'])
    val,va=load_group(sources,'validation',p['max_validation_sequences'])
    if train is None or val is None or set(train['day'])&set(val['day']):raise ValueError('Disjoint development observations required')
    records=[]
    for row in json.loads(original.read_text())['models']:
        model=frozen_model(row,backbones)
        shutil.copyfile(backbones/row['checkpoint'],output/row['checkpoint'])
        record={**row,**fit(model,train,val,output/f"{row['architecture']}_seed{row['seed']}_skip.npz")}
        head=SkipReadout(output/record['skip_checkpoint'],record['skip_checkpoint_sha256'])
        score=head.probabilities(val,training.predict(model,val)[0])
        t,status=training.threshold(future_any_target(val['y']),score.max(1))
        record.update(risk_thresholds=[a['threshold'] for a in record['skip_policies']],
            risk_calibration=head.meta['calibration'],
            risk_threshold_status=[a['status'] for a in record['skip_policies']],
            any_horizon_threshold=t,any_horizon_threshold_status=status,
            any_horizon_validation=training.binary_metrics(future_any_target(val['y']),score.max(1),t))
        records.append(record)
        print(json.dumps({'fitted':record['architecture'],'seed':record['seed'],
            'readouts':record['risk_readout_kinds'],'validation_any_horizon':record['any_horizon_validation']}),flush=True)
    baseline=training.fit_logistic(train,val,output)
    training.write_json(output/'freeze.json',{'protocol_sha256':training.sha(protocol),
        'frozen_at_utc_epoch':time.time(),'test_records_parsed':False,
        'original_backbone_freeze_sha256':training.sha(original),'models':records,'baseline':baseline})
    test,ea=load_group(sources,'test',p['max_final_sequences'],mmap_dir=output/'test_sequences')
    if test is None:raise ValueError('No eligible fresh final sequences; no gate assumed')
    if set(test['day'])&(set(train['day'])|set(val['day'])):raise ValueError('Final calendar-day leakage')
    results=[evaluate(r,test,output) for r in records];summary={}
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
        'protocol_sha256':training.sha(protocol),'freeze_sha256':training.sha(output/'freeze.json'),
        'feature_order':FEATURES,'graph_nodes':SERVICE_NODES,'model_schema':CONNECTION_START_SCHEMA,
        'sources':{'train':ta,'validation':va,'test':ea},'models':results,'summary':summary,
        'equal_history_logistic_baseline':training.score_logistic(baseline,test,output),
        'risk_readout_type':'observed_history_skip_with_validation_selected_rollouts',
        'all_state_and_risk_gates_passed':all(r['state_gate_passed'] and r['risk_gate_passed'] for r in results),
        'future_target':'next 10/20/30/40s native-labelled connection starts',
        'live_sensor_availability_certified':False,'packet_features_used':False,
        'precompromise_certified':False,'automatic_promotion':False,'automatic_containment':False,
        'claim_boundary':'Fresh same-publisher release holdout; native connection-start targets, not host-compromise events. Frozen backbones, train-only normalization and validation-only skip/readout selection. History-only selections do not prove additional predictive value from learned rollouts.'}
    training.write_json(output/'report.json',report)
    print(json.dumps({'summary':summary,'report':str(output/'report.json')}),flush=True)
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('protocol','cache','backbones','output'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();run(a.protocol,a.cache,a.backbones,a.output)


if __name__=='__main__':main()
