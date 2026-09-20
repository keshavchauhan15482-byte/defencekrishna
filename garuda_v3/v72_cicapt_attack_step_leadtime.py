"""V72 prospective attack-step onset lead-time audit on CICAPT Phase 2.

A residual world model is fit only on Phase-1 packet+flow state sequences. A warning
score is computed from the model's *predicted future transition magnitude* relative to
persistence, so the score is available at the observation cutoff and does not consume
future ground truth. The alert threshold is frozen from a late Phase-1 policy segment.
Only after that freeze are Phase-2 alert timestamps compared with the independently
commit-pinned third-party attack_info timeline.

The timeline is development-grade and publisher_verified=false. Therefore this script
reports ATTACK-STEP ONSET lead time only. It must never be described as verified
successful-compromise lead time or production zero-day prevention.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import HISTORY, HORIZON
from .v60_residual_state_forecasting import train_residual_world_model
from .v70_cicapt_packet_world_model import EMBARGO_SEQUENCES, contiguous_sequences, packet_states

POLICY_FALSE_ALERT_BUDGET = 0.005
LOOKBACK_SECONDS = 600


def sha256(path: Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):
            h.update(b)
    return h.hexdigest()


def transition_score(pred, persistence):
    # Prediction-only future change magnitude. No observed future state enters score.
    return np.mean(np.abs(np.asarray(pred) - np.asarray(persistence)), axis=(1,2))


def upper_tail_threshold(values, budget):
    x=np.sort(np.asarray(values,dtype=float))
    if len(x)<100:
        raise RuntimeError(f'Policy reference too small: {len(x)}')
    q=max(0.0,min(1.0,1.0-float(budget)))
    # "higher" empirical quantile: reference exceedance cannot silently exceed budget
    idx=int(np.ceil(q*len(x))-1)
    idx=max(0,min(idx,len(x)-1))
    return float(x[idx])


def load_events(path: Path, first_epoch: float, last_epoch: float):
    df=pd.read_csv(path)
    required={'Time of Attack','Tactic Name','Technique Name'}
    if not required.issubset(df.columns):
        raise RuntimeError(f'Timeline schema mismatch: {list(df.columns)}')
    t=pd.to_numeric(df['Time of Attack'],errors='coerce')
    rows=[]
    for i,epoch in enumerate(t):
        if not np.isfinite(epoch):
            continue
        epoch=float(epoch)
        if epoch<first_epoch or epoch>last_epoch:
            continue
        rows.append({
            'epoch':epoch,
            'tactic':str(df.iloc[i]['Tactic Name']).strip(),
            'technique':str(df.iloc[i]['Technique Name']).strip(),
        })
    # Deduplicate exact command-time/tactic/technique copies only; do not invent episodes.
    uniq={ (r['epoch'],r['tactic'],r['technique']):r for r in rows }
    return sorted(uniq.values(),key=lambda r:(r['epoch'],r['tactic'],r['technique']))


def event_audit(events, alert_times):
    alert_times=np.sort(np.asarray(alert_times,dtype=float))
    rows=[]
    leads=[]
    for e in events:
        lo=e['epoch']-LOOKBACK_SECONDS
        ids=alert_times[(alert_times>=lo)&(alert_times<e['epoch'])]
        # First alert in lookback gives maximum defensible lead within declared window.
        first=float(ids[0]) if len(ids) else None
        lead=float(e['epoch']-first) if first is not None else None
        if lead is not None:
            leads.append(lead)
        rows.append({**e,'warning_hit':bool(len(ids)),'first_warning_epoch':first,'lead_seconds':lead,'alerts_in_lookback':int(len(ids))})
    return rows,leads


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1',required=True)
    p.add_argument('--phase2',required=True)
    p.add_argument('--timeline',required=True)
    p.add_argument('--timeline-provenance',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--packet-limit',type=int,default=3_000_000)
    p.add_argument('--seeds',nargs='+',type=int,default=[42,43,44])
    p.add_argument('--epochs',type=int,default=18)
    args=p.parse_args()
    if len(set(args.seeds))<3:
        p.error('At least three seeds required')

    prov=json.loads(Path(args.timeline_provenance).read_text())
    if prov.get('publisher_verified') is not False:
        raise RuntimeError('V72 expects explicitly non-publisher-verified development timeline provenance')
    timeline_path=Path(args.timeline)
    expected=prov.get('sha256') or prov.get('source_sha256')
    actual=sha256(timeline_path)
    if expected and str(expected).lower()!=actual.lower():
        raise RuntimeError(f'Timeline SHA mismatch {actual} != {expected}')

    t1,s1,n1=packet_states(Path(args.phase1),args.packet_limit)
    t2,s2,n2=packet_states(Path(args.phase2),args.packet_limit)
    x1,f1,c1=contiguous_sequences(t1,s1)
    x2,f2,c2=contiguous_sequences(t2,s2)

    # Phase1: 60% train, 20% validation, 20% policy, with embargoes around boundaries.
    n=len(x1)
    b1=int(n*0.60)
    b2=int(n*0.80)
    val_start=b1+EMBARGO_SEQUENCES
    policy_start=b2+EMBARGO_SEQUENCES
    val_end=max(val_start,b2-EMBARGO_SEQUENCES)
    if b1<100 or val_end-val_start<50 or n-policy_start<50:
        raise RuntimeError(f'Insufficient Phase1 support n={n} train={b1} val={val_end-val_start} policy={n-policy_start}')

    X=np.concatenate([x1,x2],axis=0)
    F=np.concatenate([f1,f2],axis=0)
    train=np.zeros(len(X),dtype=bool); val=np.zeros(len(X),dtype=bool); policy=np.zeros(len(X),dtype=bool); phase2=np.zeros(len(X),dtype=bool)
    train[:b1]=True
    val[val_start:val_end]=True
    policy[policy_start:n]=True
    phase2[n:]=True

    # Timeline may extend beyond bounded Phase2 packet prefix; evaluate only events
    # actually covered by this run's decoded Phase2 time range.
    events=load_events(timeline_path,float(t2[0]),float(t2[-1]))
    if len(events)<5:
        raise RuntimeError(f'Too few independently timestamped events within capture prefix: {len(events)}')

    rows={}
    for seed in args.seeds:
        print(f'V72 seed={seed}',flush=True)
        world=train_residual_world_model(X,F,train,val,int(seed),epochs=args.epochs)
        score=transition_score(world['pred'],world['persistence'])
        threshold=upper_tail_threshold(score[policy],POLICY_FALSE_ALERT_BUDGET)
        policy_alert=score[policy]>threshold
        p2_ids=np.where(phase2)[0]
        p2_alert=score[p2_ids]>threshold
        alert_times=c2[p2_alert]
        ev,leads=event_audit(events,alert_times)
        hits=sum(int(e['warning_hit']) for e in ev)
        # Phase2 alert density is reported to prevent a high event-recall number from
        # hiding a trivial always-alerting detector.
        rows[str(seed)]={
            'seed':int(seed),
            'blend_alpha':float(world['blend_alpha']),
            'trend_beta':float(world['trend_beta']),
            'validation_mse':float(world['validation_mse']),
            'validation_persistence_mse':float(world['validation_persistence_mse']),
            'validation_state_gate_passed':bool(world['state_gate_passed']),
            'threshold':threshold,
            'phase1_policy_sequences':int(policy.sum()),
            'phase1_policy_alerts':int(policy_alert.sum()),
            'phase1_policy_alert_rate':float(policy_alert.mean()),
            'phase2_sequences':int(len(p2_ids)),
            'phase2_alerts':int(p2_alert.sum()),
            'phase2_alert_rate':float(p2_alert.mean()),
            'events_evaluated':len(ev),
            'warning_hits':hits,
            'event_warning_recall':float(hits/len(ev)),
            'lead_seconds':{
                'count':len(leads),
                'mean':float(np.mean(leads)) if leads else None,
                'median':float(np.median(leads)) if leads else None,
                'min':float(np.min(leads)) if leads else None,
                'max':float(np.max(leads)) if leads else None,
            },
            'events':ev,
        }

    vals=list(rows.values())
    rec=np.asarray([r['event_warning_recall'] for r in vals],dtype=float)
    rates=np.asarray([r['phase2_alert_rate'] for r in vals],dtype=float)
    med=np.asarray([r['lead_seconds']['median'] for r in vals if r['lead_seconds']['median'] is not None],dtype=float)
    report={
        'protocol':'V72 prospective prediction-only transition alert before third-party timestamped CICAPT attack steps',
        'claim_boundary':(
            'This is ATTACK-STEP ONSET lead-time evidence against a commit-pinned third-party copy whose '
            'publisher_verified flag is false. The warning threshold is frozen from Phase1 before Phase2 '
            'event comparison. This is NOT verified successful-compromise lead time and NOT production zero-day proof.'
        ),
        'score_definition':'mean absolute predicted future-state transition away from persistence; prediction only',
        'policy_false_alert_budget':POLICY_FALSE_ALERT_BUDGET,
        'lookback_seconds':LOOKBACK_SECONDS,
        'timeline':str(timeline_path),
        'timeline_sha256':actual,
        'timeline_source_tier':prov.get('source_tier'),
        'publisher_verified':prov.get('publisher_verified'),
        'events_evaluated_within_bounded_phase2_prefix':len(events),
        'phase1':{'decoded_packets':n1,'observed_windows':len(s1),'sequences':len(x1),'train':int(train.sum()),'validation':int(val.sum()),'policy':int(policy.sum())},
        'phase2':{'decoded_packets':n2,'observed_windows':len(s2),'sequences':len(x2),'first_epoch':int(t2[0]),'last_epoch':int(t2[-1])},
        'leakage_contract':{
            'phase2_used_for_training':False,
            'phase2_used_for_normalization':False,
            'phase2_used_for_blend_selection':False,
            'phase2_used_for_threshold_selection':False,
            'timeline_events_used_for_threshold_selection':False,
            'alert_score_uses_observed_future_ground_truth':False,
        },
        'seeds':rows,
        'summary':{
            'seed_evaluations':len(vals),
            'event_warning_recall_mean':float(rec.mean()),
            'event_warning_recall_sd':float(rec.std(ddof=1)),
            'phase2_alert_rate_mean':float(rates.mean()),
            'phase2_alert_rate_sd':float(rates.std(ddof=1)),
            'median_attack_step_lead_seconds_mean_across_seeds':float(med.mean()) if len(med) else None,
            'all_validation_state_gates_pass':all(r['validation_state_gate_passed'] for r in vals),
        },
    }
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps(report['summary'],indent=2),flush=True)
    for seed,r in rows.items():
        print(seed,json.dumps({k:r[k] for k in ('threshold','phase1_policy_alert_rate','phase2_alert_rate','event_warning_recall','lead_seconds')},indent=2),flush=True)


if __name__=='__main__':
    main()
