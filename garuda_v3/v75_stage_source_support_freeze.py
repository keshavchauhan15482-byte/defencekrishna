"""V75 support-only source holdout freeze for a fresh X-IIoTID stage test.

This script does **not** train or score any model. It constructs the same host-minute
sequence representation used by Garuda, retains source identity, derives the five
lifecycle-stage proxy targets, and selects reserve source hosts using only stage support
counts. The resulting source list is intended to be committed before any reserve-source
model metric is computed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import HISTORY, HORIZON, build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v48_strict_runner import canonical_family_name
from .v71_future_stage_proxy import STAGES, stage_name

MIN_RESERVE_PER_STAGE = 20
MIN_DEV_PER_STAGE = 80


def sha256(path: Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):
            h.update(b)
    return h.hexdigest()


def make_sequences_with_src(state, feature_cols):
    X=[]; future=[]; cutoff=[]; srcs=[]; step_families=[]
    for src, group in state.groupby('src', sort=False):
        g=group.sort_values('minute').reset_index(drop=True)
        t=g['minute'].astype('int64').to_numpy()//10**9
        z=g[feature_cols].to_numpy(dtype=np.float32)
        fam=g['families'].tolist()
        for i in range(HISTORY-1,len(g)-HORIZON):
            lo=i-HISTORY+1; stop=i+HORIZON+1
            span=t[lo:stop]
            if len(span)!=HISTORY+HORIZON or not np.all(np.diff(span)==60):
                continue
            X.append(z[lo:i+1]); future.append(z[i+1:stop]); cutoff.append(int(t[i])); srcs.append(str(src))
            steps=[]
            for item in fam[i+1:stop]: steps.append(frozenset(item))
            step_families.append(tuple(steps))
    if not X: raise RuntimeError('No contiguous sequences')
    return {'X':np.stack(X),'future':np.stack(future),'cutoff':np.asarray(cutoff,dtype=np.int64),'src':np.asarray(srcs,dtype=object),'step_families':np.asarray(step_families,dtype=object)}


def stage_targets(seq):
    out=np.full(len(seq['X']),-1,dtype=np.int16)
    rank={s:i for i,s in enumerate(STAGES)}
    for i,steps in enumerate(seq['step_families']):
        mapped=[]
        for fams in steps:
            for fam in fams:
                s=stage_name(fam)
                if s is not None: mapped.append(s)
        if mapped: out[i]=max(rank[s] for s in mapped)
    return out


def counts_by_source(src, y_stage):
    rows={}
    for s in sorted(set(src.tolist())):
        mask=src==s
        c=Counter(STAGES[int(x)] for x in y_stage[mask & (y_stage>=0)])
        rows[s]={stage:int(c.get(stage,0)) for stage in STAGES}
        rows[s]['total']=int(sum(c.values()))
    return rows


def greedy_sources(rows):
    total={stage:sum(r[stage] for r in rows.values()) for stage in STAGES}
    chosen=[]; reserve={stage:0 for stage in STAGES}
    remaining=set(rows)
    # Cover weakest stage first. Score uses support only: gain toward minimum reserve,
    # then balanced minimum gain, total useful gain, smaller source total, source id.
    while min(reserve.values())<MIN_RESERVE_PER_STAGE:
        best=None
        for src in sorted(remaining):
            r=rows[src]
            if any(total[stage]-reserve[stage]-r[stage] < MIN_DEV_PER_STAGE for stage in STAGES):
                continue
            gains={stage:min(r[stage],max(0,MIN_RESERVE_PER_STAGE-reserve[stage])) for stage in STAGES}
            weakest=min(STAGES,key=lambda st:(reserve[st],st))
            key=(gains[weakest],min(reserve[st]+gains[st] for st in STAGES),sum(gains.values()),-r['total'],src)
            if best is None or key>best[0]: best=(key,src,gains)
        if best is None:
            raise RuntimeError(f'Cannot support source holdout: reserve={reserve}, total={total}')
        _,src,gains=best
        chosen.append(src); remaining.remove(src)
        for stage in STAGES: reserve[stage]+=rows[src][stage]
        if len(chosen)>20: raise RuntimeError('Support-only greedy selection exceeded 20 sources')
    dev={stage:total[stage]-sum(rows[s][stage] for s in chosen) for stage in STAGES}
    return chosen,reserve,dev,total


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv',required=True); p.add_argument('--output',required=True)
    args=p.parse_args()
    csv=Path(args.csv)
    df=pd.read_csv(csv,low_memory=False)
    dt,date_col,ts_col,time_method=parse_time(df)
    binary,family,binary_col,family_col,profiles=detect_label_hierarchy(df)
    family=family.map(canonical_family_name)
    feature_cols,feature_audit=choose_network_numeric_features(df)
    state,names,src_col=build_minute_state(df,dt,binary,family,feature_cols)
    if not src_col: raise RuntimeError('Source identity unavailable; cannot freeze source holdout')
    seq=make_sequences_with_src(state,names)
    y_stage=stage_targets(seq)
    rows=counts_by_source(seq['src'],y_stage)
    rows={k:v for k,v in rows.items() if v['total']>0}
    chosen,reserve,dev,total=greedy_sources(rows)
    freeze={
      'protocol':'V75 support-only fresh source-host stage holdout freeze',
      'dataset_sha256':sha256(csv),
      'selection_used_model_metrics':False,
      'model_scored_reserve_before_freeze':False,
      'source_column':src_col,
      'stage_mapping':{'Reconnaissance':'Reconnaissance','Exploitation':'Initial Access proxy','Lateral Movement':'Lateral Movement','C&C':'Command & Control','Exfiltration':'Exfiltration'},
      'minimum_reserve_per_stage':MIN_RESERVE_PER_STAGE,
      'minimum_development_per_stage_after_reserve':MIN_DEV_PER_STAGE,
      'selected_reserve_sources':chosen,
      'reserve_stage_support':reserve,
      'development_stage_support':dev,
      'total_stage_support':total,
      'selected_source_support':{s:rows[s] for s in chosen},
      'all_source_support':rows,
      'network_features':feature_cols,
      'time':{'date_column':date_col,'timestamp_column':ts_col,'method':time_method},
      'labels':{'binary':binary_col,'family':family_col,'profiles':profiles},
      'sequence_count':int(len(seq['X'])),
      'stage_labelled_sequence_count':int((y_stage>=0).sum()),
      'claim_boundary':'Support-only freeze. No model was trained or scored and no reserve metric exists at this stage.'
    }
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(freeze,indent=2,allow_nan=False)+'\n')
    print(json.dumps({k:freeze[k] for k in ('dataset_sha256','selected_reserve_sources','reserve_stage_support','development_stage_support','total_stage_support','sequence_count','stage_labelled_sequence_count')},indent=2),flush=True)

if __name__=='__main__': main()
