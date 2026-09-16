"""V51 CIC-IDS2017 campaign-disjoint unseen-family support audit.

No model is trained here. Each source CSV is treated as an immutable campaign. For a
held-out family, its entire source campaign is reserved for evaluation and all other
campaigns form development support. Timestamp and labels are used only for chronology
and evaluation truth, never as model features.
"""
from __future__ import annotations

import argparse, hashlib, json
from pathlib import Path
import numpy as np
import pandas as pd

WINDOW_SECONDS = 10
HISTORY = 8
HORIZON = 4
BENIGN = {'benign', 'normal'}


def norm(x): return ''.join(ch.lower() for ch in str(x) if ch.isalnum())

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def resolve_columns(path):
    cols=list(pd.read_csv(path,nrows=0).columns)
    m={norm(c):c for c in cols}
    ts=next((m[k] for k in ('timestamp','flowstarttime','starttime') if k in m),None)
    label=next((m[k] for k in ('label','traffic','class') if k in m),None)
    if not ts or not label: raise ValueError(f'Missing timestamp/label in {path.name}: {cols}')
    return ts,label,len(cols)

def parse_time(s):
    dt=pd.to_datetime(s.astype(str).str.strip(),errors='coerce',utc=True)
    if float(dt.notna().mean()) < .95:
        raise ValueError('Timestamp parse coverage below 95%; row-order fallback refused')
    return dt

def build_campaign(path, chunksize=250000):
    ts_col,label_col,column_count=resolve_columns(path)
    frames=[]; rows=0; parsed=0
    for chunk in pd.read_csv(path,usecols=[ts_col,label_col],chunksize=chunksize,low_memory=False):
        dt=parse_time(chunk[ts_col]); lab=chunk[label_col].astype(str).str.strip()
        good=dt.notna() & lab.notna(); dt=dt[good]; lab=lab[good]; rows += len(chunk); parsed += int(good.sum())
        bucket=dt.dt.floor(f'{WINDOW_SECONDS}s')
        f=pd.DataFrame({'bucket':bucket,'label':lab})
        frames.append(f)
    data=pd.concat(frames,ignore_index=True)
    def family_tuple(values):
        return tuple(sorted({str(v).strip() for v in values if str(v).strip().lower() not in BENIGN and str(v).strip()}))
    g=data.groupby('bucket',sort=True)['label']
    fam=g.apply(family_tuple)
    timeline=pd.DataFrame({'time':fam.index,'families':fam.values})
    timeline['attack_now']=timeline['families'].map(lambda x:int(bool(x)))
    return timeline, {'rows':rows,'parsed_rows':parsed,'timestamp_column':ts_col,'label_column':label_col,'columns':column_count}

def make_sequences(timeline):
    t=timeline['time'].astype('int64').to_numpy()//10**9
    a=timeline['attack_now'].to_numpy(np.int8); fam=timeline['families'].tolist()
    clean=[]; future_attack=[]; hist=[]; steps=[]; cutoff=[]
    for i in range(HISTORY-1,len(timeline)-HORIZON):
        lo=i-HISTORY+1; stop=i+HORIZON+1; span=t[lo:stop]
        if len(span)!=HISTORY+HORIZON or not np.all(np.diff(span)==WINDOW_SECONDS): continue
        hs=set()
        for x in fam[lo:i+1]: hs.update(x)
        hist.append(frozenset(hs)); steps.append(tuple(frozenset(x) for x in fam[i+1:stop]))
        clean.append(bool(a[lo:i+1].max()==0)); future_attack.append(int(a[i+1:stop].max())); cutoff.append(int(t[i]))
    return {'clean':np.asarray(clean,bool),'future_attack':np.asarray(future_attack,np.int8),'history_families':np.asarray(hist,object),'step_families':np.asarray(steps,object),'cutoff':np.asarray(cutoff,np.int64)}
def family_presence(seq,family):
    hist=np.asarray([family in x for x in seq['history_families']],bool)
    future=np.zeros((len(hist),HORIZON),bool)
    for i,row in enumerate(seq['step_families']):
        for h,x in enumerate(row): future[i,h]=family in x
    return hist,future

def campaign_support(campaigns):
    family_campaigns={}
    for cid,item in campaigns.items():
        families=sorted({f for row in item['sequence']['step_families'] for step in row for f in step})
        for f in families: family_campaigns.setdefault(f,set()).add(cid)
    rows=[]
    for family,ids in sorted(family_campaigns.items()):
        for test_id in sorted(ids):
            seq=campaigns[test_id]['sequence']; hist,future=family_presence(seq,family); any_future=future.any(1)
            positive=any_future
            onset=(~hist)&any_future
            clean_onset=seq['clean']&onset
            negative=seq['clean']&(seq['future_attack']==0)
            dev=0; dev_campaigns=[]
            for cid,item in campaigns.items():
                if cid==test_id: continue
                s=item['sequence']; h,fu=family_presence(s,family); free=~(h|fu.any(1)); dev += int(free.sum()); dev_campaigns.append(cid)
            rows.append({'family':family,'test_campaign':test_id,'development_campaigns':dev_campaigns,'development_family_free_sequences':dev,
                'test_future_positive':int(positive.sum()),'test_family_onset_positive':int(onset.sum()),
                'test_clean_history_onset_positive':int(clean_onset.sum()),'test_clean_benign_negative':int(negative.sum()),
                'horizon_positive_support':[int(future[:,:h].any(1).sum()) for h in range(1,HORIZON+1)]})
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--csv',nargs='+',required=True); p.add_argument('--output',required=True)
    p.add_argument('--min-positive',type=int,default=20);p.add_argument('--min-negative',type=int,default=100);p.add_argument('--min-clean-onset',type=int,default=1);p.add_argument('--min-dev',type=int,default=1000)
    args=p.parse_args(); out=Path(args.output)
    if out.exists(): p.error('Output exists; audit evidence is immutable')
    out.mkdir(parents=True)
    campaigns={}; provenance={}
    for raw in args.csv:
        path=Path(raw); cid=path.stem
        timeline,meta=build_campaign(path); seq=make_sequences(timeline)
        campaigns[cid]={'sequence':seq}; provenance[cid]={**meta,'bytes':int(path.stat().st_size),'sha256':sha256(path),'timeline_windows':int(len(timeline)),'sequence_rows':int(len(seq['clean']))}
    support=campaign_support(campaigns)
    eligible=[r for r in support if r['test_future_positive']>=args.min_positive and r['test_clean_benign_negative']>=args.min_negative and r['test_clean_history_onset_positive']>=args.min_clean_onset and r['development_family_free_sequences']>=args.min_dev]
    report={'protocol':'V51 CICIDS2017 whole-campaign unseen-family support audit','window_seconds':WINDOW_SECONDS,'history_seconds':HISTORY*WINDOW_SECONDS,'horizon_seconds':HORIZON*WINDOW_SECONDS,
        'claim_boundary':'Support audit only; no model accuracy or real zero-day/compromise-lead-time claim.','campaign_provenance':provenance,'support':support,
        'eligibility_rule':{'min_future_positive':args.min_positive,'min_clean_benign_negative':args.min_negative,'min_clean_history_onset':args.min_clean_onset,'min_development_family_free_sequences':args.min_dev},
        'eligible_family_campaign_pairs':eligible,'model_training_permitted':bool(eligible)}
    (out/'support.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'eligible_family_campaign_pairs':eligible,'model_training_permitted':bool(eligible),'support':support},indent=2),flush=True)
if __name__=='__main__': main()
