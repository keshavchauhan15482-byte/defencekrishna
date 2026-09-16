"""Timestamp-preserving CSV adapter and executor for the frozen V49 campaign gate.

The cleaned parquet mirror deliberately removes Timestamp. This adapter therefore
uses the original CICFlowMeter CSVs and reads only the fixed network feature columns.
No row-order-as-time fallback exists.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v49_cic_unseen_campaign import (
    HISTORY,HORIZON,WINDOW_SECONDS,SEEDS,POLICY_FPR_RESERVE,RELEASE_FPR,RELEASE_RECALL,
    MIN_CLEAN_ONSET,RISK_WEIGHT,WORLD_WEIGHT,train_world,risk_lstm,logistic,robust_ref,
    anomaly,percentile,threshold,metric,
)

ALIASES={
 'dst_port':('dst port','destination port'), 'protocol':('protocol',), 'flow_duration':('flow duration',),
 'tot_fwd_pkts':('total fwd packets','tot fwd pkts'), 'tot_bwd_pkts':('total backward packets','tot bwd pkts'),
 'totlen_fwd':('fwd packets length total','total length of fwd packets','totlen fwd pkts'),
 'totlen_bwd':('bwd packets length total','total length of bwd packets','totlen bwd pkts'),
 'fwd_len_max':('fwd packet length max','fwd pkt len max'), 'fwd_len_mean':('fwd packet length mean','fwd pkt len mean'),
 'bwd_len_max':('bwd packet length max','bwd pkt len max'), 'bwd_len_mean':('bwd packet length mean','bwd pkt len mean'),
 'flow_iat_mean':('flow iat mean',), 'flow_iat_std':('flow iat std',), 'flow_iat_max':('flow iat max',),
 'fwd_iat_mean':('fwd iat mean',), 'bwd_iat_mean':('bwd iat mean',),
 'fwd_header':('fwd header length',), 'bwd_header':('bwd header length',),
 'fwd_pps':('fwd packets/s',), 'bwd_pps':('bwd packets/s',),
 'pkt_len_mean':('packet length mean','pkt len mean'), 'pkt_len_std':('packet length std','pkt len std'),
 'fin':('fin flag count','fin flag cnt'), 'syn':('syn flag count','syn flag cnt'), 'rst':('rst flag count','rst flag cnt'),
 'psh':('psh flag count','psh flag cnt'), 'ack':('ack flag count','ack flag cnt'), 'urg':('urg flag count','urg flag cnt'),
 'init_fwd_win':('init fwd win bytes','init fwd win byts','init_win_bytes_forward'),
 'init_bwd_win':('init bwd win bytes','init bwd win byts','init_win_bytes_backward'),
 'fwd_seg_avg':('fwd seg size avg','avg fwd segment size'), 'bwd_seg_avg':('bwd seg size avg','avg bwd segment size'),
 'active_mean':('active mean',), 'idle_mean':('idle mean',),
}

def norm(x):return ' '.join(str(x).strip().lower().replace('_',' ').split())
def find(cols,names):
    m={norm(c):c for c in cols}
    for n in names:
        if norm(n) in m:return m[norm(n)]
    return None

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def sample_schema(path):
    df=pd.read_csv(path,nrows=20000,low_memory=False)
    ts=find(df.columns,('timestamp',));label=find(df.columns,('label',))
    if not ts or not label:raise ValueError(f'Original CSV missing Timestamp/Label: {Path(path).name}; first={list(df.columns)[:12]}')
    features={}
    for name,aliases in ALIASES.items():
        c=find(df.columns,aliases)
        if c:
            x=pd.to_numeric(df[c],errors='coerce').replace([np.inf,-np.inf],np.nan)
            if float(x.notna().mean())>=.75 and int(x.nunique(dropna=True))>1:features[name]=c
    if len(features)<20:raise ValueError(f'Only {len(features)} fixed flow features in {path}: {features}')
    return {'timestamp':ts,'label':label,'features':features}

def common_schema(paths):
    schemas=[sample_schema(p) for p in paths];common=set(schemas[0]['features'])
    for s in schemas[1:]:common&=set(s['features'])
    fixed=[k for k in ALIASES if k in common]
    if len(fixed)<20:raise ValueError(f'Common flow feature contract too small: {fixed}')
    return fixed,schemas

def parse_time(s):
    dt=pd.to_datetime(s.astype(str),errors='coerce',dayfirst=True,utc=True,format='mixed')
    if float(dt.notna().mean())<.95:raise ValueError('Timestamp parse below 95%; no row-order fallback')
    return dt

def load_campaign(path,schema,fixed,role):
    use=[schema['timestamp'],schema['label']]+[schema['features'][k] for k in fixed]
    df=pd.read_csv(path,usecols=use,low_memory=False)
    dt=parse_time(df[schema['timestamp']]);labels=df[schema['label']].astype(str).str.strip();attack=(labels.str.lower()!='benign').astype(np.int8)
    base=pd.DataFrame({'dt':dt,'attack':attack})
    for k in fixed:base[k]=pd.to_numeric(df[schema['features'][k]],errors='coerce').replace([np.inf,-np.inf],np.nan)
    del df;gc.collect();base=base.dropna(subset=['dt']);base['bucket']=base['dt'].dt.floor(f'{WINDOW_SECONDS}s')
    g=base.groupby('bucket',sort=True);state=g[fixed].agg(['mean','std','max']);state.columns=['__'.join(x) for x in state.columns];state['flow_count']=g.size().astype(float);state['attack_now']=g['attack'].max().astype(np.int8);state=state.reset_index().sort_values('bucket').reset_index(drop=True)
    state_cols=[c for c in state if c not in ('bucket','attack_now')];z=state[state_cols].to_numpy(np.float32);a=state['attack_now'].to_numpy(np.int8);t=state['bucket'].astype('int64').to_numpy()//10**9
    X=[];F=[];y=[];clean=[];cut=[];first=[]
    for i in range(HISTORY-1,len(state)-HORIZON):
        lo=i-HISTORY+1;stop=i+HORIZON+1;span=t[lo:stop]
        if len(span)!=HISTORY+HORIZON or not np.all(np.diff(span)==WINDOW_SECONDS):continue
        fut=a[i+1:stop];hits=np.where(fut==1)[0];X.append(z[lo:i+1]);F.append(z[i+1:stop]);y.append(int(fut.max()));clean.append(bool(a[lo:i+1].max()==0));cut.append(int(t[i]));first.append(int(hits[0]+1) if len(hits) else -1)
    if not X:raise ValueError(f'No contiguous sequences for {role}')
    return {'role':role,'X':np.stack(X),'future':np.stack(F),'y':np.asarray(y,np.int8),'clean':np.asarray(clean,bool),'cutoff':np.asarray(cut,np.int64),'first':np.asarray(first,np.int8),'state_cols':state_cols,'state_rows':len(state),'sequence_rows':len(X),'attack_windows':int(a.sum()),'benign_windows':int((a==0).sum())}
def combine(camps):
    cols=camps[0]['state_cols']
    if any(c['state_cols']!=cols for c in camps):raise ValueError('State schema drift')
    out={k:np.concatenate([c[k] for c in camps],axis=0) for k in ('X','future','y','clean','cutoff','first')};roles=[]
    for c in camps:roles.extend([c['role']]*len(c['y']))
    out['role']=np.asarray(roles,dtype=object);return out

def average(rows,section,key):
    vals=[r[section].get(key) for r in rows if r[section].get(key) is not None]
    return {'mean':float(np.mean(vals)) if vals else None,'sd':float(np.std(vals,ddof=1)) if len(vals)>1 else None}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--train',nargs='+',required=True);p.add_argument('--calibration',required=True);p.add_argument('--policy',required=True);p.add_argument('--final',required=True);p.add_argument('--output',required=True);p.add_argument('--epochs',type=int,default=15);p.add_argument('--seeds',nargs='+',type=int,default=list(SEEDS));args=p.parse_args()
    if len(set(args.seeds))<3:p.error('At least 3 seeds required')
    out=Path(args.output)
    if out.exists():p.error('Output exists; evidence immutable')
    out.mkdir(parents=True)
    paths=[Path(x) for x in args.train]+[Path(args.calibration),Path(args.policy),Path(args.final)];fixed,schemas=common_schema(paths);roles=[f'train_{i}' for i in range(len(args.train))]+['calibration','policy','final'];camps=[]
    for path,schema,role in zip(paths,schemas,roles):
        print(f'Preparing {role}: {path.name}',flush=True);camps.append(load_campaign(path,schema,fixed,role));gc.collect()
    d=combine(camps);tr=np.where(np.char.startswith(d['role'].astype(str),'train_'))[0];ca=np.where(d['role']=='calibration')[0];po=np.where(d['role']=='policy')[0];final=np.where(d['role']=='final')[0]
    pos=final[d['y'][final]==1];neg=final[d['clean'][final]&(d['y'][final]==0)];clean_pos=pos[d['clean'][pos]];test=np.concatenate([pos,neg]);test_y=np.concatenate([np.ones(len(pos),np.int8),np.zeros(len(neg),np.int8)])
    if min(len(tr),len(ca),len(po),len(pos),len(neg))<20:raise ValueError(f'Support low train={len(tr)} cal={len(ca)} policy={len(po)} pos={len(pos)} neg={len(neg)}')
    report={'protocol':'V49 fresh CSE-CIC-IDS2018 DDoS campaign gate','claim_boundary':'DDoS day/family excluded from all fitting. Controlled unseen-family/day forecast, not real undisclosed zero-day or verified compromise lead time.','window_seconds':WINDOW_SECONDS,'history_seconds':HISTORY*WINDOW_SECONDS,'horizon_seconds':HORIZON*WINDOW_SECONDS,'roles':{'train':[str(x) for x in args.train],'calibration':args.calibration,'policy':args.policy,'final':args.final},'source':{str(x):{'bytes':x.stat().st_size,'sha256':sha256(x)} for x in paths},'common_raw_features':fixed,'campaigns':[{k:c[k] for k in ('role','state_rows','sequence_rows','attack_windows','benign_windows')} for c in camps],'support':{'train':len(tr),'calibration':len(ca),'policy':len(po),'final_positive':len(pos),'final_clean_negative':len(neg),'clean_history_future_positive':len(clean_pos)},'frozen_fusion':{'risk_weight':RISK_WEIGHT,'world_weight':WORLD_WEIGHT,'policy_fpr_reserve':POLICY_FPR_RESERVE},'seeds':args.seeds,'results':{},'automatic_containment_approved':False}
    for seed in args.seeds:
        print(f'Training seed {seed}',flush=True);world=train_world(d['X'],d['future'],tr,ca,seed,args.epochs);risk=risk_lstm(d['X'],d['y'],tr,ca,seed,args.epochs);lr=logistic(d['X'],d['y'],tr,ca,seed)
        if risk is None:raise ValueError('Calibration has insufficient classes')
        cb=ca[d['clean'][ca]&(d['y'][ca]==0)];pb=po[d['clean'][po]&(d['y'][po]==0)]
        if len(cb)<40 or len(pb)<100:raise ValueError(f'Benign support calibration={len(cb)} policy={len(pb)}')
        center,scale=robust_ref(world['pred'][cb]);wr=anomaly(world['pred'],center,scale);wp=percentile(wr,wr[cb]);rp=percentile(risk,risk[cb]);lp=percentile(lr,lr[cb]);hy=RISK_WEIGHT*rp+WORLD_WEIGHT*wp
        th=threshold(hy[pb]);rth=threshold(rp[pb]);wth=threshold(wp[pb]);lth=threshold(lp[pb]);row={'state':{'validation_mse':world['validation_mse'],'validation_persistence_mse':world['validation_persistence_mse'],'state_gate_passed':world['state_gate_passed'],'test_mse':float(np.mean((world['pred'][test]-world['future'][test])**2)),'test_persistence_mse':float(np.mean((world['persistence'][test]-world['future'][test])**2))},'hybrid':metric(test_y,hy[test],th),'risk_lstm':metric(test_y,rp[test],rth),'world_novelty':metric(test_y,wp[test],wth),'logistic':metric(test_y,lp[test],lth),'thresholds':{'hybrid':th,'risk_lstm':rth,'world_novelty':wth,'logistic':lth}}
        cp=np.concatenate([clean_pos,neg]);cy=np.concatenate([np.ones(len(clean_pos),np.int8),np.zeros(len(neg),np.int8)]);row['clean_history_hybrid']=metric(cy,hy[cp],th) if len(clean_pos) else {'positives':0,'status':'no_clean_history_future_positive'};hz=[]
        for h in range(1,HORIZON+1):
            hp=pos[d['first'][pos]==h];ids=np.concatenate([hp,neg]);yy=np.concatenate([np.ones(len(hp),np.int8),np.zeros(len(neg),np.int8)]);hz.append({'lead_seconds':h*WINDOW_SECONDS,'positive_support':len(hp),'metrics':metric(yy,hy[ids],th) if len(hp) else None})
        row['first_attack_horizon']=hz;report['results'][str(seed)]=row
    rows=list(report['results'].values());report['release_gate_all_seeds']=bool(all(r['state']['state_gate_passed'] and r['hybrid']['fpr']<=RELEASE_FPR and r['hybrid']['recall']>=RELEASE_RECALL for r in rows));report['clean_pre_onset_gate_all_seeds']=bool(len(clean_pos)>=MIN_CLEAN_ONSET and all(r['clean_history_hybrid']['fpr']<=RELEASE_FPR and r['clean_history_hybrid']['recall']>=RELEASE_RECALL for r in rows));report['summary']={m+'_'+k:average(rows,m,k) for m in ('hybrid','risk_lstm','world_novelty','logistic') for k in ('recall','fpr')};report['summary']['clean_history_recall']=average(rows,'clean_history_hybrid','recall') if len(clean_pos) else {'mean':None,'sd':None}
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n');print(json.dumps({'support':report['support'],'summary':report['summary'],'release_gate_all_seeds':report['release_gate_all_seeds'],'clean_pre_onset_gate_all_seeds':report['clean_pre_onset_gate_all_seeds']},indent=2))
if __name__=='__main__':main()
