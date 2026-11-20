"""V49 fresh campaign-level unseen-DDoS forecasting benchmark.

Frozen roles (chosen before final-campaign model evaluation):
- train: CSE-CIC-IDS2018 BruteForce + Botnet campaigns
- calibration/state validation: Infiltration campaign
- benign policy threshold: Web campaign
- final untouched campaign: Wednesday-21-Feb DDoS HOIC/LOIC-UDP

The final campaign is never used for feature selection, scaling, checkpoint selection,
calibration, threshold selection or fusion weights. Each flow campaign is converted
into global 10-second network-state vectors. The frozen V48 hybrid combines temporal
known-family risk (75%) with world-state novelty (25%).

This can establish a controlled unseen-family/day forecast result. It is not proof of
an undisclosed production zero-day or successful compromise lead time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

HISTORY = 8
HORIZON = 4
WINDOW_SECONDS = 10
SEEDS = (42, 43, 44)
POLICY_FPR_RESERVE = 0.005
RELEASE_FPR = 0.01
RELEASE_RECALL = 0.80
MIN_CLEAN_ONSET = 20
RISK_WEIGHT = 0.75
WORLD_WEIGHT = 0.25

# Fixed flow-level contract. Only columns present in all development/final campaign
# files are retained; aliases handle original and cleaned CICFlowMeter spelling.
FEATURE_ALIASES = {
    'dst_port': ('dst port','destination port'),
    'protocol': ('protocol',),
    'flow_duration': ('flow duration',),
    'tot_fwd_pkts': ('tot fwd pkts','total fwd packets'),
    'tot_bwd_pkts': ('tot bwd pkts','total backward packets'),
    'totlen_fwd': ('totlen fwd pkts','total length of fwd packets'),
    'totlen_bwd': ('totlen bwd pkts','total length of bwd packets'),
    'fwd_len_mean': ('fwd pkt len mean','fwd packet length mean'),
    'bwd_len_mean': ('bwd pkt len mean','bwd packet length mean'),
    'flow_iat_mean': ('flow iat mean',),
    'flow_iat_std': ('flow iat std',),
    'flow_iat_max': ('flow iat max',),
    'fwd_iat_mean': ('fwd iat mean',),
    'bwd_iat_mean': ('bwd iat mean',),
    'pkt_len_mean': ('pkt len mean','packet length mean'),
    'pkt_len_std': ('pkt len std','packet length std'),
    'pkt_len_max': ('pkt len max','max packet length'),
    'syn': ('syn flag cnt','syn flag count'),
    'ack': ('ack flag cnt','ack flag count'),
    'rst': ('rst flag cnt','rst flag count'),
    'psh': ('psh flag cnt','psh flag count'),
    'urg': ('urg flag cnt','urg flag count'),
    'init_fwd_win': ('init fwd win byts','init_win_bytes_forward'),
    'init_bwd_win': ('init bwd win byts','init_win_bytes_backward'),
    'active_mean': ('active mean',),
    'idle_mean': ('idle mean',),
}


def norm(v):
    return ' '.join(str(v).strip().lower().replace('_',' ').split())


def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


def find_col(columns, aliases):
    m={norm(c):c for c in columns}
    for a in aliases:
        if norm(a) in m: return m[norm(a)]
    return None


def schema_for(df):
    timestamp=find_col(df.columns,('timestamp',))
    label=find_col(df.columns,('label',))
    if timestamp is None or label is None:
        raise ValueError(f'CICFlowMeter Timestamp/Label missing; columns={list(df.columns)[:20]}')
    features={}
    for name,aliases in FEATURE_ALIASES.items():
        col=find_col(df.columns,aliases)
        if col is not None:
            x=pd.to_numeric(df[col],errors='coerce').replace([np.inf,-np.inf],np.nan)
            if float(x.notna().mean())>=0.80 and int(x.nunique(dropna=True))>1:
                features[name]=col
    if len(features)<18:
        raise ValueError(f'Only {len(features)} fixed CIC flow features available: {features}')
    return {'timestamp':timestamp,'label':label,'features':features}


def common_schema(dataframes):
    schemas=[schema_for(df) for df in dataframes]
    common=set(schemas[0]['features'])
    for s in schemas[1:]: common &= set(s['features'])
    fixed=[k for k in FEATURE_ALIASES if k in common]
    if len(fixed)<18: raise ValueError(f'Common feature intersection too small: {fixed}')
    return {'features':fixed,'per_file':schemas}


def parse_timestamp(s):
    # Original CIC-IDS2018 flow CSV timestamps are day-first strings. Clean parquet
    # mirrors preserve them. Numeric epoch timestamps are also accepted explicitly.
    num=pd.to_numeric(s,errors='coerce')
    if float(num.notna().mean())>=0.95:
        med=float(num.dropna().median()); unit='ms' if med>1e11 else 's'
        dt=pd.to_datetime(num,unit=unit,errors='coerce',utc=True)
        if float(dt.notna().mean())>=0.95: return dt,unit
    dt=pd.to_datetime(s.astype(str),errors='coerce',dayfirst=True,utc=True,format='mixed')
    if float(dt.notna().mean())<0.95: raise ValueError('Timestamp parse below 95%')
    return dt,'dayfirst-text'


def make_campaign(df, schema, common_features, campaign):
    dt,time_method=parse_timestamp(df[schema['timestamp']])
    labels=df[schema['label']].astype(str).str.strip()
    attack=(labels.str.lower()!='benign').astype(np.int8)
    base=pd.DataFrame({'dt':dt,'attack':attack})
    reverse={name:col for name,col in schema['features'].items()}
    for name in common_features:
        base[name]=pd.to_numeric(df[reverse[name]],errors='coerce').replace([np.inf,-np.inf],np.nan)
    base=base.dropna(subset=['dt']).copy()
    base['bucket']=base['dt'].dt.floor(f'{WINDOW_SECONDS}s')
    g=base.groupby('bucket',sort=True)
    state=g[common_features].agg(['mean','std','max'])
    state.columns=['__'.join(x) for x in state.columns]
    state['flow_count']=g.size().astype(float)
    state['attack_now']=g['attack'].max().astype(np.int8)
    state=state.reset_index().sort_values('bucket').reset_index(drop=True)
    fcols=[c for c in state.columns if c not in {'bucket','attack_now'}]
    z=state[fcols].to_numpy(np.float32)
    a=state['attack_now'].to_numpy(np.int8)
    t=state['bucket'].astype('int64').to_numpy()//10**9
    X=[];F=[];Y=[];clean=[];cutoff=[];first=[]
    for i in range(HISTORY-1,len(state)-HORIZON):
        lo=i-HISTORY+1; stop=i+HORIZON+1; span=t[lo:stop]
        if len(span)!=HISTORY+HORIZON or not np.all(np.diff(span)==WINDOW_SECONDS): continue
        fut=a[i+1:stop]
        hits=np.where(fut==1)[0]
        X.append(z[lo:i+1]); F.append(z[i+1:stop]); Y.append(int(fut.max()))
        clean.append(bool(a[lo:i+1].max()==0)); cutoff.append(int(t[i])); first.append(int(hits[0]+1) if len(hits) else -1)
    if not X: raise ValueError(f'No contiguous sequences for {campaign}')
    return {'campaign':campaign,'X':np.stack(X),'future':np.stack(F),'y':np.asarray(Y,np.int8),'clean':np.asarray(clean,bool),'cutoff':np.asarray(cutoff,np.int64),'first_horizon':np.asarray(first,np.int8),'state_rows':int(len(state)),'sequence_rows':len(X),'label_counts':{str(k):int(v) for k,v in zip(*np.unique(attack,return_counts=True))},'timestamp_method':time_method,'features':fcols}


def combine(campaigns):
    features=campaigns[0]['features']
    if any(c['features']!=features for c in campaigns): raise ValueError('State feature drift across campaigns')
    fields=('X','future','y','clean','cutoff','first_horizon')
    out={k:np.concatenate([c[k] for c in campaigns],axis=0) for k in fields}
    role=[]
    for c in campaigns: role.extend([c['campaign']]*len(c['y']))
    out['campaign']=np.asarray(role,dtype=object); out['features']=features
    return out


def fit_state_scale(X,F,tr):
    joint=np.concatenate([X[tr].reshape(-1,X.shape[-1]),F[tr].reshape(-1,F.shape[-1])],0).astype(np.float64)
    joint[~np.isfinite(joint)]=np.nan; med=np.nanmedian(joint,axis=0); med[~np.isfinite(med)]=0
    def imp(a):
        z=np.asarray(a,np.float32).copy(); bad=~np.isfinite(z)
        if bad.any(): z[bad]=med[np.where(bad)[-1]]
        return z
    train_joint=np.concatenate([imp(X[tr]).reshape(-1,X.shape[-1]),imp(F[tr]).reshape(-1,F.shape[-1])],0)
    scaler=StandardScaler().fit(train_joint)
    def tx(a):
        z=imp(a); return scaler.transform(z.reshape(-1,z.shape[-1])).reshape(z.shape).astype(np.float32)
    return tx(X),tx(F)


def train_world(X,F,tr,va,seed,epochs):
    import torch, torch.nn as nn
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed);torch.set_num_threads(max(1,min(2,os.cpu_count() or 1)))
    Xs,Fs=fit_state_scale(X,F,tr)
    class M(nn.Module):
        def __init__(self,d): super().__init__();self.r=nn.LSTM(d,32,batch_first=True);self.h=nn.Sequential(nn.Linear(32,64),nn.ReLU(),nn.Linear(64,HORIZON*d))
        def forward(self,x): _,(h,_)=self.r(x);return self.h(h[-1]).reshape(len(x),HORIZON,x.shape[-1])
    m=M(X.shape[-1]);opt=torch.optim.Adam(m.parameters(),lr=.003);lossfn=nn.MSELoss();rng=np.random.default_rng(seed)
    xtr=torch.tensor(Xs[tr]);ftr=torch.tensor(Fs[tr]);xva=torch.tensor(Xs[va]);fva=torch.tensor(Fs[va]);best=None;state=None;stale=0
    for _ in range(epochs):
        m.train();order=rng.permutation(len(tr))
        for s in range(0,len(order),256):
            ids=order[s:s+256];loss=lossfn(m(xtr[ids]),ftr[ids]);opt.zero_grad();loss.backward();opt.step()
        m.eval()
        with torch.no_grad(): val=float(lossfn(m(xva),fva).item())
        if best is None or val<best-1e-7: best=val;state={k:v.detach().cpu().clone() for k,v in m.state_dict().items()};stale=0
        else:
            stale+=1
            if stale>=5: break
    m.load_state_dict(state);m.eval()
    with torch.no_grad(): pred=m(torch.tensor(Xs)).cpu().numpy()
    persist=np.repeat(Xs[:,-1:,:],HORIZON,axis=1)
    vm=float(np.mean((pred[va]-Fs[va])**2));vp=float(np.mean((persist[va]-Fs[va])**2))
    return {'pred':pred,'future':Fs,'persistence':persist,'validation_mse':vm,'validation_persistence_mse':vp,'state_gate_passed':bool(vm<vp)}


def prep_risk(X,tr):
    z=X.astype(np.float64,copy=True);z[~np.isfinite(z)]=np.nan;flat=z[tr].reshape(-1,X.shape[-1]);med=np.nanmedian(flat,axis=0);med[~np.isfinite(med)]=0
    bad=~np.isfinite(z)
    if bad.any(): z[bad]=med[np.where(bad)[-1]]
    sc=StandardScaler().fit(z[tr].reshape(-1,X.shape[-1]));return sc.transform(z.reshape(-1,X.shape[-1])).reshape(z.shape).astype(np.float32)


def risk_lstm(X,y,tr,ca,seed,epochs):
    import torch,torch.nn as nn
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed);torch.set_num_threads(max(1,min(2,os.cpu_count() or 1)))
    if len(np.unique(y[tr]))<2 or len(np.unique(y[ca]))<2:return None
    Z=prep_risk(X,tr)
    class R(nn.Module):
        def __init__(self,d):super().__init__();self.r=nn.LSTM(d,32,batch_first=True);self.h=nn.Linear(32,1)
        def forward(self,x):_,(h,_)=self.r(x);return self.h(h[-1]).squeeze(-1)
    m=R(X.shape[-1]);pos=max(1,int((y[tr]==1).sum()));neg=max(1,int((y[tr]==0).sum()));fn=nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(neg/pos)));opt=torch.optim.Adam(m.parameters(),lr=.003);rng=np.random.default_rng(seed)
    xtr=torch.tensor(Z[tr]);ytr=torch.tensor(y[tr].astype(np.float32));xca=torch.tensor(Z[ca]);yca=torch.tensor(y[ca].astype(np.float32));best=None;state=None;stale=0
    for _ in range(epochs):
        m.train();order=rng.permutation(len(tr))
        for s in range(0,len(order),256):
            ids=order[s:s+256];loss=fn(m(xtr[ids]),ytr[ids]);opt.zero_grad();loss.backward();opt.step()
        m.eval()
        with torch.no_grad():val=float(fn(m(xca),yca).item())
        if best is None or val<best-1e-6:best=val;state={k:v.detach().cpu().clone() for k,v in m.state_dict().items()};stale=0
        else:
            stale+=1
            if stale>=4:break
    m.load_state_dict(state);m.eval()
    with torch.no_grad():raw=m(torch.tensor(Z)).cpu().numpy()
    cal=LogisticRegression(C=1e6,solver='lbfgs',max_iter=300);cal.fit(raw[ca].reshape(-1,1),y[ca]);return cal.predict_proba(raw.reshape(-1,1))[:,1]


def logistic(X,y,tr,ca,seed):
    flat=X.reshape(len(X),-1).astype(np.float64);flat[~np.isfinite(flat)]=np.nan;med=np.nanmedian(flat[tr],axis=0);med[~np.isfinite(med)]=0;bad=~np.isfinite(flat)
    if bad.any():flat[bad]=med[np.where(bad)[1]]
    sc=StandardScaler().fit(flat[tr]);z=sc.transform(flat);m=LogisticRegression(max_iter=1000,class_weight='balanced',solver='liblinear',random_state=seed);m.fit(z[tr],y[tr]);raw=m.decision_function(z)
    cal=LogisticRegression(C=1e6,solver='lbfgs',max_iter=300);cal.fit(raw[ca].reshape(-1,1),y[ca]);return cal.predict_proba(raw.reshape(-1,1))[:,1]


def robust_ref(pred):
    x=pred.reshape(len(pred),-1);center=np.median(x,axis=0);mad=np.median(np.abs(x-center),axis=0)*1.4826;std=np.std(x,axis=0);return center,np.maximum(mad,np.maximum(.1*std,1e-3))

def anomaly(pred,c,s):return np.mean(((pred.reshape(len(pred),-1)-c)/s)**2,axis=1)
def percentile(score,ref):
    r=np.sort(np.asarray(ref,float));return np.searchsorted(r,np.asarray(score,float),side='right')/max(1,len(r))
def threshold(benign):
    x=np.sort(np.asarray(benign,float))[::-1];allowed=int(math.floor(POLICY_FPR_RESERVE*len(x)))
    if not len(x):return None
    return float(np.nextafter(x[allowed] if allowed<len(x) else x[-1],np.inf))
def metric(y,s,th):
    p=np.asarray(s)>=th;tn,fp,fn,tp=confusion_matrix(y,p,labels=[0,1]).ravel();return {'n':int(len(y)),'positives':int((y==1).sum()),'negatives':int((y==0).sum()),'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),'fpr':float(fp/(fp+tn)) if fp+tn else None,'recall':float(tp/(tp+fn)) if tp+fn else None,'precision':float(tp/(tp+fp)) if tp+fp else None,'f1':float(f1_score(y,p,zero_division=0))}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train',nargs='+',required=True);p.add_argument('--calibration',required=True);p.add_argument('--policy',required=True);p.add_argument('--final',required=True);p.add_argument('--output',required=True);p.add_argument('--epochs',type=int,default=15);p.add_argument('--seeds',nargs='+',type=int,default=list(SEEDS));args=p.parse_args()
    if len(set(args.seeds))<3:p.error('At least three distinct seeds required')
    out=Path(args.output)
    if out.exists():p.error('Output exists; V49 evidence immutable')
    out.mkdir(parents=True)
    paths=[Path(x) for x in args.train]+[Path(args.calibration),Path(args.policy),Path(args.final)]
    dfs=[pd.read_parquet(x) for x in paths];common=common_schema(dfs);camps=[]
    names=[f'train_{i}' for i in range(len(args.train))]+['calibration','policy','final']
    for path,df,name,schema in zip(paths,dfs,names,common['per_file']):camps.append(make_campaign(df,schema,common['features'],name))
    data=combine(camps);tr=np.where(np.char.startswith(data['campaign'].astype(str),'train_'))[0];ca=np.where(data['campaign']=='calibration')[0];po=np.where(data['campaign']=='policy')[0];te_all=np.where(data['campaign']=='final')[0]
    # Final evaluation: all future-positive sequences vs clean-history/future-benign negatives.
    te_pos=te_all[data['y'][te_all]==1];te_neg=te_all[data['clean'][te_all]&(data['y'][te_all]==0)];te=np.concatenate([te_pos,te_neg]);te_y=np.concatenate([np.ones(len(te_pos),np.int8),np.zeros(len(te_neg),np.int8)])
    clean_pos=te_pos[data['clean'][te_pos]]
    if min(len(tr),len(ca),len(po),len(te_pos),len(te_neg))<20:raise ValueError(f'Insufficient role support train={len(tr)} cal={len(ca)} policy={len(po)} final_pos={len(te_pos)} final_neg={len(te_neg)}')
    report={'protocol':'V49 frozen campaign-level unseen-DDoS forecast','claim_boundary':'Fresh CSE-CIC-IDS2018 DDoS campaign excluded from all fitting. Unseen-family/day proxy, not real undisclosed zero-day or verified compromise lead time.','window_seconds':WINDOW_SECONDS,'history_seconds':HISTORY*WINDOW_SECONDS,'horizon_seconds':HORIZON*WINDOW_SECONDS,'roles':{'train':[str(x) for x in args.train],'calibration':args.calibration,'policy':args.policy,'final':args.final},'source':{str(p):{'bytes':p.stat().st_size,'sha256':sha256(p)} for p in paths},'common_raw_features':common['features'],'campaigns':[{k:c[k] for k in ('campaign','state_rows','sequence_rows','label_counts','timestamp_method')} for c in camps],'support':{'train':len(tr),'calibration':len(ca),'policy':len(po),'final_positive':len(te_pos),'final_clean_negative':len(te_neg),'clean_history_future_positive':len(clean_pos)},'frozen_fusion':{'risk_weight':RISK_WEIGHT,'world_weight':WORLD_WEIGHT,'policy_fpr_reserve':POLICY_FPR_RESERVE},'seeds':args.seeds,'results':{},'automatic_containment_approved':False}
    for seed in args.seeds:
        world=train_world(data['X'],data['future'],tr,ca,seed,args.epochs);risk=risk_lstm(data['X'],data['y'],tr,ca,seed,args.epochs);lr=logistic(data['X'],data['y'],tr,ca,seed)
        if risk is None:raise ValueError('Calibration lacks both risk classes')
        cal_benign=ca[data['clean'][ca]&(data['y'][ca]==0)];policy_benign=po[data['clean'][po]&(data['y'][po]==0)]
        if len(cal_benign)<40 or len(policy_benign)<100:raise ValueError(f'Benign calibration/policy support low: {len(cal_benign)}/{len(policy_benign)}')
        center,scale=robust_ref(world['pred'][cal_benign]);wraw=anomaly(world['pred'],center,scale);wp=percentile(wraw,wraw[cal_benign]);rp=percentile(risk,risk[cal_benign]);lp=percentile(lr,lr[cal_benign]);hy=RISK_WEIGHT*rp+WORLD_WEIGHT*wp
        th=threshold(hy[policy_benign]);lrth=threshold(lp[policy_benign]);wth=threshold(wp[policy_benign]);rth=threshold(rp[policy_benign])
        test_m=float(np.mean((world['pred'][te]-world['future'][te])**2));test_p=float(np.mean((world['persistence'][te]-world['future'][te])**2))
        row={'state':{'validation_mse':world['validation_mse'],'validation_persistence_mse':world['validation_persistence_mse'],'state_gate_passed':world['state_gate_passed'],'test_mse':test_m,'test_persistence_mse':test_p},'hybrid':metric(te_y,hy[te],th),'risk_lstm':metric(te_y,rp[te],rth),'world_novelty':metric(te_y,wp[te],wth),'logistic':metric(te_y,lp[te],lrth),'thresholds':{'hybrid':th,'risk_lstm':rth,'world_novelty':wth,'logistic':lrth}}
        cp=np.concatenate([clean_pos,te_neg]);cpy=np.concatenate([np.ones(len(clean_pos),np.int8),np.zeros(len(te_neg),np.int8)]);row['clean_history_hybrid']=metric(cpy,hy[cp],th) if len(clean_pos) else {'n':len(te_neg),'positives':0,'status':'no_clean_history_future_positive'}
        horizon=[]
        for h in range(1,HORIZON+1):
            hp=te_pos[data['first_horizon'][te_pos]==h];ids=np.concatenate([hp,te_neg]);yy=np.concatenate([np.ones(len(hp),np.int8),np.zeros(len(te_neg),np.int8)]);horizon.append({'lead_seconds':h*WINDOW_SECONDS,'positive_support':len(hp),'metrics':metric(yy,hy[ids],th) if len(hp) else None})
        row['first_attack_horizon']=horizon;report['results'][str(seed)]=row
    rows=list(report['results'].values());report['release_gate_all_seeds']=bool(all(r['state']['state_gate_passed'] and r['hybrid']['fpr'] is not None and r['hybrid']['fpr']<=RELEASE_FPR and r['hybrid']['recall'] is not None and r['hybrid']['recall']>=RELEASE_RECALL for r in rows));report['clean_pre_onset_gate_all_seeds']=bool(len(clean_pos)>=MIN_CLEAN_ONSET and all(r['clean_history_hybrid'].get('fpr') is not None and r['clean_history_hybrid']['fpr']<=RELEASE_FPR and r['clean_history_hybrid'].get('recall') is not None and r['clean_history_hybrid']['recall']>=RELEASE_RECALL for r in rows))
    def avg(path):
        vals=[]
        for r in rows:
            x=r
            for key in path:x=x[key]
            if x is not None:vals.append(float(x))
        return {'mean':float(np.mean(vals)) if vals else None,'sd':float(np.std(vals,ddof=1)) if len(vals)>1 else None}
    report['summary']={'hybrid_recall':avg(('hybrid','recall')),'hybrid_fpr':avg(('hybrid','fpr')),'risk_lstm_recall':avg(('risk_lstm','recall')),'risk_lstm_fpr':avg(('risk_lstm','fpr')),'world_recall':avg(('world_novelty','recall')),'world_fpr':avg(('world_novelty','fpr')),'logistic_recall':avg(('logistic','recall')),'logistic_fpr':avg(('logistic','fpr')),'clean_history_recall':avg(('clean_history_hybrid','recall')) if len(clean_pos) else {'mean':None,'sd':None}}
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n');print(json.dumps({'support':report['support'],'summary':report['summary'],'release_gate_all_seeds':report['release_gate_all_seeds'],'clean_pre_onset_gate_all_seeds':report['clean_pre_onset_gate_all_seeds']},indent=2))

if __name__=='__main__':main()
