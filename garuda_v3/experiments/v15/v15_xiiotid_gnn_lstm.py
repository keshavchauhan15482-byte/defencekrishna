import os, json, random, hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, average_precision_score, brier_score_loss

from v15_xiiotid_pilot_v2 import (
    SEEDS, HISTORY, HORIZON, MIN_RECALL, MAX_TRAIN,
    sha256, parse_time, detect_label, build_minute_state, time_split,
    sample_train, pick_col
)

OUT = Path('artifacts/v15_gnn')
OUT.mkdir(parents=True, exist_ok=True)


def select_graph_features(fcols):
    # Prefer stable per-minute means; add structural counters. The GNN self path still sees
    # all state features, while neighbor messages use this bounded subset for memory safety.
    means = [c for c in fcols if c.endswith('__mean')]
    structural = [c for c in ['flow_count', 'unique_dst'] if c in fcols]
    picked = (means[:24] + structural)[:26]
    if len(picked) < 4:
        picked = fcols[:min(26, len(fcols))]
    return picked


def build_neighbor_context(df, dt, state, graph_fcols, src_col, dst_col):
    if not src_col or not dst_col:
        raise RuntimeError('Source/destination IP columns required for GNN evaluation')
    edges = pd.DataFrame({
        'minute': dt.dt.floor('min'),
        'src': df[src_col].astype(str),
        'dst': df[dst_col].astype(str),
    }).dropna(subset=['minute'])
    # Multiple flows between the same endpoints in one minute are one graph edge for
    # mean-message passing. Edge multiplicity is already represented in node telemetry.
    edges = edges.drop_duplicates(['minute','src','dst'])

    dst_state = state[['minute','src'] + graph_fcols].copy()
    dst_state = dst_state.rename(columns={'src':'dst', **{c:'nbr__'+c for c in graph_fcols}})
    joined = edges.merge(dst_state, on=['minute','dst'], how='left', sort=False)
    nbr_cols = ['nbr__'+c for c in graph_fcols]
    joined['nbr_present'] = joined[nbr_cols].notna().any(axis=1).astype(float)
    # Mean over destination-node states observed at the same minute only.
    agg = joined.groupby(['src','minute'], sort=False)[nbr_cols + ['nbr_present']].mean().reset_index()
    degree = edges.groupby(['src','minute'], sort=False).size().rename('out_degree').reset_index()
    agg = agg.merge(degree, on=['src','minute'], how='left')
    out = state[['src','minute']].merge(agg, on=['src','minute'], how='left', sort=False)
    out['out_degree'] = out['out_degree'].fillna(0.0)
    out['nbr_present'] = out['nbr_present'].fillna(0.0)
    # A node with no matched internal destination neighbor gets zero message. NaNs inside
    # matched neighbor telemetry are preserved for train-only imputation later.
    no_nbr = out['nbr_present'].eq(0).to_numpy()
    out.loc[no_nbr, nbr_cols] = 0.0
    return out, nbr_cols + ['out_degree','nbr_present'], int(len(edges))


def make_graph_sequences(state, self_cols, nbr_state, nbr_cols):
    merged = state.merge(nbr_state, on=['src','minute'], how='left', sort=False)
    Xs, Xn, Y, cutoff, clean = [], [], [], [], []
    for src, g in merged.groupby('src', sort=False):
        g = g.sort_values('minute').reset_index(drop=True)
        t = g['minute'].astype('int64').to_numpy() // 10**9
        a = g['attack_now'].to_numpy(dtype=int)
        zs = g[self_cols].to_numpy(dtype=np.float32)
        zn = g[nbr_cols].to_numpy(dtype=np.float32)
        for i in range(HISTORY - 1, len(g) - HORIZON):
            lo = i - HISTORY + 1
            span = t[lo:i + HORIZON + 1]
            if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
                continue
            Xs.append(zs[lo:i+1]); Xn.append(zn[lo:i+1])
            Y.append(int(a[i+1:i+HORIZON+1].max()))
            cutoff.append(int(t[i])); clean.append(bool(a[lo:i+1].max() == 0))
    if not Xs:
        raise RuntimeError('No graph sequences with complete history/future horizon')
    return np.stack(Xs), np.stack(Xn), np.asarray(Y,int), np.asarray(cutoff,np.int64), np.asarray(clean,bool)


def fit_median(X, idx):
    z = X[idx].reshape(-1, X.shape[-1]).astype(np.float64)
    z[~np.isfinite(z)] = np.nan
    med = np.nanmedian(z, axis=0)
    med[~np.isfinite(med)] = 0.0
    return med.astype(np.float32)


def apply_impute(X, med):
    z = X.astype(np.float32, copy=True)
    bad = ~np.isfinite(z)
    if bad.any():
        cols = np.where(bad)[2]
        z[bad] = med[cols]
    return z


def platt_fit(raw, y):
    m = LogisticRegression(C=1e6, solver='lbfgs', max_iter=300)
    m.fit(np.asarray(raw).reshape(-1,1), y)
    return m


def platt_apply(m, raw):
    return m.predict_proba(np.asarray(raw).reshape(-1,1))[:,1]


def choose_threshold(y, p):
    best = None
    grid = np.unique(np.concatenate([np.linspace(.005,.995,199), p]))
    for th in grid:
        pred = p >= th
        tn,fp,fn,tp = confusion_matrix(y,pred,labels=[0,1]).ravel()
        rec = tp/(tp+fn) if tp+fn else 0.0
        fpr = fp/(fp+tn) if fp+tn else 1.0
        prec = tp/(tp+fp) if tp+fp else 0.0
        if rec >= MIN_RECALL:
            cand = (fpr,-rec,-prec,float(th))
            if best is None or cand < best: best = cand
    return None if best is None else best[3]


def metrics(y,p,th,clean):
    pred = p >= th
    tn,fp,fn,tp = confusion_matrix(y,pred,labels=[0,1]).ravel()
    mask = clean & (y == 1)
    return {
        'n':int(len(y)), 'benign':int((y==0).sum()), 'attack':int((y==1).sum()),
        'threshold':float(th), 'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),
        'fpr':float(fp/(fp+tn)) if fp+tn else None,
        'recall':float(tp/(tp+fn)) if tp+fn else None,
        'precision':float(tp/(tp+fp)) if tp+fp else None,
        'f1':float(f1_score(y,pred,zero_division=0)),
        'pr_auc':float(average_precision_score(y,p)),
        'brier':float(brier_score_loss(y,p)),
        'clean_history_future_positive_n':int(mask.sum()),
        'clean_history_future_positive_recall':float(pred[mask].mean()) if mask.any() else None,
    }


def gnn_lstm_run(Xs, Xn, y, clean, split, seed):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
    torch.set_num_threads(max(1,min(2,os.cpu_count() or 1)))
    tr = sample_train(split['train'], y, seed)
    med_s, med_n = fit_median(Xs,tr), fit_median(Xn,tr)
    S, N = apply_impute(Xs,med_s), apply_impute(Xn,med_n)
    ss = StandardScaler().fit(S[tr].reshape(-1,S.shape[-1]))
    ns = StandardScaler().fit(N[tr].reshape(-1,N.shape[-1]))
    def scaled(idx):
        a = ss.transform(S[idx].reshape(-1,S.shape[-1])).reshape(len(idx),S.shape[1],S.shape[2]).astype(np.float32)
        b = ns.transform(N[idx].reshape(-1,N.shape[-1])).reshape(len(idx),N.shape[1],N.shape[2]).astype(np.float32)
        return a,b
    xst,xnt = scaled(tr); yt = y[tr].astype(np.float32)

    class GraphSAGELSTM(nn.Module):
        def __init__(self, fs, fn):
            super().__init__()
            self.self_proj = nn.Linear(fs,32)
            self.nbr_proj = nn.Linear(fn,32,bias=False)
            self.norm = nn.LayerNorm(32)
            self.rnn = nn.LSTM(32,32,batch_first=True)
            self.head = nn.Sequential(nn.Linear(32,16),nn.ReLU(),nn.Linear(16,1))
        def forward(self, xs, xn):
            h = torch.relu(self.norm(self.self_proj(xs) + self.nbr_proj(xn)))
            o,_ = self.rnn(h)
            return self.head(o[:,-1]).squeeze(1)

    net = GraphSAGELSTM(S.shape[-1],N.shape[-1])
    pos=max(1,int((yt==1).sum())); neg=max(1,int((yt==0).sum()))
    lossfn=nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg/pos],dtype=torch.float32))
    opt=torch.optim.Adam(net.parameters(),lr=1e-3,weight_decay=1e-5)
    dl=DataLoader(TensorDataset(torch.from_numpy(xst),torch.from_numpy(xnt),torch.from_numpy(yt)),batch_size=256,shuffle=True)
    for _ in range(12):
        net.train()
        for a,b,t in dl:
            opt.zero_grad(set_to_none=True); loss=lossfn(net(a,b),t); loss.backward(); opt.step()
    def logits(idx):
        net.eval(); a,b=scaled(idx); out=[]
        with torch.no_grad():
            for i in range(0,len(a),1024): out.append(net(torch.from_numpy(a[i:i+1024]),torch.from_numpy(b[i:i+1024])).numpy())
        return np.concatenate(out)
    ca,po,te=split['calibration'],split['policy'],split['test']
    cal=platt_fit(logits(ca),y[ca])
    ppol=platt_apply(cal,logits(po)); th=choose_threshold(y[po],ppol)
    actionable=th is not None
    if th is None: th=.5
    ptest=platt_apply(cal,logits(te))
    return metrics(y[te],ptest,th,clean[te]), actionable, int((~np.isfinite(Xs[tr])).sum()), int((~np.isfinite(Xn[tr])).sum())


def main():
    import kagglehub
    handle='munaalhawawreh/xiiotid-iiot-intrusion-dataset'
    root=Path(kagglehub.dataset_download(handle)); csvs=list(root.rglob('*.csv'))
    if not csvs: raise RuntimeError('No CSV in X-IIoTID package')
    csv_path=max(csvs,key=lambda p:p.stat().st_size)
    prov={'dataset':'X-IIoTID','transport_mirror':handle,'filename':csv_path.name,'bytes':int(csv_path.stat().st_size),'sha256':sha256(csv_path)}
    print('DATASET',json.dumps(prov,indent=2),flush=True)
    df=pd.read_csv(csv_path,low_memory=False); prov.update({'rows':int(len(df)),'columns':int(len(df.columns))})
    dt,date_col,ts_col,time_method,parsed_fraction=parse_time(df)
    y,label_col,label_reports=detect_label(df)
    state,fcols,raw_features,src_col,dst_col=build_minute_state(df,dt,y,label_col,date_col,ts_col)
    graph_fcols=select_graph_features(fcols)
    nbr_state,nbr_cols,edge_count=build_neighbor_context(df,dt,state,graph_fcols,src_col,dst_col)
    Xs,Xn,target,cutoff,clean=make_graph_sequences(state,fcols,nbr_state,nbr_cols)
    split,bounds=time_split(cutoff,target)
    report={
      'schema':'krishna-v15-xiiotid-graphsage-lstm-v1',
      'claim_scope':'One-hop mean-message GraphSAGE-style spatial encoder plus LSTM temporal encoder on the same fresh chronological X-IIoTID protocol. Not verified-compromise forecasting or campaign-independent validation.',
      'provenance':prov,
      'graph':{'source_ip_col':src_col,'destination_ip_col':dst_col,'unique_minute_edges':edge_count,'self_state_features':len(fcols),'neighbor_message_features':len(nbr_cols),'neighbor_base_features':graph_fcols,'message_rule':'mean destination-node state at same minute; no future graph rows'},
      'sequence':{'history_minutes':HISTORY,'future_horizon_minutes':HORIZON,'n':int(len(Xs)),'benign_targets':int((target==0).sum()),'attack_targets':int((target==1).sum()),'clean_history_n':int(clean.sum())},
      'split_boundaries':bounds,
      'splits':{k:{'n':int(len(v)),'benign':int((target[v]==0).sum()),'attack':int((target[v]==1).sum()),'first_cutoff_epoch':int(cutoff[v].min()),'last_cutoff_epoch':int(cutoff[v].max())} for k,v in split.items()},
      'seeds':{}
    }
    for seed in SEEDS:
        print('SEED',seed,'GNN+LSTM',flush=True)
        m,actionable,sbad,nbad=gnn_lstm_run(Xs,Xn,target,clean,split,seed)
        report['seeds'][str(seed)]={'gnn_lstm':m,'actionable':actionable,'self_train_nonfinite_imputed':sbad,'neighbor_train_nonfinite_imputed':nbad}
        print(json.dumps(report['seeds'][str(seed)],indent=2),flush=True)
    keys=['fpr','recall','precision','f1','pr_auc','brier','clean_history_future_positive_recall']
    mean={}
    for k in keys:
        vals=[report['seeds'][str(s)]['gnn_lstm'][k] for s in SEEDS if report['seeds'][str(s)]['gnn_lstm'][k] is not None]
        mean[k]=float(np.mean(vals)) if vals else None
    report['three_seed_mean']=mean
    report['release_gate']={
      'engineering_target':'mean FPR <= 0.06 and mean recall >= 0.80 with valid policy threshold in every seed',
      'gnn_lstm_pass':bool(mean['fpr']<=.06 and mean['recall']>=.80 and all(report['seeds'][str(s)]['actionable'] for s in SEEDS)),
      'evidence_limit':'Same as V15 pilot: zero clean-history future-positive test examples means no pre-compromise warning claim.'
    }
    (OUT/'results.json').write_text(json.dumps(report,indent=2))
    lines=['# Krishna Defence V15 — X-IIoTID GNN+LSTM','',report['claim_scope'],'','## Three-seed mean','',json.dumps(mean,indent=2),'','## Gate','',json.dumps(report['release_gate'],indent=2),'','## Graph protocol','',json.dumps(report['graph'],indent=2)]
    (OUT/'REPORT.md').write_text('\n'.join(lines))
    print('FINAL_GNN_MEAN',json.dumps(mean,indent=2),flush=True)
    print('GNN_GATE',json.dumps(report['release_gate'],indent=2),flush=True)

if __name__=='__main__': main()
