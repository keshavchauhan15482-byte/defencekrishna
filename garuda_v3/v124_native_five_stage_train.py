"""V124 exact-native five-stage MITRE tactic classifier certification.

Uses only publisher-labelled UWF Zeek network records with the exact five SIH tactics.
No proxy mapping is permitted. Sources are fixed before metrics; each class is sorted by
timestamp and split 60/20/20 chronologically. Candidate head selection is validation-only;
final test is scored once after the winner is frozen in memory.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, urllib.request
from pathlib import Path
import numpy as np

STAGES = ["Reconnaissance","Initial Access","Lateral Movement","Command and Control","Exfiltration"]
SOURCES = {
 "Reconnaissance": "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Reconnaissance/part-00000-ae3fd4d9-9aba-4c1d-968c-88755355ee78-c000.csv",
 "Initial Access": "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Initial_Access/part-00000-e6022464-fb77-4508-a850-006424f5de8a-c000.csv",
 "Lateral Movement": "https://datasets.uwf.edu/data/UWF-ZeekDataFall24-2/csv/Lateral_Movement/part-00000-0d012414-989a-4b0f-937d-36b02cacf398-c000.csv",
 "Command and Control": "https://datasets.uwf.edu/data/UWF-ZeekDataFall22/csv/Command_and_Control/part-00000-c365ae06-4940-4fb1-b261-3a9ed9970961-c000.csv",
 "Exfiltration": "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Exfiltration/part-00000-6a530c25-0f6b-46a1-ba16-c6b658ef75e8-c000.csv",
}
FEATURES=["duration","missed_bytes","orig_bytes","orig_ip_bytes","orig_pkts","resp_bytes","resp_ip_bytes","resp_pkts","src_port_zeek","dest_port_zeek"]
MIN_ROWS=10

def sha(path):
 h=hashlib.sha256();
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()

def norm_stage(v): return str(v).strip().replace('_',' ').lower()
def fnum(v):
 try: return float(v)
 except Exception: return 0.0

def load(stage,url,root):
 p=root/(stage.lower().replace(' ','_')+'.csv')
 req=urllib.request.Request(url,headers={'User-Agent':'Garuda-V124/1.0'})
 with urllib.request.urlopen(req,timeout=120) as r, p.open('wb') as w: w.write(r.read())
 rows=[]
 with p.open(newline='',encoding='utf-8-sig') as f:
  for row in csv.DictReader(f):
   if norm_stage(row.get('label_tactic','')) != stage.lower():
    raise RuntimeError(f'native label mismatch for {stage}: {row.get("label_tactic")}')
   x=[fnum(row.get(k,'')) for k in FEATURES]
   # stable protocol indicators remain network-only and improve stage separation
   proto=str(row.get('proto','')).lower(); service=str(row.get('service','')).lower()
   x += [float(proto=='tcp'),float(proto=='udp'),float(service=='http'),float(service=='ftp'),float(service=='smb')]
   rows.append((fnum(row.get('ts','0')),x))
 rows.sort(key=lambda z:z[0])
 return p,rows

def metrics(y,pred):
 out={}; recalls=[]
 for i,s in enumerate(STAGES):
  tp=int(np.sum((y==i)&(pred==i))); fn=int(np.sum((y==i)&(pred!=i))); fp=int(np.sum((y!=i)&(pred==i)))
  rec=tp/(tp+fn) if tp+fn else 0.; pre=tp/(tp+fp) if tp+fp else 0.; f1=2*pre*rec/(pre+rec) if pre+rec else 0.
  out[s]={'support':int(np.sum(y==i)),'tp':tp,'fp':fp,'fn':fn,'precision':pre,'recall':rec,'f1':f1}; recalls.append(rec)
 return {'accuracy':float(np.mean(y==pred)),'macro_recall':float(np.mean(recalls)),'per_stage':out}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--output',required=True,type=Path); args=ap.parse_args()
 if args.output.exists(): raise RuntimeError('immutable V124 result already exists')
 root=args.output.parent/'sources'; root.mkdir(parents=True,exist_ok=True)
 Xtr=[];ytr=[];Xv=[];yv=[];Xt=[];yt=[]; source={}
 for i,s in enumerate(STAGES):
  p,rows=load(s,SOURCES[s],root); n=len(rows)
  if n<MIN_ROWS: raise RuntimeError(f'{s} has only {n} native rows; need {MIN_ROWS}')
  a=max(1,int(n*.60)); b=max(a+1,int(n*.80)); b=min(b,n-1)
  parts=[rows[:a],rows[a:b],rows[b:]]
  if min(map(len,parts))<1: raise RuntimeError(f'{s} split empty')
  for arr,XX,yy in zip(parts,[Xtr,Xv,Xt],[ytr,yv,yt]):
   XX.extend([r[1] for r in arr]); yy.extend([i]*len(arr))
  source[s]={'url':SOURCES[s],'rows':n,'sha256':sha(p),'train':len(parts[0]),'validation':len(parts[1]),'test':len(parts[2])}
 Xtr=np.asarray(Xtr,float); Xv=np.asarray(Xv,float); Xt=np.asarray(Xt,float); ytr=np.asarray(ytr); yv=np.asarray(yv); yt=np.asarray(yt)
 from sklearn.ensemble import ExtraTreesClassifier
 from sklearn.linear_model import LogisticRegression
 from sklearn.pipeline import Pipeline
 from sklearn.preprocessing import StandardScaler
 candidates={
  'logistic':Pipeline([('s',StandardScaler()),('m',LogisticRegression(max_iter=3000,class_weight='balanced',C=.5,random_state=20260927))]),
  'extra_trees':ExtraTreesClassifier(n_estimators=400,min_samples_leaf=1,max_features='sqrt',class_weight='balanced',random_state=20260927,n_jobs=2),
 }
 val=[]
 for name,m in candidates.items():
  m.fit(Xtr,ytr); mm=metrics(yv,m.predict(Xv)); val.append((mm['macro_recall'],mm['accuracy'],name,mm))
 val.sort(reverse=True); winner=val[0][2]
 # freeze architecture from validation, then refit on train+validation only
 model=candidates[winner]; model.fit(np.vstack([Xtr,Xv]),np.concatenate([ytr,yv])); test=metrics(yt,model.predict(Xt))
 gates={
  'all_exact_native_labels_no_proxy':True,
  'all_stage_source_rows_at_least_10':all(v['rows']>=MIN_ROWS for v in source.values()),
  'all_stage_test_support_at_least_2':all(v['support']>=2 for v in test['per_stage'].values()),
  'test_macro_recall_at_least_0_60':test['macro_recall']>=.60,
  'each_stage_recall_at_least_0_40':all(v['recall']>=.40 for v in test['per_stage'].values()),
 }
 result={'schema_version':'v124-five-stage.1','status':'PASS' if all(gates.values()) else 'FAIL','proxy_mapping_used':False,'stages':STAGES,'network_features':FEATURES+['proto_tcp','proto_udp','service_http','service_ftp','service_smb'],'source':source,'selection':{'split':'per-class chronological 60/20/20','validation_candidates':[{'name':n,'macro_recall':mr,'accuracy':a} for mr,a,n,_ in val],'winner':winner},'test':test,'gates':gates,'claim_boundary':'Exact publisher-native five-stage network-record classifier evidence. This certifies the five requested stage labels without proxy mapping; it does not by itself claim successful-compromise lead time.'}
 args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
