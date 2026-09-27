"""V125 targeted untouched native Initial Access replication for V124.

V124 remains immutable. This runner deterministically reconstructs the V124 validation-selected
ExtraTrees classifier from the same train+validation records, then evaluates exactly one
pre-registered, previously unused UWF-ZeekData24 Initial_Access CSV. No retuning is allowed.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, urllib.request
from pathlib import Path
import numpy as np
from .v124_native_five_stage_train import STAGES, SOURCES, FEATURES, load, fnum, norm_stage

FRESH_URL="https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Initial_Access/part-00000-9a37b839-429e-444b-82a5-a6d5e69dad7e-c000.csv"
MIN_ROWS=10
MIN_RECALL=0.40

def sha(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()

def row_features(row):
 x=[fnum(row.get(k,'')) for k in FEATURES]
 proto=str(row.get('proto','')).lower(); service=str(row.get('service','')).lower()
 return x+[float(proto=='tcp'),float(proto=='udp'),float(service=='http'),float(service=='ftp'),float(service=='smb')]

def main()->int:
 ap=argparse.ArgumentParser(); ap.add_argument('--prereg',required=True,type=Path); ap.add_argument('--base-result',required=True,type=Path); ap.add_argument('--output',required=True,type=Path); args=ap.parse_args()
 if args.output.exists(): raise RuntimeError('V125 result already exists and is immutable')
 prereg=json.loads(args.prereg.read_text()); base=json.loads(args.base_result.read_text())
 if prereg.get('status')!='SOURCE_SELECTED_BEFORE_METRICS' or prereg['fresh_test_source']['url']!=FRESH_URL: raise RuntimeError('V125 preregistration mismatch')
 if float(prereg['replication_gate']['minimum_initial_access_recall'])!=MIN_RECALL or prereg['replication_gate']['proxy_mapping_permitted'] is not False: raise RuntimeError('V125 gate changed')
 if base.get('schema_version')!='v124-five-stage.1' or base.get('proxy_mapping_used') is not False: raise RuntimeError('V124 base evidence invalid')
 # V124 must remain an immutable FAIL caused only by Initial Access falling below 0.40.
 other=[s for s in STAGES if s!='Initial Access']
 if base.get('status')!='FAIL' or not all(base['test']['per_stage'][s]['recall']>=MIN_RECALL for s in other): raise RuntimeError('Unexpected V124 base-stage state')
 if not (base['test']['per_stage']['Initial Access']['recall']<MIN_RECALL): raise RuntimeError('V124 Initial Access was not the failed stage')

 work=args.output.parent/'sources'; train_root=work/'training'; fresh_root=work/'fresh'; train_root.mkdir(parents=True,exist_ok=True); fresh_root.mkdir(parents=True,exist_ok=True)
 X=[]; y=[]; source_hashes={}
 for i,s in enumerate(STAGES):
  p,rows=load(s,SOURCES[s],train_root); n=len(rows); b=max(max(1,int(n*.60))+1,int(n*.80)); b=min(b,n-1)
  chosen=rows[:b]; X.extend([r[1] for r in chosen]); y.extend([i]*len(chosen)); source_hashes[s]={'sha256':sha(p),'fit_rows':len(chosen),'total_rows':n}
 from sklearn.ensemble import ExtraTreesClassifier
 model=ExtraTreesClassifier(n_estimators=400,min_samples_leaf=1,max_features='sqrt',class_weight='balanced',random_state=20260927,n_jobs=2)
 model.fit(np.asarray(X,float),np.asarray(y))

 fresh=fresh_root/'initial_access_uwf_zeekdata24.csv'; req=urllib.request.Request(FRESH_URL,headers={'User-Agent':'Garuda-V125/1.0'})
 with urllib.request.urlopen(req,timeout=120) as r, fresh.open('wb') as w: w.write(r.read())
 rows=[]
 with fresh.open(newline='',encoding='utf-8-sig') as f:
  for row in csv.DictReader(f):
   if norm_stage(row.get('label_tactic',''))!='initial access': raise RuntimeError(f'Fresh source contains non-native Initial Access label: {row.get("label_tactic")}')
   rows.append(row_features(row))
 if len(rows)<MIN_ROWS: raise RuntimeError(f'Fresh Initial Access rows {len(rows)} < prereg minimum {MIN_ROWS}')
 pred=model.predict(np.asarray(rows,float)); ia=STAGES.index('Initial Access'); recall=float(np.mean(pred==ia)); counts={s:int(np.sum(pred==i)) for i,s in enumerate(STAGES)}
 replication_pass=bool(recall>=MIN_RECALL)
 composite_pass=bool(replication_pass and base['test']['macro_recall']>=0.60 and all(base['test']['per_stage'][s]['recall']>=MIN_RECALL for s in other))
 result={
  'schema_version':'v125-ia-replication.1','status':'PASS' if replication_pass else 'FAIL','composite_five_stage_evidence_status':'PASS' if composite_pass else 'FAIL',
  'base_v124_status':'FAIL_IMMUTABLE','proxy_mapping_used':False,'model_selection':'frozen V124 validation winner extra_trees; no fresh-test selection','fresh_source':{'dataset_release':'UWF-ZeekData24','native_tactic':'Initial Access','url':FRESH_URL,'sha256':sha(fresh),'rows':len(rows),'used_in_v124_training_or_test':False},
  'replication':{'initial_access_recall':recall,'minimum_recall_gate':MIN_RECALL,'prediction_counts':counts,'gate_passed':replication_pass},
  'base_other_stage_evidence':{s:base['test']['per_stage'][s] for s in other},'base_macro_recall':base['test']['macro_recall'],'training_reconstruction':{'winner':'extra_trees','source_hashes':source_hashes,'fresh_test_used_for_fit':False,'fresh_test_used_for_selection':False,'retuned_on_fresh_test':False},
  'claim_boundary':'Composite exact-native five-stage evidence: V124 supplies independently held-out Reconnaissance/Lateral Movement/Command and Control/Exfiltration results; V125 supplies a separately preregistered untouched native Initial Access replication. V124 itself remains FAIL and is not rewritten.'
 }
 args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
