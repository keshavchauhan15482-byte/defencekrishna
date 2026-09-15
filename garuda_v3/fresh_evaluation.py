"""Evaluate frozen checkpoints once on the predeclared original DoS victim capture."""
import json,hashlib
from pathlib import Path
from datetime import datetime,timezone,timedelta
import numpy as np
from .ids2018_prepare import clean
from .pcap import convert_pcap
from .pcap_reader import packets
from .data import save_dataset
from .model import GraphWorldModel
from .train import batch,infer,pooled
from .calibration import apply,family_report
from .state_evaluation import state_evidence

def main():
 root=Path('datasets/ids2018/fresh_holdout');protocol=json.loads((root/'frozen_protocol.json').read_text());modeldir=Path(protocol['model_dir'])
 if (root/'evaluation.json').exists():raise ValueError('Fresh evaluation already consumed; preserve report and do not retune')
 for name,sha in protocol['checkpoint_sha256'].items():
  if hashlib.sha256((modeldir/name).read_bytes()).hexdigest()!=sha:raise ValueError('Frozen checkpoint changed')
 path=root/'Thursday-15-02-2018.pcap';cleaned,audit=clean(path,root)
 d=convert_pcap(cleaned,window_seconds=60,max_nodes=64,max_packets=1000000)
 keep=~np.isin(d['times'],audit['excluded_windows'])
 for k in ('x','adj','mask','y','times'):d[k]=d[k][keep]
 d['metadata']['node_names']=[v for v,k in zip(d['metadata']['node_names'],keep) if k]
 ranges=[]
 for s in protocol['schedule']:
  ts=[datetime.fromisoformat(s[k]).replace(tzinfo=timezone.utc).timestamp()+4*3600 for k in ('start','end')];ranges.append((*ts,set(s['attacker'])))
 peers={}
 for p in packets(cleaned,max_packets=1000000):
  t=int(p['t']//60)*60
  for _,_,hosts in ranges:
   if p['src'] in hosts or p['dst'] in hosts:peers[t]=True
 y=[]
 for t in d['times']:
  full=any(a+60<=t and t+60<=b-60 for a,b,_ in ranges);overlap=any(t<b+60 and t+60>a-60 for a,b,_ in ranges)
  y.append(1 if full and peers.get(t) else -1 if overlap or peers.get(t) else 0)
 d['y']=np.asarray(y,dtype=np.int8);d['metadata'].update(campaign_id=protocol['capture_day'],attack_family='dos',annotation_status='schedule-assisted weak labels; UTC-04:00 assumption unverified',incidents=[],windows=len(y))
 save_dataset(d,root/'labelled_graph.npz')
 h=protocol['history'];k=protocol['horizon'];indices=[]
 for start in range(0,len(y)-h-k+1,protocol['stride']):
  if np.any(np.diff(d['times'][start:start+h+k])!=60) or np.any(d['y'][start:start+h+k]<0):continue
  indices.append((0,start))
 report=dict(protocol=protocol,source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),preprocessing=audit,labels={str(v):int((d['y']==v).sum()) for v in [-1,0,1]},examples=len(indices),models={},release_approved=False,scope='One new capture day and DoS family; weak schedule-assisted labels, not verified compromise/stage evidence')
 if indices:
  arrays=batch([d],indices,h,k);base=pooled(arrays[0],arrays[2])[:,-1:]
  outputs={}
  for name in ('lstm','gnn_lstm'):
   model,meta=GraphWorldModel.load(modeldir/(name+'.npz'));mu,sd,risk=infer(model,arrays,k);risk=apply(risk,meta.get('risk_calibration',{'status':'disabled'}));th=meta['alert_threshold']
   outputs[name]=mu
   report['models'][name]=dict(per_family=family_report([d],indices,arrays[4],risk,th if th<=1 else None),state=state_evidence(mu,arrays[3],base),state_mse=float(np.mean((mu-arrays[3])**2)),clean_history_positive_examples=int(arrays[4][arrays[5]==0].max(1).sum()))
   np.savez_compressed(root/(name+'_predictions.npz'),probabilities=risk,labels=arrays[4],state_prediction=mu,state_target=arrays[3],example_indices=indices)
  report['gnn_vs_lstm']=state_evidence(outputs['gnn_lstm'],arrays[3],outputs['lstm'])
  report['gnn_vs_lstm']['interpretation']='Negative paired difference favors GNN over LSTM. Persistence-labelled field names refer to LSTM here.'
 (root/'evaluation.json').write_text(json.dumps(report,indent=2,allow_nan=False));print(json.dumps({k:v for k,v in report.items() if k not in ('protocol','preprocessing')},indent=2))
if __name__=='__main__':main()
