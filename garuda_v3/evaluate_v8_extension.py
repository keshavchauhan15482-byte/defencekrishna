"""Fixed-model evaluation of the predeclared remaining capture; no fitting or tuning."""
import json,hashlib
from pathlib import Path
import numpy as np
from .data import load_dataset
from .train import batch,infer,pooled,metrics
from .model import GraphWorldModel
from .calibration import apply,family_report,future_target
from .state_evaluation import state_evidence

def main():
 root=Path('datasets/ids2018/diverse_v8_extension');out=root/'evaluation.json'
 if out.exists():raise ValueError('Extension already evaluated; do not overwrite')
 protocol=json.loads((root/'protocol.json').read_text());folder=Path(protocol['model_dir'])
 for name,sha in protocol['checkpoint_sha256'].items():
  if hashlib.sha256((folder/name).read_bytes()).hexdigest()!=sha:raise ValueError('Frozen model changed')
 d=load_dataset(root/'labelled_graph.npz');indices=[];h=8;k=4
 for i in range(0,len(d['times'])-h-k+1,2):
  if np.all(np.diff(d['times'][i:i+h+k])==60):indices.append((0,i))
 report=dict(scale_deviation=json.loads((root/'scale_deviation.json').read_text()),graph_nodes_limit=d['metadata']['max_nodes'],max_observed_nodes=int(d['mask'].sum(1).max()),scope='Additional previously unseen victim-capture part; extension selected after initial part had no positives. Fixed weights and thresholds, no model selection on extension.',examples=len(indices),label_quality=d['metadata']['annotation_status'],timezone_assumption=d['metadata']['timezone_assumption'],source_sha256=d['metadata']['source_sha256'],models={},release_approved=False)
 if indices:
  arrays=batch([d],indices,h,k);base=pooled(arrays[0],arrays[2])[:,-1:];means={};trained=json.loads((folder/'metrics.json').read_text())
  for name in ['lstm','gnn_lstm']:
   model,meta=GraphWorldModel.load(folder/(name+'.npz'));mu,sd,risk=infer(model,arrays,k,batch_size=4);risk=apply(risk,meta.get('risk_calibration',{'status':'disabled'}));means[name]=mu
   th=meta['alert_threshold'];early=trained['models'][name]['clean_history_warning_policy'];clean=arrays[5]==0
   report['models'][name]=dict(last_horizon=metrics(arrays[4][:,-1],risk[:,-1],meta['threshold']),any_horizon=family_report([d],indices,arrays[4],risk,th if th<=1 else None),clean_history_future_positive_examples=int((future_target(arrays[4][clean])==1).sum()),clean_history_warning_policy=dict(threshold=early['threshold'],status=early['status'],metrics=metrics(future_target(arrays[4][clean]),risk[clean].max(1),early['threshold'])),state=state_evidence(mu,arrays[3],base))
   np.savez_compressed(root/(name+'_predictions.npz'),probabilities=risk,labels=arrays[4],state_prediction=mu,state_target=arrays[3],indices=indices)
  lr=np.load(folder/'logistic_regression.npz');flat=pooled(arrays[0],arrays[2]).reshape(len(indices),-1);z=flat@lr['weights'].T+lr['bias'];p=1/(1+np.exp(-np.clip(z.ravel(),-35,35)))
  report['models']['logistic_regression']=dict(last_horizon=metrics(arrays[4][:,-1],p,float(lr['threshold'])))
  report['gnn_vs_lstm_state']=state_evidence(means['gnn_lstm'],arrays[3],means['lstm'])
 out.write_text(json.dumps(report,indent=2,allow_nan=False));print(json.dumps({n:{k:v for k,v in m.items() if k!='state'} for n,m in report['models'].items()},indent=2))
if __name__=='__main__':main()
