import json,hashlib
from pathlib import Path
import numpy as np
from garuda_v3.data import load_dataset,campaign_examples
from garuda_v3.train import batch,metrics
from garuda_v3.support_gate import fit,score
from garuda_v3.model import GraphWorldModel
import argparse
p=argparse.ArgumentParser(description='Fit input support gate on training/validation only; report abstention coverage')
p.add_argument('--data-root',default='datasets/ids2018');p.add_argument('--artifacts',required=True)
a=p.parse_args();root=Path(a.data_root);out=Path(a.artifacts)
r=json.loads((out/'metrics.json').read_text());ds=[load_dataset(p) for p in r['config']['graphs']]
splits,_=campaign_examples(ds,json.loads((root/'split.json').read_text()),8,4,2);arrays=[batch(ds,s,8,4) for s in splits]
gate=fit(arrays[0][0],arrays[0][2],arrays[1][0],arrays[1][2]);(out/'support_gate.json').write_text(json.dumps(gate,indent=2))
accepted=score(gate,arrays[2][0],arrays[2][2])<=gate['threshold']
with np.load(out/'gnn_lstm_test_predictions.npz') as p:prob=p['probabilities'][:,-1]
r['support_gate_diagnostic']=dict(evaluation_scope='development diagnostic added after observing ungated holdout failure; NOT a new blind test',
 test_examples=len(accepted),accepted_examples=int(accepted.sum()),abstained_examples=int((~accepted).sum()),coverage=float(accepted.mean()),
 accepted_test=metrics(arrays[2][4][accepted,-1],prob[accepted],r['models']['gnn_lstm']['threshold']),
 interpretation='Abstentions are unknown, not benign or prevented attacks. Overall ungated failures remain in report.')
for name in ('gnn_lstm','lstm'):
 model,meta=GraphWorldModel.load(out/(name+'.npz'));meta.update(support_gate='support_gate.json',
  validation_scope='exploratory cross-family PCAP holdout with schedule-assisted weak labels; not zero-day evidence',
  target='future windows containing scheduled attacker-endpoint traffic (weak supervision); not compromise probability',
  label_quality='schedule-assisted; timezone alignment assumed UTC-04:00',promotion_status='research_only_not_default')
 model.save(out/(name+'.npz'),meta)
r['checkpoint_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.npz')}
r['checkpoint_sha256']['support_gate.json']=hashlib.sha256((out/'support_gate.json').read_bytes()).hexdigest()
r['evaluation_scope']='exploratory cross-family PCAP holdout; schedule-assisted weak labels'
r['limitations']+=['timezone UTC-04:00 inferred from schedule alignment, not publisher-confirmed','only selected victim captures; not all days or traffic','no clean-history future positives survive conservative exclusion','test support differs strongly from training; 40/40 negative examples falsely alert before gate']
(out/'metrics.json').write_text(json.dumps(r,indent=2,allow_nan=False));print(json.dumps(r['support_gate_diagnostic'],indent=2))
