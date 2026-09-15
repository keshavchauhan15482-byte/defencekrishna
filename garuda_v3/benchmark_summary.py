"""Reproducible, equal-treatment summary across matched residual model runs."""
import hashlib,json
from pathlib import Path
import numpy as np

def summarize(root=None):
    root=Path(root) if root else Path(__file__).parent/'artifacts'
    paths=[root/n/'metrics.json' for n in ('residual_run','residual_seed7','residual_seed19')]
    runs=[json.loads(p.read_text()) for p in paths]
    for r in runs[1:]:
        for field in ('split_boundaries','split_counts','sources','target'):
            if r[field]!=runs[0][field]:raise ValueError('Incomparable seed runs: '+field)
    models={}
    for model in ('logistic_regression','lstm','gnn_lstm'):
        rows=[r['models'][model] for r in runs]
        result={}
        for key in ('f1','precision','recall','fpr','brier'):
            v=[r['test'][key] for r in rows]
            result[key]=dict(mean=float(np.mean(v)),sd=float(np.std(v,ddof=1)),values=v)
        if all('state_mse' in r for r in rows):
            v=[r['state_mse'] for r in rows]
            result['state_mse']=dict(mean=float(np.mean(v)),sd=float(np.std(v,ddof=1)),values=v)
        models[model]=result
    return dict(seeds=[r['config']['seed'] for r in runs],models=models,test_samples=runs[0]['models']['gnn_lstm']['test']['samples'],
                persistence_mse=runs[0]['state_persistence_mse'],
                scope='Three initialization seeds on the same reused internal holdout; sample SD, not independent-dataset uncertainty. Logistic regression repeats the same deterministic baseline.',
                primary_run=runs[0]['models'],provenance=[dict(path=str(p.relative_to(root)),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths])
if __name__=='__main__':print(json.dumps(summarize(),indent=2))
