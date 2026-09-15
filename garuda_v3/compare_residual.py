"""Recompute paired diagnostics for bundled, already-seen development holdouts."""
import json
from pathlib import Path
import numpy as np
from .data import load_dataset,build_examples
from .train import batch,pooled
from .state_evaluation import state_evidence

def main():
    root=Path(__file__).parent/'artifacts'
    ds=[load_dataset(root/f'{day}.npz') for day in ('Thursday','Friday')]
    splits,_=build_examples(ds,8,4,8);arrays=[batch(ds,s,8,4) for s in splits]
    persistence=pooled(arrays[2][0],arrays[2][2])[:,-1:]
    rows=[]
    for name in ('residual_run','residual_seed7','residual_seed19'):
        folder=root/name;report=json.loads((folder/'metrics.json').read_text())
        for a,counts in zip(arrays,report['split_counts']):
            counts['clean_history_future_positive_examples']=int(a[4][a[5]==0].max(axis=1).sum())
        for architecture in ('lstm','gnn_lstm'):
            with np.load(folder/f'{architecture}_test_predictions.npz',allow_pickle=False) as p:
                report['models'][architecture]['state_evidence']=state_evidence(p['state_prediction'],p['state_target'],persistence,report['config']['seed'])
        (folder/'metrics.json').write_text(json.dumps(report,indent=2,allow_nan=False))
        g=report['models']['gnn_lstm'];rows.append(dict(run=name,seed=report['config']['seed'],f1=g['test']['f1'],state_mse=g['state_mse'],
            persistence_mse=report['state_persistence_mse'],validation_state_mse=g['validation_state_mse'],validation_persistence_mse=g['validation_persistence_mse'],
            paired_difference_ci=g['state_evidence']['paired_block_bootstrap_95pct']))
    summary=dict(scope='development comparison on already inspected internal holdout; not a new blind test',
        primary='residual_run, seed 42 fixed; no best-test-seed promotion',runs=rows,
        mean_f1=float(np.mean([r['f1'] for r in rows])),mean_state_mse=float(np.mean([r['state_mse'] for r in rows])),
        all_three_state_errors_below_persistence=all(r['state_mse']<r['persistence_mse'] for r in rows))
    (root/'residual_comparison.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
