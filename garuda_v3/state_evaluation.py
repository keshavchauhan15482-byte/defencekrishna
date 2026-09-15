"""Paired state errors, including changed entries and block uncertainty."""
import numpy as np
from .data import FEATURES

def state_evidence(mean,target,persistence,seed=42):
    mean=np.asarray(mean);target=np.asarray(target)
    persistence=np.broadcast_to(persistence,target.shape)
    error=(mean-target)**2;base=(persistence-target)**2
    changed=abs(target-persistence)>1e-5
    paired=(error-base).mean(axis=(1,2))
    if not len(paired):raise ValueError('No state examples to evaluate')
    rng=np.random.default_rng(seed);block=20;samples=[]
    # A full-length block on a tiny sample produces a false zero-width interval.
    # Require at least two blocks; even then this is descriptive, not IID evidence.
    sufficient=len(paired)>=2*block
    for _ in range(200 if sufficient else 0):
        starts=rng.integers(0,len(paired)-block+1,size=int(np.ceil(len(paired)/block)))
        ids=np.concatenate([np.arange(s,s+block) for s in starts])[:len(paired)]
        samples.append(float(paired[ids].mean()))
    return dict(per_feature={name:dict(model_mse=float(error[:,:,i].mean()),persistence_mse=float(base[:,:,i].mean())) for i,name in enumerate(FEATURES)},
        per_horizon=[dict(model_mse=float(error[:,i].mean()),persistence_mse=float(base[:,i].mean())) for i in range(target.shape[1])],
        changed_entries=int(changed.sum()),changed_entry_model_mse=float(error[changed].mean()) if changed.any() else None,
        changed_entry_persistence_mse=float(base[changed].mean()) if changed.any() else None,
        paired_mse_difference=float(paired.mean()),paired_block_bootstrap_95pct=np.quantile(samples,[.025,.975]).tolist() if sufficient else [None,None],
        bootstrap_status='descriptive_correlated_blocks' if sufficient else 'insufficient_examples_for_two_blocks',
        bootstrap_block_examples=block,interpretation='Negative difference favors model. Correlated internal samples; not independent campaign evidence.')
