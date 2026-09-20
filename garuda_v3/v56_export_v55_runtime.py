"""Fit and export the frozen V55 three-seed joint runtime with parity checks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    build_minute_state, choose_network_numeric_features, detect_label_hierarchy,
    fpr_threshold, make_sequences, parse_time, sha256, temporal_masks,
)
from .v48_strict_runner import canonical_family_name
from .v48_unseen_fusion import tail_evidence
from .v54_joint_family_generalization import _joint_reserve_split, _prepare_world_components
from .v55_runtime import V55Runtime, export_v55, fit_nonlinear_runtime


def fused(evidence, weights):
    out=np.zeros_like(next(iter(evidence.values())),dtype=float)
    for k,w in weights.items():
        if float(w): out += float(w)*evidence[k]
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv',required=True); p.add_argument('--frozen-config',required=True)
    p.add_argument('--output',required=True); p.add_argument('--epochs',type=int,default=12)
    p.add_argument('--seeds',nargs='+',type=int,default=[42,43,44]); args=p.parse_args()
    if set(args.seeds)!={42,43,44}: p.error('V55 runtime export requires exactly seeds 42,43,44')
    out=Path(args.output)
    if out.exists(): p.error('Output exists; runtime export is immutable')
    out.mkdir(parents=True)
    config=json.loads(Path(args.frozen_config).read_text())
    reserve=[canonical_family_name(x) for x in config['reserve_families']]
    df=pd.read_csv(args.csv,low_memory=False)
    dt,*_=parse_time(df); binary,family,*_=detect_label_hierarchy(df); family=family.map(canonical_family_name)
    feature_cols,_=choose_network_numeric_features(df)
    state,names,_=build_minute_state(df,dt,binary,family,feature_cols)
    seq=make_sequences(state,names); masks,_=temporal_masks(seq['cutoff'])
    split=_joint_reserve_split(seq,masks,reserve)
    manifests=[]
    rng=np.random.default_rng(5600)
    check=np.sort(rng.choice(len(seq['X']),size=min(512,len(seq['X'])),replace=False))
    for seed in args.seeds:
        print(f'V56 export seed={seed}',flush=True)
        world,base=_prepare_world_components(seq,split,seed,args.epochs)
        nonlinear,nruntime=fit_nonlinear_runtime(seq['X'],seq['y'],split,seed)
        nruntime['score']=nonlinear
        ev={
            'future_state_novelty':base['evidence']['future_state_novelty'],
            'transition_energy':base['evidence']['transition_energy'],
            'nonlinear_temporal_transfer':tail_evidence(nonlinear[base['cal_benign']],nonlinear),
        }
        score=fused(ev,config['weights'])
        threshold=fpr_threshold(score[base['policy_benign']],config['policy_budget'])
        dest=out/f'seed{seed}'
        manifest=export_v55(dest,world=world,base_components=base,nonlinear_runtime=nruntime,
                            config=config,threshold=threshold,feature_names=names,seed=seed)
        runtime=V55Runtime(dest); got=runtime.predict(seq['X'][check],names)
        np.testing.assert_allclose(got['state_scaled'],world['pred'][check],rtol=1e-5,atol=1e-6)
        np.testing.assert_allclose(got['score'],score[check],rtol=1e-10,atol=1e-10)
        np.testing.assert_array_equal(got['alert'],(score[check]>=threshold)&bool(world['state_gate_passed']))
        manifests.append(manifest)
    report={'protocol':'V56 portable V55 runtime export','source_sha256':sha256(Path(args.csv)),
            'frozen_config_sha256':sha256(Path(args.frozen_config)),'seeds':list(args.seeds),
            'feature_names':names,'parity_samples_per_seed':int(len(check)),
            'parity':'state, fused evidence score and alert exact/tolerance checks passed',
            'manifests':manifests,'automatic_containment_approved':False}
    (out/'export_report.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'parity':report['parity'],'hashes':[m['arrays_sha256'] for m in manifests]},indent=2),flush=True)

if __name__=='__main__': main()
