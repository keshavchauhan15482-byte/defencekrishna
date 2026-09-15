"""Refresh V10 descriptive evidence after the small-sample bootstrap correction.
Never changes fitted parameters, selects models, or retrains on holdout data.
"""
import json
import hashlib
from pathlib import Path
import numpy as np
from .state_evaluation import state_evidence
from .model import GraphWorldModel


def main():
    for folder in sorted(Path('garuda_v3/artifacts/v10').iterdir()):
        p=folder/'metrics.json'
        if not p.exists():raise ValueError('Experiment incomplete')
        r=json.loads(p.read_text())
        with np.load(folder/'state_predictions.npz',allow_pickle=False) as z:
            indices=z['example_indices'];mean=z['mean'];target=z['target'];base=z['persistence']
        sources=sorted(set(indices[:,0].tolist()))
        if len(sources)!=len(r['test']):raise ValueError('Test source mapping differs')
        for source,(name,metrics) in zip(sources,r['test'].items()):
            keep=indices[:,0]==source
            if int(keep.sum())!=metrics['examples']:raise ValueError('Test count changed')
            evidence=state_evidence(mean[keep],target[keep],base[keep],r['seed'])
            metrics['evidence']=evidence
        checkpoint=folder/f"{r['architecture']}.npz"
        model,meta=GraphWorldModel.load(checkpoint)
        meta['training_objective']=r['objective']
        fitted_risk=r['objective']=='legacy_joint' and r['source']!='cicapt_only'
        meta['risk_parameters_fitted']=fitted_risk
        meta['risk_head_trained']=fitted_risk
        meta['risk_output_permitted']=False
        model.save(checkpoint,meta)
        r['checkpoint_sha256'][checkpoint.name]=hashlib.sha256(checkpoint.read_bytes()).hexdigest()
        r['evidence_revision']='V10: require >=40 examples for 20-example block bootstrap; small-sample intervals withheld'
        p.write_text(json.dumps(r,indent=2,allow_nan=False))


if __name__=='__main__':main()
