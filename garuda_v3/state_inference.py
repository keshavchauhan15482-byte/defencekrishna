"""Offline V10 traffic-state forecasts; never emits untrained attack scores.

python -m garuda_v3.state_inference --model DIR --graph DATA.npz --output result.json
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from .data import load_dataset, FEATURES, SCHEMA
from .model import GraphWorldModel
from .inference import ForecastService
from .autograd import Tensor


class StateForecastService:
    validate=ForecastService.validate

    def __init__(self,folder,architecture='gnn_lstm'):
        if architecture not in ('lstm','gnn_lstm'):raise ValueError('Unknown architecture')
        folder=Path(folder);path=folder/f'{architecture}.npz'
        report=json.loads((folder/'metrics.json').read_text())
        self.model_hash=hashlib.sha256(path.read_bytes()).hexdigest()
        if report['checkpoint_sha256'].get(path.name)!=self.model_hash:
            raise ValueError('Checkpoint integrity mismatch')
        self.model,self.meta=GraphWorldModel.load(path)
        if not self.meta.get('state_head_trained') or not self.meta.get('state_only_experiment'):
            raise ValueError('Expected explicitly evaluated V10 state checkpoint')
        # Load only the validation-derived radius, never held-out state targets.
        calibration=folder/'state_predictions.npz'
        if hashlib.sha256(calibration.read_bytes()).hexdigest()!=report['checkpoint_sha256'].get(calibration.name):
            raise ValueError('Validation error-band integrity mismatch')
        with np.load(calibration,allow_pickle=False) as z:self.radius=z['validation_error_radius']
        if self.radius.shape!=(self.meta['horizon'],len(FEATURES)) or not np.isfinite(self.radius).all() or (self.radius<0).any():
            raise ValueError('Invalid error-band radius')
        for p in self.model.parameters():p.requires_grad=False

    def predict(self,payload,explain_feature='bytes_log'):
        x,a,m,times=self.validate(payload)
        mean,_,_=self.model.forward(x,a,m,self.meta['horizon'])
        explanations=[]
        if explain_feature is not None:
            if explain_feature not in FEATURES:raise ValueError('Unknown output feature')
            observed=Tensor(x,requires_grad=True)
            trajectory,_,_=self.model.forward(observed,a,m,self.meta['horizon'])
            trajectory[0,-1,FEATURES.index(explain_feature)].backward()
            contribution=abs(observed.grad*x).sum(axis=(0,1,2));total=max(float(contribution.sum()),1e-12)
            explanations=sorted([dict(feature=f,relative_sensitivity=float(contribution[i]/total))
                for i,f in enumerate(FEATURES)],key=lambda v:v['relative_sensitivity'],reverse=True)[:5]
        return dict(model_sha256=self.model_hash,scope='traffic-state forecast only',
            evidence_scope=self.meta['validation_scope'],
            training_campaigns=self.meta['training_campaigns'],
            cutoff_epoch_seconds=float(times[-1]+self.meta['window_seconds']),
            features=FEATURES,
            trajectory=[dict(horizon_seconds=(i+1)*self.meta['window_seconds'],mean=mean.data[0,i].tolist(),
                empirical_band_low=np.maximum(0,mean.data[0,i]-self.radius[i]).tolist(),
                empirical_band_high=np.minimum(1,mean.data[0,i]+self.radius[i]).tolist()) for i in range(self.meta['horizon'])],
            uncertainty='Validation absolute-error 95th percentiles; descriptive marginal bands, no coverage guarantee',
            explanation=dict(method='absolute gradient times input',predicted_feature=explain_feature,
                horizon_seconds=self.meta['horizon']*self.meta['window_seconds'],top_inputs=explanations,
                limitation='Local model sensitivity, not causal proof or attack attribution'),
            infiltration_probability=None,attack_stage=None,automatic_containment=False,
            decision='No attack/containment decision from a state-only checkpoint')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--model',required=True)
    p.add_argument('--architecture',choices=['lstm','gnn_lstm'],default='gnn_lstm')
    p.add_argument('--graph',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();service=StateForecastService(a.model,a.architecture);d=load_dataset(a.graph)
    h=service.meta['history']
    if len(d['times'])<h:raise ValueError('Insufficient observed history')
    payload=dict(schema=SCHEMA,mode=d['metadata']['mode'],window_seconds=d['metadata']['window_seconds'],
        x=d['x'][-h:],adj=d['adj'][-h:],mask=d['mask'][-h:],times=d['times'][-h:])
    Path(a.output).write_text(json.dumps(service.predict(payload),indent=2,allow_nan=False))


if __name__=='__main__':main()
