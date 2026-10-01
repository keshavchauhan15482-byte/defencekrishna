"""Offline three-seed future-state/risk/tactic inference for the causal flow study.

Input has observed network graphs only. This research readout cannot publish a
firewall policy or replace the certified packet-state bundle.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .autograd import Tensor
from .causal_stage_forecast import FEATURES, STAGES, HISTORY, HORIZON, STEP, calibrate, sha
from .data import SERVICE_NODES
from .model import CAUSAL_FLOW_SCHEMA, GraphWorldModel


class CausalShadowService:
    def __init__(self, bundle):
        self.bundle = Path(bundle)
        self.report = json.loads((self.bundle/'report.json').read_text())
        if self.report.get('schema') != 'garuda-causal-native-result-1' or 'models' not in self.report:
            raise ValueError('Scored frozen experiment required')
        if self.report['feature_order'] != FEATURES or self.report['graph_nodes'] != SERVICE_NODES:
            raise ValueError('Flow feature/node identity mismatch')
        if self.report.get('automatic_promotion') is not False or self.report.get('automatic_containment') is not False:
            raise ValueError('Only an explicitly shadow-only bundle is supported')
        self.rows = [r for r in self.report['models'] if r['architecture']=='gnn_lstm']
        if sorted(r['seed'] for r in self.rows) != [42,43,44]:raise ValueError('Complete fixed seed ensemble required')
        self.models=[]
        for r in self.rows:
            name=r['checkpoint']
            if Path(name).name!=name:raise ValueError('Checkpoint path must be a bundle-local basename')
            path=self.bundle/name
            if sha(path)!=r['checkpoint_sha256']:raise ValueError('Checkpoint hash mismatch')
            model,meta=GraphWorldModel.load(path)
            if model.schema!=CAUSAL_FLOW_SCHEMA or meta.get('features')!=FEATURES or meta.get('shadow_only') is not True or meta.get('risk_head_trained') is not True:
                raise ValueError('Causal observed-flow checkpoint required')
            for p in model.parameters():p.requires_grad=False
            self.models.append(model)

    def forecast(self,payload):
        allowed={'schema','features','mode','window_seconds','times','x','adj','mask'}
        if set(payload)!=allowed:raise ValueError('Observed graphs only; labels/future targets/extra fields are forbidden')
        if payload['schema']!=CAUSAL_FLOW_SCHEMA or payload['features']!=FEATURES or payload['mode']!='service' or payload['window_seconds']!=STEP:
            raise ValueError('Causal flow/service/10-second contract mismatch')
        times=np.asarray(payload['times'])
        if times.shape!=(HISTORY,) or not np.issubdtype(times.dtype,np.number) or not np.isfinite(times).all():
            raise ValueError('Eight finite UTC bucket timestamps required')
        if np.any(times!=times.astype(np.int64)) or np.any(times%STEP) or not np.all(np.diff(times)==STEP):
            raise ValueError('Contiguous UTC 10-second buckets required')
        x,adj,mask=[np.asarray(payload[k],np.float32) for k in ('x','adj','mask')]
        n=len(SERVICE_NODES)
        if x.shape!=(HISTORY,n,len(FEATURES)) or adj.shape!=(HISTORY,n,n) or mask.shape!=(HISTORY,n):
            raise ValueError('Observed graph shape mismatch')
        if not all(np.isfinite(a).all() for a in (x,adj,mask)) or np.any((x<0)|(x>1)) or np.any(adj<0) or np.any(adj>1e7) or not np.isin(mask,[0,1]).all():
            raise ValueError('Invalid bounded observed features/adjacency/mask')
        if np.any(mask.sum(1)==0) or np.any(x[mask==0]!=0):raise ValueError('Every historical window needs valid observed nodes')
        means,sigmas,risks,stages=[],[],[],[]
        sensitivities=[]
        for model,row in zip(self.models,self.rows):
            mean,sigma,risk,stage=model.forward(x[None],adj[None],mask[None],HORIZON,return_stages=True)
            means.append(mean.data[0]);sigmas.append(sigma.data[0]);stages.append(stage.data[0])
            score=np.asarray([calibrate(risk.data[0,h],row['risk_calibration'][h]) for h in range(HORIZON)])
            risks.append(score)
            h=int(score.argmax());observed=Tensor(x[None],requires_grad=True)
            _,_,raw,_=model.forward(observed,adj[None],mask[None],HORIZON,return_stages=True)
            raw[0,h].backward()
            sensitivities.append(np.abs(observed.grad*observed.data).sum((0,1,2)))
        mean=np.mean(means,axis=0)
        total_sigma=np.sqrt(np.mean(np.asarray(sigmas)**2,axis=0)+np.var(means,axis=0))
        scores=np.mean(risks,axis=0);deviation=np.std(risks,axis=0,ddof=1)
        weights=np.mean(sensitivities,axis=0);order=np.argsort(-weights)[:5]
        top=[{'feature':FEATURES[i],'sensitivity_share':float(weights[i]/max(1e-12,weights.sum()))} for i in order]
        trajectory=[]
        for h in range(HORIZON):
            predictions=[]
            for i,s in enumerate(STAGES):
                supported=all(r['test_stage_multilabel'][s]['supported_in_development'] and
                    r['test_stage_multilabel'][s]['positive_support']>=30 and
                    r['test_stage_multilabel'][s]['recall']>=.8 and
                    r['test_stage_multilabel'][s]['precision']>=.8 for r in self.rows)
                if supported and all(stages[j][h,i]>=r['stage_thresholds'][i] for j,r in enumerate(self.rows)):predictions.append(s)
            trajectory.append({'horizon_seconds':(h+1)*STEP,'future_attack_score':float(scores[h]),
                'seed_score_sd':float(deviation[h]),'predicted_tactics':predictions or ['insufficient evidence'],
                'state_mean':mean[h].tolist(),'state_mixture_sigma':total_sigma[h].tolist()})
        return {'status':'EXPERIMENTAL_SHADOW_ONLY','retrospective_forecast_origin_utc_epoch':int(times[-1])+STEP,
            'computed_at_utc':datetime.now(timezone.utc).isoformat(),'live_warning_claim':False,
            'observed_history_seconds':80,'trajectory':trajectory,'driving_features':top,
            'attribution_method':'absolute gradient times input sensitivity; not a causal explanation',
            'model_sha256s':[r['checkpoint_sha256'] for r in self.rows],
            'input_sha256':hashlib.sha256(json.dumps(payload,sort_keys=True,allow_nan=False).encode()).hexdigest(),
            'independent_risk_gates_passed':all(r['risk_gate_passed'] for r in self.rows),
            'domain_support_certified':False,'precompromise_certified':False,
            'record_availability_certified':False,
            'automatic_containment':False,'defender_decision':'shadow review only',
            'claim_boundary':'Future completed-flow scores. No packet features, verified compromise probability or live enforcement claim.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--observed-history',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    if args.output.exists():ap.error('Output must be new')
    if args.observed_history.stat().st_size>1<<20:ap.error('Observed graph input exceeds 1 MiB')
    result=CausalShadowService(args.bundle).forecast(json.loads(args.observed_history.read_text()))
    args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')


if __name__=='__main__':main()
