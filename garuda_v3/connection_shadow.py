"""Offline/shadow connection-start forecasts with explicit observation coverage."""
import argparse
import json
from pathlib import Path

import numpy as np

from .causal_shadow import CausalShadowService
from .connection_start import FEATURES, HISTORY, HORIZON, STEP
from .model import CONNECTION_START_SCHEMA


class ConnectionStartShadowService(CausalShadowService):
    expected_features=FEATURES
    expected_model_schema=CONNECTION_START_SCHEMA
    expected_report_schema='garuda-connection-start-result-1'
    minimum_observed_history_windows=4
    claim_boundary='Native-labelled connection-start scores from network-only first-packet fields. Missing observations remain unknown. No packet statistics, successful-compromise probability, live sensor certification or autonomous containment claim.'

    def __init__(self,bundle):
        super().__init__(bundle)
        from .causal_stage_forecast import sha
        freeze_path=self.bundle/'freeze.json'
        if sha(freeze_path)!=self.report.get('freeze_sha256'):
            raise ValueError('Pre-test policy freeze hash mismatch')
        frozen=json.loads(freeze_path.read_text())
        if frozen.get('test_records_parsed') is not False:
            raise ValueError('Policies must be frozen before final record parsing')
        policies={(r['architecture'],r['seed']):r for r in frozen['models']}
        keys=('checkpoint_sha256','risk_calibration','risk_thresholds','skip_checkpoint_sha256',
              'any_horizon_threshold','stage_thresholds','feature_order','model_schema')
        for row in self.rows:
            original=policies.get((row['architecture'],row['seed']))
            if original is None or any(original.get(k)!=row.get(k) for k in keys):
                raise ValueError('Readout differs from its pre-test policy freeze')
        self.skip_heads={}
        from .skip_heads import SkipReadout
        for row in self.rows:
            if 'skip_checkpoint' in row:
                if Path(row['skip_checkpoint']).name!=row['skip_checkpoint']:
                    raise ValueError('Bundle-local skip head required')
                self.skip_heads[row['seed']]=SkipReadout(self.bundle/row['skip_checkpoint'],row['skip_checkpoint_sha256'])

    def risk_scores(self,model,row,x,adj,mask,mean=None,raw=None):
        head=self.skip_heads.get(row['seed'])
        if head is None:return super().risk_scores(model,row,x,adj,mask,mean,raw)
        if mean is None:mean=model.forward(x,adj,mask,HORIZON)[0].data
        return head.probabilities({'x':x,'mask':mask},mean)

    def risk_sensitivity(self,model,row,x,adj,mask,h):
        head=self.skip_heads.get(row['seed'])
        if head is None:return super().risk_sensitivity(model,row,x,adj,mask,h)
        return head.sensitivity(model,x,adj,mask,h)

    def forecast(self,payload):
        result=super().forecast(payload)
        # Every seed has its own validation-only combined alert policy. The
        # ensemble does not inherit a single seed's threshold or certificate.
        x,adj,mask=[np.asarray(payload[k],np.float32)[None] for k in ('x','adj','mask')]
        decisions=[]
        for model,row in zip(self.models,self.rows):
            scores=self.risk_scores(model,row,x,adj,mask)[0]
            decisions.append({'seed':row['seed'],'alert':bool(scores.max()>=row['any_horizon_threshold']),
                'validation_threshold':row['any_horizon_threshold'],
                'independent_joint_gate_passed':row['any_horizon_test']['gate_passed']})
        observed=(mask[0].sum(1)>0)
        result.update(future_target='native-labelled connection starts',
            observed_history_windows=int(observed.sum()),missing_history_windows=int((~observed).sum()),
            observations_complete=bool(observed.all()),seed_alert_decisions=decisions,
            risk_readout_sha256s=[r.get('skip_checkpoint_sha256',r['checkpoint_sha256']) for r in self.rows],
            risk_readout_kinds_by_seed=[{'seed':r['seed'],'kinds':r.get('risk_readout_kinds',['compressed_state']*HORIZON)} for r in self.rows],
            learned_rollouts_selected_for_risk=any('rollout_skip' in r.get('risk_readout_kinds',[]) for r in self.rows),
            fresh_reserve_support=[{'seed':r['seed'],
                'positive':r['any_horizon_test'].get('positive_support'),
                'negative':r['any_horizon_test'].get('negative_support')} for r in self.rows],
            shadow_alert=all(d['alert'] for d in decisions),
            automatic_containment=False,successful_compromise_time=None,
            live_sensor_availability_certified=False)
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--observed-history',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Output must be new')
    if args.observed_history.stat().st_size>1<<20:parser.error('Observed graph exceeds 1 MiB')
    result=ConnectionStartShadowService(args.bundle).forecast(json.loads(args.observed_history.read_text()))
    args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')


if __name__=='__main__':main()
