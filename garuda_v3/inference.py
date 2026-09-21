import hashlib
import json
from pathlib import Path
import numpy as np
from .data import SCHEMA,FEATURES
from .model import GraphWorldModel
from .autograd import Tensor
from .stage_hints import infer_stage_hint
from .support_gate import decision as support_decision
from .calibration import apply as apply_calibration

class ForecastService:
    def __init__(self,folder):
        self.folder=Path(folder)
        self.model,self.meta=GraphWorldModel.load(self.folder/'gnn_lstm.npz')
        if self.meta.get('risk_head_trained') is False or self.meta.get('risk_output_permitted') is False:
            raise ValueError('State-only checkpoint cannot supply attack probabilities or containment signals')
        self.metrics=json.loads((self.folder/'metrics.json').read_text())
        expected=self.metrics.get('checkpoint_sha256',{}).get('gnn_lstm.npz')
        actual=hashlib.sha256((self.folder/'gnn_lstm.npz').read_bytes()).hexdigest()
        if not expected or expected!=actual:raise ValueError('Checkpoint integrity mismatch')
        self.model_hash=actual
        self.support_gate=None
        if self.meta.get('support_gate'):
            if self.meta['support_gate']!='support_gate.json':raise ValueError('Invalid support gate path')
            gate_path=self.folder/'support_gate.json'
            expected_gate=self.metrics.get('checkpoint_sha256',{}).get('support_gate.json')
            if hashlib.sha256(gate_path.read_bytes()).hexdigest()!=expected_gate:raise ValueError('Support gate integrity mismatch')
            gate=json.loads(gate_path.read_text());center=np.asarray(gate['center']);scale=np.asarray(gate['scale'])
            if center.shape!=(len(FEATURES)+1,) or scale.shape!=center.shape or not np.isfinite(center).all() or not np.isfinite(scale).all() or np.any(scale<=0) or not np.isfinite(gate['threshold']) or gate['threshold']<0:raise ValueError('Invalid support gate')
            self.support_gate=gate
        for p in self.model.parameters():p.requires_grad=False
    def validate(self,payload):
        if payload.get('schema')!=SCHEMA or payload.get('mode')!=self.meta['mode'] or payload.get('window_seconds')!=self.meta['window_seconds']:
            raise ValueError('Graph schema/mode/window does not match trained checkpoint')
        x=np.asarray(payload['x'],dtype=np.float32);a=np.asarray(payload['adj'],dtype=np.float32);m=np.asarray(payload['mask'],dtype=np.float32)
        h,n,f=self.meta['history'],self.meta['max_nodes'],len(FEATURES)
        if x.shape!=(h,n,f) or a.shape!=(h,n,n) or m.shape!=(h,n):raise ValueError('Incorrect graph/history dimensions')
        if not all(np.isfinite(v).all() for v in (x,a,m)) or np.any(x<0) or np.any(x>1) or np.any(a<0) or np.any(a>1e7):raise ValueError('Invalid finite graph features/weights')
        if not np.isin(m,[0,1]).all() or np.any(m.sum(axis=1)==0):raise ValueError('Invalid active-node mask')
        if np.any(x*(1-m[:,:,None])!=0) or np.any(a*(1-m[:,:,None]*m[:,None,:])!=0):raise ValueError('Edges/features present on masked nodes')
        times=np.asarray(payload['times'],dtype=np.float64)
        if times.shape!=(h,) or not np.isfinite(times).all() or np.any(np.diff(times)!=self.meta['window_seconds']):raise ValueError('History must be ordered contiguous closed windows')
        return x[None],a[None],m[None],times
    def predict(self,payload,explain=True,allow_unsupported_advisory=False):
        x,a,m,times=self.validate(payload)
        runtime_support=support_decision(self.support_gate,x,m)
        if self.support_gate is not None and not runtime_support['supported'] and not allow_unsupported_advisory:
            raise ValueError('Traffic is outside the model training support; prediction withheld. This is unknown, not benign or blocked.')
        if x[:,:,:,FEATURES.index('packet_features_present')].max()>0 and not self.meta['packet_features_trained']:
            raise ValueError('Packet-derived graphs parsed, but this checkpoint was trained on CSV flows; retrain on packet telemetry before inference')
        advisory_abstention=bool(allow_unsupported_advisory and not runtime_support['supported'])
        mu,sd,r,stage=self.model.forward(x,a,m,self.meta['horizon'],return_stages=True)
        stage_timeline=[];predicted_stages=[]
        stage_status='Not identifiable from Bot/Benign supervision; no probability-to-stage shortcut'
        if stage is not None and self.meta.get('stage_supervised') and not advisory_abstention:
            names=self.meta.get('stage_names',[]);thresholds=self.meta.get('stage_thresholds',[])
            supported=self.meta.get('stage_validation_supported',[])
            if len(names)!=self.model.stage_count or len(thresholds)!=len(names) or len(supported)!=len(names):
                raise ValueError('Missing supervised stage validation metadata')
            for k,probs in enumerate(stage.data[0]):
                stage_timeline.append(dict(horizon_seconds=(k+1)*self.meta['window_seconds'],
                    stages=[dict(stage=name,probability=float(probs[j]),threshold=thresholds[j]) for j,name in enumerate(names) if supported[j]]))
            predicted_stages=[name for j,name in enumerate(names) if supported[j] and bool((stage.data[0,:,j]>=thresholds[j]).any())]
            stage_status='Supervised multi-label MITRE tactic forecasts; only tactics with train/validation class support shown. Tactics are not a mandatory sequence; inspect held-out stage metrics.'
        elif advisory_abstention:
            stage_status='Unresolved: runtime input support is not validated for autonomous or stage-specific interpretation.'
        probabilities=apply_calibration(r.data[0],self.meta.get('risk_calibration',{'status':'disabled'}))
        attribution=[];node_importance=[]
        if explain:
            # Gradient x input against zero baseline, explicitly not called SHAP.
            observed=Tensor(x,requires_grad=True)
            _,_,risk=self.model.forward(observed,a,m,self.meta['horizon'])
            k=int(np.argmax(probabilities));risk[0,k].backward()
            contribution=observed.grad*x
            feature_magnitude=np.abs(contribution).sum(axis=(0,1,2));total=max(float(feature_magnitude.sum()),1e-12)
            signed=contribution.sum(axis=(0,1,2))
            attribution=sorted([dict(feature=name,magnitude_fraction=float(feature_magnitude[i]/total),signed_gradient_x_input=float(signed[i])) for i,name in enumerate(FEATURES)],key=lambda z:z['magnitude_fraction'],reverse=True)
            node_score=np.abs(contribution).sum(axis=(0,1,3)); names=payload.get('node_names',[])
            node_importance=sorted([dict(node=names[i] if i<len(names) else f'node:{i}',importance=float(node_score[i])) for i in range(len(node_score)) if m[0,-1,i]],key=lambda z:z['importance'],reverse=True)[:6]
        low=np.clip(mu.data[0]-1.96*sd.data[0],0,1);high=np.clip(mu.data[0]+1.96*sd.data[0],0,1)
        alert=bool(probabilities.max()>=self.meta.get('alert_threshold',self.meta['threshold']))
        if advisory_abstention:
            stage_hint=dict(method='runtime_support_abstention',ml_trained=False,validated=False,title='Unresolved',tactic=None,technique=None,
                confidence=None,rule='Stage hint withheld because runtime support is unresolved or outside the validation-fitted cutoff.',evidence=[],
                caveat='Advisory risk/state outputs may still be displayed; no stage or autonomous-response claim is authorised.')
        else:
            stage_hint=infer_stage_hint(payload,alert)
        return dict(model='directed_graphsage_lstm_autoregressive',model_sha256=self.model_hash,
            data_source=payload.get('data_source','submitted_observed_graphs'),graph_mode=self.meta['mode'],
            target=self.meta['target'],validation_scope=self.meta['validation_scope'],
            cutoff_epoch_seconds=float(times[-1]+self.meta['window_seconds']),
            trajectory=[dict(horizon_seconds=(i+1)*self.meta['window_seconds'],malicious_flow_probability=float(p),
                state_mean=mu.data[0,i].tolist(),state_interval_low=low[i].tolist(),state_interval_high=high[i].tolist()) for i,p in enumerate(probabilities)],
            threshold=self.meta.get('alert_threshold',self.meta['threshold']),alert=alert,
            alert_policy_status=self.meta.get('alert_policy_status','legacy last-horizon threshold'),
            predicted_attack_stage=', '.join(predicted_stages) if predicted_stages else None,stage_status=stage_status,
            stage_hint=stage_hint,stage_trajectory=stage_timeline,runtime_support=runtime_support,
            operating_mode='SHADOW_UNRESOLVED' if advisory_abstention else 'SUPPORTED_RUNTIME',
            explanation=dict(method='gradient_x_input',baseline='zero normalized features',feature_attributions=attribution,node_importance=node_importance,
                limitation='local sensitivity of this prediction; not causal proof or exact Shapley values'),
            uncertainty='diagonal Gaussian state intervals; empirical coverage is in benchmark, not a guarantee',
            measured_compromise_lead_time_seconds=None,automatic_containment=False)
