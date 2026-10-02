"""Frozen state world model with an observed-history risk skip connection.

The skip protects rare risk information from state-compression loss. Validation
chooses whether learned rollouts add value over the equal-history readout. A
history-only choice is reported honestly; it is not evidence of rollout value.
"""
import json
from pathlib import Path

import numpy as np

from .autograd import Tensor, concat
from .connection_start import FEATURES, HISTORY, HORIZON
from .causal_stage_forecast import predict, calibrate, fit_calibration, threshold, binary_metrics, brier, sha


def numpy_inputs(d,mean=None):
    pooled=(d['x']*d['mask'][...,None]).sum(2)/np.maximum(d['mask'].sum(2,keepdims=True),1)
    history=pooled.reshape(len(pooled),-1)
    if mean is None:return history
    return np.concatenate((history,mean.reshape(len(mean),-1),
                           (mean-pooled[:,-1,None]).reshape(len(mean),-1)),axis=1)


class SkipReadout:
    def __init__(self,path,expected_sha):
        if sha(path)!=expected_sha:raise ValueError('Skip risk head hash mismatch')
        with np.load(path,allow_pickle=False) as z:
            self.meta=json.loads(str(z['metadata']))
            if self.meta['feature_order']!=FEATURES or self.meta['shadow_only'] is not True:
                raise ValueError('First-packet shadow readout contract mismatch')
            self.arrays={k:z[k].copy() for k in z.files if k!='metadata'}

    def probabilities(self,d,mean=None):
        inputs={'history_skip':numpy_inputs(d)}
        if 'rollout_skip' in self.meta['kinds']:
            if mean is None:raise ValueError('Selected risk head requires learned rollout')
            inputs['rollout_skip']=numpy_inputs(d,mean)
        values=[]
        for h,kind in enumerate(self.meta['kinds']):
            a=self.arrays;z=(inputs[kind]-a[f'mean{h}'])/a[f'scale{h}']
            raw=np.exp(-np.logaddexp(0,-(z@a[f'coef{h}']+a[f'intercept{h}'])))
            values.append(calibrate(raw,self.meta['calibration'][h]))
        return np.stack(values,1)

    def sensitivity(self,model,x,adj,mask,horizon):
        observed=Tensor(x,requires_grad=True)
        pooled=(observed*mask[...,None]).sum(2)/np.maximum(mask.sum(2,keepdims=True),1)
        history=pooled.reshape(len(x),-1)
        kind=self.meta['kinds'][horizon]
        if kind=='rollout_skip':
            mean,_,_=model.forward(observed,adj,mask,HORIZON)
            inputs=concat((history,mean.reshape(len(x),-1),
                (mean-pooled[:,-1,None,:]).reshape(len(x),-1)),axis=1)
        else:inputs=history
        a=self.arrays;h=horizon
        logit=(((inputs-a[f'mean{h}'])/a[f'scale{h}'])@a[f'coef{h}'][:,None])[:,0]+a[f'intercept{h}']
        cfg=self.meta['calibration'][h]
        score=(cfg['a']*logit+cfg['b']).sigmoid()
        score[0].backward()
        return np.abs(observed.grad*observed.data).sum((0,1,2))


def fit(model,train,val,path):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    tm=predict(model,train)[0];vm=predict(model,val)[0]
    inputs={'history_skip':(numpy_inputs(train),numpy_inputs(val)),
            'rollout_skip':(numpy_inputs(train,tm),numpy_inputs(val,vm))}
    candidates={};arrays={};chosen=[];calibration=[];policies=[];audit=[]
    for kind,(tr,va) in inputs.items():
        scaler=StandardScaler().fit(tr);tr=scaler.transform(tr);va=scaler.transform(va)
        rows=[]
        for h in range(HORIZON):
            keep=train['y'][:,h]>=0
            m=LogisticRegression(C=1,max_iter=1000,random_state=42).fit(tr[keep],train['y'][keep,h])
            raw=m.predict_proba(va)[:,1];cfg=fit_calibration(val['y'][:,h],raw)
            score=calibrate(raw,cfg);t,status=threshold(val['y'][:,h],score)
            rows.append({'mean':scaler.mean_,'scale':scaler.scale_,'coef':m.coef_[0],
                'intercept':m.intercept_[0],'calibration':cfg,'threshold':t,'threshold_status':status,
                'validation':binary_metrics(val['y'][:,h],score,t),'brier':brier(val['y'][:,h],score)})
        candidates[kind]=rows
    for h in range(HORIZON):
        base,aug=[candidates[k][h] for k in ('history_skip','rollout_skip')]
        kind=('rollout_skip' if aug['brier']<base['brier'] and
            aug['validation']['f1'] is not None and base['validation']['f1'] is not None and
            aug['validation']['f1']>=base['validation']['f1'] else 'history_skip')
        row=candidates[kind][h];chosen.append(kind);calibration.append(row['calibration'])
        policies.append({'threshold':row['threshold'],'status':row['threshold_status']})
        for name in ('mean','scale','coef','intercept'):arrays[f'{name}{h}']=row[name]
        audit.append({k:{'brier':candidates[k][h]['brier'],'metrics':candidates[k][h]['validation']} for k in candidates})
    arrays['metadata']=np.asarray(json.dumps({'feature_order':FEATURES,'shadow_only':True,
        'kinds':chosen,'calibration':calibration,'policies':policies,'selection_fit':'validation_only',
        'normalization_fit':'train_only','readout_regularization_C':1}))
    np.savez(path,**arrays)
    return {'skip_checkpoint':Path(path).name,'skip_checkpoint_sha256':sha(path),
            'risk_readout_type':'observed_history_skip_with_validation_selected_rollouts',
            'risk_readout_kinds':chosen,'skip_validation_candidates':audit,'skip_policies':policies}
