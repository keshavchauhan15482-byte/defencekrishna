"""Numerical integrity of real readout attribution, not a synthetic benchmark."""
import json

import numpy as np
import pytest

from garuda_v3.skip_heads import SkipReadout, numpy_inputs
from garuda_v3.connection_start import FEATURES
from garuda_v3.causal_stage_forecast import sha
from garuda_v3.model import CONNECTION_START_SCHEMA, GraphWorldModel


@pytest.mark.parametrize('kind',['history_skip','rollout_skip'])
def test_skip_gradient_matches_perturbation_through_selected_readout(tmp_path,kind):
    rng=np.random.default_rng(123);x=rng.uniform(.05,.3,(1,8,2,len(FEATURES))).astype(np.float32)
    mask=np.ones((1,8,2),np.float32);adj=np.zeros((1,8,2,2),np.float32)
    model=GraphWorldModel(feature_dim=len(FEATURES),schema=CONNECTION_START_SCHEMA,decoder='residual',stage_count=5)
    for p in model.parameters():p.requires_grad=False
    mean=model.forward(x,adj,mask,4)[0].data
    dim=numpy_inputs({'x':x,'mask':mask},mean if kind=='rollout_skip' else None).shape[1]
    coef=rng.uniform(-.05,.05,dim).astype(np.float32);arrays={}
    for h in range(4):
        arrays.update({f'mean{h}':np.zeros(dim),f'scale{h}':np.ones(dim),
                       f'coef{h}':coef,f'intercept{h}':0.})
    arrays['metadata']=np.asarray(json.dumps({'feature_order':FEATURES,'shadow_only':True,
        'kinds':[kind]*4,'calibration':[{'a':1.3,'b':-.2}]*4}))
    path=tmp_path/'head.npz';np.savez(path,**arrays);head=SkipReadout(path,sha(path))
    sensitivity=head.sensitivity(model,x,adj,mask,0)
    numerical=np.zeros(len(FEATURES))
    epsilon=.003
    for time in range(8):
        for node in range(2):
            for feature in range(len(FEATURES)):
                a=x.copy();b=x.copy();a[0,time,node,feature]+=epsilon;b[0,time,node,feature]-=epsilon
                ma=model.forward(a,adj,mask,4)[0].data;mb=model.forward(b,adj,mask,4)[0].data
                sa=head.probabilities({'x':a,'mask':mask},ma)[0,0]
                sb=head.probabilities({'x':b,'mask':mask},mb)[0,0]
                numerical[feature]+=abs((sa-sb)/(2*epsilon)*x[0,time,node,feature])
    np.testing.assert_allclose(sensitivity,numerical,rtol=.025,atol=2e-5)
