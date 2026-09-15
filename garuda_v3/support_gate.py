"""Training-support diagnostic with validation-only cutoff. Abstention is not detection."""
import numpy as np

def summary(x,mask):
    pooled=(x*mask[:,:,:,None]).sum(2)/np.maximum(mask.sum(2,keepdims=True),1)
    return np.concatenate([pooled.mean(1),mask.mean(axis=(1,2))[:,None]],axis=1)

def score(gate,x,mask):
    z=abs(summary(x,mask)-np.asarray(gate['center']))/np.asarray(gate['scale'])
    return z.max(1)

def fit(train_x,train_mask,valid_x,valid_mask):
    observed=summary(train_x,train_mask);center=np.median(observed,axis=0)
    scale=np.maximum(1.4826*np.median(abs(observed-center),axis=0),.02)
    gate=dict(center=center.tolist(),scale=scale.tolist(),method='max robust standardized history-summary deviation',
        calibration='99th percentile of validation support scores; no test fitting',target='input support, not attack probability')
    gate['threshold']=float(np.quantile(score(gate,valid_x,valid_mask),.99,method='higher'))
    return gate
