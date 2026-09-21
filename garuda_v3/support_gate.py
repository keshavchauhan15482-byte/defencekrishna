"""Training-support diagnostic with validation-only cutoff. Abstention is not detection."""
import numpy as np


def summary(x,mask):
    pooled=(x*mask[:,:,:,None]).sum(2)/np.maximum(mask.sum(2,keepdims=True),1)
    return np.concatenate([pooled.mean(1),mask.mean(axis=(1,2))[:,None]],axis=1)


def score(gate,x,mask):
    z=abs(summary(x,mask)-np.asarray(gate['center']))/np.asarray(gate['scale'])
    return z.max(1)


def decision(gate,x,mask):
    """Return an operational support decision without calling it attack/OOD detection.

    A missing gate is deliberately unresolved: the runtime may still expose an advisory
    forecast, but there is no validation-fitted evidence authorising autonomous action.
    """
    if gate is None:
        return dict(
            status='UNVERIFIED_RUNTIME_SUPPORT',
            supported=False,
            score=None,
            threshold=None,
            autonomous_action_permitted=False,
            advisory_only=True,
            reason='No integrity-pinned validation-fitted support gate is available for this runtime bundle.',
            interpretation='Support abstention is not attack detection and does not classify traffic as benign or malicious.',
        )
    value=float(score(gate,x,mask)[0])
    threshold=float(gate['threshold'])
    supported=bool(value<=threshold)
    return dict(
        status='SUPPORTED' if supported else 'OUTSIDE_VALIDATED_SUPPORT',
        supported=supported,
        score=value,
        threshold=threshold,
        autonomous_action_permitted=supported,
        advisory_only=not supported,
        reason='Input history is within the validation-fitted support cutoff.' if supported else 'Input history exceeds the validation-fitted support cutoff; prediction is advisory only.',
        interpretation='Support abstention is not attack detection and does not classify traffic as benign or malicious.',
    )


def fit(train_x,train_mask,valid_x,valid_mask):
    observed=summary(train_x,train_mask);center=np.median(observed,axis=0)
    scale=np.maximum(1.4826*np.median(abs(observed-center),axis=0),.02)
    gate=dict(center=center.tolist(),scale=scale.tolist(),method='max robust standardized history-summary deviation',
        calibration='99th percentile of validation support scores; no test fitting',target='input support, not attack probability')
    gate['threshold']=float(np.quantile(score(gate,valid_x,valid_mask),.99,method='higher'))
    return gate
