"""Development-only monotone Platt calibration and explicit non-actionable policies."""
import numpy as np

def interval(success,total,alpha=.05):
    from scipy.stats import beta
    if total==0:return [None,None]
    return [float(beta.ppf(alpha/2,success,total-success+1)) if success else 0.,float(beta.ppf(1-alpha/2,success+1,total-success)) if success<total else 1.]

def apply(p,cal):
    p=np.asarray(p,dtype=float)
    if not np.isfinite(p).all() or np.any((p<0)|(p>1)):raise ValueError('Invalid probabilities')
    if cal['status']!='fitted':return p
    logits=np.log(np.clip(p,1e-6,1-1e-6)/np.clip(1-p,1e-6,1))
    z=np.clip(cal['slope']*logits+cal['intercept'],-35,35)
    return 1/(1+np.exp(-z))

def fit(y,p):
    y=np.asarray(y).ravel();p=np.asarray(p,dtype=float).ravel()
    if y.shape!=p.shape or not np.isin(y,[0,1]).all():raise ValueError('Binary calibration pairs required')
    apply(p,{'status':'identity'})
    counts=[int((y==v).sum()) for v in (0,1)]
    result=dict(status='insufficient_development_support',counts=counts,slope=1.,intercept=0.,scope='validation only; no test labels used')
    if min(counts)<20:return result
    from scipy.optimize import minimize
    x=np.log(np.clip(p,1e-6,1-1e-6)/np.clip(1-p,1e-6,1))
    def objective(ab):
        z=ab[0]*x+ab[1];return np.mean(np.logaddexp(0,z)-y*z)+1e-4*((ab[0]-1)**2+ab[1]**2)
    opt=minimize(objective,[1.,0.],method='L-BFGS-B',bounds=[(0.,20.),(-20.,20.)])
    if opt.success:result.update(status='fitted',slope=float(opt.x[0]),intercept=float(opt.x[1]))
    return result

def select_policy(y,p,budget=.01):
    y=np.asarray(y,dtype=int);p=np.asarray(p,dtype=float)
    if not 0<budget<1 or y.shape!=p.shape or y.ndim!=1 or not np.isin(y,[0,1]).all():raise ValueError('Invalid policy inputs')
    apply(p,{'status':'identity'})
    if len(np.unique(y))<2:return dict(threshold=None,status='insufficient_validation_classes',fpr_budget=budget)
    options=[]
    for t in np.unique(np.r_[p,np.nextafter(p,np.inf)]):
        pred=p>=t;fp=int((pred&(y==0)).sum());tp=int((pred&(y==1)).sum());n=int((y==0).sum());pos=int(y.sum())
        if fp/n<=budget:options.append((tp/pos,-fp/n,float(t),fp,tp,n,pos))
    best=max(options);recall,negfpr,t,fp,tp,n,pos=best
    actionable=recall>0 and t<=1
    return dict(threshold=t if actionable else None,status='validation_selected' if actionable else 'no_useful_validation_policy',fpr_budget=budget,validation_recall=recall,validation_fpr=-negfpr,fpr_95pct=interval(fp,n),recall_95pct=interval(tp,pos),confidence_gate_passed=interval(fp,n)[1]<=budget and interval(tp,pos)[0]>=.8,independence_caveat='Binomial intervals are descriptive; overlapping windows are correlated.')

def future_target(labels):
    labels=np.asarray(labels)
    return np.where((labels==1).any(axis=1),1,np.where((labels==0).all(axis=1),0,-1))

def family_report(datasets,indices,labels,probabilities,threshold):
    out={}
    for family in sorted({d['metadata'].get('attack_family','unspecified') for d in datasets}):
        ids=[j for j,(s,_) in enumerate(indices) if datasets[s]['metadata'].get('attack_family','unspecified')==family]
        if not ids:continue
        target=future_target(labels[ids]);known=target>=0;y=target[known].astype(bool);p=np.max(probabilities[ids],axis=1)[known];pred=np.zeros(len(y),bool) if threshold is None else p>=threshold
        n=int((~y).sum());pos=int(y.sum());fp=int((pred&~y).sum());tp=int((pred&y).sum())
        out[family]=dict(examples=len(y),unknown_target_examples=int((~known).sum()),positives=pos,negatives=n,false_positives=fp,true_positives=tp,fpr=fp/n if n else None,recall=tp/pos if pos else None,fpr_95pct=interval(fp,n),recall_95pct=interval(tp,pos),policy_enabled=threshold is not None,passed=bool(n and pos and threshold is not None and interval(fp,n)[1]<=.01 and interval(tp,pos)[0]>=.8))
    return out
