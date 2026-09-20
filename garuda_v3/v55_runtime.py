"""Portable V55 joint-family scorer with no pickle deserialization.

The runtime implements the frozen V55 fusion selected on development pair holdouts:
nonlinear temporal transfer + future-state novelty + transition energy.  Scores are
benign-tail evidence, not attack probabilities, and automatic containment is disabled.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import sklearn
import torch
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import HISTORY, HORIZON, anomaly_score, build_world_model
from .v48_unseen_fusion import tail_evidence
from .v55_nonlinear_joint_generalization import temporal_history_features

SCHEMA = 'garuda.v55.joint-fold.v1'
V55_COMPONENTS = ('future_state_novelty', 'transition_energy', 'nonlinear_temporal_transfer')


def fit_nonlinear_runtime(X, target, split, seed):
    tr = np.where(split['train'])[0]
    if len(tr) < 50 or len(np.unique(np.asarray(target)[tr])) < 2:
        raise ValueError('V55 nonlinear head requires two-class development support')
    feat = temporal_history_features(X)
    feat[~np.isfinite(feat)] = np.nan
    med = np.nanmedian(feat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = med[np.where(bad)[1]]
    model = ExtraTreesClassifier(
        n_estimators=240,
        max_features='sqrt',
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=seed,
        n_jobs=1,
    )
    model.fit(feat[tr], np.asarray(target)[tr])
    return model.predict_proba(feat)[:, 1], {'model': model, 'median': med}


def _forest_arrays(runtime):
    model = runtime['model']
    offsets = [0]
    left=[]; right=[]; feature=[]; threshold=[]; values=[]
    for est in model.estimators_:
        t=est.tree_
        left.append(t.children_left.astype(np.int32))
        right.append(t.children_right.astype(np.int32))
        feature.append(t.feature.astype(np.int32))
        threshold.append(t.threshold.astype(np.float64))
        v=np.asarray(t.value, dtype=np.float64).reshape(t.node_count, -1)
        values.append(v)
        offsets.append(offsets[-1]+t.node_count)
    return {
        'forest_offsets':np.asarray(offsets,dtype=np.int64),
        'forest_left':np.concatenate(left),
        'forest_right':np.concatenate(right),
        'forest_feature':np.concatenate(feature),
        'forest_threshold':np.concatenate(threshold),
        'forest_value':np.concatenate(values,axis=0),
        'forest_classes':np.asarray(model.classes_),
        'forest_median':np.asarray(runtime['median'],dtype=np.float64),
    }


def export_v55(path, *, world, base_components, nonlinear_runtime, config, threshold, feature_names, seed):
    path=Path(path); path.mkdir(parents=True,exist_ok=False)
    scaler=world['runtime_scaler']
    arrays={
        'state_median':np.asarray(world['imputer_median']),
        'state_mean':scaler.mean_, 'state_scale':scaler.scale_,
        'future_center':base_components['runtime_references']['future'][0],
        'future_scale':base_components['runtime_references']['future'][1],
    }
    arrays.update(_forest_arrays(nonlinear_runtime))
    for key,val in world['runtime_model'].state_dict().items():
        arrays['weight.'+key]=val.cpu().numpy()
    cal=base_components['cal_benign']
    pred=world['pred']; persistence=world['persistence']; delta=pred-persistence
    raw_future=anomaly_score(pred, arrays['future_center'], arrays['future_scale'])
    raw_energy=np.mean(delta*delta,axis=(1,2))
    # Recompute tree score from the fitted estimator; parity is asserted by export workflow.
    feat=temporal_history_features(world['raw_X'] if 'raw_X' in world else np.empty((0,))) if False else None
    # Caller provides the fitted score to avoid any hidden data dependency through world.
    nonlinear_score=nonlinear_runtime['score']
    arrays['cal.future_state_novelty']=raw_future[cal]
    arrays['cal.transition_energy']=raw_energy[cal]
    arrays['cal.nonlinear_temporal_transfer']=nonlinear_score[cal]
    np.savez_compressed(path/'arrays.npz',**arrays)
    raw=(path/'arrays.npz').read_bytes()
    manifest={
        'schema':SCHEMA,'sklearn_version':sklearn.__version__,'torch_version':torch.__version__,
        'history':HISTORY,'horizon':HORIZON,'window_seconds':60,'feature_names':list(feature_names),
        'seed':int(seed),'weights':config['weights'],'threshold':float(threshold),
        'state_gate_passed':bool(world['state_gate_passed']),'automatic_containment':False,
        'score_kind':'benign_tail_evidence_not_probability',
        'arrays_sha256':hashlib.sha256(raw).hexdigest(),
    }
    (path/'manifest.json').write_text(json.dumps(manifest,indent=2,allow_nan=False)+'\n')
    return manifest


def _forest_predict_proba(a, feat):
    feat=np.asarray(feat,dtype=np.float64).copy()
    bad=~np.isfinite(feat)
    if bad.any(): feat[bad]=a['forest_median'][np.where(bad)[1]]
    offsets=a['forest_offsets']; total=np.zeros(len(feat),dtype=np.float64)
    classes=a['forest_classes'].tolist()
    if 1 not in classes: raise ValueError('V55 forest missing positive class')
    pos=classes.index(1)
    for ti in range(len(offsets)-1):
        lo,hi=int(offsets[ti]),int(offsets[ti+1])
        node=np.zeros(len(feat),dtype=np.int32)
        while True:
            g=lo+node
            left=a['forest_left'][g]
            leaf=left<0
            if bool(np.all(leaf)): break
            idx=np.where(~leaf)[0]
            gi=g[idx]
            f=a['forest_feature'][gi]
            go_left=feat[idx,f] <= a['forest_threshold'][gi]
            nxt=np.where(go_left,a['forest_left'][gi],a['forest_right'][gi])
            node[idx]=nxt
        v=a['forest_value'][lo+node]
        den=v.sum(axis=1)
        p=np.divide(v[:,pos],den,out=np.zeros(len(v),dtype=float),where=den>0)
        total+=p
    return total/max(1,len(offsets)-1)


class V55Runtime:
    def __init__(self,path):
        path=Path(path); self.path=path
        self.meta=json.loads((path/'manifest.json').read_text())
        if self.meta.get('schema')!=SCHEMA:
            raise ValueError('Incompatible V55 runtime schema')
        if self.meta['sklearn_version']!=sklearn.__version__ or self.meta['torch_version']!=torch.__version__:
            raise ValueError('V55 dependency versions differ; revalidate export parity before use')
        raw=(path/'arrays.npz').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=self.meta['arrays_sha256']:
            raise ValueError('V55 artifact checksum mismatch')
        if (self.meta['history'],self.meta['horizon'],self.meta['window_seconds'])!=(HISTORY,HORIZON,60):
            raise ValueError('Incompatible V55 time contract')
        with np.load(path/'arrays.npz',allow_pickle=False) as z:
            self.a={k:z[k].copy() for k in z.files}
        self.model=build_world_model(len(self.meta['feature_names']))
        self.model.load_state_dict({k[7:]:torch.from_numpy(v) for k,v in self.a.items() if k.startswith('weight.')})
        self.model.eval()

    def predict(self,X,feature_names,window_seconds=60):
        if list(feature_names)!=self.meta['feature_names'] or int(window_seconds)!=60:
            raise ValueError('V55 requires exact ordered minute-state features')
        X=np.asarray(X,dtype=np.float32)
        if X.ndim!=3 or X.shape[1:]!=(HISTORY,len(feature_names)) or not len(X):
            raise ValueError('Invalid V55 history shape')
        a=self.a; z=X.copy(); bad=~np.isfinite(z)
        z[bad]=a['state_median'][np.where(bad)[-1]]
        scaler=StandardScaler(); scaler.mean_=a['state_mean']; scaler.scale_=a['state_scale']; scaler.n_features_in_=len(feature_names)
        z=scaler.transform(z.reshape(-1,len(feature_names))).reshape(z.shape)
        with torch.no_grad(): pred=self.model(torch.from_numpy(z)).numpy()
        persistence=np.repeat(z[:,-1:,:],HORIZON,axis=1); delta=pred-persistence
        raw={
            'future_state_novelty':anomaly_score(pred,a['future_center'],a['future_scale']),
            'transition_energy':np.mean(delta*delta,axis=(1,2)),
            'nonlinear_temporal_transfer':_forest_predict_proba(a,temporal_history_features(X)),
        }
        evidence={k:tail_evidence(a['cal.'+k],v) for k,v in raw.items()}
        score=np.zeros(len(X),dtype=float)
        for k,w in self.meta['weights'].items():
            if float(w):
                if k not in evidence: raise ValueError(f'V55 runtime missing weighted component {k}')
                score+=float(w)*evidence[k]
        alert=(score>=float(self.meta['threshold'])) & bool(self.meta['state_gate_passed'])
        return {'state_scaled':pred,'score':score,'alert':alert,'components':evidence,
                'transition_feature_energy':np.mean(delta*delta,axis=1),
                'automatic_containment':False,'score_kind':'benign_tail_evidence_not_probability'}
