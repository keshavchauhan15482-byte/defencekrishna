import json

import numpy as np
import pytest

from garuda_v3.causal_shadow import CausalShadowService
from garuda_v3.causal_stage_forecast import FEATURES, STAGES, sha
from garuda_v3.data import SERVICE_NODES
from garuda_v3.model import CAUSAL_FLOW_SCHEMA, GraphWorldModel


def fixture_bundle(path):
    # Interface/security fixture, not a trained model or benchmark evidence.
    rows=[]
    for seed in (42,43,44):
        p=path/f'gnn_lstm_seed{seed}.npz'
        model=GraphWorldModel(feature_dim=len(FEATURES),stage_count=5,seed=seed,
            decoder='residual',schema=CAUSAL_FLOW_SCHEMA)
        model.save(p,{'features':FEATURES,'shadow_only':True,'risk_head_trained':True})
        rows.append({'architecture':'gnn_lstm','seed':seed,'checkpoint':p.name,
            'checkpoint_sha256':sha(p),'risk_calibration':[{'a':1.,'b':0.}]*4,
            'risk_gate_passed':False,'stage_thresholds':[1.000001]*5,
            'test_stage_multilabel':{s:{'supported_in_development':False,'positive_support':0,'recall':None,'precision':None} for s in STAGES}})
    (path/'report.json').write_text(json.dumps({'schema':'garuda-causal-native-result-1',
        'feature_order':FEATURES,'graph_nodes':SERVICE_NODES,'models':rows,
        'automatic_promotion':False,'automatic_containment':False}))


def observed_payload():
    x=np.zeros((8,len(SERVICE_NODES),len(FEATURES)),np.float32)
    x[:,0,:]=.1;mask=np.zeros((8,len(SERVICE_NODES)));mask[:,0]=1
    return {'schema':CAUSAL_FLOW_SCHEMA,'features':FEATURES,'mode':'service','window_seconds':10,
        'times':list(range(0,80,10)),'x':x.tolist(),
        'adj':np.zeros((8,len(SERVICE_NODES),len(SERVICE_NODES))).tolist(),'mask':mask.tolist()}


def test_ensemble_has_real_gradients_finite_rollouts_and_no_enforcement(tmp_path):
    fixture_bundle(tmp_path)
    r=CausalShadowService(tmp_path).forecast(observed_payload())
    assert [p['horizon_seconds'] for p in r['trajectory']]==[10,20,30,40]
    assert all(np.isfinite(p['state_mean']).all() and 0<=p['future_attack_score']<=1 for p in r['trajectory'])
    assert all(p['predicted_tactics']==['insufficient evidence'] for p in r['trajectory'])
    assert r['driving_features'] and 0<sum(v['sensitivity_share'] for v in r['driving_features'])<=1.000001
    assert not r['automatic_containment'] and not r['live_warning_claim']


def test_future_labels_extra_fields_noncontiguous_history_and_hash_changes_rejected(tmp_path):
    fixture_bundle(tmp_path);service=CausalShadowService(tmp_path)
    p=observed_payload();p['future_y']=[1,1,1,1]
    with pytest.raises(ValueError,match='forbidden'):service.forecast(p)
    p=observed_payload();p['times'][3]+=10
    with pytest.raises(ValueError,match='Contiguous'):service.forecast(p)
    f=tmp_path/'gnn_lstm_seed42.npz';f.write_bytes(f.read_bytes()+b'x')
    with pytest.raises(ValueError,match='hash mismatch'):CausalShadowService(tmp_path)
