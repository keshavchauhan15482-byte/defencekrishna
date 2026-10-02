"""Runtime/security fixtures only. Synthetic weights are not benchmark evidence."""
import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import numpy as np
import pytest

from garuda_v3.connection_shadow import ConnectionStartShadowService
from garuda_v3.connection_start import FEATURES, STAGES, SERVICE_NODES
from garuda_v3.causal_stage_forecast import sha
from garuda_v3.integrated_server import IntegratedApp, IntegratedHandler
from garuda_v3.model import CONNECTION_START_SCHEMA, GraphWorldModel
from garuda_v3.server import Server


def bundle(path):
    path.mkdir();rows=[]
    for seed in (42,43,44):
        p=path/f'gnn_lstm_seed{seed}.npz'
        m=GraphWorldModel(feature_dim=len(FEATURES),stage_count=5,seed=seed,
                          decoder='residual',schema=CONNECTION_START_SCHEMA)
        m.save(p,{'features':FEATURES,'shadow_only':True,'risk_head_trained':True})
        rows.append({'architecture':'gnn_lstm','seed':seed,'checkpoint':p.name,
            'checkpoint_sha256':sha(p),'risk_calibration':[{'a':1.,'b':0.}]*4,
            'risk_thresholds':[.7]*4,'risk_gate_passed':False,'stage_thresholds':[1.000001]*5,
            'feature_order':FEATURES,'model_schema':CONNECTION_START_SCHEMA,
            'any_horizon_threshold':.7,'any_horizon_test':{'gate_passed':False},
            'test_stage_multilabel':{s:{'supported_in_development':False,'positive_support':0,
                'recall':None,'precision':None} for s in STAGES}})
    freeze=path/'freeze.json';freeze.write_text(json.dumps({'test_records_parsed':False,'models':rows}))
    (path/'report.json').write_text(json.dumps({'schema':'garuda-connection-start-result-1',
        'feature_order':FEATURES,'graph_nodes':SERVICE_NODES,'models':rows,
        'freeze_sha256':sha(freeze),'automatic_promotion':False,'automatic_containment':False}))
    return path


def payload():
    x=np.zeros((8,len(SERVICE_NODES),len(FEATURES)),np.float32)
    mask=np.zeros((8,len(SERVICE_NODES)));x[4:,0]=.1;mask[4:,0]=1
    return {'schema':CONNECTION_START_SCHEMA,'features':FEATURES,'mode':'service','window_seconds':10,
        'times':list(range(0,80,10)),'x':x.tolist(),
        'adj':np.zeros((8,len(SERVICE_NODES),len(SERVICE_NODES))).tolist(),'mask':mask.tolist()}


def test_missing_history_is_exposed_and_never_authorizes_containment(tmp_path):
    service=ConnectionStartShadowService(bundle(tmp_path/'bundle'))
    result=service.forecast(payload())
    assert result['observed_history_windows']==4 and result['missing_history_windows']==4
    assert not result['observations_complete'] and not result['automatic_containment']
    assert not result['live_sensor_availability_certified'] and not result['precompromise_certified']
    assert len(result['seed_alert_decisions'])==3
    assert [t['horizon_seconds'] for t in result['trajectory']]==[10,20,30,40]
    bad=payload();bad['mask'][4][0]=0;bad['x'][4][0]=[0]*len(FEATURES)
    with pytest.raises(ValueError,match='Insufficient observed history'):service.forecast(bad)
    bad=payload();bad['future_stage']=[1]*5
    with pytest.raises(ValueError,match='forbidden'):service.forecast(bad)


def test_post_test_threshold_tampering_is_rejected(tmp_path):
    path=bundle(tmp_path/'bundle');r=json.loads((path/'report.json').read_text())
    r['models'][0]['any_horizon_threshold']=0
    (path/'report.json').write_text(json.dumps(r))
    with pytest.raises(ValueError,match='pre-test policy freeze'):ConnectionStartShadowService(path)


def test_same_port_api_requires_auth_and_never_calls_enforcement(tmp_path,monkeypatch):
    path=bundle(tmp_path/'bundle');monkeypatch.setenv('GARUDA_CONNECTION_START_BUNDLE',str(path))
    artifacts=__import__('pathlib').Path(__file__).resolve().parents[1]/'artifacts/residual_run'
    app=IntegratedApp(artifacts,tmp_path/'runtime','v'*40,'o'*40)
    def forbidden(*args):raise AssertionError('Shadow inference reached enforcement')
    monkeypatch.setattr(app.response,'observe',forbidden)
    server=Server(('127.0.0.1',0),app);server.RequestHandlerClass=IntegratedHandler
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}/api/connection-start/forecast'
    def request(token=None,origin=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        if origin:headers['Origin']=origin
        try:
            with urlopen(Request(url,json.dumps(payload()).encode(),headers),timeout=5) as r:
                return r.status,json.loads(r.read())
        except HTTPError as e:return e.code,json.loads(e.read())
    try:
        assert request()[0]==401
        assert request('v'*40,'https://outside.invalid')[0]==403
        status,result=request('v'*40)
        assert status==200 and result['status']=='EXPERIMENTAL_SHADOW_ONLY'
        assert not result['automatic_containment'] and app.policy.active()==[]
        app.compute.acquire()
        try:assert request('v'*40)[0]==503
        finally:app.compute.release()
        app.connection_start=None
        assert request('v'*40)[0]==503
    finally:
        server.shutdown();thread.join(timeout=5);server.server_close();app.policy.close()
