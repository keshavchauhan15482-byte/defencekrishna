import copy
import json
from pathlib import Path

import numpy as np
import pytest

from garuda_v3.causal_stage_forecast import (
    binary_metrics, completed_flow, graphs_from_rows, native_label, threshold,
    validate_protocol,
)
from garuda_v3.coupled_heads import future_any_target, select_any_horizon_threshold


def row(t, label='none', uid=None, duration=1):
    return {'ts':float(t), 'duration':duration, 'proto':'tcp', 'orig_pkts':2,
        'resp_pkts':1, 'orig_ip_bytes':120, 'resp_ip_bytes':60,
        'src_port_zeek':12345, 'dest_port_zeek':443, 'src_ip_zeek':'192.0.2.1',
        'dest_ip_zeek':'192.0.2.2', 'uid':uid or str(t), 'label_tactic':label}


def test_labels_never_change_observed_network_features():
    a=[row(t) for t in range(0,140,10)]
    b=copy.deepcopy(a)
    for r in b: r['label_tactic']='Initial Access'
    first,_=graphs_from_rows(a); second,_=graphs_from_rows(b)
    for k in ('x','adj','mask','times'): np.testing.assert_array_equal(first[k],second[k])
    assert (first['y']==0).all() and (second['y']==1).all()


def test_flow_enters_at_completion_not_start():
    rows=[row(1,duration=80),row(12),row(22),row(92)]
    d,_=graphs_from_rows(rows)
    assert d['times'].tolist()==[10,20,80]
    assert completed_flow(rows[0])['end']==81


def test_export_receipt_prevents_statistics_entering_before_availability():
    data=[{**row(1),'_record_available_at':41},row(12),row(52)]
    d,_=graphs_from_rows(data)
    assert d['times'].tolist()==[10,40]
    with pytest.raises(ValueError,match='Receipt precedes'):
        completed_flow({**row(1,duration=5),'_record_available_at':3})


def test_native_flattened_duplicates_count_traffic_once_and_keep_overlap():
    a=row(1,'Initial Access',uid='connection')
    b={**a,'label_tactic':'Privilege Escalation'}
    c={**a,'label_tactic':'Persistence'}
    simple,_=graphs_from_rows([a,row(12)])
    merged,audit=graphs_from_rows([a,b,c,row(12)])
    np.testing.assert_array_equal(simple['x'],merged['x'])
    np.testing.assert_array_equal(simple['adj'],merged['adj'])
    assert audit['flattened_duplicate_rows_merged']==2
    assert merged['stage'][0].tolist()==[0,1,0,0,0]
    with pytest.raises(ValueError,match='Conflicting telemetry'):
        graphs_from_rows([a,{**b,'orig_pkts':50},row(12)])


def test_missing_or_conflicting_native_truth_stays_unknown():
    assert native_label(None)[0]==-1
    assert native_label('Reconnissance')[0]==-1
    assert native_label('Discovery')[0]==1
    assert native_label('Discovery')[1].sum()==0
    d,_=graphs_from_rows([row(1,None),row(12)])
    assert d['y'][0]==-1
    a=row(1,'none');b={**a,'label_tactic':'Reconnaissance'}
    d,_=graphs_from_rows([a,b,row(12)])
    assert d['y'][0]==-1 and (d['stage'][0]==-1).all()


def test_unknown_completion_cannot_be_retroactively_imputed():
    with pytest.raises(ValueError,match='unknown-completion censoring'):
        graphs_from_rows([row(1,duration=None),row(12)])
    single={**row(1,duration=None),'orig_pkts':1,'resp_pkts':0}
    assert completed_flow(single)['end']==1


def test_threshold_disables_policy_without_actual_benign_support():
    y=np.ones(400,np.int8); score=np.full(400,.999)
    t,status=threshold(y,score)
    assert t>1 and status=='INSUFFICIENT_VALIDATION_SUPPORT'
    assert binary_metrics(y,score,t)['gate_passed'] is False
    assert binary_metrics(y,score,t)['fpr'] is None
    y=np.r_[np.zeros(400),np.ones(40)]
    score=np.r_[np.linspace(.01,.8,400),np.full(40,.9)]
    t,status=threshold(y,score)
    assert status=='VALIDATION_ONLY_1_PERCENT_FPR'
    assert binary_metrics(y,score,t)['fpr']<=.01


def test_zero_future_positives_are_unmeasurable_not_zero_recall():
    m=binary_metrics(np.zeros(500),np.zeros(500),.5)
    assert m['recall'] is None and m['f1'] is None
    assert m['attack_performance_status']=='NO_FUTURE_POSITIVE_SUPPORT'


def test_joint_future_truth_preserves_unknown_and_threshold_controls_actual_or():
    y=np.asarray([[0,0,0,0],[0,-1,0,0],[-1,0,1,0]])
    assert future_any_target(y).tolist()==[0,-1,1]
    y=np.zeros((1000,4),np.int8);y[-40:]=1
    s=np.full((1000,4),.01)
    for h in range(4):s[h*9:(h+1)*9,h]=.9
    s[-40:]=.95
    assert ((s[:960]>=.5).any(1)).mean()>.01
    t=select_any_horizon_threshold(y,s)
    m=binary_metrics(future_any_target(y),s.max(1),t)
    assert m['fpr']<=.01 and m['recall']==1


def test_final_release_cannot_share_development_identity():
    p={'schema':'garuda-causal-native-protocol-1','frozen_before_test_metrics':True,
        'window_seconds':10,'history':8,'horizon':4,'seeds':[42,43,44],
        'sources':[{'id':'a','split':'train','release':'dev'},
            {'id':'b','split':'validation','release':'dev'},
            {'id':'c','split':'test','release':'fresh'}]}
    for i,s in enumerate(p['sources']):
        s['url']='https://datasets.uwf.edu/data/'+s['id']+'.parquet'
        s['sha256']=str(i)*64
    validate_protocol(p)
    p['sources'][-1]['release']='dev'
    with pytest.raises(ValueError,match='Independent final'):validate_protocol(p)


def test_post_test_freeze_cannot_replace_initial_candidate_freeze(tmp_path, monkeypatch):
    from garuda_v3 import causal_stage_forecast as study
    root=Path(__file__).resolve().parents[2]
    artifacts=root/'garuda_v3/artifacts/causal_native_flow'
    protocols=root/'docs/release/causal_native_forecast'
    bundle=tmp_path/'bundle';bundle.mkdir()
    for name in ('initial_freeze.json','freeze.json'):
        (bundle/name).write_bytes((artifacts/name).read_bytes())
    assert json.loads((bundle/'freeze.json').read_text())['protocol_sha256'] != study.sha(protocols/'initial_protocol.json')
    def stop_before_data(*args):
        raise RuntimeError('Initial protocol and freeze verified')
    monkeypatch.setattr(study,'acquire',stop_before_data)
    args=(protocols/'amended_protocol.json',tmp_path/'cache',tmp_path/'result',bundle,protocols/'initial_protocol.json')
    with pytest.raises(RuntimeError,match='Initial protocol and freeze verified'):
        study.evaluate_frozen(*args)
    (bundle/'initial_freeze.json').unlink()
    with pytest.raises(ValueError,match='Original training protocol changed'):
        study.evaluate_frozen(*args)
