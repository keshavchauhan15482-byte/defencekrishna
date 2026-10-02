import copy

import numpy as np
import pytest

from garuda_v3.connection_start import event, graphs_from_rows
from garuda_v3.connection_experiment import event_warnings
from garuda_v3 import connection_start
from garuda_v3.causal_stage_forecast import sha, state_metrics


def row(t,label='none'):
    return {'uid':str(t),'ts':t,'src_ip_zeek':'192.0.2.1','dest_ip_zeek':'192.0.2.2',
        'src_port_zeek':43000,'dest_port_zeek':443,'proto':'tcp','label_tactic':label,
        'duration':None,'orig_pkts':100000,'resp_ip_bytes':9999999,'history':'ShADFa'}


def test_finished_statistics_and_targets_cannot_change_start_graph():
    rows=[row(t) for t in range(0,150,10)]
    altered=copy.deepcopy(rows)
    for r in altered:
        r.update(duration=10000,orig_pkts=1,resp_ip_bytes=0,history='^',label_tactic='Initial Access')
    a,_=graphs_from_rows(rows);b,_=graphs_from_rows(altered)
    for k in ('x','adj','mask','times'):np.testing.assert_array_equal(a[k],b[k])
    assert (a['y']==0).all() and (b['y']==1).all()


def test_unbounded_session_duration_does_not_censor_start_events():
    rows=[row(t,'Reconnaissance' if t>=100 else 'none') for t in range(0,150,10)]
    d,audit=graphs_from_rows(rows)
    assert len(d['times'])==14 and (d['y']==1).sum()==4
    assert audit['finished_flow_statistics_used'] is False
    assert audit['empty_windows_imputed']==0


def test_future_zeek_direction_flip_cannot_change_start_features():
    a=row(0)
    b={**a,'src_ip_zeek':a['dest_ip_zeek'],'dest_ip_zeek':a['src_ip_zeek'],
       'src_port_zeek':a['dest_port_zeek'],'dest_port_zeek':a['src_port_zeek']}
    assert event(a)==event(b)


def test_duplicate_native_tactics_do_not_inflate_counts():
    a=row(0,'Initial Access');b={**a,'label_tactic':'Persistence'}
    d,audit=graphs_from_rows([a,b,row(10)])
    reference,_=graphs_from_rows([a,row(10)])
    np.testing.assert_array_equal(d['x'],reference['x'])
    assert audit['unique_start_events']==2 and audit['duplicate_label_copies_merged']==1
    assert d['stage'][0].tolist()==[0,1,0,0,0]


def test_conflicting_truth_and_invalid_windows_stay_unknown_or_excluded():
    a=row(0,'none');b={**a,'label_tactic':'Reconnaissance'}
    d,_=graphs_from_rows([a,b,row(10),row(20)])
    assert d['y'][0]==-1
    rows=[row(0),{**row(10),'dest_ip_zeek':'invalid'},row(20),row(30)]
    d,audit=graphs_from_rows(rows)
    assert d['times'].tolist()==[0,20]
    assert audit['contaminated_windows_removed']==0  # Entire invalid-only bucket has no graph.
    assert audit['invalid_only_windows_removed']==1
    assert audit['invalid_start_events']==1
    with pytest.raises(ValueError,match='bounded observation timestamp'):
        graphs_from_rows([{**row(0),'ts':'bad','dest_ip_zeek':'invalid'}])


def test_binary_tactic_conflict_is_not_benign():
    d,_=graphs_from_rows([{**row(0),'label_binary':True},row(10)])
    assert d['y'][0]==-1


def test_event_warning_counts_unique_future_start_and_preserves_miss():
    y=np.asarray([[1,0,0,0],[0,1,0,0],[1,0,0,0]])
    test={'history_y':np.zeros((3,8),np.int8),'y':y,
          'cutoff':np.asarray([100,90,200]),'source':np.asarray(['a','a','b']),
          'future_attack_times':np.asarray([[105,np.nan,np.nan,np.nan],
              [np.nan,105,np.nan,np.nan],[205,np.nan,np.nan,np.nan]])}
    result=event_warnings(test,np.asarray([[.9,0,0,0],[0,.8,0,0],[.1,0,0,0]]),.7)
    assert result['eligible_events']==2 and result['hits']==1 and result['misses']==1
    assert result['event_recall']==.5 and result['median_hit_lead_seconds']==15
    assert result['precompromise_claim'] is False
    assert result['events'][1]['successful_compromise_time'] is None


def test_sparse_history_masks_future_targets_without_inventing_benign(tmp_path,monkeypatch):
    source=tmp_path/'source';source.write_bytes(b'fixture')
    # Missing t=20/90 buckets carry no native observation or benign annotation.
    rows=[row(t) for t in range(0,210,10) if t not in (20,90)]
    monkeypatch.setattr(connection_start,'source_rows',lambda *args:iter(rows))
    d,audit=connection_start.prepare_source({'id':'fixture','path':str(source),'sha256':sha(source)})
    i=int(np.flatnonzero(d['cutoff']==80)[0])
    assert d['history_y'][i,2]==-1 and d['mask'][i,2].sum()==0
    assert d['y'][i,1]==-1 and not d['future_observed'][i,1]
    assert d['mask'][i,-1].sum()>0
    assert audit['empty_windows_imputed']==0 and audit['missing_observation_buckets']==2
    means=d['future'].copy()+.1
    a=state_metrics(d,means)
    d['future'][~d['future_observed']]=100
    b=state_metrics(d,means)
    assert a==b  # Unknown future targets never affect scores or persistence gates.


def test_fully_unobserved_future_cannot_produce_a_state_pass():
    d={'x':np.zeros((1,8,1,2)),'mask':np.ones((1,8,1)),
       'future':np.zeros((1,4,2)),'future_observed':np.zeros((1,4),bool),
       'source':np.asarray(['s']),'day':np.asarray([1])}
    with pytest.raises(ValueError,match='observed future state'):state_metrics(d,d['future'])
