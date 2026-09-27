"""V108 development-only PS-complete GraphSAGE+LSTM recovery.

Trains the world model directly on the full SIH packet/flow feature contract already
implemented in ps_complete.py. No consumed external holdout is used for fitting,
selection, support fitting, or adapter selection.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path

import numpy as np

from .autograd import Adam
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import FEATURES, SCHEMA, _connection_flow, graph_snapshot
from .support_gate import fit as fit_support_gate, score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, EMBARGO_SEQUENCES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    RecoveryContractError, file_hash, canonical_sha256, verify_development_capture,
    build_sequences, chronological_phase1_split, persistence_prediction, mse,
    infer_state, state_objective, candidate_row, select_candidate,
)

REQUIRED_PS_FEATURES = {
    'psh_fraction','urg_fraction','iat_variance_log','iat_max_log','ttl_variance_scaled',
    'fragment_fraction','payload_mean_log','payload_variance_log','payload_max_log',
    'unique_destination_ports_log','sequential_port_transition_fraction',
    'random_port_transition_fraction','retransmission_fraction','retransmission_count_log',
}


def packet_service_graphs(path: Path, packet_limit: int):
    times=[]; xs=[]; adjs=[]; masks=[]
    current=None; conns=defaultdict(list); decoded=0

    def flush():
        nonlocal conns
        if current is None:
            return
        flows=[_connection_flow(v) for v in conns.values()]
        x,a,m,_=graph_snapshot(flows,mode='service',max_nodes=MAX_NODES)
        times.append(int(current)); xs.append(x.astype(np.float32,copy=False))
        adjs.append(a.astype(np.float32,copy=False)); masks.append(m.astype(np.float32,copy=False))
        conns=defaultdict(list)

    iterator=packets(path,max_packets=max(packet_limit*2,packet_limit+1))
    for pkt in islice(iterator,packet_limit):
        decoded+=1
        bucket=int(pkt['t']//WINDOW_SECONDS)*WINDOW_SECONDS
        if current is None:
            current=bucket
        elif bucket != current:
            if bucket < current:
                raise RecoveryContractError(f'Non-monotone packet timestamp in {path}')
            flush(); current=bucket
        endpoints=sorted([(pkt['src'],pkt['sport']),(pkt['dst'],pkt['dport'])])
        conns[(endpoints[0],endpoints[1],pkt['protocol'])].append(pkt)
    flush()
    if decoded < 1000:
        raise RecoveryContractError(f'Too few decoded IPv4 packets: {decoded}')
    if len(times) < HISTORY+HORIZON+20:
        raise RecoveryContractError(f'Too few observed 10-second graph windows: {len(times)}')
    return (np.asarray(times,dtype=np.int64),np.asarray(xs,dtype=np.float32),
            np.asarray(adjs,dtype=np.float32),np.asarray(masks,dtype=np.float32),decoded)


def packet_presence(x,mask):
    idx=FEATURES.index('packet_features_present')
    observed=mask>0
    values=x[:,:,:,idx][observed]
    return float(values.mean()) if len(values) else 0.0


def feature_presence(x,mask,name):
    idx=FEATURES.index(name)
    observed=mask>0
    values=x[:,:,:,idx][observed]
    return float(np.mean(values>0)) if len(values) else 0.0


def train_seed(train_arrays,valid_arrays,seed,epochs,batch_size):
    tx,ta,tm,ty=train_arrays; vx,va,vm,vy=valid_arrays
    model=GraphWorldModel(architecture='gnn_lstm',feature_dim=len(FEATURES),seed=int(seed),
                          decoder='residual',stage_count=0,schema=SCHEMA)
    optimizer=Adam(model.parameters(),lr=0.003); rng=np.random.default_rng(seed)
    initial=infer_state(model,vx,va,vm,batch_size=batch_size)
    best=mse(initial,vy); best_epoch=0
    best_weights={k:v.data.copy() for k,v in model.params.items()}
    curve=[{'epoch':0,'train_objective':None,'validation_mse':best}]
    for epoch in range(epochs):
        order=rng.permutation(len(tx)); losses=[]
        for offset in range(0,len(order),batch_size):
            ids=order[offset:offset+batch_size]
            objective=state_objective(model,tx[ids],ta[ids],tm[ids],ty[ids])
            objective.backward(); optimizer.step(); losses.append(float(objective.data))
        val=mse(infer_state(model,vx,va,vm,batch_size=batch_size),vy)
        curve.append({'epoch':epoch+1,'train_objective':float(np.mean(losses)),'validation_mse':val})
        if val < best:
            best=val; best_epoch=epoch+1
            best_weights={k:v.data.copy() for k,v in model.params.items()}
    for key,value in best_weights.items(): model.params[key].data=value
    return model,best,int(best_epoch),curve


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1',required=True,type=Path); p.add_argument('--phase2',required=True,type=Path)
    p.add_argument('--output-dir',required=True,type=Path); p.add_argument('--packet-limit',type=int,default=2_000_000)
    p.add_argument('--seeds',nargs='+',type=int,default=[42,43,44]); p.add_argument('--epochs',type=int,default=8)
    p.add_argument('--batch-size',type=int,default=64); args=p.parse_args()
    if len(set(args.seeds)) < 3: p.error('At least three distinct development seeds are required')
    if args.packet_limit < 100_000: p.error('packet-limit must be at least 100000')
    if not REQUIRED_PS_FEATURES.issubset(set(FEATURES)):
        raise RecoveryContractError('PS-complete schema is missing mandatory packet features')

    phase1_sha=verify_development_capture(args.phase1,PHASE1_NAME,PHASE1_SHA256)
    phase2_sha=verify_development_capture(args.phase2,PHASE2_NAME,PHASE2_SHA256)
    t1,x1,a1,m1,n1=packet_service_graphs(args.phase1,args.packet_limit)
    t2,x2,a2,m2,n2=packet_service_graphs(args.phase2,args.packet_limit)
    sx1,sa1,sm1,sy1,c1=build_sequences(t1,x1,a1,m1)
    sx2,sa2,sm2,sy2,c2=build_sequences(t2,x2,a2,m2)
    train_ids,valid_ids=chronological_phase1_split(len(sx1))
    train=(sx1[train_ids],sa1[train_ids],sm1[train_ids],sy1[train_ids])
    valid=(sx1[valid_ids],sa1[valid_ids],sm1[valid_ids],sy1[valid_ids])
    phase2=(sx2,sa2,sm2,sy2)

    presence={
        'phase1_train':packet_presence(train[0],train[2]),
        'phase1_validation':packet_presence(valid[0],valid[2]),
        'phase2_sanity':packet_presence(phase2[0],phase2[2]),
    }
    if min(presence.values()) <= .95: raise RecoveryContractError('Packet feature presence below 95%')

    rows={}; trained={}; curves={}
    for seed in args.seeds:
        print(f'V108 training seed={seed}',flush=True)
        model,_,epoch,curve=train_seed(train,valid,seed,args.epochs,args.batch_size)
        rows[str(seed)]=candidate_row(model,valid,phase2,seed,epoch)
        trained[str(seed)]=model; curves[str(seed)]=curve
        print(json.dumps(rows[str(seed)],indent=2),flush=True)
    selected_key=select_candidate(rows); selected=rows[selected_key]; model=trained[selected_key]

    gate=fit_support_gate(train[0],train[2],valid[0],valid[2])
    gate['fit_provenance']={'center_scale':'CICAPT Phase-1 train only','threshold':'CICAPT Phase-1 validation only',
                            'phase2_excluded_from_fit':True,'consumed_external_excluded_from_fit':True}
    phase2_scores=support_score(gate,phase2[0],phase2[2]); supported=phase2_scores<=float(gate['threshold'])

    active_feature_presence={name:{
        'phase1_train':feature_presence(train[0],train[2],name),
        'phase1_validation':feature_presence(valid[0],valid[2],name),
        'phase2_sanity':feature_presence(phase2[0],phase2[2],name),
    } for name in sorted(REQUIRED_PS_FEATURES)}

    adapter={'schema':SCHEMA,'features':list(FEATURES),'feature_count':len(FEATURES),'mode':'service',
             'window_seconds':WINDOW_SECONDS,'history_windows':HISTORY,'forecast_windows':HORIZON,
             'max_nodes':MAX_NODES,'packet_features_required':True,
             'mapping':'raw PCAP -> bidirectional connections -> PS-complete service graph'}
    args.output_dir.mkdir(parents=True,exist_ok=True)
    model_path=args.output_dir/'gnn_lstm_ps_complete_candidate.npz'; gate_path=args.output_dir/'support_gate.json'
    metadata={'schema':SCHEMA,'features':list(FEATURES),'architecture':'gnn_lstm','history':HISTORY,'horizon':HORIZON,
              'mode':'service','max_nodes':MAX_NODES,'window_seconds':WINDOW_SECONDS,'source_hashes':[phase1_sha,phase2_sha],
              'seed':int(selected_key),'decoder':'residual','trained':True,'packet_features_trained':True,
              'ps_complete_features_trained':True,'risk_head_trained':False,'stage_supervised':False,
              'evaluation_scope':'development_reused_cross_phase','consumed_external_used_for_fitting':False,
              'claim_boundary':'Development-only PS-complete state-transition candidate; no external/stage/precompromise claim.'}
    model.save(model_path,metadata)
    gate_path.write_text(json.dumps(gate,indent=2,allow_nan=False)+'\n')
    recovery=bool(selected['validation_gate_passed'] and selected['phase2_sanity_passed'])
    report={
        'schema_version':'v108.1','status':'DEV_PS_COMPLETE_PASS' if recovery else 'DEV_PS_COMPLETE_FAIL',
        'recovery_gate_passed':recovery,
        'claim_boundary':'Development-only full SIH flow+packet feature recovery; consumed external holdouts are not used and no fresh external, five-stage, or successful-compromise claim is created.',
        'development_sources':{'dataset':'CICAPT-IIoT2024','development_reuse':True,
            'phase1':{'capture':PHASE1_NAME,'sha256':phase1_sha,'decoded_packets':int(n1),'observed_windows':int(len(t1)),'contiguous_sequences':int(len(sx1)),'train_sequences':int(len(train_ids)),'validation_sequences':int(len(valid_ids)),'embargo_sequences':EMBARGO_SEQUENCES},
            'phase2':{'capture':PHASE2_NAME,'sha256':phase2_sha,'decoded_packets':int(n2),'observed_windows':int(len(t2)),'contiguous_sequences':int(len(sx2)),'used_for_selection':False}},
        'adapter_contract':adapter,'adapter_contract_sha256':canonical_sha256(adapter),
        'packet_features_present_mean':presence,'mandatory_ps_feature_nonzero_fraction':active_feature_presence,
        'selection':{'rule':'minimum Phase-1 validation MSE only; ties by seed','selected_seed':int(selected_key),'phase2_used_for_selection':False,'external_used_for_selection':False},
        'seeds':rows,'selected_candidate':selected,
        'support_gate':{'threshold':float(gate['threshold']),'method':gate['method'],'phase2_supported_sequences':int(supported.sum()),'phase2_total_sequences':int(len(supported)),'phase2_supported_fraction':float(supported.mean()),'phase2_median_score':float(np.median(phase2_scores)),'phase2_max_score':float(phase2_scores.max()),'fit_provenance':gate['fit_provenance']},
        'freeze':{'model_file':model_path.name,'model_sha256':file_hash(model_path),'support_gate_file':gate_path.name,'support_gate_sha256':file_hash(gate_path),'candidate_frozen_before_new_external_holdout':True,'new_external_holdout_selected':False},
        'training_curves':curves,
    }
    (args.output_dir/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'selected_candidate':selected,'feature_count':len(FEATURES)},indent=2))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
