"""V112 development-only tolerant runtime recovery after the sealed V111 incompatibility.

The V108 34-feature GraphSAGE+LSTM weights and V108 support gate are kept byte-for-byte
unchanged. Only the packet ingestion contract is versioned to the already-implemented
pcap_reader allow_truncated=True behavior, which skips unrecoverable short link-layer
records and audits all degraded/skipped records. Validation uses only previously-used
CICAPT development data. V111 is quarantined and must never be supplied here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path

import numpy as np

from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import FEATURES, SCHEMA, _connection_flow, graph_snapshot
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    PHASE2_NAME, PHASE2_SHA256, RecoveryContractError,
    build_sequences, infer_state, persistence_prediction, canonical_sha256,
)

MODEL_SHA256 = "f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed"
SUPPORT_SHA256 = "7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1"
V111_SHA256 = "cf478922f789926dab81f212a1a64d604b849068908c5c8885f42cdc32206ae3"
V111_NAME = "capture_win11.pcap"

AUDIT_KEYS = (
    'decoded_ipv4','full_tcp','full_udp','degraded_short_ip_options',
    'degraded_short_tcp','degraded_short_udp','nonfirst_fragment','other_protocol',
    'skipped_truncated_ethernet','skipped_truncated_vlan',
    'skipped_truncated_ipv4_header','non_ipv4',
)


def file_hash(path: Path, algorithm: str = 'sha256') -> str:
    h=hashlib.new(algorithm)
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


def verify_phase2(path: Path) -> str:
    if path.name == V111_NAME:
        raise RecoveryContractError('V111 external capture is quarantined from V112')
    observed=file_hash(path)
    if observed == V111_SHA256:
        raise RecoveryContractError('V111 external capture hash is quarantined from V112')
    if path.name != PHASE2_NAME or observed != PHASE2_SHA256:
        raise RecoveryContractError('V112 accepts only hash-pinned CICAPT Phase-2 development capture')
    return observed


def tolerant_packet_service_graphs(path: Path, packet_limit: int):
    times=[]; xs=[]; adjs=[]; masks=[]
    current=None; conns=defaultdict(list); decoded=0; audit={}

    def flush():
        nonlocal conns
        if current is None: return
        flows=[_connection_flow(v) for v in conns.values()]
        x,a,m,_=graph_snapshot(flows,mode='service',max_nodes=MAX_NODES)
        times.append(int(current)); xs.append(x.astype(np.float32,copy=False))
        adjs.append(a.astype(np.float32,copy=False)); masks.append(m.astype(np.float32,copy=False))
        conns=defaultdict(list)

    iterator=packets(path,max_packets=max(packet_limit*2,packet_limit+1),allow_truncated=True,audit=audit)
    for pkt in islice(iterator,packet_limit):
        decoded+=1
        bucket=int(pkt['t']//WINDOW_SECONDS)*WINDOW_SECONDS
        if current is None: current=bucket
        elif bucket != current:
            if bucket < current:
                raise RecoveryContractError(f'Non-monotone packet timestamp in {path}')
            flush(); current=bucket
        endpoints=sorted([(pkt['src'],pkt['sport']),(pkt['dst'],pkt['dport'])])
        conns[(endpoints[0],endpoints[1],pkt['protocol'])].append(pkt)
    flush()
    if decoded < 1000: raise RecoveryContractError(f'Too few decoded IPv4 packets: {decoded}')
    if len(times) < HISTORY+HORIZON+20:
        raise RecoveryContractError(f'Too few observed windows: {len(times)}')
    normalized={k:int(audit.get(k,0)) for k in AUDIT_KEYS}
    return (np.asarray(times,dtype=np.int64),np.asarray(xs,dtype=np.float32),
            np.asarray(adjs,dtype=np.float32),np.asarray(masks,dtype=np.float32),decoded,normalized)


def packet_presence(x,mask):
    idx=FEATURES.index('packet_features_present')
    vals=x[:,:,idx][mask>0]
    return float(vals.mean()) if len(vals) else 0.0


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase2',required=True,type=Path)
    p.add_argument('--model',required=True,type=Path)
    p.add_argument('--support-gate',required=True,type=Path)
    p.add_argument('--packet-limit',type=int,default=2_000_000)
    p.add_argument('--output-dir',required=True,type=Path)
    args=p.parse_args()
    if args.packet_limit < 100_000: p.error('packet-limit must be at least 100000')
    args.output_dir.mkdir(parents=True,exist_ok=True)
    summary_path=args.output_dir/'summary.json'
    if summary_path.exists(): p.error('V112 evidence is immutable; output already exists')

    phase2_sha=verify_phase2(args.phase2)
    if file_hash(args.model) != MODEL_SHA256: raise RecoveryContractError('V108 model hash drift')
    if file_hash(args.support_gate) != SUPPORT_SHA256: raise RecoveryContractError('V108 support gate hash drift')
    model,meta=GraphWorldModel.load(args.model)
    contract={
        'architecture':model.config['architecture'],'decoder':model.config['decoder'],
        'schema':model.schema,'feature_count':int(model.f),'history':int(meta.get('history',-1)),
        'horizon':int(meta.get('horizon',-1)),'mode':meta.get('mode'),
        'window_seconds':int(meta.get('window_seconds',-1)),'max_nodes':int(meta.get('max_nodes',-1)),
        'packet_features_trained':bool(meta.get('packet_features_trained')),
        'ps_complete_features_trained':bool(meta.get('ps_complete_features_trained')),
        'feature_order_match':list(meta.get('features',[]))==list(FEATURES),
    }
    expected={'architecture':'gnn_lstm','decoder':'residual','schema':SCHEMA,'feature_count':34,
              'history':8,'horizon':4,'mode':'service','window_seconds':10,'max_nodes':32,
              'packet_features_trained':True,'ps_complete_features_trained':True,'feature_order_match':True}
    if contract != expected: raise RecoveryContractError(f'Frozen V108 model contract mismatch: {contract}')

    times,x,adj,mask,decoded,audit=tolerant_packet_service_graphs(args.phase2,args.packet_limit)
    sx,sa,sm,target,cutoffs=build_sequences(times,x,adj,mask)
    pred=infer_state(model,sx,sa,sm)
    persistence=persistence_prediction(sx,sm)
    model_mse=float(np.mean((pred-target)**2,dtype=np.float64))
    persistence_mse=float(np.mean((persistence-target)**2,dtype=np.float64))
    improvement=float((persistence_mse-model_mse)/persistence_mse) if persistence_mse else 0.0

    gate=json.loads(args.support_gate.read_text())
    scores=support_score(gate,sx,sm)
    threshold=float(gate['threshold']); supported=scores<=threshold
    supported_fraction=float(supported.mean()) if len(supported) else 0.0
    presence=packet_presence(x,mask)

    adapter={
        'schema':SCHEMA,'features':list(FEATURES),'feature_count':len(FEATURES),
        'mode':'service','window_seconds':WINDOW_SECONDS,'history_windows':HISTORY,
        'forecast_windows':HORIZON,'max_nodes':MAX_NODES,'packet_features_required':True,
        'mapping':'raw PCAP/PCAPNG -> tolerant audited decoder -> bidirectional connections -> PS-complete service graph',
        'pcap_reader_mode':{'allow_truncated':True,'skip_unrecoverable_short_link_layer_records':True,
                            'degrade_recoverable_short_network_transport_records':True,
                            'audit_keys':list(AUDIT_KEYS)},
        'frozen_model_weights_changed':False,'frozen_support_gate_changed':False,
    }
    adapter_sha=canonical_sha256(adapter)
    gates={
        'phase2_sequences_at_least_32':len(sx)>=32,
        'model_beats_persistence':model_mse<persistence_mse,
        'improvement_positive':improvement>0.0,
        'support_fraction_at_least_0_95':supported_fraction>=0.95,
        'packet_presence_at_least_0_95':presence>=0.95,
    }
    passed=all(gates.values())
    report={
        'schema_version':'v112.1','status':'DEV_TOLERANT_RUNTIME_PASS' if passed else 'DEV_TOLERANT_RUNTIME_FAIL',
        'claim_boundary':'Development-only runtime-adapter recovery. V111 is quarantined; no new external-generalisation, attack, MITRE-stage, or successful-compromise claim is created.',
        'recovery_design':{
            'model_weights_retrained_after_v111':False,'support_gate_refit_after_v111':False,
            'normalization_refit_after_v111':False,'risk_or_stage_thresholds_changed':False,
            'only_change':'packet decoder runtime contract switches to pre-existing audited allow_truncated=True mode',
            'v111_used_for_fit_selection_or_thresholding':False,
        },
        'quarantined_external':{'dataset':'CTU-Malware-Capture-Botnet-327-1','sha256':V111_SHA256,'used':False},
        'development_source':{'dataset':'CICAPT-IIoT2024','capture':PHASE2_NAME,'sha256':phase2_sha,
                              'development_reuse':True,'decoded_ipv4_packets':int(decoded),'observed_windows':int(len(times)),
                              'contiguous_sequences':int(len(sx))},
        'frozen_candidate':{'model_sha256':MODEL_SHA256,'support_gate_sha256':SUPPORT_SHA256,'contract':contract},
        'adapter_contract':adapter,'adapter_contract_sha256':adapter_sha,
        'parser_audit':audit,'packet_features_present_mean':presence,
        'state_forecasting':{'model_mse':model_mse,'persistence_mse':persistence_mse,
                             'improvement_vs_persistence':improvement,'beats_persistence':model_mse<persistence_mse},
        'runtime_support':{'method':gate.get('method'),'threshold':threshold,'supported_sequences':int(supported.sum()),
                           'total_sequences':int(len(supported)),'supported_fraction':supported_fraction,
                           'median_score':float(np.median(scores)),'max_score':float(scores.max())},
        'gates':gates,'recovery_gate_passed':passed,
        'freeze':{'candidate_frozen_before_new_external_selection':bool(passed),
                  'new_external_holdout_selected':False,
                  'model_sha256':MODEL_SHA256,'support_gate_sha256':SUPPORT_SHA256,
                  'adapter_contract_sha256':adapter_sha},
        'cutoff_timestamps_sha256':hashlib.sha256(cutoffs.astype(np.int64).tobytes()).hexdigest(),
    }
    summary_path.write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    (args.output_dir/'adapter_contract.json').write_text(json.dumps(adapter,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'state_forecasting':report['state_forecasting'],
                      'runtime_support':report['runtime_support'],'parser_audit':audit,
                      'adapter_contract_sha256':adapter_sha},indent=2))
    return 0

if __name__=='__main__': raise SystemExit(main())
