"""V116 development-only clamp-free relative-state world-model recovery.

V115 proved the history-relative representation improves raw reconstruction and support,
but its relative coordinates were fed to the legacy [0,1]-clamped residual decoder.
V116 changes only that decoder contract: relative_residual performs an unbounded residual
rollout in relative coordinates. Training/selection use CICAPT development data only.
All previously observed external captures remain quarantined and are not read here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .autograd import Adam
from .model import GraphWorldModel
from .ps_complete import FEATURES
from .support_gate import fit as fit_support_gate, score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES, EMBARGO_SEQUENCES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    RecoveryContractError, file_hash, canonical_sha256, verify_development_capture,
    build_sequences, chronological_phase1_split, infer_state, state_objective, mse,
)
from .v112_tolerant_ps_complete_runtime import tolerant_packet_service_graphs
from .v115_relative_state_world_model import (
    RELATIVE_SCHEMA, RAW_SCHEMA, RELATIVE_FEATURES, PRESENCE_FEATURES,
    SCALE_FLOOR, fit_transform, apply_transform, normalized_and_raw_metrics,
)

DECODER = 'relative_residual'
CONSUMED_EXTERNAL = [
    'HIKARI-2021/V99', 'MAWI/V102', 'CTU-IDSEVAL-6/V104',
    'USTC-TFC2016-Miuref/V106', 'MCFP-327-1/V111',
    'MCFP-111-1/V113', 'MCFP-326-1-Dridex/V114',
]


def train_seed(train, valid, seed: int, epochs: int, batch_size: int):
    tx, ta, tm, ty = train
    vx, va, vm, vy = valid
    model = GraphWorldModel(
        architecture='gnn_lstm', feature_dim=len(FEATURES), seed=int(seed),
        decoder=DECODER, stage_count=0, schema=RELATIVE_SCHEMA,
    )
    opt = Adam(model.parameters(), lr=0.003)
    rng = np.random.default_rng(seed)
    initial = mse(infer_state(model, vx, va, vm, batch_size=batch_size), vy)
    best = initial; best_epoch = 0
    best_weights = {k: v.data.copy() for k, v in model.params.items()}
    curve = [{'epoch': 0, 'train_objective': None, 'validation_mse': initial}]
    for epoch in range(epochs):
        order = rng.permutation(len(tx)); losses = []
        for offset in range(0, len(order), batch_size):
            ids = order[offset:offset + batch_size]
            objective = state_objective(model, tx[ids], ta[ids], tm[ids], ty[ids])
            objective.backward(); opt.step(); losses.append(float(objective.data))
        val = mse(infer_state(model, vx, va, vm, batch_size=batch_size), vy)
        curve.append({'epoch': epoch + 1, 'train_objective': float(np.mean(losses)), 'validation_mse': val})
        if val < best:
            best = val; best_epoch = epoch + 1
            best_weights = {k: v.data.copy() for k, v in model.params.items()}
    for key, value in best_weights.items():
        model.params[key].data = value
    return model, int(best_epoch), curve


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1', required=True, type=Path)
    p.add_argument('--phase2', required=True, type=Path)
    p.add_argument('--output-dir', required=True, type=Path)
    p.add_argument('--packet-limit', type=int, default=2_000_000)
    p.add_argument('--seeds', nargs='+', type=int, default=[42,43,44])
    p.add_argument('--epochs', type=int, default=8)
    p.add_argument('--batch-size', type=int, default=64)
    args = p.parse_args()
    if len(FEATURES) != 34 or len(RELATIVE_FEATURES) != 29 or len(PRESENCE_FEATURES) != 5:
        raise RecoveryContractError('V116 requires the V115 34-feature relative contract')
    if len(set(args.seeds)) < 3:
        p.error('At least three distinct development seeds are required')

    phase1_sha = verify_development_capture(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_development_capture(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    t1,x1,a1,m1,n1,audit1 = tolerant_packet_service_graphs(args.phase1,args.packet_limit)
    t2,x2,a2,m2,n2,audit2 = tolerant_packet_service_graphs(args.phase2,args.packet_limit)
    sx1,sa1,sm1,sy1_raw,_ = build_sequences(t1,x1,a1,m1)
    sx2,sa2,sm2,sy2_raw,_ = build_sequences(t2,x2,a2,m2)
    train_ids,valid_ids = chronological_phase1_split(len(sx1))

    transform = fit_transform(sx1[train_ids],sm1[train_ids])
    nx1,ny1,c1 = apply_transform(sx1,sy1_raw,sm1,transform)
    nx2,ny2,c2 = apply_transform(sx2,sy2_raw,sm2,transform)
    train=(nx1[train_ids],sa1[train_ids],sm1[train_ids],ny1[train_ids])
    valid=(nx1[valid_ids],sa1[valid_ids],sm1[valid_ids],ny1[valid_ids])
    phase2=(nx2,sa2,sm2,ny2)

    rows={}; models={}; curves={}
    for seed in args.seeds:
        print(f'V116 training seed={seed}',flush=True)
        model,epoch,curve=train_seed(train,valid,int(seed),args.epochs,args.batch_size)
        vm=normalized_and_raw_metrics(model,valid,sy1_raw[valid_ids],c1[valid_ids],transform,args.batch_size)
        pm=normalized_and_raw_metrics(model,phase2,sy2_raw,c2,transform,args.batch_size)
        rows[str(seed)]={'seed':int(seed),'best_epoch':epoch,'validation':vm,'phase2':pm}
        models[str(seed)]=model; curves[str(seed)]=curve
        print(json.dumps(rows[str(seed)],indent=2),flush=True)
    selected_key=min(rows,key=lambda k:(rows[k]['validation']['normalized_model_mse'],int(k)))
    selected=rows[selected_key]; model=models[selected_key]

    gate=fit_support_gate(train[0],train[2],valid[0],valid[2])
    gate['fit_provenance']={
        'center_scale':'history-relative Phase-1 train only',
        'threshold':'history-relative Phase-1 validation only',
        'phase2_excluded_from_fit':True,
        'all_consumed_external_holdouts_excluded_from_fit':True,
    }
    scores=support_score(gate,phase2[0],phase2[2]); supported=scores<=float(gate['threshold'])
    support_fraction=float(supported.mean())
    gates={
        'validation_normalized_beats_persistence':bool(selected['validation']['normalized_beats_persistence']),
        'validation_raw_beats_persistence':bool(selected['validation']['raw_beats_persistence']),
        'phase2_normalized_beats_persistence':bool(selected['phase2']['normalized_beats_persistence']),
        'phase2_raw_beats_persistence':bool(selected['phase2']['raw_beats_persistence']),
        'phase2_supported_fraction_at_least_0_95':bool(support_fraction>=0.95),
    }
    passed=all(gates.values())

    args.output_dir.mkdir(parents=True,exist_ok=True)
    model_path=args.output_dir/'gnn_lstm_relative_residual_candidate.npz'
    gate_path=args.output_dir/'support_gate.json'
    transform_path=args.output_dir/'relative_transform.json'
    transform_path.write_text(json.dumps(transform,indent=2,allow_nan=False)+'\n')
    gate_path.write_text(json.dumps(gate,indent=2,allow_nan=False)+'\n')
    transform_sha=file_hash(transform_path)
    metadata={
        'schema':RELATIVE_SCHEMA,'raw_input_schema':RAW_SCHEMA,'features':list(FEATURES),
        'architecture':'gnn_lstm','history':HISTORY,'horizon':HORIZON,'mode':'service',
        'max_nodes':MAX_NODES,'window_seconds':WINDOW_SECONDS,'seed':int(selected_key),
        'decoder':DECODER,'trained':True,'packet_features_trained':True,
        'ps_complete_features_trained':True,'history_relative_state':True,
        'relative_transform_sha256':transform_sha,'risk_head_trained':False,'stage_supervised':False,
        'evaluation_scope':'development_reused_cross_phase','consumed_external_used_for_fitting':False,
        'claim_boundary':'Development-only clamp-free relative-state candidate; no external/stage/precompromise claim.',
    }
    model.save(model_path,metadata)
    contract={
        'raw_schema':RAW_SCHEMA,'model_schema':RELATIVE_SCHEMA,'decoder':DECODER,
        'raw_feature_count':34,'relative_feature_count':29,'presence_identity_count':5,
        'local_center':'per-sequence median of pooled history only',
        'scale_fit':'1.4826*MAD of pooled Phase-1 training histories only','scale_floor':SCALE_FLOOR,
        'decoder_rollout':'current + 0.1*tanh(innovation), no [0,1] clamp',
        'future_information_used':False,'external_statistics_used':False,
    }
    report={
        'schema_version':'v116.1','status':'DEV_RELATIVE_RESIDUAL_PASS' if passed else 'DEV_RELATIVE_RESIDUAL_FAIL',
        'recovery_gate_passed':passed,
        'claim_boundary':'Development-only decoder correction after V115. All consumed external captures are quarantined; no fresh external claim is created.',
        'development_sources':{
            'dataset':'CICAPT-IIoT2024','development_reuse':True,
            'phase1':{'capture':PHASE1_NAME,'sha256':phase1_sha,'decoded_ipv4_packets':int(n1),'parser_audit':audit1,'train_sequences':int(len(train_ids)),'validation_sequences':int(len(valid_ids)),'embargo_sequences':EMBARGO_SEQUENCES},
            'phase2':{'capture':PHASE2_NAME,'sha256':phase2_sha,'decoded_ipv4_packets':int(n2),'parser_audit':audit2,'sequences':int(len(sx2)),'used_for_selection':False},
            'consumed_external_packets_used':False,
        },
        'representation':{'contract':contract,'contract_sha256':canonical_sha256(contract),'transform_sha256':transform_sha},
        'selection':{'rule':'minimum Phase-1 validation normalized MSE only; ties by seed','selected_seed':int(selected_key),'phase2_used_for_selection':False,'external_used_for_selection':False},
        'seeds':rows,'selected_candidate':selected,
        'support_gate':{'method':gate['method'],'threshold':float(gate['threshold']),'phase2_supported_sequences':int(supported.sum()),'phase2_total_sequences':int(len(supported)),'phase2_supported_fraction':support_fraction,'phase2_median_score':float(np.median(scores)),'phase2_max_score':float(scores.max()),'fit_provenance':gate['fit_provenance']},
        'gates':gates,
        'quarantine':{'consumed_external_holdouts':CONSUMED_EXTERNAL,'used_for_fitting_or_selection':False},
        'freeze':{'model_file':model_path.name,'model_sha256':file_hash(model_path),'support_gate_file':gate_path.name,'support_gate_sha256':file_hash(gate_path),'relative_transform_file':transform_path.name,'relative_transform_sha256':transform_sha,'candidate_frozen_before_new_external_selection':bool(passed),'new_external_holdout_selected':False},
        'training_curves':curves,
    }
    (args.output_dir/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'status':report['status'],'selected':selected,'support':report['support_gate'],'gates':gates},indent=2),flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
