"""V112 development-only tolerant adapter recovery for the frozen V108 34-feature world model.

V111 is consumed and quarantined. This module never reads V111 bytes. It validates the
opt-in tolerant PCAP policy only on hash-pinned CICAPT development captures and freezes
an adapter contract for a later, different untouched external holdout.
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
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    build_sequences, chronological_phase1_split, infer_state,
    persistence_prediction, mse, file_hash, canonical_sha256,
)
from .v108_ps_complete_graph_recovery import packet_presence

V108_MODEL_SHA256 = 'f063ae8c890f9e805c913c02c92b8174cc1d58552514484ea2ef723611258fed'
V108_SUPPORT_SHA256 = '7006671148e0dba3be55a2fe27a2fd17d3a7ece030dbcddd599c7aaa7f5368c1'
V111_SHA256 = 'cf478922f789926dab81f212a1a64d604b849068908c5c8885f42cdc32206ae3'
CONSUMED_TOKENS = ('hikari', 'mawi', 'idseval6', 'ctu-idseval-6', 'miuref', '327-1', 'capture_win11')

class V112ContractError(RuntimeError):
    pass


def assert_not_consumed_external(path: Path) -> None:
    low = path.name.lower()
    if any(token in low for token in CONSUMED_TOKENS):
        raise V112ContractError(f'Consumed external holdout is quarantined from V112 development: {path.name}')
    if path.exists() and file_hash(path) == V111_SHA256:
        raise V112ContractError('Consumed V111 capture SHA-256 is quarantined from V112 development')


def verify_dev(path: Path, expected_name: str, expected_sha: str) -> str:
    assert_not_consumed_external(path)
    if path.name != expected_name:
        raise V112ContractError(f'Unexpected development capture: {path.name}')
    observed = file_hash(path)
    if observed != expected_sha:
        raise V112ContractError(f'Development capture hash mismatch for {path.name}: {observed}')
    return observed


def packet_service_graphs_tolerant_ps(path: Path, packet_limit: int):
    times, xs, adjs, masks = [], [], [], []
    current = None
    conns = defaultdict(list)
    decoded = 0
    audit = {}

    def flush():
        nonlocal conns
        if current is None:
            return
        flows = [_connection_flow(rows) for rows in conns.values()]
        x, adj, mask, _ = graph_snapshot(flows, mode='service', max_nodes=MAX_NODES)
        times.append(int(current)); xs.append(x.astype(np.float32, copy=False))
        adjs.append(adj.astype(np.float32, copy=False)); masks.append(mask.astype(np.float32, copy=False))
        conns = defaultdict(list)

    iterator = packets(
        path,
        max_packets=max(packet_limit * 2, packet_limit + 1),
        allow_truncated=True,
        audit=audit,
    )
    for pkt in islice(iterator, packet_limit):
        decoded += 1
        bucket = int(pkt['t'] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current is None:
            current = bucket
        elif bucket != current:
            if bucket < current:
                raise V112ContractError(f'Non-monotone packet timestamp in {path}')
            flush(); current = bucket
        endpoints = sorted([(pkt['src'], pkt['sport']), (pkt['dst'], pkt['dport'])])
        conns[(endpoints[0], endpoints[1], pkt['protocol'])].append(pkt)
    flush()
    if decoded < 1000:
        raise V112ContractError(f'Too few decoded IPv4 packets: {decoded}')
    if len(times) < HISTORY + HORIZON + 20:
        raise V112ContractError(f'Too few observed 10-second graph windows: {len(times)}')
    return (
        np.asarray(times, dtype=np.int64), np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32), np.asarray(masks, dtype=np.float32),
        int(decoded), {k: int(v) for k, v in sorted(audit.items())},
    )


def evaluate_state(model, arrays):
    x, adj, mask, target = arrays
    pred = infer_state(model, x, adj, mask)
    persist = persistence_prediction(x, mask)
    mm = mse(pred, target); pm = mse(persist, target)
    return {
        'model_mse': mm,
        'persistence_mse': pm,
        'improvement_vs_persistence': float((pm - mm) / pm) if pm else 0.0,
        'beats_persistence': bool(mm < pm),
    }


def metric_matches(observed: dict, expected_model: float, expected_persist: float) -> bool:
    return bool(
        np.isclose(observed['model_mse'], expected_model, rtol=1e-6, atol=1e-10)
        and np.isclose(observed['persistence_mse'], expected_persist, rtol=1e-6, atol=1e-10)
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1', required=True, type=Path)
    p.add_argument('--phase2', required=True, type=Path)
    p.add_argument('--model', required=True, type=Path)
    p.add_argument('--support-gate', required=True, type=Path)
    p.add_argument('--v108-summary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--packet-limit', type=int, default=2_000_000)
    args = p.parse_args()

    if args.output.exists():
        p.error('V112 evidence already exists; do not silently overwrite')
    if args.packet_limit < 100_000:
        p.error('packet-limit must be at least 100000')

    phase1_sha = verify_dev(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_dev(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    if file_hash(args.model) != V108_MODEL_SHA256:
        raise V112ContractError('Frozen V108 model SHA-256 mismatch')
    if file_hash(args.support_gate) != V108_SUPPORT_SHA256:
        raise V112ContractError('Frozen V108 support gate SHA-256 mismatch')

    model, meta = GraphWorldModel.load(args.model)
    if model.schema != SCHEMA or model.f != len(FEATURES) or len(FEATURES) != 34:
        raise V112ContractError('Frozen V108 PS-complete model schema mismatch')
    if not bool(meta.get('packet_features_trained')) or not bool(meta.get('ps_complete_features_trained')):
        raise V112ContractError('Frozen V108 model lacks PS-complete packet training provenance')

    t1, x1, a1, m1, n1, audit1 = packet_service_graphs_tolerant_ps(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2, audit2 = packet_service_graphs_tolerant_ps(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1, _ = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2, _ = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))
    valid = (sx1[valid_ids], sa1[valid_ids], sm1[valid_ids], sy1[valid_ids])
    phase2 = (sx2, sa2, sm2, sy2)

    validation = evaluate_state(model, valid)
    phase2_metrics = evaluate_state(model, phase2)
    v108 = json.loads(args.v108_summary.read_text())
    ref = v108['selected_candidate']
    equivalence = {
        'phase1_validation': metric_matches(validation, ref['validation_mse'], ref['validation_persistence_mse']),
        'phase2_sanity': metric_matches(phase2_metrics, ref['phase2_mse'], ref['phase2_persistence_mse']),
    }

    gate = json.loads(args.support_gate.read_text())
    phase2_scores = support_score(gate, sx2, sm2)
    supported = phase2_scores <= float(gate['threshold'])
    presence = {
        'phase1_train': packet_presence(sx1[train_ids], sm1[train_ids]),
        'phase1_validation': packet_presence(valid[0], valid[2]),
        'phase2_sanity': packet_presence(sx2, sm2),
    }

    reader_sha = file_hash(Path(__file__).with_name('pcap_reader.py'))
    adapter_policy = {
        'schema_version': 'v112-adapter.1',
        'base_schema': SCHEMA,
        'feature_count': len(FEATURES),
        'strict_default_unchanged': True,
        'future_external_mode': 'allow_truncated=True',
        'linklayer_runt_semantics': 'skip+audit; fabricate no network fields',
        'short_transport_semantics': 'degrade only to trustworthy IP-level telemetry',
        'payload_bytes_fabricated': False,
        'model_sha256': V108_MODEL_SHA256,
        'support_gate_sha256': V108_SUPPORT_SHA256,
        'pcap_reader_sha256': reader_sha,
        'consumed_external_quarantine': [
            'HIKARI-2021/V99', 'MAWI/V102', 'CTU-IDSEVAL-6/V104',
            'USTC-TFC2016-Miuref/V106', 'CTU-Malware-Capture-Botnet-327-1/V111'
        ],
    }
    adapter_sha = canonical_sha256(adapter_policy)

    passed = bool(
        validation['beats_persistence'] and phase2_metrics['beats_persistence']
        and all(equivalence.values()) and min(presence.values()) > 0.95
        and float(supported.mean()) > 0.95
    )
    report = {
        'schema_version': 'v112.1',
        'status': 'DEV_TOLERANT_PS_COMPLETE_PASS' if passed else 'DEV_TOLERANT_PS_COMPLETE_FAIL',
        'recovery_gate_passed': passed,
        'claim_boundary': 'Development-only tolerant adapter recovery for the frozen V108 34-feature model. V111 and all earlier external holdouts are quarantined and unused. No fresh external claim is created.',
        'frozen_runtime': {
            'model_sha256': V108_MODEL_SHA256,
            'support_gate_sha256': V108_SUPPORT_SHA256,
            'model_changed': False,
            'support_gate_changed': False,
            'schema': SCHEMA,
            'feature_count': len(FEATURES),
        },
        'adapter': {
            'policy': adapter_policy,
            'adapter_contract_sha256': adapter_sha,
            'selected_without_consumed_external_fitting': True,
        },
        'development_sources': {
            'dataset': 'CICAPT-IIoT2024',
            'phase1': {'capture': PHASE1_NAME, 'sha256': phase1_sha, 'decoded_packets': n1, 'parser_audit': audit1},
            'phase2': {'capture': PHASE2_NAME, 'sha256': phase2_sha, 'decoded_packets': n2, 'parser_audit': audit2, 'used_for_selection': False},
            'consumed_external_packets_used': False,
        },
        'packet_features_present_mean': presence,
        'state_forecasting': {
            'phase1_validation': validation,
            'phase2_sanity': phase2_metrics,
            'matches_v108_frozen_reference': equivalence,
        },
        'runtime_support': {
            'threshold': float(gate['threshold']),
            'phase2_supported_sequences': int(supported.sum()),
            'phase2_total_sequences': int(len(supported)),
            'phase2_supported_fraction': float(supported.mean()),
            'support_gate_refit': False,
        },
        'freeze': {
            'adapter_contract_sha256': adapter_sha,
            'pcap_reader_sha256': reader_sha,
            'candidate_model_sha256': V108_MODEL_SHA256,
            'support_gate_sha256': V108_SUPPORT_SHA256,
            'new_external_holdout_selected': False,
        },
        'quarantine': {
            'v111_used_for_fitting': False,
            'v111_rerun_allowed': False,
            'future_external_must_be_different_capture': True,
        },
        'next_gate': 'After V112 is frozen and merged, select a genuinely different untouched external capture and evaluate exactly once without retuning.'
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if passed else 2

if __name__ == '__main__':
    raise SystemExit(main())
