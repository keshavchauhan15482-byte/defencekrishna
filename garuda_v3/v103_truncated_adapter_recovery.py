"""V103 development-only truncated-PCAP adapter recovery.

The V101 packet-compatible GraphSAGE+LSTM checkpoint and support gate stay frozen.
V103 changes only the opt-in packet adapter used for future snaplen-limited captures.
Consumed HIKARI (V99) and MAWI (V102) are hard-quarantined from fitting, selection,
and adapter validation. CICAPT Phase-1/Phase-2 are development reuse only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np

from .data import FEATURES, SCHEMA, graph_snapshot
from .model import GraphWorldModel
from .pcap_reader import packets
from .ps_complete import _connection_flow
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    build_sequences, chronological_phase1_split, infer_state,
    persistence_prediction, mse, packet_presence,
)

V101_MODEL_SHA256 = '30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79'
V101_SUPPORT_SHA256 = '2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3'
HIKARI_NAME = 'Monday_2022-04-11_0622_BRUTEFORCE_XML_150s.pcap'
HIKARI_MD5 = '900deec66e058801a377fd81c5fc805e'
MAWI_NAME = '200601011400.dump'
MAWI_SHA256 = '6d0925f42db3a296ba84976e908f256f14efd39db6ae318f58d8e343bcabf199'


class V103ContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = 'sha256') -> str:
    h = hashlib.new(algorithm)
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def canonical_sha256(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def assert_not_consumed_external(path: Path) -> None:
    low = path.name.lower()
    if 'hikari' in low or path.name == HIKARI_NAME or path.name == MAWI_NAME or 'mawi' in low:
        raise V103ContractError('Consumed HIKARI/MAWI holdouts are quarantined from V103 development')
    if not path.exists():
        return
    sha = file_hash(path, 'sha256')
    if sha == MAWI_SHA256:
        raise V103ContractError('Consumed V102 MAWI hash is quarantined from V103 development')
    if file_hash(path, 'md5') == HIKARI_MD5:
        raise V103ContractError('Consumed V99 HIKARI hash is quarantined from V103 development')


def verify_dev(path: Path, name: str, sha256: str) -> str:
    assert_not_consumed_external(path)
    if path.name != name:
        raise V103ContractError(f'Unexpected development capture: {path.name}')
    observed = file_hash(path)
    if observed != sha256:
        raise V103ContractError(f'Development capture hash mismatch for {path.name}: {observed}')
    return observed


def _flow(rows: List[dict]) -> dict:
    flow = _connection_flow(rows)
    flow['retransmission_fraction'] = float(flow.get('retransmission_count', 0.0)) / max(
        float(flow.get('packets', 0.0)), 1.0
    )
    return flow


def packet_service_graphs_tolerant(path: Path, packet_limit: int):
    times, xs, adjs, masks = [], [], [], []
    current = None
    conns: Dict[tuple, List[dict]] = defaultdict(list)
    decoded = 0
    audit: dict = {}

    def flush():
        nonlocal conns
        if current is None:
            return
        flows = [_flow(v) for v in conns.values()]
        x, adj, mask, _ = graph_snapshot(flows, mode='service', max_nodes=MAX_NODES)
        times.append(int(current))
        xs.append(x.astype(np.float32, copy=False))
        adjs.append(adj.astype(np.float32, copy=False))
        masks.append(mask.astype(np.float32, copy=False))
        conns = defaultdict(list)

    iterator: Iterable[dict] = packets(
        path,
        max_packets=max(packet_limit * 2, packet_limit + 1),
        allow_truncated=True,
        audit=audit,
    )
    for packet in islice(iterator, packet_limit):
        decoded += 1
        bucket = int(packet['t'] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current is None:
            current = bucket
        elif bucket != current:
            if bucket < current:
                raise V103ContractError(f'Non-monotone packet timestamp in {path}')
            flush()
            current = bucket
        endpoints = sorted([(packet['src'], packet['sport']), (packet['dst'], packet['dport'])])
        conns[(endpoints[0], endpoints[1], packet['protocol'])].append(packet)
    flush()

    if decoded < 1000:
        raise V103ContractError(f'Too few decoded IPv4 packets: {decoded}')
    if len(times) < HISTORY + HORIZON + 20:
        raise V103ContractError(f'Too few observed graph windows: {len(times)}')
    return (
        np.asarray(times, dtype=np.int64), np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32), np.asarray(masks, dtype=np.float32),
        int(decoded), {k: int(v) for k, v in sorted(audit.items())},
    )


def evaluate_state(model, arrays):
    x, adj, mask, target = arrays
    pred = infer_state(model, x, adj, mask)
    persist = persistence_prediction(x, mask)
    mm = mse(pred, target)
    pm = mse(persist, target)
    return {
        'model_mse': mm,
        'persistence_mse': pm,
        'improvement_vs_persistence': float((pm - mm) / pm) if pm else 0.0,
        'beats_persistence': bool(mm < pm),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1', required=True, type=Path)
    p.add_argument('--phase2', required=True, type=Path)
    p.add_argument('--model', required=True, type=Path)
    p.add_argument('--support-gate', required=True, type=Path)
    p.add_argument('--v101-summary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--packet-limit', type=int, default=2_000_000)
    args = p.parse_args()
    if args.output.exists():
        p.error('V103 development evidence already exists; do not silently overwrite')
    if args.packet_limit < 100_000:
        p.error('packet-limit must be at least 100000')

    phase1_sha = verify_dev(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_dev(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    if file_hash(args.model) != V101_MODEL_SHA256:
        raise V103ContractError('Frozen V101 model SHA-256 mismatch')
    if file_hash(args.support_gate) != V101_SUPPORT_SHA256:
        raise V103ContractError('Frozen V101 support gate SHA-256 mismatch')

    model, meta = GraphWorldModel.load(args.model)
    expected = {
        'architecture': 'gnn_lstm', 'history': HISTORY, 'horizon': HORIZON,
        'decoder': 'residual', 'mode': 'service', 'window_seconds': WINDOW_SECONDS,
        'max_nodes': MAX_NODES,
    }
    observed = {
        'architecture': model.config['architecture'], 'history': int(meta.get('history', -1)),
        'horizon': int(meta.get('horizon', -1)), 'decoder': model.config['decoder'],
        'mode': meta.get('mode'), 'window_seconds': int(meta.get('window_seconds', -1)),
        'max_nodes': int(meta.get('max_nodes', -1)),
    }
    if observed != expected or not bool(meta.get('packet_features_trained', False)):
        raise V103ContractError(f'Frozen model contract mismatch: {observed}')

    t1, x1, a1, m1, n1, audit1 = packet_service_graphs_tolerant(args.phase1, args.packet_limit)
    t2, x2, a2, m2, n2, audit2 = packet_service_graphs_tolerant(args.phase2, args.packet_limit)
    sx1, sa1, sm1, sy1, _ = build_sequences(t1, x1, a1, m1)
    sx2, sa2, sm2, sy2, _ = build_sequences(t2, x2, a2, m2)
    train_ids, valid_ids = chronological_phase1_split(len(sx1))

    valid = (sx1[valid_ids], sa1[valid_ids], sm1[valid_ids], sy1[valid_ids])
    phase2 = (sx2, sa2, sm2, sy2)
    validation_metrics = evaluate_state(model, valid)
    phase2_metrics = evaluate_state(model, phase2)

    gate = json.loads(args.support_gate.read_text())
    phase2_scores = support_score(gate, sx2, sm2)
    supported = phase2_scores <= float(gate['threshold'])
    v101 = json.loads(args.v101_summary.read_text())

    adapter_policy = {
        'schema_version': 'v103-adapter.1',
        'base_schema': SCHEMA,
        'strict_default_unchanged': True,
        'tolerant_mode_opt_in': True,
        'snaplen_semantics': {
            'ip_base_header_required': True,
            'short_ip_options': 'degrade to protocol other with IP-level telemetry',
            'tcp_base_header_required_for_tcp': True,
            'tcp_options_may_be_truncated': True,
            'short_tcp_base_header': 'degrade to protocol other',
            'short_udp_header': 'degrade to protocol other',
            'nonfirst_fragment': 'protocol other with IP-level telemetry',
            'payload_length': 'derive from IPv4 total length and declared transport header length',
            'fabricate_payload_bytes': False,
        },
        'consumed_external_quarantine': ['HIKARI-2021/V99', 'MAWI-200601011400/V102'],
        'model_sha256': V101_MODEL_SHA256,
        'support_gate_sha256': V101_SUPPORT_SHA256,
    }
    reader_sha = file_hash(Path(__file__).with_name('pcap_reader.py'))
    adapter_policy['pcap_reader_sha256'] = reader_sha
    adapter_sha = canonical_sha256(adapter_policy)

    train_presence = packet_presence(sx1[train_ids], sm1[train_ids])
    val_presence = packet_presence(valid[0], valid[2])
    phase2_presence = packet_presence(sx2, sm2)
    passed = bool(
        validation_metrics['beats_persistence'] and
        phase2_metrics['beats_persistence'] and
        min(train_presence, val_presence, phase2_presence) > 0.0
    )

    report = {
        'schema_version': 'v103.1',
        'status': 'DEV_ADAPTER_RECOVERY_PASS' if passed else 'DEV_ADAPTER_RECOVERY_FAIL',
        'recovery_gate_passed': passed,
        'claim_boundary': 'Development-only adapter robustness evidence. HIKARI and MAWI are consumed/quarantined and were not used. No fresh external generalisation claim is created.',
        'frozen_runtime': {
            'model_sha256': V101_MODEL_SHA256,
            'support_gate_sha256': V101_SUPPORT_SHA256,
            'model_changed_from_v101': False,
            'support_gate_changed_from_v101': False,
            'contract': observed,
        },
        'adapter': {
            'policy': adapter_policy,
            'adapter_contract_sha256': adapter_sha,
            'development_selected_without_hikari_or_mawi': True,
        },
        'quarantine': {
            'hikari_used': False,
            'mawi_used': False,
            'hikari_future_fitting_allowed': False,
            'mawi_future_fitting_allowed': False,
            'mawi_rerun_after_adapter_change_allowed': False,
        },
        'development_sources': {
            'dataset': 'CICAPT-IIoT2024',
            'development_reuse': True,
            'phase1': {'capture': PHASE1_NAME, 'sha256': phase1_sha, 'decoded_packets': n1, 'parser_audit': audit1, 'observed_windows': int(len(t1)), 'contiguous_sequences': int(len(sx1)), 'train_sequences': int(len(train_ids)), 'validation_sequences': int(len(valid_ids))},
            'phase2': {'capture': PHASE2_NAME, 'sha256': phase2_sha, 'decoded_packets': n2, 'parser_audit': audit2, 'observed_windows': int(len(t2)), 'contiguous_sequences': int(len(sx2)), 'used_for_selection': False},
        },
        'packet_features_present_mean': {
            'phase1_train': train_presence,
            'phase1_validation': val_presence,
            'phase2_sanity': phase2_presence,
        },
        'state_forecasting': {
            'phase1_validation': validation_metrics,
            'phase2_sanity': phase2_metrics,
            'v101_reference_selected_candidate': v101['selected_candidate'],
        },
        'runtime_support': {
            'threshold': float(gate['threshold']),
            'phase2_supported_sequences': int(supported.sum()),
            'phase2_total_sequences': int(len(supported)),
            'phase2_supported_fraction': float(supported.mean()),
            'phase2_median_score': float(np.median(phase2_scores)),
            'phase2_max_score': float(phase2_scores.max()),
            'support_gate_refit': False,
        },
        'freeze': {
            'adapter_contract_sha256': adapter_sha,
            'pcap_reader_sha256': reader_sha,
            'candidate_model_sha256': V101_MODEL_SHA256,
            'support_gate_sha256': V101_SUPPORT_SHA256,
            'new_external_holdout_selected': False,
        },
        'next_gate': 'Only after V103 is frozen/merged: select and preregister a different genuinely untouched non-HIKARI/non-MAWI external holdout, then evaluate exactly once without retuning.',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
