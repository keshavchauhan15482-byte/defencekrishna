"""V104 frozen one-shot CTU-IDSEVAL-6 state-transition evaluation.

All six registered real PCAP payload members must be accounted for and evaluable. No
labels, Zeek logs, or capture selection are used. The unchanged V101 model/support
gate and frozen V103 tolerant packet adapter are evaluated against persistence over
all publisher captures, with the primary MSE aggregated by predicted state elements.

The six-member count was refrozen before packet extraction/decoding after ZIP
central-directory metadata established that the other six .pcap-suffixed names were
__MACOSX AppleDouble packaging sidecars rather than capture payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
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
    build_sequences, infer_state, persistence_prediction,
)

MODEL_SHA256 = '30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79'
SUPPORT_SHA256 = '2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3'
ADAPTER_SHA256 = '65052c50704ad371ff7ad84fec6b74c7530d546a7916722c96a255b9b7c93841'
PCAP_READER_SHA256 = '91c978b54c5ca32fb9e30cde75e8abe7e7c9fc24655f49ea40291762feddab71'
EXPECTED_MEMBERS = 6
MAX_PACKETS_PER_MEMBER = 2_000_000


class V104ContractError(RuntimeError):
    pass


def file_hash(path: Path, algorithm: str = 'sha256') -> str:
    h = hashlib.new(algorithm)
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _flow(rows: List[dict]) -> dict:
    flow = _connection_flow(rows)
    flow['retransmission_fraction'] = float(flow.get('retransmission_count', 0.0)) / max(
        float(flow.get('packets', 0.0)), 1.0
    )
    return flow


def packet_service_graphs(path: Path):
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
        path, max_packets=MAX_PACKETS_PER_MEMBER,
        allow_truncated=True, audit=audit,
    )
    for pkt in iterator:
        decoded += 1
        bucket = int(pkt['t'] // WINDOW_SECONDS) * WINDOW_SECONDS
        if current is None:
            current = bucket
        elif bucket != current:
            if bucket < current:
                raise V104ContractError(f'Non-monotone timestamp in {path.name}')
            flush()
            current = bucket
        endpoints = sorted([(pkt['src'], pkt['sport']), (pkt['dst'], pkt['dport'])])
        conns[(endpoints[0], endpoints[1], pkt['protocol'])].append(pkt)
    flush()
    if decoded < 1:
        raise V104ContractError(f'No IPv4 packets decoded from registered member {path.name}')
    if len(times) < HISTORY + HORIZON:
        raise V104ContractError(f'Registered member has too few observed graph windows: {path.name} windows={len(times)}')
    return (
        np.asarray(times, dtype=np.int64), np.asarray(xs, dtype=np.float32),
        np.asarray(adjs, dtype=np.float32), np.asarray(masks, dtype=np.float32),
        int(decoded), {k: int(v) for k, v in sorted(audit.items())},
    )


def evaluate_member(path: Path, model: GraphWorldModel, gate: dict) -> tuple[dict, float, float, int]:
    times, x, adj, mask, decoded, audit = packet_service_graphs(path)
    try:
        sx, sa, sm, target, cutoffs = build_sequences(times, x, adj, mask)
    except Exception as exc:
        raise V104ContractError(f'Registered member has no valid contiguous sequence: {path.name}: {exc}') from exc
    pred = infer_state(model, sx, sa, sm)
    persist = persistence_prediction(sx, sm)
    model_sse = float(np.sum((pred - target) ** 2, dtype=np.float64))
    persistence_sse = float(np.sum((persist - target) ** 2, dtype=np.float64))
    elements = int(target.size)
    mm = model_sse / elements
    pm = persistence_sse / elements
    scores = support_score(gate, sx, sm)
    threshold = float(gate['threshold'])
    supported = scores <= threshold
    pidx = FEATURES.index('packet_features_present')
    vals = x[:, :, pidx][mask > 0]
    row = {
        'member': path.name,
        'decoded_ipv4_packets': decoded,
        'parser_audit': audit,
        'observed_windows': int(len(times)),
        'contiguous_sequences': int(len(sx)),
        'first_window_epoch': int(times[0]),
        'last_window_epoch': int(times[-1]),
        'model_mse': float(mm),
        'persistence_mse': float(pm),
        'improvement_vs_persistence': float((pm - mm) / pm) if pm else 0.0,
        'beats_persistence': bool(mm < pm),
        'mse_elements': elements,
        'support': {
            'supported_sequences': int(supported.sum()),
            'total_sequences': int(len(supported)),
            'supported_fraction': float(supported.mean()),
            'median_score': float(np.median(scores)),
            'max_score': float(scores.max()),
        },
        'packet_features_present_mean_on_observed_nodes': float(vals.mean()) if len(vals) else 0.0,
        'cutoff_timestamps_sha256': hashlib.sha256(cutoffs.astype(np.int64).tobytes()).hexdigest(),
    }
    return row, model_sse, persistence_sse, elements


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap-dir', required=True, type=Path)
    p.add_argument('--model', required=True, type=Path)
    p.add_argument('--support-gate', required=True, type=Path)
    p.add_argument('--prereg', required=True, type=Path)
    p.add_argument('--acquisition', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error('V104 one-shot result already exists and is immutable')

    prereg = json.loads(args.prereg.read_text())
    acq = json.loads(args.acquisition.read_text())
    if prereg['status'] != 'HASH_FROZEN_ONE_SHOT_REGISTERED' or prereg['evaluation_permitted'] is not True:
        raise V104ContractError('V104 packet evaluation is not hash-frozen/permitted')
    if acq['status'] != 'HASH_AND_ENTRY_METADATA_FROZEN_MODEL_NOT_RUN':
        raise V104ContractError('V104 acquisition manifest not frozen')
    if file_hash(args.model) != MODEL_SHA256 or file_hash(args.support_gate) != SUPPORT_SHA256:
        raise V104ContractError('Frozen model/support hash mismatch')
    if file_hash(Path(__file__).with_name('pcap_reader.py')) != PCAP_READER_SHA256:
        raise V104ContractError('Frozen V103 packet reader hash mismatch')
    reg = prereg['registered_candidate']
    if reg['adapter_contract_sha256'] != ADAPTER_SHA256 or reg['pcap_reader_sha256'] != PCAP_READER_SHA256:
        raise V104ContractError('Frozen adapter identity mismatch')

    frozen_entries = prereg['external_holdout']['pcap_entries']
    if len(frozen_entries) != EXPECTED_MEMBERS or frozen_entries != acq['pcap_entries']:
        raise V104ContractError('Registered PCAP entry manifest mismatch')
    expected_names = [Path(r['filename']).name for r in frozen_entries]
    if len(set(expected_names)) != EXPECTED_MEMBERS:
        raise V104ContractError('Registered archive contains duplicate PCAP basenames')
    actual = sorted(p.name for p in args.pcap_dir.iterdir() if p.is_file())
    if actual != sorted(expected_names):
        raise V104ContractError(f'Extracted member set mismatch: expected={sorted(expected_names)} actual={actual}')

    model, meta = GraphWorldModel.load(args.model)
    contract = {
        'architecture': model.config['architecture'], 'history': int(meta.get('history', -1)),
        'horizon': int(meta.get('horizon', -1)), 'decoder': model.config['decoder'],
        'mode': meta.get('mode'), 'window_seconds': int(meta.get('window_seconds', -1)),
        'max_nodes': int(meta.get('max_nodes', -1)),
    }
    expected_contract = {'architecture':'gnn_lstm','history':8,'horizon':4,'decoder':'residual','mode':'service','window_seconds':10,'max_nodes':32}
    if contract != expected_contract or not bool(meta.get('packet_features_trained', False)):
        raise V104ContractError(f'Frozen model contract mismatch: {contract}')
    gate = json.loads(args.support_gate.read_text())

    members = []
    total_model_sse = 0.0
    total_persistence_sse = 0.0
    total_elements = 0
    for name in expected_names:
        row, msse, psse, elements = evaluate_member(args.pcap_dir / name, model, gate)
        members.append(row)
        total_model_sse += msse
        total_persistence_sse += psse
        total_elements += elements
    if len(members) != EXPECTED_MEMBERS or total_elements <= 0:
        raise V104ContractError('Not all registered real PCAP members produced evidence')

    model_mse = total_model_sse / total_elements
    persistence_mse = total_persistence_sse / total_elements
    improvement = float((persistence_mse - model_mse) / persistence_mse) if persistence_mse else 0.0
    passed = bool(model_mse < persistence_mse)
    supported = sum(r['support']['supported_sequences'] for r in members)
    total_sequences = sum(r['support']['total_sequences'] for r in members)

    result = {
        'schema_version': 'v104.2',
        'status': 'PASS' if passed else 'FAIL',
        'gate': 'element-weighted aggregate frozen-model state MSE across all six registered real PCAP members must be lower than aggregate persistence MSE',
        'dataset': {
            'name': 'CTU-IDSEVAL-6', 'version': 'v1', 'zenodo_record': '21027042',
            'doi': '10.5281/zenodo.21027042',
            'archive_md5': acq['archive_md5'], 'archive_sha256': acq['archive_sha256'],
            'publisher_logical_capture_count': 6, 'registered_pcap_member_count': EXPECTED_MEMBERS,
            'labels_accessed': False,
        },
        'frozen_runtime': {
            'model_sha256': MODEL_SHA256, 'support_gate_sha256': SUPPORT_SHA256,
            'adapter_contract_sha256': ADAPTER_SHA256, 'pcap_reader_sha256': PCAP_READER_SHA256,
            'contract': contract, 'packet_features_trained': True,
        },
        'aggregate_state_forecasting': {
            'model_mse': float(model_mse), 'persistence_mse': float(persistence_mse),
            'improvement_vs_persistence': improvement, 'beats_persistence': passed,
            'mse_elements': int(total_elements),
        },
        'member_accounting': {
            'registered_members': EXPECTED_MEMBERS, 'evaluated_members': len(members),
            'members_dropped': 0, 'members': members,
        },
        'runtime_support': {
            'method': gate.get('method'), 'threshold': float(gate['threshold']),
            'supported_sequences': int(supported), 'total_sequences': int(total_sequences),
            'supported_fraction': float(supported / total_sequences) if total_sequences else 0.0,
            'interpretation': 'training-support diagnostic only; outside support is not attack/OOD detection',
        },
        'one_shot_integrity': {
            'runs_allowed': 1, 'all_registered_real_pcap_members_included': True,
            'retrained_on_external': False, 'normalization_fit_on_external': False,
            'support_fit_on_external': False, 'threshold_fit_on_external': False,
            'adapter_changed_after_external_packet_decode': False,
            'labels_accessed': False, 'rerun_for_claim_improvement': False,
            'packaging_sidecars_excluded_before_packet_decode': True,
        },
        'claim_boundary': 'Fresh external one-shot state-transition forecasting only. No attack recall/FPR, MITRE-stage, or successful-compromise warning claim is made.',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
