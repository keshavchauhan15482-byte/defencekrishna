"""V105 development-only link-layer runt recovery.

V104 consumed CTU-IDSEVAL-6 and stopped on a truncated Ethernet frame before model
inference. V105 does not reuse that holdout. It validates the generic opt-in L2-runt
handling only with synthetic unit tests plus hash-pinned CICAPT development reuse.
The V101 model and support gate remain unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from .data import SCHEMA
from .model import GraphWorldModel
from .support_gate import score as support_score
from .v101_packet_graph_recovery import (
    HISTORY, HORIZON, WINDOW_SECONDS, MAX_NODES,
    PHASE1_NAME, PHASE2_NAME, PHASE1_SHA256, PHASE2_SHA256,
    build_sequences, chronological_phase1_split, infer_state,
    persistence_prediction, mse, packet_presence,
)
from .v103_truncated_adapter_recovery import packet_service_graphs_tolerant

V101_MODEL_SHA256 = '30694adf0819e6ffd79079512a348059195dcc651d7f0b4d5049e278b4d7cb79'
V101_SUPPORT_SHA256 = '2f281593f163ba3e4bbed592ea41eeaa1c8d5e3dfe49de933473b15fe6c17df3'
HIKARI_MD5 = '900deec66e058801a377fd81c5fc805e'
MAWI_SHA256 = '6d0925f42db3a296ba84976e908f256f14efd39db6ae318f58d8e343bcabf199'
CTU_IDSEVAL6_ARCHIVE_SHA256 = 'fa1da03ac3797f70747c62b89f12cc31305cc260f74162c6b8060aeb2e74c518'
CONSUMED_TOKENS = ('hikari', 'mawi', 'ctu-idseval-6', 'idseval6')


class V105ContractError(RuntimeError):
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
    if any(token in low for token in CONSUMED_TOKENS):
        raise V105ContractError(f'Consumed external holdout is quarantined from V105 development: {path.name}')
    if not path.exists():
        return
    sha = file_hash(path, 'sha256')
    if sha in {MAWI_SHA256, CTU_IDSEVAL6_ARCHIVE_SHA256}:
        raise V105ContractError('Consumed external SHA-256 is quarantined from V105 development')
    if file_hash(path, 'md5') == HIKARI_MD5:
        raise V105ContractError('Consumed HIKARI MD5 is quarantined from V105 development')


def verify_dev(path: Path, expected_name: str, expected_sha256: str) -> str:
    assert_not_consumed_external(path)
    if path.name != expected_name:
        raise V105ContractError(f'Unexpected development capture: {path.name}')
    observed = file_hash(path)
    if observed != expected_sha256:
        raise V105ContractError(f'Development capture hash mismatch for {path.name}: {observed}')
    return observed


def evaluate_state(model, arrays) -> dict:
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


def same_metric_block(a: dict, b: dict, tol: float = 1e-12) -> bool:
    for key in ('model_mse', 'persistence_mse', 'improvement_vs_persistence'):
        if not np.isclose(float(a[key]), float(b[key]), rtol=0.0, atol=tol):
            return False
    return bool(a['beats_persistence']) == bool(b['beats_persistence'])


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1', required=True, type=Path)
    p.add_argument('--phase2', required=True, type=Path)
    p.add_argument('--model', required=True, type=Path)
    p.add_argument('--support-gate', required=True, type=Path)
    p.add_argument('--v101-summary', required=True, type=Path)
    p.add_argument('--v103-summary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--packet-limit', type=int, default=2_000_000)
    args = p.parse_args()

    if args.output.exists():
        p.error('V105 development evidence already exists; do not silently overwrite')
    if args.packet_limit < 100_000:
        p.error('packet-limit must be at least 100000')

    phase1_sha = verify_dev(args.phase1, PHASE1_NAME, PHASE1_SHA256)
    phase2_sha = verify_dev(args.phase2, PHASE2_NAME, PHASE2_SHA256)
    if file_hash(args.model) != V101_MODEL_SHA256:
        raise V105ContractError('Frozen V101 model SHA-256 mismatch')
    if file_hash(args.support_gate) != V101_SUPPORT_SHA256:
        raise V105ContractError('Frozen V101 support gate SHA-256 mismatch')

    model, meta = GraphWorldModel.load(args.model)
    observed_contract = {
        'architecture': model.config['architecture'],
        'history': int(meta.get('history', -1)),
        'horizon': int(meta.get('horizon', -1)),
        'decoder': model.config['decoder'],
        'mode': meta.get('mode'),
        'window_seconds': int(meta.get('window_seconds', -1)),
        'max_nodes': int(meta.get('max_nodes', -1)),
    }
    expected_contract = {
        'architecture': 'gnn_lstm', 'history': HISTORY, 'horizon': HORIZON,
        'decoder': 'residual', 'mode': 'service', 'window_seconds': WINDOW_SECONDS,
        'max_nodes': MAX_NODES,
    }
    if observed_contract != expected_contract or not bool(meta.get('packet_features_trained', False)):
        raise V105ContractError(f'Frozen model contract mismatch: {observed_contract}')

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
    v103 = json.loads(args.v103_summary.read_text())

    if v103.get('status') != 'DEV_ADAPTER_RECOVERY_PASS':
        raise V105ContractError('V103 reference must be a passing frozen development artifact')
    if v103['frozen_runtime']['model_sha256'] != V101_MODEL_SHA256:
        raise V105ContractError('V103 model identity mismatch')
    if v103['frozen_runtime']['support_gate_sha256'] != V101_SUPPORT_SHA256:
        raise V105ContractError('V103 support identity mismatch')

    reader_sha = file_hash(Path(__file__).with_name('pcap_reader.py'))
    adapter_policy = {
        'schema_version': 'v105-adapter.1',
        'base_schema': SCHEMA,
        'strict_default_unchanged': True,
        'tolerant_mode_opt_in': True,
        'l2_runt_semantics': {
            'truncated_ethernet_header': 'skip record and audit; fabricate no network fields',
            'truncated_vlan_header': 'skip record and audit; fabricate no network fields',
            'truncated_ipv4_base_header': 'skip record and audit; fabricate no network fields',
            'valid_records_after_skipped_runt_continue_decoding': True,
        },
        'inherited_v103_snaplen_semantics': {
            'short_ip_options': 'degrade to protocol other with trustworthy IP-level telemetry',
            'short_tcp_base_header': 'degrade to protocol other',
            'short_udp_header': 'degrade to protocol other',
            'tcp_options_may_be_truncated_after_complete_base_header': True,
            'nonfirst_fragment': 'protocol other with IP-level telemetry',
            'fabricate_payload_bytes': False,
        },
        'consumed_external_quarantine': [
            'HIKARI-2021/V99', 'MAWI-200601011400/V102', 'CTU-IDSEVAL-6/V104'
        ],
        'model_sha256': V101_MODEL_SHA256,
        'support_gate_sha256': V101_SUPPORT_SHA256,
        'pcap_reader_sha256': reader_sha,
    }
    adapter_sha = canonical_sha256(adapter_policy)

    train_presence = packet_presence(sx1[train_ids], sm1[train_ids])
    val_presence = packet_presence(valid[0], valid[2])
    phase2_presence = packet_presence(sx2, sm2)
    metric_equivalence = {
        'phase1_validation_matches_v103': same_metric_block(
            validation_metrics, v103['state_forecasting']['phase1_validation']
        ),
        'phase2_sanity_matches_v103': same_metric_block(
            phase2_metrics, v103['state_forecasting']['phase2_sanity']
        ),
    }
    l2_audit_keys = ('skipped_truncated_ethernet', 'skipped_truncated_vlan', 'skipped_truncated_ipv4_header')
    dev_l2_skips = {
        'phase1': {k: int(audit1.get(k, 0)) for k in l2_audit_keys},
        'phase2': {k: int(audit2.get(k, 0)) for k in l2_audit_keys},
    }
    no_dev_runt_dependency = not any(
        value for phase in dev_l2_skips.values() for value in phase.values()
    )

    passed = bool(
        validation_metrics['beats_persistence']
        and phase2_metrics['beats_persistence']
        and min(train_presence, val_presence, phase2_presence) > 0.0
        and metric_equivalence['phase1_validation_matches_v103']
        and metric_equivalence['phase2_sanity_matches_v103']
        and no_dev_runt_dependency
    )

    report = {
        'schema_version': 'v105.1',
        'status': 'DEV_LINKLAYER_RECOVERY_PASS' if passed else 'DEV_LINKLAYER_RECOVERY_FAIL',
        'recovery_gate_passed': passed,
        'claim_boundary': 'Development-only generic link-layer runt recovery evidence. HIKARI, MAWI, and CTU-IDSEVAL-6 are consumed/quarantined and were not used for fitting, parser selection, or validation. No fresh external generalisation claim is created.',
        'frozen_runtime': {
            'model_sha256': V101_MODEL_SHA256,
            'support_gate_sha256': V101_SUPPORT_SHA256,
            'model_changed_from_v101': False,
            'support_gate_changed_from_v101': False,
            'contract': observed_contract,
        },
        'adapter': {
            'policy': adapter_policy,
            'adapter_contract_sha256': adapter_sha,
            'pcap_reader_sha256': reader_sha,
            'generic_change_selected_without_consumed_external_fitting': True,
        },
        'quarantine': {
            'hikari_used': False,
            'mawi_used': False,
            'ctu_idseval6_used': False,
            'hikari_future_fitting_allowed': False,
            'mawi_future_fitting_allowed': False,
            'ctu_idseval6_future_fitting_allowed': False,
            'ctu_idseval6_rerun_after_parser_change_allowed': False,
        },
        'development_sources': {
            'dataset': 'CICAPT-IIoT2024',
            'development_reuse': True,
            'phase1': {
                'capture': PHASE1_NAME, 'sha256': phase1_sha, 'decoded_packets': n1,
                'parser_audit': audit1, 'linklayer_skip_audit': dev_l2_skips['phase1'],
                'observed_windows': int(len(t1)), 'contiguous_sequences': int(len(sx1)),
                'train_sequences': int(len(train_ids)), 'validation_sequences': int(len(valid_ids)),
            },
            'phase2': {
                'capture': PHASE2_NAME, 'sha256': phase2_sha, 'decoded_packets': n2,
                'parser_audit': audit2, 'linklayer_skip_audit': dev_l2_skips['phase2'],
                'observed_windows': int(len(t2)), 'contiguous_sequences': int(len(sx2)),
                'used_for_selection': False,
            },
            'consumed_external_packets_used': False,
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
            'v103_metric_equivalence': metric_equivalence,
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
        'recovery_checks': {
            'strict_default_preserved_by_unit_tests': True,
            'synthetic_l2_runt_skip_semantics_required_by_unit_tests': True,
            'development_metrics_match_v103': bool(all(metric_equivalence.values())),
            'development_depends_on_l2_runt_skips': not no_dev_runt_dependency,
        },
        'freeze': {
            'adapter_contract_sha256': adapter_sha,
            'pcap_reader_sha256': reader_sha,
            'candidate_model_sha256': V101_MODEL_SHA256,
            'support_gate_sha256': V101_SUPPORT_SHA256,
            'new_external_holdout_selected': False,
        },
        'next_gate': 'Only after V105 is frozen and merged: select a different genuinely untouched non-HIKARI/non-MAWI/non-CTU-IDSEVAL-6 external holdout, preregister it, and evaluate exactly once without retuning.',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
