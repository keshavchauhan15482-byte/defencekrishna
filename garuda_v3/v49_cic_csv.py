"""Timestamp-preserving CSV adapter and executor for the frozen V49 campaign gate.

The cleaned parquet mirror deliberately removes Timestamp. This adapter uses the
original CICFlowMeter CSVs and reads only a fixed network-feature contract.
No row-order-as-time fallback exists.

The feature contract is frozen from development campaigns only. Final DDoS
positives and final clean negatives come from separate evaluation-only campaign
files so final data cannot influence feature selection or fitting.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v49_cic_unseen_campaign import (
    HISTORY,
    HORIZON,
    WINDOW_SECONDS,
    SEEDS,
    POLICY_FPR_RESERVE,
    RELEASE_FPR,
    RELEASE_RECALL,
    MIN_CLEAN_ONSET,
    RISK_WEIGHT,
    WORLD_WEIGHT,
    train_world,
    risk_lstm,
    logistic,
    robust_ref,
    anomaly,
    percentile,
    threshold,
    metric,
)

ALIASES = {
    'dst_port': ('dst port', 'destination port'),
    'protocol': ('protocol',),
    'flow_duration': ('flow duration',),
    'tot_fwd_pkts': ('total fwd packets', 'tot fwd pkts'),
    'tot_bwd_pkts': ('total backward packets', 'tot bwd pkts'),
    'totlen_fwd': ('fwd packets length total', 'total length of fwd packets', 'totlen fwd pkts'),
    'totlen_bwd': ('bwd packets length total', 'total length of bwd packets', 'totlen bwd pkts'),
    'fwd_len_max': ('fwd packet length max', 'fwd pkt len max'),
    'fwd_len_mean': ('fwd packet length mean', 'fwd pkt len mean'),
    'bwd_len_max': ('bwd packet length max', 'bwd pkt len max'),
    'bwd_len_mean': ('bwd packet length mean', 'bwd pkt len mean'),
    'flow_iat_mean': ('flow iat mean',),
    'flow_iat_std': ('flow iat std',),
    'flow_iat_max': ('flow iat max',),
    'fwd_iat_mean': ('fwd iat mean',),
    'bwd_iat_mean': ('bwd iat mean',),
    'fwd_header': ('fwd header length',),
    'bwd_header': ('bwd header length',),
    'fwd_pps': ('fwd packets/s',),
    'bwd_pps': ('bwd packets/s',),
    'pkt_len_mean': ('packet length mean', 'pkt len mean'),
    'pkt_len_std': ('packet length std', 'pkt len std'),
    'fin': ('fin flag count', 'fin flag cnt'),
    'syn': ('syn flag count', 'syn flag cnt'),
    'rst': ('rst flag count', 'rst flag cnt'),
    'psh': ('psh flag count', 'psh flag cnt'),
    'ack': ('ack flag count', 'ack flag cnt'),
    'urg': ('urg flag count', 'urg flag cnt'),
    'init_fwd_win': ('init fwd win bytes', 'init fwd win byts', 'init_win_bytes_forward'),
    'init_bwd_win': ('init bwd win bytes', 'init bwd win byts', 'init_win_bytes_backward'),
    'fwd_seg_avg': ('fwd seg size avg', 'avg fwd segment size'),
    'bwd_seg_avg': ('bwd seg size avg', 'avg bwd segment size'),
    'active_mean': ('active mean',),
    'idle_mean': ('idle mean',),
}


def norm(value):
    return ' '.join(str(value).strip().lower().replace('_', ' ').split())


def find(columns, names):
    mapping = {norm(c): c for c in columns}
    for name in names:
        if norm(name) in mapping:
            return mapping[norm(name)]
    return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def sample_schema(path):
    """Discover usable features from development data only."""
    df = pd.read_csv(path, nrows=20000, low_memory=False)
    timestamp = find(df.columns, ('timestamp',))
    label = find(df.columns, ('label',))
    if not timestamp or not label:
        raise ValueError(
            f'Original CSV missing Timestamp/Label: {Path(path).name}; first={list(df.columns)[:12]}'
        )
    features = {}
    for name, aliases in ALIASES.items():
        column = find(df.columns, aliases)
        if column:
            numeric = pd.to_numeric(df[column], errors='coerce').replace([np.inf, -np.inf], np.nan)
            if float(numeric.notna().mean()) >= 0.75 and int(numeric.nunique(dropna=True)) > 1:
                features[name] = column
    if len(features) < 20:
        raise ValueError(f'Only {len(features)} fixed flow features in {path}: {features}')
    return {'timestamp': timestamp, 'label': label, 'features': features}


def common_schema(paths):
    """Freeze a common feature contract using development campaigns only."""
    schemas = [sample_schema(path) for path in paths]
    common = set(schemas[0]['features'])
    for schema in schemas[1:]:
        common &= set(schema['features'])
    fixed = [name for name in ALIASES if name in common]
    if len(fixed) < 20:
        raise ValueError(f'Common flow feature contract too small: {fixed}')
    return fixed, schemas


def evaluation_schema(path, fixed):
    """Map a frozen development feature contract onto an evaluation-only file.

    Final data may validate column availability, but it cannot add/drop/re-rank
    the development-selected feature contract.
    """
    header = pd.read_csv(path, nrows=0)
    timestamp = find(header.columns, ('timestamp',))
    label = find(header.columns, ('label',))
    if not timestamp or not label:
        raise ValueError(f'Evaluation CSV missing Timestamp/Label: {Path(path).name}')
    features = {}
    for name in fixed:
        column = find(header.columns, ALIASES[name])
        if column is None:
            raise ValueError(f'Evaluation CSV {Path(path).name} missing frozen feature {name}')
        features[name] = column
    return {'timestamp': timestamp, 'label': label, 'features': features}


def parse_time(series):
    dt = pd.to_datetime(
        series.astype(str), errors='coerce', dayfirst=True, utc=True, format='mixed'
    )
    if float(dt.notna().mean()) < 0.95:
        raise ValueError('Timestamp parse below 95%; no row-order fallback')
    return dt


def load_campaign(path, schema, fixed, role):
    usecols = [schema['timestamp'], schema['label']] + [schema['features'][name] for name in fixed]
    df = pd.read_csv(path, usecols=usecols, low_memory=False)
    dt = parse_time(df[schema['timestamp']])
    labels = df[schema['label']].astype(str).str.strip()
    attack = (labels.str.lower() != 'benign').astype(np.int8)
    base = pd.DataFrame({'dt': dt, 'attack': attack})
    for name in fixed:
        base[name] = pd.to_numeric(df[schema['features'][name]], errors='coerce').replace(
            [np.inf, -np.inf], np.nan
        )
    del df
    gc.collect()

    base = base.dropna(subset=['dt'])
    base['bucket'] = base['dt'].dt.floor(f'{WINDOW_SECONDS}s')
    grouped = base.groupby('bucket', sort=True)
    state = grouped[fixed].agg(['mean', 'std', 'max'])
    state.columns = ['__'.join(parts) for parts in state.columns]
    state['flow_count'] = grouped.size().astype(float)
    state['attack_now'] = grouped['attack'].max().astype(np.int8)
    state = state.reset_index().sort_values('bucket').reset_index(drop=True)

    state_cols = [c for c in state if c not in ('bucket', 'attack_now')]
    z = state[state_cols].to_numpy(np.float32)
    attack_state = state['attack_now'].to_numpy(np.int8)
    times = state['bucket'].astype('int64').to_numpy() // 10**9

    X, future, y, clean, cutoff, first = [], [], [], [], [], []
    for i in range(HISTORY - 1, len(state) - HORIZON):
        lo = i - HISTORY + 1
        stop = i + HORIZON + 1
        span = times[lo:stop]
        if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == WINDOW_SECONDS):
            continue
        future_attack = attack_state[i + 1:stop]
        hits = np.where(future_attack == 1)[0]
        X.append(z[lo:i + 1])
        future.append(z[i + 1:stop])
        y.append(int(future_attack.max()))
        clean.append(bool(attack_state[lo:i + 1].max() == 0))
        cutoff.append(int(times[i]))
        first.append(int(hits[0] + 1) if len(hits) else -1)
    if not X:
        raise ValueError(f'No contiguous sequences for {role}')
    return {
        'role': role,
        'X': np.stack(X),
        'future': np.stack(future),
        'y': np.asarray(y, np.int8),
        'clean': np.asarray(clean, bool),
        'cutoff': np.asarray(cutoff, np.int64),
        'first': np.asarray(first, np.int8),
        'state_cols': state_cols,
        'state_rows': len(state),
        'sequence_rows': len(X),
        'attack_windows': int(attack_state.sum()),
        'benign_windows': int((attack_state == 0).sum()),
    }


def combine(campaigns):
    columns = campaigns[0]['state_cols']
    if any(campaign['state_cols'] != columns for campaign in campaigns):
        raise ValueError('State schema drift')
    out = {
        key: np.concatenate([campaign[key] for campaign in campaigns], axis=0)
        for key in ('X', 'future', 'y', 'clean', 'cutoff', 'first')
    }
    roles = []
    for campaign in campaigns:
        roles.extend([campaign['role']] * len(campaign['y']))
    out['role'] = np.asarray(roles, dtype=object)
    return out


def average(rows, section, key):
    values = [row[section].get(key) for row in rows if row[section].get(key) is not None]
    return {
        'mean': float(np.mean(values)) if values else None,
        'sd': float(np.std(values, ddof=1)) if len(values) > 1 else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--train', nargs='+', required=True)
    parser.add_argument('--calibration', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--final-positive', required=True)
    parser.add_argument('--final-negative', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--epochs', type=int, default=15)
    parser.add_argument('--seeds', nargs='+', type=int, default=list(SEEDS))
    args = parser.parse_args()
    if len(set(args.seeds)) < 3:
        parser.error('At least 3 seeds required')

    out = Path(args.output)
    if out.exists():
        parser.error('Output exists; evidence immutable')
    out.mkdir(parents=True)

    train_paths = [Path(value) for value in args.train]
    calibration_path = Path(args.calibration)
    policy_path = Path(args.policy)
    final_positive_path = Path(args.final_positive)
    final_negative_path = Path(args.final_negative)

    # Freeze schema from development campaigns only. Evaluation data can only
    # demonstrate that the frozen columns exist.
    development_paths = train_paths + [calibration_path, policy_path]
    fixed, development_schemas = common_schema(development_paths)
    final_positive_schema = evaluation_schema(final_positive_path, fixed)
    final_negative_schema = evaluation_schema(final_negative_path, fixed)

    paths = development_paths + [final_positive_path, final_negative_path]
    schemas = development_schemas + [final_positive_schema, final_negative_schema]
    roles = (
        [f'train_{i}' for i in range(len(train_paths))]
        + ['calibration', 'policy', 'final_positive', 'final_negative']
    )

    campaigns = []
    for path, schema, role in zip(paths, schemas, roles):
        print(f'Preparing {role}: {path.name}', flush=True)
        campaigns.append(load_campaign(path, schema, fixed, role))
        gc.collect()

    data = combine(campaigns)
    train_idx = np.where(np.char.startswith(data['role'].astype(str), 'train_'))[0]
    calibration_idx = np.where(data['role'] == 'calibration')[0]
    policy_idx = np.where(data['role'] == 'policy')[0]
    final_positive_idx = np.where(data['role'] == 'final_positive')[0]
    final_negative_idx = np.where(data['role'] == 'final_negative')[0]

    # DDoS positives come only from the frozen final-positive day. FPR comes
    # from clean benign sequences on a separate fresh evaluation-only day.
    positives = final_positive_idx[data['y'][final_positive_idx] == 1]
    negatives = final_negative_idx[
        data['clean'][final_negative_idx] & (data['y'][final_negative_idx] == 0)
    ]
    clean_positives = positives[data['clean'][positives]]
    test_idx = np.concatenate([positives, negatives])
    test_y = np.concatenate([
        np.ones(len(positives), np.int8), np.zeros(len(negatives), np.int8)
    ])

    if min(
        len(train_idx), len(calibration_idx), len(policy_idx), len(positives), len(negatives)
    ) < 20:
        raise ValueError(
            'Support low '
            f'train={len(train_idx)} cal={len(calibration_idx)} policy={len(policy_idx)} '
            f'pos={len(positives)} neg={len(negatives)}'
        )

    report = {
        'protocol': 'V49 fresh CSE-CIC-IDS2018 DDoS campaign gate',
        'claim_boundary': (
            'DDoS positive day/family and clean-negative evaluation day are excluded from all fitting. '
            'Controlled unseen-family/day forecast, not real undisclosed zero-day or verified compromise lead time.'
        ),
        'window_seconds': WINDOW_SECONDS,
        'history_seconds': HISTORY * WINDOW_SECONDS,
        'horizon_seconds': HORIZON * WINDOW_SECONDS,
        'roles': {
            'train': [str(path) for path in train_paths],
            'calibration': str(calibration_path),
            'policy': str(policy_path),
            'final_positive': str(final_positive_path),
            'final_negative': str(final_negative_path),
        },
        'source': {
            str(path): {'bytes': path.stat().st_size, 'sha256': sha256(path)} for path in paths
        },
        'feature_selection_scope': 'train+calibration+policy only; final files only checked for frozen-column availability',
        'common_raw_features': fixed,
        'campaigns': [
            {
                key: campaign[key]
                for key in ('role', 'state_rows', 'sequence_rows', 'attack_windows', 'benign_windows')
            }
            for campaign in campaigns
        ],
        'support': {
            'train': len(train_idx),
            'calibration': len(calibration_idx),
            'policy': len(policy_idx),
            'final_positive': len(positives),
            'final_clean_negative': len(negatives),
            'clean_history_future_positive': len(clean_positives),
        },
        'frozen_fusion': {
            'risk_weight': RISK_WEIGHT,
            'world_weight': WORLD_WEIGHT,
            'policy_fpr_reserve': POLICY_FPR_RESERVE,
        },
        'seeds': args.seeds,
        'results': {},
        'automatic_containment_approved': False,
    }

    for seed in args.seeds:
        print(f'Training seed {seed}', flush=True)
        world = train_world(
            data['X'], data['future'], train_idx, calibration_idx, seed, args.epochs
        )
        risk = risk_lstm(
            data['X'], data['y'], train_idx, calibration_idx, seed, args.epochs
        )
        lr = logistic(data['X'], data['y'], train_idx, calibration_idx, seed)
        if risk is None:
            raise ValueError('Calibration has insufficient classes')

        calibration_benign = calibration_idx[
            data['clean'][calibration_idx] & (data['y'][calibration_idx] == 0)
        ]
        policy_benign = policy_idx[
            data['clean'][policy_idx] & (data['y'][policy_idx] == 0)
        ]
        if len(calibration_benign) < 40 or len(policy_benign) < 100:
            raise ValueError(
                f'Benign support calibration={len(calibration_benign)} policy={len(policy_benign)}'
            )

        center, scale = robust_ref(world['pred'][calibration_benign])
        world_raw = anomaly(world['pred'], center, scale)
        world_percentile = percentile(world_raw, world_raw[calibration_benign])
        risk_percentile = percentile(risk, risk[calibration_benign])
        logistic_percentile = percentile(lr, lr[calibration_benign])
        hybrid = RISK_WEIGHT * risk_percentile + WORLD_WEIGHT * world_percentile

        hybrid_threshold = threshold(hybrid[policy_benign])
        risk_threshold = threshold(risk_percentile[policy_benign])
        world_threshold = threshold(world_percentile[policy_benign])
        logistic_threshold = threshold(logistic_percentile[policy_benign])

        row = {
            'state': {
                'validation_mse': world['validation_mse'],
                'validation_persistence_mse': world['validation_persistence_mse'],
                'state_gate_passed': world['state_gate_passed'],
                'test_mse': float(
                    np.mean((world['pred'][test_idx] - world['future'][test_idx]) ** 2)
                ),
                'test_persistence_mse': float(
                    np.mean(
                        (world['persistence'][test_idx] - world['future'][test_idx]) ** 2
                    )
                ),
            },
            'hybrid': metric(test_y, hybrid[test_idx], hybrid_threshold),
            'risk_lstm': metric(test_y, risk_percentile[test_idx], risk_threshold),
            'world_novelty': metric(test_y, world_percentile[test_idx], world_threshold),
            'logistic': metric(test_y, logistic_percentile[test_idx], logistic_threshold),
            'thresholds': {
                'hybrid': hybrid_threshold,
                'risk_lstm': risk_threshold,
                'world_novelty': world_threshold,
                'logistic': logistic_threshold,
            },
        }

        clean_idx = np.concatenate([clean_positives, negatives])
        clean_y = np.concatenate([
            np.ones(len(clean_positives), np.int8), np.zeros(len(negatives), np.int8)
        ])
        row['clean_history_hybrid'] = (
            metric(clean_y, hybrid[clean_idx], hybrid_threshold)
            if len(clean_positives)
            else {'positives': 0, 'status': 'no_clean_history_future_positive'}
        )

        horizons = []
        for horizon in range(1, HORIZON + 1):
            horizon_positive = positives[data['first'][positives] == horizon]
            ids = np.concatenate([horizon_positive, negatives])
            labels = np.concatenate([
                np.ones(len(horizon_positive), np.int8), np.zeros(len(negatives), np.int8)
            ])
            horizons.append({
                'lead_seconds': horizon * WINDOW_SECONDS,
                'positive_support': len(horizon_positive),
                'metrics': (
                    metric(labels, hybrid[ids], hybrid_threshold)
                    if len(horizon_positive)
                    else None
                ),
            })
        row['first_attack_horizon'] = horizons
        report['results'][str(seed)] = row

    rows = list(report['results'].values())
    report['release_gate_all_seeds'] = bool(
        all(
            row['state']['state_gate_passed']
            and row['hybrid']['fpr'] <= RELEASE_FPR
            and row['hybrid']['recall'] >= RELEASE_RECALL
            for row in rows
        )
    )
    report['clean_pre_onset_gate_all_seeds'] = bool(
        len(clean_positives) >= MIN_CLEAN_ONSET
        and all(
            row['clean_history_hybrid']['fpr'] <= RELEASE_FPR
            and row['clean_history_hybrid']['recall'] >= RELEASE_RECALL
            for row in rows
        )
    )
    report['summary'] = {
        model + '_' + key: average(rows, model, key)
        for model in ('hybrid', 'risk_lstm', 'world_novelty', 'logistic')
        for key in ('recall', 'fpr')
    }
    report['summary']['clean_history_recall'] = (
        average(rows, 'clean_history_hybrid', 'recall')
        if len(clean_positives)
        else {'mean': None, 'sd': None}
    )

    (out / 'summary.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({
        'support': report['support'],
        'summary': report['summary'],
        'release_gate_all_seeds': report['release_gate_all_seeds'],
        'clean_pre_onset_gate_all_seeds': report['clean_pre_onset_gate_all_seeds'],
    }, indent=2))


if __name__ == '__main__':
    main()
