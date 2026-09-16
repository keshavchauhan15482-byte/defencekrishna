"""V50 WUSTL-IIoT-2021 temporal unseen-family support audit.

This module does not train or score a model.  It answers the prerequisite question
for a defensible pre-onset unseen-family experiment: does the fixed final chronological
tail naturally contain attack-family onsets after a completely clean observed history?

StartTime is used only for ordering/split construction.  Publisher-identified leakage
columns and all labels/identifiers are never model features (no model is trained here).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

HISTORY = 8
HORIZON = 4
EMBARGO_MINUTES = HISTORY + HORIZON


def norm(value):
    return ''.join(ch.lower() for ch in str(value) if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def pick_col(columns, names):
    mapping = {norm(c): c for c in columns}
    for name in names:
        if norm(name) in mapping:
            return mapping[norm(name)]
    return None


def resolve_schema(df):
    start = pick_col(df.columns, ['StartTime', 'Start Time', 'start_time'])
    last = pick_col(df.columns, ['LastTime', 'Last Time', 'last_time'])
    family = pick_col(df.columns, ['Traffic', 'attack_type', 'type'])
    if start is None or family is None:
        raise ValueError(f'WUSTL temporal columns missing: StartTime={start}, Traffic={family}')
    excluded = {
        norm(x) for x in [start, last, family, 'SrcAddr', 'DstAddr', 'sIpId', 'dIpId'] if x
    }
    excluded_words = ('label', 'attack', 'traffic', 'class')
    eligible_numeric = []
    for col in df.columns:
        key = norm(col)
        if key in excluded or any(word in key for word in excluded_words):
            continue
        numeric = pd.to_numeric(df[col], errors='coerce')
        coverage = float(numeric.notna().mean())
        unique = int(numeric.nunique(dropna=True))
        if coverage >= 0.90 and unique > 1:
            eligible_numeric.append(col)
    return {
        'start_time': start,
        'last_time': last,
        'family': family,
        'publisher_leakage_exclusions': [x for x in [start, last, 'SrcAddr', 'DstAddr', 'sIpId', 'dIpId'] if x],
        'eligible_network_numeric_count': len(eligible_numeric),
        'eligible_network_numeric_sample': eligible_numeric[:30],
    }


def parse_time(series):
    # WUSTL mirrors usually preserve a textual/datetime StartTime. Numeric epoch is
    # accepted if present. No row-order fallback is permitted.
    numeric = pd.to_numeric(series, errors='coerce')
    if float(numeric.notna().mean()) >= 0.95:
        med = float(numeric.dropna().median())
        unit = 'ms' if med > 1e11 else 's'
        dt = pd.to_datetime(numeric, unit=unit, errors='coerce', utc=True)
        if float(dt.notna().mean()) >= 0.95:
            return dt, f'epoch_{unit}'
    dt = pd.to_datetime(series.astype(str), errors='coerce', utc=True)
    coverage = float(dt.notna().mean())
    if coverage < 0.95:
        raise ValueError(f'StartTime parse coverage {coverage:.4f} < 0.95; row-order fallback refused')
    return dt, 'datetime_text'


def normalize_family(series):
    text = series.astype(str).str.strip()
    lower = text.str.lower()
    benign = lower.isin(['normal', 'benign', 'normaltraffic', '0'])
    family = text.where(~benign, 'Normal')
    return family, (~benign).astype(np.int8)


def minute_timeline(dt, family, attack):
    base = pd.DataFrame({'dt': dt, 'family': family, 'attack': attack}).dropna(subset=['dt']).copy()
    base['minute'] = base['dt'].dt.floor('min')
    grouped = base.groupby('minute', sort=True)
    attack_now = grouped['attack'].max().astype(int)
    fam = grouped.apply(
        lambda g: tuple(sorted({str(v).strip() for v, a in zip(g['family'], g['attack']) if int(a) == 1})),
        include_groups=False,
    )
    timeline = pd.DataFrame({'minute': attack_now.index, 'attack_now': attack_now.values, 'families': fam.values})
    return timeline.sort_values('minute').reset_index(drop=True)


def build_sequences(timeline):
    t = timeline['minute'].astype('int64').to_numpy() // 10**9
    attack = timeline['attack_now'].to_numpy(dtype=np.int8)
    families = timeline['families'].tolist()
    cutoff, clean, future_attack, history_families, step_families = [], [], [], [], []
    for i in range(HISTORY - 1, len(timeline) - HORIZON):
        lo = i - HISTORY + 1
        stop = i + HORIZON + 1
        span = t[lo:stop]
        if len(span) != HISTORY + HORIZON or not np.all(np.diff(span) == 60):
            continue
        cutoff.append(int(t[i]))
        clean.append(bool(attack[lo:i + 1].max() == 0))
        future_attack.append(int(attack[i + 1:stop].max()))
        hs = set()
        for item in families[lo:i + 1]:
            hs.update(item)
        history_families.append(frozenset(hs))
        step_families.append(tuple(frozenset(item) for item in families[i + 1:stop]))
    if not cutoff:
        raise ValueError('No contiguous 8-minute histories with four future minutes')
    return {
        'cutoff': np.asarray(cutoff, dtype=np.int64),
        'clean': np.asarray(clean, dtype=bool),
        'future_attack': np.asarray(future_attack, dtype=np.int8),
        'history_families': np.asarray(history_families, dtype=object),
        'step_families': np.asarray(step_families, dtype=object),
    }


def temporal_masks(cutoff):
    times = np.unique(cutoff)
    if len(times) < 80:
        raise ValueError(f'Only {len(times)} unique sequence cutoffs; audit refused')
    b1 = times[int(0.60 * (len(times) - 1))]
    b2 = times[int(0.75 * (len(times) - 1))]
    b3 = times[int(0.85 * (len(times) - 1))]
    embargo = EMBARGO_MINUTES * 60
    return {
        'train': cutoff <= b1,
        'calibration': (cutoff > b1 + embargo) & (cutoff <= b2),
        'policy': (cutoff > b2 + embargo) & (cutoff <= b3),
        'test': cutoff > b3 + embargo,
    }, {'train_end': int(b1), 'calibration_end': int(b2), 'policy_end': int(b3), 'embargo_seconds': int(embargo)}


def family_presence(sequences, family):
    hist = np.asarray([family in values for values in sequences['history_families']], dtype=bool)
    future = np.zeros((len(hist), HORIZON), dtype=bool)
    for i, row in enumerate(sequences['step_families']):
        for h, values in enumerate(row):
            future[i, h] = family in values
    return hist, future


def audit_support(sequences, masks):
    families = sorted({f for row in sequences['step_families'] for step in row for f in step})
    negative = masks['test'] & sequences['clean'] & (sequences['future_attack'] == 0)
    rows = []
    for family in families:
        hist, steps = family_presence(sequences, family)
        future_any = steps.any(axis=1)
        positive = masks['test'] & ~hist & future_any
        clean_positive = positive & sequences['clean']
        dev_exposed = hist | future_any
        rows.append({
            'family': family,
            'train_family_free': int((masks['train'] & ~dev_exposed).sum()),
            'calibration_family_free': int((masks['calibration'] & ~dev_exposed).sum()),
            'policy_family_free': int((masks['policy'] & ~dev_exposed).sum()),
            'test_future_positive': int(positive.sum()),
            'test_clean_history_future_positive': int(clean_positive.sum()),
            'test_clean_benign_negative': int(negative.sum()),
            'horizon_positive_support': [int((masks['test'] & ~hist & steps[:, :h].any(axis=1)).sum()) for h in range(1, HORIZON + 1)],
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--min-positive', type=int, default=20)
    parser.add_argument('--min-negative', type=int, default=100)
    args = parser.parse_args()
    out = Path(args.output)
    if out.exists():
        parser.error('Output exists; audit evidence is immutable')
    out.mkdir(parents=True)

    path = Path(args.csv)
    df = pd.read_csv(path, low_memory=False)
    schema = resolve_schema(df)
    dt, time_method = parse_time(df[schema['start_time']])
    family, attack = normalize_family(df[schema['family']])
    timeline = minute_timeline(dt, family, attack)
    sequences = build_sequences(timeline)
    masks, boundaries = temporal_masks(sequences['cutoff'])
    support = audit_support(sequences, masks)
    eligible = [r['family'] for r in support if r['test_clean_history_future_positive'] >= args.min_positive and r['test_clean_benign_negative'] >= args.min_negative and r['train_family_free'] >= 100 and r['calibration_family_free'] >= 50 and r['policy_family_free'] >= 50]

    report = {
        'protocol': 'V50 WUSTL-IIoT-2021 clean-history unseen-family support audit',
        'claim_boundary': 'Support audit only. No model accuracy, zero-day detection, compromise lead-time or containment claim.',
        'source': {'filename': path.name, 'bytes': int(path.stat().st_size), 'sha256': sha256(path), 'rows': int(len(df)), 'columns': int(len(df.columns))},
        'schema': schema,
        'timestamp_method': time_method,
        'history_minutes': HISTORY,
        'horizon_minutes': HORIZON,
        'timeline_minutes': int(len(timeline)),
        'sequence_rows': int(len(sequences['cutoff'])),
        'boundaries': boundaries,
        'test_sequences': int(masks['test'].sum()),
        'family_support': support,
        'eligibility_rule': {'min_clean_history_future_positive': args.min_positive, 'min_clean_benign_negative': args.min_negative},
        'eligible_families_for_fresh_v50_model_test': eligible,
        'model_training_permitted': bool(eligible),
    }
    (out / 'support.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'source': report['source'], 'eligible': eligible, 'support': support, 'model_training_permitted': bool(eligible)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
