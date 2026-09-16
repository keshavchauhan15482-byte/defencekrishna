"""V47 leave-one-family-out open-set benchmark.

This complements the stricter chronological pre-onset protocol.  An attack family is
completely withheld from model development, then evaluated wherever it occurs.  The
benchmark measures unseen-family generalisation/detection, while separately reporting
how many positives are true clean-history onsets.  It must not be presented as verified
pre-compromise lead time or a real undisclosed zero-day.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd

from .v47_unseen_family import (
    HISTORY, HORIZON, SEEDS, FPR_BUDGET, norm, sha256, parse_time,
    detect_label_hierarchy, choose_network_numeric_features, build_minute_state,
    make_sequences, temporal_masks, family_presence, train_world_model,
    robust_reference, anomaly_score, fpr_threshold, binary_metrics,
    logistic_unseen_baseline, summarize_family,
)

EMBARGO_STEPS = HISTORY + HORIZON


def leave_one_family_split(sequences, time_masks, family):
    """Reserve every sequence containing family plus a raw-window-overlap embargo.

    Development sees zero history/future occurrences of the held-out family.  Test
    positives are all future occurrences of that family, even if the family is already
    present in the observed history.  `clean_onset_positive` is the stricter subset
    where the complete observed history is free of the family and all attacks.
    """
    hist, future_steps = family_presence(sequences, family)
    future_any = future_steps.any(axis=1)
    exposed = hist | future_any
    cutoffs = sequences['cutoff']

    # Prevent overlapping histories/horizons from leaking the held-out episode into
    # development through neighboring sequence cutoffs.
    positive_times = cutoffs[future_any]
    blocked = set()
    for t in positive_times.tolist():
        for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
            blocked.add(int(t + 60 * k))
    overlap_blocked = np.asarray([int(t) in blocked for t in cutoffs], dtype=bool)
    development_free = ~exposed & ~overlap_blocked

    train = time_masks['train'] & development_free
    calibration = time_masks['calibration'] & development_free
    policy = time_masks['policy'] & development_free

    # FPR controls remain the untouched chronological benign tail. These sequences
    # are never used to fit the family-free world model or its benign reference.
    negative = time_masks['test'] & sequences['clean'] & (sequences['y'] == 0)
    positive = future_any
    clean_onset = positive & ~hist & sequences['clean']
    evaluation = positive | negative
    return {
        'train': train,
        'calibration': calibration,
        'policy': policy,
        'test_positive': positive,
        'test_negative': negative,
        'test_eval': evaluation,
        'clean_onset_positive': clean_onset,
        'future_steps': future_steps,
        'overlap_blocked': overlap_blocked,
    }


def logistic_baseline_clean_policy(X, target, clean, split, seed):
    """Known-family discriminative baseline with clean-benign policy selection."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    tr = np.where(split['train'])[0]
    policy_benign = np.where(split['policy'] & clean & (target == 0))[0]
    eval_idx = np.where(split['test_eval'])[0]
    if len(tr) < 50 or len(policy_benign) < 20 or len(np.unique(target[tr])) < 2:
        return {'status': 'insufficient_support'}
    x = X.reshape(len(X), -1).astype(np.float64)
    x[~np.isfinite(x)] = np.nan
    med = np.nanmedian(x[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(x)
    if bad.any():
        x[bad] = med[np.where(bad)[1]]
    scaler = StandardScaler().fit(x[tr])
    z = scaler.transform(x)
    model = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=seed, solver='liblinear')
    model.fit(z[tr], target[tr])
    score = model.predict_proba(z)[:, 1]
    threshold = fpr_threshold(score[policy_benign])
    y_eval = split['test_positive'][eval_idx].astype(int)
    return {'threshold': threshold, 'test': binary_metrics(y_eval, score[eval_idx], threshold)}


def run_family(sequences, time_masks, family, seeds, epochs, min_pos, min_neg):
    split = leave_one_family_split(sequences, time_masks, family)
    support = {
        'train': int(split['train'].sum()),
        'calibration': int(split['calibration'].sum()),
        'policy': int(split['policy'].sum()),
        'test_positive': int(split['test_positive'].sum()),
        'test_negative': int(split['test_negative'].sum()),
        'clean_history_onset_positive': int(split['clean_onset_positive'].sum()),
        'overlap_embargoed_sequences': int(split['overlap_blocked'].sum()),
    }
    if support['test_positive'] < min_pos or support['test_negative'] < min_neg:
        return {'status': 'insufficient_test_support', 'support': support, 'seeds': {}}

    rows = {}
    for seed in seeds:
        world = train_world_model(
            sequences['X'], sequences['future'], split['train'], split['calibration'], seed, epochs=epochs
        )
        cal_benign = split['calibration'] & sequences['clean'] & (sequences['y'] == 0)
        policy_benign = split['policy'] & sequences['clean'] & (sequences['y'] == 0)
        if int(cal_benign.sum()) < 20 or int(policy_benign.sum()) < 20:
            rows[str(seed)] = {
                'status': 'insufficient_benign_reference',
                'state': {k: world[k] for k in ('validation_mse', 'validation_persistence_mse', 'state_gate_passed')},
            }
            continue

        center, scale = robust_reference(world['pred'][cal_benign])
        scores = anomaly_score(world['pred'], center, scale)
        threshold = fpr_threshold(scores[policy_benign])
        eval_idx = np.where(split['test_eval'])[0]
        y_eval = split['test_positive'][eval_idx].astype(int)
        overall = binary_metrics(y_eval, scores[eval_idx], threshold)

        onset_idx = np.where(split['clean_onset_positive'] | split['test_negative'])[0]
        onset_y = split['clean_onset_positive'][onset_idx].astype(int)
        onset_metrics = binary_metrics(onset_y, scores[onset_idx], threshold)
        if support['clean_history_onset_positive'] == 0:
            onset_metrics['status'] = 'no_clean_history_unseen_family_onsets'

        test_state = split['test_eval']
        state_test_mse = float(np.mean((world['pred'][test_state] - world['future_scaled'][test_state]) ** 2))
        persistence_test_mse = float(np.mean((world['persistence'][test_state] - world['future_scaled'][test_state]) ** 2))

        horizon_rows = []
        hist, _ = family_presence(sequences, family)
        for h in range(1, HORIZON + 1):
            c, s = robust_reference(world['pred'][cal_benign, :h])
            hscores = anomaly_score(world['pred'][:, :h], c, s)
            hth = fpr_threshold(hscores[policy_benign])
            hpos = np.asarray([
                any(family in steps[j] for j in range(h))
                for steps in sequences['step_families']
            ], dtype=bool)
            ids = np.where(hpos | split['test_negative'])[0]
            horizon_rows.append({
                'horizon_minutes': h,
                'positive_support': int(hpos.sum()),
                'clean_history_onset_support': int((hpos & ~hist & sequences['clean']).sum()),
                'threshold': hth,
                'test': binary_metrics(hpos[ids].astype(int), hscores[ids], hth),
            })

        baseline = logistic_baseline_clean_policy(sequences['X'], sequences['y'], sequences['clean'], split, seed)
        rows[str(seed)] = {
            'status': 'evaluated',
            'state': {
                'validation_mse': world['validation_mse'],
                'validation_persistence_mse': world['validation_persistence_mse'],
                'state_gate_passed': world['state_gate_passed'],
                'test_mse': state_test_mse,
                'test_persistence_mse': persistence_test_mse,
            },
            'open_set_world_forecast': {
                'threshold': threshold,
                'test': overall,
                'clean_history_onset_test': onset_metrics,
                'horizons': horizon_rows,
            },
            'known_attack_logistic_baseline': baseline,
        }
    return {'status': 'evaluated', 'support': support, 'seeds': rows}


def compact_summary(result):
    if result.get('status') != 'evaluated':
        return {'status': result.get('status'), 'support': result.get('support')}
    rows = [r for r in result['seeds'].values() if r.get('status') == 'evaluated']
    def mean_sd(path):
        vals = []
        for row in rows:
            cur = row
            for p in path:
                cur = cur.get(p) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if isinstance(cur, (int, float)):
                vals.append(float(cur))
        return (float(np.mean(vals)) if vals else None, float(np.std(vals, ddof=1)) if len(vals) > 1 else None)
    wr, wrsd = mean_sd(('open_set_world_forecast', 'test', 'recall'))
    wf, wfsd = mean_sd(('open_set_world_forecast', 'test', 'fpr'))
    lr, lrsd = mean_sd(('known_attack_logistic_baseline', 'test', 'recall'))
    lf, lfsd = mean_sd(('known_attack_logistic_baseline', 'test', 'fpr'))
    return {
        'evaluated_seeds': len(rows),
        'world_recall_mean': wr, 'world_recall_sd': wrsd,
        'world_fpr_mean': wf, 'world_fpr_sd': wfsd,
        'logistic_recall_mean': lr, 'logistic_recall_sd': lrsd,
        'logistic_fpr_mean': lf, 'logistic_fpr_sd': lfsd,
        'state_gate_passed_all_seeds': bool(rows and all(r['state']['state_gate_passed'] for r in rows)),
        'unseen_family_gate_passed_all_seeds': bool(rows and all(
            r['state']['state_gate_passed'] and
            r['open_set_world_forecast']['test'].get('fpr') is not None and r['open_set_world_forecast']['test']['fpr'] <= FPR_BUDGET and
            r['open_set_world_forecast']['test'].get('recall') is not None and r['open_set_world_forecast']['test']['recall'] >= 0.80
            for r in rows
        )),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--csv', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--epochs', type=int, default=12)
    p.add_argument('--max-families', type=int, default=5)
    p.add_argument('--min-test-positives', type=int, default=20)
    p.add_argument('--min-test-negatives', type=int, default=50)
    p.add_argument('--seeds', nargs='+', type=int, default=list(SEEDS))
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error('At least three distinct seeds required')
    out = Path(args.output)
    if out.exists():
        p.error('Output exists; evidence is immutable')
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences['cutoff'])

    families = sorted({item for steps in sequences['step_families'] for fams in steps for item in fams})
    support_rows = []
    for fam in families:
        split = leave_one_family_split(sequences, time_masks, fam)
        support_rows.append({
            'family': fam,
            'future_positive': int(split['test_positive'].sum()),
            'clean_history_onset_positive': int(split['clean_onset_positive'].sum()),
            'negative': int(split['test_negative'].sum()),
            'train': int(split['train'].sum()),
            'calibration': int(split['calibration'].sum()),
            'policy': int(split['policy'].sum()),
        })
    eligible = [r for r in support_rows if r['future_positive'] >= args.min_test_positives and r['negative'] >= args.min_test_negatives and r['train'] >= 50 and r['calibration'] >= 20 and r['policy'] >= 20]
    eligible.sort(key=lambda r: (-r['future_positive'], r['family']))
    selected = [r['family'] for r in eligible[:args.max_families]]

    report = {
        'protocol': 'V47 leave-one-family-out open-set generalisation',
        'claim_boundary': 'Held-out public-dataset families have zero development exposure. This measures unseen-family generalisation, not real undisclosed zero-day prediction or verified pre-compromise lead time.',
        'source': {'filename': csv_path.name, 'bytes': int(csv_path.stat().st_size), 'sha256': sha256(csv_path), 'rows': int(len(df)), 'columns': int(len(df.columns))},
        'history_minutes': HISTORY, 'horizon_minutes': HORIZON, 'seeds': list(args.seeds), 'fpr_budget': FPR_BUDGET,
        'label_columns': {'binary': binary_col, 'family': family_col, 'profiles': label_profiles},
        'time': {'date_column': date_col, 'timestamp_column': ts_col, 'method': time_method, 'boundaries': boundaries},
        'network_only_feature_audit': {'raw_selected': feature_cols, 'state_feature_count': len(state_features), 'audit': feature_audit},
        'state_rows': int(len(state)), 'sequence_rows': int(len(sequences['X'])), 'source_group_column': src_col,
        'family_support': support_rows,
        'family_selection': {'method': 'largest supported held-out families by positive support only; never by model performance', 'selected': selected},
        'families': {},
        'automatic_containment_approved': False,
    }
    for fam in selected:
        print(f'V47 LOO family={fam}', flush=True)
        result = run_family(sequences, time_masks, fam, tuple(args.seeds), args.epochs, args.min_test_positives, args.min_test_negatives)
        result['summary'] = compact_summary(result)
        report['families'][fam] = result
        (out / f'{norm(fam)}.json').write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    report['all_selected_unseen_family_gates_passed'] = bool(selected and all(v['summary'].get('unseen_family_gate_passed_all_seeds') for v in report['families'].values()))
    report['pre_onset_claim_supported'] = bool(selected and all(v['support'].get('clean_history_onset_positive', 0) > 0 for v in report['families'].values()))
    (out / 'summary.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'selected': selected, 'summaries': {k: v['summary'] for k, v in report['families'].items()}, 'pre_onset_claim_supported': report['pre_onset_claim_supported']}, indent=2), flush=True)


if __name__ == '__main__':
    main()
