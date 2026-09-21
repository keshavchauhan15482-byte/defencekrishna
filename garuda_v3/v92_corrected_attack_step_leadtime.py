"""V92 corrected attack-step onset lead-time audit on CICAPT Phase 2.

V72 used the timestamp of the last observed 10-second bucket as the warning timestamp.
That timestamp marks the START of the final observed bucket; a prediction consuming that
bucket cannot be issued until the bucket has ended. V92 therefore defines prediction
issue time as sequence_cutoff + WINDOW_SECONDS and uses only that corrected timestamp for
lead-time claims.

The third-party attack timeline remains publisher_verified=false. Results are therefore
ATTACK-STEP ONSET evidence only, never verified compromise-time or production zero-day
prevention evidence.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np

from .v60_residual_state_forecasting import train_residual_world_model
from .v70_cicapt_packet_world_model import EMBARGO_SEQUENCES, WINDOW_SECONDS, contiguous_sequences, packet_states
from .v72_cicapt_attack_step_leadtime import (
    LOOKBACK_SECONDS,
    POLICY_FALSE_ALERT_BUDGET,
    event_audit,
    load_events,
    sha256,
    transition_score,
    upper_tail_threshold,
)


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / den
    return {"lower": float(max(0.0, center - margin)), "upper": float(min(1.0, center + margin))}


def prediction_issue_epochs(sequence_cutoffs):
    """Earliest defensible issue time after the entire history window is observed."""
    return np.asarray(sequence_cutoffs, dtype=float) + float(WINDOW_SECONDS)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase1', required=True)
    p.add_argument('--phase2', required=True)
    p.add_argument('--timeline', required=True)
    p.add_argument('--timeline-provenance', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--packet-limit', type=int, default=3_000_000)
    p.add_argument('--seeds', nargs='+', type=int, default=[42, 43, 44])
    p.add_argument('--epochs', type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error('At least three seeds required')

    prov = json.loads(Path(args.timeline_provenance).read_text())
    if prov.get('publisher_verified') is not False:
        raise RuntimeError('V92 expects explicitly non-publisher-verified timeline provenance')
    timeline = Path(args.timeline)
    actual = sha256(timeline)
    expected = prov.get('sha256') or prov.get('source_sha256')
    if expected and str(expected).lower() != actual.lower():
        raise RuntimeError(f'Timeline SHA mismatch {actual} != {expected}')

    t1, s1, n1 = packet_states(Path(args.phase1), args.packet_limit)
    t2, s2, n2 = packet_states(Path(args.phase2), args.packet_limit)
    x1, f1, c1 = contiguous_sequences(t1, s1)
    x2, f2, c2 = contiguous_sequences(t2, s2)

    n = len(x1)
    b1 = int(n * 0.60); b2 = int(n * 0.80)
    val_start = b1 + EMBARGO_SEQUENCES
    val_end = max(val_start, b2 - EMBARGO_SEQUENCES)
    policy_start = b2 + EMBARGO_SEQUENCES
    if b1 < 100 or val_end - val_start < 50 or n - policy_start < 50:
        raise RuntimeError(f'Insufficient Phase1 support n={n}')

    X = np.concatenate([x1, x2], axis=0)
    F = np.concatenate([f1, f2], axis=0)
    train = np.zeros(len(X), dtype=bool); val = np.zeros(len(X), dtype=bool)
    policy = np.zeros(len(X), dtype=bool); phase2 = np.zeros(len(X), dtype=bool)
    train[:b1] = True
    val[val_start:val_end] = True
    policy[policy_start:n] = True
    phase2[n:] = True

    events = load_events(timeline, float(t2[0]), float(t2[-1]))
    if len(events) < 5:
        raise RuntimeError(f'Too few timestamped events in bounded Phase2 prefix: {len(events)}')

    corrected_issue = prediction_issue_epochs(c2)
    legacy_bucket_start = np.asarray(c2, dtype=float)
    rows = {}
    for seed in args.seeds:
        print(f'V92 seed={seed}', flush=True)
        world = train_residual_world_model(X, F, train, val, int(seed), epochs=args.epochs)
        score = transition_score(world['pred'], world['persistence'])
        threshold = upper_tail_threshold(score[policy], POLICY_FALSE_ALERT_BUDGET)
        policy_alert = score[policy] > threshold
        p2_ids = np.where(phase2)[0]
        p2_alert = score[p2_ids] > threshold

        corrected_alert_times = corrected_issue[p2_alert]
        corrected_events, corrected_leads = event_audit(events, corrected_alert_times)
        legacy_events, legacy_leads = event_audit(events, legacy_bucket_start[p2_alert])
        hits = sum(int(e['warning_hit']) for e in corrected_events)
        legacy_hits = sum(int(e['warning_hit']) for e in legacy_events)

        rows[str(seed)] = {
            'seed': int(seed),
            'blend_alpha': float(world['blend_alpha']),
            'trend_beta': float(world['trend_beta']),
            'validation_mse': float(world['validation_mse']),
            'validation_persistence_mse': float(world['validation_persistence_mse']),
            'validation_state_gate_passed': bool(world['state_gate_passed']),
            'threshold': float(threshold),
            'phase1_policy_sequences': int(policy.sum()),
            'phase1_policy_alerts': int(policy_alert.sum()),
            'phase1_policy_alert_rate': float(policy_alert.mean()),
            'phase2_sequences': int(len(p2_ids)),
            'phase2_alerts': int(p2_alert.sum()),
            'phase2_alert_rate': float(p2_alert.mean()),
            'events_evaluated': len(corrected_events),
            'warning_hits': hits,
            'event_warning_recall': float(hits / len(corrected_events)),
            'event_warning_recall_wilson95': wilson(hits, len(corrected_events)),
            'lead_seconds': {
                'count': len(corrected_leads),
                'mean': float(np.mean(corrected_leads)) if corrected_leads else None,
                'median': float(np.median(corrected_leads)) if corrected_leads else None,
                'min': float(np.min(corrected_leads)) if corrected_leads else None,
                'max': float(np.max(corrected_leads)) if corrected_leads else None,
            },
            'legacy_window_start_diagnostic': {
                'warning_hits': legacy_hits,
                'event_warning_recall': float(legacy_hits / len(legacy_events)),
                'median_lead_seconds': float(np.median(legacy_leads)) if legacy_leads else None,
            },
            'events': corrected_events,
        }

    vals = list(rows.values())
    rec = np.asarray([r['event_warning_recall'] for r in vals], dtype=float)
    rates = np.asarray([r['phase2_alert_rate'] for r in vals], dtype=float)
    med = np.asarray([r['lead_seconds']['median'] for r in vals if r['lead_seconds']['median'] is not None], dtype=float)
    report = {
        'protocol': 'V92 corrected prediction-issue-time attack-step onset audit on CICAPT Phase 2',
        'claim_boundary': (
            'Prediction issue time is the END of the final observed 10-second history bucket. '
            'Lead time is measured only to third-party timestamped ATTACK-STEP ONSET. The timeline '
            'publisher_verified flag is false, so this is NOT verified successful-compromise lead time '
            'and NOT production zero-day prevention proof.'
        ),
        'score_definition': 'mean absolute predicted future-state transition away from persistence; prediction only',
        'prediction_issue_time_definition': 'sequence_cutoff_epoch + WINDOW_SECONDS',
        'window_seconds': WINDOW_SECONDS,
        'policy_false_alert_budget': POLICY_FALSE_ALERT_BUDGET,
        'lookback_seconds': LOOKBACK_SECONDS,
        'timeline': str(timeline),
        'timeline_sha256': actual,
        'timeline_source_tier': prov.get('source_tier'),
        'publisher_verified': prov.get('publisher_verified'),
        'events_evaluated_within_bounded_phase2_prefix': len(events),
        'phase1': {'decoded_packets': n1, 'observed_windows': len(s1), 'sequences': len(x1), 'train': int(train.sum()), 'validation': int(val.sum()), 'policy': int(policy.sum())},
        'phase2': {'decoded_packets': n2, 'observed_windows': len(s2), 'sequences': len(x2), 'first_epoch': int(t2[0]), 'last_epoch': int(t2[-1])},
        'leakage_contract': {
            'phase2_used_for_training': False,
            'phase2_used_for_normalization': False,
            'phase2_used_for_blend_selection': False,
            'phase2_used_for_threshold_selection': False,
            'timeline_events_used_for_threshold_selection': False,
            'alert_score_uses_observed_future_ground_truth': False,
            'prediction_timestamp_uses_history_window_end': True,
            'legacy_history_bucket_start_used_for_claim': False,
        },
        'seeds': rows,
        'summary': {
            'seed_evaluations': len(vals),
            'event_warning_recall_mean': float(rec.mean()),
            'event_warning_recall_sd': float(rec.std(ddof=1)),
            'phase2_alert_rate_mean': float(rates.mean()),
            'phase2_alert_rate_sd': float(rates.std(ddof=1)),
            'median_attack_step_lead_seconds_mean_across_seeds': float(med.mean()) if len(med) else None,
            'all_validation_state_gates_pass': all(r['validation_state_gate_passed'] for r in vals),
        },
    }
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps(report['summary'], indent=2), flush=True)
    for seed, row in rows.items():
        print(seed, json.dumps({
            'policy_alert_rate': row['phase1_policy_alert_rate'],
            'phase2_alert_rate': row['phase2_alert_rate'],
            'event_warning_recall': row['event_warning_recall'],
            'event_warning_recall_wilson95': row['event_warning_recall_wilson95'],
            'lead_seconds': row['lead_seconds'],
            'legacy_window_start_diagnostic': row['legacy_window_start_diagnostic'],
        }, indent=2), flush=True)


if __name__ == '__main__':
    main()
