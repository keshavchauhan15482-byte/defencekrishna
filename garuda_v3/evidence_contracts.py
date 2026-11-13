"""Complete metric accounting and holdout checks; never a model certification.

Unknown truth stays excluded. Abstentions count as missed known attacks, not as
successful negatives. These checks cannot authenticate publisher annotations.
"""
import numpy as np

STAGES = ('Reconnaissance', 'Initial Access', 'Lateral Movement',
          'Command and Control', 'Exfiltration')


def binary_metrics(labels, predictions):
    y, p = np.asarray(labels), np.asarray(predictions)
    if y.ndim != 1 or p.shape != y.shape or not np.isin(y, [-1, 0, 1]).all() or not np.isin(p, [-1, 0, 1]).all():
        raise ValueError('Aligned labels/predictions in {-1,0,1} required')
    known, positive = y >= 0, y == 1
    tp = int(((p == 1) & positive).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p != 1) & positive).sum())
    tn = int(((p != 1) & (y == 0)).sum())
    ratio = lambda n, d: n / d if d else None
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, positives=tp+fn, negatives=tn+fp,
                precision=ratio(tp, tp+fp), recall=ratio(tp, tp+fn),
                f1=ratio(2*tp, 2*tp+fp+fn), fpr=ratio(fp, fp+tn),
                unknown_truth=int((~known).sum()), abstained=int(((p == -1) & known).sum()),
                coverage=ratio(int(((p != -1) & known).sum()), int(known.sum())),
                negative_not_alerted_includes_abstentions=True)


def matched_binary_report(labels, scores, thresholds, feature_hashes):
    """One common labelled cohort and feature hash; thresholds supplied from validation.

    A caller must separately freeze the protocol and authenticate hashes. This
    checks consistency, not whether the declared provenance is true.
    """
    if not scores or set(scores) != set(thresholds) or set(scores) != set(feature_hashes):
        raise ValueError('Every model needs scores, threshold and feature hash')
    hashes = list(feature_hashes.values())
    if any(not isinstance(h, str) or len(h) != 64 or any(c not in '0123456789abcdef' for c in h) for h in hashes) or len(set(hashes)) != 1:
        raise ValueError('Same input feature SHA256 required for all baselines')
    result = {}
    for name, values in scores.items():
        p = np.asarray(values, dtype=float)
        threshold = thresholds[name]
        if p.shape != np.asarray(labels).shape or not np.isfinite(p).all() or np.any((p < 0) | (p > 1)):
            raise ValueError('Finite aligned probabilities in [0,1] required')
        if isinstance(threshold, bool) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError('Finite validation threshold in [0,1] required')
        result[name] = binary_metrics(labels, (p >= threshold).astype(int))
    return dict(models=result, input_feature_sha256=hashes[0],
                provenance_authenticated=False, automatic_containment=False)


def five_stage_report(labels, predictions, *, min_support=20, min_recall=.8):
    y, p = np.asarray(labels), np.asarray(predictions)
    allowed = [-1, 0, 1, 2, 3, 4]
    if y.ndim != 1 or p.shape != y.shape or not np.isin(y, allowed).all() or not np.isin(p, allowed).all():
        raise ValueError('Aligned exact five-stage indices or unknown -1 required')
    if isinstance(min_support, bool) or not isinstance(min_support, int) or min_support < 1 or not 0 <= min_recall <= 1:
        raise ValueError('Positive integer support and bounded recall required')
    known = y >= 0
    rows, matrix = {}, np.zeros((5, 6), dtype=int)
    for actual, guess in zip(y[known], p[known]):
        matrix[int(actual), int(guess) if guess >= 0 else 5] += 1
    for i, stage in enumerate(STAGES):
        row = binary_metrics((y[known] == i).astype(int), (p[known] == i).astype(int))
        row['support'] = row['positives']
        row['supported'] = row['support'] >= min_support and row['recall'] >= min_recall
        rows[stage] = row
    complete = all(row['support'] > 0 for row in rows.values())
    return dict(per_stage=rows, confusion_matrix=matrix.tolist(),
                confusion_columns=[*STAGES, 'abstain'], unknown_truth=int((~known).sum()),
                coverage=float((p[known] >= 0).mean()) if known.any() else None,
                five_stage_macro_f1=float(np.mean([r['f1'] or 0 for r in rows.values()])) if complete else None,
                all_five_supported=all(r['supported'] for r in rows.values()),
                claim='Held-out stage classification only; future progression needs horizon-aligned targets',
                automatic_containment=False)


def audit_holdout(protocol):
    """Reject exposed finals and source/campaign overlap, including preprocessing."""
    reasons, groups = [], {}
    for name in ('train', 'validation', 'test'):
        rows = protocol.get(name, [])
        if not rows:
            reasons.append(name + '_empty')
        groups[name] = ({r['campaign_id'] for r in rows}, {r['source_sha256'] for r in rows})
    for a, b in (('train', 'validation'), ('train', 'test'), ('validation', 'test')):
        if groups[a][0] & groups[b][0] or groups[a][1] & groups[b][1]:
            reasons.append(a + '_' + b + '_overlap')
    if groups['test'][1] & set(protocol.get('exposed_source_sha256', [])):
        reasons.append('final_source_already_exposed')
    for field, split in (('normalization_sources', 'train'), ('class_weight_sources', 'train'),
                         ('calibration_sources', 'validation'), ('threshold_sources', 'validation')):
        declared = protocol.get(field)
        if not declared or not set(declared) <= groups[split][1]:
            reasons.append(field + '_not_' + split + '_only')
    return dict(passed=not reasons, reasons=reasons, metric_gate_passed=None,
                claim='Declared split consistency only; source authenticity and model performance not certified')
