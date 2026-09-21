"""V89.1 computational hardening for the controlled progression gate.

V89's threshold selector evaluated the full label vector once for every unique score,
which is quadratic in the number of scored rows. This wrapper preserves the exact
selection objective and FPR budget but computes feasible thresholds from one descending
sort plus cumulative TP/FP counts. No dataset split, label, feature, model, alpha grid,
release criterion, or exposed-reserve rule is changed.
"""
from __future__ import annotations

import numpy as np

from . import v89_controlled_progression_gate as base


def select_threshold_fast(y, p, budget=base.FPR_BUDGET):
    y = np.asarray(y, dtype=np.int8)
    p = np.asarray(p, dtype=float)
    pos = int(np.sum(y == 1)); neg = int(np.sum(y == 0))
    if pos < 1 or neg < 1:
        raise RuntimeError("Threshold selection requires both positive and negative controls")
    if len(y) != len(p) or len(y) == 0:
        raise RuntimeError("Threshold selection arrays are empty or misaligned")

    # Stable descending score order. Because predictions use score >= threshold, all
    # tied scores must enter together. Evaluate once at the end of each tie group.
    order = np.argsort(-p, kind="mergesort")
    ys = y[order]; ps = p[order]
    cum_tp = np.cumsum(ys == 1)
    cum_fp = np.cumsum(ys == 0)
    group_end = np.r_[ps[1:] != ps[:-1], True]
    idx = np.where(group_end)[0]

    best_key = None; best_threshold = None
    for j in idx:
        tp = int(cum_tp[j]); fp = int(cum_fp[j])
        fpr = fp / neg
        if fpr > float(budget) + 1e-12:
            continue
        fn = pos - tp
        recall = tp / pos
        precision = tp / max(tp + fp, 1)
        threshold = float(ps[j])
        # Same ordering as V89: recall, precision, lower FPR, then lower threshold.
        key = (recall, precision, -fpr, -threshold)
        if best_key is None or key > best_key:
            best_key = key; best_threshold = threshold

    # Include the legal no-alert operating point used by V89's original grid.
    no_alert_threshold = float(np.nextafter(float(np.max(p)), np.inf))
    no_alert_key = (0.0, 0.0, -0.0, -no_alert_threshold)
    if best_key is None or no_alert_key > best_key:
        best_threshold = no_alert_threshold

    metric = base.binary_metrics(y, p, float(best_threshold))
    if metric["fpr"] > float(budget) + 1e-12:
        raise RuntimeError(f"Fast selector violated FPR budget: {metric}")
    return float(best_threshold), metric


base.select_threshold = select_threshold_fast


if __name__ == "__main__":
    base.main()
