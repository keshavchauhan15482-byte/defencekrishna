"""V78b metric-definition fix for V78.

V78 completed all three model seeds but strict JSON serialization rejected a NaN that
came from converting a supported stage with no predicted positives into a per-stage F1.
For a supported class, no positive prediction is a real zero-score outcome: F1 = 0.0,
not missing/NaN. This wrapper changes only that metric representation and reruns the
same frozen support-only holdout protocol; it does not change holdout selection, model
inputs, training data, thresholds, seeds, or evaluation membership.
"""
from __future__ import annotations

from . import v78_supported_stage_unseen_subtype_eval as base


def add_stage_f1_strict(metric):
    for row in metric["per_stage"].values():
        p = row["precision"]
        r = row["recall"]
        support = int(row["support"])
        if support <= 0:
            row["f1"] = None
        elif p is None or r is None or (p + r) == 0:
            row["f1"] = 0.0
        else:
            row["f1"] = float(2.0 * p * r / (p + r))
        row["recall_wilson95"] = base.wilson(row["tp"], row["tp"] + row["fn"])
    return metric


def main():
    base.add_stage_f1 = add_stage_f1_strict
    base.main()


if __name__ == "__main__":
    main()
