"""V90 clean-negative progression gate.

V87 exposed a methodological weakness: its leave-subtype-out *selection* folds were
constructed from labelled attack-stage sequences only, so some calibration folds had
zero negatives and an apparent 0% FPR was not meaningful. V90 keeps the exact same
world model, cumulative hazard target, candidate models, exposed reserve and thresholds,
but fixes the development diagnostic masks so every held-out-subtype fold trains and
calibrates against reserve-free clean/no-supported-stage development sequences too.

No exposed-reserve metric participates in candidate/model/threshold selection.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

from . import v87_monotonic_progression_hazard as base

MIN_CAL_NEGATIVES = 100


def clean_negative_mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs):
    """Build subtype folds while adding reserve-free clean negatives to train/calibration.

    Positive diagnostic discovery/evaluation remains restricted to labelled development.
    The training mask, however, is the entire reserve-free development set except any
    sequence touching the held-out subtype. This supplies meaningful negatives for the
    binary cumulative-hazard head without leaking the held-out subtype.
    """
    original = base._v90_original_mapper(seq, labelled_development, reserve_pairs)
    _, _, blocked = base.reserve_isolation(seq, dict(base.EXPECTED_V81_SELECTED))
    development = ~blocked
    rows = []
    for row in original:
        pair = (row["stage"], row["subtype"])
        touch = np.asarray([
            pair in set(h) or pair in set(f)
            for h, f in zip(seq["history_pairs"], seq["future_pairs"])
        ], dtype=bool)
        train_mask = development & ~touch
        revised = dict(row)
        revised["train_mask"] = train_mask
        revised["development_train_support_with_clean_negatives"] = int(train_mask.sum())
        revised["clean_or_no_supported_stage_train_sequences"] = int(
            np.sum(train_mask & (np.asarray(seq["y_stage"]) < 0))
        )
        rows.append(revised)
    return rows


def strict_select_architecture(*args, **kwargs):
    winner, candidates, feature_cache, diagnostics = base._v90_original_select(*args, **kwargs)

    # Candidates with an invalid FPR denominator are explicitly non-viable. Re-rank using
    # the same robustness objective, but require >=MIN_CAL_NEGATIVES for every fold.
    for candidate in candidates:
        neg_counts = [int(f["calibration"].get("negatives", 0)) for f in candidate["folds"]]
        candidate["minimum_calibration_negatives"] = min(neg_counts) if neg_counts else 0
        candidate["meaningful_fpr_denominator"] = bool(
            neg_counts and min(neg_counts) >= MIN_CAL_NEGATIVES
        )
        candidate["development_viable"] = bool(
            candidate["development_viable"] and candidate["meaningful_fpr_denominator"]
        )

    candidates.sort(
        key=lambda r: (
            int(r["development_viable"]),
            int(r["meaningful_fpr_denominator"]),
            r["minimum_subtype_recall_at_1pct_cal_fpr"],
            r["mean_subtype_recall_at_1pct_cal_fpr"],
            -r["maximum_calibration_fpr"],
            r["mean_calibration_pr_auc"],
            int(r["future_weight_alpha"] > 0),
            int(r["model"] == "histgb"),
        ),
        reverse=True,
    )
    return candidates[0], candidates, feature_cache, diagnostics


def _output_arg() -> Path:
    try:
        i = sys.argv.index("--output")
        return Path(sys.argv[i + 1])
    except Exception as exc:
        raise RuntimeError("V90 requires --output") from exc


def main():
    # Save originals once so the mapper can reuse the exact V87 subtype discovery contract.
    if not hasattr(base, "_v90_original_mapper"):
        base._v90_original_mapper = base.mapper_diagnostic_pairs
    if not hasattr(base, "_v90_original_select"):
        base._v90_original_select = base.select_architecture

    base.mapper_diagnostic_pairs = clean_negative_mapper_diagnostic_pairs
    base.select_architecture = strict_select_architecture
    out = _output_arg()
    base.main()

    summary_path = out / "summary.json"
    d = json.loads(summary_path.read_text())
    d["protocol"] = "V90 clean-negative monotonic cumulative attacker-progression hazard diagnostic"
    d["methodology_fix"] = {
        "v87_issue": "leave-subtype-out selection calibration could contain zero negatives",
        "v90_change": "reserve-free clean/no-supported-stage development sequences are included as negatives in every subtype-fold train/calibration mask",
        "minimum_required_calibration_negatives_per_fold": MIN_CAL_NEGATIVES,
        "exposed_reserve_used_for_selection": False,
    }
    winner = d["architecture_selection"]["winner"]
    folds = winner.get("folds", [])
    min_neg = min((int(f["calibration"].get("negatives", 0)) for f in folds), default=0)
    d["release_gate"]["meaningful_1pct_fpr_denominator_passed"] = bool(min_neg >= MIN_CAL_NEGATIVES)
    d["release_gate"]["minimum_calibration_negatives"] = int(min_neg)
    d["release_gate"]["development_subtype_gate_80pct_recall_at_1pct_fpr_passed"] = bool(
        winner.get("development_viable", False) and min_neg >= MIN_CAL_NEGATIVES
    )
    d["leakage_contract"]["clean_negative_calibration_fix"] = True
    summary_path.write_text(json.dumps(d, indent=2, allow_nan=False) + "\n")
    print("V90 FINAL DEVELOPMENT GATE", json.dumps({
        "winner": winner,
        "minimum_calibration_negatives": min_neg,
        "release_gate": d["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
