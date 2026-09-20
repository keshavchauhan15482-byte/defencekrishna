"""Support-only diagnostics for V62. No model is fitted and no attack score is computed."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import build_minute_state
from .v59_unsw_independent_replication import COMMON_FEATURES, adapt_unsw, load_unsw_raw
from .v61_unsw_source_aware_fresh_holdout import canonical, make_sequences_with_source
from .v62_unsw_rolling_campaign_holdout import (
    CONTAMINATED,
    MIN_CAL,
    MIN_NEGATIVE,
    MIN_POLICY,
    MIN_RESERVE_POSITIVE,
    MIN_TRAIN,
    campaign_split,
    clean_family_positive,
    support_row,
)

TARGETS = {
    "train": MIN_TRAIN,
    "calibration": MIN_CAL,
    "policy": MIN_POLICY,
    "negative": MIN_NEGATIVE,
    "positive": MIN_RESERVE_POSITIVE,
}


def coverage(s):
    ratios = {k: (float(s[k]) / float(v) if v else 1.0) for k, v in TARGETS.items()}
    return min(ratios.values()), ratios


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    raw, _ = load_unsw_raw(Path(args.dataset_root))
    adapted, y, family = adapt_unsw(raw)
    family = family.map(canonical)
    dt = pd.to_datetime(adapted["Timestamp"], unit="s", errors="coerce", utc=True)
    state, names, _ = build_minute_state(adapted, dt, y, family, list(COMMON_FEATURES))
    seq = make_sequences_with_source(state, names)
    available = sorted({canonical(x) for steps in seq["step_families"] for fams in steps for x in fams})

    rows = []
    for fam in available:
        pos = clean_family_positive(seq, fam)
        times = np.sort(np.unique(seq["cutoff"][pos]))
        best = None
        max_counts = {k: 0 for k in TARGETS}
        for cutoff in times.tolist():
            split = campaign_split(seq, fam, int(cutoff))
            s = support_row(split)
            for k in max_counts:
                max_counts[k] = max(max_counts[k], int(s[k]))
            score, ratios = coverage(s)
            cand = {
                "campaign_cutoff": int(cutoff),
                "support": s,
                "coverage_min_ratio": float(score),
                "coverage_ratios": ratios,
            }
            if best is None or (cand["coverage_min_ratio"], cand["campaign_cutoff"]) > (best["coverage_min_ratio"], best["campaign_cutoff"]):
                best = cand
        row = {
            "family": fam,
            "contaminated": fam in CONTAMINATED,
            "total_clean_history_positive_windows": int(pos.sum()),
            "unique_positive_cutoffs": int(len(times)),
            "max_individual_counts_over_cutoffs": max_counts,
            "best_balanced_campaign": best,
        }
        rows.append(row)

    payload = {
        "protocol": "V62 support-only audit; no model fit, no scores, no metrics",
        "targets": TARGETS,
        "families": rows,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
    print(json.dumps(payload, indent=2), flush=True)


if __name__ == "__main__":
    main()
