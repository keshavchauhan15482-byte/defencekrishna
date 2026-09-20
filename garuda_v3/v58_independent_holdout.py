"""V58 prospective independent holdout audit for the frozen V55 scorer.

This runner does not search weights, thresholds, policy budgets, or model-family
choices on the holdout families. It reuses the already-frozen V55 fusion and
holds the requested families out of fitting, calibration and policy fitting.

The purpose is to verify whether the strong V55 regression metrics survive on
families that were not part of V55 development or its Exploitation/C&C reserve.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from .v47_unseen_family import (
    SEEDS,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    make_sequences,
    parse_time,
    sha256,
    temporal_masks,
)
from .v48_strict_runner import canonical_family_name
from .v55_nonlinear_joint_generalization import evaluate_joint

DEFAULT_HOLDOUT = ("rdos", "crypto-ransomware")


def canonical_json_sha(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--frozen-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    p.add_argument("--holdout-families", nargs="+", default=list(DEFAULT_HOLDOUT))
    args = p.parse_args()

    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds are required")

    output = Path(args.output)
    if output.exists():
        p.error("Output exists; V58 evidence is immutable")
    output.mkdir(parents=True)

    frozen_path = Path(args.frozen_config)
    frozen = json.loads(frozen_path.read_text())
    if frozen.get("reserve_metrics_used_for_selection") is not False:
        raise RuntimeError("Frozen scorer is not certified reserve-independent")

    historical = {
        canonical_family_name(x)
        for x in list(frozen.get("development_families", []))
        + list(frozen.get("reserve_families", []))
    }
    holdout = [canonical_family_name(x) for x in args.holdout_families]
    overlap = sorted(set(holdout) & historical)
    if overlap:
        raise RuntimeError(
            f"Independent holdout overlaps prior V55 development/evaluation families: {overlap}"
        )

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, source_group = build_minute_state(
        df, dt, binary, family, feature_cols
    )
    sequences = make_sequences(state, names)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    available = sorted(
        {x for steps in sequences["step_families"] for fams in steps for x in fams}
    )
    missing = [x for x in holdout if x not in available]
    if missing:
        raise RuntimeError(f"Holdout families missing: {missing}; available={available}")

    # Critical point: evaluate_joint fits the model with every holdout family
    # blocked from train/calibration/policy, and uses the supplied frozen V55
    # weights + policy budget without running scorer selection.
    joint = evaluate_joint(
        sequences,
        time_masks,
        holdout,
        tuple(args.seeds),
        args.epochs,
        frozen,
    )

    report = {
        "protocol": "V58 prospective independent fresh-family holdout using frozen V55 fusion",
        "claim_boundary": (
            "Independent family holdout inside X-IIoTID; not yet a cross-dataset or production zero-day claim."
        ),
        "source_sha256": sha256(csv_path),
        "frozen_config_sha256": canonical_json_sha(frozen),
        "frozen_config_source": str(frozen_path),
        "selection_reused_without_modification": True,
        "holdout_metrics_used_for_selection": False,
        "holdout_blocked_from_fit_calibration_policy": True,
        "prior_v55_families": sorted(historical),
        "fresh_holdout_families": holdout,
        "seeds": list(args.seeds),
        "joint_holdout": joint,
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "boundaries": boundaries,
        },
        "labels": {
            "binary": binary_col,
            "family": family_col,
            "profiles": profiles,
        },
        "network_only_feature_audit": {
            "raw_selected": feature_cols,
            "audit": feature_audit,
        },
        "source_group_column": source_group,
    }

    (output / "summary.json").write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n"
    )
    print(
        json.dumps(
            {
                "fresh_holdout_families": holdout,
                "selection_reused_without_modification": True,
                "joint": {
                    k: v["summary"] for k, v in joint["families"].items()
                },
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
