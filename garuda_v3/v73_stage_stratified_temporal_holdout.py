"""V73 five-stage proxy mapping with per-stage temporal block holdout.

X-IIoTID lifecycle stages are globally campaign-ordered, so a single chronological
cutoff cannot place all five classes on both sides. V73 therefore measures the narrower
stage-mapping capability using a predeclared, class-stratified temporal block holdout:
within each stage, earliest labelled sequences train, the next block validates, and the
latest block tests, with 12 sequence indices embargoed between adjacent blocks.

This is NOT a globally future chronological benchmark. It is a leakage-controlled
supervised stage-mapping benchmark. Exploitation remains 'Initial Access proxy'.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    make_sequences,
    parse_time,
)
from .v48_strict_runner import canonical_family_name
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics, fit_stage_mapper, future_stage_targets

TRAIN_FRAC = 0.55
VAL_FRAC = 0.15
EMBARGO_SEQUENCES = 12
MIN_TEST_PER_STAGE = 20


def stage_temporal_masks(seq, y_stage):
    train = np.zeros(len(y_stage), dtype=bool)
    val = np.zeros(len(y_stage), dtype=bool)
    test = np.zeros(len(y_stage), dtype=bool)
    audit = {}
    for label, stage in enumerate(STAGES):
        ids = np.where(y_stage == label)[0]
        ids = ids[np.argsort(seq["cutoff"][ids], kind="stable")]
        n = len(ids)
        if n < 100:
            raise RuntimeError(f"{stage}: insufficient total stage sequences {n}")
        train_end = int(np.floor(TRAIN_FRAC * n))
        val_count = int(np.floor(VAL_FRAC * n))
        val_start = train_end + EMBARGO_SEQUENCES
        val_end = val_start + val_count
        test_start = val_end + EMBARGO_SEQUENCES
        if n - test_start < MIN_TEST_PER_STAGE:
            raise RuntimeError(f"{stage}: test support {n-test_start} < {MIN_TEST_PER_STAGE}")
        tr_ids = ids[:train_end]
        va_ids = ids[val_start:val_end]
        te_ids = ids[test_start:]
        train[tr_ids] = True
        val[va_ids] = True
        test[te_ids] = True
        audit[stage] = {
            "total": int(n),
            "train": int(len(tr_ids)),
            "validation": int(len(va_ids)),
            "test": int(len(te_ids)),
            "embargo_after_train": int(EMBARGO_SEQUENCES),
            "embargo_after_validation": int(EMBARGO_SEQUENCES),
            "train_time": [int(seq["cutoff"][tr_ids[0]]), int(seq["cutoff"][tr_ids[-1]])],
            "validation_time": [int(seq["cutoff"][va_ids[0]]), int(seq["cutoff"][va_ids[-1]])],
            "test_time": [int(seq["cutoff"][te_ids[0]]), int(seq["cutoff"][te_ids[-1]])],
        }
    if np.any(train & val) or np.any(train & test) or np.any(val & test):
        raise RuntimeError("Stage masks overlap")
    return train, val, test, audit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44])
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V73 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(args.csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    seq = make_sequences(state, names)
    y_stage, mapped_support = future_stage_targets(seq)
    train, val, test, split_audit = stage_temporal_masks(seq, y_stage)

    support = {
        "train": {stage: int(np.sum(train & (y_stage == i))) for i, stage in enumerate(STAGES)},
        "validation": {stage: int(np.sum(val & (y_stage == i))) for i, stage in enumerate(STAGES)},
        "test": {stage: int(np.sum(test & (y_stage == i))) for i, stage in enumerate(STAGES)},
    }
    split_freeze = {
        "protocol": "V73 predeclared per-stage temporal block split",
        "selection_used_model_metrics": False,
        "train_fraction": TRAIN_FRAC,
        "validation_fraction": VAL_FRAC,
        "embargo_sequence_indices_between_blocks": EMBARGO_SEQUENCES,
        "minimum_test_per_stage": MIN_TEST_PER_STAGE,
        "stage_support": support,
        "stage_time_ranges": split_audit,
    }
    (out / "split_freeze.json").write_text(json.dumps(split_freeze, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"split_freeze": split_freeze}, indent=2), flush=True)

    rows = {}
    for seed in args.seeds:
        print(f"V73 seed={seed}", flush=True)
        world = train_residual_world_model(seq["X"], seq["future"], train, val, int(seed), epochs=args.epochs)
        mapper, mapper_ids = fit_stage_mapper(world["future_scaled"], y_stage, train)
        ids = np.where(test)[0]
        y_true = y_stage[ids]
        pred = mapper.predict(world["pred"][ids].reshape(len(ids), -1))
        persistence_pred = mapper.predict(world["persistence"][ids].reshape(len(ids), -1))
        m = exact_metrics(y_true, pred)
        pm = exact_metrics(y_true, persistence_pred)
        rows[str(seed)] = {
            "seed": int(seed),
            "stage_mapper_train_sequences": int(len(mapper_ids)),
            "world_validation_mse": float(world["validation_mse"]),
            "world_validation_persistence_mse": float(world["validation_persistence_mse"]),
            "world_validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "forecast_state_stage_metrics": m,
            "persistence_state_stage_metrics": pm,
            "macro_f1_delta_vs_persistence_state": float(m["macro_f1_supported_classes"] - pm["macro_f1_supported_classes"]),
        }

    vals = list(rows.values())
    def arr(key):
        return np.asarray([r["forecast_state_stage_metrics"][key] for r in vals], dtype=float)
    f1, recall, precision, acc = arr("macro_f1_supported_classes"), arr("macro_recall_supported_classes"), arr("macro_precision_supported_classes"), arr("accuracy")
    pf1 = np.asarray([r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)
    report = {
        "protocol": "V73 five-stage proxy mapping, class-stratified temporal block holdout",
        "claim_boundary": (
            "This measures held-out stage mapping within each X-IIoTID lifecycle class using temporal blocks. "
            "It is not a single globally chronological future benchmark because dataset campaigns are stage-ordered. "
            "Reconnaissance, Lateral Movement, Command & Control and Exfiltration are direct lifecycle-name matches; "
            "Exploitation is only an Initial Access proxy, not exact MITRE Initial Access truth."
        ),
        "stage_mapping": {"Reconnaissance":"Reconnaissance","Exploitation":"Initial Access proxy","Lateral Movement":"Lateral Movement","C&C":"Command & Control","Exfiltration":"Exfiltration"},
        "target_rule": "furthest mapped lifecycle stage present within the 4-window future horizon",
        "split_freeze": split_freeze,
        "leakage_contract": {
            "attack_labels_are_world_model_inputs": False,
            "stage_mapper_fit_on_test": False,
            "world_model_fit_on_test": False,
            "split_selected_by_model_metrics": False,
            "test_sequences_disjoint_from_train_and_validation": True,
            "per_stage_temporal_order_train_before_validation_before_test": True,
            "global_chronological_split": False,
        },
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "labels": {"binary": binary_col, "family": family_col, "profiles": profiles},
        "source_group_column": src_col,
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "mapped_future_occurrences_before_sequence_collapse": mapped_support,
        "seeds": rows,
        "summary": {
            "seed_evaluations": len(vals),
            "test_sequences": int(test.sum()),
            "macro_f1_mean": float(f1.mean()),
            "macro_f1_sd": float(f1.std(ddof=1)),
            "macro_f1_min": float(f1.min()),
            "macro_recall_mean": float(recall.mean()),
            "macro_precision_mean": float(precision.mean()),
            "accuracy_mean": float(acc.mean()),
            "persistence_state_macro_f1_mean": float(pf1.mean()),
            "forecast_minus_persistence_macro_f1_pp": float(100.0 * (f1.mean() - pf1.mean())),
            "all_world_validation_gates_pass": all(r["world_validation_gate_passed"] for r in vals),
            "all_five_stages_present_in_test_all_seeds": all(r["forecast_state_stage_metrics"]["all_five_classes_present_in_test"] for r in vals),
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["summary"], indent=2), flush=True)
    for seed, row in rows.items():
        print("SEED", seed, json.dumps(row["forecast_state_stage_metrics"], indent=2), flush=True)


if __name__ == "__main__":
    main()
