"""V71b support-frozen chronological future-stage proxy benchmark.

V71's generic final temporal tail contained zero mapped lifecycle-stage targets. V71b
fixes the *evaluation protocol*, not the metric: before any model is trained, it chooses
a chronological test boundary using only timestamped stage-label support counts. The
support freeze is written to disk before model training. No model score participates in
that choice.

Four X-IIoTID lifecycle labels directly match requested stage names. Exploitation is
reported only as ``Initial Access proxy``; it is not exact MITRE Initial Access truth.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import (
    EMBARGO_MINUTES,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    make_sequences,
    parse_time,
)
from .v48_strict_runner import canonical_family_name
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics, fit_stage_mapper, future_stage_targets

EMBARGO_SECONDS = EMBARGO_MINUTES * 60
MIN_TEST_TOTAL = 50
MIN_DEV_STAGE_TOTAL = 200
MIN_TEST_PER_CLASS_TARGET = 10


def counts(y_stage, mask):
    c = Counter(STAGES[int(x)] for x in y_stage[mask & (y_stage >= 0)])
    return {s: int(c.get(s, 0)) for s in STAGES}


def support_freeze(seq, y_stage):
    stage_times = np.unique(seq["cutoff"][y_stage >= 0])
    if len(stage_times) < 30:
        raise RuntimeError(f"Too few unique stage-labelled cutoffs: {len(stage_times)}")
    candidates = []
    # Fixed support-only grid; no model outcome can affect the candidate set.
    for q in np.linspace(0.25, 0.85, 25):
        t = int(stage_times[int(round(q * (len(stage_times) - 1)))])
        dev = (seq["cutoff"] < t - EMBARGO_SECONDS) & (y_stage >= 0)
        test = (seq["cutoff"] > t + EMBARGO_SECONDS) & (y_stage >= 0)
        dc, tc = counts(y_stage, dev), counts(y_stage, test)
        candidates.append({
            "cutoff": t,
            "quantile": float(q),
            "dev_total": int(dev.sum()),
            "test_total": int(test.sum()),
            "dev_counts": dc,
            "test_counts": tc,
            "dev_classes": int(sum(v > 0 for v in dc.values())),
            "test_classes": int(sum(v > 0 for v in tc.values())),
            "test_classes_ge_target": int(sum(v >= MIN_TEST_PER_CLASS_TARGET for v in tc.values())),
            "min_test_support_all_five": int(min(tc.values())),
            "min_dev_support_all_five": int(min(dc.values())),
        })
    feasible = [r for r in candidates if r["dev_total"] >= MIN_DEV_STAGE_TOTAL and r["test_total"] >= MIN_TEST_TOTAL and r["dev_classes"] >= 4 and r["test_classes"] >= 4]
    if not feasible:
        raise RuntimeError(f"No support-qualified chronological stage boundary; audit={candidates}")
    # Predeclared objective: five-class coverage first, then per-class support, then
    # number of well-supported classes, then total test support, then later cutoff.
    chosen = max(feasible, key=lambda r: (
        int(r["test_classes"] == 5 and r["dev_classes"] == 5),
        r["min_test_support_all_five"],
        r["test_classes_ge_target"],
        r["test_total"],
        r["cutoff"],
    ))
    return chosen, candidates


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
        p.error("Output exists; V71b evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(args.csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    seq = make_sequences(state, names)
    y_stage, mapped_support = future_stage_targets(seq)

    chosen, candidates = support_freeze(seq, y_stage)
    test_cut = int(chosen["cutoff"])
    dev_limit = test_cut - EMBARGO_SECONDS
    test_mask = (seq["cutoff"] > test_cut + EMBARGO_SECONDS) & (y_stage >= 0)
    dev_stage = (seq["cutoff"] < dev_limit) & (y_stage >= 0)

    # World-model train/validation are both strictly before the frozen test boundary.
    dev_times = np.unique(seq["cutoff"][seq["cutoff"] < dev_limit])
    if len(dev_times) < 40:
        raise RuntimeError("Insufficient pre-test world-model timeline")
    world_split = int(dev_times[int(round(0.70 * (len(dev_times) - 1)))])
    world_train = seq["cutoff"] <= world_split
    world_val = (seq["cutoff"] > world_split + EMBARGO_SECONDS) & (seq["cutoff"] < dev_limit)
    if int(world_train.sum()) < 50 or int(world_val.sum()) < 20:
        raise RuntimeError(f"World support train={world_train.sum()} val={world_val.sum()}")

    freeze = {
        "protocol": "V71b support-only chronological stage boundary freeze",
        "selection_used_model_metrics": False,
        "candidate_grid": "25 fixed quantiles from 0.25 through 0.85 of stage-labelled cutoffs",
        "objective": "five-class dev/test coverage, minimum test support, classes>=10, total test support, later cutoff",
        "embargo_seconds": EMBARGO_SECONDS,
        "chosen": chosen,
        "world_train_end": world_split,
        "world_validation_after": world_split + EMBARGO_SECONDS,
        "world_development_limit": dev_limit,
        "test_after": test_cut + EMBARGO_SECONDS,
        "candidates": candidates,
    }
    (out / "support_freeze.json").write_text(json.dumps(freeze, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"support_freeze": freeze}, indent=2), flush=True)

    train_support = counts(y_stage, dev_stage)
    test_support = counts(y_stage, test_mask)
    rows = {}
    for seed in args.seeds:
        print(f"V71b seed={seed}", flush=True)
        world = train_residual_world_model(seq["X"], seq["future"], world_train, world_val, int(seed), epochs=args.epochs)
        mapper, mapper_ids = fit_stage_mapper(world["future_scaled"], y_stage, dev_stage)
        ids = np.where(test_mask)[0]
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
    f1 = np.asarray([r["forecast_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)
    recall = np.asarray([r["forecast_state_stage_metrics"]["macro_recall_supported_classes"] for r in vals], dtype=float)
    precision = np.asarray([r["forecast_state_stage_metrics"]["macro_precision_supported_classes"] for r in vals], dtype=float)
    acc = np.asarray([r["forecast_state_stage_metrics"]["accuracy"] for r in vals], dtype=float)
    pf1 = np.asarray([r["persistence_state_stage_metrics"]["macro_f1_supported_classes"] for r in vals], dtype=float)

    report = {
        "protocol": "V71b support-frozen chronological future-state lifecycle-stage proxy benchmark",
        "claim_boundary": (
            "X-IIoTID lifecycle labels supervise the mapper. Reconnaissance, Lateral Movement, Command & Control "
            "and Exfiltration are direct lifecycle-name matches. Exploitation is only an Initial Access proxy, "
            "not exact MITRE Initial Access. The test boundary is support/timestamp-selected before model training."
        ),
        "stage_mapping": {"Reconnaissance":"Reconnaissance","Exploitation":"Initial Access proxy","Lateral Movement":"Lateral Movement","C&C":"Command & Control","Exfiltration":"Exfiltration"},
        "target_rule": "furthest mapped lifecycle stage present within 4-window future horizon",
        "support_freeze": freeze,
        "leakage_contract": {
            "attack_labels_are_world_model_inputs": False,
            "stage_mapper_fit_on_test": False,
            "world_model_fit_on_test": False,
            "test_boundary_selected_by_model_metrics": False,
            "chronological_test_boundary": True,
            "embargo_seconds": EMBARGO_SECONDS,
            "world_blend_selected_on_pretest_validation_only": True,
        },
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method},
        "labels": {"binary": binary_col, "family": family_col, "profiles": profiles},
        "source_group_column": src_col,
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "mapped_future_occurrences_before_sequence_collapse": mapped_support,
        "train_stage_support": train_support,
        "test_stage_support": test_support,
        "test_stage_sequences": int(test_mask.sum()),
        "seeds": rows,
        "summary": {
            "seed_evaluations": len(vals),
            "macro_f1_mean": float(f1.mean()),
            "macro_f1_sd": float(f1.std(ddof=1)),
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
    print(json.dumps({"train_support": train_support, "test_support": test_support, "summary": report["summary"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
