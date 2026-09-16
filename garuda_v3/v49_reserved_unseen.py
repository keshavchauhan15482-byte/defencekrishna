"""V49 reserved unseen-family scoring study for X-IIoTID.

V47 exposed five family-disjoint diagnostics. V49 uses those five families only as
pseudo-unseen development folds to select a warning score, then freezes that choice
before evaluating two previously unscored reserve families: C&C and Exploitation.

This is still a controlled public-dataset unseen-family simulation, not proof of an
undisclosed production zero-day or verified pre-compromise lead time.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import (
    SEEDS,
    FPR_BUDGET,
    norm,
    sha256,
    parse_time,
    detect_label_hierarchy,
    choose_network_numeric_features,
    build_minute_state,
    make_sequences,
    temporal_masks,
    train_world_model,
    robust_reference,
    anomaly_score,
    fpr_threshold,
    binary_metrics,
)
from .v47_leave_one_family import leave_one_family_split

DEV_FAMILIES = (
    "Tampering",
    "Lateral _movement",
    "Weaponization",
    "Exfiltration",
    "Reconnaissance",
)
RESERVE_FAMILIES = ("C&C", "Exploitation")
WORLD_CANDIDATES = ("world_future", "world_delta", "world_delta_future")
HYBRID_CANDIDATES = (
    "hybrid_log75_delta25",
    "hybrid_log50_delta50",
    "hybrid_log25_delta75",
    "hybrid_log60_delta20_future20",
    "hybrid_and",
    "hybrid_or",
)
ALL_CANDIDATES = WORLD_CANDIDATES + HYBRID_CANDIDATES + ("logistic_only",)


def _impute_and_scale_history(X, train_idx):
    flat = X.reshape(len(X), -1).astype(np.float64)
    flat[~np.isfinite(flat)] = np.nan
    med = np.nanmedian(flat[train_idx], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(flat)
    if bad.any():
        rows, cols = np.where(bad)
        flat[rows, cols] = med[cols]
    scaler = StandardScaler().fit(flat[train_idx])
    return scaler.transform(flat)


def logistic_signal(X, y, train_mask, seed):
    train_idx = np.where(train_mask)[0]
    if len(train_idx) < 50 or len(np.unique(y[train_idx])) < 2:
        raise ValueError("Known-family logistic signal lacks training support")
    z = _impute_and_scale_history(X, train_idx)
    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        solver="liblinear",
        random_state=int(seed),
    )
    model.fit(z[train_idx], y[train_idx])
    return model.predict_proba(z)[:, 1]


def empirical_surprise(reference, values):
    ref = np.sort(np.asarray(reference, dtype=float))
    val = np.asarray(values, dtype=float)
    if len(ref) < 20:
        raise ValueError("At least 20 benign calibration samples required")
    rank = np.searchsorted(ref, val, side="right")
    tail = (len(ref) - rank + 1.0) / (len(ref) + 1.0)
    return -np.log10(np.maximum(tail, 1.0 / (len(ref) + 1.0)))


def candidate_scores(world, log_prob, calibration_benign):
    future_center, future_scale = robust_reference(world["pred"][calibration_benign])
    future_raw = anomaly_score(world["pred"], future_center, future_scale)

    delta = world["pred"] - world["persistence"]
    delta_center, delta_scale = robust_reference(delta[calibration_benign])
    delta_raw = anomaly_score(delta, delta_center, delta_scale)

    sf = empirical_surprise(future_raw[calibration_benign], future_raw)
    sd = empirical_surprise(delta_raw[calibration_benign], delta_raw)
    sl = empirical_surprise(log_prob[calibration_benign], log_prob)

    return {
        "world_future": sf,
        "world_delta": sd,
        "world_delta_future": 0.5 * sd + 0.5 * sf,
        "logistic_only": sl,
        "hybrid_log75_delta25": 0.75 * sl + 0.25 * sd,
        "hybrid_log50_delta50": 0.50 * sl + 0.50 * sd,
        "hybrid_log25_delta75": 0.25 * sl + 0.75 * sd,
        "hybrid_log60_delta20_future20": 0.60 * sl + 0.20 * sd + 0.20 * sf,
        "hybrid_and": np.minimum(sl, sd),
        "hybrid_or": np.maximum(sl, sd),
    }


def evaluate_scores(scores, split, policy_benign):
    eval_idx = np.where(split["test_eval"])[0]
    y_eval = split["test_positive"][eval_idx].astype(int)
    rows = {}
    for name, score in scores.items():
        threshold = fpr_threshold(score[policy_benign])
        rows[name] = {"threshold": threshold, "test": binary_metrics(y_eval, score[eval_idx], threshold)}
    return rows


def state_metrics(world, split):
    mask = split["test_eval"]
    return {
        "validation_mse": world["validation_mse"],
        "validation_persistence_mse": world["validation_persistence_mse"],
        "state_gate_passed": world["state_gate_passed"],
        "test_mse": float(np.mean((world["pred"][mask] - world["future_scaled"][mask]) ** 2)),
        "test_persistence_mse": float(np.mean((world["persistence"][mask] - world["future_scaled"][mask]) ** 2)),
    }


def run_family(sequences, time_masks, family, seeds, epochs, candidate_names=ALL_CANDIDATES):
    split = leave_one_family_split(sequences, time_masks, family)
    support = {
        "train": int(split["train"].sum()),
        "calibration": int(split["calibration"].sum()),
        "policy": int(split["policy"].sum()),
        "test_positive": int(split["test_positive"].sum()),
        "test_negative": int(split["test_negative"].sum()),
        "clean_history_onset_positive": int(split["clean_onset_positive"].sum()),
    }
    rows = {}
    for seed in seeds:
        world = train_world_model(
            sequences["X"], sequences["future"], split["train"], split["calibration"], int(seed), epochs=epochs
        )
        calibration_benign = split["calibration"] & sequences["clean"] & (sequences["y"] == 0)
        policy_benign = split["policy"] & sequences["clean"] & (sequences["y"] == 0)
        if int(calibration_benign.sum()) < 20 or int(policy_benign.sum()) < 20:
            rows[str(seed)] = {"status": "insufficient_benign_reference", "state": state_metrics(world, split)}
            continue
        log_prob = logistic_signal(sequences["X"], sequences["y"], split["train"], seed)
        all_scores = candidate_scores(world, log_prob, calibration_benign)
        selected_scores = {name: all_scores[name] for name in candidate_names}
        rows[str(seed)] = {
            "status": "evaluated",
            "state": state_metrics(world, split),
            "scores": evaluate_scores(selected_scores, split, policy_benign),
        }
    return {"support": support, "seeds": rows}


def aggregate_candidate(dev_results, candidate):
    family_rows = {}
    for family, result in dev_results.items():
        metrics = []
        for row in result["seeds"].values():
            if row.get("status") != "evaluated":
                continue
            test = row["scores"][candidate]["test"]
            if test.get("fpr") is None or test.get("recall") is None:
                continue
            metrics.append((float(test["recall"]), float(test["fpr"])))
        if metrics:
            rec = float(np.mean([x[0] for x in metrics]))
            fpr = float(np.mean([x[1] for x in metrics]))
            family_rows[family] = {"recall_mean": rec, "fpr_mean": fpr, "seeds": len(metrics)}
    if not family_rows:
        return {"candidate": candidate, "family_rows": {}, "gate_family_count": 0, "full_gate_family_count": 0}
    values = list(family_rows.values())
    gate_count = sum(v["fpr_mean"] <= FPR_BUDGET for v in values)
    full_gate = sum(v["fpr_mean"] <= FPR_BUDGET and v["recall_mean"] >= 0.80 for v in values)
    budgeted_recalls = [v["recall_mean"] for v in values if v["fpr_mean"] <= FPR_BUDGET]
    return {
        "candidate": candidate,
        "family_rows": family_rows,
        "gate_family_count": int(gate_count),
        "full_gate_family_count": int(full_gate),
        "mean_recall_on_budget_families": float(np.mean(budgeted_recalls)) if budgeted_recalls else 0.0,
        "mean_recall_all": float(np.mean([v["recall_mean"] for v in values])),
        "mean_fpr_all": float(np.mean([v["fpr_mean"] for v in values])),
    }


def choose_candidate(dev_results, names):
    rows = [aggregate_candidate(dev_results, name) for name in names]
    def key(row):
        return (
            row["full_gate_family_count"],
            row["gate_family_count"],
            row["mean_recall_on_budget_families"],
            row["mean_recall_all"],
            -row["mean_fpr_all"],
            row["candidate"],
        )
    selected = max(rows, key=key)
    return selected["candidate"], rows


def compact_reserve(result, selected_world, selected_hybrid):
    out = {"support": result["support"], "state_gate_passed_all_seeds": True, "scores": {}}
    evaluated = [r for r in result["seeds"].values() if r.get("status") == "evaluated"]
    if not evaluated:
        out["status"] = "no_evaluated_seeds"
        out["state_gate_passed_all_seeds"] = False
        return out
    out["state_gate_passed_all_seeds"] = all(r["state"]["state_gate_passed"] for r in evaluated)
    for name in (selected_world, selected_hybrid, "logistic_only"):
        rec = [r["scores"][name]["test"].get("recall") for r in evaluated]
        fpr = [r["scores"][name]["test"].get("fpr") for r in evaluated]
        rec = [float(v) for v in rec if v is not None]
        fpr = [float(v) for v in fpr if v is not None]
        out["scores"][name] = {
            "recall_mean": float(np.mean(rec)) if rec else None,
            "recall_sd": float(np.std(rec, ddof=1)) if len(rec) > 1 else None,
            "fpr_mean": float(np.mean(fpr)) if fpr else None,
            "fpr_sd": float(np.std(fpr, ddof=1)) if len(fpr) > 1 else None,
            "gate_passed_all_seeds": bool(evaluated and all(
                r["state"]["state_gate_passed"] and
                r["scores"][name]["test"].get("fpr") is not None and r["scores"][name]["test"]["fpr"] <= FPR_BUDGET and
                r["scores"][name]["test"].get("recall") is not None and r["scores"][name]["test"]["recall"] >= 0.80
                for r in evaluated
            )),
        }
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    args = parser.parse_args()
    if len(set(args.seeds)) < 3:
        parser.error("At least three distinct seeds required")
    out = Path(args.output)
    if out.exists():
        parser.error("Output already exists; V49 evidence is immutable")
    out.mkdir(parents=True)

    csv_path = Path(args.csv)
    df = pd.read_csv(csv_path, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, label_profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    sequences = make_sequences(state, state_features)
    time_masks, boundaries = temporal_masks(sequences["cutoff"])

    present = {item for steps in sequences["step_families"] for fams in steps for item in fams}
    missing = [f for f in DEV_FAMILIES + RESERVE_FAMILIES if f not in present]
    if missing:
        raise RuntimeError(f"Required frozen family names missing from dataset: {missing}")

    dev_results = {}
    for family_name in DEV_FAMILIES:
        print(f"V49 development pseudo-unseen family={family_name}", flush=True)
        dev_results[family_name] = run_family(sequences, time_masks, family_name, tuple(args.seeds), args.epochs, ALL_CANDIDATES)

    selected_world, world_selection = choose_candidate(dev_results, WORLD_CANDIDATES)
    selected_hybrid, hybrid_selection = choose_candidate(dev_results, HYBRID_CANDIDATES)
    frozen = (selected_world, selected_hybrid, "logistic_only")
    print(json.dumps({"selected_world": selected_world, "selected_hybrid": selected_hybrid}, indent=2), flush=True)

    reserve_results = {}
    for family_name in RESERVE_FAMILIES:
        print(f"V49 RESERVED family={family_name}", flush=True)
        reserve_results[family_name] = run_family(sequences, time_masks, family_name, tuple(args.seeds), args.epochs, frozen)

    reserve_summary = {family_name: compact_reserve(result, selected_world, selected_hybrid) for family_name, result in reserve_results.items()}
    report = {
        "protocol": "V49 frozen-score reserved unseen-family evaluation",
        "claim_boundary": "Public-dataset family-disjoint simulation only; not a real undisclosed zero-day or verified compromise lead-time result.",
        "source": {"filename": csv_path.name, "bytes": int(csv_path.stat().st_size), "sha256": sha256(csv_path), "rows": int(len(df)), "columns": int(len(df.columns))},
        "seeds": list(args.seeds),
        "fpr_budget": FPR_BUDGET,
        "development_pseudo_unseen_families": list(DEV_FAMILIES),
        "reserved_unscored_before_v49_families": list(RESERVE_FAMILIES),
        "selection_rule": "maximize full-gate family count, then FPR-budget family count, then recall under budget, then overall recall, then lower FPR; no reserve metrics used",
        "selected_world_candidate": selected_world,
        "selected_hybrid_candidate": selected_hybrid,
        "world_candidate_selection": world_selection,
        "hybrid_candidate_selection": hybrid_selection,
        "network_only_feature_audit": {"raw_selected": feature_cols, "state_feature_count": len(state_features), "audit": feature_audit},
        "labels": {"binary": binary_col, "family": family_col, "profiles": label_profiles},
        "time": {"date_column": date_col, "timestamp_column": ts_col, "method": time_method, "boundaries": boundaries},
        "state_rows": int(len(state)), "sequence_rows": int(len(sequences["X"])), "source_group_column": src_col,
        "development_results": dev_results,
        "reserve_results": reserve_results,
        "reserve_summary": reserve_summary,
        "automatic_containment_approved": False,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    for family_name, result in reserve_results.items():
        (out / f"reserve_{norm(family_name)}.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"selected_world": selected_world, "selected_hybrid": selected_hybrid, "reserve_summary": reserve_summary}, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
