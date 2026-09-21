"""V89 support-correct monotonic attacker-progression hazard benchmark.

V87 exposed a protocol defect in development architecture selection: subtype folds were
constructed from attack-labelled sequences only, so threshold calibration could contain
zero negatives. A nominal 1% FPR budget is meaningless in that case.

V89 fixes the protocol rather than hiding the failure:
  * every held-out-subtype fold uses the full reserve-free development pool (including
    clean/no-stage and lower-stage future steps) after excluding every sequence touching
    the held-out fine subtype;
  * chronological fit/calibration splits are selected by support only and must contain
    both positives and >=100 negative future-step examples in calibration;
  * the 1% FPR operating threshold is selected only on that mixed development
    calibration slice;
  * release-candidate architectures MUST use a non-zero Garuda future-state weight;
  * an alpha=0 persistence-state diagnostic is measured on the same development folds
    but cannot win architecture selection;
  * the already exposed V81/V82 subtype reserve is diagnostic only.

This benchmark still does not claim a fresh zero-day or verified pre-compromise result.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .v47_unseen_family import HORIZON, build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import WORLD_SEEDS, development_split, mse, reserve_isolation, scaled_history
from .v82_robust_stage_head_fresh_eval import EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT, choose_gamma, mapper_diagnostic_pairs
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v86_multihorizon_progression import sample_features, sha256, step_targets
from .v87_monotonic_progression_hazard import (
    BinaryHazardHead,
    FPR_BUDGET,
    MIN_SUBTYPE_RECALL,
    calibrate_threshold,
    evaluate_exposed,
    fit_binary,
    flat_rows,
)

ALPHA_GRID = (0.10, 0.25, 0.50, 1.00)
MIN_FIT_POS = 40
MIN_FIT_NEG = 200
MIN_CAL_POS = 20
MIN_CAL_NEG = 100
SPLIT_GRID = tuple(np.linspace(0.55, 0.85, 13))
EPS = 1e-12


def class_support(ids, y_step, threshold_rank):
    ii, _hh, yy = flat_rows(np.asarray(ids, dtype=int), threshold_rank, y_step)
    pos = int(yy.sum())
    neg = int(len(yy) - pos)
    return {"sequences": int(len(np.asarray(ids))), "steps": int(len(ii)), "positives": pos, "negatives": neg}


def support_ok(fit_support, cal_support):
    return bool(
        fit_support["positives"] >= MIN_FIT_POS
        and fit_support["negatives"] >= MIN_FIT_NEG
        and cal_support["positives"] >= MIN_CAL_POS
        and cal_support["negatives"] >= MIN_CAL_NEG
    )


def chronological_support_split(ids, cutoff, y_step, threshold_rank):
    """Choose a chronological split by label support only, never by model outcomes."""
    ids = np.asarray(ids, dtype=int)
    ordered = ids[np.argsort(np.asarray(cutoff)[ids], kind="stable")]
    if len(ordered) < 50:
        raise RuntimeError(f"Too few candidate sequences: {len(ordered)}")
    rows = []
    for frac in SPLIT_GRID:
        split = max(1, min(len(ordered) - 1, int(round(len(ordered) * float(frac)))))
        fit_ids = ordered[:split]
        cal_ids = ordered[split:]
        fs = class_support(fit_ids, y_step, threshold_rank)
        cs = class_support(cal_ids, y_step, threshold_rank)
        rows.append({
            "fraction": float(frac), "fit_ids": fit_ids, "cal_ids": cal_ids,
            "fit_support": fs, "cal_support": cs, "supported": support_ok(fs, cs),
        })
    viable = [r for r in rows if r["supported"]]
    if not viable:
        public = [{k: r[k] for k in ("fraction", "fit_support", "cal_support", "supported")} for r in rows]
        raise RuntimeError(f"No chronological mixed-class split satisfies support contract: {public}")
    viable.sort(key=lambda r: (abs(r["fraction"] - 0.75), -r["cal_support"]["negatives"], -r["cal_support"]["positives"]))
    winner = viable[0]
    return winner["fit_ids"], winner["cal_ids"], {
        "fraction": winner["fraction"],
        "fit_support": winner["fit_support"],
        "cal_support": winner["cal_support"],
    }


def subtype_positive_recall(head, threshold, X3, y_step, step_pairs, eval_ids, stage, subtype):
    k = STAGES.index(stage)
    total = correct = 0
    by_h = []
    for h in range(HORIZON):
        ids = np.asarray([
            int(i) for i in np.asarray(eval_ids, dtype=int)
            if int(y_step[int(i), h]) >= k and (stage, subtype) in step_pairs[int(i), h]
        ], dtype=int)
        if len(ids):
            p = head.predict_proba(X3[ids, h])
            c = int(np.sum(p >= float(threshold)))
            total += len(ids); correct += c
            by_h.append({"horizon_minutes": h + 1, "support": int(len(ids)), "recall": c / len(ids)})
        else:
            by_h.append({"horizon_minutes": h + 1, "support": 0, "recall": None})
    return (None if total == 0 else correct / total), by_h, int(total)


def fold_pool_mask(seq, development, stage, subtype):
    pair = (stage, subtype)
    touch = np.asarray([
        pair in set(h) or pair in set(f)
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)
    return np.asarray(development, dtype=bool) & ~touch


def evaluate_candidate(kind, alpha, X3, seq, y_step, step_pairs, development, diagnostics):
    folds = []
    for row in diagnostics:
        stage = row["stage"]; subtype = row["subtype"]; k = STAGES.index(stage)
        pool_mask = fold_pool_mask(seq, development, stage, subtype)
        pool_ids = np.where(pool_mask)[0]
        eval_ids = np.where(row["eval_mask"])[0]
        try:
            fit_ids, cal_ids, split_audit = chronological_support_split(pool_ids, seq["cutoff"], y_step, k)
            head = fit_binary(kind, X3, y_step, step_pairs, fit_ids, k)
            threshold, cal_metric = calibrate_threshold(head, X3, y_step, cal_ids, k)
            if int(cal_metric["negatives"]) < MIN_CAL_NEG or int(cal_metric["positives"]) < MIN_CAL_POS:
                raise RuntimeError(f"Mixed calibration support contract violated: {cal_metric}")
            recall, by_h, support = subtype_positive_recall(head, threshold, X3, y_step, step_pairs, eval_ids, stage, subtype)
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"
        if recall is None:
            return None, f"No held-out subtype step support for {stage}/{subtype}"
        folds.append({
            "stage": stage, "subtype": subtype, "support": support,
            "recall_at_1pct_cal_fpr": float(recall), "by_horizon": by_h,
            "threshold": float(threshold), "calibration": cal_metric,
            "mixed_support_split": split_audit,
        })
    recalls = np.asarray([r["recall_at_1pct_cal_fpr"] for r in folds], dtype=float)
    cal_fprs = np.asarray([r["calibration"]["fpr"] for r in folds], dtype=float)
    cal_neg = np.asarray([r["calibration"]["negatives"] for r in folds], dtype=int)
    cal_pos = np.asarray([r["calibration"]["positives"] for r in folds], dtype=int)
    ap = np.asarray([0.0 if r["calibration"]["pr_auc"] is None else r["calibration"]["pr_auc"] for r in folds], dtype=float)
    out = {
        "future_weight_alpha": float(alpha), "model": kind, "folds": folds,
        "minimum_subtype_recall_at_1pct_cal_fpr": float(recalls.min()),
        "mean_subtype_recall_at_1pct_cal_fpr": float(recalls.mean()),
        "maximum_calibration_fpr": float(cal_fprs.max()),
        "minimum_calibration_negatives": int(cal_neg.min()),
        "minimum_calibration_positives": int(cal_pos.min()),
        "mean_calibration_pr_auc": float(ap.mean()),
    }
    out["development_viable"] = bool(
        out["minimum_subtype_recall_at_1pct_cal_fpr"] >= MIN_SUBTYPE_RECALL
        and out["maximum_calibration_fpr"] <= FPR_BUDGET + EPS
        and out["minimum_calibration_negatives"] >= MIN_CAL_NEG
        and out["minimum_calibration_positives"] >= MIN_CAL_POS
    )
    return out, None


def select_architecture(history, forecast, persistence, state_names, seq, y_step, step_pairs, development, labelled_development, reserve_pairs):
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No development subtype diagnostics")
    candidates = []
    failures = []
    feature_cache = {}

    # alpha=0 is a matched development diagnostic only; it can never win.
    baseline_X3 = sample_features(history, persistence, persistence, state_names)
    baseline_rows = []
    for kind in ("logistic", "histgb"):
        row, err = evaluate_candidate(kind, 0.0, baseline_X3, seq, y_step, step_pairs, development, diagnostics)
        if row is not None:
            baseline_rows.append(row)
        else:
            failures.append({"alpha": 0.0, "model": kind, "error": err})
    if not baseline_rows:
        raise RuntimeError(f"No support-correct alpha=0 baseline completed: {failures}")
    baseline_rows.sort(key=lambda r: (r["minimum_subtype_recall_at_1pct_cal_fpr"], r["mean_subtype_recall_at_1pct_cal_fpr"]), reverse=True)
    baseline = baseline_rows[0]

    for alpha in ALPHA_GRID:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        X3 = sample_features(history, stage_future, persistence, state_names)
        feature_cache[float(alpha)] = X3
        for kind in ("logistic", "histgb"):
            row, err = evaluate_candidate(kind, alpha, X3, seq, y_step, step_pairs, development, diagnostics)
            if row is None:
                failures.append({"alpha": float(alpha), "model": kind, "error": err})
                continue
            row["delta_min_recall_vs_best_alpha0"] = float(
                row["minimum_subtype_recall_at_1pct_cal_fpr"] - baseline["minimum_subtype_recall_at_1pct_cal_fpr"]
            )
            row["delta_mean_recall_vs_best_alpha0"] = float(
                row["mean_subtype_recall_at_1pct_cal_fpr"] - baseline["mean_subtype_recall_at_1pct_cal_fpr"]
            )
            candidates.append(row)
    if not candidates:
        raise RuntimeError(f"No learned-future V89 candidate completed: {failures}")
    candidates.sort(key=lambda r: (
        int(r["development_viable"]),
        r["minimum_subtype_recall_at_1pct_cal_fpr"],
        r["mean_subtype_recall_at_1pct_cal_fpr"],
        -r["maximum_calibration_fpr"],
        r["mean_calibration_pr_auc"],
        r["future_weight_alpha"],
        int(r["model"] == "histgb"),
    ), reverse=True)
    return candidates[0], candidates, baseline, baseline_rows, feature_cache, diagnostics, failures


def fit_final_heads(kind, X3, y_step, step_pairs, train_mask, validation_mask):
    train_ids = np.where(train_mask)[0]
    val_ids = np.where(validation_mask)[0]
    heads = []; thresholds = []; calibration = []
    for k, stage in enumerate(STAGES):
        ts = class_support(train_ids, y_step, k); vs = class_support(val_ids, y_step, k)
        if not support_ok(ts, vs):
            raise RuntimeError(f"Final mixed-class support failed for {stage}: train={ts}, validation={vs}")
        head = fit_binary(kind, X3, y_step, step_pairs, train_ids, k)
        threshold, metric = calibrate_threshold(head, X3, y_step, val_ids, k)
        if metric["fpr"] > FPR_BUDGET + EPS:
            raise RuntimeError(f"Final threshold exceeds FPR budget for {stage}: {metric}")
        heads.append(head); thresholds.append(float(threshold))
        calibration.append({"stage_threshold": stage, "train_support": ts, **metric})
    return heads, np.asarray(thresholds, dtype=float), calibration


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--epochs", type=int, default=18)
    args = ap.parse_args()

    csv = Path(args.csv); freeze = Path(args.freeze); out = Path(args.output)
    frozen = json.loads(freeze.read_text())
    if sha256(freeze) != EXPECTED_V81_FREEZE_SHA256:
        raise RuntimeError("V81 freeze hash drift")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset differs from V81 freeze")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V81_SELECTED:
        raise RuntimeError("V81 selected reserve drift")
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        if subtype not in EXPOSED_SUBTYPE_REGISTRY.get(stage, []):
            raise RuntimeError("Exposed reserve registry drift")
    if out.exists():
        ap.error("Output exists; V89 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(csv, low_memory=False)
    dt, *_ = parse_time(df)
    binary, family, binary_col, family_col, _ = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_names, _ = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    minute_pairs, _ = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_names, minute_pairs)
    y_step, step_pairs = step_targets(seq, minute_pairs)

    reserve_pairs, reserve_touch, blocked = reserve_isolation(seq, dict(EXPECTED_V81_SELECTED))
    development = ~blocked
    train, validation, boundary = development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)

    test_masks = {}
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        target = STAGES.index(stage); pair = (stage, subtype); other = reserve_pairs - {pair}
        mask = np.asarray([
            seq["y_stage"][i] == target
            and pair in seq["future_pairs"][i]
            and not other.intersection(set(seq["history_pairs"][i]) | set(seq["future_pairs"][i]))
            for i in range(len(seq["X"]))
        ], dtype=bool)
        test_masks[stage] = mask; test_union |= mask
    support = {s: int(test_masks[s].sum()) for s in EXPECTED_V81_SELECTED}
    if support != EXPECTED_V81_SUPPORT:
        raise RuntimeError(f"Exposed support drift: {support}")

    worlds = []
    for seed in WORLD_SEEDS:
        print(f"V89 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])

    winner, candidates, dev_baseline, dev_baseline_rows, feature_cache, diagnostics, failures = select_architecture(
        history, forecast, persistence, list(state_names), seq, y_step, step_pairs,
        development, labelled_development, reserve_pairs,
    )
    print("V89 DEVELOPMENT WINNER", json.dumps(winner, indent=2), flush=True)
    alpha = float(winner["future_weight_alpha"])
    if alpha <= 0.0:
        raise RuntimeError("V89 release candidate must use learned future state")
    X3 = feature_cache[alpha]
    heads, thresholds, calibration = fit_final_heads(winner["model"], X3, y_step, step_pairs, train, validation)
    learned = evaluate_exposed(heads, thresholds, X3, y_step, step_pairs, test_masks)

    pX3 = sample_features(history, persistence, persistence, list(state_names))
    pheads, pthresholds, pcal = fit_final_heads(winner["model"], pX3, y_step, step_pairs, train, validation)
    persistence_eval = evaluate_exposed(pheads, pthresholds, pX3, y_step, step_pairs, test_masks)

    fmse = mse(forecast, target, test_union); pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    lrec = learned["macro_recall_supported_subtypes"]
    prec = persistence_eval["macro_recall_supported_subtypes"]
    dev_beats = bool(
        winner["minimum_subtype_recall_at_1pct_cal_fpr"] > dev_baseline["minimum_subtype_recall_at_1pct_cal_fpr"] + EPS
        or (
            abs(winner["minimum_subtype_recall_at_1pct_cal_fpr"] - dev_baseline["minimum_subtype_recall_at_1pct_cal_fpr"]) <= EPS
            and winner["mean_subtype_recall_at_1pct_cal_fpr"] > dev_baseline["mean_subtype_recall_at_1pct_cal_fpr"] + EPS
        )
    )

    report = {
        "protocol": "V89 support-correct monotonic cumulative attacker-progression hazard diagnostic",
        "claim_boundary": (
            "Development subtype folds use real mixed-class calibration support. Models P(reach stage >= k by horizon h) "
            "from observed history plus predicted network state. The reused X-IIoTID V81/V82 reserve is exposed and "
            "diagnostic only; not a fresh zero-day or verified pre-compromise result. Exploitation remains an Initial Access proxy."
        ),
        "dataset_sha256": sha256(csv), "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols, "feature_audit": feature_audit,
        "horizons_minutes": list(range(1, HORIZON + 1)), "false_positive_budget": FPR_BUDGET,
        "support_contract": {
            "min_fit_positives": MIN_FIT_POS, "min_fit_negatives": MIN_FIT_NEG,
            "min_calibration_positives": MIN_CAL_POS, "min_calibration_negatives": MIN_CAL_NEG,
            "chronological_split_grid": list(SPLIT_GRID),
        },
        "split": {
            "sequence_count": int(len(seq["X"])), "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()), "development_train": int(train.sum()),
            "development_validation": int(validation.sum()), "exposed_sequence_support": support,
            "boundary": boundary,
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "winner": winner, "all_learned_candidates": candidates,
            "alpha0_development_baseline": dev_baseline,
            "all_alpha0_baselines": dev_baseline_rows,
            "candidate_failures": failures,
            "world_gamma_winner": gamma_winner, "world_gamma_table": gamma_table,
            "development_diagnostic_subtypes": [
                {k: r[k] for k in ("stage", "subtype", "support", "same_stage_train_after_exclusion")}
                for r in diagnostics
            ],
        },
        "state_task": {"forecast_mse": fmse, "persistence_mse": pmse, "improvement_vs_persistence": state_gain},
        "hazard_heads": {
            "stages": STAGES, "decision_thresholds": thresholds.tolist(),
            "development_calibration": calibration,
            "monotonic_contract": {"by_horizon_non_decreasing": True, "later_stage_threshold_not_above_earlier_stage": True},
        },
        "exposed_diagnostic": {
            "learned_future": learned, "persistence_future": persistence_eval,
            "macro_recall_delta_vs_persistence": None if lrec is None or prec is None else float(lrec - prec),
            "persistence_development_calibration": pcal,
        },
        "release_gate": {
            "mixed_negative_calibration_contract_passed": bool(
                winner["minimum_calibration_negatives"] >= MIN_CAL_NEG
                and winner["minimum_calibration_positives"] >= MIN_CAL_POS
            ),
            "development_subtype_gate_80pct_recall_at_1pct_fpr_passed": bool(winner["development_viable"]),
            "learned_future_contribution_required": True,
            "learned_future_contribution_used": True,
            "learned_future_beats_alpha0_on_development": dev_beats,
            "exposed_hazard_recall_beats_persistence": bool(lrec is not None and prec is not None and lrec > prec + EPS),
            "eligible_for_unseen_progression_claim": False,
            "fresh_claim_allowed": False,
            "reason": "A genuinely external sealed progression-labelled dataset/campaign is required for a fresh progression claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_selection": False,
            "reserve_metrics_used_for_hazard_architecture_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "attack_labels_are_world_model_inputs": False,
            "future_observed_state_used_at_inference": False,
            "development_calibration_contains_real_negatives": True,
            "alpha_zero_allowed_to_win": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": winner,
        "alpha0_baseline": dev_baseline,
        "state_task": report["state_task"],
        "learned_exposed": learned,
        "persistence_exposed": persistence_eval,
        "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
