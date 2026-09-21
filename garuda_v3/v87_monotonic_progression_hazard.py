"""V87 monotonic cumulative attacker-progression hazard benchmark.

V86 showed that exact future-stage classification is brittle under unseen subtypes. V87
instead models the PS-native question directly: P(attacker reaches stage >= k by horizon h
| observed history). Binary threshold heads are trained only on development traffic, with
thresholds selected on development calibration traffic under an explicit false-positive
budget. Probabilities are projected to be monotonic across both horizon and lifecycle
threshold. The previously exposed V81/V82 reserve remains diagnostic only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import HORIZON, build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import WORLD_SEEDS, development_split, mse, reserve_isolation, scaled_history
from .v82_robust_stage_head_fresh_eval import EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT, choose_gamma, mapper_diagnostic_pairs
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v86_multihorizon_progression import sha256, step_targets, sample_features

EPS = 1e-9
ALPHA_GRID = (0.0, 0.25, 0.50, 1.00)
FPR_BUDGET = 0.01
MIN_SUBTYPE_RECALL = 0.80


def ece_binary(y, p, bins=10):
    y = np.asarray(y, dtype=int)
    p = np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = max(len(y), 1)
    out = 0.0
    for j in range(bins):
        lo, hi = edges[j], edges[j + 1]
        mask = (p >= lo) & (p < hi if j < bins - 1 else p <= hi)
        if mask.any():
            out += float(mask.sum()) / total * abs(float(y[mask].mean()) - float(p[mask].mean()))
    return float(out)


def binary_metrics(y, p, threshold):
    y = np.asarray(y, dtype=int)
    p = np.asarray(p, dtype=float)
    pred = p >= float(threshold)
    pos = y == 1
    neg = ~pos
    tp = int(np.sum(pred & pos)); fn = int(np.sum((~pred) & pos))
    fp = int(np.sum(pred & neg)); tn = int(np.sum((~pred) & neg))
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, EPS)
    ap = float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else None
    auc = float(roc_auc_score(y, p)) if len(np.unique(y)) > 1 else None
    brier = float(np.mean((p - y) ** 2))
    return {
        "support": int(len(y)), "positives": int(pos.sum()), "negatives": int(neg.sum()),
        "threshold": float(threshold), "recall": float(recall), "fpr": float(fpr),
        "precision": float(precision), "f1": float(f1), "pr_auc": ap, "roc_auc": auc,
        "brier": brier, "ece_10bin": ece_binary(y, p),
    }


def select_threshold(y, p, max_fpr=FPR_BUDGET):
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    if not np.any(y == 1) or not np.any(y == 0):
        return 0.5, binary_metrics(y, p, 0.5)
    grid = np.unique(np.concatenate([
        np.linspace(0.0, 1.0, 401),
        np.clip(p, 0.0, 1.0),
        np.asarray([np.nextafter(float(p.max()), 2.0)])
    ]))
    rows = [binary_metrics(y, p, float(t)) for t in grid]
    feasible = [r for r in rows if r["fpr"] <= max_fpr + 1e-12]
    if not feasible:
        feasible = rows
    feasible.sort(key=lambda r: (r["recall"], r["precision"], -r["fpr"], -r["threshold"]), reverse=True)
    win = feasible[0]
    return float(win["threshold"]), win


class BinaryHazardHead:
    def __init__(self, kind):
        self.kind = str(kind)
        if self.kind == "logistic":
            self.model = Pipeline([
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(
                    C=0.35, class_weight="balanced", max_iter=4000,
                    solver="lbfgs", random_state=20260921,
                )),
            ])
        elif self.kind == "histgb":
            self.model = HistGradientBoostingClassifier(
                learning_rate=0.05, max_iter=260, max_leaf_nodes=15,
                min_samples_leaf=20, l2_regularization=4.0,
                class_weight="balanced", random_state=20260921,
            )
        else:
            raise KeyError(kind)

    def fit(self, X, y, sample_weight=None):
        if len(np.unique(y)) < 2:
            raise RuntimeError("Binary hazard head needs both classes")
        if self.kind == "logistic":
            self.model.fit(X, y, clf__sample_weight=sample_weight)
        else:
            self.model.fit(X, y, sample_weight=sample_weight)
        return self

    def predict_proba(self, X):
        return np.asarray(self.model.predict_proba(X)[:, 1], dtype=float)


def flat_rows(seq_ids, threshold_rank, y_step):
    ii, hh, yy = [], [], []
    for i in np.asarray(seq_ids, dtype=int):
        for h in range(HORIZON):
            ii.append(int(i)); hh.append(int(h)); yy.append(int(y_step[i, h] >= threshold_rank))
    return np.asarray(ii, dtype=int), np.asarray(hh, dtype=int), np.asarray(yy, dtype=np.int8)


def subtype_balanced_weights(ii, hh, yy, step_pairs, threshold_rank):
    rank = {s: i for i, s in enumerate(STAGES)}
    keys = []
    for i, h, y in zip(ii, hh, yy):
        if int(y) == 0:
            keys.append(("negative",))
            continue
        subs = sorted(
            f"{s}:{sub}" for s, sub in step_pairs[int(i), int(h)]
            if s in rank and rank[s] >= threshold_rank
        )
        keys.append(("positive", subs[0] if subs else "__unknown__"))
    counts = {}
    for k in keys:
        counts[k] = counts.get(k, 0) + 1
    w = np.ones(len(keys), dtype=float)
    pos_groups = max(len([k for k in counts if k[0] == "positive"]), 1)
    pos_total = max(sum(v for k, v in counts.items() if k[0] == "positive"), 1)
    for j, k in enumerate(keys):
        if k[0] == "positive":
            w[j] = pos_total / (pos_groups * counts[k])
    w /= max(float(w.mean()), EPS)
    return np.clip(w, 0.20, 6.0)


def fit_binary(kind, X3, y_step, step_pairs, seq_ids, threshold_rank):
    ii, hh, yy = flat_rows(seq_ids, threshold_rank, y_step)
    if len(ii) < 200 or yy.sum() < 20 or (len(yy) - yy.sum()) < 20:
        raise RuntimeError(f"Insufficient binary support stage={STAGES[threshold_rank]} n={len(ii)} pos={int(yy.sum())}")
    w = subtype_balanced_weights(ii, hh, yy, step_pairs, threshold_rank)
    return BinaryHazardHead(kind).fit(X3[ii, hh], yy, w)


def temporal_fit_cal(ids, cutoff, frac=0.75):
    ids = np.asarray(ids, dtype=int)
    if len(ids) < 20:
        return ids, ids
    ordered = ids[np.argsort(np.asarray(cutoff)[ids], kind="stable")]
    split = max(1, min(len(ordered) - 1, int(round(len(ordered) * frac))))
    return ordered[:split], ordered[split:]


def calibrate_threshold(head, X3, y_step, cal_ids, threshold_rank):
    ii, hh, yy = flat_rows(cal_ids, threshold_rank, y_step)
    p = head.predict_proba(X3[ii, hh])
    threshold, metrics = select_threshold(yy, p, FPR_BUDGET)
    return threshold, metrics


def subtype_positive_recall(head, threshold, X3, y_step, step_pairs, eval_ids, stage, subtype):
    k = STAGES.index(stage)
    total = correct = 0
    by_h = []
    for h in range(HORIZON):
        ids = np.asarray([
            int(i) for i in np.asarray(eval_ids, dtype=int)
            if y_step[int(i), h] >= k and (stage, subtype) in step_pairs[int(i), h]
        ], dtype=int)
        if len(ids):
            p = head.predict_proba(X3[ids, h])
            c = int(np.sum(p >= float(threshold)))
            total += len(ids); correct += c
            by_h.append({"horizon_minutes": h + 1, "support": int(len(ids)), "recall": c / len(ids)})
        else:
            by_h.append({"horizon_minutes": h + 1, "support": 0, "recall": None})
    return (None if total == 0 else correct / total), by_h, int(total)


def select_architecture(history, forecast, persistence, state_names, seq, y_step, step_pairs, labelled_development, reserve_pairs):
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No development subtype diagnostics")
    candidates = []
    feature_cache = {}
    for alpha in ALPHA_GRID:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        X3 = sample_features(history, stage_future, persistence, state_names)
        feature_cache[float(alpha)] = X3
        for kind in ("logistic", "histgb"):
            folds = []
            failed = None
            for row in diagnostics:
                stage = row["stage"]; subtype = row["subtype"]; k = STAGES.index(stage)
                train_ids = np.where(row["train_mask"])[0]
                eval_ids = np.where(row["eval_mask"])[0]
                fit_ids, cal_ids = temporal_fit_cal(train_ids, seq["cutoff"])
                try:
                    head = fit_binary(kind, X3, y_step, step_pairs, fit_ids, k)
                    threshold, cal_metric = calibrate_threshold(head, X3, y_step, cal_ids, k)
                    recall, by_h, support = subtype_positive_recall(
                        head, threshold, X3, y_step, step_pairs, eval_ids, stage, subtype
                    )
                except Exception as exc:
                    failed = f"{type(exc).__name__}: {exc}"
                    break
                if recall is not None:
                    folds.append({
                        "stage": stage, "subtype": subtype, "support": support,
                        "recall_at_1pct_cal_fpr": float(recall), "by_horizon": by_h,
                        "threshold": float(threshold), "calibration": cal_metric,
                    })
            if failed or not folds:
                continue
            recalls = np.asarray([r["recall_at_1pct_cal_fpr"] for r in folds], dtype=float)
            cal_fprs = np.asarray([r["calibration"]["fpr"] for r in folds], dtype=float)
            cal_ap = np.asarray([
                0.0 if r["calibration"]["pr_auc"] is None else r["calibration"]["pr_auc"] for r in folds
            ], dtype=float)
            row = {
                "future_weight_alpha": float(alpha), "model": kind, "folds": folds,
                "minimum_subtype_recall_at_1pct_cal_fpr": float(recalls.min()),
                "mean_subtype_recall_at_1pct_cal_fpr": float(recalls.mean()),
                "maximum_calibration_fpr": float(cal_fprs.max()),
                "mean_calibration_pr_auc": float(cal_ap.mean()),
            }
            row["development_viable"] = bool(
                row["minimum_subtype_recall_at_1pct_cal_fpr"] >= MIN_SUBTYPE_RECALL
                and row["maximum_calibration_fpr"] <= FPR_BUDGET + 1e-12
            )
            candidates.append(row)
    if not candidates:
        raise RuntimeError("No V87 candidate completed")
    candidates.sort(key=lambda r: (
        int(r["development_viable"]),
        r["minimum_subtype_recall_at_1pct_cal_fpr"],
        r["mean_subtype_recall_at_1pct_cal_fpr"],
        -r["maximum_calibration_fpr"],
        r["mean_calibration_pr_auc"],
        int(r["future_weight_alpha"] > 0),
        int(r["model"] == "histgb"),
    ), reverse=True)
    return candidates[0], candidates, feature_cache, diagnostics


def fit_final_heads(kind, X3, y_step, step_pairs, train_mask, validation_mask):
    train_ids = np.where(train_mask)[0]
    val_ids = np.where(validation_mask)[0]
    heads = []; thresholds = []; calibration = []
    for k, stage in enumerate(STAGES):
        head = fit_binary(kind, X3, y_step, step_pairs, train_ids, k)
        threshold, metric = calibrate_threshold(head, X3, y_step, val_ids, k)
        heads.append(head); thresholds.append(float(threshold))
        calibration.append({"stage_threshold": stage, **metric})
    return heads, np.asarray(thresholds, dtype=float), calibration


def monotonic_probabilities(heads, X3, ids):
    ids = np.asarray(ids, dtype=int)
    p = np.zeros((len(ids), HORIZON, len(STAGES)), dtype=float)
    for h in range(HORIZON):
        X = X3[ids, h]
        for k, head in enumerate(heads):
            p[:, h, k] = head.predict_proba(X)
        p[:, h, :] = np.minimum.accumulate(p[:, h, :], axis=1)
    p = np.maximum.accumulate(p, axis=1)
    return np.clip(p, 0.0, 1.0)


def evaluate_exposed(heads, thresholds, X3, y_step, step_pairs, test_masks):
    per_stage = {}
    recalls = []
    examples = []
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        k = STAGES.index(stage)
        ids = np.where(test_masks[stage])[0]
        pmono = monotonic_probabilities(heads, X3, ids) if len(ids) else np.zeros((0, HORIZON, len(STAGES)))
        total = correct = 0
        by_h = []
        for h in range(HORIZON):
            local = [
                j for j, i in enumerate(ids)
                if y_step[int(i), h] >= k and (stage, subtype) in step_pairs[int(i), h]
            ]
            if local:
                vals = pmono[np.asarray(local, dtype=int), h, k]
                c = int(np.sum(vals >= thresholds[k]))
                total += len(local); correct += c
                by_h.append({"horizon_minutes": h + 1, "support": len(local), "recall": c / len(local)})
            else:
                by_h.append({"horizon_minutes": h + 1, "support": 0, "recall": None})
        rec = None if total == 0 else correct / total
        if rec is not None:
            recalls.append(rec)
        per_stage[stage] = {
            "held_out_subtype": subtype, "threshold_event": f"reach >= {stage}",
            "support": int(total), "recall": rec, "by_horizon": by_h,
        }
        for j in range(min(2, len(ids))):
            examples.append({
                "stage": stage, "subtype": subtype,
                "trajectory": [
                    {
                        "horizon_minutes": h + 1,
                        "p_reach_or_beyond": {STAGES[k2]: float(pmono[j, h, k2]) for k2 in range(len(STAGES))}
                    } for h in range(HORIZON)
                ],
            })
    return {
        "per_stage": per_stage,
        "macro_recall_supported_subtypes": None if not recalls else float(np.mean(recalls)),
        "minimum_recall_supported_subtypes": None if not recalls else float(np.min(recalls)),
        "examples": examples,
    }


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
        ap.error("Output exists; V87 evidence is immutable")
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
        print(f"V87 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])

    winner, candidates, feature_cache, diagnostics = select_architecture(
        history, forecast, persistence, list(state_names), seq, y_step, step_pairs,
        labelled_development, reserve_pairs,
    )
    print("V87 DEVELOPMENT WINNER", json.dumps(winner, indent=2), flush=True)
    alpha = float(winner["future_weight_alpha"])
    X3 = feature_cache[alpha]
    heads, thresholds, calibration = fit_final_heads(
        winner["model"], X3, y_step, step_pairs, train, validation
    )
    learned = evaluate_exposed(heads, thresholds, X3, y_step, step_pairs, test_masks)

    pX3 = sample_features(history, persistence, persistence, list(state_names))
    pheads, pthresholds, pcal = fit_final_heads(
        winner["model"], pX3, y_step, step_pairs, train, validation
    )
    persistence_eval = evaluate_exposed(pheads, pthresholds, pX3, y_step, step_pairs, test_masks)

    fmse = mse(forecast, target, test_union); pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    lrec = learned["macro_recall_supported_subtypes"]
    prec = persistence_eval["macro_recall_supported_subtypes"]
    learned_future_used = alpha > 0.0
    beats = bool(lrec is not None and prec is not None and lrec > prec + 1e-12)
    dev_viable = bool(winner["development_viable"])

    report = {
        "protocol": "V87 monotonic cumulative attacker-progression hazard diagnostic",
        "claim_boundary": (
            "Models P(reach stage >= k by horizon h) from observed history plus predicted network state. "
            "The reused X-IIoTID V81/V82 reserve is exposed and is diagnostic only; it is not a fresh or "
            "verified pre-compromise result. Exploitation remains an Initial Access proxy."
        ),
        "dataset_sha256": sha256(csv), "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols, "feature_audit": feature_audit,
        "horizons_minutes": list(range(1, HORIZON + 1)),
        "false_positive_budget": FPR_BUDGET,
        "split": {
            "sequence_count": int(len(seq["X"])), "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()), "development_train": int(train.sum()),
            "development_validation": int(validation.sum()), "exposed_sequence_support": support,
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "winner": winner, "all_candidates": candidates,
            "world_gamma_winner": gamma_winner, "world_gamma_table": gamma_table,
            "development_diagnostic_subtypes": [
                {k: r[k] for k in ("stage", "subtype", "support", "same_stage_train_after_exclusion")}
                for r in diagnostics
            ],
        },
        "state_task": {
            "forecast_mse": fmse, "persistence_mse": pmse,
            "improvement_vs_persistence": state_gain,
        },
        "hazard_heads": {
            "stages": STAGES, "decision_thresholds": thresholds.tolist(),
            "development_calibration": calibration,
            "monotonic_contract": {
                "by_horizon_non_decreasing": True,
                "later_stage_threshold_not_above_earlier_stage": True,
            },
        },
        "exposed_diagnostic": {
            "learned_future": learned,
            "persistence_future": persistence_eval,
            "macro_recall_delta_vs_persistence": None if lrec is None or prec is None else float(lrec - prec),
            "persistence_development_calibration": pcal,
        },
        "release_gate": {
            "development_subtype_gate_80pct_recall_at_1pct_fpr_passed": dev_viable,
            "learned_future_contribution_used": bool(learned_future_used),
            "exposed_hazard_recall_beats_persistence": beats,
            "eligible_for_unseen_progression_claim": False,
            "fresh_claim_allowed": False,
            "reason": "A genuinely external sealed dataset/campaign is required for a fresh claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_selection": False,
            "reserve_metrics_used_for_hazard_architecture_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "attack_labels_are_world_model_inputs": False,
            "future_observed_state_used_at_inference": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": winner,
        "state_task": report["state_task"],
        "learned_exposed": learned,
        "persistence_exposed": persistence_eval,
        "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
