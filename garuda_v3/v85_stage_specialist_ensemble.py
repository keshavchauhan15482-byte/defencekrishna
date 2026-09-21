"""V85 stage-specialist ensemble diagnostic for Garuda future-state forecasting.

V85 addresses V84's key failure: one global multiclass head could not generalise across
heterogeneous Reconnaissance and Lateral Movement subtypes. It keeps the same sealed
V81/V82 reserve boundary (already exposed, therefore diagnostic only) and selects two
stage-specific binary expert ensembles using reserve-free leave-subtype-out folds.

Each expert may use a different progression view and learned-future trust alpha. Expert
pairs and decision thresholds are chosen only from development folds, with a held-out
chronological negative audit used to constrain false positives. A five-stage fallback
head handles stages without enough subtype diversity for specialist selection.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import WORLD_SEEDS, add_strict_stage_metrics, development_split, fresh_test_masks, mse, reserve_isolation, scaled_history
from .v82_robust_stage_head_fresh_eval import EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT, choose_gamma, mapper_diagnostic_pairs
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v84_stage_progression_robustness import FlatStageHead, probability_metrics, progression_views

TARGET_STAGES = ("Reconnaissance", "Lateral Movement")
ALPHAS = (0.0, 0.10, 0.25, 0.50, 1.0)
THRESHOLDS = (0.20, 0.30, 0.40, 0.50, 0.60)
MIN_SUBTYPE_RECALL = 0.20
MAX_NEGATIVE_FPR = 0.10
NEGATIVE_AUDIT_FRACTION = 0.20
EPS = 1e-6


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def make_binary(kind: str):
    if kind.startswith("logistic_c"):
        C = float(kind.split("c", 1)[1].replace("p", "."))
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=3000, solver="liblinear", random_state=20260921)),
        ])
    if kind == "lda_shrinkage":
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LinearDiscriminantAnalysis(solver="lsqr", shrinkage="auto")),
        ])
    if kind.startswith("extra_trees_leaf"):
        leaf = int(kind.rsplit("leaf", 1)[1])
        return ExtraTreesClassifier(
            n_estimators=500, max_features="sqrt", min_samples_leaf=leaf,
            class_weight="balanced", random_state=20260921 + leaf, n_jobs=2,
        )
    raise KeyError(kind)


def positive_proba(model, X):
    p = np.asarray(model.predict_proba(X), dtype=float)
    if hasattr(model, "classes_"):
        classes = np.asarray(model.classes_, dtype=int)
    else:
        classes = np.asarray(model.named_steps[list(model.named_steps)[-1]].classes_, dtype=int)
    if 1 not in classes:
        return np.zeros(len(X), dtype=float)
    return p[:, int(np.where(classes == 1)[0][0])]


def view_cache(history, forecast, persistence, state_names):
    cache = {}
    audit = None
    for alpha in ALPHAS:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        views, a = progression_views(history, stage_future, persistence, state_names)
        cache[float(alpha)] = views
        if audit is None:
            audit = a
    return cache, audit


def chronological_negative_audit(seq, labelled_development, target_rank):
    neg = labelled_development & (seq["y_stage"] >= 0) & (seq["y_stage"] != target_rank)
    ids = np.where(neg)[0]
    if len(ids) < 100:
        raise RuntimeError("Insufficient negatives for specialist audit")
    times = np.asarray(seq["cutoff"])[ids]
    boundary = int(np.quantile(times, 1.0 - NEGATIVE_AUDIT_FRACTION))
    audit = neg & (np.asarray(seq["cutoff"]) >= boundary)
    if int(audit.sum()) < 40:
        raise RuntimeError("Chronological negative audit too small")
    return audit, boundary


def candidate_specs():
    kinds = ("logistic_c0p05", "logistic_c0p2", "lda_shrinkage", "extra_trees_leaf3", "extra_trees_leaf8")
    views = ("relative_full", "relative_no_ports", "semantic_pool")
    return [
        {"alpha": float(a), "view": v, "model": k, "name": f"a{a:g}:{v}:{k}"}
        for a in ALPHAS for v in views for k in kinds
    ]


def fit_score_candidate(spec, stage, rows, cache, seq, labelled_development, neg_audit):
    rank = STAGES.index(stage)
    fold_rows = []
    for row in rows:
        train_mask = row["train_mask"] & labelled_development & ~neg_audit
        train_ids = np.where(train_mask)[0]
        pos_ids = np.where(row["eval_mask"])[0]
        neg_ids = np.where(neg_audit)[0]
        y = (seq["y_stage"][train_ids] == rank).astype(int)
        if len(np.unique(y)) != 2 or len(pos_ids) == 0:
            raise RuntimeError(f"Binary fold invalid for {stage}/{row['subtype']}")
        X = cache[spec["alpha"]][spec["view"]]
        model = make_binary(spec["model"])
        model.fit(X[train_ids], y)
        fold_rows.append({
            "stage": stage,
            "subtype": row["subtype"],
            "support": int(len(pos_ids)),
            "positive_scores": positive_proba(model, X[pos_ids]),
            "negative_scores": positive_proba(model, X[neg_ids]),
        })
    return fold_rows


def combo_metrics(combo, scored, threshold):
    folds = []
    for fi in range(len(next(iter(scored.values())))):
        pos = np.max(np.vstack([scored[name][fi]["positive_scores"] for name in combo]), axis=0)
        neg = np.max(np.vstack([scored[name][fi]["negative_scores"] for name in combo]), axis=0)
        base = scored[combo[0]][fi]
        folds.append({
            "stage": base["stage"], "subtype": base["subtype"], "support": base["support"],
            "recall": float(np.mean(pos >= threshold)),
            "negative_fpr": float(np.mean(neg >= threshold)),
        })
    recalls = np.asarray([f["recall"] for f in folds], dtype=float)
    fprs = np.asarray([f["negative_fpr"] for f in folds], dtype=float)
    return {
        "experts": list(combo), "threshold": float(threshold), "folds": folds,
        "minimum_subtype_recall": float(recalls.min()),
        "mean_subtype_recall": float(recalls.mean()),
        "maximum_negative_fpr": float(fprs.max()),
        "mean_negative_fpr": float(fprs.mean()),
    }


def select_specialist(stage, diagnostics, cache, seq, labelled_development):
    rank = STAGES.index(stage)
    rows = [r for r in diagnostics if r["stage"] == stage]
    if len(rows) < 2:
        raise RuntimeError(f"Need at least two development subtypes for specialist {stage}")
    neg_audit, neg_boundary = chronological_negative_audit(seq, labelled_development, rank)
    specs = candidate_specs()
    scored = {}
    singles = []
    for spec in specs:
        fold_rows = fit_score_candidate(spec, stage, rows, cache, seq, labelled_development, neg_audit)
        scored[spec["name"]] = fold_rows
        m = combo_metrics((spec["name"],), scored, 0.50)
        m["uses_learned_future"] = bool(spec["alpha"] > 0.0)
        singles.append(m)
    singles.sort(key=lambda r: (r["minimum_subtype_recall"], r["mean_subtype_recall"], -r["maximum_negative_fpr"]), reverse=True)
    shortlist = [r["experts"][0] for r in singles[:14]]
    by_name = {s["name"]: s for s in specs}
    trials = []
    combos = [(x,) for x in shortlist] + list(itertools.combinations(shortlist, 2))
    for combo in combos:
        for threshold in THRESHOLDS:
            m = combo_metrics(combo, scored, threshold)
            m["uses_learned_future"] = any(by_name[n]["alpha"] > 0.0 for n in combo)
            m["development_viable"] = bool(
                m["minimum_subtype_recall"] >= MIN_SUBTYPE_RECALL
                and m["maximum_negative_fpr"] <= MAX_NEGATIVE_FPR
            )
            trials.append(m)
    trials.sort(key=lambda r: (
        int(r["development_viable"]),
        r["minimum_subtype_recall"],
        r["mean_subtype_recall"],
        -r["maximum_negative_fpr"],
        int(r["uses_learned_future"]),
        -len(r["experts"]),
    ), reverse=True)
    winner = trials[0]
    winner["expert_specs"] = [by_name[n] for n in winner["experts"]]
    winner["negative_audit_boundary"] = int(neg_boundary)
    winner["negative_audit_support"] = int(neg_audit.sum())

    final_models = []
    ids = np.where(labelled_development)[0]
    y = (seq["y_stage"][ids] == rank).astype(int)
    for spec in winner["expert_specs"]:
        X = cache[spec["alpha"]][spec["view"]]
        model = make_binary(spec["model"])
        model.fit(X[ids], y)
        final_models.append((spec, model))
    return winner, trials[:30], final_models


def specialist_score(models, cache, ids):
    scores = []
    for spec, model in models:
        X = cache[spec["alpha"]][spec["view"]][ids]
        scores.append(positive_proba(model, X))
    return np.max(np.vstack(scores), axis=0)


def combined_probabilities(base_model, base_cache, specialist_models, specialist_winners, cache, ids):
    base_X = base_cache[0.10]["relative_no_ports"][ids]
    p = np.asarray(base_model.predict_proba(base_X), dtype=float)
    for stage in TARGET_STAGES:
        rank = STAGES.index(stage)
        score = specialist_score(specialist_models[stage], cache, ids)
        threshold = float(specialist_winners[stage]["threshold"])
        odds = np.clip(score, EPS, 1.0 - EPS) / np.clip(1.0 - score, EPS, 1.0)
        t_odds = threshold / max(EPS, 1.0 - threshold)
        calibrated = odds / (odds + t_odds)
        p[:, rank] = np.maximum(p[:, rank], calibrated)
    p = np.clip(p, EPS, None)
    return p / p.sum(axis=1, keepdims=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--epochs", type=int, default=18)
    args = ap.parse_args()

    csv = Path(args.csv); freeze = Path(args.freeze); out = Path(args.output)
    frozen = json.loads(freeze.read_text())
    if sha256(freeze) != EXPECTED_V81_FREEZE_SHA256: raise RuntimeError("V81 freeze hash drift")
    if frozen.get("dataset_sha256") != sha256(csv): raise RuntimeError("Dataset differs from V81 freeze")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V81_SELECTED: raise RuntimeError("V81 selected reserve drift")
    if frozen.get("selection_used_model_metrics") is not False or frozen.get("model_training_or_scoring_performed") is not False: raise RuntimeError("V81 freeze is not support-only")
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        if subtype not in EXPOSED_SUBTYPE_REGISTRY.get(stage, []): raise RuntimeError("Exposed reserve registry drift")
    if out.exists(): ap.error("Output exists; V85 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(csv, low_memory=False)
    dt, *_ = parse_time(df)
    binary, family, binary_col, family_col, _ = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_names, _ = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    minute_pairs, _ = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_names, minute_pairs)

    reserve_pairs, reserve_touch, blocked = reserve_isolation(seq, dict(EXPECTED_V81_SELECTED))
    development = ~blocked
    train, validation, boundary = development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    test_masks, test_diag = fresh_test_masks(seq, dict(EXPECTED_V81_SELECTED), reserve_pairs)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage in EXPECTED_V81_SELECTED: test_union |= test_masks[stage]
    support = {s: int(test_masks[s].sum()) for s in EXPECTED_V81_SELECTED}
    if support != EXPECTED_V81_SUPPORT: raise RuntimeError(f"Exposed diagnostic support drift: {support}")

    worlds = []
    for seed in WORLD_SEEDS:
        print(f"V85 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    forecast = persistence + float(gamma_winner["gamma"]) * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])
    learned_cache, feature_view_audit = view_cache(history, forecast, persistence, list(state_names))
    persistence_cache, _ = view_cache(history, persistence, persistence, list(state_names))

    specialist_winners = {}; specialist_trials = {}; specialist_models = {}
    for stage in TARGET_STAGES:
        w, trials, models = select_specialist(stage, diagnostics, learned_cache, seq, labelled_development)
        specialist_winners[stage] = w; specialist_trials[stage] = trials; specialist_models[stage] = models
        print("V85 SPECIALIST", stage, json.dumps({k:w[k] for k in ("experts","threshold","minimum_subtype_recall","mean_subtype_recall","maximum_negative_fpr","development_viable","uses_learned_future")}, indent=2), flush=True)

    mapper_ids = np.where(labelled_development)[0]
    base_model = FlatStageHead(0.10).fit(learned_cache[0.10]["relative_no_ports"][mapper_ids], seq["y_stage"][mapper_ids])

    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    learned_p = combined_probabilities(base_model, learned_cache, specialist_models, specialist_winners, learned_cache, test_ids)
    persistence_p = combined_probabilities(base_model, persistence_cache, specialist_models, specialist_winners, persistence_cache, test_ids)
    learned_pred = learned_p.argmax(axis=1); persistence_pred = persistence_p.argmax(axis=1)
    learned_metric = add_strict_stage_metrics(exact_metrics(truth, learned_pred))
    persistence_metric = add_strict_stage_metrics(exact_metrics(truth, persistence_pred))
    learned_probq = probability_metrics(truth, learned_p)
    persistence_probq = probability_metrics(truth, persistence_p)

    fmse = mse(forecast, target, test_union); pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    lf1 = float(learned_metric["macro_f1_supported_classes"]); pf1 = float(persistence_metric["macro_f1_supported_classes"])
    dev_viable = all(bool(specialist_winners[s]["development_viable"]) for s in TARGET_STAGES)
    uses_future = any(bool(specialist_winners[s]["uses_learned_future"]) for s in TARGET_STAGES)

    public_diag = [{k:r[k] for k in ("stage","subtype","support","same_stage_train_after_exclusion")} for r in diagnostics]
    report = {
        "protocol": "V85 stage-specialist future-state ensemble diagnostic",
        "claim_boundary": "V85 reuses the already-exposed V81/V82 reserve and is diagnostic only. Specialist architecture, expert pairs and thresholds are selected only on reserve-free development subtype folds plus chronological negative audits.",
        "dataset_sha256": sha256(csv), "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols, "feature_audit": feature_audit, "progression_feature_audit": feature_view_audit,
        "split": {
            "sequence_count": int(len(seq["X"])), "reserve_touch_sequences": int(reserve_touch.sum()), "blocked_sequences": int(blocked.sum()),
            "development_train": int(train.sum()), "development_validation": int(validation.sum()), "development_stage_mapper": int(labelled_development.sum()),
            "development_boundary": int(boundary), "exposed_diagnostic_support": support, "history_exposure": test_diag,
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "world_gamma_winner": gamma_winner, "world_gamma_table": gamma_table,
            "development_diagnostic_subtypes": public_diag,
            "specialist_viability_thresholds": {"minimum_subtype_recall": MIN_SUBTYPE_RECALL, "maximum_negative_fpr": MAX_NEGATIVE_FPR},
            "specialist_winners": specialist_winners, "top_specialist_trials": specialist_trials,
            "fallback_head": {"view":"relative_no_ports", "future_weight_alpha":0.10, "model":"flat_logistic_c0.10"},
        },
        "state_task": {"forecast_mse": fmse, "persistence_mse": pmse, "improvement_vs_persistence": state_gain},
        "stage_task_exposed_diagnostic": {
            "learned_forecast": learned_metric, "persistence_state": persistence_metric,
            "macro_f1_delta_vs_persistence": float(lf1-pf1),
            "probability_quality_learned": learned_probq, "probability_quality_persistence": persistence_probq,
        },
        "release_gate": {
            "development_subtype_viability_passed": dev_viable,
            "learned_future_contribution_used": uses_future,
            "stage_task_beats_persistence_passed": bool(lf1 > pf1 + 1e-12),
            "release_eligible_for_unseen_subtype_stage_claim": bool(dev_viable and uses_future and lf1 > pf1 + 1e-12),
            "fresh_claim_allowed": False,
            "reason": "Exposed diagnostic only; a newly sealed dataset/campaign is required for a fresh stage-generalisation release claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_gamma_selection": False,
            "reserve_metrics_used_for_specialist_selection": False,
            "reserve_metrics_used_for_threshold_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "chronological_negative_audit_used": True,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out/"summary.json").write_text(json.dumps(report, indent=2, allow_nan=False)+"\n")
    print(json.dumps({
        "specialists": {s:{k:specialist_winners[s][k] for k in ("experts","threshold","minimum_subtype_recall","maximum_negative_fpr","development_viable","uses_learned_future")} for s in TARGET_STAGES},
        "state_task": report["state_task"], "stage_macro_f1": lf1, "persistence_macro_f1": pf1, "release_gate": report["release_gate"]
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
