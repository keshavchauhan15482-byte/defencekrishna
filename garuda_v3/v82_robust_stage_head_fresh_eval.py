"""V82 robust stage-head selection followed by one-shot V81 fresh-reserve evaluation.

V81 sealed a third untouched Class1 reserve before this architecture existed:
  Reconnaissance -> generic scanning
  Lateral Movement -> tcp relay

The V82 architecture is selected without V81 scores.  It trains a three-seed Garuda
world ensemble on V81-reserve-free sequences, caps the validation-selected residual
forecast contribution at 0.5 after the OOD state-MSE failure observed in the now-exposed
V80 diagnostic, and chooses a stage head by leave-one-development-subtype-out mapper
validation.  Candidate head/feature-view selection sees only reserve-free development
subtypes.  V81 is scored once after the winner is frozen in-memory.

This remains unseen-subtype future-stage generalisation after observation.  It is not a
clean-onset/pre-compromise benchmark and Exploitation remains an Initial Access proxy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import NearestCentroid
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import (
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    parse_time,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import (
    WORLD_SEEDS,
    add_strict_stage_metrics,
    development_split,
    fresh_test_masks,
    mse,
    reserve_isolation,
    scaled_history,
    trajectory_features,
)

EXPECTED_V81_FREEZE_SHA256 = "820aa7de8925d3d0812e1df3753c9f4a2c7da0f5d45efd3d16456b33e3e7d75f"
EXPECTED_V81_SELECTED = {
    "Reconnaissance": "generic scanning",
    "Lateral Movement": "tcp relay",
}
EXPECTED_V81_SUPPORT = {"Reconnaissance": 45, "Lateral Movement": 479}
GAMMA_GRID = (0.0, 0.25, 0.5)
MIN_DIAGNOSTIC_SUPPORT = 30


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def choose_gamma(pred, persistence, target, validation):
    ids = np.where(validation)[0]
    rows = []
    for gamma in GAMMA_GRID:
        candidate = persistence + float(gamma) * (pred - persistence)
        value = float(np.mean((candidate[ids] - target[ids]) ** 2))
        rows.append({"gamma": float(gamma), "validation_mse": value})
    rows.sort(key=lambda r: (r["validation_mse"], r["gamma"]))
    return rows[0], rows


def feature_views(full, state_dim):
    # trajectory_features has ten state_dim blocks:
    # last, hist_mean, hist_std, recent_delta, future_mean, future_std,
    # future_last, delta_mean, delta_last, delta_absmax.
    blocks = [full[:, i * state_dim:(i + 1) * state_dim] for i in range(10)]
    return {
        "full": full,
        # Compact keeps observed context + learned future state while dropping the
        # high-variance forecast-delta/detail blocks that hurt V80 OOD behaviour.
        "compact": np.concatenate(
            [blocks[0], blocks[1], blocks[3], blocks[4], blocks[6]], axis=1
        ).astype(np.float32),
    }


def model_templates():
    return {
        "logistic": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=0.35,
                class_weight="balanced",
                max_iter=3000,
                solver="lbfgs",
                random_state=20260921,
            )),
        ]),
        "lda_shrinkage": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LinearDiscriminantAnalysis(solver="lsqr", shrinkage="auto")),
        ]),
        "nearest_centroid": Pipeline([
            ("scale", StandardScaler()),
            ("clf", NearestCentroid(shrink_threshold=0.10)),
        ]),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=20260921,
            n_jobs=2,
        ),
    }


def mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    rows = []
    selected_stages = set(EXPECTED_V81_SELECTED)
    seen = Counter()
    for i in np.where(labelled_development)[0]:
        stage = STAGES[int(seq["y_stage"][i])]
        if stage not in selected_stages:
            continue
        for pair in seq["future_pairs"][i]:
            if pair[0] == stage and pair not in reserve_pairs:
                seen[pair] += 1
    for (stage, subtype), support in sorted(seen.items()):
        if support < MIN_DIAGNOSTIC_SUPPORT:
            continue
        pair = (stage, subtype)
        touch = np.asarray([
            pair in set(h) or pair in set(f)
            for h, f in zip(seq["history_pairs"], seq["future_pairs"])
        ], dtype=bool)
        eval_mask = np.asarray([
            bool(labelled_development[i])
            and int(seq["y_stage"][i]) == rank[stage]
            and pair in seq["future_pairs"][i]
            for i in range(len(seq["X"]))
        ], dtype=bool)
        train_mask = labelled_development & ~touch
        same_stage_train = int(np.sum(train_mask & (seq["y_stage"] == rank[stage])))
        if int(eval_mask.sum()) < MIN_DIAGNOSTIC_SUPPORT or same_stage_train < MIN_DIAGNOSTIC_SUPPORT:
            continue
        rows.append({
            "stage": stage,
            "subtype": subtype,
            "support": int(eval_mask.sum()),
            "same_stage_train_after_exclusion": same_stage_train,
            "train_mask": train_mask,
            "eval_mask": eval_mask,
        })
    return rows


def select_stage_head(views, seq, labelled_development, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    by_stage = Counter(row["stage"] for row in diagnostics)
    if by_stage["Reconnaissance"] < 2 or by_stage["Lateral Movement"] < 2:
        raise RuntimeError(f"Insufficient mapper subtype diagnostics: {dict(by_stage)}")

    candidates = []
    for view_name, X in views.items():
        for model_name, template in model_templates().items():
            folds = []
            for row in diagnostics:
                train_ids = np.where(row["train_mask"])[0]
                eval_ids = np.where(row["eval_mask"])[0]
                y_train = seq["y_stage"][train_ids]
                if len(np.unique(y_train)) < 5:
                    raise RuntimeError(
                        f"Diagnostic train lost stage class for {row['stage']}/{row['subtype']}"
                    )
                model = clone(template)
                model.fit(X[train_ids], y_train)
                pred = model.predict(X[eval_ids])
                target = rank[row["stage"]]
                recall = float(np.mean(pred == target))
                folds.append({
                    "stage": row["stage"],
                    "subtype": row["subtype"],
                    "support": int(len(eval_ids)),
                    "recall": recall,
                })
            recalls = np.asarray([f["recall"] for f in folds], dtype=float)
            recon = [f["recall"] for f in folds if f["stage"] == "Reconnaissance"]
            lateral = [f["recall"] for f in folds if f["stage"] == "Lateral Movement"]
            candidate = {
                "view": view_name,
                "model": model_name,
                "folds": folds,
                "minimum_subtype_recall": float(recalls.min()),
                "mean_subtype_recall": float(recalls.mean()),
                "recon_mean_recall": float(np.mean(recon)),
                "recon_min_recall": float(np.min(recon)),
                "lateral_mean_recall": float(np.mean(lateral)),
                "lateral_min_recall": float(np.min(lateral)),
            }
            candidates.append(candidate)

    # OOD objective: protect the worst held-out subtype first, then overall mean.
    # Ties prefer compact features and linear/prototype heads deterministically.
    view_pref = {"compact": 1, "full": 0}
    model_pref = {"logistic": 3, "lda_shrinkage": 2, "nearest_centroid": 1, "extra_trees": 0}
    candidates.sort(
        key=lambda c: (
            c["minimum_subtype_recall"],
            c["mean_subtype_recall"],
            c["recon_min_recall"],
            c["lateral_min_recall"],
            view_pref[c["view"]],
            model_pref[c["model"]],
        ),
        reverse=True,
    )
    winner = candidates[0]
    final = clone(model_templates()[winner["model"]])
    mapper_ids = np.where(labelled_development)[0]
    final.fit(views[winner["view"]][mapper_ids], seq["y_stage"][mapper_ids])
    return winner, candidates, final, diagnostics


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--freeze", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()

    csv = Path(args.csv)
    freeze_path = Path(args.freeze)
    frozen = json.loads(freeze_path.read_text())
    if sha256(freeze_path) != EXPECTED_V81_FREEZE_SHA256:
        raise RuntimeError(f"V81 freeze hash drift: {sha256(freeze_path)}")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset differs from V81 freeze")
    if frozen.get("selection_used_model_metrics") is not False:
        raise RuntimeError("V81 selection used model metrics")
    if frozen.get("model_training_or_scoring_performed") is not False:
        raise RuntimeError("V81 freshness audit unexpectedly trained/scored a model")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V81_SELECTED:
        raise RuntimeError("V81 selected reserve drift")
    if frozen.get("reserve_stage_support") != EXPECTED_V81_SUPPORT:
        raise RuntimeError("V81 support drift")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V82 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    minute_pairs, subtype_src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_features, minute_pairs)

    selected = dict(EXPECTED_V81_SELECTED)
    selected_stages = [s for s in STAGES if s in selected]
    reserve_pairs, reserve_touch, blocked = reserve_isolation(seq, selected)
    development = ~blocked
    train, validation, dev_boundary = development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)

    test_masks, test_diagnostics = fresh_test_masks(seq, selected, reserve_pairs)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage in selected_stages:
        test_union |= test_masks[stage]
    actual_support = {stage: int(test_masks[stage].sum()) for stage in selected_stages}
    if actual_support != EXPECTED_V81_SUPPORT:
        raise RuntimeError(f"V81 evaluator support drift: {actual_support}")

    worlds = []
    for seed in WORLD_SEEDS:
        print(f"V82 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(
            seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs
        ))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    ensemble_raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(ensemble_raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (ensemble_raw - persistence)

    history_scaled = scaled_history(seq["X"], worlds[0])
    full_features = trajectory_features(history_scaled, forecast, persistence)
    views = feature_views(full_features, seq["X"].shape[-1])

    # IMPORTANT: head/view selection happens entirely on reserve-free development.
    winner, candidate_table_rows, mapper, diagnostic_rows = select_stage_head(
        views, seq, labelled_development, reserve_pairs
    )
    print("V82 HEAD WINNER", json.dumps({
        k: winner[k] for k in [
            "view", "model", "minimum_subtype_recall", "mean_subtype_recall",
            "recon_mean_recall", "lateral_mean_recall"
        ]
    }, indent=2), flush=True)

    # One-shot scoring starts only after the architecture/head winner is fixed above.
    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    chosen_X = views[winner["view"]]
    pred = mapper.predict(chosen_X[test_ids])
    metric = add_strict_stage_metrics(exact_metrics(truth, pred))

    persistence_full = trajectory_features(history_scaled, persistence, persistence)
    persistence_views = feature_views(persistence_full, seq["X"].shape[-1])
    persistence_pred = mapper.predict(persistence_views[winner["view"]][test_ids])
    persistence_metric = add_strict_stage_metrics(exact_metrics(truth, persistence_pred))

    per_stage = {}
    for stage in selected_stages:
        fm = metric["per_stage"][stage]
        pm = persistence_metric["per_stage"][stage]
        per_stage[stage] = {
            **test_diagnostics[stage],
            "recall": fm["recall"],
            "precision": fm["precision"],
            "f1": fm["f1"],
            "recall_wilson95": fm["recall_wilson95"],
            "tp": fm["tp"], "fp": fm["fp"], "fn": fm["fn"], "tn": fm["tn"],
            "persistence_ablation_recall": pm["recall"],
            "persistence_ablation_f1": pm["f1"],
        }

    ensemble_state_mse = mse(forecast, target, test_union)
    persistence_state_mse = mse(persistence, target, test_union)
    state_gain = None if not persistence_state_mse else float(
        (persistence_state_mse - ensemble_state_mse) / persistence_state_mse
    )

    report = {
        "protocol": "V82 development-selected robust stage head -> one-shot V81 fresh subtype evaluation",
        "claim_boundary": (
            "V81 fresh subtypes were support-only sealed before V82 architecture work and are absent from world-model train/validation and stage-mapper fit. Head/view selection uses leave-one-development-subtype-out diagnostics only. Test histories may contain the held-out subtype, so this is stage generalisation after observation, not clean-onset/pre-compromise proof. Exploitation remains an Initial Access proxy."
        ),
        "dataset_sha256": sha256(csv),
        "v81_freeze_sha256": sha256(freeze_path),
        "selected_reserve_subtype_by_stage": selected,
        "verified_label_hierarchy": {
            "binary": binary_col,
            "lifecycle": family_col,
            "fine_subtype": subtype_col,
        },
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "reserve_plus_source_local_embargo_blocked_sequences": int(blocked.sum()),
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "development_stage_mapper": int(labelled_development.sum()),
            "fresh_test_support": actual_support,
            "fresh_test_history_exposure": test_diagnostics,
        },
        "architecture_selection": {
            "fresh_v81_metrics_used_for_selection": False,
            "gamma_grid_capped_after_exposed_v80_ood_diagnostic": list(GAMMA_GRID),
            "gamma_winner": gamma_winner,
            "gamma_table": gamma_table,
            "head_selection_method": "leave-one-development-fine-subtype-out; maximize worst subtype recall then mean recall",
            "diagnostic_subtypes": [
                {k: row[k] for k in ["stage", "subtype", "support", "same_stage_train_after_exclusion"]}
                for row in diagnostic_rows
            ],
            "winner": winner,
            "all_candidates": candidate_table_rows,
        },
        "world_models": {
            str(seed): {
                "validation_mse": float(world["validation_mse"]),
                "validation_persistence_mse": float(world["validation_persistence_mse"]),
                "validation_gate_passed": bool(world["state_gate_passed"]),
                "blend_alpha": float(world["blend_alpha"]),
                "trend_beta": float(world["trend_beta"]),
            }
            for seed, world in zip(WORLD_SEEDS, worlds)
        },
        "fresh_stage_metrics": metric,
        "persistence_ablation_stage_metrics": persistence_metric,
        "per_stage_summary": per_stage,
        "fresh_reserve_ensemble_state_mse": ensemble_state_mse,
        "fresh_reserve_persistence_state_mse": persistence_state_mse,
        "fresh_reserve_state_mse_improvement_vs_persistence": state_gain,
        "leakage_contract": {
            "v81_selection_used_model_metrics": False,
            "v81_subtypes_seen_by_world_model_fit": False,
            "v81_subtypes_seen_by_world_validation": False,
            "v81_subtypes_seen_by_stage_mapper_fit": False,
            "fresh_v81_metrics_used_for_gamma_selection": False,
            "fresh_v81_metrics_used_for_head_selection": False,
            "attack_labels_are_world_model_inputs": False,
            "clean_onset_claim": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": report["architecture_selection"]["winner"],
        "gamma": gamma_winner,
        "fresh_test_support": actual_support,
        "per_stage": per_stage,
        "macro": {
            "accuracy": metric["accuracy"],
            "macro_f1": metric["macro_f1_supported_classes"],
            "macro_recall": metric["macro_recall_supported_classes"],
            "macro_precision": metric["macro_precision_supported_classes"],
            "persistence_macro_f1": persistence_metric["macro_f1_supported_classes"],
        },
        "state_mse": {
            "forecast": ensemble_state_mse,
            "persistence": persistence_state_mse,
            "improvement": state_gain,
        },
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
