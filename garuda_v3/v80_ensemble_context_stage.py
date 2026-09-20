"""V80 frozen-fresh subtype benchmark with a stability-focused Garuda upgrade.

Architecture is fixed AFTER V79 sealed a fresh support-only reserve and BEFORE any V79
model score exists.  Changes motivated by the exposed/failed V78b diagnostic:

1. Three residual world models (seeds 42/43/44) are averaged at inference.
2. A final shrinkage toward persistence is selected ONLY on reserve-free validation
   state MSE; gamma=0 is allowed, so validation cannot be made worse than persistence.
3. Stage mapping consumes both the observed state history and the forecast trajectory:
   robust history summaries, predicted future summaries, and forecast deltas.  The
   mapper is trained on reserve-free DEVELOPMENT model predictions, not on V79 labels.
4. A fixed ExtraTrees ensemble is used for stage mapping to remove the seed-dependent
   stage-head instability observed in V78b.

V79 reserve subtypes are absent from world-model train/validation and from stage-mapper
fit, with a source-local 12-step overlap embargo. Test history may already contain the
held-out subtype, so this measures unseen-subtype future-state/stage generalisation
after observation, not clean-onset warning, verified pre-compromise lead time, or a
production zero-day.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    parse_time,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes

WORLD_SEEDS = (42, 43, 44)
EMBARGO_STEPS = HISTORY + HORIZON
GAMMA_GRID = (0.0, 0.25, 0.5, 0.75, 1.0)
EXPECTED_V79_FREEZE_SHA256 = "807f422b3351cf1f4ceb9ba7020239959b2e8b80ce7ed37b020f38fc604f8a8c"
EXPECTED_V79_SELECTED = {
    "Reconnaissance": "fuzzing",
    "Lateral Movement": "mqtt cloud broker subscription",
}
EXPECTED_V79_SUPPORT = {"Reconnaissance": 126, "Lateral Movement": 528}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    den = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / den
    margin = z * math.sqrt(p * (1.0 - p) / total + z2 / (4.0 * total * total)) / den
    return {
        "lower": float(max(0.0, center - margin)),
        "upper": float(min(1.0, center + margin)),
    }


def reserve_isolation(seq, selected):
    reserve_pairs = {(stage, subtype) for stage, subtype in selected.items()}
    touch = np.asarray([
        bool(reserve_pairs.intersection(set(h) | set(f)))
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)
    blocked = touch.copy()
    by_src = {}
    for i, (src, t) in enumerate(zip(seq["src"], seq["cutoff"])):
        by_src.setdefault(str(src), []).append((i, int(t)))
    for rows in by_src.values():
        touched_times = [t for i, t in rows if touch[i]]
        if not touched_times:
            continue
        embargo_times = set()
        for t in touched_times:
            for k in range(-EMBARGO_STEPS, EMBARGO_STEPS + 1):
                embargo_times.add(t + 60 * k)
        for i, t in rows:
            if t in embargo_times:
                blocked[i] = True
    return reserve_pairs, touch, blocked


def development_split(cutoff, allowed):
    ids = np.where(allowed)[0]
    times = np.unique(cutoff[ids])
    if len(ids) < 100 or len(times) < 20:
        raise RuntimeError(f"Insufficient reserve-free development support ids={len(ids)} times={len(times)}")
    boundary = int(times[int(0.80 * (len(times) - 1))])
    train = allowed & (cutoff <= boundary)
    validation = allowed & (cutoff > boundary)
    if int(train.sum()) < 50 or int(validation.sum()) < 20:
        raise RuntimeError(f"Development split too small train={int(train.sum())} validation={int(validation.sum())}")
    return train, validation, boundary


def fresh_test_masks(seq, selected, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    masks = {}
    diagnostics = {}
    for stage, subtype in selected.items():
        pair = (stage, subtype)
        other = reserve_pairs - {pair}
        mask = np.asarray([
            seq["y_stage"][i] == rank[stage]
            and pair in seq["future_pairs"][i]
            and not other.intersection(set(seq["history_pairs"][i]) | set(seq["future_pairs"][i]))
            for i in range(len(seq["X"]))
        ], dtype=bool)
        ids = np.where(mask)[0]
        masks[stage] = mask
        diagnostics[stage] = {
            "held_out_subtype": subtype,
            "test_sequences": int(len(ids)),
            "history_exposed": int(sum(pair in seq["history_pairs"][i] for i in ids)),
            "clean_onset": int(sum(pair not in seq["history_pairs"][i] for i in ids)),
        }
    return masks, diagnostics


def scaled_history(X, world):
    z = np.asarray(X, dtype=np.float32).copy()
    med = np.asarray(world["imputer_median"], dtype=np.float32)
    bad = ~np.isfinite(z)
    if bad.any():
        cols = np.where(bad)[-1]
        z[bad] = med[cols]
    flat = world["runtime_scaler"].transform(z.reshape(-1, z.shape[-1]))
    return flat.reshape(z.shape).astype(np.float32)


def trajectory_features(history_scaled, forecast, persistence):
    """Context + forecast features; all inputs are network-state values, never labels."""
    last = history_scaled[:, -1, :]
    hist_mean = history_scaled.mean(axis=1)
    hist_std = history_scaled.std(axis=1)
    recent_delta = history_scaled[:, -1, :] - history_scaled[:, -2, :]

    future_mean = forecast.mean(axis=1)
    future_std = forecast.std(axis=1)
    future_last = forecast[:, -1, :]
    delta = forecast - persistence
    delta_mean = delta.mean(axis=1)
    delta_last = delta[:, -1, :]
    delta_absmax = np.max(np.abs(delta), axis=1)

    return np.concatenate([
        last,
        hist_mean,
        hist_std,
        recent_delta,
        future_mean,
        future_std,
        future_last,
        delta_mean,
        delta_last,
        delta_absmax,
    ], axis=1).astype(np.float32)


def choose_validation_gamma(pred, persistence, target, validation):
    ids = np.where(validation)[0]
    rows = []
    for gamma in GAMMA_GRID:
        candidate = persistence + float(gamma) * (pred - persistence)
        mse = float(np.mean((candidate[ids] - target[ids]) ** 2))
        rows.append({"gamma": float(gamma), "mse": mse})
    rows.sort(key=lambda r: (r["mse"], r["gamma"]))
    return rows[0], rows


def add_strict_stage_metrics(metric):
    for row in metric["per_stage"].values():
        p = row["precision"]
        r = row["recall"]
        support = int(row["support"])
        if support <= 0:
            row["f1"] = None
        elif p is None or r is None or (p + r) == 0:
            row["f1"] = 0.0
        else:
            row["f1"] = float(2.0 * p * r / (p + r))
        row["recall_wilson95"] = wilson(row["tp"], row["tp"] + row["fn"])
    return metric


def mse(pred, target, mask):
    ids = np.where(mask)[0]
    if len(ids) == 0:
        return None
    return float(np.mean((pred[ids] - target[ids]) ** 2))


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
    if sha256(freeze_path) != EXPECTED_V79_FREEZE_SHA256:
        raise RuntimeError(f"V79 freeze hash drift: {sha256(freeze_path)}")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset hash differs from sealed V79 freeze")
    if frozen.get("selection_used_model_metrics") is not False or frozen.get("model_scored_reserve_before_freeze") is not False:
        raise RuntimeError("V79 is not a valid pre-model support-only freeze")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V79_SELECTED:
        raise RuntimeError("V79 selected reserve changed")
    if frozen.get("reserve_stage_support") != EXPECTED_V79_SUPPORT:
        raise RuntimeError("V79 reserve support changed")

    selected = dict(EXPECTED_V79_SELECTED)
    selected_stages = [s for s in STAGES if s in selected]
    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V80 evidence is immutable")
    out.mkdir(parents=True)

    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, state_features, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    subtype_col = find_subtype_column(df, binary_col, family_col)
    minute_pairs, subtype_src_col = build_minute_pairs(df, dt, binary, family, subtype_col)
    seq = make_sequences_with_subtypes(state, state_features, minute_pairs)

    reserve_pairs, reserve_touch, blocked = reserve_isolation(seq, selected)
    development = ~blocked
    train, validation, dev_boundary = development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)

    test_masks, test_diagnostics = fresh_test_masks(seq, selected, reserve_pairs)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage in selected_stages:
        test_union |= test_masks[stage]
    actual_support = {stage: int(test_masks[stage].sum()) for stage in selected_stages}
    if actual_support != EXPECTED_V79_SUPPORT:
        raise RuntimeError(f"Freeze/evaluator support drift expected={EXPECTED_V79_SUPPORT} actual={actual_support}")

    worlds = []
    for seed in WORLD_SEEDS:
        print(f"V80 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(
            seq["X"], seq["future"], train, validation, seed, epochs=args.epochs
        ))

    # Training split/scaler are identical across seeds; use seed 42 as canonical target/runtime transform.
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    ensemble_raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_validation_gamma(
        ensemble_raw, persistence, target, validation
    )
    gamma = gamma_winner["gamma"]
    forecast = persistence + gamma * (ensemble_raw - persistence)

    history_scaled = scaled_history(seq["X"], worlds[0])
    stage_X = trajectory_features(history_scaled, forecast, persistence)
    mapper_ids = np.where(labelled_development)[0]
    mapper_y = seq["y_stage"][mapper_ids]
    if len(set(mapper_y.tolist())) < 5:
        raise RuntimeError(f"Stage mapper development lacks classes: {sorted(set(mapper_y.tolist()))}")
    mapper = ExtraTreesClassifier(
        n_estimators=700,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=20260920,
        n_jobs=2,
    )
    mapper.fit(stage_X[mapper_ids], mapper_y)

    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    pred = mapper.predict(stage_X[test_ids])
    metric = add_strict_stage_metrics(exact_metrics(truth, pred))

    # Persistence ablation uses the same fixed mapper feature contract but replaces the
    # predicted future trajectory with persistence; observed-history context is retained.
    persistence_X = trajectory_features(history_scaled, persistence, persistence)
    persistence_pred = mapper.predict(persistence_X[test_ids])
    persistence_metric = add_strict_stage_metrics(exact_metrics(truth, persistence_pred))

    world_rows = {}
    for seed, world in zip(WORLD_SEEDS, worlds):
        world_rows[str(seed)] = {
            "validation_mse": float(world["validation_mse"]),
            "validation_persistence_mse": float(world["validation_persistence_mse"]),
            "validation_gate_passed": bool(world["state_gate_passed"]),
            "blend_alpha": float(world["blend_alpha"]),
            "trend_beta": float(world["trend_beta"]),
            "fresh_reserve_state_mse": mse(world["pred"], world["future_scaled"], test_union),
            "fresh_reserve_persistence_mse": mse(world["persistence"], world["future_scaled"], test_union),
        }

    ensemble_state_mse = mse(forecast, target, test_union)
    persistence_state_mse = mse(persistence, target, test_union)
    state_gain = (
        None if not persistence_state_mse
        else float((persistence_state_mse - ensemble_state_mse) / persistence_state_mse)
    )

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
            "tp": fm["tp"],
            "fp": fm["fp"],
            "fn": fm["fn"],
            "tn": fm["tn"],
            "persistence_ablation_recall": pm["recall"],
            "persistence_ablation_f1": pm["f1"],
        }

    report = {
        "protocol": "V80 sealed-V79 fresh subtype benchmark with three-world ensemble and context-aware forecast-stage mapper",
        "claim_boundary": (
            "V79 reserve subtypes were sealed by support only before this architecture existed and are absent from world-model train/validation and stage-mapper fit. Test histories may already contain the held-out subtype; this measures future-stage generalisation after observation, not clean-onset warning, pre-compromise lead time, or production zero-day defence."
        ),
        "dataset_sha256": sha256(csv),
        "sealed_v79_freeze_sha256": sha256(freeze_path),
        "selected_reserve_subtype_by_stage": selected,
        "fresh_test_support": actual_support,
        "verified_label_hierarchy": {
            "binary": binary_col,
            "lifecycle": family_col,
            "fine_subtype": subtype_col,
        },
        "architecture_frozen_before_v79_scoring": True,
        "architecture": {
            "world_seeds": list(WORLD_SEEDS),
            "world_ensemble": "mean of three persistence-anchored residual world forecasts",
            "validation_only_gamma_grid": list(GAMMA_GRID),
            "selected_gamma": gamma,
            "gamma_validation_table": gamma_table,
            "stage_mapper": "ExtraTreesClassifier on observed-history + forecast-trajectory + forecast-delta network-state summaries",
            "stage_mapper_estimators": 700,
            "stage_mapper_min_samples_leaf": 2,
            "stage_mapper_random_state": 20260920,
        },
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "source_group_column": src_col,
        "subtype_source_column": subtype_src_col,
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "development_train_validation_boundary": dev_boundary,
        },
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "reserve_plus_source_local_embargo_blocked_sequences": int(blocked.sum()),
            "embargo_steps_each_side": EMBARGO_STEPS,
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "stage_mapper_development": int(labelled_development.sum()),
            "fresh_test_sequences": int(test_union.sum()),
            "test_history_exposure": test_diagnostics,
        },
        "leakage_contract": {
            "v79_reserve_selected_with_model_metrics": False,
            "v79_reserve_scored_before_architecture_freeze": False,
            "v79_reserve_subtypes_seen_by_world_fit": False,
            "v79_reserve_subtypes_seen_by_world_validation": False,
            "v79_reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "test_used_for_gamma_selection": False,
            "test_used_for_stage_mapper_fit": False,
            "source_local_overlap_embargo_applied": True,
            "clean_onset_claim": False,
            "pre_compromise_claim": False,
        },
        "world_components": world_rows,
        "state_forecasting": {
            "validation_selected_gamma": gamma,
            "fresh_reserve_ensemble_mse": ensemble_state_mse,
            "fresh_reserve_persistence_mse": persistence_state_mse,
            "fresh_reserve_mse_improvement_vs_persistence": state_gain,
            "all_component_validation_gates_pass": all(w["state_gate_passed"] for w in worlds),
        },
        "forecast_stage_metrics": metric,
        "persistence_ablation_stage_metrics": persistence_metric,
        "per_stage_summary": per_stage,
        "summary": {
            "fresh_test_sequences": int(test_union.sum()),
            "evaluated_stage_count": len(selected_stages),
            "accuracy": metric["accuracy"],
            "macro_recall": metric["macro_recall_supported_classes"],
            "macro_precision": metric["macro_precision_supported_classes"],
            "macro_f1": metric["macro_f1_supported_classes"],
            "persistence_ablation_macro_f1": persistence_metric["macro_f1_supported_classes"],
            "forecast_minus_persistence_ablation_macro_f1_pp": float(
                100.0 * (metric["macro_f1_supported_classes"] - persistence_metric["macro_f1_supported_classes"])
            ),
            "state_mse_improvement_vs_persistence": state_gain,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "selected": selected,
        "split": report["split"],
        "architecture": report["architecture"],
        "state_forecasting": report["state_forecasting"],
        "per_stage": per_stage,
        "summary": report["summary"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
