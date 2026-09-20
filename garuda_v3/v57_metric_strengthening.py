"""V57 metric-strengthening experiment for joint-family generalisation.

V57 keeps the V55 leakage contract (Exploitation and C&C are excluded together
from fit/calibration/policy/selection) and strengthens the transferable history
signal without selecting on reserve outcomes.

Changes versus V55:
* richer deterministic temporal summaries computed from history only;
* two complementary transfer heads (ExtraTrees + HistGradientBoosting);
* fixed internal model seeds to remove classifier-seed noise from the outer
  world-model seed sweep;
* development-only fusion search with a focused 0.125 grid around the four
  strongest transferable components and finer benign-tail policy budgets.

Family labels remain evaluation/split metadata only; model inputs are network
history features. Reserve metrics are evaluated only after one configuration
has been frozen from pair-held-out development families.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier

from .v47_unseen_family import (
    FPR_BUDGET,
    SEEDS,
    binary_metrics,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    fpr_threshold,
    make_sequences,
    parse_time,
    sha256,
    temporal_masks,
)
from .v48_strict_runner import canonical_family_name
from .v48_unseen_fusion import EXPOSED_DEVELOPMENT_FAMILIES, tail_evidence
from .v54_joint_family_generalization import (
    DEFAULT_RESERVE,
    _future_presence,
    _joint_development_split,
    _joint_reserve_split,
    _metric,
    _prepare_world_components,
    build_pair_holdout_cache,
)

BASE_COMPONENTS = (
    "known_attack_transfer",
    "future_state_novelty",
    "predicted_delta_novelty",
    "transition_energy",
    "history_state_novelty",
)
RICH_COMPONENTS = ("rich_extra_transfer", "rich_hist_gradient_transfer")
COMPONENTS = BASE_COMPONENTS + RICH_COMPONENTS
FOCUSED_COMPONENTS = (
    "future_state_novelty",
    "transition_energy",
    "rich_extra_transfer",
    "rich_hist_gradient_transfer",
)
POLICY_BUDGETS = (0.0015, 0.0025, 0.0035, 0.005)
DEV_FPR_MARGIN = 0.0075
INTERNAL_RANDOM_STATE = 20260920


def rich_temporal_history_features(X):
    """History-only features designed for transfer, not family memorisation."""
    X = np.asarray(X, dtype=np.float64)
    if X.ndim != 3 or X.shape[1] < 2:
        raise ValueError(f"Expected [samples, history, features], got {X.shape}")

    flat = X.reshape(len(X), -1)
    mean = np.nanmean(X, axis=1)
    std = np.nanstd(X, axis=1)
    median = np.nanmedian(X, axis=1)
    minimum = np.nanmin(X, axis=1)
    maximum = np.nanmax(X, axis=1)
    value_range = maximum - minimum
    first = X[:, 0, :]
    last = X[:, -1, :]
    long_delta = last - first
    recent_delta = X[:, -1, :] - X[:, -2, :]

    mid = X.shape[1] // 2
    early = np.nanmean(X[:, :mid, :], axis=1)
    late = np.nanmean(X[:, mid:, :], axis=1)
    half_delta = late - early

    diff = np.diff(X, axis=1)
    diff_mean = np.nanmean(diff, axis=1)
    diff_std = np.nanstd(diff, axis=1)
    diff_abs_mean = np.nanmean(np.abs(diff), axis=1)
    diff_abs_max = np.nanmax(np.abs(diff), axis=1)

    if X.shape[1] >= 3:
        accel = np.diff(X, n=2, axis=1)
        accel_mean = np.nanmean(accel, axis=1)
        accel_std = np.nanstd(accel, axis=1)
    else:
        accel_mean = np.zeros_like(mean)
        accel_std = np.zeros_like(std)

    t = np.arange(X.shape[1], dtype=np.float64)
    tc = t - t.mean()
    denom = float(np.sum(tc * tc)) or 1.0
    slope = np.nansum((X - mean[:, None, :]) * tc[None, :, None], axis=1) / denom

    return np.concatenate(
        [
            flat,
            mean,
            std,
            median,
            minimum,
            maximum,
            value_range,
            first,
            last,
            long_delta,
            recent_delta,
            early,
            late,
            half_delta,
            diff_mean,
            diff_std,
            diff_abs_mean,
            diff_abs_max,
            accel_mean,
            accel_std,
            slope,
        ],
        axis=1,
    )


def _balanced_sample_weight(y):
    y = np.asarray(y, dtype=int)
    n = len(y)
    pos = int((y == 1).sum())
    neg = int((y == 0).sum())
    if pos == 0 or neg == 0:
        return np.ones(n, dtype=np.float64)
    return np.where(y == 1, n / (2.0 * pos), n / (2.0 * neg)).astype(np.float64)


def rich_transfer_scores(X, target, split):
    """Fit deterministic complementary nonlinear heads on leakage-safe training only."""
    tr = np.where(split["train"])[0]
    target = np.asarray(target, dtype=int)
    if len(tr) < 50 or len(np.unique(target[tr])) < 2:
        raise RuntimeError("V57 rich transfer heads require two-class development support")

    feat = rich_temporal_history_features(X)
    feat[~np.isfinite(feat)] = np.nan
    med = np.nanmedian(feat[tr], axis=0)
    med[~np.isfinite(med)] = 0.0
    bad = ~np.isfinite(feat)
    if bad.any():
        feat[bad] = med[np.where(bad)[1]]

    extra = ExtraTreesClassifier(
        n_estimators=720,
        max_features=0.60,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=INTERNAL_RANDOM_STATE,
        n_jobs=1,
    )
    extra.fit(feat[tr], target[tr])

    hgb = HistGradientBoostingClassifier(
        learning_rate=0.045,
        max_iter=180,
        max_leaf_nodes=31,
        min_samples_leaf=16,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=INTERNAL_RANDOM_STATE,
    )
    hgb.fit(feat[tr], target[tr], sample_weight=_balanced_sample_weight(target[tr]))

    return {
        "rich_extra_transfer": extra.predict_proba(feat)[:, 1],
        "rich_hist_gradient_transfer": hgb.predict_proba(feat)[:, 1],
    }


def extend_evidence(base_components, sequences, split):
    evidence = dict(base_components["evidence"])
    raw = rich_transfer_scores(sequences["X"], sequences["y"], split)
    cal = base_components["cal_benign"]
    for name in RICH_COMPONENTS:
        evidence[name] = tail_evidence(raw[name][cal], raw[name])
    return evidence


def _compositions(total, parts, prefix=()):
    if parts == 1:
        yield prefix + (total,)
        return
    for i in range(total + 1):
        yield from _compositions(total - i, parts - 1, prefix + (i,))


def candidate_weights():
    """Development-only search grid; never adapts to reserve metrics."""
    rows = []
    seen = set()

    def add(vals):
        vals = np.asarray(vals, dtype=np.float64)
        if np.any(vals < 0) or not np.isclose(vals.sum(), 1.0):
            return
        key = tuple(np.round(vals, 8))
        if key in seen:
            return
        seen.add(key)
        weights = {c: float(v) for c, v in zip(COMPONENTS, vals)}
        name = "_".join(f"{c}{int(round(100*v))}" for c, v in weights.items() if v > 0)
        rows.append({"name": name, "weights": weights})

    for counts in _compositions(4, len(COMPONENTS)):
        add([x / 4.0 for x in counts])

    focused_idx = [COMPONENTS.index(c) for c in FOCUSED_COMPONENTS]
    for counts in _compositions(8, len(focused_idx)):
        vals = np.zeros(len(COMPONENTS), dtype=np.float64)
        for idx, count in zip(focused_idx, counts):
            vals[idx] = count / 8.0
        add(vals)

    return rows


def _fused_from_matrix(matrix, weights):
    vec = np.asarray([weights[c] for c in COMPONENTS], dtype=np.float64)
    return matrix @ vec


def _prepare_selection_fold(row, evidence):
    """Precompute matrices reused by every fusion candidate/budget."""
    policy = row["components"]["policy_benign"]
    evaluation = row["positive"] | row["negative"]
    return {
        "withheld_pair": tuple(row["withheld_pair"]),
        "family": row["family"],
        "seed": int(row["seed"]),
        "state_gate_passed": bool(row["world"]["state_gate_passed"]),
        "policy_matrix": np.column_stack([evidence[c][policy] for c in COMPONENTS]),
        "eval_matrix": np.column_stack([evidence[c][evaluation] for c in COMPONENTS]),
        "eval_y": row["positive"][evaluation].astype(int),
    }


def _selection_row(fold, weights, budget):
    policy_score = _fused_from_matrix(fold["policy_matrix"], weights)
    eval_score = _fused_from_matrix(fold["eval_matrix"], weights)
    threshold = fpr_threshold(policy_score, budget)
    m = binary_metrics(fold["eval_y"], eval_score, threshold)
    return {
        "withheld_pair": list(fold["withheld_pair"]),
        "family": fold["family"],
        "seed": fold["seed"],
        "state_gate_passed": fold["state_gate_passed"],
        "recall": m.get("recall"),
        "fpr": m.get("fpr"),
        "precision": m.get("precision"),
        "f1": m.get("f1"),
        "threshold": float(threshold),
    }


def robust_objective(rows):
    state = [r for r in rows if r["state_gate_passed"]]
    safe = [r for r in state if r["fpr"] is not None and r["fpr"] <= DEV_FPR_MARGIN]
    gate = [r for r in safe if r["recall"] is not None and r["recall"] >= 0.80]
    recalls = np.asarray([float(r["recall"]) for r in safe if r["recall"] is not None], dtype=float)
    if len(recalls):
        q10 = float(np.quantile(recalls, 0.10))
        worst = float(np.min(recalls))
        mean = float(np.mean(recalls))
    else:
        q10 = worst = mean = 0.0
    max_fpr = max((float(r["fpr"]) for r in state if r["fpr"] is not None), default=1.0)
    return (len(gate), len(safe), q10, worst, mean, -max_fpr)


def choose_fusion(dev_cache, sequences, time_masks, reserve_mask):
    rich_by_pair = {}
    prepared_folds = []
    for row in dev_cache:
        pair = tuple(row["withheld_pair"])
        if pair not in rich_by_pair:
            split = _joint_development_split(sequences, time_masks, pair, reserve_mask)
            rich_by_pair[pair] = extend_evidence(row["components"], sequences, split)
        evidence = dict(row["components"]["evidence"])
        for name in RICH_COMPONENTS:
            evidence[name] = rich_by_pair[pair][name]
        prepared_folds.append(_prepare_selection_fold(row, evidence))

    candidates = []
    for cand in candidate_weights():
        for budget in POLICY_BUDGETS:
            folds = [_selection_row(fold, cand["weights"], budget) for fold in prepared_folds]
            obj = robust_objective(folds)
            candidates.append(
                {
                    "name": cand["name"],
                    "weights": cand["weights"],
                    "policy_budget": float(budget),
                    "objective": list(obj),
                    "folds": folds,
                }
            )

    candidates.sort(
        key=lambda c: tuple(c["objective"]) + (-c["policy_budget"],),
        reverse=True,
    )
    return candidates[0], candidates


def fused_extended(evidence, weights):
    score = np.zeros_like(next(iter(evidence.values())), dtype=np.float64)
    for name in COMPONENTS:
        score += float(weights.get(name, 0.0)) * evidence[name]
    return score


def evaluate_joint(sequences, time_masks, reserve, seeds, epochs, frozen):
    split = _joint_reserve_split(sequences, time_masks, reserve)
    positive = {f: _future_presence(sequences, f) for f in reserve}
    out = {f: {} for f in reserve}
    component_refs = {f: {c: [] for c in COMPONENTS} for f in reserve}

    rich_raw = rich_transfer_scores(sequences["X"], sequences["y"], split)

    for seed in seeds:
        print(f"V57 JOINT seed={seed}", flush=True)
        world, base = _prepare_world_components(sequences, split, seed, epochs)
        ev = dict(base["evidence"])
        cal = base["cal_benign"]
        for name in RICH_COMPONENTS:
            ev[name] = tail_evidence(rich_raw[name][cal], rich_raw[name])

        score = fused_extended(ev, frozen["weights"])
        policy = base["policy_benign"]
        threshold = fpr_threshold(score[policy], frozen["policy_budget"])

        for fam in reserve:
            m = _metric(positive[fam], split["test_negative"], score, threshold)
            state_mask = positive[fam] | split["test_negative"]
            mse = float(np.mean((world["pred"][state_mask] - world["future_scaled"][state_mask]) ** 2))
            pmse = float(np.mean((world["persistence"][state_mask] - world["future_scaled"][state_mask]) ** 2))
            out[fam][str(seed)] = {
                "threshold": float(threshold),
                "test": m,
                "state_gate_passed": bool(world["state_gate_passed"]),
                "test_state_mse": mse,
                "test_persistence_mse": pmse,
                "test_state_gate_passed": bool(mse < pmse),
            }
            for c in COMPONENTS:
                ct = fpr_threshold(ev[c][policy], frozen["policy_budget"])
                cm = _metric(positive[fam], split["test_negative"], ev[c], ct)
                component_refs[fam][c].append(
                    {"seed": int(seed), "threshold": float(ct), "test": cm}
                )

    def summary(rows):
        vals = list(rows.values())

        def st(k):
            x = [r["test"].get(k) for r in vals if r["test"].get(k) is not None]
            return {
                "mean": float(np.mean(x)) if x else None,
                "sd": float(np.std(x, ddof=1)) if len(x) > 1 else None,
            }

        return {
            "evaluated_seeds": len(vals),
            "recall": st("recall"),
            "fpr": st("fpr"),
            "precision": st("precision"),
            "f1": st("f1"),
            "state_gate_passed_all_seeds": all(r["state_gate_passed"] for r in vals),
            "test_state_gate_passed_all_seeds": all(r["test_state_gate_passed"] for r in vals),
            "reference_gate_passed_all_seeds": all(
                r["state_gate_passed"]
                and r["test"]["fpr"] <= FPR_BUDGET
                and r["test"]["recall"] >= 0.80
                for r in vals
            ),
        }

    return {
        "support": {
            "train": int(split["train"].sum()),
            "calibration": int(split["calibration"].sum()),
            "policy": int(split["policy"].sum()),
            "negative": int(split["test_negative"].sum()),
            "positive": {f: int(positive[f].sum()) for f in reserve},
        },
        "families": {
            f: {
                "seeds": out[f],
                "summary": summary(out[f]),
                "component_reference": component_refs[f],
            }
            for f in reserve
        },
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=12)
    p.add_argument("--seeds", nargs="+", type=int, default=list(SEEDS))
    p.add_argument("--reserve-families", nargs="+", default=list(DEFAULT_RESERVE))
    args = p.parse_args()
    if len(set(args.seeds)) < 3:
        p.error("At least three distinct outer world-model seeds required")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V57 evidence is immutable")
    out.mkdir(parents=True)

    csv = Path(args.csv)
    df = pd.read_csv(csv, low_memory=False)
    dt, date_col, ts_col, time_method = parse_time(df)
    binary, family, binary_col, family_col, profiles = detect_label_hierarchy(df)
    family = family.map(canonical_family_name)
    feature_cols, feature_audit = choose_network_numeric_features(df)
    state, names, src_col = build_minute_state(df, dt, binary, family, feature_cols)
    seq = make_sequences(state, names)
    masks, boundaries = temporal_masks(seq["cutoff"])

    available = sorted({x for steps in seq["step_families"] for fams in steps for x in fams})
    reserve = [canonical_family_name(x) for x in args.reserve_families]
    if any(x not in available for x in reserve):
        raise RuntimeError(f"Reserve missing; available={available}")
    exposed = [
        canonical_family_name(x)
        for x in EXPOSED_DEVELOPMENT_FAMILIES
        if canonical_family_name(x) in available and canonical_family_name(x) not in reserve
    ]

    dev, pair_support, reserve_mask = build_pair_holdout_cache(
        seq, masks, exposed, reserve, tuple(args.seeds), args.epochs
    )
    winner, candidates = choose_fusion(dev, seq, masks, reserve_mask)

    frozen = {
        "protocol": "V57 rich deterministic temporal transfer + pair-held-out development selection",
        "weights": winner["weights"],
        "policy_budget": winner["policy_budget"],
        "selection_candidate": winner["name"],
        "selection_objective": winner["objective"],
        "development_fpr_margin": DEV_FPR_MARGIN,
        "development_families": exposed,
        "reserve_families": reserve,
        "reserve_metrics_used_for_selection": False,
        "reserve_blocked_during_selection": True,
        "internal_temporal_model_seed": INTERNAL_RANDOM_STATE,
        "rich_feature_contract": "history-only temporal summaries; no family labels as inputs",
    }
    (out / "frozen_config.json").write_text(json.dumps(frozen, indent=2) + "\n")

    joint = evaluate_joint(seq, masks, reserve, tuple(args.seeds), args.epochs, frozen)
    report = {
        "protocol": frozen["protocol"],
        "claim_boundary": "Regression on previously exposed Exploitation/C&C; no fresh-holdout claim.",
        "source_sha256": sha256(csv),
        "seeds": list(args.seeds),
        "frozen_config": frozen,
        "development_pair_support": pair_support,
        "candidate_count": len(candidates),
        "top_candidates": [
            {k: c[k] for k in ("name", "weights", "policy_budget", "objective")}
            for c in candidates[:30]
        ],
        "joint_reserve_regression": joint,
        "automatic_containment_approved": False,
        "time": {
            "date_column": date_col,
            "timestamp_column": ts_col,
            "method": time_method,
            "boundaries": boundaries,
        },
        "labels": {"binary": binary_col, "family": family_col, "profiles": profiles},
        "network_only_feature_audit": {"raw_selected": feature_cols, "audit": feature_audit},
        "source_group_column": src_col,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(
        json.dumps(
            {
                "frozen_config": frozen,
                "joint": {f: v["summary"] for f, v in joint["families"].items()},
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
