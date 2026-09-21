"""V85 transition-aware robust stage diagnostic for Garuda.

V85 advances V84 with three leakage-safe ideas:
1. subgroup-balanced fitting so dominant fine subtypes cannot control a stage head,
2. an observed-history current-stage estimator learned from network state only, and
3. a learned development-only lifecycle transition prior fused with Garuda future-state evidence.

The V81/V82 reserve is already exposed, so this remains a diagnostic benchmark. It does
not claim a fresh zero-day, verified pre-compromise warning, or exact MITRE Initial Access.
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
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import (
    WORLD_SEEDS, add_strict_stage_metrics, development_split, fresh_test_masks,
    mse, reserve_isolation, scaled_history,
)
from .v82_robust_stage_head_fresh_eval import (
    EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT,
    choose_gamma, mapper_diagnostic_pairs,
)
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v84_stage_progression_robustness import progression_views, probability_metrics

MIN_WORST_SUBTYPE_RECALL = 0.20
MIN_RECON_MEAN_RECALL = 0.20
MIN_LATERAL_MEAN_RECALL = 0.20
STAGE_FUSION_ALPHA_GRID = (0.0, 0.10, 0.50, 1.0)
TRANSITION_BETA_GRID = (0.0, 0.25, 0.50, 0.75, 1.0)
TEMPERATURE_GRID = (0.50, 0.75, 1.00, 1.25, 1.50, 2.00, 3.00)
EPS = 1e-8


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _port_mask(state_names):
    return np.asarray(["port" not in str(n).lower() for n in state_names], dtype=bool)


def history_features(history: np.ndarray, state_names: list[str]) -> np.ndarray:
    """Subtype-invariant observed-history descriptors; no attack labels are inputs."""
    keep = _port_mask(state_names)
    h = history[:, :, keep]
    last = h[:, -1, :]
    mean = h.mean(axis=1)
    std = h.std(axis=1)
    recent = h[:, -1, :] - h[:, -2, :]
    if h.shape[1] >= 3:
        accel = (h[:, -1, :] - h[:, -2, :]) - (h[:, -2, :] - h[:, -3, :])
    else:
        accel = np.zeros_like(recent)
    t = np.arange(h.shape[1], dtype=np.float32)
    tc = t - t.mean()
    denom = float(np.sum(tc * tc))
    slope = np.einsum("t,ntd->nd", tc, h - h.mean(axis=1, keepdims=True)) / max(denom, EPS)
    scale = np.maximum(std, 0.25)
    blocks = [last, mean, std, recent / scale, accel / scale, slope / scale]
    return np.concatenate([np.clip(x, -8.0, 8.0) for x in blocks], axis=1).astype(np.float32)


def current_stage_targets(seq) -> np.ndarray:
    rank = {stage: i for i, stage in enumerate(STAGES)}
    out = np.full(len(seq["X"]), -1, dtype=np.int16)
    for i, pairs in enumerate(seq["history_pairs"]):
        vals = [rank[s] for s, _ in pairs if s in rank]
        if vals:
            out[i] = max(vals)
    return out


def _primary_subtype(pairs, stage_idx: int) -> str:
    stage = STAGES[int(stage_idx)]
    vals = sorted({str(sub) for s, sub in pairs if s == stage})
    return vals[0] if vals else "__none__"


def subgroup_weights(seq, ids: np.ndarray, y: np.ndarray, pair_key: str) -> np.ndarray:
    """Equalize fine-subtype influence within each stage, then normalize mean weight to 1."""
    keys = [(int(y[i]), _primary_subtype(seq[pair_key][i], int(y[i]))) for i in ids]
    counts = Counter(keys)
    stage_counts = Counter(int(y[i]) for i in ids)
    stage_groups = Counter(k[0] for k in counts)
    w = []
    for i, key in zip(ids, keys):
        stage = int(y[i])
        group_mass = 1.0 / max(stage_groups[stage], 1)
        inv_group = 1.0 / max(counts[key], 1)
        stage_mass = 1.0 / max(stage_counts[stage], 1)
        w.append(math.sqrt(group_mass * inv_group / max(stage_mass, EPS)))
    w = np.asarray(w, dtype=float)
    w /= max(float(w.mean()), EPS)
    return np.clip(w, 0.20, 6.0)


class WeightedFlatHead:
    def __init__(self, C: float):
        self.C = float(C)
        self.model = Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=self.C, class_weight="balanced", max_iter=5000,
                solver="lbfgs", random_state=20260921,
            )),
        ])

    def fit(self, X, y, sample_weight=None):
        kw = {} if sample_weight is None else {"clf__sample_weight": sample_weight}
        self.model.fit(X, y, **kw)
        return self

    def predict_proba(self, X):
        raw = self.model.predict_proba(X)
        classes = np.asarray(self.model.named_steps["clf"].classes_, dtype=int)
        out = np.zeros((len(X), len(STAGES)), dtype=float)
        out[:, classes] = raw
        return np.clip(out, EPS, 1.0)


class WeightedOrdinalHead:
    def __init__(self, C: float):
        self.C = float(C)
        self.models = []

    def fit(self, X, y, sample_weight=None):
        y = np.asarray(y, dtype=int)
        self.models = []
        for threshold in range(len(STAGES) - 1):
            binary = (y > threshold).astype(int)
            if len(np.unique(binary)) != 2:
                raise RuntimeError(f"Ordinal threshold {threshold} lacks both classes")
            model = Pipeline([
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(
                    C=self.C, class_weight="balanced", max_iter=5000,
                    solver="lbfgs", random_state=20260921 + threshold,
                )),
            ])
            kw = {} if sample_weight is None else {"clf__sample_weight": sample_weight}
            model.fit(X, binary, **kw)
            self.models.append(model)
        return self

    def predict_proba(self, X):
        q = np.column_stack([m.predict_proba(X)[:, 1] for m in self.models])
        q = np.minimum.accumulate(q, axis=1)
        p = np.empty((len(X), len(STAGES)), dtype=float)
        p[:, 0] = 1.0 - q[:, 0]
        for k in range(1, len(STAGES) - 1):
            p[:, k] = q[:, k - 1] - q[:, k]
        p[:, -1] = q[:, -1]
        p = np.clip(p, EPS, 1.0)
        return p / p.sum(axis=1, keepdims=True)


def make_future_head(kind: str):
    if kind == "flat_c0p1":
        return WeightedFlatHead(0.1)
    if kind == "flat_c0p5":
        return WeightedFlatHead(0.5)
    if kind == "ordinal_c0p5":
        return WeightedOrdinalHead(0.5)
    raise KeyError(kind)


def fit_current_head(X_hist, y_current, seq, train_ids):
    ids = np.asarray([i for i in train_ids if y_current[i] >= 0], dtype=int)
    if len(ids) < 100 or len(np.unique(y_current[ids])) < 2:
        return None
    w = subgroup_weights(seq, ids, y_current, "history_pairs")
    return WeightedFlatHead(0.25).fit(X_hist[ids], y_current[ids], w)


def transition_matrix(y_current, y_future, ids):
    """Development-only transition model with soft lifecycle-order regularization."""
    counts = np.ones((len(STAGES), len(STAGES)), dtype=float) * 0.5
    for i in ids:
        a, b = int(y_current[i]), int(y_future[i])
        if a >= 0 and b >= 0:
            counts[a, b] += 1.0
    for a in range(len(STAGES)):
        for b in range(len(STAGES)):
            if b < a:
                counts[a, b] *= 0.25
            elif b > a + 2:
                counts[a, b] *= 0.50
    return counts / counts.sum(axis=1, keepdims=True)


def fuse_probabilities(p_future, p_current, trans, beta: float):
    if p_current is None or beta <= 0:
        p = np.clip(p_future, EPS, 1.0)
        return p / p.sum(axis=1, keepdims=True)
    p_trans = np.clip(p_current @ trans, EPS, 1.0)
    pf = np.clip(p_future, EPS, 1.0)
    logp = (1.0 - float(beta)) * np.log(pf) + float(beta) * np.log(p_trans)
    logp -= logp.max(axis=1, keepdims=True)
    p = np.exp(logp)
    return p / p.sum(axis=1, keepdims=True)


def apply_temperature(proba, temperature: float):
    p = np.clip(np.asarray(proba, dtype=float), EPS, 1.0)
    logits = np.log(p) / float(temperature)
    logits -= logits.max(axis=1, keepdims=True)
    out = np.exp(logits)
    return out / out.sum(axis=1, keepdims=True)


def nll(y, proba):
    y = np.asarray(y, dtype=int)
    p = np.clip(proba[np.arange(len(y)), y], EPS, 1.0)
    return float(-np.log(p).mean())


def calibrate_temperature(y, proba):
    rows = []
    for t in TEMPERATURE_GRID:
        q = apply_temperature(proba, t)
        rows.append({"temperature": float(t), "nll": nll(y, q)})
    rows.sort(key=lambda r: (r["nll"], abs(r["temperature"] - 1.0)))
    return rows[0], rows


def candidate_key(c):
    return (
        int(c["development_viable"]),
        c["minimum_subtype_recall"],
        min(c["recon_mean_recall"], c["lateral_mean_recall"]),
        c["mean_subtype_recall"],
        c["macro_f1_oof"],
        int(c["transition_beta"] > 0),
        int(c["future_weight_alpha"] > 0),
        -float(c["transition_beta"]),
    )


def select_transition_path(history, forecast, persistence, state_names, seq, labelled_development, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No reserve-free development subtype diagnostics")
    public = [{k: r[k] for k in ("stage", "subtype", "support", "same_stage_train_after_exclusion")} for r in diagnostics]

    X_hist = history_features(history, state_names)
    y_current = current_stage_targets(seq)
    kinds = ("flat_c0p1", "flat_c0p5", "ordinal_c0p5")
    candidates = []
    cached = {}
    feature_audit = None

    for alpha in STAGE_FUSION_ALPHA_GRID:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        views, audit = progression_views(history, stage_future, persistence, state_names)
        cached[float(alpha)] = views
        if feature_audit is None:
            feature_audit = audit
        for view_name in ("relative_no_ports", "semantic_pool"):
            X = views[view_name]
            for kind in kinds:
                fold_cache = []
                failed = None
                for row in diagnostics:
                    train_ids = np.where(row["train_mask"])[0]
                    eval_ids = np.where(row["eval_mask"])[0]
                    try:
                        w = subgroup_weights(seq, train_ids, seq["y_stage"], "future_pairs")
                        future_head = make_future_head(kind).fit(X[train_ids], seq["y_stage"][train_ids], w)
                        p_future = future_head.predict_proba(X[eval_ids])
                        current_head = fit_current_head(X_hist, y_current, seq, train_ids)
                        p_current = None if current_head is None else current_head.predict_proba(X_hist[eval_ids])
                        trans = transition_matrix(y_current, seq["y_stage"], train_ids)
                    except Exception as exc:
                        failed = f"{type(exc).__name__}: {exc}"
                        break
                    fold_cache.append((row, eval_ids, p_future, p_current, trans))
                if failed:
                    continue

                for beta in TRANSITION_BETA_GRID:
                    folds = []
                    ys, ps = [], []
                    for row, eval_ids, p_future, p_current, trans in fold_cache:
                        p = fuse_probabilities(p_future, p_current, trans, beta)
                        pred = p.argmax(axis=1)
                        target = rank[row["stage"]]
                        folds.append({
                            "stage": row["stage"], "subtype": row["subtype"],
                            "support": int(len(eval_ids)), "recall": float(np.mean(pred == target)),
                        })
                        ys.append(seq["y_stage"][eval_ids])
                        ps.append(p)
                    recalls = np.asarray([r["recall"] for r in folds], dtype=float)
                    recon = np.asarray([r["recall"] for r in folds if r["stage"] == "Reconnaissance"], dtype=float)
                    lateral = np.asarray([r["recall"] for r in folds if r["stage"] == "Lateral Movement"], dtype=float)
                    y_oof = np.concatenate(ys)
                    p_oof = np.concatenate(ps)
                    pred_oof = p_oof.argmax(axis=1)
                    metric_oof = exact_metrics(y_oof, pred_oof)
                    c = {
                        "future_weight_alpha": float(alpha),
                        "transition_beta": float(beta),
                        "view": view_name,
                        "model": kind,
                        "folds": folds,
                        "minimum_subtype_recall": float(recalls.min()),
                        "mean_subtype_recall": float(recalls.mean()),
                        "recon_mean_recall": float(recon.mean()),
                        "lateral_mean_recall": float(lateral.mean()),
                        "macro_f1_oof": float(metric_oof["macro_f1_supported_classes"]),
                    }
                    c["development_viable"] = bool(
                        c["minimum_subtype_recall"] >= MIN_WORST_SUBTYPE_RECALL
                        and c["recon_mean_recall"] >= MIN_RECON_MEAN_RECALL
                        and c["lateral_mean_recall"] >= MIN_LATERAL_MEAN_RECALL
                    )
                    candidates.append(c)

    if not candidates:
        raise RuntimeError("No V85 stage candidates fitted")
    candidates.sort(key=candidate_key, reverse=True)
    winner = candidates[0]

    alpha = float(winner["future_weight_alpha"])
    beta = float(winner["transition_beta"])
    X = cached[alpha][winner["view"]]
    train_ids = np.where(labelled_development)[0]
    w = subgroup_weights(seq, train_ids, seq["y_stage"], "future_pairs")
    future_head = make_future_head(winner["model"]).fit(X[train_ids], seq["y_stage"][train_ids], w)
    current_head = fit_current_head(X_hist, y_current, seq, train_ids)
    trans = transition_matrix(y_current, seq["y_stage"], train_ids)

    oof_y, oof_p = [], []
    for row in diagnostics:
        tr = np.where(row["train_mask"])[0]
        ev = np.where(row["eval_mask"])[0]
        ww = subgroup_weights(seq, tr, seq["y_stage"], "future_pairs")
        fh = make_future_head(winner["model"]).fit(X[tr], seq["y_stage"][tr], ww)
        ch = fit_current_head(X_hist, y_current, seq, tr)
        tt = transition_matrix(y_current, seq["y_stage"], tr)
        pf = fh.predict_proba(X[ev])
        pc = None if ch is None else ch.predict_proba(X_hist[ev])
        oof_y.append(seq["y_stage"][ev])
        oof_p.append(fuse_probabilities(pf, pc, tt, beta))
    oof_y = np.concatenate(oof_y)
    oof_p = np.concatenate(oof_p)
    temp_winner, temp_table = calibrate_temperature(oof_y, oof_p)

    return {
        "winner": winner,
        "candidates": candidates,
        "future_head": future_head,
        "current_head": current_head,
        "transition": trans,
        "temperature": float(temp_winner["temperature"]),
        "temperature_selection": {"winner": temp_winner, "table": temp_table},
        "X": X,
        "X_hist": X_hist,
        "y_current": y_current,
        "diagnostics": public,
        "feature_audit": feature_audit,
    }


def selective_metrics(y_true, proba):
    conf = proba.max(axis=1)
    pred = proba.argmax(axis=1)
    rows = []
    for threshold in (0.40, 0.50, 0.60, 0.70, 0.80):
        keep = conf >= threshold
        if not keep.any():
            rows.append({"threshold": threshold, "coverage": 0.0, "accuracy": None})
            continue
        rows.append({
            "threshold": threshold,
            "coverage": float(keep.mean()),
            "accuracy": float((pred[keep] == y_true[keep]).mean()),
        })
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", required=True)
    p.add_argument("--freeze", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--epochs", type=int, default=18)
    args = p.parse_args()

    csv = Path(args.csv)
    freeze = Path(args.freeze)
    frozen = json.loads(freeze.read_text())
    if sha256(freeze) != EXPECTED_V81_FREEZE_SHA256:
        raise RuntimeError("V81 freeze hash drift")
    if frozen.get("dataset_sha256") != sha256(csv):
        raise RuntimeError("Dataset differs from V81 freeze")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V81_SELECTED:
        raise RuntimeError("V81 selected reserve drift")
    if frozen.get("selection_used_model_metrics") is not False or frozen.get("model_training_or_scoring_performed") is not False:
        raise RuntimeError("V81 freeze is not support-only")
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        if subtype not in EXPOSED_SUBTYPE_REGISTRY.get(stage, []):
            raise RuntimeError(f"Exposed reserve registry drift: {stage}/{subtype}")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V85 evidence is immutable")
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
    test_masks, test_diag = fresh_test_masks(seq, dict(EXPECTED_V81_SELECTED), reserve_pairs)
    test_union = np.zeros(len(seq["X"]), dtype=bool)
    for stage in EXPECTED_V81_SELECTED:
        test_union |= test_masks[stage]
    support = {s: int(test_masks[s].sum()) for s in EXPECTED_V81_SELECTED}
    if support != EXPECTED_V81_SUPPORT:
        raise RuntimeError(f"Exposed diagnostic support drift: {support}")

    worlds = []
    for seed in WORLD_SEEDS:
        print(f"V85 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(
            seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs
        ))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])

    stage = select_transition_path(
        history, forecast, persistence, list(state_names), seq, labelled_development, reserve_pairs
    )
    winner = stage["winner"]
    print("V85 DEVELOPMENT WINNER", json.dumps(winner, indent=2), flush=True)

    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    pf = stage["future_head"].predict_proba(stage["X"][test_ids])
    pc = None if stage["current_head"] is None else stage["current_head"].predict_proba(stage["X_hist"][test_ids])
    learned_p = fuse_probabilities(pf, pc, stage["transition"], winner["transition_beta"])
    learned_p = apply_temperature(learned_p, stage["temperature"])
    pred = learned_p.argmax(axis=1)

    pviews, _ = progression_views(history, persistence, persistence, list(state_names))
    pX = pviews[winner["view"]]
    dev_ids = np.where(labelled_development)[0]
    pw = subgroup_weights(seq, dev_ids, seq["y_stage"], "future_pairs")
    phead = make_future_head(winner["model"]).fit(pX[dev_ids], seq["y_stage"][dev_ids], pw)
    ppf = phead.predict_proba(pX[test_ids])
    persistence_p = fuse_probabilities(ppf, pc, stage["transition"], winner["transition_beta"])
    persistence_p = apply_temperature(persistence_p, stage["temperature"])
    ppred = persistence_p.argmax(axis=1)

    metric = add_strict_stage_metrics(exact_metrics(truth, pred))
    pmetric = add_strict_stage_metrics(exact_metrics(truth, ppred))
    fmse = mse(forecast, target, test_union)
    pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    learned_f1 = float(metric["macro_f1_supported_classes"])
    persistence_f1 = float(pmetric["macro_f1_supported_classes"])

    dev_viable = bool(winner["development_viable"])
    stage_beats_persistence = bool(learned_f1 > persistence_f1 + 1e-12)
    learned_future_used = bool(float(winner["future_weight_alpha"]) > 0.0)
    release_eligible = bool(dev_viable and stage_beats_persistence and learned_future_used)

    report = {
        "protocol": "V85 transition-aware subgroup-robust stage diagnostic",
        "claim_boundary": (
            "V85 is an exposed-reserve diagnostic. Architecture selection, subgroup balancing, transition estimation, "
            "and temperature calibration use reserve-free development data only. No fresh or pre-compromise claim."
        ),
        "dataset_sha256": sha256(csv),
        "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "progression_feature_audit": stage["feature_audit"],
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()),
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "development_stage_mapper": int(labelled_development.sum()),
            "exposed_diagnostic_support": support,
            "history_exposure": test_diag,
            "current_stage_trainable_sequences": int(np.sum(stage["y_current"] >= 0)),
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "world_gamma_winner": gamma_winner,
            "world_gamma_table": gamma_table,
            "stage_future_alpha_grid": list(STAGE_FUSION_ALPHA_GRID),
            "transition_beta_grid": list(TRANSITION_BETA_GRID),
            "development_diagnostic_subtypes": stage["diagnostics"],
            "viability_thresholds": {
                "minimum_subtype_recall": MIN_WORST_SUBTYPE_RECALL,
                "recon_mean_recall": MIN_RECON_MEAN_RECALL,
                "lateral_mean_recall": MIN_LATERAL_MEAN_RECALL,
            },
            "winner": winner,
            "temperature_selection": stage["temperature_selection"],
            "transition_matrix": stage["transition"].tolist(),
            "all_candidates": stage["candidates"],
        },
        "state_task": {
            "forecast_mse": fmse,
            "persistence_mse": pmse,
            "improvement_vs_persistence": state_gain,
        },
        "stage_task_exposed_diagnostic": {
            "learned_forecast": metric,
            "persistence_state": pmetric,
            "macro_f1_delta_vs_persistence": float(learned_f1 - persistence_f1),
            "probability_quality_learned": probability_metrics(truth, learned_p),
            "probability_quality_persistence": probability_metrics(truth, persistence_p),
            "selective_prediction": selective_metrics(truth, learned_p),
        },
        "release_gate": {
            "development_subtype_viability_passed": dev_viable,
            "learned_future_contribution_used": learned_future_used,
            "stage_task_beats_persistence_passed": stage_beats_persistence,
            "release_eligible_for_unseen_subtype_stage_claim": release_eligible,
            "fresh_claim_allowed": False,
            "reason": "V81/V82 reserve is exposed; a newly sealed dataset/campaign is required for a fresh claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_gamma_selection": False,
            "reserve_metrics_used_for_stage_alpha_selection": False,
            "reserve_metrics_used_for_transition_beta_selection": False,
            "reserve_metrics_used_for_head_or_view_selection": False,
            "reserve_metrics_used_for_temperature_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "current_stage_labels_used_at_inference": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": winner,
        "state_task": report["state_task"],
        "stage_macro_f1": learned_f1,
        "persistence_macro_f1": persistence_f1,
        "probability_quality": report["stage_task_exposed_diagnostic"]["probability_quality_learned"],
        "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
