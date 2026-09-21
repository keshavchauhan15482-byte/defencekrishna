"""V84 progression-robust stage diagnostic for Garuda.

V84 fixes the main V83 failure mode without re-labelling already exposed evidence as
fresh. The world model is still selected on reserve-free validation state MSE. The
stage path is redesigned around task-aware conservative future fusion and subtype-
invariant progression features.

The V81/V82 subtype reserve is already exposed, so its score below is diagnostic only.
No pre-compromise, fresh-zero-day, or exact MITRE Initial Access claim is made.
"""
from __future__ import annotations

import argparse
import hashlib
import json
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

MIN_WORST_SUBTYPE_RECALL = 0.20
MIN_RECON_MEAN_RECALL = 0.20
MIN_LATERAL_MEAN_RECALL = 0.20
STAGE_FUSION_ALPHA_GRID = (0.0, 0.10, 0.25, 0.50, 1.0)
EPS = 1e-4


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _port_mask(state_names: list[str]) -> np.ndarray:
    return np.asarray(["port" not in str(n).lower() for n in state_names], dtype=bool)


def _semantic_group(name: str) -> str:
    n = str(name).lower()
    if "port" in n:
        return "port"
    if any(k in n for k in ("syn", "ack", "fin", "rst", "payload", "checksum")):
        return "flags"
    if "byte" in n:
        return "bytes"
    if any(k in n for k in ("pkt", "packet")):
        return "packets"
    if "rate" in n:
        return "rates"
    if "ratio" in n:
        return "ratios"
    if any(k in n for k in ("duration", "iat", "time")):
        return "timing"
    return "other"


def _relative_blocks(history: np.ndarray, future: np.ndarray, persistence: np.ndarray):
    """Seven progression descriptors normalized by each sequence's observed variance."""
    last = history[:, -1, :]
    hist_std = history.std(axis=1)
    scale = np.maximum(hist_std, 0.25)
    recent = (history[:, -1, :] - history[:, -2, :]) / scale
    future_mean = (future.mean(axis=1) - last) / scale
    future_last = (future[:, -1, :] - last) / scale
    future_vol = future.std(axis=1) / scale
    innovation = future - persistence
    innovation_mean = innovation.mean(axis=1) / scale
    innovation_last = innovation[:, -1, :] / scale
    innovation_peak = np.max(np.abs(innovation), axis=1) / scale
    return [np.clip(x, -8.0, 8.0).astype(np.float32) for x in (
        recent, future_mean, future_last, future_vol,
        innovation_mean, innovation_last, innovation_peak,
    )]


def _semantic_pool(blocks: list[np.ndarray], state_names: list[str]) -> np.ndarray:
    groups = {}
    for j, name in enumerate(state_names):
        group = _semantic_group(name)
        if group == "port":
            continue
        groups.setdefault(group, []).append(j)
    ordered = [g for g in ("flags", "bytes", "packets", "rates", "ratios", "timing", "other") if g in groups]
    pooled = []
    for block in blocks:
        for group in ordered:
            x = block[:, groups[group]]
            pooled.extend([
                x.mean(axis=1, keepdims=True),
                x.std(axis=1, keepdims=True),
                np.max(np.abs(x), axis=1, keepdims=True),
            ])
    return np.concatenate(pooled, axis=1).astype(np.float32)


def progression_views(history: np.ndarray, future: np.ndarray, persistence: np.ndarray, state_names: list[str]):
    blocks = _relative_blocks(history, future, persistence)
    keep = _port_mask(state_names)
    full = np.concatenate(blocks, axis=1).astype(np.float32)
    no_ports = np.concatenate([b[:, keep] for b in blocks], axis=1).astype(np.float32)
    semantic = _semantic_pool(blocks, state_names)
    return {
        "relative_full": full,
        "relative_no_ports": no_ports,
        "semantic_pool": semantic,
    }, {
        "relative_blocks": [
            "recent_change", "future_mean_displacement", "future_terminal_displacement",
            "future_volatility", "innovation_mean", "innovation_terminal", "innovation_peak",
        ],
        "state_dim": int(len(state_names)),
        "behavioral_state_dim": int(keep.sum()),
        "semantic_pool_dim": int(semantic.shape[1]),
        "dropped_port_state_features": [str(n) for n, k in zip(state_names, keep) if not k],
    }


class FlatStageHead:
    def __init__(self, C: float):
        self.C = float(C)
        self.model = Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=self.C, class_weight="balanced", max_iter=4000,
                solver="lbfgs", random_state=20260921,
            )),
        ])

    def fit(self, X, y):
        self.model.fit(X, y)
        return self

    def predict_proba(self, X):
        p = self.model.predict_proba(X)
        classes = np.asarray(self.model.named_steps["clf"].classes_, dtype=int)
        out = np.zeros((len(X), len(STAGES)), dtype=float)
        out[:, classes] = p
        return out

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1).astype(int)


class OrdinalStageHead:
    """Four cumulative balanced logistic heads that preserve lifecycle ordering."""
    def __init__(self, C: float):
        self.C = float(C)
        self.models = []

    def fit(self, X, y):
        y = np.asarray(y, dtype=int)
        self.models = []
        for threshold in range(len(STAGES) - 1):
            binary = (y > threshold).astype(int)
            if len(np.unique(binary)) != 2:
                raise RuntimeError(f"Ordinal threshold {threshold} lacks both classes")
            model = Pipeline([
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(
                    C=self.C, class_weight="balanced", max_iter=4000,
                    solver="lbfgs", random_state=20260921 + threshold,
                )),
            ])
            model.fit(X, binary)
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
        p = np.clip(p, 0.0, 1.0)
        return p / np.maximum(p.sum(axis=1, keepdims=True), EPS)

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1).astype(int)


def make_head(kind: str):
    family, ctext = kind.split("_c", 1)
    C = float(ctext.replace("p", "."))
    if family == "flat":
        return FlatStageHead(C)
    if family == "ordinal":
        return OrdinalStageHead(C)
    raise KeyError(kind)


def probability_metrics(y_true: np.ndarray, proba: np.ndarray, bins: int = 10):
    y_true = np.asarray(y_true, dtype=int)
    proba = np.asarray(proba, dtype=float)
    onehot = np.eye(len(STAGES), dtype=float)[y_true]
    brier = float(np.mean(np.sum((proba - onehot) ** 2, axis=1)))
    confidence = proba.max(axis=1)
    correct = (proba.argmax(axis=1) == y_true).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    rows = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (confidence >= lo) & (confidence < hi if hi < 1.0 else confidence <= hi)
        n = int(mask.sum())
        if not n:
            continue
        acc = float(correct[mask].mean())
        conf = float(confidence[mask].mean())
        ece += (n / len(y_true)) * abs(acc - conf)
        rows.append({"lower": float(lo), "upper": float(hi), "samples": n, "accuracy": acc, "confidence": conf})
    return {"multiclass_brier": brier, "ece_10bin": float(ece), "bins": rows}


def candidate_key(c):
    alpha = float(c["future_weight_alpha"])
    return (
        int(c["development_viable"]),
        c["minimum_subtype_recall"],
        min(c["recon_mean_recall"], c["lateral_mean_recall"]),
        c["mean_subtype_recall"],
        int(alpha > 0.0),
        -alpha,
        int(c["view"] == "semantic_pool"),
        int(c["model"].startswith("ordinal_")),
    )


def select_stage_path(history, forecast, persistence, state_names, seq, labelled_development, reserve_pairs):
    rank = {stage: i for i, stage in enumerate(STAGES)}
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No reserve-free development subtype diagnostics")
    diagnostics_public = [{k: r[k] for k in (
        "stage", "subtype", "support", "same_stage_train_after_exclusion"
    )} for r in diagnostics]

    kinds = ("flat_c0p1", "flat_c0p5", "ordinal_c0p1", "ordinal_c0p5")
    candidates = []
    cached_views = {}
    view_audit = None
    for alpha in STAGE_FUSION_ALPHA_GRID:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        views, audit = progression_views(history, stage_future, persistence, state_names)
        cached_views[float(alpha)] = views
        if view_audit is None:
            view_audit = audit
        for view_name, X in views.items():
            for kind in kinds:
                folds = []
                failed = None
                for row in diagnostics:
                    train_ids = np.where(row["train_mask"])[0]
                    eval_ids = np.where(row["eval_mask"])[0]
                    try:
                        model = make_head(kind).fit(X[train_ids], seq["y_stage"][train_ids])
                        pred = model.predict(X[eval_ids])
                    except Exception as exc:
                        failed = f"{type(exc).__name__}: {exc}"
                        break
                    target = rank[row["stage"]]
                    folds.append({
                        "stage": row["stage"], "subtype": row["subtype"],
                        "support": int(len(eval_ids)), "recall": float(np.mean(pred == target)),
                    })
                if failed:
                    candidates.append({
                        "future_weight_alpha": float(alpha), "view": view_name, "model": kind,
                        "development_viable": False, "fit_error": failed,
                        "minimum_subtype_recall": -1.0, "mean_subtype_recall": -1.0,
                        "recon_mean_recall": -1.0, "lateral_mean_recall": -1.0,
                        "folds": folds,
                    })
                    continue
                recalls = np.asarray([r["recall"] for r in folds], dtype=float)
                recon = np.asarray([r["recall"] for r in folds if r["stage"] == "Reconnaissance"], dtype=float)
                lateral = np.asarray([r["recall"] for r in folds if r["stage"] == "Lateral Movement"], dtype=float)
                c = {
                    "future_weight_alpha": float(alpha), "view": view_name, "model": kind,
                    "folds": folds,
                    "minimum_subtype_recall": float(recalls.min()),
                    "mean_subtype_recall": float(recalls.mean()),
                    "recon_mean_recall": float(recon.mean()),
                    "lateral_mean_recall": float(lateral.mean()),
                }
                c["development_viable"] = bool(
                    c["minimum_subtype_recall"] >= MIN_WORST_SUBTYPE_RECALL
                    and c["recon_mean_recall"] >= MIN_RECON_MEAN_RECALL
                    and c["lateral_mean_recall"] >= MIN_LATERAL_MEAN_RECALL
                )
                candidates.append(c)

    candidates.sort(key=candidate_key, reverse=True)
    winner = candidates[0]
    alpha = float(winner["future_weight_alpha"])
    X = cached_views[alpha][winner["view"]]
    ids = np.where(labelled_development)[0]
    mapper = make_head(winner["model"]).fit(X[ids], seq["y_stage"][ids])
    return winner, candidates, mapper, cached_views, diagnostics_public, view_audit


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
        p.error("Output exists; V84 evidence is immutable")
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
        print(f"V84 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])

    winner, candidates, mapper, cached_views, diagnostics, view_audit = select_stage_path(
        history, forecast, persistence, list(state_names), seq, labelled_development, reserve_pairs
    )
    alpha = float(winner["future_weight_alpha"])
    learned_views = cached_views[alpha]
    persistence_views, _ = progression_views(history, persistence, persistence, list(state_names))

    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    learned_X = learned_views[winner["view"]][test_ids]
    persistence_X = persistence_views[winner["view"]][test_ids]
    pred = mapper.predict(learned_X)
    ppred = mapper.predict(persistence_X)
    proba = mapper.predict_proba(learned_X)
    pproba = mapper.predict_proba(persistence_X)
    metric = add_strict_stage_metrics(exact_metrics(truth, pred))
    pmetric = add_strict_stage_metrics(exact_metrics(truth, ppred))
    probability_metric = probability_metrics(truth, proba)
    persistence_probability_metric = probability_metrics(truth, pproba)

    fmse = mse(forecast, target, test_union)
    pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    learned_f1 = float(metric["macro_f1_supported_classes"])
    persistence_f1 = float(pmetric["macro_f1_supported_classes"])
    stage_beats_persistence = bool(learned_f1 > persistence_f1 + 1e-12)
    dev_viable = bool(winner["development_viable"])
    uses_learned_future = bool(alpha > 0.0)

    report = {
        "protocol": "V84 progression-robust task-aware future fusion diagnostic",
        "claim_boundary": (
            "V84 reuses the already-exposed V81/V82 reserve, so it is diagnostic only. "
            "Future trust alpha, feature view and stage-head family are selected exclusively by reserve-free development leave-subtype-out folds."
        ),
        "dataset_sha256": sha256(csv),
        "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "progression_feature_audit": view_audit,
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()),
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "development_stage_mapper": int(labelled_development.sum()),
            "exposed_diagnostic_support": support,
            "history_exposure": test_diag,
            "development_boundary": int(boundary),
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "world_gamma_winner": gamma_winner,
            "world_gamma_table": gamma_table,
            "stage_future_alpha_grid": list(STAGE_FUSION_ALPHA_GRID),
            "development_diagnostic_subtypes": diagnostics,
            "viability_thresholds": {
                "minimum_subtype_recall": MIN_WORST_SUBTYPE_RECALL,
                "recon_mean_recall": MIN_RECON_MEAN_RECALL,
                "lateral_mean_recall": MIN_LATERAL_MEAN_RECALL,
            },
            "winner": winner,
            "all_candidates": candidates,
        },
        "state_task": {
            "forecast_mse": fmse,
            "persistence_mse": pmse,
            "improvement_vs_persistence": state_gain,
        },
        "stage_task_exposed_diagnostic": {
            "learned_future_weight_alpha": alpha,
            "learned_future_contribution_used": uses_learned_future,
            "learned_forecast": metric,
            "persistence_state": pmetric,
            "macro_f1_delta_vs_persistence": float(learned_f1 - persistence_f1),
            "probability_quality_learned": probability_metric,
            "probability_quality_persistence": persistence_probability_metric,
        },
        "release_gate": {
            "development_subtype_viability_passed": dev_viable,
            "learned_future_contribution_used": uses_learned_future,
            "stage_task_beats_persistence_passed": stage_beats_persistence,
            "release_eligible_for_unseen_subtype_stage_claim": bool(dev_viable and uses_learned_future and stage_beats_persistence),
            "fresh_claim_allowed": False,
            "reason": "Exposed diagnostic only; a new sealed dataset/campaign is still required for a fresh stage-generalisation claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_gamma_selection": False,
            "reserve_metrics_used_for_stage_alpha_selection": False,
            "reserve_metrics_used_for_head_or_view_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "reserve_subtypes_seen_by_stage_mapper_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": {k: winner[k] for k in (
            "future_weight_alpha", "view", "model", "development_viable",
            "minimum_subtype_recall", "recon_mean_recall", "lateral_mean_recall")},
        "state_task": report["state_task"],
        "stage_macro_f1": learned_f1,
        "persistence_macro_f1": persistence_f1,
        "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
