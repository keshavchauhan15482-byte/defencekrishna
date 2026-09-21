"""V83 benchmark hardening for Garuda future-stage evidence.

V83 is intentionally conservative.  The V81/V82 subtype reserve has already been
observed, so this script NEVER calls it fresh.  It is a diagnostic rerun used to test
whether stronger, subtype-invariant stage heads fix the failure exposed by V82.

Release eligibility is decided by two independent gates:
  1. development leave-subtype-out viability (before exposed diagnostic scoring), and
  2. a task-aware persistence ablation on the exposed diagnostic slice.

A model can improve state MSE yet fail the stage task; those claims are kept separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import (
    build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import (
    WORLD_SEEDS, add_strict_stage_metrics, development_split, fresh_test_masks, mse,
    reserve_isolation, scaled_history, trajectory_features,
)
from .v82_robust_stage_head_fresh_eval import (
    EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT,
    GAMMA_GRID, choose_gamma, mapper_diagnostic_pairs,
)

# These are RELEASE gates, not tuning targets.  If no candidate satisfies them the
# benchmark says NOT_RELEASE_ELIGIBLE instead of silently promoting the least-bad head.
MIN_WORST_SUBTYPE_RECALL = 0.20
MIN_RECON_MEAN_RECALL = 0.20
MIN_LATERAL_MEAN_RECALL = 0.20

# All already-observed subtype reserves are listed so they can never be described as
# fresh again by this protocol.
EXPOSED_SUBTYPE_REGISTRY = {
    "Reconnaissance": ["discovering resources", "fuzzing", "generic scanning"],
    "Lateral Movement": ["modbus register reading", "mqtt cloud broker subscription", "tcp relay"],
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _blocks(full: np.ndarray, state_dim: int):
    return [full[:, i * state_dim:(i + 1) * state_dim] for i in range(10)]


def feature_views(full: np.ndarray, state_names: list[str]):
    """Return full, compact and port-invariant trajectory views.

    Port identity is useful in-distribution but can encourage subtype memorisation.
    The behavioural view removes every state dimension whose name contains 'port'
    while retaining timing/rate/flags/bytes/packets and their temporal trajectory.
    """
    d = len(state_names)
    b = _blocks(full, d)
    keep = np.asarray(["port" not in str(n).lower() for n in state_names], dtype=bool)
    if int(keep.sum()) < max(4, d // 4):
        raise RuntimeError("Behavioural-invariant feature view removed too many dimensions")
    invariant = np.concatenate([block[:, keep] for block in b], axis=1).astype(np.float32)
    compact = np.concatenate([b[0], b[1], b[3], b[4], b[6]], axis=1).astype(np.float32)
    return {
        "full": full.astype(np.float32),
        "compact": compact,
        "behavioral_no_ports": invariant,
    }, {
        "state_dim": d,
        "behavioral_state_dim": int(keep.sum()),
        "dropped_state_features": [str(n) for n, k in zip(state_names, keep) if not k],
    }


def _flat_model(kind: str):
    if kind == "flat_logistic":
        return Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=0.25, class_weight="balanced", max_iter=4000,
                solver="lbfgs", random_state=20260921,
            )),
        ])
    if kind == "flat_extra_trees":
        return ExtraTreesClassifier(
            n_estimators=600, max_features="sqrt", min_samples_leaf=3,
            class_weight="balanced", random_state=20260921, n_jobs=2,
        )
    raise KeyError(kind)


class HierarchicalStageHead:
    """Coarse lifecycle routing followed by balanced branch-specific heads."""
    def __init__(self, kind: str):
        self.kind = kind

    def _binary(self, seed_offset=0):
        if self.kind == "hier_logistic":
            return Pipeline([
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(
                    C=0.20, class_weight="balanced", max_iter=4000,
                    solver="lbfgs", random_state=20260921 + seed_offset,
                )),
            ])
        if self.kind == "hier_extra_trees":
            return ExtraTreesClassifier(
                n_estimators=500, max_features="sqrt", min_samples_leaf=4,
                class_weight="balanced", random_state=20260921 + seed_offset, n_jobs=2,
            )
        raise KeyError(self.kind)

    def fit(self, X, y):
        y = np.asarray(y, dtype=int)
        if set(np.unique(y).tolist()) != set(range(5)):
            raise RuntimeError("Hierarchical stage head requires all five development stages")
        coarse = np.where(y <= 1, 0, np.where(y == 2, 1, 2))
        self.coarse = self._binary(0).fit(X, coarse)
        early = y <= 1
        control = y >= 3
        self.early = self._binary(1).fit(X[early], y[early])
        self.control = self._binary(2).fit(X[control], y[control])
        return self

    def predict(self, X):
        coarse = np.asarray(self.coarse.predict(X), dtype=int)
        out = np.full(len(X), 2, dtype=int)
        early = coarse == 0
        control = coarse == 2
        if early.any():
            out[early] = self.early.predict(X[early]).astype(int)
        if control.any():
            out[control] = self.control.predict(X[control]).astype(int)
        return out


def fit_model(kind: str, X, y):
    if kind.startswith("flat_"):
        model = _flat_model(kind)
    else:
        model = HierarchicalStageHead(kind)
    return model.fit(X, y)


def select_head(views, seq, labelled_development, reserve_pairs):
    """Development-only grouped subtype CV with explicit viability gating."""
    rank = {stage: i for i, stage in enumerate(STAGES)}
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    diag_public = [{k: r[k] for k in (
        "stage", "subtype", "support", "same_stage_train_after_exclusion"
    )} for r in diagnostics]
    if not diagnostics:
        raise RuntimeError("No development subtype diagnostics")

    kinds = ("flat_logistic", "flat_extra_trees", "hier_logistic", "hier_extra_trees")
    candidates = []
    for view_name, X in views.items():
        for kind in kinds:
            folds = []
            for row in diagnostics:
                train_ids = np.where(row["train_mask"])[0]
                eval_ids = np.where(row["eval_mask"])[0]
                model = fit_model(kind, X[train_ids], seq["y_stage"][train_ids])
                pred = model.predict(X[eval_ids])
                target = rank[row["stage"]]
                recall = float(np.mean(pred == target))
                folds.append({
                    "stage": row["stage"], "subtype": row["subtype"],
                    "support": int(len(eval_ids)), "recall": recall,
                })
            recalls = np.asarray([r["recall"] for r in folds], dtype=float)
            recon = np.asarray([r["recall"] for r in folds if r["stage"] == "Reconnaissance"], dtype=float)
            lateral = np.asarray([r["recall"] for r in folds if r["stage"] == "Lateral Movement"], dtype=float)
            if not len(recon) or not len(lateral):
                raise RuntimeError("Development diagnostics missing Recon/Lateral stage")
            row = {
                "view": view_name,
                "model": kind,
                "folds": folds,
                "minimum_subtype_recall": float(recalls.min()),
                "mean_subtype_recall": float(recalls.mean()),
                "recon_mean_recall": float(recon.mean()),
                "recon_min_recall": float(recon.min()),
                "lateral_mean_recall": float(lateral.mean()),
                "lateral_min_recall": float(lateral.min()),
            }
            row["development_viable"] = bool(
                row["minimum_subtype_recall"] >= MIN_WORST_SUBTYPE_RECALL
                and row["recon_mean_recall"] >= MIN_RECON_MEAN_RECALL
                and row["lateral_mean_recall"] >= MIN_LATERAL_MEAN_RECALL
            )
            candidates.append(row)

    # Equal-stage protection: worst subtype -> worst stage -> mean subtype.
    candidates.sort(key=lambda c: (
        int(c["development_viable"]),
        c["minimum_subtype_recall"],
        min(c["recon_mean_recall"], c["lateral_mean_recall"]),
        c["mean_subtype_recall"],
        int(c["view"] == "behavioral_no_ports"),
        int(c["model"].startswith("hier_")),
    ), reverse=True)
    winner = candidates[0]
    mapper_ids = np.where(labelled_development)[0]
    mapper = fit_model(winner["model"], views[winner["view"]][mapper_ids], seq["y_stage"][mapper_ids])
    return winner, candidates, mapper, diag_public


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
    if frozen.get("selection_used_model_metrics") is not False or frozen.get("model_training_or_scoring_performed") is not False:
        raise RuntimeError("V81 freeze is not support-only")
    if frozen.get("selected_reserve_subtype_by_stage") != EXPECTED_V81_SELECTED:
        raise RuntimeError("V81 selected reserve drift")

    # This is the central V83 freshness rule: the V81/V82 reserve is exposed now.
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        if subtype not in EXPOSED_SUBTYPE_REGISTRY.get(stage, []):
            raise RuntimeError(f"Exposed reserve missing from registry: {stage}/{subtype}")

    out = Path(args.output)
    if out.exists():
        p.error("Output exists; V83 evidence is immutable")
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
        print(f"V83 world seed={seed}", flush=True)
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
    forecast_full = trajectory_features(history, forecast, persistence)
    persistence_full = trajectory_features(history, persistence, persistence)
    views, view_audit = feature_views(forecast_full, list(state_names))
    pviews, _ = feature_views(persistence_full, list(state_names))

    winner, candidates, mapper, diagnostics = select_head(
        views, seq, labelled_development, reserve_pairs
    )
    print("V83 DEVELOPMENT WINNER", json.dumps({k: winner[k] for k in (
        "view", "model", "development_viable", "minimum_subtype_recall",
        "mean_subtype_recall", "recon_mean_recall", "lateral_mean_recall"
    )}, indent=2), flush=True)

    # IMPORTANT: this slice is already exposed by V82.  It is diagnostic only and
    # cannot be promoted to a fresh benchmark regardless of its score.
    test_ids = np.where(test_union)[0]
    truth = seq["y_stage"][test_ids]
    pred = mapper.predict(views[winner["view"]][test_ids])
    ppred = mapper.predict(pviews[winner["view"]][test_ids])
    metric = add_strict_stage_metrics(exact_metrics(truth, pred))
    pmetric = add_strict_stage_metrics(exact_metrics(truth, ppred))

    fmse = mse(forecast, target, test_union)
    pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)

    learned_f1 = float(metric["macro_f1_supported_classes"])
    persistence_f1 = float(pmetric["macro_f1_supported_classes"])
    stage_beats_persistence = bool(learned_f1 > persistence_f1 + 1e-12)
    dev_viable = bool(winner["development_viable"])
    release_eligible = bool(dev_viable and stage_beats_persistence)

    release_gate = {
        "development_subtype_viability_passed": dev_viable,
        "stage_task_beats_persistence_passed": stage_beats_persistence,
        "release_eligible_for_unseen_subtype_stage_claim": release_eligible,
        "fresh_claim_allowed": False,
        "reason": (
            "V83 reuses the V81 reserve after V82 exposed it; scores are diagnostic only. "
            "A future release claim requires a newly sealed dataset/campaign/subtype reserve."
        ),
    }

    report = {
        "protocol": "V83 stage benchmark hardening and exposed-reserve diagnostic",
        "claim_boundary": (
            "Benchmark hardening only. V81/V82 reserve is already exposed, so V83 does not call it fresh. "
            "Architecture selection uses reserve-free development diagnostics. State forecasting and stage-task gates are separate."
        ),
        "dataset_sha256": sha256(csv),
        "freeze_sha256": sha256(freeze),
        "exposed_subtype_registry": EXPOSED_SUBTYPE_REGISTRY,
        "network_only_features": feature_cols,
        "feature_audit": feature_audit,
        "feature_view_audit": view_audit,
        "split": {
            "sequence_count": int(len(seq["X"])),
            "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()),
            "development_train": int(train.sum()),
            "development_validation": int(validation.sum()),
            "development_stage_mapper": int(labelled_development.sum()),
            "exposed_diagnostic_support": support,
            "history_exposure": test_diag,
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "gamma_winner": gamma_winner,
            "gamma_table": gamma_table,
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
            "learned_forecast": metric,
            "persistence_state": pmetric,
            "macro_f1_delta_vs_persistence": float(learned_f1 - persistence_f1),
        },
        "release_gate": release_gate,
        "leakage_contract": {
            "reserve_metrics_used_for_gamma_selection": False,
            "reserve_metrics_used_for_head_selection": False,
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
            "view", "model", "development_viable", "minimum_subtype_recall",
            "recon_mean_recall", "lateral_mean_recall")},
        "state_task": report["state_task"],
        "stage_macro_f1": learned_f1,
        "persistence_macro_f1": persistence_f1,
        "release_gate": release_gate,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
