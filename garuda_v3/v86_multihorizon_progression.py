"""V86 multi-horizon attacker-progression benchmark.

Instead of collapsing a four-minute future into one furthest lifecycle label, V86
supervises the stage mapper at each future horizon independently.  The mapper consumes
only observed network history plus Garuda-predicted future network state and emits a
stage probability vector for +1, +2, +3 and +4 minutes.  This directly supports an
attacker-progression probability timeline while preserving a persistence-state ablation.

The V81/V82 X-IIoTID reserve is already exposed.  V86 is therefore a diagnostic and
must not be described as a fresh zero-day or verified pre-compromise benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import HORIZON, build_minute_state, choose_network_numeric_features, detect_label_hierarchy, parse_time
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES, exact_metrics
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import WORLD_SEEDS, add_strict_stage_metrics, development_split, mse, reserve_isolation, scaled_history
from .v82_robust_stage_head_fresh_eval import EXPECTED_V81_FREEZE_SHA256, EXPECTED_V81_SELECTED, EXPECTED_V81_SUPPORT, choose_gamma, mapper_diagnostic_pairs
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v84_stage_progression_robustness import probability_metrics

EPS = 1e-8
ALPHA_GRID = (0.10, 0.25, 0.50, 1.00)
MIN_WORST_SUBTYPE_RECALL = 0.20
MIN_RECON_MEAN_RECALL = 0.20
MIN_LATERAL_MEAN_RECALL = 0.20


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def step_targets(seq, minute_pairs: pd.DataFrame):
    """Exact future-minute stage targets and fine subtype pairs for each horizon."""
    rank = {stage: i for i, stage in enumerate(STAGES)}
    lookup = {}
    for row in minute_pairs.itertuples(index=False):
        sec = int(pd.Timestamp(row.minute).value // 10**9)
        lookup[(str(row.src), sec)] = frozenset(row.stage_subtypes)

    y = np.full((len(seq["X"]), HORIZON), -1, dtype=np.int16)
    pairs = np.empty((len(seq["X"]), HORIZON), dtype=object)
    for i, (src, cutoff) in enumerate(zip(seq["src"], seq["cutoff"])):
        for h in range(HORIZON):
            p = lookup.get((str(src), int(cutoff) + 60 * (h + 1)), frozenset())
            pairs[i, h] = p
            vals = [rank[s] for s, _ in p if s in rank]
            if vals:
                y[i, h] = max(vals)
    return y, pairs


def _port_keep(state_names):
    return np.asarray(["port" not in str(n).lower() for n in state_names], dtype=bool)


def sample_features(history, future_state, persistence, state_names):
    """Return N x H x F network-only features aligned to each future minute."""
    keep = _port_keep(state_names)
    hist = history[:, :, keep]
    fut = future_state[:, :, keep]
    per = persistence[:, :, keep]
    last = hist[:, -1, :]
    mean = hist.mean(axis=1)
    std = np.maximum(hist.std(axis=1), 0.25)
    recent = (hist[:, -1, :] - hist[:, -2, :]) / std

    rows = []
    for h in range(HORIZON):
        prev = last if h == 0 else fut[:, h - 1, :]
        absolute = fut[:, h, :]
        from_last = (absolute - last) / std
        step_delta = (absolute - prev) / std
        innovation = (fut[:, h, :] - per[:, h, :]) / std
        horizon = np.zeros((len(history), HORIZON), dtype=np.float32)
        horizon[:, h] = 1.0
        x = np.concatenate([
            last, mean, std,
            np.clip(recent, -8, 8),
            absolute,
            np.clip(from_last, -8, 8),
            np.clip(step_delta, -8, 8),
            np.clip(innovation, -8, 8),
            horizon,
        ], axis=1).astype(np.float32)
        rows.append(x)
    return np.stack(rows, axis=1)


def flatten_ids(seq_ids, y_step):
    seq_ids = np.asarray(seq_ids, dtype=int)
    ii, hh, yy = [], [], []
    for i in seq_ids:
        for h in range(HORIZON):
            if int(y_step[i, h]) >= 0:
                ii.append(int(i)); hh.append(h); yy.append(int(y_step[i, h]))
    return np.asarray(ii, dtype=int), np.asarray(hh, dtype=int), np.asarray(yy, dtype=int)


def subtype_weights(seq_ids, horizons, y, step_pairs):
    keys = []
    for i, h, stage_idx in zip(seq_ids, horizons, y):
        stage = STAGES[int(stage_idx)]
        subs = sorted({str(sub) for s, sub in step_pairs[i, h] if s == stage})
        keys.append((int(stage_idx), subs[0] if subs else "__none__"))
    counts = Counter(keys)
    stage_groups = Counter(k[0] for k in counts)
    w = np.asarray([
        1.0 / (max(stage_groups[k[0]], 1) * max(counts[k], 1))
        for k in keys
    ], dtype=float)
    w /= max(float(w.mean()), EPS)
    return np.clip(w, 0.15, 8.0)


class ProgressionHead:
    def __init__(self, kind: str):
        self.kind = kind
        if kind == "logistic":
            self.model = Pipeline([
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(
                    C=0.25, class_weight="balanced", max_iter=5000,
                    solver="lbfgs", random_state=20260921,
                )),
            ])
        elif kind == "histgb":
            self.model = HistGradientBoostingClassifier(
                learning_rate=0.05, max_iter=300, max_leaf_nodes=15,
                min_samples_leaf=18, l2_regularization=3.0,
                class_weight="balanced", random_state=20260921,
            )
        else:
            raise KeyError(kind)

    def fit(self, X, y, sample_weight):
        if self.kind == "logistic":
            self.model.fit(X, y, clf__sample_weight=sample_weight)
        else:
            self.model.fit(X, y, sample_weight=sample_weight)
        return self

    def predict_proba(self, X):
        raw = self.model.predict_proba(X)
        classes = np.asarray(self.model.classes_ if self.kind == "histgb" else self.model.named_steps["clf"].classes_, dtype=int)
        out = np.full((len(X), len(STAGES)), EPS, dtype=float)
        out[:, classes] = raw
        out /= out.sum(axis=1, keepdims=True)
        return out


def fit_head(kind, X3, y_step, step_pairs, seq_ids):
    ii, hh, yy = flatten_ids(seq_ids, y_step)
    if len(ii) < 200 or len(np.unique(yy)) < 4:
        raise RuntimeError(f"Insufficient step-labelled development support n={len(ii)} classes={np.unique(yy)}")
    w = subtype_weights(ii, hh, yy, step_pairs)
    X = X3[ii, hh]
    return ProgressionHead(kind).fit(X, yy, w)


def fold_stage_recall(head, X3, y_step, step_pairs, eval_ids, stage, subtype):
    target = STAGES.index(stage)
    xs, truth = [], []
    by_horizon = []
    for h in range(HORIZON):
        ids = [
            int(i) for i in eval_ids
            if int(y_step[i, h]) == target and (stage, subtype) in step_pairs[i, h]
        ]
        if ids:
            p = head.predict_proba(X3[np.asarray(ids), h])
            pred = p.argmax(axis=1)
            correct = int(np.sum(pred == target))
            xs.extend(pred.tolist()); truth.extend([target] * len(ids))
            by_horizon.append({"horizon_minutes": h + 1, "support": len(ids), "recall": correct / len(ids)})
        else:
            by_horizon.append({"horizon_minutes": h + 1, "support": 0, "recall": None})
    if not truth:
        return None, by_horizon, 0
    pred = np.asarray(xs, dtype=int)
    return float(np.mean(pred == target)), by_horizon, len(truth)


def select_head(history, forecast, persistence, state_names, seq, y_step, step_pairs, labelled_development, reserve_pairs):
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No development subtype diagnostics")
    candidates = []
    features = {}
    for alpha in ALPHA_GRID:
        stage_future = persistence + float(alpha) * (forecast - persistence)
        X3 = sample_features(history, stage_future, persistence, state_names)
        features[float(alpha)] = X3
        for kind in ("logistic", "histgb"):
            folds = []
            failed = None
            for row in diagnostics:
                train_ids = np.where(row["train_mask"])[0]
                eval_ids = np.where(row["eval_mask"])[0]
                try:
                    head = fit_head(kind, X3, y_step, step_pairs, train_ids)
                    rec, by_h, support = fold_stage_recall(
                        head, X3, y_step, step_pairs, eval_ids, row["stage"], row["subtype"]
                    )
                except Exception as exc:
                    failed = f"{type(exc).__name__}: {exc}"
                    break
                if rec is not None:
                    folds.append({
                        "stage": row["stage"], "subtype": row["subtype"],
                        "support": int(support), "recall": rec, "by_horizon": by_h,
                    })
            if failed or not folds:
                continue
            recalls = np.asarray([r["recall"] for r in folds], dtype=float)
            recon = np.asarray([r["recall"] for r in folds if r["stage"] == "Reconnaissance"], dtype=float)
            lateral = np.asarray([r["recall"] for r in folds if r["stage"] == "Lateral Movement"], dtype=float)
            if not len(recon) or not len(lateral):
                continue
            row = {
                "future_weight_alpha": float(alpha), "model": kind, "folds": folds,
                "minimum_subtype_recall": float(recalls.min()),
                "mean_subtype_recall": float(recalls.mean()),
                "recon_mean_recall": float(recon.mean()),
                "lateral_mean_recall": float(lateral.mean()),
            }
            row["development_viable"] = bool(
                row["minimum_subtype_recall"] >= MIN_WORST_SUBTYPE_RECALL
                and row["recon_mean_recall"] >= MIN_RECON_MEAN_RECALL
                and row["lateral_mean_recall"] >= MIN_LATERAL_MEAN_RECALL
            )
            candidates.append(row)
    if not candidates:
        raise RuntimeError("No V86 candidates")
    candidates.sort(key=lambda r: (
        int(r["development_viable"]), r["minimum_subtype_recall"],
        min(r["recon_mean_recall"], r["lateral_mean_recall"]),
        r["mean_subtype_recall"], int(r["model"] == "histgb"),
        -abs(r["future_weight_alpha"] - 0.5),
    ), reverse=True)
    winner = candidates[0]
    ids = np.where(labelled_development)[0]
    final_head = fit_head(winner["model"], features[winner["future_weight_alpha"]], y_step, step_pairs, ids)
    return winner, candidates, final_head, features[winner["future_weight_alpha"]], diagnostics


def evaluate_exposed(head, X3, y_step, step_pairs, test_masks):
    y_all, p_all = [], []
    per_stage = {}
    timeline_examples = []
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        ids = np.where(test_masks[stage])[0]
        target = STAGES.index(stage)
        horizon_rows = []
        total = correct = 0
        for h in range(HORIZON):
            hids = np.asarray([
                int(i) for i in ids
                if int(y_step[i, h]) == target and (stage, subtype) in step_pairs[i, h]
            ], dtype=int)
            if len(hids):
                p = head.predict_proba(X3[hids, h])
                pred = p.argmax(axis=1)
                c = int(np.sum(pred == target))
                total += len(hids); correct += c
                y_all.append(np.full(len(hids), target, dtype=int)); p_all.append(p)
                horizon_rows.append({"horizon_minutes": h + 1, "support": int(len(hids)), "recall": c / len(hids)})
                if len(timeline_examples) < 8:
                    for j in range(min(2, len(hids))):
                        timeline_examples.append({
                            "stage": stage, "subtype": subtype, "horizon_minutes": h + 1,
                            "probabilities": {STAGES[k]: float(p[j, k]) for k in range(len(STAGES))},
                        })
            else:
                horizon_rows.append({"horizon_minutes": h + 1, "support": 0, "recall": None})
        per_stage[stage] = {
            "held_out_subtype": subtype, "step_occurrences": int(total),
            "recall": None if total == 0 else correct / total,
            "by_horizon": horizon_rows,
        }
    if not y_all:
        raise RuntimeError("No exposed step-level diagnostic support")
    y = np.concatenate(y_all); p = np.concatenate(p_all)
    pred = p.argmax(axis=1)
    metric = add_strict_stage_metrics(exact_metrics(y, pred))
    return metric, probability_metrics(y, p), per_stage, timeline_examples


def progression_probabilities(head, X3, seq_ids):
    """Return per-sequence cumulative P(stage >= k by horizon h) diagnostics."""
    out = []
    for i in seq_ids[:10]:
        per_h = []
        running = np.zeros(len(STAGES), dtype=float)
        for h in range(HORIZON):
            p = head.predict_proba(X3[np.asarray([i]), h])[0]
            threshold = np.asarray([p[k:].sum() for k in range(len(STAGES))], dtype=float)
            running = np.maximum(running, threshold)
            per_h.append({
                "horizon_minutes": h + 1,
                "stage_at_or_beyond_probability": {STAGES[k]: float(running[k]) for k in range(len(STAGES))},
            })
        out.append({"sequence_id": int(i), "timeline": per_h})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--freeze", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--epochs", type=int, default=18)
    args = ap.parse_args()

    csv = Path(args.csv); freeze = Path(args.freeze)
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
            raise RuntimeError("Exposed reserve registry drift")

    out = Path(args.output)
    if out.exists():
        ap.error("Output exists; V86 evidence is immutable")
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

    # Rebuild the same exposed sequence masks as V82 without importing a fresh-claim helper.
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
        print(f"V86 world seed={seed}", flush=True)
        worlds.append(train_residual_world_model(seq["X"], seq["future"], train, validation, int(seed), epochs=args.epochs))
    target = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])

    winner, candidates, head, X3, diagnostics = select_head(
        history, forecast, persistence, list(state_names), seq, y_step, step_pairs,
        labelled_development, reserve_pairs,
    )
    print("V86 DEVELOPMENT WINNER", json.dumps(winner, indent=2), flush=True)

    learned_metric, learned_prob, per_stage, examples = evaluate_exposed(head, X3, y_step, step_pairs, test_masks)

    pX3 = sample_features(history, persistence, persistence, list(state_names))
    dev_ids = np.where(labelled_development)[0]
    phead = fit_head(winner["model"], pX3, y_step, step_pairs, dev_ids)
    pmetric, pprob, p_per_stage, _ = evaluate_exposed(phead, pX3, y_step, step_pairs, test_masks)

    fmse = mse(forecast, target, test_union); pmse = mse(persistence, target, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    lf1 = float(learned_metric["macro_f1_supported_classes"]); pf1 = float(pmetric["macro_f1_supported_classes"])
    dev_viable = bool(winner["development_viable"])
    beats = bool(lf1 > pf1 + 1e-12)
    learned_future_used = bool(winner["future_weight_alpha"] > 0)

    report = {
        "protocol": "V86 multi-horizon network-state attacker progression diagnostic",
        "claim_boundary": (
            "Each future minute is supervised separately and mapped from Garuda-predicted network state. "
            "The X-IIoTID reserve is already exposed, so these are diagnostic scores only. Exploitation remains Initial Access proxy."
        ),
        "dataset_sha256": sha256(csv), "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols, "feature_audit": feature_audit,
        "horizons_minutes": list(range(1, HORIZON + 1)),
        "split": {
            "sequence_count": int(len(seq["X"])), "reserve_touch_sequences": int(reserve_touch.sum()),
            "blocked_sequences": int(blocked.sum()), "development_train": int(train.sum()),
            "development_validation": int(validation.sum()), "development_stage_sequences": int(labelled_development.sum()),
            "exposed_sequence_support": support,
            "development_step_labels": int(np.sum((y_step >= 0) & development[:, None])),
        },
        "architecture_selection": {
            "selection_uses_exposed_reserve_metrics": False,
            "world_gamma_winner": gamma_winner, "world_gamma_table": gamma_table,
            "stage_future_alpha_grid": list(ALPHA_GRID),
            "winner": winner, "all_candidates": candidates,
            "development_diagnostic_subtypes": [
                {k: r[k] for k in ("stage", "subtype", "support", "same_stage_train_after_exclusion")}
                for r in diagnostics
            ],
        },
        "state_task": {"forecast_mse": fmse, "persistence_mse": pmse, "improvement_vs_persistence": state_gain},
        "progression_task_exposed_diagnostic": {
            "learned_forecast_step_metrics": learned_metric,
            "persistence_step_metrics": pmetric,
            "macro_f1_delta_vs_persistence": float(lf1 - pf1),
            "probability_quality_learned": learned_prob,
            "probability_quality_persistence": pprob,
            "held_out_subtype_step_recall": per_stage,
            "persistence_held_out_subtype_step_recall": p_per_stage,
            "example_stage_probability_rows": examples,
            "cumulative_progression_probability_examples": progression_probabilities(head, X3, np.where(test_union)[0]),
        },
        "release_gate": {
            "development_subtype_viability_passed": dev_viable,
            "learned_future_contribution_used": learned_future_used,
            "progression_task_beats_persistence_passed": beats,
            "release_eligible_for_unseen_subtype_progression_claim": bool(dev_viable and learned_future_used and beats),
            "fresh_claim_allowed": False,
            "reason": "The V81/V82 subtype reserve is exposed; a new sealed campaign/dataset is required for a fresh claim.",
        },
        "leakage_contract": {
            "reserve_metrics_used_for_world_gamma_selection": False,
            "reserve_metrics_used_for_progression_head_selection": False,
            "reserve_subtypes_seen_by_world_fit_or_validation": False,
            "reserve_subtypes_seen_by_progression_head_fit": False,
            "attack_labels_are_world_model_inputs": False,
            "future_observed_state_used_at_inference": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "winner": winner, "state_task": report["state_task"],
        "progression_macro_f1": lf1, "persistence_macro_f1": pf1,
        "held_out_step_recall": per_stage, "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
