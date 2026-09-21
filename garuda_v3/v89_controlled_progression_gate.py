"""V89 controlled future-risk and attacker-progression benchmark.

V87 exposed two methodological problems: the selected progression mapper used alpha=0
(no learned-future contribution), and some subtype folds contained no real negatives, so
an apparent 0% FPR was not an operationally meaningful gate. V89 fixes both issues.

The benchmark separates two questions:
  1. P(any binary-labelled attack occurs by horizon h), and
  2. P(the lifecycle reaches a severity threshold by horizon h).

Every development subtype fold excludes the held-out fine subtype from head fitting,
uses distinct temporal fit/calibration/threshold/control partitions, and evaluates the
held-out subtype positives against real non-event controls. Thresholds are selected on a
separate development slice under a 1% FPR budget. Observed-only, persistence-future and
Garuda-learned-future variants are compared with the same protocol. The V81/V82 reserve
is already exposed and remains diagnostic only; V89 cannot create a fresh zero-day or
verified pre-compromise claim.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .v47_unseen_family import (
    HISTORY,
    HORIZON,
    build_minute_state,
    choose_network_numeric_features,
    detect_label_hierarchy,
    parse_time,
)
from .v60_residual_state_forecasting import train_residual_world_model
from .v71_future_stage_proxy import STAGES
from .v76_stage_subtype_support_freeze import build_minute_pairs, find_subtype_column
from .v77_unseen_subtype_stage_generalization import make_sequences_with_subtypes
from .v80_ensemble_context_stage import WORLD_SEEDS, development_split, mse, reserve_isolation, scaled_history, wilson
from .v82_robust_stage_head_fresh_eval import (
    EXPECTED_V81_FREEZE_SHA256,
    EXPECTED_V81_SELECTED,
    EXPECTED_V81_SUPPORT,
    choose_gamma,
    mapper_diagnostic_pairs,
)
from .v83_stage_benchmark_hardening import EXPOSED_SUBTYPE_REGISTRY
from .v86_multihorizon_progression import sha256, step_targets, sample_features

EPS = 1e-9
FPR_BUDGET = 0.01
MIN_RECALL_GATE = 0.80
MIN_NEGATIVE_EVAL = 100
GARUDA_ALPHAS = (0.25, 0.50, 1.00)
EMBARGO_SECONDS = (HISTORY + HORIZON) * 60

TARGETS = (
    ("any_attack", None),
    ("initial_access_or_beyond", 1),
    ("lateral_movement_or_beyond", 2),
    ("command_control_or_beyond", 3),
    ("exfiltration", 4),
)


def ece_binary(y, p, bins=10):
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    out = 0.0; n = max(len(y), 1)
    for j in range(bins):
        lo, hi = edges[j], edges[j + 1]
        mask = (p >= lo) & (p < hi if j < bins - 1 else p <= hi)
        if mask.any():
            out += float(mask.sum()) / n * abs(float(y[mask].mean()) - float(p[mask].mean()))
    return float(out)


def binary_metrics(y, p, threshold):
    y = np.asarray(y, dtype=np.int8); p = np.asarray(p, dtype=float)
    pred = p >= float(threshold); pos = y == 1; neg = ~pos
    tp = int(np.sum(pred & pos)); fn = int(np.sum((~pred) & pos))
    fp = int(np.sum(pred & neg)); tn = int(np.sum((~pred) & neg))
    recall = tp / max(tp + fn, 1); fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, EPS)
    ap = float(average_precision_score(y, p)) if len(np.unique(y)) > 1 else None
    auc = float(roc_auc_score(y, p)) if len(np.unique(y)) > 1 else None
    return {
        "support": int(len(y)), "positives": int(pos.sum()), "negatives": int(neg.sum()),
        "threshold": float(threshold), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": float(recall), "recall_wilson95": wilson(tp, tp + fn),
        "fpr": float(fpr), "fpr_wilson95": wilson(fp, fp + tn),
        "precision": float(precision), "f1": float(f1),
        "pr_auc": ap, "roc_auc": auc,
        "brier": float(np.mean((p - y) ** 2)), "ece_10bin": ece_binary(y, p),
    }


def select_threshold(y, p, budget=FPR_BUDGET):
    y = np.asarray(y, dtype=np.int8); p = np.asarray(p, dtype=float)
    if int(np.sum(y == 1)) < 1 or int(np.sum(y == 0)) < 1:
        raise RuntimeError("Threshold selection requires both positive and negative controls")
    grid = np.unique(np.concatenate([
        np.linspace(0.0, 1.0, 401), np.clip(p, 0.0, 1.0),
        np.asarray([np.nextafter(float(np.max(p)), 2.0)]),
    ]))
    rows = [binary_metrics(y, p, float(t)) for t in grid]
    feasible = [r for r in rows if r["fpr"] <= budget + 1e-12]
    if not feasible:
        raise RuntimeError("No threshold satisfies development FPR budget")
    feasible.sort(key=lambda r: (r["recall"], r["precision"], -r["fpr"], -r["threshold"]), reverse=True)
    win = feasible[0]
    return float(win["threshold"]), win


class BinaryHead:
    def __init__(self):
        self.model = Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                C=0.35, class_weight="balanced", max_iter=5000,
                solver="lbfgs", random_state=20260921,
            )),
        ])

    def fit(self, X, y):
        y = np.asarray(y, dtype=np.int8)
        if int(np.sum(y == 1)) < 20 or int(np.sum(y == 0)) < 20:
            raise RuntimeError(f"Binary head support too small pos={int(np.sum(y==1))} neg={int(np.sum(y==0))}")
        self.model.fit(X, y)
        return self

    def predict_proba(self, X):
        return np.asarray(self.model.predict_proba(X)[:, 1], dtype=float)


class PlattCalibrator:
    def __init__(self):
        self.model = LogisticRegression(C=1000.0, solver="lbfgs", max_iter=2000, random_state=20260921)

    @staticmethod
    def _logit(p):
        p = np.clip(np.asarray(p, dtype=float), 1e-6, 1.0 - 1e-6)
        return np.log(p / (1.0 - p)).reshape(-1, 1)

    def fit(self, p, y):
        y = np.asarray(y, dtype=np.int8)
        if int(np.sum(y == 1)) < 10 or int(np.sum(y == 0)) < 10:
            raise RuntimeError(f"Platt calibration support too small pos={int(np.sum(y==1))} neg={int(np.sum(y==0))}")
        self.model.fit(self._logit(p), y)
        return self

    def transform(self, p):
        return np.asarray(self.model.predict_proba(self._logit(p))[:, 1], dtype=float)


def attack_step_targets(seq, state: pd.DataFrame):
    lookup = {}
    for row in state[["src", "minute", "attack_now"]].itertuples(index=False):
        sec = int(pd.Timestamp(row.minute).value // 10**9)
        lookup[(str(row.src), sec)] = int(row.attack_now)
    y = np.zeros((len(seq["X"]), HORIZON), dtype=np.int8)
    missing = 0
    for i, (src, cutoff) in enumerate(zip(seq["src"], seq["cutoff"])):
        for h in range(HORIZON):
            key = (str(src), int(cutoff) + 60 * (h + 1))
            if key not in lookup:
                missing += 1
                continue
            y[i, h] = int(lookup[key])
    if missing:
        raise RuntimeError(f"Attack-step alignment missing {missing} future minutes")
    return y


def cumulative_target(attack_step, stage_step, threshold_rank):
    if threshold_rank is None:
        exact = np.asarray(attack_step == 1, dtype=np.int8)
    else:
        exact = np.asarray(stage_step >= int(threshold_rank), dtype=np.int8)
    return np.maximum.accumulate(exact, axis=1).astype(np.int8)


def _keep_nonport(state_names):
    return np.asarray(["port" not in str(n).lower() for n in state_names], dtype=bool)


def observed_features(history, state_names):
    keep = _keep_nonport(state_names)
    hist = history[:, :, keep]
    last = hist[:, -1, :]
    mean = hist.mean(axis=1)
    std = np.maximum(hist.std(axis=1), 0.25)
    recent = np.clip((hist[:, -1, :] - hist[:, -2, :]) / std, -8, 8)
    rows = []
    for h in range(HORIZON):
        horizon = np.zeros((len(history), HORIZON), dtype=np.float32)
        horizon[:, h] = 1.0
        rows.append(np.concatenate([last, mean, std, recent, horizon], axis=1).astype(np.float32))
    return np.stack(rows, axis=1)


def build_feature_variants(history, forecast, persistence, state_names):
    out = {
        "observed_only": observed_features(history, state_names),
        "persistence_future": sample_features(history, persistence, persistence, state_names),
    }
    for alpha in GARUDA_ALPHAS:
        future = persistence + float(alpha) * (forecast - persistence)
        out[f"garuda_future_alpha_{alpha:.2f}"] = sample_features(history, future, persistence, state_names)
    return out


def flatten(ids, target):
    ids = np.asarray(ids, dtype=int)
    ii = np.repeat(ids, HORIZON)
    hh = np.tile(np.arange(HORIZON, dtype=int), len(ids))
    yy = target[ii, hh]
    return ii, hh, np.asarray(yy, dtype=np.int8)


def temporal_fourway(ids, cutoff):
    ids = np.asarray(ids, dtype=int)
    times = np.unique(np.asarray(cutoff)[ids])
    if len(ids) < 120 or len(times) < 24:
        raise RuntimeError(f"Four-way split support too small ids={len(ids)} times={len(times)}")
    b1 = int(times[int(0.50 * (len(times) - 1))])
    b2 = int(times[int(0.68 * (len(times) - 1))])
    b3 = int(times[int(0.84 * (len(times) - 1))])
    c = np.asarray(cutoff)
    fit = ids[c[ids] <= b1]
    cal = ids[(c[ids] > b1 + EMBARGO_SECONDS) & (c[ids] <= b2)]
    threshold = ids[(c[ids] > b2 + EMBARGO_SECONDS) & (c[ids] <= b3)]
    control = ids[c[ids] > b3 + EMBARGO_SECONDS]
    if min(len(fit), len(cal), len(threshold), len(control)) < 15:
        raise RuntimeError(
            f"Four-way split collapsed fit={len(fit)} cal={len(cal)} threshold={len(threshold)} control={len(control)}"
        )
    return fit, cal, threshold, control, {"b1": b1, "b2": b2, "b3": b3, "embargo_seconds": EMBARGO_SECONDS}


def fit_calibrated_head(X3, target, fit_ids, cal_ids):
    ii, hh, yy = flatten(fit_ids, target)
    head = BinaryHead().fit(X3[ii, hh], yy)
    ci, ch, cy = flatten(cal_ids, target)
    raw = head.predict_proba(X3[ci, ch])
    cal = PlattCalibrator().fit(raw, cy)
    return head, cal


def threshold_on_slice(head, cal, X3, target, ids):
    ii, hh, yy = flatten(ids, target)
    p = cal.transform(head.predict_proba(X3[ii, hh]))
    return select_threshold(yy, p, FPR_BUDGET)


def subtype_positive_rows(seq, step_pairs, target, positive_ids, stage, subtype):
    pair = (stage, subtype)
    ii, hh = [], []
    for i in np.asarray(positive_ids, dtype=int):
        seen = False
        for h in range(HORIZON):
            if pair in step_pairs[int(i), h]:
                seen = True
            if seen and int(target[int(i), h]) == 1:
                ii.append(int(i)); hh.append(int(h))
    return np.asarray(ii, dtype=int), np.asarray(hh, dtype=int)


def matched_negative_rows(control_ids, positive_ids, cutoff, target):
    control_ids = np.asarray(control_ids, dtype=int)
    positive_ids = np.asarray(positive_ids, dtype=int)
    c = np.asarray(cutoff)
    if len(positive_ids):
        lo = int(np.min(c[positive_ids])); hi = int(np.max(c[positive_ids]))
        matched = control_ids[(c[control_ids] >= lo) & (c[control_ids] <= hi)]
        if len(matched) >= 50:
            control_ids = matched
    ii, hh, yy = flatten(control_ids, target)
    neg = yy == 0
    ii, hh = ii[neg], hh[neg]
    if len(ii) > 20000:
        # deterministic temporal/support-only cap, independent of model scores
        order = np.lexsort((hh, c[ii]))[:20000]
        ii, hh = ii[order], hh[order]
    return ii, hh


def target_for_stage(stage):
    if stage == "Reconnaissance":
        return "any_attack", None
    k = STAGES.index(stage)
    return {
        1: "initial_access_or_beyond",
        2: "lateral_movement_or_beyond",
        3: "command_control_or_beyond",
        4: "exfiltration",
    }[k], k


def evaluate_subtype_fold(X3, target, seq, step_pairs, development, row):
    stage = row["stage"]; subtype = row["subtype"]
    pair = (stage, subtype)
    touch = np.asarray([
        pair in set(h) or pair in set(f)
        for h, f in zip(seq["history_pairs"], seq["future_pairs"])
    ], dtype=bool)
    allowed = development & ~touch
    fit_ids, cal_ids, threshold_ids, control_ids, boundaries = temporal_fourway(np.where(allowed)[0], seq["cutoff"])
    positive_ids = np.where(row["eval_mask"] & development)[0]
    if len(positive_ids) < 10:
        raise RuntimeError(f"Held-out subtype support too small {stage}/{subtype}: {len(positive_ids)}")
    head, cal = fit_calibrated_head(X3, target, fit_ids, cal_ids)
    threshold, threshold_metric = threshold_on_slice(head, cal, X3, target, threshold_ids)
    pi, ph = subtype_positive_rows(seq, step_pairs, target, positive_ids, stage, subtype)
    ni, nh = matched_negative_rows(control_ids, positive_ids, seq["cutoff"], target)
    if len(pi) < 10 or len(ni) < MIN_NEGATIVE_EVAL:
        raise RuntimeError(f"Evaluation controls insufficient pos={len(pi)} neg={len(ni)} for {stage}/{subtype}")
    X = np.concatenate([X3[pi, ph], X3[ni, nh]], axis=0)
    y = np.concatenate([np.ones(len(pi), dtype=np.int8), np.zeros(len(ni), dtype=np.int8)])
    p = cal.transform(head.predict_proba(X))
    metric = binary_metrics(y, p, threshold)
    metric["target"] = target_for_stage(stage)[0]
    metric["stage"] = stage; metric["subtype"] = subtype
    metric["held_out_positive_rows"] = int(len(pi)); metric["real_negative_control_rows"] = int(len(ni))
    metric["threshold_slice"] = threshold_metric; metric["split_boundaries"] = boundaries
    return metric


def evaluate_variant_cv(name, X3, target_map, seq, step_pairs, development, diagnostics):
    folds = []
    for row in diagnostics:
        target_name, _ = target_for_stage(row["stage"])
        target = target_map[target_name]
        folds.append(evaluate_subtype_fold(X3, target, seq, step_pairs, development, row))
    recalls = np.asarray([r["recall"] for r in folds], dtype=float)
    fprs = np.asarray([r["fpr"] for r in folds], dtype=float)
    f1s = np.asarray([r["f1"] for r in folds], dtype=float)
    aps = np.asarray([0.0 if r["pr_auc"] is None else r["pr_auc"] for r in folds], dtype=float)
    min_neg = min(r["real_negative_control_rows"] for r in folds)
    viable = bool(
        float(recalls.min()) >= MIN_RECALL_GATE
        and float(fprs.max()) <= FPR_BUDGET + 1e-12
        and min_neg >= MIN_NEGATIVE_EVAL
    )
    return {
        "variant": name, "folds": folds,
        "minimum_subtype_recall": float(recalls.min()),
        "mean_subtype_recall": float(recalls.mean()),
        "maximum_eval_fpr": float(fprs.max()),
        "mean_eval_f1": float(f1s.mean()),
        "mean_eval_pr_auc": float(aps.mean()),
        "minimum_real_negative_controls": int(min_neg),
        "development_viable_80pct_recall_1pct_fpr": viable,
    }


def final_target_evaluation(X3, target_map, train_mask, validation_mask, cutoff):
    # Heads fit on development train only. Validation is internally split into three
    # chronological, embargo-separated pieces for calibration, threshold selection and
    # held-out evaluation. This is a development diagnostic, not a fresh external test.
    val_ids = np.where(validation_mask)[0]
    times = np.unique(np.asarray(cutoff)[val_ids])
    if len(times) < 12:
        raise RuntimeError("Validation timeline too short for final target evaluation")
    b1 = int(times[int(0.34 * (len(times) - 1))])
    b2 = int(times[int(0.67 * (len(times) - 1))])
    c = np.asarray(cutoff)
    cal_ids = val_ids[c[val_ids] <= b1]
    threshold_ids = val_ids[(c[val_ids] > b1 + EMBARGO_SECONDS) & (c[val_ids] <= b2)]
    eval_ids = val_ids[c[val_ids] > b2 + EMBARGO_SECONDS]
    if min(len(cal_ids), len(threshold_ids), len(eval_ids)) < 10:
        raise RuntimeError(f"Validation three-way split collapsed {len(cal_ids)}/{len(threshold_ids)}/{len(eval_ids)}")
    train_ids = np.where(train_mask)[0]
    out = {}
    for target_name, _ in TARGETS:
        target = target_map[target_name]
        try:
            head, cal = fit_calibrated_head(X3, target, train_ids, cal_ids)
            threshold, tmetric = threshold_on_slice(head, cal, X3, target, threshold_ids)
            ii, hh, yy = flatten(eval_ids, target)
            p = cal.transform(head.predict_proba(X3[ii, hh]))
            metric = binary_metrics(yy, p, threshold)
            metric["threshold_slice"] = tmetric
            metric["supported_for_gate"] = bool(metric["positives"] >= 20 and metric["negatives"] >= MIN_NEGATIVE_EVAL)
            out[target_name] = metric
        except Exception as exc:
            out[target_name] = {"error": f"{type(exc).__name__}: {exc}", "supported_for_gate": False}
    out["split"] = {
        "calibration_sequences": int(len(cal_ids)), "threshold_sequences": int(len(threshold_ids)),
        "evaluation_sequences": int(len(eval_ids)), "embargo_seconds": EMBARGO_SECONDS,
    }
    return out


def fit_final_for_exposed(X3, target_map, train_mask, validation_mask, cutoff):
    val_ids = np.where(validation_mask)[0]
    times = np.unique(np.asarray(cutoff)[val_ids])
    b = int(times[int(0.50 * (len(times) - 1))])
    c = np.asarray(cutoff)
    cal_ids = val_ids[c[val_ids] <= b]
    threshold_ids = val_ids[c[val_ids] > b + EMBARGO_SECONDS]
    train_ids = np.where(train_mask)[0]
    models = {}
    for target_name, _ in TARGETS:
        target = target_map[target_name]
        try:
            head, cal = fit_calibrated_head(X3, target, train_ids, cal_ids)
            threshold, metric = threshold_on_slice(head, cal, X3, target, threshold_ids)
            models[target_name] = (head, cal, threshold, metric)
        except Exception:
            continue
    return models


def exposed_positive_diagnostic(models, X3, target_map, seq, step_pairs, test_masks):
    out = {}
    for stage, subtype in EXPECTED_V81_SELECTED.items():
        target_name, _ = target_for_stage(stage)
        if target_name not in models:
            out[stage] = {"held_out_subtype": subtype, "error": "target_head_unavailable"}
            continue
        head, cal, threshold, threshold_metric = models[target_name]
        ids = np.where(test_masks[stage])[0]
        pi, ph = subtype_positive_rows(seq, step_pairs, target_map[target_name], ids, stage, subtype)
        if not len(pi):
            out[stage] = {"held_out_subtype": subtype, "support": 0, "recall": None}
            continue
        p = cal.transform(head.predict_proba(X3[pi, ph]))
        tp = int(np.sum(p >= threshold)); n = int(len(p))
        out[stage] = {
            "held_out_subtype": subtype, "target": target_name,
            "support": n, "recall": float(tp / n), "recall_wilson95": wilson(tp, n),
            "threshold": float(threshold),
            "development_threshold_slice_fpr": float(threshold_metric["fpr"]),
            "development_threshold_slice_negatives": int(threshold_metric["negatives"]),
        }
    return out


def supported_gate(target_eval):
    rows = [v for k, v in target_eval.items() if k != "split" and isinstance(v, dict) and v.get("supported_for_gate")]
    if not rows:
        return False
    return bool(all(r["recall"] >= MIN_RECALL_GATE and r["fpr"] <= FPR_BUDGET + 1e-12 for r in rows))


def mean_supported(target_eval, key):
    vals = [v[key] for k, v in target_eval.items() if k != "split" and isinstance(v, dict) and v.get("supported_for_gate") and v.get(key) is not None]
    return None if not vals else float(np.mean(vals))


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
    stage_step, step_pairs = step_targets(seq, minute_pairs)
    attack_step = attack_step_targets(seq, state)

    target_map = {}
    for name, rank in TARGETS:
        target_map[name] = cumulative_target(attack_step, stage_step, rank)

    reserve_pairs, reserve_touch, blocked = reserve_isolation(seq, dict(EXPECTED_V81_SELECTED))
    development = ~blocked
    train, validation, boundary = development_split(seq["cutoff"], development)
    labelled_development = development & (seq["y_stage"] >= 0)
    diagnostics = mapper_diagnostic_pairs(seq, labelled_development, reserve_pairs)
    if not diagnostics:
        raise RuntimeError("No development subtype diagnostics")

    test_masks = {}; test_union = np.zeros(len(seq["X"]), dtype=bool)
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
    target_state = worlds[0]["future_scaled"]
    persistence = worlds[0]["persistence"]
    raw = np.mean(np.stack([w["pred"] for w in worlds], axis=0), axis=0)
    gamma_winner, gamma_table = choose_gamma(raw, persistence, target_state, validation)
    gamma = float(gamma_winner["gamma"])
    forecast = persistence + gamma * (raw - persistence)
    history = scaled_history(seq["X"], worlds[0])
    features = build_feature_variants(history, forecast, persistence, list(state_names))

    cv_rows = []
    for name, X3 in features.items():
        try:
            row = evaluate_variant_cv(name, X3, target_map, seq, step_pairs, development, diagnostics)
        except Exception as exc:
            row = {"variant": name, "error": f"{type(exc).__name__}: {exc}", "development_viable_80pct_recall_1pct_fpr": False}
        cv_rows.append(row)
        print("V89 CV", json.dumps(row, indent=2), flush=True)

    complete = [r for r in cv_rows if "error" not in r]
    if not complete:
        raise RuntimeError("Every V89 feature variant failed controlled subtype CV")
    garuda_rows = [r for r in complete if r["variant"].startswith("garuda_future_alpha_")]
    if not garuda_rows:
        raise RuntimeError("No Garuda learned-future candidate completed")
    garuda_rows.sort(key=lambda r: (
        int(r["development_viable_80pct_recall_1pct_fpr"]),
        r["minimum_subtype_recall"], -r["maximum_eval_fpr"],
        r["mean_eval_f1"], r["mean_eval_pr_auc"],
    ), reverse=True)
    garuda_winner = garuda_rows[0]
    selected_variant = garuda_winner["variant"]

    # Three-way development evaluation. Garuda alpha is selected only from reserve-free
    # subtype CV. Observed and persistence are matched ablations under the same target protocol.
    final_variants = {
        "observed_only": features["observed_only"],
        "persistence_future": features["persistence_future"],
        selected_variant: features[selected_variant],
    }
    target_evals = {}
    for name, X3 in final_variants.items():
        target_evals[name] = final_target_evaluation(X3, target_map, train, validation, seq["cutoff"])

    exposed_models = fit_final_for_exposed(features[selected_variant], target_map, train, validation, seq["cutoff"])
    exposed = exposed_positive_diagnostic(
        exposed_models, features[selected_variant], target_map, seq, step_pairs, test_masks
    )

    fmse = mse(forecast, target_state, test_union); pmse = mse(persistence, target_state, test_union)
    state_gain = None if not pmse else float((pmse - fmse) / pmse)
    garuda_eval = target_evals[selected_variant]
    persistence_eval = target_evals["persistence_future"]
    observed_eval = target_evals["observed_only"]
    garuda_f1 = mean_supported(garuda_eval, "f1")
    persistence_f1 = mean_supported(persistence_eval, "f1")
    observed_f1 = mean_supported(observed_eval, "f1")
    garuda_recall = mean_supported(garuda_eval, "recall")
    persistence_recall = mean_supported(persistence_eval, "recall")
    learned_beats_persistence = bool(
        garuda_f1 is not None and persistence_f1 is not None
        and garuda_f1 > persistence_f1 + 1e-12
    )
    learned_beats_observed = bool(
        garuda_f1 is not None and observed_f1 is not None
        and garuda_f1 > observed_f1 + 1e-12
    )

    report = {
        "protocol": "V89 controlled cumulative future-risk and attacker-progression diagnostic",
        "claim_boundary": (
            "Risk uses X-IIoTID binary attack ground truth; severity progression uses mapped lifecycle labels. "
            "All subtype folds include genuine non-event controls and disjoint fit/calibration/threshold/control slices. "
            "The V81/V82 reserve is already exposed, so no score here is a fresh zero-day, production-traffic, or verified pre-compromise result."
        ),
        "dataset_sha256": sha256(csv), "freeze_sha256": sha256(freeze),
        "network_only_features": feature_cols, "feature_audit": feature_audit,
        "targets": [{"name": n, "minimum_stage_rank": k} for n, k in TARGETS],
        "horizons_minutes": list(range(1, HORIZON + 1)), "false_positive_budget": FPR_BUDGET,
        "split": {
            "sequence_count": int(len(seq["X"])), "development_sequences": int(development.sum()),
            "development_train": int(train.sum()), "development_validation": int(validation.sum()),
            "reserve_touch_sequences": int(reserve_touch.sum()), "blocked_sequences": int(blocked.sum()),
            "exposed_sequence_support": support,
        },
        "world_model": {
            "seeds": list(WORLD_SEEDS), "gamma_winner": gamma_winner, "gamma_table": gamma_table,
            "state_task_exposed_diagnostic": {
                "forecast_mse": fmse, "persistence_mse": pmse,
                "improvement_vs_persistence": state_gain,
            },
        },
        "controlled_subtype_cv": {
            "selection_uses_exposed_reserve_metrics": False,
            "garuda_alpha_candidates": list(GARUDA_ALPHAS),
            "selected_garuda_variant": selected_variant,
            "all_variants": cv_rows,
            "development_diagnostic_subtypes": [
                {k: r[k] for k in ("stage", "subtype", "support", "same_stage_train_after_exclusion")}
                for r in diagnostics
            ],
        },
        "three_way_development_ablation": {
            "observed_only": observed_eval,
            "persistence_future": persistence_eval,
            "garuda_learned_future": garuda_eval,
            "garuda_variant": selected_variant,
            "mean_supported_f1": {
                "observed_only": observed_f1,
                "persistence_future": persistence_f1,
                "garuda_learned_future": garuda_f1,
            },
            "mean_supported_recall": {
                "persistence_future": persistence_recall,
                "garuda_learned_future": garuda_recall,
            },
        },
        "exposed_reserve_positive_diagnostic": exposed,
        "release_gate": {
            "controlled_subtype_cv_80pct_recall_1pct_fpr_passed": bool(garuda_winner["development_viable_80pct_recall_1pct_fpr"]),
            "garuda_supported_target_gate_passed": supported_gate(garuda_eval),
            "learned_future_beats_persistence_f1": learned_beats_persistence,
            "learned_future_beats_observed_f1": learned_beats_observed,
            "learned_future_contribution_required": True,
            "selected_garuda_alpha_positive": True,
            "eligible_for_progression_release_claim": bool(
                garuda_winner["development_viable_80pct_recall_1pct_fpr"]
                and supported_gate(garuda_eval)
                and learned_beats_persistence
                and learned_beats_observed
            ),
            "fresh_claim_allowed": False,
            "reason": "X-IIoTID reserve is exposed; an external sealed campaign is still required for a fresh progression claim.",
        },
        "leakage_contract": {
            "subtype_fold_head_fit_excludes_held_out_subtype": True,
            "subtype_fold_has_real_negative_controls": True,
            "calibration_threshold_and_eval_control_slices_disjoint": True,
            "thresholds_use_development_only": True,
            "reserve_metrics_used_for_world_selection": False,
            "reserve_metrics_used_for_garuda_alpha_selection": False,
            "attack_or_stage_labels_are_world_model_inputs": False,
            "future_observed_state_used_at_inference": False,
            "reused_exposed_reserve_labeled_fresh": False,
            "pre_compromise_claim": False,
        },
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("V89 FINAL", json.dumps({
        "selected_garuda_variant": selected_variant,
        "controlled_subtype_cv": garuda_winner,
        "three_way_mean_supported_f1": report["three_way_development_ablation"]["mean_supported_f1"],
        "three_way_mean_supported_recall": report["three_way_development_ablation"]["mean_supported_recall"],
        "exposed_reserve_positive_diagnostic": exposed,
        "state_task": report["world_model"]["state_task_exposed_diagnostic"],
        "release_gate": report["release_gate"],
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
